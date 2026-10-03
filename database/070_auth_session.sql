/***********************************************************************************************************************
Script:         070_auth_session.sql
Purpose:        auth.UserSession -- what a successful sign-in leaves behind, and the only thing a later request presents.
Target:         SQL Server 2022.
Run as:         db_owner in the target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/070_auth_session.sql
Idempotent:     Yes.  Every CREATE is guarded, the trigger is CREATE OR ALTER, nothing is dropped, nothing is seeded.
Depends on:     005_schemas_and_roles.sql (schema auth), 030_auth_tenant.sql (auth.Application),
                040_auth_userprofile.sql (auth.User), 045_auth_identity.sql (auth.LoginAttempt),
                templates/extended-properties.sql (util.uspSetObjectDescription).
Implements:     DES-AUTH-001 sections 7.1, 7.3, 11.5 and 15.3.  PLAN-AUTH-001 task T-030.
To retarget:    Pass it per run:  sqlcmd -d <database> -v DbName=<database>.  There is no in-file default.

THE TOKEN IS NOT IN THIS TABLE.  A HASH OF IT IS
-----------------------------------------------
SessionTokenHash is a SHA-256 of the session token, and the token itself is never stored anywhere in this database.
That is the same decision as auth.UserCredential.VerifierPhc made for a different reason: a stored session token is a
stored password.  Anybody who can read this table -- a backup, a replica, a support query, an application login that was
never meant to have SELECT here -- can present every live session as its owner, with no cracking required and nothing
in the trail to distinguish them from the real user.

A hash costs nothing to check (the application presents the token, the procedure hashes it and looks it up) and turns a
disclosure of this table from immediate impersonation into a list of opaque 32-byte values.

It is a plain SHA-256 and NOT a memory-hard KDF, for the same reason auth.UserMfaRecoveryCode.CodeHash is: a session
token is machine-generated with full entropy, so guessing is not the attack and a KDF would buy nothing while adding a
per-request cost to every authenticated request in the estate.

ActiveUserProfileId IS NULLABLE, AND ITS FOREIGN KEY IS APPLIED CONDITIONALLY
-----------------------------------------------------------------------------
auth.UserProfile is Phase 3, task T-046 -- see section 2 of 040_auth_userprofile.sql.  So in Phase 2 this column was
always NULL, and a Phase 2 session could authenticate a person and authorize nothing they do.  That was the correct
boundary and not a shortfall: authentication is who you are, authorization is what you may do.

The key is now added by section 1 of this file, guarded on the PARENT TABLE rather than on the phase:

    IF OBJECT_ID (N'auth.UserProfile', N'U') IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = N'FK_auth_UserSession_UserProfile')
    BEGIN
        ALTER TABLE auth.UserSession WITH CHECK
            ADD CONSTRAINT FK_auth_UserSession_UserProfile FOREIGN KEY (ActiveUserProfileId)
                REFERENCES auth.UserProfile (UserProfileId);
    END

WITH CHECK is deliberate.  Any rows that exist by then were written before Phase 3 with NULL in the column, so the check
cannot fail, and a NOCHECK constraint that nobody ever validates is a constraint the optimizer ignores and the catalog
reports as untrusted.

IT IS IN THIS FILE AND NOT IN 040, AND THAT IS THE WHOLE REASON IT WAS MISSED.  040_auth_userprofile.sql installs at
manifest step 10 and auth.UserSession does not exist until step 16, so 040 cannot add it; this file installed before
auth.UserProfile existed, so for two phases it could not either.  Phase 3 built auth.UserProfile and the ALTER was
written down in this header for "the next reader" -- which is not an owner.  A deferred statement that belongs to no
script is a statement nobody runs, and the deployment reported PENDING every time without anyone acting on it.  The fix
is structural rather than a reminder: the ALTER is a guarded step in the install path, so the NEXT deployment of a
Phase 3 database applies it whether or not anybody remembers.  BL-049.

The closing report emits a PENDING row for it on any database where auth.UserProfile is still absent.

TWO EXPIRY COLUMNS, BOTH STORED, NEITHER COMPUTED
------------------------------------------------
Section 7.3.  AbsoluteExpiryUtc is when the session dies whatever happens; IdleExpiryUtc is when it dies if nothing more
arrives, and it moves forward on each request.  Both are STORED, computed once at sign-in from the resolved policy
(auth.TenantAuthenticationPolicy.SessionLifetimeMinutes and IdleTimeoutMinutes, falling back to
Authn.SessionLifetimeMinutes and Authn.IdleTimeoutMinutes).

Stored rather than derived on read, because the policy can change while a session is live.  A session that was issued
under an eight-hour policy should not silently become a one-hour session because somebody edited the policy row at
lunchtime -- and it should not become a twelve-hour session either.  The rule in force when the session started is the
rule it lives under, and the only way to say that is to write it down.

WHY THIS TABLE REPEATS ClientAddress, IsBypassRoute AND MfaSatisfied FROM auth.LoginAttempt
-----------------------------------------------------------------------------------------
It looks like duplication and it is not.  auth.LoginAttempt records the EXCHANGE -- the thing that happened, once, and
is now immutable history.  auth.UserSession records the CAPABILITY that exchange produced, and the capability is what
gets checked on every subsequent request.  Reading the invariant off the attempt row would mean every authorization
check joined back through the attempt, and it would mean INV-08 was enforced only on history.

So CK_auth_UserSession_BypassNeedsMfa refuses a bypass-route session with no satisfied second factor -- the same
invariant as CK_auth_LoginAttempt_BypassNeedsMfa, on the row that the rest of the system actually reads.

ENDING A SESSION IS A WRITE-ONCE ACT
-----------------------------------
EndedUtc and EndReason are set together, once, by auth.uspEndSession -- and the trigger refuses to clear or change
them.  A session that can be un-ended is a session that can be resurrected by one UPDATE after a user has signed out,
after an administrator has revoked it, or after an incident response has terminated it.  Nothing is deleted: the ended
row is the evidence that it ended.
***********************************************************************************************************************/

:on error exit

-- THE TARGET DATABASE IS SUPPLIED ON THE COMMAND LINE AND HAS NO DEFAULT.  There is deliberately no `:setvar DbName`
-- line: measured on sqlcmd 17, a :setvar in the file OVERRIDES -v rather than acting as a fallback for its absence.

SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;
GO


-- *** 0. Assert the target and the parents ***
IF DB_NAME () <> N'$(DbName)'
BEGIN
    DECLARE @Mismatch NVARCHAR (2000) =
        N'Target mismatch. Connected to [' + DB_NAME () + N'] but this file is configured for [$(DbName)]. '
      + N'Either connect with  -d $(DbName)  or override the file with  -v DbName=' + DB_NAME ()
      + N'. Nothing has been changed.';

    THROW 50000, @Mismatch, 1;
END
GO

USE [$(DbName)];
GO

IF OBJECT_ID (N'auth.User', N'U') IS NULL
   OR OBJECT_ID (N'auth.LoginAttempt', N'U') IS NULL
   OR OBJECT_ID (N'auth.Application', N'U') IS NULL
BEGIN
    DECLARE @MsgParents NVARCHAR (2000) =
        N'Tables auth.User, auth.LoginAttempt and auth.Application must all exist. Run database/030_auth_tenant.sql, '
      + N'database/040_auth_userprofile.sql and database/045_auth_identity.sql first. Nothing has been changed.';

    THROW 50000, @MsgParents, 1;
END
GO


-- *** 1. auth.UserSession ***
--
-- LoginAttemptId is NOT NULL and there is no way to create a session without one.  That is the audit chain: every live
-- session points at the exchange that produced it, and that exchange names the address, the method and the outcome.
IF OBJECT_ID (N'auth.UserSession', N'U') IS NULL
BEGIN
    CREATE TABLE auth.UserSession
    (
        UserSessionId        BIGINT          IDENTITY (1, 1) NOT NULL
      , UserId               INT                             NOT NULL
      , ActiveUserProfileId  INT                                 NULL
      , LoginAttemptId       BIGINT                          NOT NULL
      , ApplicationId        INT                             NOT NULL
      , SessionTokenHash     VARBINARY (32)                  NOT NULL
      , ClientAddress        NVARCHAR (45)                   NOT NULL
      , AuthenticationMethod VARCHAR (20)                    NOT NULL
      , IsBypassRoute        BIT                             NOT NULL
            CONSTRAINT DF_auth_UserSession_IsBypassRoute DEFAULT (0)
      , MfaSatisfied         BIT                             NOT NULL
            CONSTRAINT DF_auth_UserSession_MfaSatisfied DEFAULT (0)
      , StartedUtc           DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_UserSession_StartedUtc DEFAULT (SYSUTCDATETIME ())
      , LastSeenUtc          DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_UserSession_LastSeenUtc DEFAULT (SYSUTCDATETIME ())
      , AbsoluteExpiryUtc    DATETIME2 (3)                   NOT NULL
      , IdleExpiryUtc        DATETIME2 (3)                   NOT NULL
      , ElevatedUntilUtc     DATETIME2 (3)                       NULL
      , EndedUtc             DATETIME2 (3)                       NULL
      , EndReason            VARCHAR (40)                        NULL
      , IsDeleted            BIT                             NOT NULL
            CONSTRAINT DF_auth_UserSession_IsDeleted DEFAULT (0)
      , auditDeletedBy       NVARCHAR (255)                      NULL
      , auditDeletedDateUtc  DATETIME2 (3)                       NULL
      , auditCreatedBy       NVARCHAR (255)                  NOT NULL
            CONSTRAINT DF_auth_UserSession_auditCreatedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditCreatedDateUtc  DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_UserSession_auditCreatedDateUtc DEFAULT (SYSUTCDATETIME ())
      , auditModifiedBy      NVARCHAR (255)                  NOT NULL
            CONSTRAINT DF_auth_UserSession_auditModifiedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditModifiedDateUtc DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_UserSession_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ())
      , CONSTRAINT PK_auth_UserSession PRIMARY KEY CLUSTERED (UserSessionId)
      , CONSTRAINT FK_auth_UserSession_User
            FOREIGN KEY (UserId) REFERENCES auth.[User] (UserId)
      , CONSTRAINT FK_auth_UserSession_LoginAttempt
            FOREIGN KEY (LoginAttemptId) REFERENCES auth.LoginAttempt (LoginAttemptId)
      , CONSTRAINT FK_auth_UserSession_Application
            FOREIGN KEY (ApplicationId) REFERENCES auth.Application (ApplicationId)
      -- ActiveUserProfileId's foreign key is NOT declared here: auth.UserProfile may not exist yet, and a CREATE TABLE
      -- cannot be conditional in its own column list.  It is added by the guarded ALTER at the end of this section as
      -- soon as auth.UserProfile is present, and the closing report reports it PENDING until then.
      , CONSTRAINT CK_auth_UserSession_SessionTokenHash
            CHECK (DATALENGTH (SessionTokenHash) = 32)
      , CONSTRAINT CK_auth_UserSession_ClientAddress
            CHECK (LEN (ClientAddress) > 0 AND ClientAddress = LTRIM (RTRIM (ClientAddress)))
      , CONSTRAINT CK_auth_UserSession_AuthenticationMethod
            CHECK (AuthenticationMethod IN ('LocalPassword', 'Federated'))
      -- INV-08 on the row the rest of the system reads, not only on the history row.  See the header.
      , CONSTRAINT CK_auth_UserSession_BypassNeedsMfa
            CHECK (IsBypassRoute = 0 OR MfaSatisfied = 1)
      -- Both expiries must be after the start, and idle can never outlast absolute: an idle window longer than the
      -- session lifetime is an idle window that never fires, which is the misconfiguration that looks like it works.
      , CONSTRAINT CK_auth_UserSession_Expiries
            CHECK (AbsoluteExpiryUtc > StartedUtc
               AND IdleExpiryUtc > StartedUtc
               AND IdleExpiryUtc <= AbsoluteExpiryUtc)
      , CONSTRAINT CK_auth_UserSession_LastSeenUtc
            CHECK (LastSeenUtc >= StartedUtc)
      -- Step-up elevation cannot outlast the session it elevates -- section 11.5.
      , CONSTRAINT CK_auth_UserSession_ElevatedUntilUtc
            CHECK (ElevatedUntilUtc IS NULL
               OR (ElevatedUntilUtc > StartedUtc AND ElevatedUntilUtc <= AbsoluteExpiryUtc))
      -- Ended is a pair: a reason with no time, or a time with no reason, is a session whose state nobody can read.
      , CONSTRAINT CK_auth_UserSession_EndedPair
            CHECK ((EndedUtc IS     NULL AND EndReason IS     NULL)
                OR (EndedUtc IS NOT NULL AND EndReason IS NOT NULL
                    AND LEN (EndReason) > 0 AND EndedUtc >= StartedUtc))
      , CONSTRAINT CK_auth_UserSession_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS     NULL AND auditDeletedDateUtc IS     NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL))
    );
END
GO

-- The lookup every authenticated request performs: hash the presented token, find the row.  UNIQUE because two sessions
-- with the same token hash is either a collision nobody should plan for or a token-generation bug that must not be
-- absorbed silently.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'UX_auth_UserSession_TokenHash' AND object_id = OBJECT_ID (N'auth.UserSession'))
BEGIN
    CREATE UNIQUE INDEX UX_auth_UserSession_TokenHash
        ON auth.UserSession (SessionTokenHash) WHERE IsDeleted = 0;
END
GO

-- "Sign me out everywhere", and the administrative revoke.  Filtered to the live sessions, which is a small fraction of
-- the table once it has been in production for a week.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_auth_UserSession_UserLive' AND object_id = OBJECT_ID (N'auth.UserSession'))
BEGIN
    CREATE INDEX IX_auth_UserSession_UserLive
        ON auth.UserSession (UserId, AbsoluteExpiryUtc) WHERE EndedUtc IS NULL AND IsDeleted = 0;
END
GO

-- The expiry sweep, and the "how many sessions are live right now" question 950_verify_deployment.sql asks.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_auth_UserSession_Expiry' AND object_id = OBJECT_ID (N'auth.UserSession'))
BEGIN
    CREATE INDEX IX_auth_UserSession_Expiry
        ON auth.UserSession (IdleExpiryUtc) WHERE EndedUtc IS NULL AND IsDeleted = 0;
END
GO

-- "Which session came out of which exchange", for incident response reading in the other direction.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_auth_UserSession_LoginAttempt' AND object_id = OBJECT_ID (N'auth.UserSession'))
BEGIN
    CREATE INDEX IX_auth_UserSession_LoginAttempt
        ON auth.UserSession (LoginAttemptId) WHERE IsDeleted = 0;
END
GO

-- The Phase 3 foreign key, applied HERE rather than in 040_auth_userprofile.sql because 040 installs at step 10 and this
-- table does not exist until step 16.  The constraint belongs to auth.UserSession, so it lives in auth.UserSession's
-- file and is guarded on the parent instead of on the phase: a database that has run Phase 3 gets the key on its next
-- deployment, and a database that has not is unchanged.  The closing report's PENDING row is what this closes.
--
-- WITH CHECK is deliberate.  Every row written before Phase 3 carries NULL in the column, so the check cannot fail, and
-- a NOCHECK constraint nobody validates is one the optimizer ignores and the catalog reports as untrusted.
IF OBJECT_ID (N'auth.UserProfile', N'U') IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = N'FK_auth_UserSession_UserProfile')
BEGIN
    ALTER TABLE auth.UserSession WITH CHECK
        ADD CONSTRAINT FK_auth_UserSession_UserProfile FOREIGN KEY (ActiveUserProfileId)
            REFERENCES auth.UserProfile (UserProfileId);

    PRINT N'  FK_auth_UserSession_UserProfile added -- auth.UserProfile is present, so the Phase 3 key is now enforced.';
END
GO

-- Without the key an authenticated session can name a profile that does not exist, which is exactly the state
-- auth.uspSetSessionContext trusts the row to be in.  So on a database that HAS auth.UserProfile the absence is a
-- defect, not a phase boundary, and it is worth saying so on the way past rather than only in the closing report.
IF OBJECT_ID (N'auth.UserProfile', N'U') IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = N'FK_auth_UserSession_UserProfile')
BEGIN
    PRINT N'  WARNING: auth.UserProfile exists and FK_auth_UserSession_UserProfile does not. The ALTER above did not '
        + N'apply. ActiveUserProfileId is unconstrained -- see the header of this file.';
END
GO


-- *** 2. Audit trigger ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.trg_au_updt_UserSession
Author:       rsincero
CreateDate:   2026-09-19
Description:
AFTER UPDATE audit stamp for auth.UserSession, the guard that makes the session's identity and its issued limits
immutable, and the guard that makes ending write-once -- E-50010.

Three groups of columns, and it is worth knowing which is which.

IMMUTABLE.  UserId, LoginAttemptId, ApplicationId, SessionTokenHash, StartedUtc, AbsoluteExpiryUtc, IsBypassRoute,
AuthenticationMethod.  Moving a live session to another UserId is impersonation with no sign-in; rewriting
SessionTokenHash hands a live session to whoever chose the new value; extending AbsoluteExpiryUtc defeats the one limit
section 7.3 says cannot be defeated by activity.  None of these is something a legitimate request needs to do.

MUTABLE, and they are the working state.  LastSeenUtc and IdleExpiryUtc move forward on each request.
ActiveUserProfileId changes when the user switches profile (Phase 3).  ElevatedUntilUtc is set by a step-up and is
bounded by a CHECK constraint rather than by this trigger.  MfaSatisfied may go 0 to 1 -- MFA is satisfied partway
through some flows -- and may not go back, because a satisfied factor is not unsatisfied by a later request.

WRITE-ONCE.  EndedUtc and EndReason.  A session that can be un-ended can be resurrected by one UPDATE after a sign-out,
after a revoke, or after an incident response terminated it.

Modification History:
2026-09-19  rsincero  Created.  PLAN-AUTH-001 T-030.
***********************************************************************************************************************/
CREATE OR ALTER TRIGGER auth.trg_au_updt_UserSession
    ON auth.UserSession
    AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    IF (UPDATE (UserId) OR UPDATE (LoginAttemptId) OR UPDATE (ApplicationId) OR UPDATE (SessionTokenHash)
        OR UPDATE (StartedUtc) OR UPDATE (AbsoluteExpiryUtc) OR UPDATE (IsBypassRoute)
        OR UPDATE (AuthenticationMethod))
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.UserSessionId = i.UserSessionId
                    WHERE i.UserId <> d.UserId
                       OR i.LoginAttemptId <> d.LoginAttemptId
                       OR i.ApplicationId <> d.ApplicationId
                       OR i.SessionTokenHash <> d.SessionTokenHash
                       OR i.StartedUtc <> d.StartedUtc
                       OR i.AbsoluteExpiryUtc <> d.AbsoluteExpiryUtc
                       OR i.IsBypassRoute <> d.IsBypassRoute
                       OR i.AuthenticationMethod <> d.AuthenticationMethod)
    BEGIN
        ;THROW 50010, N'auth.UserSession: UserId, LoginAttemptId, ApplicationId, SessionTokenHash, StartedUtc, AbsoluteExpiryUtc, IsBypassRoute and AuthenticationMethod are immutable. Moving a live session is impersonation with no sign-in, and extending AbsoluteExpiryUtc defeats the one limit activity cannot extend -- section 7.3. End the session and start a new one.', 1;
    END;

    IF UPDATE (MfaSatisfied)
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.UserSessionId = i.UserSessionId
                    WHERE d.MfaSatisfied = 1 AND i.MfaSatisfied = 0)
    BEGIN
        ;THROW 50010, N'auth.UserSession.MfaSatisfied cannot go from 1 back to 0: a second factor that has been satisfied is not unsatisfied by a later request, and clearing it would step around CK_auth_UserSession_BypassNeedsMfa -- INV-08.', 1;
    END;

    IF (UPDATE (EndedUtc) OR UPDATE (EndReason))
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.UserSessionId = i.UserSessionId
                    WHERE d.EndedUtc IS NOT NULL
                      AND (i.EndedUtc IS NULL
                        OR i.EndedUtc <> d.EndedUtc
                        OR i.EndReason IS NULL
                        OR i.EndReason <> d.EndReason))
    BEGIN
        ;THROW 50010, N'auth.UserSession.EndedUtc and EndReason are write-once: a session that can be un-ended can be resurrected by one UPDATE after a sign-out, a revoke, or an incident response. The ended row is the evidence that it ended.', 1;
    END;

    DECLARE @Now   DATETIME2 (3)  = SYSUTCDATETIME ()
          , @Actor NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                            , ORIGINAL_LOGIN ());

    UPDATE t
       SET t.auditModifiedDateUtc = @Now
         , t.auditModifiedBy      = CASE WHEN UPDATE (auditModifiedBy)
                                         THEN COALESCE (NULLIF (i.auditModifiedBy, N''), @Actor)
                                         ELSE @Actor END
         , t.auditDeletedBy       = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Actor ELSE t.auditDeletedBy      END
         , t.auditDeletedDateUtc  = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Now   ELSE t.auditDeletedDateUtc END
      FROM auth.UserSession AS t
      JOIN inserted AS i ON i.UserSessionId = t.UserSessionId
      JOIN deleted  AS d ON d.UserSessionId = t.UserSessionId;
END;
GO


-- *** 3. Descriptions ***
IF OBJECT_ID (N'util.uspSetObjectDescription', N'P') IS NOT NULL
BEGIN
    DECLARE @Descriptions TABLE
    (
        RowNo       INT IDENTITY (1, 1) PRIMARY KEY,
        SchemaName  SYSNAME         NOT NULL,
        ObjectType  SYSNAME         NOT NULL,
        ObjectName  SYSNAME         NOT NULL,
        ColumnName  SYSNAME             NULL,
        Description NVARCHAR (3750) NOT NULL
    );

    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    VALUES
      (N'auth', N'TABLE', N'UserSession', NULL, N'What a successful sign-in leaves behind, and the only thing a later request presents. The token itself is NEVER stored -- SessionTokenHash is a SHA-256 of it -- because a stored session token is a stored password: anybody who can read the table could present every live session as its owner, with nothing in the trail to tell them apart. Section 7.3.')
    , (N'auth', N'TABLE', N'UserSession', N'UserSessionId',       N'Surrogate key, BIGINT. Never sent to a client: the client holds the token, and the token is not derivable from this.')
    , (N'auth', N'TABLE', N'UserSession', N'UserId',              N'Whose session it is. IMMUTABLE -- moving a live session to another user is impersonation with no sign-in.')
    , (N'auth', N'TABLE', N'UserSession', N'ActiveUserProfileId', N'Which profile the user is currently acting as -- the whole basis of authorization. NULL on a fresh sign-in, which 110 writes that way, and set by auth.uspSetSessionContext or by a profile switch. FK_auth_UserSession_UserProfile constrains it, and is added by section 1 of 070_auth_session.sql as soon as auth.UserProfile exists rather than being declared in the CREATE TABLE, because this table installs at manifest step 16 and its parent at step 10 of a phase that may not have run.')
    , (N'auth', N'TABLE', N'UserSession', N'LoginAttemptId',      N'The exchange that produced this session -- NOT NULL, so every live session names the attempt that created it, and that attempt names the address, the method and the outcome. IMMUTABLE. This is the audit chain.')
    , (N'auth', N'TABLE', N'UserSession', N'ApplicationId',       N'Which application the session belongs to. A session is not portable between applications. IMMUTABLE.')
    , (N'auth', N'TABLE', N'UserSession', N'SessionTokenHash',    N'SHA-256 of the session token, 32 bytes. The token is never stored. A plain hash and not a memory-hard KDF, deliberately: the token is machine-generated with full entropy, so guessing is not the attack and a KDF would add cost to every authenticated request in the estate. IMMUTABLE.')
    , (N'auth', N'TABLE', N'UserSession', N'ClientAddress',       N'The address the session was issued to, as the application reported it. Repeated from auth.LoginAttempt on purpose: this is the capability row that later requests read, and reading it off history would make every check a join.')
    , (N'auth', N'TABLE', N'UserSession', N'AuthenticationMethod', N'''LocalPassword'' or ''Federated'' -- how this session was obtained. IMMUTABLE.')
    , (N'auth', N'TABLE', N'UserSession', N'IsBypassRoute',       N'1 if the session came from the platform-administrator bypass route. IMMUTABLE, and bound by CK_auth_UserSession_BypassNeedsMfa: a bypass session with no satisfied second factor cannot exist -- INV-08.')
    , (N'auth', N'TABLE', N'UserSession', N'MfaSatisfied',        N'1 once a second factor has been accepted for this session. May go 0 to 1 -- some flows satisfy MFA partway through -- and never back, because clearing it would step around INV-08''s CHECK constraint.')
    , (N'auth', N'TABLE', N'UserSession', N'StartedUtc',          N'When the session was issued, UTC. IMMUTABLE: both expiry windows are measured from it.')
    , (N'auth', N'TABLE', N'UserSession', N'LastSeenUtc',         N'When a request last presented this session, UTC. Moves forward on each request, alongside IdleExpiryUtc.')
    , (N'auth', N'TABLE', N'UserSession', N'AbsoluteExpiryUtc',   N'When the session dies whatever happens, UTC. Computed ONCE at sign-in from the resolved policy and then IMMUTABLE -- section 7.3: activity extends the idle window and must never extend this one. Stored rather than derived on read so that editing a policy row at lunchtime does not retroactively shorten or lengthen sessions already issued.')
    , (N'auth', N'TABLE', N'UserSession', N'IdleExpiryUtc',       N'When the session dies if nothing more arrives, UTC. Moves forward on each request. Can never exceed AbsoluteExpiryUtc -- an idle window longer than the session lifetime is one that never fires, which is the misconfiguration that looks like it works.')
    , (N'auth', N'TABLE', N'UserSession', N'ElevatedUntilUtc',    N'When a step-up elevation lapses, UTC, or NULL if the session is not elevated. Bounded by the session''s own absolute expiry: elevation cannot outlast the session it elevates. Section 11.5, and read wherever RequireStepUpForPrivileged is set.')
    , (N'auth', N'TABLE', N'UserSession', N'EndedUtc',            N'When the session ended, UTC. NULL means live. WRITE-ONCE with EndReason: a session that can be un-ended can be resurrected by one UPDATE after a sign-out, a revoke, or an incident response.')
    , (N'auth', N'TABLE', N'UserSession', N'EndReason',           N'Why it ended -- a short token: SignedOut, IdleExpired, AbsoluteExpired, Revoked, PasswordChanged, UserDeactivated. Set with EndedUtc, once. Never shown to a signed-out user, who is told only that they must sign in again.');

    -- The seven audit columns carry the same description on every table, so they are generated rather than typed out.
    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    SELECT N'auth', N'TABLE', t.TableName, c.ColumnName, c.Description
      FROM (VALUES (N'UserSession')) AS t (TableName)
     CROSS JOIN (VALUES
          (N'IsDeleted',            N'Soft-delete flag. 1 means the row is gone as far as the application is concerned; nothing in this database hard-deletes. NOT the same thing as EndedUtc: an ended session is history, a deleted one is a mistake being tidied.')
        , (N'auditDeletedBy',       N'Who soft-deleted the row. NULL unless IsDeleted = 1 -- the pair is enforced by CK_<table>_DeletedPair.')
        , (N'auditDeletedDateUtc',  N'When the row was soft-deleted, UTC. NULL unless IsDeleted = 1.')
        , (N'auditCreatedBy',       N'Who inserted the row. Defaults to ORIGINAL_LOGIN (); a procedure sets it to the acting profile instead.')
        , (N'auditCreatedDateUtc',  N'When the row was inserted, UTC.')
        , (N'auditModifiedBy',      N'Who last updated the row, set by the AFTER UPDATE trigger from SESSION_CONTEXT (''AppUser'') or ORIGINAL_LOGIN ().')
        , (N'auditModifiedDateUtc', N'When the row was last updated, UTC, set by the AFTER UPDATE trigger.')
       ) AS c (ColumnName, Description);

    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    VALUES (N'auth', N'TRIGGER', N'trg_au_updt_UserSession', NULL, N'AFTER UPDATE audit stamp; the session''s identity and its issued absolute expiry made immutable; MfaSatisfied one-way; EndedUtc and EndReason write-once. E-50010.');

    DECLARE @RowNo    INT = 1
          , @MaxRowNo INT = (SELECT MAX (RowNo) FROM @Descriptions)
          , @dSchema  SYSNAME
          , @dType    SYSNAME
          , @dObject  SYSNAME
          , @dColumn  SYSNAME
          , @dText    NVARCHAR (3750);

    WHILE @RowNo <= @MaxRowNo
    BEGIN
        SELECT @dSchema = SchemaName
             , @dType   = ObjectType
             , @dObject = ObjectName
             , @dColumn = ColumnName
             , @dText   = Description
          FROM @Descriptions
         WHERE RowNo = @RowNo;

        EXEC util.uspSetObjectDescription
              @SchemaName  = @dSchema
            , @ObjectType  = @dType
            , @ObjectName  = @dObject
            , @Description = @dText
            , @ColumnName  = @dColumn;

        SET @RowNo = @RowNo + 1;
    END;
END
ELSE
BEGIN
    PRINT N'util.uspSetObjectDescription is absent. Descriptions were NOT applied. Run '
        + N'.claude/skills/ponytail-sql-objects/templates/extended-properties.sql and then re-run this script.';
END
GO


-- *** 4. Grants ***
--
-- DELIBERATELY EMPTY.  INV-11 again, and this table is the one where a SELECT grant is most obviously fatal: every live
-- session token hash in the estate, with the user it belongs to.  applicationRole reaches it only through ownership
-- chaining inside auth.uspCompleteLogin, auth.uspCompleteSsoLogin and auth.uspEndSession.  170_permissions.sql.
GO


-- *** 5. Closing report ***
DECLARE @Report TABLE
(
    RowNo    INT IDENTITY (1, 1) PRIMARY KEY,
    Severity INT             NOT NULL,
    Status   VARCHAR (10)    NOT NULL,
    Item     NVARCHAR (200)  NOT NULL,
    Detail   NVARCHAR (1000)     NULL
);

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (N'auth.UserSession', N'U') IS NULL THEN 1 ELSE 4 END
     , CASE WHEN OBJECT_ID (N'auth.UserSession', N'U') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Table auth.UserSession'
     , N'The capability a successful sign-in produces. Holds a hash of the token, never the token -- section 7.3.';

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN i.name IS NULL THEN 2 ELSE 4 END
     , CASE WHEN i.name IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Index ' + x.IndexName
     , x.Purpose
  FROM (VALUES (N'UX_auth_UserSession_TokenHash',   N'UNIQUE. The lookup every authenticated request performs.')
             , (N'IX_auth_UserSession_UserLive',    N'"Sign me out everywhere", and the administrative revoke. Filtered to live sessions.')
             , (N'IX_auth_UserSession_Expiry',      N'The expiry sweep, and the live-session count 950_verify_deployment.sql reports.')
             , (N'IX_auth_UserSession_LoginAttempt', N'Which session came out of which exchange -- the audit chain read backwards.'))
       AS x (IndexName, Purpose)
  LEFT JOIN sys.indexes AS i ON i.name = x.IndexName AND i.object_id = OBJECT_ID (N'auth.UserSession');

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (N'auth.trg_au_updt_UserSession', N'TR') IS NULL THEN 2 ELSE 4 END
     , CASE WHEN OBJECT_ID (N'auth.trg_au_updt_UserSession', N'TR') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Trigger auth.trg_au_updt_UserSession'
     , N'Identity and absolute expiry immutable; MfaSatisfied one-way; ending write-once. E-50010.';

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN EXISTS (SELECT 1 FROM sys.check_constraints
                          WHERE name = N'CK_auth_UserSession_BypassNeedsMfa'
                            AND parent_object_id = OBJECT_ID (N'auth.UserSession'))
            THEN 4 ELSE 1 END
     , CASE WHEN EXISTS (SELECT 1 FROM sys.check_constraints
                          WHERE name = N'CK_auth_UserSession_BypassNeedsMfa'
                            AND parent_object_id = OBJECT_ID (N'auth.UserSession'))
            THEN 'OK' ELSE 'VIOLATION' END
     , N'INV-08 holds on the session row, not only on history'
     , N'A bypass-route session with MfaSatisfied = 0 cannot exist. The same invariant is enforced on '
     + N'auth.LoginAttempt, but that row is history: this is the row every later authorization check reads.';

-- Three states, not two.  PENDING is only legitimate while auth.UserProfile is absent; once it exists, a missing key is
-- a VIOLATION, because section 1 of this file should have added it on this very run.  The old version of this row read
-- the key's absence as a phase boundary unconditionally, which is why it reported PENDING on a Phase 3 database for a
-- whole phase and nobody acted -- BL-049.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = N'FK_auth_UserSession_UserProfile') THEN 4
            WHEN OBJECT_ID (N'auth.UserProfile', N'U') IS NULL                                           THEN 3
            ELSE 1 END
     , CASE WHEN EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = N'FK_auth_UserSession_UserProfile') THEN 'OK'
            WHEN OBJECT_ID (N'auth.UserProfile', N'U') IS NULL                                           THEN 'PENDING'
            ELSE 'VIOLATION' END
     , N'FK_auth_UserSession_UserProfile'
     , CASE WHEN EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = N'FK_auth_UserSession_UserProfile')
            THEN N'Present and trusted. auth.UserProfile exists and ActiveUserProfileId is constrained.'
            WHEN OBJECT_ID (N'auth.UserProfile', N'U') IS NULL
            THEN N'NOT CREATED, and not expected yet: auth.UserProfile is Phase 3 task T-046. Until then '
               + N'ActiveUserProfileId is always NULL and a session can authenticate a person while authorizing '
               + N'nothing they do. Section 1 adds the key -- WITH CHECK, deliberately -- as soon as the parent exists.'
            ELSE N'MISSING ON A DATABASE THAT HAS auth.UserProfile. ActiveUserProfileId is unconstrained, so a session '
               + N'can name a profile that does not exist -- which is the state auth.uspSetSessionContext trusts the '
               + N'row not to be in. Section 1 of this file adds the key; if this row is showing, that ALTER did not '
               + N'apply and the transcript above says why.'
       END;

INSERT @Report (Severity, Status, Item, Detail)
SELECT 3, 'INFO', N'Sessions'
     , CASE WHEN COUNT (*) = 0
            THEN N'None. Expected: this script seeds nothing and only auth.uspCompleteLogin or '
               + N'auth.uspCompleteSsoLogin can create one.'
            ELSE CAST (COUNT (*) AS NVARCHAR (10)) + N' session row(s), of which '
               + CAST (SUM (CASE WHEN EndedUtc IS NULL THEN 1 ELSE 0 END) AS NVARCHAR (10))
               + N' not ended and '
               + CAST (SUM (CASE WHEN EndedUtc IS NULL AND IdleExpiryUtc <= SYSUTCDATETIME () THEN 1 ELSE 0 END)
                       AS NVARCHAR (10))
               + N' idle-expired but not yet swept.'
       END
  FROM auth.UserSession
 WHERE IsDeleted = 0;

INSERT @Report (Severity, Status, Item, Detail)
VALUES (3, 'NEXT', N'Next scripts'
      , N'085_logs_auth_tables.sql (logs.AuthenticationEvent), then 100_auth_functions.sql '
      + N'(auth.udfResolveAuthPolicy, auth.udfIsUserUsable) and 110_auth_authn_procedures.sql.');

IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
    PRINT N'auth.UserSession: PROBLEMS found. Read the report below before running the next script.';
ELSE
    PRINT N'auth.UserSession: no problems found.';

PRINT N'';

SELECT Severity, Status, Item, Detail
  FROM @Report
 ORDER BY Severity, RowNo;
GO
