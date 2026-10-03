/***********************************************************************************************************************
Script:         085_logs_auth_tables.sql
Purpose:        The four durable, append-only trails of section 15.5:
                  logs.AuthenticationEvent  -- what happened to an ACCOUNT (Phase 2, T-033)
                  logs.AuthorizationChange  -- who granted WHAT to WHOM, under whose authority (T-055, P-08)
                  logs.AuthorizationDenial  -- what was refused, to whom, where (T-055)
                  logs.DataChangeLog        -- which business ROW changed, and how (T-055, D-12)
Target:         SQL Server 2022.
Run as:         db_owner in the target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/085_logs_auth_tables.sql
Idempotent:     Yes.  Every CREATE is guarded, every trigger is CREATE OR ALTER, nothing is dropped, nothing is seeded.
Depends on:     005_schemas_and_roles.sql (schema logs), 030_auth_tenant.sql (auth.Application, auth.Tenant),
                040_auth_userprofile.sql (auth.User, auth.UserProfile), 045_auth_identity.sql (auth.LoginAttempt),
                055_auth_role.sql (auth.Role), 070_auth_session.sql (auth.UserSession),
                templates/extended-properties.sql.
Implements:     DES-AUTH-001 sections 7.4, 10.5, 15.5, 19.2 and 19.3.  PLAN-AUTH-001 tasks T-033, T-055 and the
                logs.AuthenticationEvent half of T-066 (the MaintenanceBypass vocabulary).
To retarget:    Pass it per run:  sqlcmd -d <database> -v DbName=<database>.  There is no in-file default.

WHY THIS TABLE EXISTS WHEN auth.LoginAttempt ALREADY DOES
--------------------------------------------------------
This is the first question a reviewer asks and the design is wrong if it cannot be answered.  The two tables record
different kinds of thing and have different lifetimes.

auth.LoginAttempt is OPERATIONAL STATE.  It is the sign-in exchange itself: one row, updated as the exchange proceeds
(D-14), read on every attempt to compute both lockout counts, and needed only for as long as the lockout window plus
whatever retention an incident review wants.  It is narrow, hot, and indexed for two specific counting queries.

logs.AuthenticationEvent is the NARRATIVE.  It is append-only, it is never read by the authentication path, and it
records the things that are not sign-in attempts at all: a password changed, a factor enrolled, a recovery code
redeemed, a lockout applied, a session revoked by an administrator, an exchange abandoned.  None of those has a row in
auth.LoginAttempt, and all of them are the first things anybody asks for after an incident.

Concretely: truncating a year of auth.LoginAttempt would be a reasonable retention decision and would cost nothing
operationally.  Doing the same here would destroy the only record that a factor was removed the day before the account
was used to sign in from somewhere new.

WHY IT IS IN logs AND NOT logsData
---------------------------------
logsData holds the high-volume machine-written tables the platform generates for itself -- logsData.DdlChange gains 122
rows on every deployment pass.  logs holds the tables a human reads: logs.ExecutionLog, and now this.  The distinction
is who the audience is, and it decides the permission story: logsAuditReader is granted SELECT on SCHEMA::logs and
reads this table directly, without a procedure and without needing anything on SCHEMA::auth.

That is the whole reason this table can be read at all.  Every table in 045 and 070 is behind INV-11's wall; an auditor
who needs to answer "what happened to this account" cannot be given SELECT on auth.UserCredential to find out.  So the
narrative lives where it can be read, and it is written so that nothing in it is dangerous to read.

NOTHING SECRET GOES IN HERE, AND THAT IS A RULE ABOUT DetailJson
--------------------------------------------------------------
No verifier, no PHC string, no token, no token hash, no MFA secret, no ciphertext, no recovery code, no recovery-code
hash.  DetailJson takes the shape of an event -- which policy was resolved, which threshold was crossed, which factor
type was involved, which end reason was used -- and never the material.

The reason is the previous section.  This table is deliberately readable by a role that is deliberately denied
everything else, so anything put in here has escaped INV-11 by the front door.  A token hash written here to "help
correlation" would hand logsAuditReader the ability to identify a live session; the session identifier does that job
and is useless to anybody who cannot already read auth.UserSession.

EventType IS A CHECK CONSTRAINT, NOT A FREE STRING
-------------------------------------------------
An unconstrained event type becomes three spellings of the same event within a year -- 'LoginFailed', 'Login_Failed',
'loginFailure' -- and every report and alert built on it silently under-counts.  A CHECK constraint makes adding an
event type a deliberate schema change with a reviewer, which is the correct cost.  The set is listed in the constraint
and in the column description.

The trade is that a deployment which wants a new event type must alter the constraint.  That is accepted: the
alternative trades a one-line ALTER for reports nobody can trust.

EVERY FOREIGN KEY HERE IS NULLABLE, DELIBERATELY
----------------------------------------------
An event about a user name that does not exist has no UserId -- and those are the events an enumeration probe generates,
which are the events most worth having (section 19.2).  An event raised before an application could be resolved has no
ApplicationId.  A lockout applied by a sweep has no session.  A table that could only record events with every parent
present would be a table that lost exactly the events that matter.

The cost is that a query here must tolerate NULL, and UserName is carried as a string alongside UserId so that the
unresolvable cases are still attributable to something.

THE THREE AUTHORIZATION TRAILS ARRIVED WITH T-055, AND THEY ANSWER THREE DIFFERENT QUESTIONS
------------------------------------------------------------------------------------------
The temptation was one table with a Kind column.  It was refused because the three have different columns, different
volumes and different audiences, and a single table would have been mostly NULL, hot, and indexed for nobody.

logs.AuthorizationChange is the AUTHORITY trail.  Low volume, very long retention, read by a human being reviewing a
disputed grant.  Section 2 of the design puts it plainly: the audit columns say a row changed, this says who granted what
to whom.  Its whole reason for existing beyond the audit columns is ActorAuthorityTenantId -- P-08.

logs.AuthorizationDenial is the OPERATIONAL trail.  Higher volume, short retention, read by a dashboard.  A denial is not
an incident on its own; a hundred denials of the same permission in an hour is either a misconfigured role or somebody
probing, and both are worth a graph.

logs.DataChangeLog is the BUSINESS trail.  Highest volume of the three, written by domain procedures, and about rows
rather than about authority.  D-12: written by procedures and not by a generic audit trigger, because P-11 guarantees
every change arrives through one and the procedure knows which columns actually matter.

WHAT MAKES ActorAuthorityTenantId THE POINT OF logs.AuthorizationChange (P-08)
---------------------------------------------------------------------------
Every other column on that table records WHAT was done.  This one records WHY THE ACTOR WAS ALLOWED TO DO IT: the tenant
at which the actor's own grant of Authz.RoleAssign was held when they relied on it.

Without it, a review of a disputed grant six months later can establish that Smith granted EDITOR at Anne Arundel and
cannot establish whether Smith was entitled to.  Smith's authority may since have been revoked, re-granted at a different
scope, or inherited from a tenant that has been reparented -- and auth.ProfilePermissionScope is DERIVED, so it holds
today's answer and no history at all.  Recording the authority at the moment it was exercised is the only way the
question stays answerable, and it costs one INT.

A NULL there is meaningful rather than missing, and there are exactly two legitimate causes: the bootstrap
(115_seed_reference_data.sql attributes the root's own grants to ActorUserProfileId = NULL, section 16.1), and a platform
administrator acting under a Platform permission -- which is not tenant-scoped, so there is no authority tenant to record.
The closing report counts rows with an actor and no authority tenant so the second case stays visible instead of looking
like a bug.

A DENIAL RECORDED INSIDE SOMEBODY ELSE'S TRANSACTION CAN BE ROLLED BACK, AND THE CALL ORDER IS WHAT SAVES IT
----------------------------------------------------------------------------------------------------------
logs.AuthorizationDenial is written by auth.uspDemandPermission immediately before it raises E-50030.  If the caller were
inside an open transaction, the raise would abort it and the denial row would go with it -- the same mechanism that leaves
gaps in logs.ExecutionLog identity values.

Section 9's call order is what prevents it: the permission check is step 5 and the work is step 6, so a procedure that
follows the pattern demands its permission BEFORE it opens a transaction, and the denial is committed on its own.  A
procedure that demands a permission halfway through a transaction loses the record of the refusal.  That is a real and
accepted limitation -- the alternative is a loopback connection or a queue, both of which cost more than the trail is
worth -- and the reason it is written here is so that nobody discovers it while wondering where a denial went.

PermissionCode IS A STRING HERE AND NOT A FOREIGN KEY, FOR THE SAME REASON UserName IS
------------------------------------------------------------------------------------
A denial for N'Data.Aprove' is a denial worth seeing, and a foreign key to auth.Permission would refuse to record it --
turning a typo in a procedure into a row nobody can find while the procedure quietly fails for everybody.  The codes that
do not resolve are exactly the ones worth a dashboard.

logs.DataChangeLog CARRIES NO TenantId, AND THAT IS DELIBERATE
------------------------------------------------------------
Section 15.5 does not give it one, and adding one would have two consequences.  It would make the table look
tenant-scoped, which invites a row in config.TenantScopedTable and an RLS policy -- and an audit trail that hides rows
from the auditor is not an audit trail.  And it would put a TenantId column in a schema 950_verify_deployment.sql scans
for exactly that (section 10.1), producing a permanent finding in the build.

The tenant of a changed row is in KeyJson if the domain procedure puts it there, which is where a row-identifying value
belongs.
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

IF SCHEMA_ID (N'logs') IS NULL
BEGIN
    DECLARE @MsgSchema NVARCHAR (2000) =
        N'Schema [logs] does not exist. Run database/005_schemas_and_roles.sql first. Nothing has been changed.';

    THROW 50000, @MsgSchema, 1;
END
GO

IF OBJECT_ID (N'auth.User', N'U') IS NULL
   OR OBJECT_ID (N'auth.LoginAttempt', N'U') IS NULL
   OR OBJECT_ID (N'auth.UserSession', N'U') IS NULL
BEGIN
    DECLARE @MsgParents NVARCHAR (2000) =
        N'Tables auth.User, auth.LoginAttempt and auth.UserSession must all exist. Run database/040_auth_userprofile.sql, '
      + N'database/045_auth_identity.sql and database/070_auth_session.sql first. Nothing has been changed.';

    THROW 50000, @MsgParents, 1;
END
GO

-- Added with T-055, for the three authorization trails.  auth.Role is the Phase 3 table this file did not need before,
-- and auth.UserProfile is the parent of four of the new foreign keys -- two on one table, which is what makes a disputed
-- grant reviewable at all (the target and the actor).
IF OBJECT_ID (N'auth.UserProfile', N'U') IS NULL
   OR OBJECT_ID (N'auth.Role', N'U') IS NULL
   OR OBJECT_ID (N'auth.Tenant', N'U') IS NULL
BEGIN
    DECLARE @MsgAuthzParents NVARCHAR (2000) =
        N'Tables auth.UserProfile, auth.Role and auth.Tenant must all exist. Run database/030_auth_tenant.sql, '
      + N'database/040_auth_userprofile.sql and database/055_auth_role.sql first -- logs.AuthorizationChange references '
      + N'all three. Nothing has been changed.';

    THROW 50000, @MsgAuthzParents, 1;
END
GO


-- *** 1. logs.AuthenticationEvent ***
IF OBJECT_ID (N'logs.AuthenticationEvent', N'U') IS NULL
BEGIN
    CREATE TABLE logs.AuthenticationEvent
    (
        AuthenticationEventId BIGINT         IDENTITY (1, 1) NOT NULL
      , EventUtc             DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_logs_AuthenticationEvent_EventUtc DEFAULT (SYSUTCDATETIME ())
      , EventType            VARCHAR (40)                    NOT NULL
      , EventSeverity        VARCHAR (10)                    NOT NULL
            CONSTRAINT DF_logs_AuthenticationEvent_EventSeverity DEFAULT ('Info')
      , ApplicationId        INT                                 NULL
      , UserId               INT                                 NULL
      , UserName             NVARCHAR (256)                      NULL
      , LoginAttemptId       BIGINT                              NULL
      , UserSessionId        BIGINT                              NULL
      , ClientAddress        NVARCHAR (45)                       NULL
      , Actor                NVARCHAR (255)                  NOT NULL
            CONSTRAINT DF_logs_AuthenticationEvent_Actor DEFAULT (ORIGINAL_LOGIN ())
      , DetailJson           NVARCHAR (MAX)                      NULL
      , IsDeleted            BIT                             NOT NULL
            CONSTRAINT DF_logs_AuthenticationEvent_IsDeleted DEFAULT (0)
      , auditDeletedBy       NVARCHAR (255)                      NULL
      , auditDeletedDateUtc  DATETIME2 (3)                       NULL
      , auditCreatedBy       NVARCHAR (255)                  NOT NULL
            CONSTRAINT DF_logs_AuthenticationEvent_auditCreatedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditCreatedDateUtc  DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_logs_AuthenticationEvent_auditCreatedDateUtc DEFAULT (SYSUTCDATETIME ())
      , auditModifiedBy      NVARCHAR (255)                  NOT NULL
            CONSTRAINT DF_logs_AuthenticationEvent_auditModifiedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditModifiedDateUtc DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_logs_AuthenticationEvent_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ())
      , CONSTRAINT PK_logs_AuthenticationEvent PRIMARY KEY CLUSTERED (AuthenticationEventId)
      -- Every one of these is nullable on purpose.  See the header: a table that could only record events with every
      -- parent present would lose exactly the events an enumeration probe generates.
      , CONSTRAINT FK_logs_AuthenticationEvent_Application
            FOREIGN KEY (ApplicationId) REFERENCES auth.Application (ApplicationId)
      , CONSTRAINT FK_logs_AuthenticationEvent_User
            FOREIGN KEY (UserId) REFERENCES auth.[User] (UserId)
      , CONSTRAINT FK_logs_AuthenticationEvent_LoginAttempt
            FOREIGN KEY (LoginAttemptId) REFERENCES auth.LoginAttempt (LoginAttemptId)
      , CONSTRAINT FK_logs_AuthenticationEvent_UserSession
            FOREIGN KEY (UserSessionId) REFERENCES auth.UserSession (UserSessionId)
      -- The closed set.  Adding one is an ALTER with a reviewer, which is the correct cost: an unconstrained event type
      -- becomes three spellings of the same event and every report built on it silently under-counts.
      , CONSTRAINT CK_logs_AuthenticationEvent_EventType
            CHECK (EventType IN ('LoginSucceeded', 'LoginFailed', 'LoginBlocked'
                               , 'SsoBegun', 'SsoSucceeded', 'SsoFailed'
                               , 'MfaChallenged', 'MfaSucceeded', 'MfaFailed', 'RecoveryCodeUsed'
                               , 'MfaEnrolled', 'MfaConfirmed', 'MfaRemoved'
                               , 'RecoveryCodesIssued', 'MfaKeyRotated', 'MfaEnrolmentRefused'
                               , 'LockoutApplied', 'LockoutCleared', 'AddressThrottled'
                               , 'PasswordChanged', 'PasswordReset', 'CredentialCreated', 'CredentialRetired'
                               , 'FederatedLinkAdded', 'FederatedLinkRemoved'
                               , 'SessionStarted', 'SessionEnded', 'SessionRevoked', 'SessionElevated'
                               , 'ExchangeExpired', 'PolicyResolutionFailed'
                               -- T-066, section 10.5.  The two halves of a maintenance bypass: who turned row-level
                               -- security off for their own connection, why, and when they turned it back on.  Section
                               -- 15.5's published list names MaintenanceBypass; the Ended half is this template's, and
                               -- it is here because a bypass window with no closing time is one nobody can review.
                               , 'MaintenanceBypass', 'MaintenanceBypassEnded'
                               -- T-078, section 12.1 step 6.  Section 15.5's published list names ProfileSwitch and this
                               -- constraint did not permit it, because the renaming that turned 'SignIn' into
                               -- 'LoginSucceeded' and 'StepUp' into 'SessionElevated' dropped it on the way past.  It
                               -- surfaced when auth.uspSwitchProfile was written four phases later; nothing had needed
                               -- the value before, so nothing had noticed.  A switch is the act of declaring which
                               -- organization you are working for (section 12.2), which makes it the one event in this
                               -- table that explains why a later insert landed in the tenant it did.  G-29, BL-055.
                               , 'ProfileSwitch'
                               -- T-112, section 16.2.  auth.uspExpireCredentials writes one of these per user it forces
                               -- a change on (G-12).  NOT 'CredentialRetired': the credential still verifies and the
                               -- next sign-in still succeeds with it -- what changed is that the sign-in now arrives
                               -- with MustChangePassword = 1.  Recording an expiry as a retirement would make the
                               -- report "how many credentials were withdrawn this month" wrong in the direction that
                               -- looks like diligence.
                               , 'CredentialExpired'))
      -- Three levels and no more.  'Alert' means somebody should look now; a fourth level in the middle is a level
      -- nobody can define the difference of, and it ends up meaning "the writer was unsure".
      , CONSTRAINT CK_logs_AuthenticationEvent_EventSeverity
            CHECK (EventSeverity IN ('Info', 'Warning', 'Alert'))
      , CONSTRAINT CK_logs_AuthenticationEvent_UserName
            CHECK (UserName IS NULL OR LEN (UserName) > 0)
      , CONSTRAINT CK_logs_AuthenticationEvent_ClientAddress
            CHECK (ClientAddress IS NULL
               OR (LEN (ClientAddress) > 0 AND ClientAddress = LTRIM (RTRIM (ClientAddress))))
      , CONSTRAINT CK_logs_AuthenticationEvent_Actor
            CHECK (LEN (Actor) > 0)
      -- NVARCHAR (MAX) with an ISJSON check and NOT the native json type: that type is SQL Server 2025 and the floor --
      -- and the ceiling -- of this design is 2022.
      , CONSTRAINT CK_logs_AuthenticationEvent_DetailJson
            CHECK (DetailJson IS NULL OR ISJSON (DetailJson) = 1)
      -- An event that names neither a user nor a user name is an event nobody can attribute, and an unattributable
      -- security event is noise.  One of the two must be present; both is normal.
      , CONSTRAINT CK_logs_AuthenticationEvent_Attributable
            CHECK (UserId IS NOT NULL OR UserName IS NOT NULL)
      , CONSTRAINT CK_logs_AuthenticationEvent_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS     NULL AND auditDeletedDateUtc IS     NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL))
    );
END
GO

-- ADDING TO THE CLOSED SET, FOR A DATABASE THAT ALREADY HAS THE OLD ONE.  Task T-041 added three event types --
-- 'RecoveryCodesIssued', 'MfaKeyRotated' and 'MfaEnrolmentRefused' -- and the CREATE TABLE above only runs where the
-- table does not exist, so without this block a database built by an earlier run of this script would refuse them from
-- 112_auth_mfa_procedures.sql at INSERT time, with error 547 and no clue as to which script was out of step.
--
-- The guard is the constraint's own DEFINITION TEXT, not a version number.  That is the one thing that cannot drift: if
-- the list inline above gains a value and this list does not, the next deployment against an existing database drops the
-- constraint, adds THIS list, and the closing report's assertion below fails -- loudly, in the transcript, rather than
-- six months later at an INSERT.  Two copies of a closed vocabulary is the cost of being able to extend it at all; the
-- inline copy stays because the table definition is where a reader looks for it.
--
-- WITH CHECK, so the existing rows are validated: adding values can only widen the set, so this cannot fail unless
-- somebody has already written a value the new list does not contain either -- which is worth knowing.
IF EXISTS (SELECT 1 FROM sys.check_constraints
            WHERE name             = N'CK_logs_AuthenticationEvent_EventType'
              AND parent_object_id = OBJECT_ID (N'logs.AuthenticationEvent')
              AND (definition NOT LIKE N'%RecoveryCodesIssued%' OR definition NOT LIKE N'%MfaKeyRotated%'
                OR definition NOT LIKE N'%MfaEnrolmentRefused%'
                OR definition NOT LIKE N'%MaintenanceBypass%'  OR definition NOT LIKE N'%MaintenanceBypassEnded%'
                OR definition NOT LIKE N'%ProfileSwitch%'      OR definition NOT LIKE N'%CredentialExpired%'))
BEGIN
    ALTER TABLE logs.AuthenticationEvent DROP CONSTRAINT CK_logs_AuthenticationEvent_EventType;

    PRINT N'CK_logs_AuthenticationEvent_EventType predated T-041, T-066, T-078 or T-112 and did not permit all of '
        + N'RecoveryCodesIssued, MfaKeyRotated, MfaEnrolmentRefused, MaintenanceBypass, MaintenanceBypassEnded, '
        + N'ProfileSwitch and CredentialExpired. It has been replaced with the current vocabulary. No row was changed.';
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.check_constraints
                WHERE name             = N'CK_logs_AuthenticationEvent_EventType'
                  AND parent_object_id = OBJECT_ID (N'logs.AuthenticationEvent'))
BEGIN
    ALTER TABLE logs.AuthenticationEvent WITH CHECK
        ADD CONSTRAINT CK_logs_AuthenticationEvent_EventType
            CHECK (EventType IN ('LoginSucceeded', 'LoginFailed', 'LoginBlocked'
                               , 'SsoBegun', 'SsoSucceeded', 'SsoFailed'
                               , 'MfaChallenged', 'MfaSucceeded', 'MfaFailed', 'RecoveryCodeUsed'
                               , 'MfaEnrolled', 'MfaConfirmed', 'MfaRemoved'
                               , 'RecoveryCodesIssued', 'MfaKeyRotated', 'MfaEnrolmentRefused'
                               , 'LockoutApplied', 'LockoutCleared', 'AddressThrottled'
                               , 'PasswordChanged', 'PasswordReset', 'CredentialCreated', 'CredentialRetired'
                               , 'FederatedLinkAdded', 'FederatedLinkRemoved'
                               , 'SessionStarted', 'SessionEnded', 'SessionRevoked', 'SessionElevated'
                               , 'ExchangeExpired', 'PolicyResolutionFailed'
                               -- T-066, section 10.5.  Kept in step with the inline list in section 1 -- the closing
                               -- report asserts both halves of the bypass are permitted.
                               , 'MaintenanceBypass', 'MaintenanceBypassEnded'
                               -- T-078, section 12.1 step 6.  See the inline list in section 1 for why it was missing.
                               , 'ProfileSwitch'
                               -- T-112, G-12.  auth.uspExpireCredentials. See the inline list for why this is not
                               -- 'CredentialRetired'.
                               , 'CredentialExpired'));
END
GO

-- "What happened, most recent first" -- the read every incident starts with.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_logs_AuthenticationEvent_When'
                  AND object_id = OBJECT_ID (N'logs.AuthenticationEvent'))
BEGIN
    CREATE INDEX IX_logs_AuthenticationEvent_When
        ON logs.AuthenticationEvent (EventUtc DESC) WHERE IsDeleted = 0;
END
GO

-- "What happened to this account" -- the read the second question asks.  On UserId, so it sees only the events that
-- resolved to a real person; the unresolvable ones are found through the name index below.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_logs_AuthenticationEvent_User'
                  AND object_id = OBJECT_ID (N'logs.AuthenticationEvent'))
BEGIN
    CREATE INDEX IX_logs_AuthenticationEvent_User
        ON logs.AuthenticationEvent (UserId, EventUtc DESC) WHERE UserId IS NOT NULL AND IsDeleted = 0;
END
GO

-- "Who has been trying names that do not exist" -- the enumeration-probe read, which by definition has no UserId.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_logs_AuthenticationEvent_UnknownName'
                  AND object_id = OBJECT_ID (N'logs.AuthenticationEvent'))
BEGIN
    CREATE INDEX IX_logs_AuthenticationEvent_UnknownName
        ON logs.AuthenticationEvent (UserName, EventUtc DESC) WHERE UserId IS NULL AND IsDeleted = 0;
END
GO

-- The alert feed.  Filtered so the index holds only the rows anybody is paged about, which on a healthy deployment is
-- almost none of them.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_logs_AuthenticationEvent_Alert'
                  AND object_id = OBJECT_ID (N'logs.AuthenticationEvent'))
BEGIN
    CREATE INDEX IX_logs_AuthenticationEvent_Alert
        ON logs.AuthenticationEvent (EventUtc DESC, EventType)
        WHERE EventSeverity = 'Alert' AND IsDeleted = 0;
END
GO

-- "Everything that happened in this one exchange", which is how a support call about a failed sign-in is answered.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_logs_AuthenticationEvent_LoginAttempt'
                  AND object_id = OBJECT_ID (N'logs.AuthenticationEvent'))
BEGIN
    CREATE INDEX IX_logs_AuthenticationEvent_LoginAttempt
        ON logs.AuthenticationEvent (LoginAttemptId) WHERE LoginAttemptId IS NOT NULL AND IsDeleted = 0;
END
GO


-- *** 2. Audit trigger ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   logs.trg_au_updt_AuthenticationEvent
Author:       rsincero
CreateDate:   2026-09-19
Description:
AFTER UPDATE audit stamp for logs.AuthenticationEvent, and the guard that makes the whole row immutable -- E-50010.

APPEND-ONLY MEANS APPEND-ONLY.  Every column here is a statement about something that already happened, so there is
nothing on the row an UPDATE could legitimately correct: a wrong event is a wrong event, and the right response is
another event saying so, not a rewrite that leaves no sign it happened.

IsDeleted is the single exception, and it is not an escape hatch -- a soft-deleted event is still in the table, still
readable by logsAuditReader, and still carries who deleted it and when.  Nothing in this database hard-deletes, so there
is no statement anybody can issue that makes a row here go away.

This is the strictest trigger in the deployment, and it is on the table whose whole value is that it can be trusted.

Modification History:
2026-09-19  rsincero  Created.  PLAN-AUTH-001 T-033.
***********************************************************************************************************************/
CREATE OR ALTER TRIGGER logs.trg_au_updt_AuthenticationEvent
    ON logs.AuthenticationEvent
    AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    IF EXISTS (SELECT 1
                 FROM inserted AS i
                 JOIN deleted  AS d ON d.AuthenticationEventId = i.AuthenticationEventId
                WHERE i.EventUtc <> d.EventUtc
                   OR i.EventType <> d.EventType
                   OR i.EventSeverity <> d.EventSeverity
                   OR i.Actor <> d.Actor
                   OR ISNULL (i.ApplicationId, -1) <> ISNULL (d.ApplicationId, -1)
                   OR ISNULL (i.UserId, -1) <> ISNULL (d.UserId, -1)
                   OR ISNULL (i.UserName, N'~') <> ISNULL (d.UserName, N'~')
                   OR ISNULL (i.LoginAttemptId, -1) <> ISNULL (d.LoginAttemptId, -1)
                   OR ISNULL (i.UserSessionId, -1) <> ISNULL (d.UserSessionId, -1)
                   OR ISNULL (i.ClientAddress, N'~') <> ISNULL (d.ClientAddress, N'~')
                   OR ISNULL (i.DetailJson, N'~') <> ISNULL (d.DetailJson, N'~'))
    BEGIN
        ;THROW 50010, N'logs.AuthenticationEvent is append-only: every column on it is a statement about something that already happened, and the right response to a wrong event is another event saying so, not a rewrite that leaves no sign it happened. Only IsDeleted may change.', 1;
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
      FROM logs.AuthenticationEvent AS t
      JOIN inserted AS i ON i.AuthenticationEventId = t.AuthenticationEventId
      JOIN deleted  AS d ON d.AuthenticationEventId = t.AuthenticationEventId;
END;
GO


-- *** 3. logs.AuthorizationChange ***
-- The authority trail.  Low volume, long retention, and the one table in this database that answers "was this person
-- entitled to do that" after the answer has stopped being derivable -- see the header on P-08.
IF OBJECT_ID (N'logs.AuthorizationChange', N'U') IS NULL
BEGIN
    CREATE TABLE logs.AuthorizationChange
    (
        AuthorizationChangeId  BIGINT        IDENTITY (1, 1) NOT NULL
      , OccurredUtc            DATETIME2 (3)                 NOT NULL
            CONSTRAINT DF_logs_AuthorizationChange_OccurredUtc DEFAULT (SYSUTCDATETIME ())
      , ChangeType             VARCHAR (40)                  NOT NULL
      , TargetUserId           INT                               NULL
      , TargetUserProfileId    INT                               NULL
      , RoleId                 INT                               NULL
      , ScopeTenantId          INT                               NULL
      , ActorUserProfileId     INT                               NULL
      , ActorAuthorityTenantId INT                               NULL
      , DetailJson             NVARCHAR (MAX)                    NULL
      , IsDeleted              BIT                           NOT NULL
            CONSTRAINT DF_logs_AuthorizationChange_IsDeleted DEFAULT (0)
      , auditDeletedBy         NVARCHAR (255)                    NULL
      , auditDeletedDateUtc    DATETIME2 (3)                     NULL
      , auditCreatedBy         NVARCHAR (255)                NOT NULL
            CONSTRAINT DF_logs_AuthorizationChange_auditCreatedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditCreatedDateUtc    DATETIME2 (3)                 NOT NULL
            CONSTRAINT DF_logs_AuthorizationChange_auditCreatedDateUtc DEFAULT (SYSUTCDATETIME ())
      , auditModifiedBy        NVARCHAR (255)                NOT NULL
            CONSTRAINT DF_logs_AuthorizationChange_auditModifiedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditModifiedDateUtc   DATETIME2 (3)                 NOT NULL
            CONSTRAINT DF_logs_AuthorizationChange_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ())
      , CONSTRAINT PK_logs_AuthorizationChange PRIMARY KEY CLUSTERED (AuthorizationChangeId)
      -- Six nullable foreign keys, for the same reason section 1 has four: a trail that could only record fully resolved
      -- events would lose the bootstrap, and the bootstrap is where the root's own authority comes from.
      , CONSTRAINT FK_logs_AuthorizationChange_TargetUser
            FOREIGN KEY (TargetUserId) REFERENCES auth.[User] (UserId)
      , CONSTRAINT FK_logs_AuthorizationChange_TargetUserProfile
            FOREIGN KEY (TargetUserProfileId) REFERENCES auth.UserProfile (UserProfileId)
      , CONSTRAINT FK_logs_AuthorizationChange_Role
            FOREIGN KEY (RoleId) REFERENCES auth.Role (RoleId)
      , CONSTRAINT FK_logs_AuthorizationChange_ScopeTenant
            FOREIGN KEY (ScopeTenantId) REFERENCES auth.Tenant (TenantId)
      , CONSTRAINT FK_logs_AuthorizationChange_ActorUserProfile
            FOREIGN KEY (ActorUserProfileId) REFERENCES auth.UserProfile (UserProfileId)
      , CONSTRAINT FK_logs_AuthorizationChange_ActorAuthorityTenant
            FOREIGN KEY (ActorAuthorityTenantId) REFERENCES auth.Tenant (TenantId)
      -- The closed set.  Some of these have no writer until Phase 6 (the administrative procedures) and two have none
      -- planned before Phase 7; they are here anyway, because the alternative is the drop-and-re-add convergence dance
      -- section 1 had to grow for three values, and a vocabulary is cheaper to agree on once.
      , CONSTRAINT CK_logs_AuthorizationChange_ChangeType
            CHECK (ChangeType IN ('RoleGranted', 'RoleRevoked', 'GrantExpiryChanged'
                                , 'RoleCreated', 'RoleModified', 'RoleRetired'
                                , 'RolePermissionAdded', 'RolePermissionRemoved'
                                , 'ProfileCreated', 'ProfileActivated', 'ProfileDeactivated', 'ProfileRetired'
                                , 'PlatformAdminGranted', 'PlatformAdminRevoked'
                                , 'TenantReparented', 'ScopeRebuilt'
                                -- G-43, sections 7.2, 7.3, 8.5 and 11.5.  The five verbs
                                -- auth.uspSetTenantAuthenticationPolicy and auth.uspSetTenantDefaultRoles write.  Kept
                                -- in step with the ALTER below -- the closing report asserts both halves.
                                , 'TenantPolicyChanged'
                                , 'TenantTrustedIssuerAdded',  'TenantTrustedIssuerRemoved'
                                , 'TenantDefaultRoleAdded',    'TenantDefaultRoleRemoved'))
      -- An authority change that names neither a person, a profile nor a role is a change nobody can review.  One of the
      -- three is enough: 'RoleModified' names a role and no person, 'PlatformAdminGranted' names a person and no role.
      --
      -- AND THEN THERE IS A FOURTH CASE, WHICH THIS CHECK MADE UNWRITABLE FOR AS LONG AS THE TABLE HAS EXISTED.  A change
      -- to a TENANT's own configuration names a tenant and nothing else: no person's authority moved, no profile was
      -- touched, no role was defined.  'TenantReparented' is in the vocabulary above and has been since the first cut,
      -- and it has never had a writer -- partly because auth.uspUpdateTenant predates the trail, and partly because this
      -- constraint would have refused the row if it had tried.  G-43's auth.uspSetTenantAuthenticationPolicy is the call
      -- that finally needed it, so ScopeTenantId joins the three, for the tenant-scoped verbs ONLY.
      --
      -- Restricted by ChangeType rather than widened to "any of four", because the original rule is right: a ROLE grant
      -- that named only a tenant would be exactly the unreviewable row this check exists to refuse, and a writer that
      -- forgot its TargetUserProfileId would then write one silently.  The list is short and deliberate; adding to it is
      -- a decision, which is the point.
      , CONSTRAINT CK_logs_AuthorizationChange_Attributable
            CHECK (TargetUserId        IS NOT NULL
                OR TargetUserProfileId IS NOT NULL
                OR RoleId              IS NOT NULL
                OR (ChangeType IN ('TenantReparented', 'TenantPolicyChanged'
                                 , 'TenantTrustedIssuerAdded', 'TenantTrustedIssuerRemoved', 'ScopeRebuilt')
                    AND ScopeTenantId IS NOT NULL))
      -- NVARCHAR (MAX) with ISJSON and not the native json type: that type is SQL Server 2025 and the floor -- and the
      -- ceiling -- of this design is 2022.  The same rule as section 1 applies to the contents: shape, never material.
      , CONSTRAINT CK_logs_AuthorizationChange_DetailJson
            CHECK (DetailJson IS NULL OR ISJSON (DetailJson) = 1)
      , CONSTRAINT CK_logs_AuthorizationChange_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS     NULL AND auditDeletedDateUtc IS     NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL))
    );
END
GO

-- ADDING TO THE CLOSED SET AND WIDENING THE ATTRIBUTION RULE, FOR A DATABASE THAT ALREADY HAS THE OLD ONES.  Exactly
-- section 1's dance, for the same reason and with the same guard: the CREATE TABLE above only runs where the table does
-- not exist, so a database built by an earlier run would refuse G-43's five new verbs at INSERT time with error 547.
--
-- The Attributable half is the part worth reading twice.  Its original text -- TargetUserId OR TargetUserProfileId OR
-- RoleId -- makes a row that names only a TENANT impossible, which is why 'TenantReparented' has been in the vocabulary
-- since the first cut with nothing able to write it.  auth.uspSetTenantAuthenticationPolicy writes precisely that shape:
-- a policy changed at a tenant, attributable to no person and no role.  So the check gains a fourth branch, restricted to
-- the tenant-scoped verbs.
--
-- WITH CHECK on both, so existing rows are validated.  Neither can fail: the ChangeType list only gains values, and the
-- Attributable rule only gains a branch, so every row that satisfied the old constraint satisfies the new one.  If one
-- does fail, something has written a row neither rule permits and that is worth stopping for.
IF EXISTS (SELECT 1 FROM sys.check_constraints
            WHERE name             = N'CK_logs_AuthorizationChange_ChangeType'
              AND parent_object_id = OBJECT_ID (N'logs.AuthorizationChange')
              AND (definition NOT LIKE N'%TenantPolicyChanged%'
                OR definition NOT LIKE N'%TenantTrustedIssuerAdded%'
                OR definition NOT LIKE N'%TenantTrustedIssuerRemoved%'
                OR definition NOT LIKE N'%TenantDefaultRoleAdded%'
                OR definition NOT LIKE N'%TenantDefaultRoleRemoved%'))
BEGIN
    ALTER TABLE logs.AuthorizationChange DROP CONSTRAINT CK_logs_AuthorizationChange_ChangeType;

    PRINT N'CK_logs_AuthorizationChange_ChangeType predated G-43 and did not permit TenantPolicyChanged, '
        + N'TenantTrustedIssuerAdded, TenantTrustedIssuerRemoved, TenantDefaultRoleAdded or TenantDefaultRoleRemoved. '
        + N'It has been replaced with the current vocabulary. No row was changed.';
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.check_constraints
                WHERE name             = N'CK_logs_AuthorizationChange_ChangeType'
                  AND parent_object_id = OBJECT_ID (N'logs.AuthorizationChange'))
BEGIN
    ALTER TABLE logs.AuthorizationChange WITH CHECK
        ADD CONSTRAINT CK_logs_AuthorizationChange_ChangeType
            CHECK (ChangeType IN ('RoleGranted', 'RoleRevoked', 'GrantExpiryChanged'
                                , 'RoleCreated', 'RoleModified', 'RoleRetired'
                                , 'RolePermissionAdded', 'RolePermissionRemoved'
                                , 'ProfileCreated', 'ProfileActivated', 'ProfileDeactivated', 'ProfileRetired'
                                , 'PlatformAdminGranted', 'PlatformAdminRevoked'
                                , 'TenantReparented', 'ScopeRebuilt'
                                -- G-43.  Kept in step with the inline list in section 3.
                                , 'TenantPolicyChanged'
                                , 'TenantTrustedIssuerAdded',  'TenantTrustedIssuerRemoved'
                                , 'TenantDefaultRoleAdded',    'TenantDefaultRoleRemoved'));
END
GO

IF EXISTS (SELECT 1 FROM sys.check_constraints
            WHERE name             = N'CK_logs_AuthorizationChange_Attributable'
              AND parent_object_id = OBJECT_ID (N'logs.AuthorizationChange')
              AND definition NOT LIKE N'%ScopeTenantId%')
BEGIN
    ALTER TABLE logs.AuthorizationChange DROP CONSTRAINT CK_logs_AuthorizationChange_Attributable;

    PRINT N'CK_logs_AuthorizationChange_Attributable required a user, a profile or a role, which made a row naming only '
        + N'a TENANT impossible -- the reason the published TenantReparented verb never had a writer. It has been '
        + N'replaced with a rule that also accepts ScopeTenantId, for the tenant-scoped verbs only. No row was changed.';
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.check_constraints
                WHERE name             = N'CK_logs_AuthorizationChange_Attributable'
                  AND parent_object_id = OBJECT_ID (N'logs.AuthorizationChange'))
BEGIN
    ALTER TABLE logs.AuthorizationChange WITH CHECK
        ADD CONSTRAINT CK_logs_AuthorizationChange_Attributable
            CHECK (TargetUserId        IS NOT NULL
                OR TargetUserProfileId IS NOT NULL
                OR RoleId              IS NOT NULL
                OR (ChangeType IN ('TenantReparented', 'TenantPolicyChanged'
                                 , 'TenantTrustedIssuerAdded', 'TenantTrustedIssuerRemoved', 'ScopeRebuilt')
                    AND ScopeTenantId IS NOT NULL));
END
GO

-- "What has changed lately" -- the read a periodic authority review starts with.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_logs_AuthorizationChange_When'
                  AND object_id = OBJECT_ID (N'logs.AuthorizationChange'))
BEGIN
    CREATE INDEX IX_logs_AuthorizationChange_When
        ON logs.AuthorizationChange (OccurredUtc DESC) WHERE IsDeleted = 0;
END
GO

-- "How did this person come to have this" -- the read a disputed grant starts with, and the reason the table exists.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_logs_AuthorizationChange_Target'
                  AND object_id = OBJECT_ID (N'logs.AuthorizationChange'))
BEGIN
    CREATE INDEX IX_logs_AuthorizationChange_Target
        ON logs.AuthorizationChange (TargetUserProfileId, OccurredUtc DESC)
        INCLUDE (ChangeType, RoleId, ScopeTenantId, ActorUserProfileId, ActorAuthorityTenantId)
        WHERE TargetUserProfileId IS NOT NULL AND IsDeleted = 0;
END
GO

-- "What has this administrator been doing" -- the read that finds an account handing out authority it should not have.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_logs_AuthorizationChange_Actor'
                  AND object_id = OBJECT_ID (N'logs.AuthorizationChange'))
BEGIN
    CREATE INDEX IX_logs_AuthorizationChange_Actor
        ON logs.AuthorizationChange (ActorUserProfileId, OccurredUtc DESC)
        INCLUDE (ChangeType, TargetUserProfileId, RoleId, ScopeTenantId)
        WHERE ActorUserProfileId IS NOT NULL AND IsDeleted = 0;
END
GO

-- "Who has ever held this role, and where" -- the read that follows a role whose permission set has just been widened.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_logs_AuthorizationChange_Role'
                  AND object_id = OBJECT_ID (N'logs.AuthorizationChange'))
BEGIN
    CREATE INDEX IX_logs_AuthorizationChange_Role
        ON logs.AuthorizationChange (RoleId, OccurredUtc DESC)
        INCLUDE (ChangeType, TargetUserProfileId, ScopeTenantId)
        WHERE RoleId IS NOT NULL AND IsDeleted = 0;
END
GO


-- *** 4. logs.AuthorizationDenial ***
-- The operational trail.  Denials only -- a grant that worked is not news, and recording the successes would multiply the
-- volume of this table by the traffic of the application for no reader.
IF OBJECT_ID (N'logs.AuthorizationDenial', N'U') IS NULL
BEGIN
    CREATE TABLE logs.AuthorizationDenial
    (
        AuthorizationDenialId BIGINT        IDENTITY (1, 1) NOT NULL
      , OccurredUtc           DATETIME2 (3)                 NOT NULL
            CONSTRAINT DF_logs_AuthorizationDenial_OccurredUtc DEFAULT (SYSUTCDATETIME ())
      , UserProfileId         INT                               NULL
      , PermissionCode        NVARCHAR (100)                NOT NULL
      , TenantId              INT                               NULL
      , ObjectName            NVARCHAR (256)                    NULL
      , DetailJson            NVARCHAR (MAX)                    NULL
      , IsDeleted             BIT                           NOT NULL
            CONSTRAINT DF_logs_AuthorizationDenial_IsDeleted DEFAULT (0)
      , auditDeletedBy        NVARCHAR (255)                    NULL
      , auditDeletedDateUtc   DATETIME2 (3)                     NULL
      , auditCreatedBy        NVARCHAR (255)                NOT NULL
            CONSTRAINT DF_logs_AuthorizationDenial_auditCreatedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditCreatedDateUtc   DATETIME2 (3)                 NOT NULL
            CONSTRAINT DF_logs_AuthorizationDenial_auditCreatedDateUtc DEFAULT (SYSUTCDATETIME ())
      , auditModifiedBy       NVARCHAR (255)                NOT NULL
            CONSTRAINT DF_logs_AuthorizationDenial_auditModifiedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditModifiedDateUtc  DATETIME2 (3)                 NOT NULL
            CONSTRAINT DF_logs_AuthorizationDenial_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ())
      , CONSTRAINT PK_logs_AuthorizationDenial PRIMARY KEY CLUSTERED (AuthorizationDenialId)
      -- Nullable: a demand made on a connection with no session context is refused, and THAT is the denial most worth
      -- seeing -- it means a procedure is reachable without auth.uspSetSessionContext having run.
      , CONSTRAINT FK_logs_AuthorizationDenial_UserProfile
            FOREIGN KEY (UserProfileId) REFERENCES auth.UserProfile (UserProfileId)
      , CONSTRAINT FK_logs_AuthorizationDenial_Tenant
            FOREIGN KEY (TenantId) REFERENCES auth.Tenant (TenantId)
      -- PermissionCode is a STRING and not a foreign key to auth.Permission.  See the header: a denial for a code that
      -- does not exist is a typo in a procedure, and a foreign key would refuse to record the one row that proves it.
      , CONSTRAINT CK_logs_AuthorizationDenial_PermissionCode
            CHECK (LEN (PermissionCode) > 0 AND PermissionCode = LTRIM (RTRIM (PermissionCode)))
      , CONSTRAINT CK_logs_AuthorizationDenial_ObjectName
            CHECK (ObjectName IS NULL OR LEN (ObjectName) > 0)
      , CONSTRAINT CK_logs_AuthorizationDenial_DetailJson
            CHECK (DetailJson IS NULL OR ISJSON (DetailJson) = 1)
      , CONSTRAINT CK_logs_AuthorizationDenial_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS     NULL AND auditDeletedDateUtc IS     NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL))
    );
END
GO

-- The dashboard read: "denials per hour", and the one that matters, "denials per hour, by permission".  Leading on time
-- because every question anybody asks of this table is bounded by a window first.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_logs_AuthorizationDenial_When'
                  AND object_id = OBJECT_ID (N'logs.AuthorizationDenial'))
BEGIN
    CREATE INDEX IX_logs_AuthorizationDenial_When
        ON logs.AuthorizationDenial (OccurredUtc DESC)
        INCLUDE (PermissionCode, UserProfileId, TenantId, ObjectName)
        WHERE IsDeleted = 0;
END
GO

-- "What is this person being refused" -- the support read, which is nearly always a missing role rather than an attack.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_logs_AuthorizationDenial_Profile'
                  AND object_id = OBJECT_ID (N'logs.AuthorizationDenial'))
BEGIN
    CREATE INDEX IX_logs_AuthorizationDenial_Profile
        ON logs.AuthorizationDenial (UserProfileId, OccurredUtc DESC)
        INCLUDE (PermissionCode, TenantId, ObjectName)
        WHERE UserProfileId IS NOT NULL AND IsDeleted = 0;
END
GO

-- "Which permission is being refused most" -- the read that finds a baseline role somebody forgot to grant, and the one
-- that finds a permission code no procedure spells correctly.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_logs_AuthorizationDenial_Permission'
                  AND object_id = OBJECT_ID (N'logs.AuthorizationDenial'))
BEGIN
    CREATE INDEX IX_logs_AuthorizationDenial_Permission
        ON logs.AuthorizationDenial (PermissionCode, OccurredUtc DESC)
        INCLUDE (UserProfileId, TenantId)
        WHERE IsDeleted = 0;
END
GO


-- *** 5. logs.DataChangeLog ***
-- The business trail.  Written by the domain procedures, never by a generic trigger -- D-12, and the header says why.
IF OBJECT_ID (N'logs.DataChangeLog', N'U') IS NULL
BEGIN
    CREATE TABLE logs.DataChangeLog
    (
        DataChangeLogId      BIGINT        IDENTITY (1, 1) NOT NULL
      , OccurredUtc          DATETIME2 (3)                 NOT NULL
            CONSTRAINT DF_logs_DataChangeLog_OccurredUtc DEFAULT (SYSUTCDATETIME ())
      , SchemaName           SYSNAME                       NOT NULL
      , TableName            SYSNAME                       NOT NULL
      , Operation            VARCHAR (20)                  NOT NULL
      , KeyJson              NVARCHAR (MAX)                NOT NULL
      , ChangedColumnsJson   NVARCHAR (MAX)                    NULL
      , ActorUserProfileId   INT                               NULL
      , IsDeleted            BIT                           NOT NULL
            CONSTRAINT DF_logs_DataChangeLog_IsDeleted DEFAULT (0)
      , auditDeletedBy       NVARCHAR (255)                    NULL
      , auditDeletedDateUtc  DATETIME2 (3)                     NULL
      , auditCreatedBy       NVARCHAR (255)                NOT NULL
            CONSTRAINT DF_logs_DataChangeLog_auditCreatedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditCreatedDateUtc  DATETIME2 (3)                 NOT NULL
            CONSTRAINT DF_logs_DataChangeLog_auditCreatedDateUtc DEFAULT (SYSUTCDATETIME ())
      , auditModifiedBy      NVARCHAR (255)                NOT NULL
            CONSTRAINT DF_logs_DataChangeLog_auditModifiedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditModifiedDateUtc DATETIME2 (3)                 NOT NULL
            CONSTRAINT DF_logs_DataChangeLog_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ())
      , CONSTRAINT PK_logs_DataChangeLog PRIMARY KEY CLUSTERED (DataChangeLogId)
      -- Nullable, and it will be NULL for anything a deployment script changes.  A migration is a change with no acting
      -- profile, and refusing to record it would mean the trail stops exactly where a data correction happened.
      , CONSTRAINT FK_logs_DataChangeLog_ActorUserProfile
            FOREIGN KEY (ActorUserProfileId) REFERENCES auth.UserProfile (UserProfileId)
      -- Four operations.  'SoftDelete' and 'Restore' are separate from 'Update' although the statement is the same one,
      -- because section 10.4 is the whole reason they are separate PERMISSIONS: RLS cannot tell them apart, the procedure
      -- can, and a trail that recorded a soft delete as an update would lose the distinction the permissions bought.
      , CONSTRAINT CK_logs_DataChangeLog_Operation
            CHECK (Operation IN ('Insert', 'Update', 'SoftDelete', 'Restore'))
      , CONSTRAINT CK_logs_DataChangeLog_SchemaName
            CHECK (LEN (SchemaName) > 0)
      , CONSTRAINT CK_logs_DataChangeLog_TableName
            CHECK (LEN (TableName) > 0)
      -- KeyJson identifies the row and is mandatory: a change log entry nobody can trace to a row is a row count.
      , CONSTRAINT CK_logs_DataChangeLog_KeyJson
            CHECK (ISJSON (KeyJson) = 1)
      -- NULL for an insert, where every column is new and the row itself is the change.
      , CONSTRAINT CK_logs_DataChangeLog_ChangedColumnsJson
            CHECK (ChangedColumnsJson IS NULL OR ISJSON (ChangedColumnsJson) = 1)
      , CONSTRAINT CK_logs_DataChangeLog_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS     NULL AND auditDeletedDateUtc IS     NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL))
    );
END
GO

-- "What changed lately", the only unbounded read this table supports.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_logs_DataChangeLog_When'
                  AND object_id = OBJECT_ID (N'logs.DataChangeLog'))
BEGIN
    CREATE INDEX IX_logs_DataChangeLog_When
        ON logs.DataChangeLog (OccurredUtc DESC) WHERE IsDeleted = 0;
END
GO

-- "What changed in this table" -- and, with KeyJson included, "what changed to this row" without a second lookup.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_logs_DataChangeLog_Table'
                  AND object_id = OBJECT_ID (N'logs.DataChangeLog'))
BEGIN
    CREATE INDEX IX_logs_DataChangeLog_Table
        ON logs.DataChangeLog (SchemaName, TableName, OccurredUtc DESC)
        INCLUDE (Operation, ActorUserProfileId)
        WHERE IsDeleted = 0;
END
GO

-- "What has this person changed" -- the read a data-entry dispute needs, and the one section 25.1's narrative ends at.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_logs_DataChangeLog_Actor'
                  AND object_id = OBJECT_ID (N'logs.DataChangeLog'))
BEGIN
    CREATE INDEX IX_logs_DataChangeLog_Actor
        ON logs.DataChangeLog (ActorUserProfileId, OccurredUtc DESC)
        INCLUDE (SchemaName, TableName, Operation)
        WHERE ActorUserProfileId IS NOT NULL AND IsDeleted = 0;
END
GO


-- *** 6. Audit triggers for the three authorization trails ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   logs.trg_au_updt_AuthorizationChange
Author:       rsincero
CreateDate:   2026-09-20
Description:
AFTER UPDATE audit stamp for logs.AuthorizationChange, and the guard that makes the whole row immutable -- E-50010.

THE SAME RULE AS SECTION 2, AND HERE IT IS THE POINT OF THE TABLE.  If ActorAuthorityTenantId could be edited, then the
record of whose authority a disputed grant relied on could be edited by whoever the dispute is about.  A trail that can be
rewritten by the party with a motive is not evidence, and P-08 would be decoration.

IsDeleted is the single exception, and a soft-deleted row is still here, still readable by logsAuditReader, and still says
who removed it and when.

Modification History:
2026-09-20  rsincero  Created.  PLAN-AUTH-001 T-055.
***********************************************************************************************************************/
CREATE OR ALTER TRIGGER logs.trg_au_updt_AuthorizationChange
    ON logs.AuthorizationChange
    AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    IF EXISTS (SELECT 1
                 FROM inserted AS i
                 JOIN deleted  AS d ON d.AuthorizationChangeId = i.AuthorizationChangeId
                WHERE i.OccurredUtc <> d.OccurredUtc
                   OR i.ChangeType <> d.ChangeType
                   OR ISNULL (i.TargetUserId, -1) <> ISNULL (d.TargetUserId, -1)
                   OR ISNULL (i.TargetUserProfileId, -1) <> ISNULL (d.TargetUserProfileId, -1)
                   OR ISNULL (i.RoleId, -1) <> ISNULL (d.RoleId, -1)
                   OR ISNULL (i.ScopeTenantId, -1) <> ISNULL (d.ScopeTenantId, -1)
                   OR ISNULL (i.ActorUserProfileId, -1) <> ISNULL (d.ActorUserProfileId, -1)
                   OR ISNULL (i.ActorAuthorityTenantId, -1) <> ISNULL (d.ActorAuthorityTenantId, -1)
                   OR ISNULL (i.DetailJson, N'~') <> ISNULL (d.DetailJson, N'~'))
    BEGIN
        ;THROW 50010, N'logs.AuthorizationChange is append-only. Every column on it is a statement about an authority change that already happened, and ActorAuthorityTenantId in particular is the record of whose authority was relied on -- a trail the subject of a dispute could edit would not be evidence. Only IsDeleted may change.', 1;
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
      FROM logs.AuthorizationChange AS t
      JOIN inserted AS i ON i.AuthorizationChangeId = t.AuthorizationChangeId
      JOIN deleted  AS d ON d.AuthorizationChangeId = t.AuthorizationChangeId;
END;
GO

/***********************************************************************************************************************
ObjectName:   logs.trg_au_updt_AuthorizationDenial
Author:       rsincero
CreateDate:   2026-09-20
Description:
AFTER UPDATE audit stamp for logs.AuthorizationDenial, and the guard that makes the whole row immutable -- E-50010.

APPEND-ONLY FOR A REASON PARTICULAR TO THIS TABLE.  The value of a denial trail is its SHAPE over time: a hundred denials
of one permission in an hour is the signal, and any statement that can rewrite or retype rows can flatten exactly that
signal.  Deleting them cannot hide them either -- a soft delete leaves the row, and the dashboard that filters on
IsDeleted = 0 can be pointed at the whole table.

Modification History:
2026-09-20  rsincero  Created.  PLAN-AUTH-001 T-055.
***********************************************************************************************************************/
CREATE OR ALTER TRIGGER logs.trg_au_updt_AuthorizationDenial
    ON logs.AuthorizationDenial
    AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    IF EXISTS (SELECT 1
                 FROM inserted AS i
                 JOIN deleted  AS d ON d.AuthorizationDenialId = i.AuthorizationDenialId
                WHERE i.OccurredUtc <> d.OccurredUtc
                   OR i.PermissionCode <> d.PermissionCode
                   OR ISNULL (i.UserProfileId, -1) <> ISNULL (d.UserProfileId, -1)
                   OR ISNULL (i.TenantId, -1) <> ISNULL (d.TenantId, -1)
                   OR ISNULL (i.ObjectName, N'~') <> ISNULL (d.ObjectName, N'~')
                   OR ISNULL (i.DetailJson, N'~') <> ISNULL (d.DetailJson, N'~'))
    BEGIN
        ;THROW 50010, N'logs.AuthorizationDenial is append-only: the value of a denial trail is its shape over time, and a statement that can retype rows can flatten the one signal the table exists to show. Only IsDeleted may change.', 1;
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
      FROM logs.AuthorizationDenial AS t
      JOIN inserted AS i ON i.AuthorizationDenialId = t.AuthorizationDenialId
      JOIN deleted  AS d ON d.AuthorizationDenialId = t.AuthorizationDenialId;
END;
GO

/***********************************************************************************************************************
ObjectName:   logs.trg_au_updt_DataChangeLog
Author:       rsincero
CreateDate:   2026-09-20
Description:
AFTER UPDATE audit stamp for logs.DataChangeLog, and the guard that makes the whole row immutable -- E-50010.

THE TABLE THAT RECORDS CORRECTIONS MUST NOT BE CORRECTABLE.  Every row here says a business row changed; if the trail
itself were editable, the cheapest way to hide a change would be to edit the record of it, and D-12's whole argument --
that a procedure-written trail is trustworthy because P-11 leaves no other path -- would collapse.

A wrong entry is fixed the way a wrong entry in a ledger is fixed: by another entry.

Modification History:
2026-09-20  rsincero  Created.  PLAN-AUTH-001 T-055.
***********************************************************************************************************************/
CREATE OR ALTER TRIGGER logs.trg_au_updt_DataChangeLog
    ON logs.DataChangeLog
    AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    IF EXISTS (SELECT 1
                 FROM inserted AS i
                 JOIN deleted  AS d ON d.DataChangeLogId = i.DataChangeLogId
                WHERE i.OccurredUtc <> d.OccurredUtc
                   OR i.SchemaName <> d.SchemaName
                   OR i.TableName <> d.TableName
                   OR i.Operation <> d.Operation
                   OR i.KeyJson <> d.KeyJson
                   OR ISNULL (i.ChangedColumnsJson, N'~') <> ISNULL (d.ChangedColumnsJson, N'~')
                   OR ISNULL (i.ActorUserProfileId, -1) <> ISNULL (d.ActorUserProfileId, -1))
    BEGIN
        ;THROW 50010, N'logs.DataChangeLog is append-only. It records that a business row changed, so an editable trail would make editing the record of a change the cheapest way to hide one -- which is exactly what D-12 claims this table prevents. A wrong entry is fixed by another entry. Only IsDeleted may change.', 1;
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
      FROM logs.DataChangeLog AS t
      JOIN inserted AS i ON i.DataChangeLogId = t.DataChangeLogId
      JOIN deleted  AS d ON d.DataChangeLogId = t.DataChangeLogId;
END;
GO


-- *** 7. Descriptions ***
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
      (N'logs', N'TABLE', N'AuthenticationEvent', NULL, N'The append-only security narrative of the authentication subsystem -- section 15.5. NOT a duplicate of auth.LoginAttempt: that table is operational state (one row per exchange, read to compute lockout counts, safely aged out); this one records the things that are not sign-in attempts at all -- a factor removed, a session revoked, a lockout applied -- and is the first thing anybody asks for after an incident. Lives in logs rather than logsData because its audience is a human: logsAuditReader reads it directly, which is the only readable account of the authentication subsystem given INV-11. NOTHING SECRET GOES IN IT.')
    , (N'logs', N'TABLE', N'AuthenticationEvent', N'AuthenticationEventId', N'Surrogate key, BIGINT. Append-only, so it is also the insertion order.')
    , (N'logs', N'TABLE', N'AuthenticationEvent', N'EventUtc',       N'When the event happened, UTC. IMMUTABLE.')
    , (N'logs', N'TABLE', N'AuthenticationEvent', N'EventType',      N'What happened, from a CLOSED SET enforced by CK_logs_AuthenticationEvent_EventType: LoginSucceeded, LoginFailed, LoginBlocked, SsoBegun, SsoSucceeded, SsoFailed, MfaChallenged, MfaSucceeded, MfaFailed, RecoveryCodeUsed, MfaEnrolled, MfaConfirmed, MfaRemoved, RecoveryCodesIssued, MfaKeyRotated, MfaEnrolmentRefused, LockoutApplied, LockoutCleared, AddressThrottled, PasswordChanged, PasswordReset, CredentialCreated, CredentialRetired, FederatedLinkAdded, FederatedLinkRemoved, SessionStarted, SessionEnded, SessionRevoked, SessionElevated, ExchangeExpired, PolicyResolutionFailed, MaintenanceBypass, MaintenanceBypassEnded, ProfileSwitch, CredentialExpired. Closed on purpose: a free string becomes three spellings of one event and every report built on it under-counts. RecoveryCodesIssued, MfaKeyRotated and MfaEnrolmentRefused were added by task T-041, and adding them meant an ALTER with a reviewer -- which is the cost the closed set is charging on purpose. MfaEnrolmentRefused is the only one of the three that records something that did NOT happen, and it is here because a borrowed session trying to replace a working authenticator (E-50119) is worth seeing. MaintenanceBypass and MaintenanceBypassEnded were added by task T-066 for section 10.5: they are the only rows in this table written by a named human being rather than by an application login, and they are the trail that makes turning row-level security off for one connection an act somebody can review rather than a habit. ProfileSwitch was added by task T-078 for section 12.1 step 6, and its absence until then is the clearest example of what a closed vocabulary costs and buys: section 15.5 published the name four phases before anything wrote it, the renaming that turned SignIn into LoginSucceeded dropped it in passing, and nothing failed until auth.uspSwitchProfile existed to need it. G-29. CredentialExpired was added by task T-112 for auth.uspExpireCredentials (G-12), and it is deliberately NOT CredentialRetired: an expired credential still verifies, and the only thing that changed is that the next sign-in carries MustChangePassword = 1. Filing an expiry as a retirement would understate how many credentials are still in use.')
    , (N'logs', N'TABLE', N'AuthenticationEvent', N'EventSeverity',  N'''Info'', ''Warning'' or ''Alert''. Three levels and no more: ''Alert'' means somebody should look now, and a fourth level in the middle ends up meaning "the writer was unsure".')
    , (N'logs', N'TABLE', N'AuthenticationEvent', N'ApplicationId',  N'Which application, or NULL when the event was raised before one could be resolved (E-50101).')
    , (N'logs', N'TABLE', N'AuthenticationEvent', N'UserId',         N'Which person, or NULL when the name did not resolve to one. Nullable deliberately: the events with no UserId are the ones an enumeration probe generates, and they are the ones most worth having -- section 19.2.')
    , (N'logs', N'TABLE', N'AuthenticationEvent', N'UserName',       N'The name involved, as a string, whether or not it names a real account. At least one of UserId and UserName must be present -- CK_logs_AuthenticationEvent_Attributable -- because an unattributable security event is noise.')
    , (N'logs', N'TABLE', N'AuthenticationEvent', N'LoginAttemptId', N'The exchange this event belongs to, or NULL for events outside a sign-in (a factor removed, an administrative revoke). Indexed, because "everything that happened in this one exchange" is how a support call is answered.')
    , (N'logs', N'TABLE', N'AuthenticationEvent', N'UserSessionId',  N'The session this event concerns, or NULL. An identifier and not a token hash: the identifier is useless to anybody who cannot already read auth.UserSession, which is the point.')
    , (N'logs', N'TABLE', N'AuthenticationEvent', N'ClientAddress',  N'The address involved, as reported. NULL when the event did not come from a request.')
    , (N'logs', N'TABLE', N'AuthenticationEvent', N'Actor',          N'Who caused the event: the acting profile from SESSION_CONTEXT (''AppUser'') where there is one, otherwise ORIGINAL_LOGIN (). For a self-service action this is the user themselves; for a revoke it is the administrator, which is the distinction an audit needs.')
    , (N'logs', N'TABLE', N'AuthenticationEvent', N'DetailJson',     N'The shape of the event -- which policy resolved, which threshold was crossed, which factor type, which end reason. NVARCHAR (MAX) with an ISJSON check, not the native json type (SQL Server 2025). NEVER MATERIAL: no verifier, no PHC string, no token, no token hash, no MFA secret, no ciphertext, no recovery code or its hash. This table is readable by a role denied everything else, so anything secret put here has escaped INV-11 by the front door.');

    -- The three authorization trails, added by T-055.
    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    VALUES
      (N'logs', N'TABLE', N'AuthorizationChange', NULL, N'The AUTHORITY trail -- section 15.5, and P-08. Low volume, long retention, read by a human reviewing a disputed grant: the audit columns say a row changed, this says who granted what to whom and under whose authority. Not merged with logs.AuthorizationDenial or logs.DataChangeLog because the three have different columns, volumes and audiences, and one table with a Kind column would have been mostly NULL, hot, and indexed for nobody. Append-only, enforced by trg_au_updt_AuthorizationChange: a trail the subject of a dispute could edit would not be evidence.')
    , (N'logs', N'TABLE', N'AuthorizationChange', N'AuthorizationChangeId',  N'Surrogate key, BIGINT. Append-only, so it is also the order in which authority changed.')
    , (N'logs', N'TABLE', N'AuthorizationChange', N'OccurredUtc',            N'When the change happened, UTC. IMMUTABLE.')
    , (N'logs', N'TABLE', N'AuthorizationChange', N'ChangeType',             N'What kind of change, from a CLOSED SET enforced by CK_logs_AuthorizationChange_ChangeType: RoleGranted, RoleRevoked, GrantExpiryChanged, RoleCreated, RoleModified, RoleRetired, RolePermissionAdded, RolePermissionRemoved, ProfileCreated, ProfileActivated, ProfileDeactivated, ProfileRetired, PlatformAdminGranted, PlatformAdminRevoked, TenantReparented, ScopeRebuilt. Several have no writer before Phase 6 and two have none planned before Phase 7; they are in the set anyway, because widening a closed vocabulary on a live database costs the drop-and-re-add dance section 1 had to grow.')
    , (N'logs', N'TABLE', N'AuthorizationChange', N'TargetUserId',           N'Whose authority changed, at the person level -- set for PlatformAdminGranted and PlatformAdminRevoked, which are about the user and not about a profile. NULL otherwise.')
    , (N'logs', N'TABLE', N'AuthorizationChange', N'TargetUserProfileId',    N'Which profile''s authority changed -- the usual target, since a grant is made to a profile and not to a person. At least one of TargetUserId, TargetUserProfileId and RoleId must be present -- CK_logs_AuthorizationChange_Attributable -- because a change naming none of the three cannot be reviewed. G-43 added a fourth branch for the tenant-scoped verbs (TenantReparented, TenantPolicyChanged, TenantTrustedIssuerAdded, TenantTrustedIssuerRemoved, ScopeRebuilt), which name a ScopeTenantId and nothing else; until then that shape was unwritable, which is why TenantReparented had been in the vocabulary from the first cut with no writer.')
    , (N'logs', N'TABLE', N'AuthorizationChange', N'RoleId',                 N'Which role was granted, revoked or redefined. Set with no target for RoleCreated, RoleModified, RoleRetired and the two RolePermission changes, which alter what a role MEANS for everybody who holds it -- the reason IX_logs_AuthorizationChange_Role exists.')
    , (N'logs', N'TABLE', N'AuthorizationChange', N'ScopeTenantId',          N'The tenant the grant was made AT -- the scope, which reaches every tenant beneath it. Not the target''s own tenant: section 8.6 and D-07.')
    , (N'logs', N'TABLE', N'AuthorizationChange', N'ActorUserProfileId',     N'Which profile made the change. NULL means the bootstrap: 115_seed_reference_data.sql attributes the root''s own grants to nobody, because there was no profile in existence to attribute them to (section 16.1, item 5).')
    , (N'logs', N'TABLE', N'AuthorizationChange', N'ActorAuthorityTenantId', N'THE POINT OF THIS TABLE -- P-08. The tenant at which the ACTOR''s own grant of the permission they relied on was held. Without it, a review can establish that Smith granted EDITOR at Anne Arundel and cannot establish whether Smith was entitled to: auth.ProfilePermissionScope is DERIVED, so it holds today''s answer and no history. NULL has two legitimate causes -- the bootstrap, and a platform administrator acting under a Platform permission, which is not tenant-scoped and so has no authority tenant to record. The closing report counts the second case so it does not look like a defect.')
    , (N'logs', N'TABLE', N'AuthorizationChange', N'DetailJson',             N'The shape of the change -- the old and new expiry, the permission code added, the previous parent tenant. NVARCHAR (MAX) with an ISJSON check, not the native json type (SQL Server 2025, and this design''s ceiling is 2022). NEVER MATERIAL: the same rule as logs.AuthenticationEvent, because the same role reads both.')
    , (N'logs', N'TABLE', N'AuthorizationDenial', NULL, N'The OPERATIONAL trail -- section 15.5. Denials only: a permission check that passed is not news, and recording the successes would multiply this table by the traffic of the application for no reader. One denial is not an incident; a hundred denials of the same permission in an hour is either a misconfigured role or somebody probing, and both are worth a graph. Written by auth.uspDemandPermission immediately before it raises E-50030 -- which means a denial demanded from inside an open transaction is rolled back with it, and section 9''s call order (check at step 5, work at step 6) is what keeps that from happening.')
    , (N'logs', N'TABLE', N'AuthorizationDenial', N'AuthorizationDenialId', N'Surrogate key, BIGINT.')
    , (N'logs', N'TABLE', N'AuthorizationDenial', N'OccurredUtc',           N'When the refusal happened, UTC. IMMUTABLE. Leads every index on this table, because every question anybody asks of it is bounded by a window first.')
    , (N'logs', N'TABLE', N'AuthorizationDenial', N'UserProfileId',         N'Who was refused. NULL when the connection had no session context -- and THAT is the denial most worth seeing, because it means a procedure was reached without auth.uspSetSessionContext having run.')
    , (N'logs', N'TABLE', N'AuthorizationDenial', N'PermissionCode',        N'Which permission was demanded, as a STRING and not a foreign key to auth.Permission. Deliberate, and the same reasoning as UserName on logs.AuthenticationEvent: a denial for a code that does not exist is a typo in a procedure, a foreign key would refuse to record the one row that proves it, and the codes that do not resolve are exactly the ones worth a dashboard.')
    , (N'logs', N'TABLE', N'AuthorizationDenial', N'TenantId',              N'The tenant the permission was demanded AT, or NULL for a permission that is not tenant-scoped.')
    , (N'logs', N'TABLE', N'AuthorizationDenial', N'ObjectName',            N'Which procedure refused, as passed by the caller. NULL when the caller did not say. It is what turns "this person is being refused things" into "this screen is broken for this person".')
    , (N'logs', N'TABLE', N'AuthorizationDenial', N'DetailJson',            N'Optional shape -- the arguments that were in play, never the data they name. NVARCHAR (MAX) with an ISJSON check.')
    , (N'logs', N'TABLE', N'DataChangeLog', NULL, N'The BUSINESS trail -- section 15.5, and D-12. Row-level audit of the demo domain, written by the DOMAIN PROCEDURES and not by a generic audit trigger: a trigger that serialises inserted and deleted to JSON on every table costs a write on every write, and since P-11 guarantees every change arrives through a procedure, the procedure can log the columns that actually matter at a fraction of the cost. The trade is that a change made outside a procedure is unlogged, which logsData.DdlChange and the permission model make visible. Carries NO TenantId on purpose -- an audit trail that hides rows from the auditor is not an audit trail, and a TenantId column here would invite an RLS policy and trip 950_verify_deployment.sql''s unregistered-table check.')
    , (N'logs', N'TABLE', N'DataChangeLog', N'DataChangeLogId',    N'Surrogate key, BIGINT.')
    , (N'logs', N'TABLE', N'DataChangeLog', N'OccurredUtc',        N'When the row changed, UTC. IMMUTABLE.')
    , (N'logs', N'TABLE', N'DataChangeLog', N'SchemaName',         N'Schema of the table that changed. SYSNAME, and a string rather than an object_id: an object_id becomes meaningless the moment the table is rebuilt, which is exactly what a migration does.')
    , (N'logs', N'TABLE', N'DataChangeLog', N'TableName',          N'Table that changed.')
    , (N'logs', N'TABLE', N'DataChangeLog', N'Operation',          N'''Insert'', ''Update'', ''SoftDelete'' or ''Restore''. The last two are separate from ''Update'' although the statement is identical, because that distinction is the whole reason Data.SoftDelete and Data.Restore are separate permissions (section 10.4): RLS cannot tell them apart, the procedure can, and a trail that recorded a soft delete as an update would lose what the permissions bought.')
    , (N'logs', N'TABLE', N'DataChangeLog', N'KeyJson',            N'The key of the row that changed, as JSON, and MANDATORY: a change log entry nobody can trace back to a row is a row count. The tenant of the row goes here if the procedure puts it there, which is where a row-identifying value belongs.')
    , (N'logs', N'TABLE', N'DataChangeLog', N'ChangedColumnsJson', N'What changed, as JSON -- the columns the procedure decided were worth recording, with before and after where it matters. NULL for an Insert, where the row itself is the change.')
    , (N'logs', N'TABLE', N'DataChangeLog', N'ActorUserProfileId', N'Which profile made the change. NULL for anything a deployment script changed: a migration is a change with no acting profile, and refusing to record it would stop the trail exactly where a data correction happened.');

    -- The seven audit columns carry the same description on every table, so they are generated rather than typed out.
    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    SELECT N'logs', N'TABLE', t.TableName, c.ColumnName, c.Description
      FROM (VALUES (N'AuthenticationEvent')
                 , (N'AuthorizationChange')
                 , (N'AuthorizationDenial')
                 , (N'DataChangeLog')) AS t (TableName)
     CROSS JOIN (VALUES
          (N'IsDeleted',            N'Soft-delete flag, and the ONLY column on this table an UPDATE may change. A soft-deleted event is still in the table, still readable, and still says who deleted it and when; nothing in this database hard-deletes.')
        , (N'auditDeletedBy',       N'Who soft-deleted the row. NULL unless IsDeleted = 1 -- the pair is enforced by CK_<table>_DeletedPair.')
        , (N'auditDeletedDateUtc',  N'When the row was soft-deleted, UTC. NULL unless IsDeleted = 1.')
        , (N'auditCreatedBy',       N'Who inserted the row. Defaults to ORIGINAL_LOGIN (); a procedure sets it to the acting profile instead.')
        , (N'auditCreatedDateUtc',  N'When the row was inserted, UTC.')
        , (N'auditModifiedBy',      N'Who last updated the row -- in practice, who soft-deleted it, since nothing else here is updatable.')
        , (N'auditModifiedDateUtc', N'When the row was last updated, UTC, set by the AFTER UPDATE trigger.')
       ) AS c (ColumnName, Description);

    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    VALUES (N'logs', N'TRIGGER', N'trg_au_updt_AuthenticationEvent', NULL, N'AFTER UPDATE audit stamp, and the guard that makes the whole row immutable except IsDeleted -- the strictest trigger in the deployment, on the table whose whole value is that it can be trusted. E-50010.')
         , (N'logs', N'TRIGGER', N'trg_au_updt_AuthorizationChange', NULL, N'AFTER UPDATE audit stamp, and the guard that makes the whole row immutable except IsDeleted. E-50010. Here it is the point of the table: if ActorAuthorityTenantId could be edited, the record of whose authority a disputed grant relied on could be edited by whoever the dispute is about, and P-08 would be decoration.')
         , (N'logs', N'TRIGGER', N'trg_au_updt_AuthorizationDenial', NULL, N'AFTER UPDATE audit stamp, and the guard that makes the whole row immutable except IsDeleted. E-50010. The value of a denial trail is its shape over time, so any statement that can retype rows can flatten the one signal the table exists to show.')
         , (N'logs', N'TRIGGER', N'trg_au_updt_DataChangeLog',       NULL, N'AFTER UPDATE audit stamp, and the guard that makes the whole row immutable except IsDeleted. E-50010. The table that records corrections must not be correctable, or editing the record of a change becomes the cheapest way to hide one -- which is what D-12 claims this table prevents. A wrong entry is fixed by another entry.');

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


-- *** 8. Grants ***
--
-- DELIBERATELY EMPTY HERE, and for once that is not because nothing may read the tables.  logsAuditReader is intended to
-- hold SELECT on SCHEMA::logs and to read all four directly -- it is the whole reason the trails live in logs rather than
-- behind INV-11's wall.  But the grant is stated once, in 170_permissions.sql, with every other grant and every
-- deliberate deny beside it, so that one file answers "who can read what" -- G-19.
--
-- applicationRole gets INSERT here through ownership chaining only: the authentication procedures write the events, the
-- administrative procedures write the authority changes, auth.uspDemandPermission writes the denials and the domain
-- procedures write the data changes.  An INSERT grant would let a compromised application login forge the narrative of
-- its own compromise -- and on logs.AuthorizationChange, forge the authority it acted under.
--
-- Audit.ReadAuthorization and Audit.ReadDataChange (appendix A) are the APPLICATION-level permissions for these tables,
-- checked by the procedures that surface them on a screen.  They are not a substitute for the grant above and do not
-- overlap with it: one governs a human reading the table with a SELECT, the other governs a request reaching a procedure.
GO


-- *** 9. Closing report ***
DECLARE @Report TABLE
(
    RowNo    INT IDENTITY (1, 1) PRIMARY KEY,
    Severity INT             NOT NULL,
    Status   VARCHAR (10)    NOT NULL,
    Item     NVARCHAR (200)  NOT NULL,
    Detail   NVARCHAR (1000)     NULL
);

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (N'logs.AuthenticationEvent', N'U') IS NULL THEN 1 ELSE 4 END
     , CASE WHEN OBJECT_ID (N'logs.AuthenticationEvent', N'U') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Table logs.AuthenticationEvent'
     , N'The append-only security narrative -- section 15.5. Readable by logsAuditReader, which is why nothing secret '
     + N'may go in it.';

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN i.name IS NULL THEN 2 ELSE 4 END
     , CASE WHEN i.name IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Index ' + x.IndexName
     , x.Purpose
  FROM (VALUES (N'IX_logs_AuthenticationEvent_When',         N'"What happened, most recent first" -- where an incident starts.')
             , (N'IX_logs_AuthenticationEvent_User',         N'"What happened to this account."')
             , (N'IX_logs_AuthenticationEvent_UnknownName',  N'"Who has been trying names that do not exist" -- the enumeration-probe read, which by definition has no UserId.')
             , (N'IX_logs_AuthenticationEvent_Alert',        N'The alert feed. Filtered, so on a healthy deployment it holds almost nothing.')
             , (N'IX_logs_AuthenticationEvent_LoginAttempt', N'"Everything that happened in this one exchange."'))
       AS x (IndexName, Purpose)
  LEFT JOIN sys.indexes AS i ON i.name = x.IndexName AND i.object_id = OBJECT_ID (N'logs.AuthenticationEvent');

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (N'logs.trg_au_updt_AuthenticationEvent', N'TR') IS NULL THEN 2 ELSE 4 END
     , CASE WHEN OBJECT_ID (N'logs.trg_au_updt_AuthenticationEvent', N'TR') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Trigger logs.trg_au_updt_AuthenticationEvent'
     , N'Append-only: every column immutable except IsDeleted. E-50010.';

-- The closed vocabulary is kept in two places -- the CREATE TABLE and the ALTER that brings an existing database up to
-- date -- so this asserts that the LIVE constraint is the current one.  Checked by looking for every value added
-- after the first cut -- T-041's three, T-066's two, T-078's one and T-112's one: if section 1's inline list gains a value and the ALTER's does not, the deployment ends up with the ALTER's list
-- and this row is where that shows.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN c.definition LIKE N'%RecoveryCodesIssued%' AND c.definition LIKE N'%MfaKeyRotated%'
             AND c.definition LIKE N'%MfaEnrolmentRefused%'  AND c.definition LIKE N'%MaintenanceBypass%'
             AND c.definition LIKE N'%MaintenanceBypassEnded%' AND c.definition LIKE N'%ProfileSwitch%'
             AND c.definition LIKE N'%CredentialExpired%'
             THEN 4 ELSE 1 END
     , CASE WHEN c.definition LIKE N'%RecoveryCodesIssued%' AND c.definition LIKE N'%MfaKeyRotated%'
             AND c.definition LIKE N'%MfaEnrolmentRefused%'  AND c.definition LIKE N'%MaintenanceBypass%'
             AND c.definition LIKE N'%MaintenanceBypassEnded%' AND c.definition LIKE N'%ProfileSwitch%'
             AND c.definition LIKE N'%CredentialExpired%'
             THEN 'OK' ELSE 'STALE' END
     , N'CK_logs_AuthenticationEvent_EventType carries the current vocabulary'
     , N'It must permit RecoveryCodesIssued, MfaKeyRotated and MfaEnrolmentRefused, which task T-041 added for '
     + N'112_auth_mfa_procedures.sql, MaintenanceBypass and MaintenanceBypassEnded, which T-066 added for '
     + N'105_auth_session_procedures.sql, ProfileSwitch, which T-078 added for 140_auth_profile_procedures.sql, and '
     + N'CredentialExpired, which T-112 added for auth.uspExpireCredentials (G-12). '
     + N'A STALE constraint means those procedures will fail at INSERT with error 547 and nothing will say which '
     + N'script is out of step -- which is why this is checked here and not discovered there.'
  FROM sys.check_constraints AS c
 WHERE c.name             = N'CK_logs_AuthenticationEvent_EventType'
   AND c.parent_object_id = OBJECT_ID (N'logs.AuthenticationEvent');

-- The same two-copies assertion as the one above, for logs.AuthorizationChange -- and for the Attributable rule, which
-- is not a vocabulary but is the constraint that decides whether a tenant-scoped row can be written at all.  Both halves
-- are checked here because 125_auth_tenant_procedures.sql installs at step 28, long after this file at step 19, and its
-- own closing report asserts the same thing from the other side: whichever end a reader starts from, the answer is in
-- the transcript.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Verbs = 1 AND x.Attributable = 1 THEN 4 ELSE 1 END
     , CASE WHEN x.Verbs = 1 AND x.Attributable = 1 THEN 'OK' ELSE 'STALE' END
     , N'logs.AuthorizationChange accepts the tenant-scoped trail rows'
     , N'CK_logs_AuthorizationChange_ChangeType must permit TenantPolicyChanged, TenantTrustedIssuerAdded, '
     + N'TenantTrustedIssuerRemoved, TenantDefaultRoleAdded and TenantDefaultRoleRemoved, which G-43 added for '
     + N'auth.uspSetTenantAuthenticationPolicy and auth.uspSetTenantDefaultRoles; and '
     + N'CK_logs_AuthorizationChange_Attributable must accept a row naming only a ScopeTenantId, which the original '
     + N'rule refused -- the reason the published TenantReparented verb never had a writer. Vocabulary current: '
     + CAST (x.Verbs AS NVARCHAR (2)) + N'. Attribution rule widened: ' + CAST (x.Attributable AS NVARCHAR (2))
     + N'. Anything but 1 and 1 means those two procedures fail at INSERT with error 547.'
  FROM (SELECT Verbs = MAX (CASE WHEN c.name = N'CK_logs_AuthorizationChange_ChangeType'
                                 AND c.definition LIKE N'%TenantPolicyChanged%'
                                 AND c.definition LIKE N'%TenantTrustedIssuerAdded%'
                                 AND c.definition LIKE N'%TenantTrustedIssuerRemoved%'
                                 AND c.definition LIKE N'%TenantDefaultRoleAdded%'
                                 AND c.definition LIKE N'%TenantDefaultRoleRemoved%' THEN 1 ELSE 0 END)
             , Attributable = MAX (CASE WHEN c.name = N'CK_logs_AuthorizationChange_Attributable'
                                        AND c.definition LIKE N'%ScopeTenantId%' THEN 1 ELSE 0 END)
          FROM sys.check_constraints AS c
         WHERE c.parent_object_id = OBJECT_ID (N'logs.AuthorizationChange')) AS x;

INSERT @Report (Severity, Status, Item, Detail)
SELECT 3, 'INFO', N'Events recorded'
     , CASE WHEN COUNT (*) = 0
            THEN N'None. Expected on a first deployment: only the authentication procedures write here, and nothing '
               + N'has authenticated yet.'
            ELSE CAST (COUNT (*) AS NVARCHAR (10)) + N' event(s), of which '
               + CAST (SUM (CASE WHEN EventSeverity = 'Alert' THEN 1 ELSE 0 END) AS NVARCHAR (10))
               + N' at Alert and '
               + CAST (SUM (CASE WHEN UserId IS NULL THEN 1 ELSE 0 END) AS NVARCHAR (10))
               + N' against a name that resolved to no account.'
       END
  FROM logs.AuthenticationEvent
 WHERE IsDeleted = 0;

-- The three authorization trails, added by T-055.  One row each rather than one row per column: what matters in a
-- transcript is that the table is there and what it is for.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (x.TableName, N'U') IS NULL THEN 1 ELSE 4 END
     , CASE WHEN OBJECT_ID (x.TableName, N'U') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Table ' + x.TableName
     , x.Detail
  FROM (VALUES (N'logs.AuthorizationChange'
              , N'The authority trail -- section 15.5, task T-055, P-08. ActorAuthorityTenantId records WHICH grant the '
              + N'actor relied on, which is the only thing that keeps a disputed grant reviewable once '
              + N'auth.ProfilePermissionScope has been rebuilt.')
             , (N'logs.AuthorizationDenial'
              , N'The operational trail -- denials only, written by auth.uspDemandPermission before it raises E-50030. '
              + N'A rise in one permission is a misconfigured role or a probe, and both are worth a graph.')
             , (N'logs.DataChangeLog'
              , N'The business trail -- D-12, written by the domain procedures rather than by a generic audit trigger. '
              + N'Carries no TenantId on purpose: an audit trail that hides rows from the auditor is not one.'))
       AS x (TableName, Detail);

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN i.name IS NULL THEN 2 ELSE 4 END
     , CASE WHEN i.name IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Index ' + x.IndexName
     , x.Purpose
  FROM (VALUES (N'logs.AuthorizationChange', N'IX_logs_AuthorizationChange_When',       N'"What has changed lately" -- where a periodic authority review starts.')
             , (N'logs.AuthorizationChange', N'IX_logs_AuthorizationChange_Target',     N'"How did this person come to have this" -- the disputed-grant read, and the reason the table exists.')
             , (N'logs.AuthorizationChange', N'IX_logs_AuthorizationChange_Actor',      N'"What has this administrator been doing."')
             , (N'logs.AuthorizationChange', N'IX_logs_AuthorizationChange_Role',       N'"Who has ever held this role, and where" -- the read that follows a role whose permissions were just widened.')
             , (N'logs.AuthorizationDenial', N'IX_logs_AuthorizationDenial_When',       N'The dashboard read. Covering, so the graph is one seek.')
             , (N'logs.AuthorizationDenial', N'IX_logs_AuthorizationDenial_Profile',    N'"What is this person being refused" -- nearly always a missing role rather than an attack.')
             , (N'logs.AuthorizationDenial', N'IX_logs_AuthorizationDenial_Permission', N'"Which permission is refused most" -- finds an ungranted baseline role, and a code no procedure spells correctly.')
             , (N'logs.DataChangeLog',       N'IX_logs_DataChangeLog_When',             N'"What changed lately."')
             , (N'logs.DataChangeLog',       N'IX_logs_DataChangeLog_Table',            N'"What changed in this table."')
             , (N'logs.DataChangeLog',       N'IX_logs_DataChangeLog_Actor',            N'"What has this person changed" -- what a data-entry dispute needs.'))
       AS x (TableName, IndexName, Purpose)
  LEFT JOIN sys.indexes AS i ON i.name = x.IndexName AND i.object_id = OBJECT_ID (x.TableName);

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (x.TriggerName, N'TR') IS NULL THEN 2 ELSE 4 END
     , CASE WHEN OBJECT_ID (x.TriggerName, N'TR') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Trigger ' + x.TriggerName
     , x.Detail
  FROM (VALUES (N'logs.trg_au_updt_AuthorizationChange'
              , N'Append-only. Without it the record of whose authority a grant relied on could be edited by whoever '
              + N'the dispute is about.')
             , (N'logs.trg_au_updt_AuthorizationDenial'
              , N'Append-only. The value of the trail is its shape over time, and retyping rows flattens it.')
             , (N'logs.trg_au_updt_DataChangeLog'
              , N'Append-only. The table that records corrections must not be correctable.'))
       AS x (TriggerName, Detail);

-- P-08 in the transcript.  A row with an actor and no authority tenant is LEGITIMATE for a platform administrator acting
-- under a Platform permission, which is not tenant-scoped -- so this is a REVIEW and never a violation.  It is here so
-- that the pattern is visible: a rising count means somebody is doing ordinary tenant work with platform authority.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 0 THEN 4 ELSE 3 END
     , CASE WHEN COUNT (*) = 0 THEN 'OK' ELSE 'REVIEW' END
     , N'Authority changes recorded with an actor but no authority tenant'
     , CASE WHEN COUNT (*) = 0
            THEN N'None. Every change made by a named profile records the tenant whose grant it relied on -- P-08.'
            ELSE CAST (COUNT (*) AS NVARCHAR (10)) + N' row(s). Legitimate for a platform administrator acting under a '
               + N'Platform permission, which is not tenant-scoped and so has no authority tenant to record. Worth a '
               + N'look if the count rises: it would mean ordinary tenant work is being done with platform authority.'
       END
  FROM logs.AuthorizationChange
 WHERE IsDeleted              = 0
   AND ActorUserProfileId     IS NOT NULL
   AND ActorAuthorityTenantId IS NULL;

INSERT @Report (Severity, Status, Item, Detail)
SELECT 3, 'INFO', N'Authorization trail volumes'
     , N'logs.AuthorizationChange ' + CAST ((SELECT COUNT (*) FROM logs.AuthorizationChange WHERE IsDeleted = 0) AS NVARCHAR (12))
     + N' row(s), logs.AuthorizationDenial ' + CAST ((SELECT COUNT (*) FROM logs.AuthorizationDenial WHERE IsDeleted = 0) AS NVARCHAR (12))
     + N' row(s), logs.DataChangeLog ' + CAST ((SELECT COUNT (*) FROM logs.DataChangeLog WHERE IsDeleted = 0) AS NVARCHAR (12))
     + N' row(s). All three are empty on a first deployment: their writers are 115_seed_reference_data.sql (the '
     + N'bootstrap grants), 150_auth_query_procedures.sql (the denials) and the domain procedures (the data changes).';

INSERT @Report (Severity, Status, Item, Detail)
VALUES (3, 'NEXT', N'Next scripts'
      , N'165_logs_procedures.sql -- the three recorders that are the only writers of the tables added here -- then '
      + N'150_auth_query_procedures.sql (auth.uspDemandPermission, which writes the denials) and '
      + N'105_auth_session_procedures.sql. The authentication narrative is written by 110_auth_authn_procedures.sql and '
      + N'112_auth_mfa_procedures.sql, which are already in place.');

IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
    PRINT N'logs authentication and authorization trails: PROBLEMS found. Read the report below before continuing.';
ELSE
    PRINT N'logs authentication and authorization trails: no problems found.';

PRINT N'';

SELECT Severity, Status, Item, Detail
  FROM @Report
 ORDER BY Severity, RowNo;
GO
