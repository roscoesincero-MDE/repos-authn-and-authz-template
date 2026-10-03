/***********************************************************************************************************************
Script:         112_auth_mfa_procedures.sql
Purpose:        Enrolment, confirmation, recovery codes, key rotation and step-up elevation for the second factor.
                Five procedures.  The first four are the half of MFA that 110_auth_authn_procedures.sql could not write
                while gap G-07 was open; the fifth is the one auth.uspSwitchProfile has pointed at since Phase 3 without
                it existing (G-48):
                  auth.uspEnrolMfaFactor        -- accept a factor the application has already encrypted (T-041)
                  auth.uspConfirmMfaFactor      -- turn an enrolment in progress into a usable factor (T-041)
                  auth.uspIssueMfaRecoveryCodes -- replace the batch of one-time codes (T-041)
                  auth.uspRotateMfaFactorKey    -- re-encrypt one factor under a new key (T-041)
                  auth.uspElevateSession        -- satisfy a step-up challenge on a LIVE session (T-125)
Target:         SQL Server 2022.
Run as:         db_owner in the target database.
Run with:       sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/112_auth_mfa_procedures.sql
Idempotent:     Yes.  CREATE OR ALTER throughout.  Creates nothing that holds state and seeds nothing.
Depends on:     025_config_tables.sql, 040_auth_userprofile.sql, 045_auth_identity.sql, 070_auth_session.sql,
                085_logs_auth_tables.sql, 100_auth_functions.sql, 110_auth_authn_procedures.sql (for the shape of the
                exchange it reads, and -- since T-125 -- for auth.uspEndSession, which the step-up throttle calls),
                010_logging_objects.sql (logs.uspStartExecutionLogging, logs.uspRecordExecutionError),
                templates/extended-properties.sql.
Implements:     DES-AUTH-001 sections 6.2, 6.4, 12.3, 14.5, 19.2.  D-08, D-14, INV-11.  Gaps G-07 and G-48, closed.
                PLAN-AUTH-001 tasks T-041 and T-125.
To retarget:    Pass it per run:  sqlcmd -d <database> -v DbName=<database>.  There is no in-file default.

WHY THIS FILE EXISTS AT ALL, AND WHY IT IS NOT PART OF 110
--------------------------------------------------------
110 is the sign-in protocol: three routes, one exchange each, and every procedure in it is reached by somebody who is
not yet authenticated.  This file is the opposite.  Every procedure here is reached by somebody who has ALREADY proved
something -- they hold a live session, or the database itself has just written down that their password verified -- and
what they are doing is changing the second factor rather than presenting it.

Keeping them apart is not tidiness.  The two files have different threat models and different callers, and the report at
the end of each is a different question: 110 asks "can this deployment sign anybody in", and this one asks "can this
deployment enrol anybody".  A single file would answer both with one PRINT and a reader would have to guess which half
failed.

AND WHY auth.uspElevateSession IS HERE RATHER THAN IN 110 EITHER, which is the same argument arriving from the other
direction.  A step-up is not a sign-in: the caller already holds a live session and is being asked to prove the second
factor AGAIN, which is the file rule above in its purest form.  It arrived with T-125, as the answer to gap G-48 -- for
three phases auth.uspSwitchProfile refused a privileged profile with E-50052 whenever the session was not elevated, and
nothing in the manifest could write auth.UserSession.ElevatedUntilUtc, so the challenge could be raised and never
satisfied.  140_auth_profile_procedures.sql said in prose that "112's MFA path wrote that column" before any procedure
here did; section 5 is what makes that sentence true.

The consequence for this file's report is that it now answers a third question -- "can this deployment step a session
up" -- and the answer depends on one setting more than enrolment does (Authn.StepUpElevationMinutes), so the closing
report checks it.

THE SECRET ARRIVES AS CIPHERTEXT AND LEAVES AS NOTHING AT ALL
-----------------------------------------------------------
Section 6.4, and the whole of the G-07 decision.  The application encrypts the TOTP secret, and the database stores the
result plus a LABEL naming the key -- never the key.  There is no procedure in this file that returns SecretCiphertext,
and that is deliberate: the engine has no use for it, so the only party that can read it is the party that can decrypt
it, and it already has it.

What that buys, concretely: a restored backup of this database, read by somebody with sysadmin on the restoring
instance, yields a column of ciphertext and a column of key names.  Power BI and every other external reader sees the
same.  SQL Server Always Encrypted was considered and rejected -- it would have put the decision in the driver and made
the column unreadable to the reporting tools this template is required to keep serving (G-07, and see the deviation note
in the design document).

WHO IS ALLOWED TO ENROL, AND THE PARADOX THAT QUESTION CONTAINS
-------------------------------------------------------------
A first factor has to be enrolled by somebody who cannot yet satisfy MFA -- that is what "first" means.  So the obvious
rule, "hold a live session", locks out exactly the person who needs the feature: a policy that requires MFA refuses the
sign-in (E-50109), and the refusal is permanent because the only route to a factor is through a session the refusal
prevents.

The way out is that the refusal is itself a record.  D-14 says one sign-in exchange is one auth.LoginAttempt row, and
110 writes PasswordVerified = 1 BEFORE it checks MFA.  So a just-refused exchange is the database's own statement that
this person's password verified, made by the database, and it is admissible as proof of identity for one narrow purpose
inside a short window.  auth.udfResolveEnrolmentActor is that rule, in one place, and Authn.MfaEnrolmentWindowSeconds is
the window.  Set it to 0 and the route closes.

Every procedure here that needs an actor therefore takes TWO parameters and requires exactly one of them:

  *  @SessionTokenHash        -- the ordinary case.  Resolved by auth.udfResolveSessionUser.
  *  @BootstrapLoginAttemptId -- the first-factor case.  Resolved by auth.udfResolveEnrolmentActor.

Supplying both is E-50117 and so is supplying neither.  An ambiguous actor is not something to resolve by precedence
rules nobody will read.

WHAT THE APPLICATION IS TRUSTED FOR HERE, EXHAUSTIVELY
----------------------------------------------------
Worth listing here as 110 lists it, because this is the other half of the same boundary.

  *  The ciphertext of a secret it generated and encrypted, and the label of the key it used.
  *  The SHA-256 of each recovery code it generated -- never the codes.
  *  Which TOTP time step it verified at when confirming, bounded here against the server's clock.
  *  A session token's SHA-256, or a login-attempt identifier.

Everything else -- whether that attempt is usable as proof, whether the account is usable, whether a factor already
exists, whether the key label is the current one -- is decided here.

WHY auth.uspRotateMfaFactorKey TAKES NO ACTOR
-------------------------------------------
It is the one procedure in this file with no @SessionTokenHash and no @BootstrapLoginAttemptId, and the reason is that
re-encrypting a secret requires the OLD key and the NEW one.  Only the application layer holds either.  There is no user
in the story: a re-key sweep runs at deployment time, over rows belonging to people who are asleep.

What bounds it instead is what it cannot do.  It cannot create a factor (the row must exist), cannot confirm one (it
never touches IsConfirmed), cannot move one between accounts (the trigger makes UserId immutable), cannot leave a row
mislabelled (the grammar is checked), and cannot be used as a no-op probe (a reference equal to the row's current one is
E-50123).  Its blast radius is "replace ciphertext the caller already had the key for", which is a thing the key holder
could do anyway.

THE RE-KEY RESETS THE REPLAY HIGH-WATER MARK, AND THAT IS ACCEPTED
----------------------------------------------------------------
trg_au_updt_UserMfaFactor requires that a changed SecretCiphertext clears LastUsedTimeStep and LastUsedUtc in the same
statement, because a new secret with an old high-water step locks the user out of their own authenticator until the
clock catches up.  The cost is that for one TOTP window after a re-key -- 30 seconds at the shipped
Authn.TotpStepSeconds, 60 with Authn.TotpWindowSteps either side -- a code already used could be presented again.

That is documented rather than engineered around.  The alternative is a second high-water column that survives re-keying
and therefore has to be reasoned about separately, to close a window that requires the attacker to have captured a code
in the last thirty seconds AND the operator to be re-keying in the same thirty seconds.  UI-32 records it.
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

-- Asserted, not gated -- finding F-07.  A PROCEDURE gets deferred name resolution, so every one of these would install
-- happily against a missing table and fail at CALL time with error 2812.
IF OBJECT_ID (N'auth.[User]', N'U') IS NULL
   OR OBJECT_ID (N'auth.UserMfaFactor', N'U') IS NULL
   OR OBJECT_ID (N'auth.UserMfaRecoveryCode', N'U') IS NULL
   OR OBJECT_ID (N'auth.LoginAttempt', N'U') IS NULL
   OR OBJECT_ID (N'auth.UserSession', N'U') IS NULL
   OR OBJECT_ID (N'logs.AuthenticationEvent', N'U') IS NULL
   OR OBJECT_ID (N'config.ApplicationSetting', N'U') IS NULL
BEGIN
    DECLARE @MsgTables NVARCHAR (2000) =
        N'One or more parent tables are missing. Run database/025_config_tables.sql, 045_auth_identity.sql, '
      + N'070_auth_session.sql and 085_logs_auth_tables.sql first. Nothing has been changed.';

    THROW 50000, @MsgTables, 1;
END
GO

-- The two actor-resolution functions are the security boundary of this file, not a convenience.  If either is missing,
-- every procedure here would still install and would then refuse every call it received -- which looks like a data
-- problem and is not one.
IF OBJECT_ID (N'auth.udfIsUserUsable', N'FN') IS NULL
   OR OBJECT_ID (N'auth.udfResolveSessionUser', N'FN') IS NULL
   OR OBJECT_ID (N'auth.udfResolveEnrolmentActor', N'FN') IS NULL
BEGIN
    DECLARE @MsgFunctions NVARCHAR (2000) =
        N'auth.udfIsUserUsable, auth.udfResolveSessionUser or auth.udfResolveEnrolmentActor is missing. Run '
      + N'database/100_auth_functions.sql first -- the two resolver functions are how every procedure in this file '
      + N'decides who is calling it. Nothing has been changed.';

    THROW 50000, @MsgFunctions, 1;
END
GO

-- The vocabulary check.  logs.AuthenticationEvent.EventType is a closed set, and three of the values this file writes
-- arrived with T-041.  Installing against the older constraint would mean every successful enrolment failed at the
-- CHECK, at call time, with a message about a constraint rather than about a missing script.
IF NOT EXISTS (SELECT 1
                 FROM sys.check_constraints
                WHERE name        = N'CK_logs_AuthenticationEvent_EventType'
                  AND definition LIKE N'%RecoveryCodesIssued%'
                  AND definition LIKE N'%MfaKeyRotated%'
                  AND definition LIKE N'%MfaEnrolmentRefused%')
BEGIN
    DECLARE @MsgVocabulary NVARCHAR (2000) =
        N'CK_logs_AuthenticationEvent_EventType does not admit ''RecoveryCodesIssued'', ''MfaKeyRotated'' and ''MfaEnrolmentRefused''. '
      + N'Re-run database/085_logs_auth_tables.sql, which reconciles the constraint in place. Nothing has been changed.';

    THROW 50000, @MsgVocabulary, 1;
END
GO

IF OBJECT_ID (N'logs.uspStartExecutionLogging', N'P') IS NULL
   OR OBJECT_ID (N'logs.uspRecordExecutionError', N'P') IS NULL
BEGIN
    DECLARE @MsgLogging NVARCHAR (2000) =
        N'logs.uspStartExecutionLogging or logs.uspRecordExecutionError is missing. Run '
      + N'database/010_logging_objects.sql first. Every procedure in this file is instrumented and will not run '
      + N'without them. Nothing has been changed.';

    THROW 50000, @MsgLogging, 1;
END
GO

-- *** 1. auth.uspEnrolMfaFactor ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspEnrolMfaFactor
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Records a second factor the application has already generated and encrypted.  The factor arrives UNCONFIRMED and cannot
satisfy MFA until auth.uspConfirmMfaFactor has seen one working code -- E-50110 is what an unconfirmed factor produces
at sign-in.

The actor is either a live session (@SessionTokenHash) or a sign-in exchange the database itself refused for want of MFA
(@BootstrapLoginAttemptId).  Exactly one.  See the notes and section 6.4.

========================================================================================================================
Notes:

THE SECRET IS A PARAMETER AND THE KEY IS NOT.  @SecretCiphertext is whatever the application's envelope encryption
produced -- at the shipped recommendation, a TPM-backed CNG key wrapping a per-secret data key, on the application-layer
server (G-07).  This procedure treats it as opaque bytes: it checks that there are at least sixteen of them, which is
shorter than any AES-GCM envelope of a 20-byte TOTP secret can be, and it checks nothing else because there is nothing
else it could check without the key.

@KeyReference MUST EQUAL Authn.MfaKeyReferenceCurrent, and defaults to it.  That is stricter than "must be grammatical",
deliberately: an application still encrypting under a retired key is the failure this catches, and it is a failure that
is otherwise invisible until the day the retired key is deleted and every factor in the table stops decrypting at once.
A deployment rotating keys therefore updates the setting FIRST and sweeps afterwards with auth.uspRotateMfaFactorKey.
The GRAMMAR -- scheme:name#vN -- is not re-checked here; CK_auth_UserMfaFactor_KeyReferenceFormat is its one authority,
and a copy of that predicate in this procedure would be a second authority that could disagree with it.

A CONFIRMED FACTOR OF THAT TYPE IS E-50119 AND NOT A REPLACEMENT.  Re-enrolling over a working authenticator is exactly
what an attacker who has borrowed a session wants to do, and it is silent: the victim's app keeps showing codes, they
just stop being the ones that work.  Replacing a confirmed factor is therefore a separate act that has to remove the old
one first, which is a deliberate, auditable step and not a side effect of the enrolment screen.

AN UNCONFIRMED FACTOR OF THAT TYPE IS OVERWRITTEN, and must be: UX_auth_UserMfaFactor_UserType permits one live row per
user per type, so an abandoned enrolment would otherwise block every later attempt until somebody cleaned it up by hand.
The overwrite clears LastUsedUtc and LastUsedTimeStep in the same statement because trg_au_updt_UserMfaFactor requires
it -- an old high-water step against a new secret locks the user out of their own new authenticator.

WHY THE BOOTSTRAP ROUTE IS NOT A BACK DOOR, in one place, because it is the question a reviewer will ask first:

  *  The proof is a row the DATABASE wrote, not a claim the caller makes.  PasswordVerified = 1 with
     FailureReason = 'MfaRequired' is written by auth.uspCompleteLogin before it refuses.
  *  It expires.  Authn.MfaEnrolmentWindowSeconds, 900 by default, measured from AttemptedUtc.  Set it to 0 and the
     route is closed with no code change.
  *  It grants an IDENTITY and not a permission.  The E-50119 check above still applies, so the window is a route to a
     FIRST factor and to nothing else -- it cannot be used to replace a working one.
  *  It is single-use in practice: the enrolment does not satisfy the refused exchange, which stays concluded.  The user
     signs in again afterwards, and that sign-in now has a factor to present.

========================================================================================================================
Example Usage and Performance:

-- Ordinary case: an authenticated user adding a factor.
declare @FactorId int;
exec auth.uspEnrolMfaFactor @SessionTokenHash = 0x4a2b..., @SecretCiphertext = 0x01A7...
   , @UserMfaFactorId = @FactorId output;

-- First factor, straight after a sign-in the policy refused (E-50109).
exec auth.uspEnrolMfaFactor @BootstrapLoginAttemptId = 4211, @SecretCiphertext = 0x01A7...
   , @UserMfaFactorId = @FactorId output;

One seek to resolve the actor, one on UX_auth_UserMfaFactor_UserType, one insert or one update, one event insert.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-041
Description:
Created.  Phase 2.  Closes gap G-07.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspEnrolMfaFactor
      @SecretCiphertext        VARBINARY (MAX)
    , @SessionTokenHash        VARBINARY (32) = NULL
    , @BootstrapLoginAttemptId BIGINT         = NULL
    , @FactorType              VARCHAR (20)   = 'Totp'
    , @KeyReference            NVARCHAR (256) = NULL
    , @UserMfaFactorId         INT            = NULL OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspEnrolMfaFactor]')
          , @StartTimeUtc   DATETIME2 (3)  = SYSUTCDATETIME ()
          , @EndTimeUtc     DATETIME2 (3)  = NULL
          , @ExecutionId    BIGINT         = NULL
          , @KeyParameters  NVARCHAR (MAX) = NULL
          , @Comments       NVARCHAR (MAX) = NULL
          , @ContextMessage NVARCHAR (MAX) = NULL
          , @DynamicSql     NVARCHAR (MAX) = NULL
          , @ErrorMsg       NVARCHAR (MAX) = NULL
          , @ErrorProc      NVARCHAR (300) = NULL
          , @ErrorNumber    INT            = NULL
          , @ErrorLine      INT            = NULL;

    DECLARE @Now     DATETIME2 (3)  = SYSUTCDATETIME ()
          , @Actor   NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                              , ORIGINAL_LOGIN ());

    -- The ciphertext is NOT a key parameter and must never become one: logs.ExecutionLog is readable by
    -- logsAuditReader, and a log of enrolment payloads is a second copy of every secret in the system.  The key
    -- REFERENCE is recorded, because it is a label and knowing which key a row was written under is the whole point of
    -- having labels.
    SET @KeyParameters = CONCAT (N'@FactorType=', @FactorType
                               , N', @KeyReference=', COALESCE (@KeyReference, N'(default)')
                               , N', actor=', CASE WHEN @SessionTokenHash IS NOT NULL THEN N'session'
                                                   WHEN @BootstrapLoginAttemptId IS NOT NULL
                                                        THEN CONCAT (N'bootstrap attempt ', @BootstrapLoginAttemptId)
                                                   ELSE N'(none supplied)' END
                               , N', ciphertext bytes=', COALESCE (DATALENGTH (@SecretCiphertext), 0));
    SET @ContextMessage = N'Enrol an unconfirmed second factor. T-041, section 6.4. The secret arrives encrypted and the key never reaches this server.';

    DECLARE @UserId           INT            = NULL
          , @UserName         NVARCHAR (256) = NULL
          , @CurrentKeyRef    NVARCHAR (256) = NULL
          , @UserSessionId    BIGINT         = NULL
          , @ClientAddress    NVARCHAR (45)  = NULL
          , @ExistingFactorId INT            = NULL
          , @ExistingIsConf   BIT            = NULL
          , @WasReplacement   BIT            = 0;

    BEGIN TRY
        EXEC logs.uspStartExecutionLogging
              @ProcedureName          = @ProcName
            , @KeyParameters          = @KeyParameters
            , @StartDateUtc           = @StartTimeUtc
            , @ReCreatedAfterRollback = 0
            , @ExecutionLogId         = @ExecutionId OUTPUT;

        BEGIN TRANSACTION;
        -- =========================================================================================
        -- ===== The procedure's own work starts here. Everything above and below is boilerplate. ==
        -- =========================================================================================

        -- 0.  Clear the output parameter.  Nothing below reads it, so this one is about what the CALLER sees: every
        --     refusal here leaves the enrolment unmade, and a caller that finds its old factor identifier still sitting
        --     in the variable afterwards has been handed a plausible answer to a question that was refused.
        SET @UserMfaFactorId = NULL;

        -- 1.  Exactly one form of actor proof.  Neither and both are the same refusal: an ambiguous actor is not
        --     something to settle by a precedence rule nobody will read.
        IF (@SessionTokenHash IS NULL AND @BootstrapLoginAttemptId IS NULL)
           OR (@SessionTokenHash IS NOT NULL AND @BootstrapLoginAttemptId IS NOT NULL)
        BEGIN
            ;THROW 50117, N'Exactly one of @SessionTokenHash or @BootstrapLoginAttemptId is required. Neither means there is nobody to attribute this enrolment to; both means two answers to the question of who is calling, and this procedure will not choose between them. Nothing has been changed.', 1;
        END;

        -- 2.  Resolve the actor.  Both rules live in 100_auth_functions.sql and neither is repeated here -- a rule that
        --     fails OPEN gets exactly one definition.
        IF @SessionTokenHash IS NOT NULL
        BEGIN
            SET @UserId = auth.udfResolveSessionUser (@SessionTokenHash);

            IF @UserId IS NULL
            BEGIN
                ;THROW 50114, N'That session token does not identify a live session: it is unknown, ended, soft-deleted, past its absolute expiry or past its idle expiry. The function that decides this does not say which, deliberately. Nothing has been changed.', 1;
            END;

            -- Session metadata for the event row.  The liveness decision was made by auth.udfResolveSessionUser above
            -- and is NOT repeated here -- this read must not be mistaken for a second check.  Hash and IsDeleted only,
            -- which UX_auth_UserSession_TokenHash makes a single unique seek.
            SELECT @UserSessionId = s.UserSessionId
                 , @ClientAddress = s.ClientAddress
              FROM auth.UserSession AS s
             WHERE s.SessionTokenHash = @SessionTokenHash
               AND s.IsDeleted        = 0;
        END
        ELSE
        BEGIN
            SET @UserId = auth.udfResolveEnrolmentActor (@BootstrapLoginAttemptId);

            IF @UserId IS NULL
            BEGIN
                ;THROW 50122, N'That login attempt is not usable as enrolment proof. It must be a Failure with FailureReason ''MfaRequired'' and PasswordVerified = 1, and it must be within Authn.MfaEnrolmentWindowSeconds of when it was made. A window of 0 closes this route entirely, which is a configuration choice and not a fault. Nothing has been changed.', 1;
            END;

            SELECT @ClientAddress = a.ClientAddress
              FROM auth.LoginAttempt AS a
             WHERE a.LoginAttemptId = @BootstrapLoginAttemptId;
        END;

        -- 3.  The account itself.  Checked after the actor is known, because an unusable account is E-50115 and that
        --     message is only safe to give somebody who has already proved who they are.
        IF auth.udfIsUserUsable (@UserId) = 0
        BEGIN
            ;THROW 50115, N'That account is deleted, inactive or locked out, so it cannot enrol a factor. Safe to say plainly here: the caller has already proved their identity to reach this point. Nothing has been changed.', 1;
        END;

        SELECT @UserName = u.UserName
          FROM auth.[User] AS u
         WHERE u.UserId = @UserId;

        -- 4.  The payload.  Two cheap checks and no third: the type vocabulary, and a floor on the ciphertext that is
        --     shorter than any real envelope of a TOTP secret.
        IF @FactorType IS NULL OR @FactorType NOT IN ('Totp')
        BEGIN
            ;THROW 50100, N'@FactorType must be ''Totp''. It is the only value CK_auth_UserMfaFactor_FactorType admits today; adding a second is an ALTER with a reviewer, which is the cost a closed vocabulary charges on purpose. Nothing has been changed.', 1;
        END;

        IF @SecretCiphertext IS NULL OR DATALENGTH (@SecretCiphertext) < 16
        BEGIN
            ;THROW 50100, N'@SecretCiphertext is missing or shorter than 16 bytes, which no AES-GCM envelope of a TOTP secret can be. This is the shape of a failed encryption that was stored anyway. Nothing has been changed.', 1;
        END;

        -- 5.  The key label must be the CURRENT one.  Fails closed when the setting is absent: a deployment with no
        --     named key has not decided which key it is using, and guessing on its behalf is how rows end up
        --     unrecoverable.
        SET @CurrentKeyRef = (SELECT NULLIF (LTRIM (RTRIM (s.SettingValue)), N'')
                                FROM config.ApplicationSetting AS s
                               WHERE s.SettingKey = N'Authn.MfaKeyReferenceCurrent'
                                 AND s.IsDeleted  = 0);

        IF @CurrentKeyRef IS NULL
        BEGIN
            ;THROW 50118, N'config.ApplicationSetting has no usable Authn.MfaKeyReferenceCurrent row, so there is no current key to label this factor with. Re-run database/025_config_tables.sql and set the value for this deployment. Failing closed is deliberate: a factor stored under a guessed label is a factor nobody can prove they can still decrypt. Nothing has been changed.', 1;
        END;

        SET @KeyReference = COALESCE (NULLIF (LTRIM (RTRIM (@KeyReference)), N''), @CurrentKeyRef);

        IF @KeyReference <> @CurrentKeyRef
        BEGIN
            ;THROW 50118, N'@KeyReference is not Authn.MfaKeyReferenceCurrent. New factors are always written under the current key; a caller naming a different one is an application still encrypting under a key this deployment has retired, which is invisible until the retired key is gone and every factor stops decrypting at once. To move to a new key, update the setting first and then sweep with auth.uspRotateMfaFactorKey. Nothing has been changed.', 1;
        END;

        -- 6.  What is already there.  One live row per user per type, so this is a single seek and there are exactly
        --     three outcomes: refuse, replace, insert.
        SELECT @ExistingFactorId = f.UserMfaFactorId
             , @ExistingIsConf   = f.IsConfirmed
          FROM auth.UserMfaFactor AS f
         WHERE f.UserId     = @UserId
           AND f.FactorType = @FactorType
           AND f.IsDeleted  = 0;

        IF @ExistingFactorId IS NOT NULL AND @ExistingIsConf = 1
        BEGIN
            -- Recorded, and recorded as a Warning, because a borrowed session quietly replacing a working authenticator
            -- is the attack this refusal exists for and the attempt is worth seeing in the log.
            INSERT logs.AuthenticationEvent
                (EventUtc, EventType, EventSeverity, UserId, UserName, LoginAttemptId, UserSessionId
               , ClientAddress, Actor, DetailJson)
            VALUES (@Now, 'MfaEnrolmentRefused', 'Warning', @UserId, @UserName, @BootstrapLoginAttemptId, @UserSessionId
                  , @ClientAddress, @Actor
                  , CONCAT (N'{"factorType":"', @FactorType, N'","existingFactorId":', @ExistingFactorId
                          , N',"reason":"a confirmed factor of this type already exists","route":"'
                          , CASE WHEN @SessionTokenHash IS NOT NULL THEN N'session' ELSE N'bootstrap' END, N'"}'));

            -- Commit the record before raising: the CATCH rolls back an open transaction, and a refusal that rolls away
            -- its own evidence is a refusal nobody can count.  Same pattern as every refusal in 110.
            IF @@TRANCOUNT > 0
            BEGIN
                COMMIT TRANSACTION;
            END;

            ;THROW 50119, N'This account already holds a confirmed factor of that type. Replacing a working authenticator is a separate, auditable act that removes the old factor first -- not a side effect of the enrolment screen -- because a silent replacement leaves the victim''s app still showing codes that no longer work. The attempt has been recorded. Nothing has been changed.', 1;
        END;

        IF @ExistingFactorId IS NOT NULL
        BEGIN
            -- An abandoned enrolment.  Overwritten rather than left to block every later attempt, and LastUsedUtc with
            -- LastUsedTimeStep are cleared in the SAME statement because trg_au_updt_UserMfaFactor requires it.
            UPDATE auth.UserMfaFactor
               SET SecretCiphertext     = @SecretCiphertext
                 , KeyReference         = @KeyReference
                 , LastUsedUtc          = NULL
                 , LastUsedTimeStep     = NULL
                 , auditModifiedBy      = @Actor
                 , auditModifiedDateUtc = @Now
             WHERE UserMfaFactorId = @ExistingFactorId;

            SET @UserMfaFactorId = @ExistingFactorId;
            SET @WasReplacement  = 1;
        END
        ELSE
        BEGIN
            INSERT auth.UserMfaFactor
                (UserId, FactorType, SecretCiphertext, KeyReference, IsConfirmed, ConfirmedUtc
               , auditCreatedBy, auditCreatedDateUtc, auditModifiedBy, auditModifiedDateUtc)
            VALUES (@UserId, @FactorType, @SecretCiphertext, @KeyReference, 0, NULL
                  , @Actor, @Now, @Actor, @Now);

            SET @UserMfaFactorId = CAST (SCOPE_IDENTITY () AS INT);
        END;

        INSERT logs.AuthenticationEvent
            (EventUtc, EventType, EventSeverity, UserId, UserName, LoginAttemptId, UserSessionId
           , ClientAddress, Actor, DetailJson)
        VALUES (@Now, 'MfaEnrolled', 'Info', @UserId, @UserName, @BootstrapLoginAttemptId, @UserSessionId
              , @ClientAddress, @Actor
              , CONCAT (N'{"factorId":', @UserMfaFactorId, N',"factorType":"', @FactorType
                      , N'","keyReference":"', STRING_ESCAPE (@KeyReference, 'json')
                      , N'","confirmed":false,"replacedUnconfirmed":'
                      , CASE WHEN @WasReplacement = 1 THEN N'true' ELSE N'false' END
                      , N',"route":"', CASE WHEN @SessionTokenHash IS NOT NULL THEN N'session' ELSE N'bootstrap' END
                      , N'"}'));

        SET @Comments = CONCAT (N'Factor ', @UserMfaFactorId, N' (', @FactorType, N') enrolled UNCONFIRMED for user '
                              , @UserId, N' under key ', @KeyReference, N'. '
                              , CASE WHEN @WasReplacement = 1 THEN N'Replaced an abandoned enrolment. '
                                     ELSE N'New row. ' END
                              , N'Route: '
                              , CASE WHEN @SessionTokenHash IS NOT NULL THEN N'live session.'
                                     ELSE N'bootstrap exchange.' END);

        -- =========================================================================================
        -- ===== End of the procedure's own work. ===================================================
        -- =========================================================================================
        IF @@TRANCOUNT > 0
        BEGIN
            COMMIT TRANSACTION;
        END;

        SET @EndTimeUtc = SYSUTCDATETIME ();

        IF @ExecutionId IS NOT NULL
        BEGIN
            UPDATE logs.ExecutionLog
               SET EndDateUtc           = @EndTimeUtc
                 , ElapsedMilliseconds  = CAST (LEAST (DATEDIFF_BIG (MILLISECOND, @StartTimeUtc, @EndTimeUtc)
                                                     , CAST (2147483647 AS BIGINT)) AS INT)
                 , Successful           = 1
                 , Comments             = @Comments
                 , auditModifiedBy      = ORIGINAL_LOGIN ()
                 , auditModifiedDateUtc = @EndTimeUtc
             WHERE ExecutionLogId = @ExecutionId;
        END;
    END TRY
    BEGIN CATCH
        SELECT @ErrorNumber = ERROR_NUMBER ()
             , @ErrorProc   = ERROR_PROCEDURE ()
             , @ErrorLine   = ERROR_LINE ()
             , @ErrorMsg    = ERROR_MESSAGE ()
                            + N' (error '  + CAST (ERROR_NUMBER () AS NVARCHAR (11))
                            + N', line '   + CAST (ERROR_LINE ()   AS NVARCHAR (11)) + N')';

        IF XACT_STATE () <> 0
        BEGIN
            ROLLBACK TRANSACTION;
        END;

        BEGIN TRY
            IF @ExecutionId IS NULL
               OR NOT EXISTS (SELECT 1 FROM logs.ExecutionLog WHERE ExecutionLogId = @ExecutionId)
            BEGIN
                EXEC logs.uspStartExecutionLogging
                      @ProcedureName          = @ProcName
                    , @KeyParameters          = @KeyParameters
                    , @StartDateUtc           = @StartTimeUtc
                    , @ReCreatedAfterRollback = 1
                    , @ExecutionLogId         = @ExecutionId OUTPUT;
            END;
        END TRY
        BEGIN CATCH
            SET @ExecutionId = NULL;
        END CATCH;

        EXEC logs.uspRecordExecutionError
              @ProcedureName   = @ProcName
            , @KeyParameters   = @KeyParameters
            , @ExecutionLogId  = @ExecutionId
            , @ErrorMessage    = @ErrorMsg
            , @ErrorProcedure  = @ErrorProc
            , @ErrorNumber     = @ErrorNumber
            , @ErrorLine       = @ErrorLine
            , @DynamicSql      = @DynamicSql
            , @ContextMessage  = @ContextMessage;

        ;THROW;
    END CATCH;

    RETURN 0;
END;
GO

-- *** 2. auth.uspConfirmMfaFactor ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspConfirmMfaFactor
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Turns an enrolment in progress into a usable factor.  The application verifies one code against the secret it has just
issued and reports which TOTP time step it verified at; this procedure bounds that step against the SERVER's clock and
then sets IsConfirmed = 1.

Until this runs, auth.uspVerifyMfa refuses the factor with E-50110.  After it runs, the same code the user just typed
still works -- see the notes, because that is a deliberate choice and it looks like an oversight.

========================================================================================================================
Notes:

THE STEP IS NOT SPENT HERE, ON PURPOSE.  LastUsedTimeStep and LastUsedUtc are left alone, so the code the user typed on
the enrolment screen can immediately be accepted by auth.uspVerifyMfa to finish the sign-in that sent them there.

Spending it would be more symmetrical and worse.  A first factor is enrolled from a REFUSED exchange (see
auth.uspEnrolMfaFactor), so the user's next action is always to sign in again and present a code.  If confirmation had
spent the step, that sign-in would refuse the only code their authenticator is currently showing -- E-50111, a replay
refusal, for a code that has never been used to authenticate anything -- and the user would have to wait out the window
staring at a wrong-code message.  The window this leaves open is "the code used to confirm can also be used once to sign
in, within thirty seconds, by whoever already holds the secret", and whoever holds the secret is the person enrolling.

auth.uspVerifyMfa REMAINS THE ONLY WRITER OF auth.LoginAttempt.MfaSatisfied.  This procedure does not touch the exchange
at all -- not even the bootstrap one it may have been called with.  Confirming a factor is not authenticating with it,
and a procedure on the enrolment path that could satisfy MFA would be a second authentication route with none of 110's
throttles in front of it.

THE CLOCK CHECK IS THE SAME ARITHMETIC AS uspVerifyMfa'S and is here for the same reason: @TimeStep is a number the
application chose, and without a bound against SYSUTCDATETIME () it is a free pass.  There is no replay check, because
there is nothing to replay against -- a factor being confirmed has no accepted step yet, and a freshly re-keyed one has
had its high-water mark cleared by trg_au_updt_UserMfaFactor.

E-50120 MEANS "NOTHING TO CONFIRM", which covers two cases a caller cannot tell apart from outside and does not need to:
there is no factor of that type at all, or the one there is has already been confirmed.  Confirming twice is not an
error worth its own number -- it is a double-submitted form -- and distinguishing it would say whether the account holds
a working factor to anybody who can reach this procedure.

========================================================================================================================
Example Usage and Performance:

declare @Confirmed bit;
exec auth.uspConfirmMfaFactor @BootstrapLoginAttemptId = 4211, @TimeStep = 58312345
   , @IsConfirmed = @Confirmed output;

One seek to resolve the actor, one on UX_auth_UserMfaFactor_UserType, one update, one event insert.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-041
Description:
Created.  Phase 2.  Closes gap G-07.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspConfirmMfaFactor
      @TimeStep                BIGINT
    , @SessionTokenHash        VARBINARY (32) = NULL
    , @BootstrapLoginAttemptId BIGINT         = NULL
    , @FactorType              VARCHAR (20)   = 'Totp'
    , @UserMfaFactorId         INT            = NULL OUTPUT
    , @IsConfirmed             BIT            = NULL OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspConfirmMfaFactor]')
          , @StartTimeUtc   DATETIME2 (3)  = SYSUTCDATETIME ()
          , @EndTimeUtc     DATETIME2 (3)  = NULL
          , @ExecutionId    BIGINT         = NULL
          , @KeyParameters  NVARCHAR (MAX) = NULL
          , @Comments       NVARCHAR (MAX) = NULL
          , @ContextMessage NVARCHAR (MAX) = NULL
          , @DynamicSql     NVARCHAR (MAX) = NULL
          , @ErrorMsg       NVARCHAR (MAX) = NULL
          , @ErrorProc      NVARCHAR (300) = NULL
          , @ErrorNumber    INT            = NULL
          , @ErrorLine      INT            = NULL;

    DECLARE @Now     DATETIME2 (3)  = SYSUTCDATETIME ()
          , @Actor   NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                              , ORIGINAL_LOGIN ());

    -- The time step is recorded, and is not a secret: it is a number derived from the clock, which everybody has.
    SET @KeyParameters = CONCAT (N'@FactorType=', @FactorType
                               , N', @TimeStep=', @TimeStep
                               , N', actor=', CASE WHEN @SessionTokenHash IS NOT NULL THEN N'session'
                                                   WHEN @BootstrapLoginAttemptId IS NOT NULL
                                                        THEN CONCAT (N'bootstrap attempt ', @BootstrapLoginAttemptId)
                                                   ELSE N'(none supplied)' END);
    SET @ContextMessage = N'Confirm an enrolled factor. T-041, section 6.4. Does not spend the time step and does not touch MfaSatisfied.';

    DECLARE @UserId        INT            = NULL
          , @UserName      NVARCHAR (256) = NULL
          , @UserSessionId BIGINT         = NULL
          , @ClientAddress NVARCHAR (45)  = NULL
          , @StepSeconds   INT            = NULL
          , @WindowSteps   INT            = NULL
          , @ServerStep    BIGINT         = NULL;

    BEGIN TRY
        EXEC logs.uspStartExecutionLogging
              @ProcedureName          = @ProcName
            , @KeyParameters          = @KeyParameters
            , @StartDateUtc           = @StartTimeUtc
            , @ReCreatedAfterRollback = 0
            , @ExecutionLogId         = @ExecutionId OUTPUT;

        BEGIN TRANSACTION;
        -- =========================================================================================
        -- ===== The procedure's own work starts here. Everything above and below is boilerplate. ==
        -- =========================================================================================

        -- 0.  CLEAR THE OUTPUT PARAMETERS FIRST, AND THIS IS NOT TIDINESS.  An OUTPUT parameter arrives holding whatever
        --     the caller last left in the variable, and step 3 below tests for "nothing to confirm" by seeing whether a
        --     SELECT assigned @UserMfaFactorId -- a SELECT that assigns NOTHING when no row matches.  Leave the caller's
        --     stale value in place and a second confirmation of an already-confirmed factor sails past E-50120 and
        --     re-stamps ConfirmedUtc on a working authenticator.  Found by _tests/040 section 12j, which re-uses one
        --     variable across calls exactly as an application with one variable per request does.
        SET @UserMfaFactorId = NULL;
        SET @IsConfirmed     = 0;

        -- 1.  Exactly one form of actor proof.  Identical rule to uspEnrolMfaFactor, and identical refusal.
        IF (@SessionTokenHash IS NULL AND @BootstrapLoginAttemptId IS NULL)
           OR (@SessionTokenHash IS NOT NULL AND @BootstrapLoginAttemptId IS NOT NULL)
        BEGIN
            ;THROW 50117, N'Exactly one of @SessionTokenHash or @BootstrapLoginAttemptId is required. Neither means there is nobody to attribute this confirmation to; both means two answers to the question of who is calling, and this procedure will not choose between them. Nothing has been changed.', 1;
        END;

        -- 2.  Resolve the actor.  Both rules live in 100_auth_functions.sql.
        IF @SessionTokenHash IS NOT NULL
        BEGIN
            SET @UserId = auth.udfResolveSessionUser (@SessionTokenHash);

            IF @UserId IS NULL
            BEGIN
                ;THROW 50114, N'That session token does not identify a live session: it is unknown, ended, soft-deleted, past its absolute expiry or past its idle expiry. The function that decides this does not say which, deliberately. Nothing has been changed.', 1;
            END;

            -- Metadata only.  The liveness decision was made above by auth.udfResolveSessionUser and is not repeated.
            SELECT @UserSessionId = s.UserSessionId
                 , @ClientAddress = s.ClientAddress
              FROM auth.UserSession AS s
             WHERE s.SessionTokenHash = @SessionTokenHash
               AND s.IsDeleted        = 0;
        END
        ELSE
        BEGIN
            SET @UserId = auth.udfResolveEnrolmentActor (@BootstrapLoginAttemptId);

            IF @UserId IS NULL
            BEGIN
                ;THROW 50122, N'That login attempt is not usable as enrolment proof. It must be a Failure with FailureReason ''MfaRequired'' and PasswordVerified = 1, and it must be within Authn.MfaEnrolmentWindowSeconds of when it was made. The window is deliberately short: it exists to get a first factor onto an account and closes on its own. Nothing has been changed.', 1;
            END;

            SELECT @ClientAddress = a.ClientAddress
              FROM auth.LoginAttempt AS a
             WHERE a.LoginAttemptId = @BootstrapLoginAttemptId;
        END;

        IF auth.udfIsUserUsable (@UserId) = 0
        BEGIN
            ;THROW 50115, N'That account is deleted, inactive or locked out, so it cannot confirm a factor. Safe to say plainly here: the caller has already proved their identity to reach this point. Nothing has been changed.', 1;
        END;

        SELECT @UserName = u.UserName
          FROM auth.[User] AS u
         WHERE u.UserId = @UserId;

        -- 3.  The factor being confirmed: live, of that type, and NOT already confirmed.
        SELECT @UserMfaFactorId = f.UserMfaFactorId
          FROM auth.UserMfaFactor AS f
         WHERE f.UserId      = @UserId
           AND f.FactorType  = @FactorType
           AND f.IsConfirmed = 0
           AND f.IsDeleted   = 0;

        IF @UserMfaFactorId IS NULL
        BEGIN
            ;THROW 50120, N'There is no unconfirmed factor of that type to confirm. Either nothing has been enrolled, or it has already been confirmed -- and this refusal deliberately does not say which, because that answer tells whoever asked whether the account holds a working second factor. A double-submitted confirmation form lands here and should be treated as success by the caller. Nothing has been changed.', 1;
        END;

        -- 4.  Bound the reported step against the server's own.  Same arithmetic as auth.uspVerifyMfa: DATEDIFF_BIG
        --     because DATEDIFF in seconds from 1970 overflows an INT in 2038, and a template that stops working on a
        --     date is a template with a fuse in it.
        SET @StepSeconds = COALESCE (TRY_CAST ((SELECT SettingValue FROM config.ApplicationSetting
                                                 WHERE SettingKey = N'Authn.TotpStepSeconds'
                                                   AND IsDeleted  = 0) AS INT), 30);
        SET @WindowSteps = COALESCE (TRY_CAST ((SELECT SettingValue FROM config.ApplicationSetting
                                                 WHERE SettingKey = N'Authn.TotpWindowSteps'
                                                   AND IsDeleted  = 0) AS INT), 1);

        SET @ServerStep = DATEDIFF_BIG (SECOND, CAST (N'1970-01-01T00:00:00' AS DATETIME2 (0)), @Now)
                        / @StepSeconds;

        IF @TimeStep IS NULL OR @TimeStep <= 0 OR ABS (@TimeStep - @ServerStep) > @WindowSteps
        BEGIN
            INSERT logs.AuthenticationEvent
                (EventUtc, EventType, EventSeverity, UserId, UserName, LoginAttemptId, UserSessionId
               , ClientAddress, Actor, DetailJson)
            VALUES (@Now, 'MfaFailed', 'Warning', @UserId, @UserName, @BootstrapLoginAttemptId, @UserSessionId
                  , @ClientAddress, @Actor
                  , CONCAT (N'{"factorId":', @UserMfaFactorId, N',"stage":"ConfirmMfaFactor","reportedStep":'
                          , COALESCE (CAST (@TimeStep AS NVARCHAR (30)), N'null'), N',"serverStep":', @ServerStep
                          , N',"windowSteps":', @WindowSteps, N',"stepSeconds":', @StepSeconds, N'}'));

            -- Committed before raising, for the reason every refusal in 110 commits: the CATCH rolls back an open
            -- transaction, and a refusal that rolls away its own evidence cannot be counted.
            IF @@TRANCOUNT > 0
            BEGIN
                COMMIT TRANSACTION;
            END;

            ;THROW 50111, N'The reported TOTP time step is missing, not positive, or outside Authn.TotpWindowSteps of the server''s own step. Nothing is confirmed. Unlike the same refusal at sign-in, this one does not conclude any exchange -- there is nothing here for an attacker to walk, because reaching this procedure already required proof of identity. The detail is in logs.AuthenticationEvent.', 1;
        END;

        -- 5.  Confirm.  IsConfirmed and ConfirmedUtc together -- CK_auth_UserMfaFactor_ConfirmedPair requires the pair.
        --     LastUsedUtc and LastUsedTimeStep are deliberately NOT written: see the notes.
        UPDATE auth.UserMfaFactor
           SET IsConfirmed          = 1
             , ConfirmedUtc         = @Now
             , auditModifiedBy      = @Actor
             , auditModifiedDateUtc = @Now
         WHERE UserMfaFactorId = @UserMfaFactorId;

        SET @IsConfirmed = 1;

        INSERT logs.AuthenticationEvent
            (EventUtc, EventType, EventSeverity, UserId, UserName, LoginAttemptId, UserSessionId
           , ClientAddress, Actor, DetailJson)
        VALUES (@Now, 'MfaConfirmed', 'Info', @UserId, @UserName, @BootstrapLoginAttemptId, @UserSessionId
              , @ClientAddress, @Actor
              , CONCAT (N'{"factorId":', @UserMfaFactorId, N',"factorType":"', @FactorType
                      , N'","confirmedAtStep":', @TimeStep, N',"stepNotSpent":true,"route":"'
                      , CASE WHEN @SessionTokenHash IS NOT NULL THEN N'session' ELSE N'bootstrap' END, N'"}'));

        SET @Comments = CONCAT (N'Factor ', @UserMfaFactorId, N' (', @FactorType, N') confirmed for user ', @UserId
                              , N' at step ', @TimeStep, N' (server step ', @ServerStep, N', window '
                              , @WindowSteps, N'). The step was NOT spent, so the same code completes the sign-in.');

        -- =========================================================================================
        -- ===== End of the procedure's own work. ===================================================
        -- =========================================================================================
        IF @@TRANCOUNT > 0
        BEGIN
            COMMIT TRANSACTION;
        END;

        SET @EndTimeUtc = SYSUTCDATETIME ();

        IF @ExecutionId IS NOT NULL
        BEGIN
            UPDATE logs.ExecutionLog
               SET EndDateUtc           = @EndTimeUtc
                 , ElapsedMilliseconds  = CAST (LEAST (DATEDIFF_BIG (MILLISECOND, @StartTimeUtc, @EndTimeUtc)
                                                     , CAST (2147483647 AS BIGINT)) AS INT)
                 , Successful           = 1
                 , Comments             = @Comments
                 , auditModifiedBy      = ORIGINAL_LOGIN ()
                 , auditModifiedDateUtc = @EndTimeUtc
             WHERE ExecutionLogId = @ExecutionId;
        END;
    END TRY
    BEGIN CATCH
        SELECT @ErrorNumber = ERROR_NUMBER ()
             , @ErrorProc   = ERROR_PROCEDURE ()
             , @ErrorLine   = ERROR_LINE ()
             , @ErrorMsg    = ERROR_MESSAGE ()
                            + N' (error '  + CAST (ERROR_NUMBER () AS NVARCHAR (11))
                            + N', line '   + CAST (ERROR_LINE ()   AS NVARCHAR (11)) + N')';

        IF XACT_STATE () <> 0
        BEGIN
            ROLLBACK TRANSACTION;
        END;

        BEGIN TRY
            IF @ExecutionId IS NULL
               OR NOT EXISTS (SELECT 1 FROM logs.ExecutionLog WHERE ExecutionLogId = @ExecutionId)
            BEGIN
                EXEC logs.uspStartExecutionLogging
                      @ProcedureName          = @ProcName
                    , @KeyParameters          = @KeyParameters
                    , @StartDateUtc           = @StartTimeUtc
                    , @ReCreatedAfterRollback = 1
                    , @ExecutionLogId         = @ExecutionId OUTPUT;
            END;
        END TRY
        BEGIN CATCH
            SET @ExecutionId = NULL;
        END CATCH;

        EXEC logs.uspRecordExecutionError
              @ProcedureName   = @ProcName
            , @KeyParameters   = @KeyParameters
            , @ExecutionLogId  = @ExecutionId
            , @ErrorMessage    = @ErrorMsg
            , @ErrorProcedure  = @ErrorProc
            , @ErrorNumber     = @ErrorNumber
            , @ErrorLine       = @ErrorLine
            , @DynamicSql      = @DynamicSql
            , @ContextMessage  = @ContextMessage;

        ;THROW;
    END CATCH;

    RETURN 0;
END;
GO

-- *** 3. auth.uspIssueMfaRecoveryCodes ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspIssueMfaRecoveryCodes
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Replaces a user's batch of one-time recovery codes.  The application generates the codes, shows them to the user once,
and sends their SHA-256 hashes here as a JSON array of hex strings.  The codes themselves never reach the database, for
the same reason passwords do not (D-08).

Issuing a batch retires whatever unused codes the user held.  Codes already spent are kept -- they are the audit trail
of a recovery that happened.

========================================================================================================================
Notes:

HASHES ARRIVE AS HEX TEXT, NOT AS A DELIMITED STRING AND NOT ONE CALL PER CODE.  A batch is issued as a batch because
that is the atomic unit: ten codes shown on one screen, and a partial issue means the user is holding a printout that is
half wrong.  JSON rather than a comma list because OPENJSON reports the TYPE of each element, which is how a malformed
entry is caught rather than silently coerced -- a bare string split on commas cannot tell '"abc"' from 'null'.

E-50046 IS "NOT A JSON ARRAY" and is the same number every other array payload in this schema uses. E-50121 is
everything else wrong with the batch, and it is deliberately ONE number covering: an empty array, more codes than
Authn.MfaRecoveryCodeCount permits, a non-string element, a string that is not 64 hex characters, and a duplicate. They
are one number because they are one caller error -- the application's code generator is broken -- and no operator action
differs between them. The detail says which.

A CONFIRMED FACTOR IS REQUIRED FIRST -- E-50110, the same number sign-in uses for the same condition.  Recovery codes
recover from the loss of a factor; a batch issued to an account that has none is a set of ten passwords that bypass an
MFA requirement nobody has satisfied yet.

THE OLD UNUSED CODES ARE SOFT-DELETED, NEVER DELETED.  Two reasons, and the second one is the one that bites:

  *  Hard DELETE is forbidden by the conventions, everywhere, without exception.
  *  UX_auth_UserMfaRecoveryCode_UserCode is filtered WHERE IsDeleted = 0, so a retired code stops colliding with a
     re-issued one the moment it is flagged.  Without the soft delete, re-issuing the same code by coincidence -- which
     happens, over enough deployments -- would be a refused issue with a unique-index error nobody could explain.

USED CODES ARE LEFT ALONE, and that is not an oversight.  A row with UsedUtc set is the record that somebody recovered an
account with a code on a particular date, which is exactly the row an incident review needs.  Soft-deleting it would put
it behind the filtered index and out of the way of every report that counts recoveries.

========================================================================================================================
Example Usage and Performance:

declare @Issued int;
exec auth.uspIssueMfaRecoveryCodes
      @SessionTokenHash = 0x4a2b...
    , @CodeHashesJson   = N'["3b1f...64 hex...", "9ac2...64 hex..."]'
    , @IssuedCount      = @Issued output;

One seek to resolve the actor, one to prove a confirmed factor, one OPENJSON over a payload of ten short strings, one
update and one insert against IX_auth_UserMfaRecoveryCode_Unused.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-041
Description:
Created.  Phase 2.  Closes gap G-07.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspIssueMfaRecoveryCodes
      @CodeHashesJson          NVARCHAR (MAX)
    , @SessionTokenHash        VARBINARY (32) = NULL
    , @BootstrapLoginAttemptId BIGINT         = NULL
    , @IssuedCount             INT            = NULL OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspIssueMfaRecoveryCodes]')
          , @StartTimeUtc   DATETIME2 (3)  = SYSUTCDATETIME ()
          , @EndTimeUtc     DATETIME2 (3)  = NULL
          , @ExecutionId    BIGINT         = NULL
          , @KeyParameters  NVARCHAR (MAX) = NULL
          , @Comments       NVARCHAR (MAX) = NULL
          , @ContextMessage NVARCHAR (MAX) = NULL
          , @DynamicSql     NVARCHAR (MAX) = NULL
          , @ErrorMsg       NVARCHAR (MAX) = NULL
          , @ErrorProc      NVARCHAR (300) = NULL
          , @ErrorNumber    INT            = NULL
          , @ErrorLine      INT            = NULL;

    DECLARE @Now     DATETIME2 (3)  = SYSUTCDATETIME ()
          , @Actor   NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                              , ORIGINAL_LOGIN ());

    -- The PAYLOAD IS NOT LOGGED, and the reason is worth stating where somebody might be tempted to add it for
    -- debugging: it is a list of hashes of live credentials, and logs.ExecutionLog is readable by logsAuditReader.  Its
    -- LENGTH is logged, which is all a diagnosis of a malformed batch actually needs.
    SET @KeyParameters = CONCAT (N'@CodeHashesJson length=', COALESCE (LEN (@CodeHashesJson), 0)
                               , N', actor=', CASE WHEN @SessionTokenHash IS NOT NULL THEN N'session'
                                                   WHEN @BootstrapLoginAttemptId IS NOT NULL
                                                        THEN CONCAT (N'bootstrap attempt ', @BootstrapLoginAttemptId)
                                                   ELSE N'(none supplied)' END);
    SET @ContextMessage = N'Replace the recovery-code batch. T-041, section 6.4. Hashes only -- the codes never reach this server.';

    DECLARE @UserId         INT            = NULL
          , @UserName       NVARCHAR (256) = NULL
          , @UserSessionId  BIGINT         = NULL
          , @ClientAddress  NVARCHAR (45)  = NULL
          , @MaxCodes       INT            = NULL
          , @Submitted      INT            = NULL
          , @BadType        INT            = NULL
          , @BadLength      INT            = NULL
          , @BadHex         INT            = NULL
          , @DistinctHashes INT            = NULL
          , @FirstBadOrdinal INT           = NULL
          , @Retired        INT            = 0;

    DECLARE @Incoming TABLE
    (
        RowNo     INT IDENTITY (1, 1) PRIMARY KEY,
        ValueType INT             NOT NULL,
        RawText   NVARCHAR (200)      NULL,
        CodeHash  VARBINARY (32)      NULL
    );

    BEGIN TRY
        EXEC logs.uspStartExecutionLogging
              @ProcedureName          = @ProcName
            , @KeyParameters          = @KeyParameters
            , @StartDateUtc           = @StartTimeUtc
            , @ReCreatedAfterRollback = 0
            , @ExecutionLogId         = @ExecutionId OUTPUT;

        BEGIN TRANSACTION;
        -- =========================================================================================
        -- ===== The procedure's own work starts here. Everything above and below is boilerplate. ==
        -- =========================================================================================

        SET @IssuedCount = 0;

        -- 1.  Exactly one form of actor proof.  Identical rule to the other two, and identical refusal.
        IF (@SessionTokenHash IS NULL AND @BootstrapLoginAttemptId IS NULL)
           OR (@SessionTokenHash IS NOT NULL AND @BootstrapLoginAttemptId IS NOT NULL)
        BEGIN
            ;THROW 50117, N'Exactly one of @SessionTokenHash or @BootstrapLoginAttemptId is required. Neither means there is nobody to issue codes to; both means two answers to the question of who is calling, and this procedure will not choose between them. Nothing has been changed.', 1;
        END;

        IF @SessionTokenHash IS NOT NULL
        BEGIN
            SET @UserId = auth.udfResolveSessionUser (@SessionTokenHash);

            IF @UserId IS NULL
            BEGIN
                ;THROW 50114, N'That session token does not identify a live session: it is unknown, ended, soft-deleted, past its absolute expiry or past its idle expiry. The function that decides this does not say which, deliberately. Nothing has been changed.', 1;
            END;

            -- Metadata only.  The liveness decision was made above and is not repeated here.
            SELECT @UserSessionId = s.UserSessionId
                 , @ClientAddress = s.ClientAddress
              FROM auth.UserSession AS s
             WHERE s.SessionTokenHash = @SessionTokenHash
               AND s.IsDeleted        = 0;
        END
        ELSE
        BEGIN
            SET @UserId = auth.udfResolveEnrolmentActor (@BootstrapLoginAttemptId);

            IF @UserId IS NULL
            BEGIN
                ;THROW 50122, N'That login attempt is not usable as enrolment proof. It must be a Failure with FailureReason ''MfaRequired'' and PasswordVerified = 1, and it must be within Authn.MfaEnrolmentWindowSeconds of when it was made. Nothing has been changed.', 1;
            END;

            SELECT @ClientAddress = a.ClientAddress
              FROM auth.LoginAttempt AS a
             WHERE a.LoginAttemptId = @BootstrapLoginAttemptId;
        END;

        IF auth.udfIsUserUsable (@UserId) = 0
        BEGIN
            ;THROW 50115, N'That account is deleted, inactive or locked out, so it cannot be issued recovery codes. Safe to say plainly here: the caller has already proved their identity to reach this point. Nothing has been changed.', 1;
        END;

        SELECT @UserName = u.UserName
          FROM auth.[User] AS u
         WHERE u.UserId = @UserId;

        -- 2.  A confirmed factor first.  E-50110, the same number sign-in raises for the same condition.
        IF NOT EXISTS (SELECT 1
                         FROM auth.UserMfaFactor AS f
                        WHERE f.UserId      = @UserId
                          AND f.IsConfirmed = 1
                          AND f.IsDeleted   = 0)
        BEGIN
            ;THROW 50110, N'This account holds no confirmed factor, so there is nothing for recovery codes to recover from. Issued first, they would be a set of one-time passwords that satisfy an MFA requirement the account has never satisfied at all. Confirm a factor with auth.uspConfirmMfaFactor and then issue the batch. Nothing has been changed.', 1;
        END;

        -- 3.  The payload has to be an array before anything can be said about its contents.
        IF @CodeHashesJson IS NULL OR ISJSON (@CodeHashesJson, ARRAY) = 0
        BEGIN
            ;THROW 50046, N'@CodeHashesJson must be a JSON ARRAY of 64-character hex strings -- ["3b1f...", "9ac2..."]. An object, a bare string or malformed text is refused here rather than half-parsed. Nothing has been changed.', 1;
        END;

        SET @MaxCodes = COALESCE (TRY_CAST ((SELECT SettingValue FROM config.ApplicationSetting
                                              WHERE SettingKey = N'Authn.MfaRecoveryCodeCount'
                                                AND IsDeleted  = 0) AS INT), 10);

        -- j.type = 1 is a JSON string.  Anything else -- a number, null, a nested array -- is a generator that has gone
        -- wrong, and TRY_CONVERT would quietly turn some of those into NULL rather than complain.
        INSERT @Incoming (ValueType, RawText, CodeHash)
        SELECT j.[type]
             , LEFT (j.[value], 200)
             , CASE WHEN j.[type] = 1 AND LEN (j.[value]) = 64
                    THEN TRY_CONVERT (VARBINARY (32), j.[value], 2)
                    ELSE NULL END
          FROM OPENJSON (@CodeHashesJson) AS j;

        SELECT @Submitted      = COUNT (*)
             , @BadType        = SUM (CASE WHEN ValueType <> 1 THEN 1 ELSE 0 END)
             , @BadLength      = SUM (CASE WHEN ValueType = 1 AND LEN (COALESCE (RawText, N'')) <> 64 THEN 1 ELSE 0 END)
             , @BadHex         = SUM (CASE WHEN ValueType = 1 AND LEN (COALESCE (RawText, N'')) = 64
                                            AND CodeHash IS NULL THEN 1 ELSE 0 END)
             , @DistinctHashes = COUNT (DISTINCT CodeHash)
          FROM @Incoming;

        -- One number for the whole class -- see the notes -- and a detail that says which member of it.
        IF @Submitted = 0 OR @Submitted > @MaxCodes
           OR @BadType > 0 OR @BadLength > 0 OR @BadHex > 0
           OR @DistinctHashes <> @Submitted
        BEGIN
            -- The ORDINAL of the first bad element, added with G-32.  That gap's subject is a sibling procedure
            -- (auth.uspSetRolePermissions, which gained E-50180 for this), and the argument two paragraphs above -- one
            -- number for the whole class, because they are one fault in the caller's generator -- still holds here, so
            -- this batch does NOT get a second error number.  What G-32 is right about regardless is that "an element is
            -- malformed" in a ten-element array is the start of a search rather than the end of one.  The position goes
            -- in the comment and not in the message, because the message is returned to a caller and the counts belong
            -- with the execution; the RAW VALUE is never recorded either way, since these elements are hashes of
            -- credentials and UI-16 covers hashes explicitly.
            SELECT @FirstBadOrdinal = MIN (i.RowNo) - 1
              FROM @Incoming AS i
             WHERE i.ValueType <> 1
                OR LEN (COALESCE (i.RawText, N'')) <> 64
                OR i.CodeHash IS NULL;

            SET @Comments = CONCAT (N'Malformed recovery-code batch for user ', @UserId, N': submitted ', @Submitted
                                  , N', permitted ', @MaxCodes, N', non-string ', @BadType, N', wrong length '
                                  , @BadLength, N', not hex ', @BadHex, N', distinct ', @DistinctHashes
                                  , N'. First malformed element at index '
                                  , COALESCE (CAST (@FirstBadOrdinal AS NVARCHAR (11))
                                            , N'(none -- the fault is the batch size or a duplicate)'), N'.');

            -- Recorded as a comment on this execution and not as an authentication event: nothing happened to the
            -- account, and a broken client retrying every second should not fill the security log.
            ;THROW 50121, N'The recovery-code batch is malformed. It must hold between one and Authn.MfaRecoveryCodeCount entries, each a distinct 64-character hex string -- the SHA-256 of one code. Empty batches, over-long batches, non-string elements, wrong-length strings, non-hex strings and duplicates are all refused here as one error, because they are all the same fault in the caller''s generator. The counts are in logs.ExecutionLog against this execution. Nothing has been changed.', 1;
        END;

        -- 4.  Retire what they held.  Unused only, soft-deleted, never a hard DELETE -- and the soft delete is what lets
        --     a coincidentally identical code be re-issued without colliding on the filtered unique index.
        UPDATE auth.UserMfaRecoveryCode
           SET IsDeleted            = 1
             , auditDeletedBy       = @Actor
             , auditDeletedDateUtc  = @Now
             , auditModifiedBy      = @Actor
             , auditModifiedDateUtc = @Now
         WHERE UserId    = @UserId
           AND UsedUtc  IS NULL
           AND IsDeleted = 0;

        SET @Retired = @@ROWCOUNT;

        -- 5.  Issue the new batch, in the order it was submitted, because that is the order on the user's printout.
        INSERT auth.UserMfaRecoveryCode
            (UserId, CodeHash, UsedUtc, auditCreatedBy, auditCreatedDateUtc, auditModifiedBy, auditModifiedDateUtc)
        SELECT @UserId, i.CodeHash, NULL, @Actor, @Now, @Actor, @Now
          FROM @Incoming AS i
         ORDER BY i.RowNo;

        SET @IssuedCount = @@ROWCOUNT;

        INSERT logs.AuthenticationEvent
            (EventUtc, EventType, EventSeverity, UserId, UserName, LoginAttemptId, UserSessionId
           , ClientAddress, Actor, DetailJson)
        VALUES (@Now, 'RecoveryCodesIssued', 'Info', @UserId, @UserName, @BootstrapLoginAttemptId, @UserSessionId
              , @ClientAddress, @Actor
              , CONCAT (N'{"issued":', @IssuedCount, N',"retiredUnused":', @Retired, N',"permitted":', @MaxCodes
                      , N',"route":"', CASE WHEN @SessionTokenHash IS NOT NULL THEN N'session' ELSE N'bootstrap' END
                      , N'"}'));

        SET @Comments = CONCAT (N'Issued ', @IssuedCount, N' recovery code(s) for user ', @UserId, N' and retired '
                              , @Retired, N' unused one(s). Used codes were left alone: they are the record that a '
                              , N'recovery happened.');

        -- =========================================================================================
        -- ===== End of the procedure's own work. ===================================================
        -- =========================================================================================
        IF @@TRANCOUNT > 0
        BEGIN
            COMMIT TRANSACTION;
        END;

        SET @EndTimeUtc = SYSUTCDATETIME ();

        IF @ExecutionId IS NOT NULL
        BEGIN
            UPDATE logs.ExecutionLog
               SET EndDateUtc           = @EndTimeUtc
                 , ElapsedMilliseconds  = CAST (LEAST (DATEDIFF_BIG (MILLISECOND, @StartTimeUtc, @EndTimeUtc)
                                                     , CAST (2147483647 AS BIGINT)) AS INT)
                 , Successful           = 1
                 , Comments             = @Comments
                 , auditModifiedBy      = ORIGINAL_LOGIN ()
                 , auditModifiedDateUtc = @EndTimeUtc
             WHERE ExecutionLogId = @ExecutionId;
        END;
    END TRY
    BEGIN CATCH
        SELECT @ErrorNumber = ERROR_NUMBER ()
             , @ErrorProc   = ERROR_PROCEDURE ()
             , @ErrorLine   = ERROR_LINE ()
             , @ErrorMsg    = ERROR_MESSAGE ()
                            + N' (error '  + CAST (ERROR_NUMBER () AS NVARCHAR (11))
                            + N', line '   + CAST (ERROR_LINE ()   AS NVARCHAR (11)) + N')';

        IF XACT_STATE () <> 0
        BEGIN
            ROLLBACK TRANSACTION;
        END;

        BEGIN TRY
            IF @ExecutionId IS NULL
               OR NOT EXISTS (SELECT 1 FROM logs.ExecutionLog WHERE ExecutionLogId = @ExecutionId)
            BEGIN
                EXEC logs.uspStartExecutionLogging
                      @ProcedureName          = @ProcName
                    , @KeyParameters          = @KeyParameters
                    , @StartDateUtc           = @StartTimeUtc
                    , @ReCreatedAfterRollback = 1
                    , @ExecutionLogId         = @ExecutionId OUTPUT;
            END;
        END TRY
        BEGIN CATCH
            SET @ExecutionId = NULL;
        END CATCH;

        -- The malformed-batch counts were put in @Comments before the THROW, and this is where they are preserved:
        -- uspRecordExecutionError takes them as the context message, so a broken generator can be diagnosed from the
        -- log without the payload ever having been written down.
        IF @ErrorNumber = 50121 AND @Comments IS NOT NULL
        BEGIN
            SET @ContextMessage = @Comments;
        END;

        EXEC logs.uspRecordExecutionError
              @ProcedureName   = @ProcName
            , @KeyParameters   = @KeyParameters
            , @ExecutionLogId  = @ExecutionId
            , @ErrorMessage    = @ErrorMsg
            , @ErrorProcedure  = @ErrorProc
            , @ErrorNumber     = @ErrorNumber
            , @ErrorLine       = @ErrorLine
            , @DynamicSql      = @DynamicSql
            , @ContextMessage  = @ContextMessage;

        ;THROW;
    END CATCH;

    RETURN 0;
END;
GO

-- *** 4. auth.uspRotateMfaFactorKey ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspRotateMfaFactorKey
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Replaces the stored ciphertext and key label of ONE factor, for a deployment that has re-encrypted that factor's secret
under a new key.  This is the sweep half of key rotation: the application decrypts with the old key, encrypts with the
new one, and calls this once per row.

The rows still to do are the ones whose KeyReference is not Authn.MfaKeyReferenceCurrent.  That query is the reason the
grammar exists -- see CK_auth_UserMfaFactor_KeyReferenceFormat in 045_auth_identity.sql.

========================================================================================================================
Notes:

THIS IS THE ONE PROCEDURE IN THIS FILE WITH NO ACTOR PROOF.  Re-encrypting a secret requires the old key and the new
one, and only the application layer holds either.  There is no user in the story: a rotation sweep runs at deployment
time over rows belonging to people who are asleep, and demanding a session token would mean the sweep could only touch
the factors of whoever happened to be signed in.

What bounds it instead is what it cannot do, and this list is the whole of the argument:

  *  It cannot create a factor.  The row must already exist and be live, else E-50120.
  *  It cannot confirm one.  IsConfirmed and ConfirmedUtc are not in the UPDATE, so a factor nobody proved a code
     against stays unconfirmed however many times it is re-keyed.
  *  It cannot move a factor between accounts.  trg_au_updt_UserMfaFactor makes UserId and FactorType immutable
     (E-50010), so there is no route from here to attaching somebody's authenticator to another account.
  *  It cannot mislabel a row.  @NewKeyReference must be Authn.MfaKeyReferenceCurrent, which is also what
     auth.uspEnrolMfaFactor enforces, so "current key" means one thing in this schema and not two.
  *  It cannot be used as a probe.  A row already on that key, or a ciphertext identical to the one stored, is E-50123 --
     so a caller cannot walk factor ids looking for which ones exist by watching which calls succeed.

Its blast radius is therefore "replace ciphertext the caller already held the key for", which is a thing the key holder
could do anyway.  What it buys is that the replacement is recorded, in logs.AuthenticationEvent, with the labels of both
keys.

THE ORDER OF A ROTATION IS: SETTING FIRST, SWEEP SECOND.  Authn.MfaKeyReferenceCurrent names the key NEW enrolments use,
so moving it first means every enrolment from that moment on is already on the new key and the sweep has a shrinking,
finite list.  Doing it the other way round -- sweep first, setting last -- means every row the sweep touches is refused
by the check above, which is a confusing way to discover the order.

RE-KEYING RESETS THE REPLAY HIGH-WATER MARK, and that is accepted rather than engineered around.
trg_au_updt_UserMfaFactor requires a changed SecretCiphertext to clear LastUsedTimeStep and LastUsedUtc in the same
statement, because an old high-water step against a new secret locks the user out of their own authenticator until the
clock catches up.  So for one TOTP window after a re-key -- 60 seconds at the shipped Authn.TotpStepSeconds of 30 with
Authn.TotpWindowSteps of 1 -- a code already used could be presented again.  UI-32 records it.  The alternative is a
second high-water column that survives re-keying and has to be reasoned about separately, to close a window that needs
the attacker to have captured a code in the last thirty seconds AND the operator to be re-keying in the same thirty.

========================================================================================================================
Example Usage and Performance:

-- The sweep, one row at a time, driven by the labels:
--   select UserMfaFactorId from auth.UserMfaFactor
--    where IsDeleted = 0 and KeyReference <> N'cng:authn-mfa-kek#v2';
declare @Owner int;
exec auth.uspRotateMfaFactorKey @UserMfaFactorId = 17, @SecretCiphertext = 0x01B9..., @UserId = @Owner output;

One clustered seek, one update, one event insert.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-041
Description:
Created.  Phase 2.  Closes gap G-07.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspRotateMfaFactorKey
      @UserMfaFactorId  INT
    , @SecretCiphertext VARBINARY (MAX)
    , @NewKeyReference  NVARCHAR (256) = NULL
    , @UserId           INT            = NULL OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspRotateMfaFactorKey]')
          , @StartTimeUtc   DATETIME2 (3)  = SYSUTCDATETIME ()
          , @EndTimeUtc     DATETIME2 (3)  = NULL
          , @ExecutionId    BIGINT         = NULL
          , @KeyParameters  NVARCHAR (MAX) = NULL
          , @Comments       NVARCHAR (MAX) = NULL
          , @ContextMessage NVARCHAR (MAX) = NULL
          , @DynamicSql     NVARCHAR (MAX) = NULL
          , @ErrorMsg       NVARCHAR (MAX) = NULL
          , @ErrorProc      NVARCHAR (300) = NULL
          , @ErrorNumber    INT            = NULL
          , @ErrorLine      INT            = NULL;

    DECLARE @Now     DATETIME2 (3)  = SYSUTCDATETIME ()
          , @Actor   NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                              , ORIGINAL_LOGIN ());

    SET @KeyParameters = CONCAT (N'@UserMfaFactorId=', @UserMfaFactorId
                               , N', @NewKeyReference=', COALESCE (@NewKeyReference, N'(default)')
                               , N', ciphertext bytes=', COALESCE (DATALENGTH (@SecretCiphertext), 0));
    SET @ContextMessage = N'Re-key one factor. T-041, section 6.4. No actor proof: only the key holder can re-encrypt, and the key holder is the application layer.';

    DECLARE @UserName       NVARCHAR (256) = NULL
          , @FactorType     VARCHAR (20)   = NULL
          , @OldKeyRef      NVARCHAR (256) = NULL
          , @CurrentKeyRef  NVARCHAR (256) = NULL
          , @OldCiphertext  VARBINARY (MAX) = NULL
          , @HadUsedStep    BIT            = 0;

    BEGIN TRY
        EXEC logs.uspStartExecutionLogging
              @ProcedureName          = @ProcName
            , @KeyParameters          = @KeyParameters
            , @StartDateUtc           = @StartTimeUtc
            , @ReCreatedAfterRollback = 0
            , @ExecutionLogId         = @ExecutionId OUTPUT;

        BEGIN TRANSACTION;
        -- =========================================================================================
        -- ===== The procedure's own work starts here. Everything above and below is boilerplate. ==
        -- =========================================================================================

        -- 0.  CLEAR THE OUTPUT PARAMETER FIRST, AND HERE IT IS LOAD-BEARING.  @UserId is both this procedure's OUTPUT and
        --     the flag step 2 reads to decide whether the factor exists at all -- and a SELECT that matches no row
        --     assigns nothing, leaving whatever the CALLER left in the variable.  The caller this matters for is the
        --     intended one: a rotation sweep looping over a list of factor identifiers with one @UserId variable.  Hand
        --     such a sweep a stale identifier and, without this line, E-50120 never fires, the UPDATE below touches zero
        --     rows, 'MfaKeyRotated' is logged for a factor that does not exist, and the sweep records the row as done --
        --     which is how a key retirement quietly leaves ciphertext behind that nothing can decrypt.  The same trap in
        --     auth.uspConfirmMfaFactor is cleared the same way, for the same reason.
        SET @UserId = NULL;

        -- 1.  The payload.  Same floor as enrolment, same reason.
        IF @SecretCiphertext IS NULL OR DATALENGTH (@SecretCiphertext) < 16
        BEGIN
            ;THROW 50100, N'@SecretCiphertext is missing or shorter than 16 bytes, which no AES-GCM envelope of a TOTP secret can be. A re-key that stored this would have destroyed a working factor. Nothing has been changed.', 1;
        END;

        -- 2.  The row.  Read before anything is decided, because both refusals below need what it holds.
        SELECT @UserId        = f.UserId
             , @FactorType    = f.FactorType
             , @OldKeyRef     = f.KeyReference
             , @OldCiphertext = f.SecretCiphertext
             , @HadUsedStep   = CASE WHEN f.LastUsedTimeStep IS NULL THEN 0 ELSE 1 END
          FROM auth.UserMfaFactor AS f
         WHERE f.UserMfaFactorId = @UserMfaFactorId
           AND f.IsDeleted       = 0;

        IF @UserId IS NULL
        BEGIN
            ;THROW 50120, N'There is no live factor with that identifier to re-key. This procedure cannot create one: a re-key replaces the ciphertext of a factor that already exists, and an identifier nobody holds is a sweep running against a stale list. Nothing has been changed.', 1;
        END;

        -- 3.  The label must be the CURRENT one, exactly as it must be at enrolment, so that "the current key" means one
        --     thing in this schema.  Fails closed when the setting is absent.
        SET @CurrentKeyRef = (SELECT NULLIF (LTRIM (RTRIM (s.SettingValue)), N'')
                                FROM config.ApplicationSetting AS s
                               WHERE s.SettingKey = N'Authn.MfaKeyReferenceCurrent'
                                 AND s.IsDeleted  = 0);

        IF @CurrentKeyRef IS NULL
        BEGIN
            ;THROW 50118, N'config.ApplicationSetting has no usable Authn.MfaKeyReferenceCurrent row, so there is no current key to re-key onto. A rotation moves that setting FIRST and sweeps afterwards; this refusal means the first half has not happened. Nothing has been changed.', 1;
        END;

        SET @NewKeyReference = COALESCE (NULLIF (LTRIM (RTRIM (@NewKeyReference)), N''), @CurrentKeyRef);

        IF @NewKeyReference <> @CurrentKeyRef
        BEGIN
            ;THROW 50118, N'@NewKeyReference is not Authn.MfaKeyReferenceCurrent. A sweep re-keys onto the current key and nowhere else; naming a third key would leave rows nobody is tracking. Update the setting first, then sweep. Nothing has been changed.', 1;
        END;

        -- 4.  Two ways a re-key is not a re-key, both E-50123.  Together they also stop this procedure being used to
        --     probe which factor identifiers exist, because a caller cannot tell a refusal apart from a no-op.
        IF @OldKeyRef = @NewKeyReference
        BEGIN
            ;THROW 50123, N'That factor is already labelled with this key, so there is nothing to rotate. Re-writing a row onto the label it already carries would clear its replay high-water mark for no reason, which is a free 60-second replay window in exchange for nothing. If the sweep is re-running, drive it from the labels: the rows still to do are the ones whose KeyReference is not Authn.MfaKeyReferenceCurrent. Nothing has been changed.', 1;
        END;

        IF @OldCiphertext = @SecretCiphertext
        BEGIN
            ;THROW 50123, N'The supplied ciphertext is byte-identical to the one already stored, so whatever the caller did, it was not encrypting under a different key. The label would have moved and the bytes would not, leaving a row that claims to be readable with a key it is not readable with -- which is the one failure key labels exist to prevent. Nothing has been changed.', 1;
        END;

        -- 5.  Replace.  LastUsedUtc and LastUsedTimeStep are cleared in the SAME statement because
        --     trg_au_updt_UserMfaFactor requires it of any change to SecretCiphertext -- see the notes on the window
        --     that opens.  IsConfirmed and ConfirmedUtc are deliberately absent: a re-key does not confirm anything.
        UPDATE auth.UserMfaFactor
           SET SecretCiphertext     = @SecretCiphertext
             , KeyReference         = @NewKeyReference
             , LastUsedUtc          = NULL
             , LastUsedTimeStep     = NULL
             , auditModifiedBy      = @Actor
             , auditModifiedDateUtc = @Now
         WHERE UserMfaFactorId = @UserMfaFactorId;

        SELECT @UserName = u.UserName
          FROM auth.[User] AS u
         WHERE u.UserId = @UserId;

        INSERT logs.AuthenticationEvent
            (EventUtc, EventType, EventSeverity, UserId, UserName, Actor, DetailJson)
        VALUES (@Now, 'MfaKeyRotated', 'Info', @UserId, @UserName, @Actor
              , CONCAT (N'{"factorId":', @UserMfaFactorId, N',"factorType":"', @FactorType
                      , N'","fromKeyReference":"', STRING_ESCAPE (@OldKeyRef, 'json')
                      , N'","toKeyReference":"',   STRING_ESCAPE (@NewKeyReference, 'json')
                      , N'","replayWatermarkCleared":'
                      , CASE WHEN @HadUsedStep = 1 THEN N'true' ELSE N'false' END, N'}'));

        SET @Comments = CONCAT (N'Factor ', @UserMfaFactorId, N' (user ', @UserId, N') re-keyed from ', @OldKeyRef
                              , N' to ', @NewKeyReference, N'. '
                              , CASE WHEN @HadUsedStep = 1
                                     THEN N'The replay high-water mark was cleared, as the trigger requires -- one TOTP '
                                        + N'window is replayable (UI-32).'
                                     ELSE N'There was no high-water mark to clear.' END);

        -- =========================================================================================
        -- ===== End of the procedure's own work. ===================================================
        -- =========================================================================================
        IF @@TRANCOUNT > 0
        BEGIN
            COMMIT TRANSACTION;
        END;

        SET @EndTimeUtc = SYSUTCDATETIME ();

        IF @ExecutionId IS NOT NULL
        BEGIN
            UPDATE logs.ExecutionLog
               SET EndDateUtc           = @EndTimeUtc
                 , ElapsedMilliseconds  = CAST (LEAST (DATEDIFF_BIG (MILLISECOND, @StartTimeUtc, @EndTimeUtc)
                                                     , CAST (2147483647 AS BIGINT)) AS INT)
                 , Successful           = 1
                 , Comments             = @Comments
                 , auditModifiedBy      = ORIGINAL_LOGIN ()
                 , auditModifiedDateUtc = @EndTimeUtc
             WHERE ExecutionLogId = @ExecutionId;
        END;
    END TRY
    BEGIN CATCH
        SELECT @ErrorNumber = ERROR_NUMBER ()
             , @ErrorProc   = ERROR_PROCEDURE ()
             , @ErrorLine   = ERROR_LINE ()
             , @ErrorMsg    = ERROR_MESSAGE ()
                            + N' (error '  + CAST (ERROR_NUMBER () AS NVARCHAR (11))
                            + N', line '   + CAST (ERROR_LINE ()   AS NVARCHAR (11)) + N')';

        IF XACT_STATE () <> 0
        BEGIN
            ROLLBACK TRANSACTION;
        END;

        BEGIN TRY
            IF @ExecutionId IS NULL
               OR NOT EXISTS (SELECT 1 FROM logs.ExecutionLog WHERE ExecutionLogId = @ExecutionId)
            BEGIN
                EXEC logs.uspStartExecutionLogging
                      @ProcedureName          = @ProcName
                    , @KeyParameters          = @KeyParameters
                    , @StartDateUtc           = @StartTimeUtc
                    , @ReCreatedAfterRollback = 1
                    , @ExecutionLogId         = @ExecutionId OUTPUT;
            END;
        END TRY
        BEGIN CATCH
            SET @ExecutionId = NULL;
        END CATCH;

        EXEC logs.uspRecordExecutionError
              @ProcedureName   = @ProcName
            , @KeyParameters   = @KeyParameters
            , @ExecutionLogId  = @ExecutionId
            , @ErrorMessage    = @ErrorMsg
            , @ErrorProcedure  = @ErrorProc
            , @ErrorNumber     = @ErrorNumber
            , @ErrorLine       = @ErrorLine
            , @DynamicSql      = @DynamicSql
            , @ContextMessage  = @ContextMessage;

        ;THROW;
    END CATCH;

    RETURN 0;
END;
GO

-- *** 5. auth.uspElevateSession ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspElevateSession
Author:       rsincero
CreateDate:   2026-09-21
========================================================================================================================
Description:

Satisfies a step-up challenge on a session that is ALREADY live, by one of two routes -- a TOTP code the application has
already verified, or a single-use recovery code -- and writes the session's elevation window, which is
auth.UserSession.ElevatedUntilUtc.  Sections 12.3 and 14.5.

This is the only writer of that column.  Gap G-48: for three phases auth.uspSwitchProfile has refused a privileged
profile with E-50052 whenever the session was not elevated, the design document has described the prompt-and-retry cycle
in section 12.1, 140_auth_profile_procedures.sql has said in prose that "112's MFA path wrote that column" -- and nothing
in the manifest could set it at all.  The challenge guarding every privileged profile could be raised and could not be
answered.  A challenge with no answer is not a control; it is an outage with a security rationale attached.

========================================================================================================================
Notes:

WHY IT IS HERE AND NOT IN 110.  110 is the sign-in protocol and every caller in it is anonymous until the exchange
concludes.  This file's rule is stated in its own header: every procedure here is reached by somebody who has ALREADY
proved something.  A step-up is the purest case of that -- the caller holds a live session and is being asked to prove
the second factor again -- so it belongs beside enrolment and confirmation rather than beside the login exchange.

IT DOES NOT CALL auth.uspSetSessionContext, AND THAT IS A DELIBERATE EXCEPTION TO THE HABIT OF EVERY OTHER
SESSION-BEARING PROCEDURE IN THIS TEMPLATE.  The caller that needs a step-up is almost always the connection that has
just received E-50052 from auth.uspSwitchProfile, which means it is ALREADY contexted -- and a second
auth.uspSetSessionContext call on a contexted connection raises E-50022, because the five identity keys are set
@read_only = 1 and cannot be re-set (UI-06, and the G-36 / BL-057 lesson).  A step-up that fails with a spurious error on
the only connection that ever asks for one is worse than no step-up at all, so the session is validated by reading
auth.UserSession directly.

WHAT THAT COSTS, STATED PLAINLY.  Reading the row loses auth.uspSetSessionContext's policy resolution.  This procedure
checks EndedUtc, AbsoluteExpiryUtc, IdleExpiryUtc and the account's own usability, and it does not re-resolve the
tenant's authentication policy.  It does not need to: nothing here is scoped by profile, nothing here reads a row-security
predicate, and the question it answers -- "was a valid second factor presented by the holder of this session" -- has no
tenant in it.  The authorization consequence of the elevation is evaluated afterwards by auth.uspSwitchProfile, on a
connection that does context itself.

IT DOES NOT SLIDE IdleExpiryUtc.  Answering a challenge is activity and it is tempting to treat it as such.  But the
idle timeout is resolved from auth.udfResolveAuthPolicy and moved forward in exactly one place --
auth.uspSetSessionContext -- and a second writer would be a second copy of the policy resolution, which is how two
copies of one rule begin to disagree.  The caller's next request re-contexts and slides it there, one round trip later.

LOCKOUT IS NOT RE-CHECKED EITHER, FOR THE SAME REASON.  auth.User.IsLockedOut governs SIGN-IN -- section 7.4 -- and the
session in front of this procedure was issued before the lock existed.  Ending such a session is
auth.uspEndSession's business and an operator's decision, and duplicating the test here would mean a second place where
"is this account usable" is defined.  IsActive and IsDeleted are checked, because those two are what
auth.uspSetSessionContext itself refuses on.

THE ELEVATION WINDOW IS BOUNDED BY THE SESSION AND NOT ONLY BY THE SETTING.  CK_auth_UserSession_ElevatedUntilUtc
requires ElevatedUntilUtc > StartedUtc AND <= AbsoluteExpiryUtc, so the value written is
LEAST (now + Authn.StepUpElevationMinutes, AbsoluteExpiryUtc).  A step-up cannot outlive the session it elevates, and the
one limit section 7.3 says activity may not extend is not extendable by a second factor either.

RE-ELEVATING NEVER SHORTENS A WINDOW THE SESSION ALREADY HOLDS -- hence GREATEST against the existing value.  The case is
an operator lowering Authn.StepUpElevationMinutes between two challenges: presenting a valid factor is not an act that
should take privilege away, and a user who was told to authenticate again and then found their window shorter than
before would reasonably conclude the prompt had been a trick.

THE SETTING IS CLAMPED TO 1..480 MINUTES.  Zero is the interesting end.  A window of zero minutes closes in the same
millisecond it opens, and on a session started in that same millisecond CK_auth_UserSession_ElevatedUntilUtc would refuse
it with error 547 -- an operator's typo surfacing as a constraint violation from inside a security procedure, which is
the least explicable failure this file could produce.  One minute is the floor instead: useless, but readable.  The
ceiling is eight hours because that is the shipped Authn.SessionLifetimeMinutes, and a window longer than the session it
bounds is a number with no effect -- and a number with no effect in a settings table is a number somebody will later
believe.

A USER WITH NO CONFIRMED FACTOR CANNOT BE ELEVATED, WHICH IS THE POLICY WORKING AND NOT A DEFECT.  E-50127 says so
plainly and names the remedy: enrol and confirm a factor from a session that does not need elevating.  A privileged
profile under a step-up policy is unreachable until then -- which is exactly what "this tenant requires a second factor
before privileged work" means.  The alternative, elevating on the strength of the session alone when no factor exists,
would make the policy self-cancelling for precisely the accounts that never set one up.

FAILED STEP-UPS ARE THROTTLED, AND THE THROTTLE ENDS THE SESSION.  This is the load-bearing decision in the procedure.
auth.uspVerifyMfa can afford a simple rule -- every failed code concludes the exchange -- because there IS an exchange to
conclude, and both of section 7.4's counters watch concluded failures.  A step-up has no exchange: the session survives
the failure by definition, so an unthrottled step-up is a TOTP oracle that whoever holds one stolen session token may
walk at their leisure, over a six-digit space, with nothing counting.  So failures are counted -- logs.AuthenticationEvent
rows of type 'MfaFailed' carrying THIS UserSessionId, inside Authn.LockoutWindowMinutes -- and at Authn.LockoutThreshold
the session is ended with EndReason 'Revoked' and E-50129 is raised.

  *  SCOPING THE COUNT BY UserSessionId IS EXACT, NOT APPROXIMATE.  auth.uspVerifyMfa's failures carry a LoginAttemptId
     and no UserSessionId, because at that point no session exists; this procedure's carry a UserSessionId and no
     LoginAttemptId.  The two populations cannot overlap, so somebody who fumbled their sign-in twice does not arrive
     here with two failures already spent.
  *  'Revoked' RATHER THAN A SEVENTH EndReason.  auth.uspEndSession accepts six values and refuses the rest (E-50100),
     and 'Revoked' is already classed there as a revocation -- which is what this is: the server, not the user, decided
     the session was over.  Inventing 'StepUpThrottled' would have meant a token no report knows how to group, in a
     column whose whole purpose is grouping.
  *  THE THRESHOLD IS SHARED WITH SIGN-IN ON PURPOSE.  An operator who has decided five wrong codes is the limit has
     decided it for both, and a separate Authn.StepUpThreshold would be a second dial nobody sets and everybody is
     surprised by.  Setting Authn.LockoutThreshold to 0 disables the database-side step-up throttle exactly as it
     disables the other one.
  *  THE ACCOUNT IS NOT LOCKED.  Only the session ends.  A step-up brute force is evidence about one token, and locking
     the account would let whoever holds that token deny service to its owner -- which turns the control into the attack.

THE FAILURE PATH RUNS WITH NO TRANSACTION OPEN, so the 'MfaFailed' row and the ended session survive the THROW that
follows them.  Rule 8's transaction is opened only once a factor has been accepted and there is state to write
atomically.  It is the same shape 140_auth_profile_procedures.sql uses for E-50052 and for the same reason: an event
recording a refusal is worthless if the refusal rolls it back.

THE STEP AND THE CODE ARE SPENT CONDITIONALLY, AND A LOST RACE IS E-50128.  The replay test reads LastUsedTimeStep before
the transaction and the UPDATE re-asserts it in its own WHERE clause, so two connections presenting the same code in the
same instant cannot both be elevated by it.  The loser gets E-50128 with no event of its own: the winner's event is the
record of what happened to that step, and two rows would read as two presentations of two codes.

ONE ERROR NUMBER FOR BOTH ROUTES' REFUSAL.  E-50128 covers a TOTP step outside the clock window, a replayed step, and a
recovery code that is unknown or already spent.  The caller supplied exactly one factor, so it already knows which one
was refused; the distinguishing detail goes to logs.AuthenticationEvent, where a reviewer can read it and a caller
cannot.

========================================================================================================================
Example Usage and Performance:

declare @Until datetime2 (3);

-- The ordinary case: auth.uspSwitchProfile raised E-50052, the UI prompted, the application verified the code.
exec auth.uspElevateSession @SessionTokenHash = 0x9F86..., @TimeStep = 58312345, @ElevatedUntilUtc = @Until output;

-- The lost-authenticator case.
exec auth.uspElevateSession @SessionTokenHash = 0x9F86...
   , @RecoveryCodeHash = 0x2C26B46B68FFC68FF99B453C1D30413413422D706483BFA0F98A5E886266E7AE
   , @ElevatedUntilUtc = @Until output;

-- Then the switch is retried ON A NEW CONNECTION, because the one that was refused is spent (UI-06).
exec auth.uspSwitchProfile @SessionTokenHash = 0x9F86..., @TargetUserProfileId = 91;

One seek on UX_auth_UserSession_TokenHash, one on the factor or the code, one narrow COUNT over
logs.AuthenticationEvent taken only when a factor is refused, and two narrow updates.

========================================================================================================================
Modification History:

Date:		2026-09-21
Author:		rsincero
Ticket:		T-125
Description:
Created.  Closes gap G-48, filed by scenario test SCEN-AUTH-001: nothing in the manifest wrote
auth.UserSession.ElevatedUntilUtc, so the step-up challenge guarding every privileged profile could be raised and never
satisfied.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspElevateSession
      @SessionTokenHash VARBINARY (32)
    , @TimeStep         BIGINT         = NULL
    , @RecoveryCodeHash VARBINARY (32) = NULL
    , @FactorType       VARCHAR (20)   = 'Totp'
    , @ElevatedUntilUtc DATETIME2 (3)  = NULL OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspElevateSession]')
          , @StartTimeUtc   DATETIME2 (3)  = SYSUTCDATETIME ()
          , @EndTimeUtc     DATETIME2 (3)  = NULL
          , @ExecutionId    BIGINT         = NULL
          , @KeyParameters  NVARCHAR (MAX) = NULL
          , @Comments       NVARCHAR (MAX) = NULL
          , @ContextMessage NVARCHAR (MAX) = NULL
          , @DynamicSql     NVARCHAR (MAX) = NULL
          , @ErrorMsg       NVARCHAR (MAX) = NULL
          , @ErrorProc      NVARCHAR (300) = NULL
          , @ErrorNumber    INT            = NULL
          , @ErrorLine      INT            = NULL;

    DECLARE @Now   DATETIME2 (3)  = SYSUTCDATETIME ()
          , @Actor NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                            , ORIGINAL_LOGIN ());

    -- The token hash is a credential in hashed form, so it is a presence flag and never a value -- rule 9, UI-16.  A
    -- time step is a clock reading and is logged as one.  UserSessionId is appended as soon as it is known, because the
    -- question asked of this row in an incident is always "which session".
    SET @KeyParameters = CONCAT (N'@SessionTokenHash=(supplied), @TimeStep='
                               , COALESCE (CAST (@TimeStep AS NVARCHAR (20)), N'(null)')
                               , N', @RecoveryCodeHash=', CASE WHEN @RecoveryCodeHash IS NULL
                                                              THEN N'(null)' ELSE N'(supplied)' END
                               , N', @FactorType=', @FactorType);
    SET @ContextMessage = N'Satisfy a step-up challenge on a live session and write its elevation window. Section 12.3.';

    DECLARE @SessionId         BIGINT          = NULL
          , @UserId            INT             = NULL
          , @ApplicationId     INT             = NULL
          , @UserName          NVARCHAR (256)  = NULL
          , @ClientAddress     NVARCHAR (45)   = NULL
          , @AbsoluteExpiryUtc DATETIME2 (3)   = NULL
          , @IdleExpiryUtc     DATETIME2 (3)   = NULL
          , @HeldUntilUtc      DATETIME2 (3)   = NULL
          , @Route             NVARCHAR (20)   = NULL
          , @StepSeconds       INT             = NULL
          , @WindowSteps       INT             = NULL
          , @ServerStep        BIGINT          = NULL
          , @FactorId          INT             = NULL
          , @LastUsedStep      BIGINT          = NULL
          , @RecoveryCodeId    INT             = NULL
          , @RemainingCodes    INT             = NULL
          , @WindowMinutes     INT             = NULL
          , @FreshUntilUtc     DATETIME2 (3)   = NULL
          , @NewUntilUtc       DATETIME2 (3)   = NULL
          , @Threshold         INT             = NULL
          , @LockoutWindow     INT             = NULL
          , @RecentFailures    INT             = NULL
          , @FailureReason     NVARCHAR (200)  = NULL
          , @Failure           NVARCHAR (2000) = NULL
          , @SessionsEnded     INT             = NULL;

    BEGIN TRY
        EXEC logs.uspStartExecutionLogging
              @ProcedureName          = @ProcName
            , @KeyParameters          = @KeyParameters
            , @StartDateUtc           = @StartTimeUtc
            , @ReCreatedAfterRollback = 0
            , @ExecutionLogId         = @ExecutionId OUTPUT;

        -- =========================================================================================
        -- ===== The procedure's own work starts here. Everything above and below is boilerplate. ==
        -- =========================================================================================
        -- STEPS 1 TO 3 RUN WITH NO TRANSACTION OPEN, ON PURPOSE.  A refusal writes an event and may revoke the session,
        -- and both of those must outlive the THROW that follows them.  See the notes.

        SET @ElevatedUntilUtc = NULL;

        -- 0.  Parameter shape, before anything is read.  All four refusals are E-50125: they are the same mistake --
        --     the call was not assembled correctly -- and splitting them would multiply numbers the UI must map without
        --     telling anybody anything the message does not already say.
        IF @SessionTokenHash IS NULL OR DATALENGTH (@SessionTokenHash) <> 32
        BEGIN
            ;THROW 50125, N'@SessionTokenHash must be exactly 32 bytes -- the SHA-256 of the session token the application holds. The token itself is never a parameter here, for the same reason a password is not (D-08). Raised before anything is read.', 1;
        END;

        IF (@TimeStep IS NULL AND @RecoveryCodeHash IS NULL)
           OR (@TimeStep IS NOT NULL AND @RecoveryCodeHash IS NOT NULL)
        BEGIN
            ;THROW 50125, N'Supply exactly one of @TimeStep (a TOTP step the application has already verified) or @RecoveryCodeHash (the SHA-256 of a recovery code). Both together would mean a failed code silently spending a recovery code; neither means there is nothing to verify and no reason to elevate. Raised before the session is read.', 1;
        END;

        SET @Route = CASE WHEN @TimeStep IS NOT NULL THEN N'Totp' ELSE N'RecoveryCode' END;

        IF @Route = N'Totp' AND (@FactorType <> 'Totp' OR @TimeStep <= 0)
        BEGIN
            ;THROW 50125, N'@FactorType must be ''Totp'' -- the only value auth.UserMfaFactor accepts today -- and @TimeStep must be a positive step number, not a Unix time in seconds. Raised before the session is read.', 1;
        END;

        IF @Route = N'RecoveryCode' AND DATALENGTH (@RecoveryCodeHash) <> 32
        BEGIN
            ;THROW 50125, N'@RecoveryCodeHash must be exactly 32 bytes -- the SHA-256 of the code, computed by the application. The code itself is never a parameter here, for the same reason a password is not (D-08).', 1;
        END;

        -- 1.  The session, read directly rather than through auth.uspSetSessionContext -- see the notes, and E-50022.
        SELECT @SessionId         = s.UserSessionId
             , @UserId            = s.UserId
             , @ApplicationId     = s.ApplicationId
             , @ClientAddress     = s.ClientAddress
             , @AbsoluteExpiryUtc = s.AbsoluteExpiryUtc
             , @IdleExpiryUtc     = s.IdleExpiryUtc
             , @HeldUntilUtc      = s.ElevatedUntilUtc
          FROM auth.UserSession AS s
         WHERE s.SessionTokenHash = @SessionTokenHash
           AND s.EndedUtc         IS NULL
           AND s.IsDeleted        = 0;

        IF @SessionId IS NOT NULL
        BEGIN
            SET @KeyParameters = CONCAT (@KeyParameters, N', UserSessionId=', @SessionId, N', UserId=', @UserId);

            -- @UserName doubles as the usability test: an inactive or deleted account leaves it NULL and the refusal
            -- below is the same one an absent session gets.
            SELECT @UserName = u.UserName
              FROM auth.[User] AS u
             WHERE u.UserId    = @UserId
               AND u.IsActive  = 1
               AND u.IsDeleted = 0;
        END;

        IF @SessionId IS NULL
           OR @UserName IS NULL
           OR @AbsoluteExpiryUtc <= @Now
           OR @IdleExpiryUtc     <= @Now
        BEGIN
            ;THROW 50126, N'There is no live, unexpired session for that token hash, or the account it belongs to is no longer usable. Sign in again: a step-up re-proves the second factor for a session that already exists and cannot create one. Absent, ended, idle-expired, absolutely expired and deactivated are one answer deliberately -- they are five facts about an account the caller may not own.', 1;
        END;

        IF @Route = N'Totp'
        BEGIN
            -- 2a.  The factor.  An unconfirmed factor is enrolment in progress and satisfies nothing: that is what
            --      IsConfirmed is for, and section 2 of this file is what sets it.
            SELECT @FactorId     = f.UserMfaFactorId
                 , @LastUsedStep = f.LastUsedTimeStep
              FROM auth.UserMfaFactor AS f
             WHERE f.UserId      = @UserId
               AND f.FactorType  = @FactorType
               AND f.IsConfirmed = 1
               AND f.IsDeleted   = 0;

            IF @FactorId IS NULL
            BEGIN
                ;THROW 50127, N'This account has no confirmed factor of that type, so there is nothing for the reported time step to have been verified against and no way to elevate this session. Enrol and confirm one -- auth.uspEnrolMfaFactor then auth.uspConfirmMfaFactor, both in 112_auth_mfa_procedures.sql -- from a session that does not need to be elevated first. This is NOT counted as a failed step-up: no factor was presented, so there is nothing to throttle.', 1;
            END;

            SET @StepSeconds = COALESCE (TRY_CAST ((SELECT SettingValue FROM config.ApplicationSetting
                                                     WHERE SettingKey = N'Authn.TotpStepSeconds'
                                                       AND IsDeleted  = 0) AS INT), 30);
            SET @WindowSteps = COALESCE (TRY_CAST ((SELECT SettingValue FROM config.ApplicationSetting
                                                     WHERE SettingKey = N'Authn.TotpWindowSteps'
                                                       AND IsDeleted  = 0) AS INT), 1);

            -- DATEDIFF_BIG, not DATEDIFF: seconds since 1970 overflows an INT in 2038, and a template with a date in it
            -- is a template with a fuse in it.  Character for character the same arithmetic auth.uspVerifyMfa uses, and
            -- that is a requirement rather than a coincidence -- if the two disagreed about which step it is, a code
            -- that signed a user in would fail to elevate them a second later.
            SET @ServerStep = DATEDIFF_BIG (SECOND, CAST (N'1970-01-01T00:00:00' AS DATETIME2 (0)), @Now)
                            / @StepSeconds;

            IF ABS (@TimeStep - @ServerStep) > @WindowSteps
               OR @TimeStep <= COALESCE (@LastUsedStep, 0)
            BEGIN
                SET @FailureReason = CASE WHEN ABS (@TimeStep - @ServerStep) > @WindowSteps
                                          THEN N'outside the server clock window'
                                          ELSE N'replay of a used or older step' END;
            END;
        END
        ELSE
        BEGIN
            -- 2b.  The recovery code, matched on (UserId, CodeHash) -- what the filtered unique index is on, and the
            --      reason 045_auth_identity.sql refused to make CodeHash globally unique.
            SELECT @RecoveryCodeId = r.UserMfaRecoveryCodeId
              FROM auth.UserMfaRecoveryCode AS r
             WHERE r.UserId    = @UserId
               AND r.CodeHash  = @RecoveryCodeHash
               AND r.UsedUtc   IS NULL
               AND r.IsDeleted = 0;

            IF @RecoveryCodeId IS NULL
            BEGIN
                -- Never existed and already spent are the same answer, here and on screen: the difference would tell
                -- somebody holding a leaked list which entries are still live.
                SET @FailureReason = N'no unused code with that hash for this account';
            END;
        END;

        -- 3.  One refusal path for both routes, still with no transaction open.  E-50128 either way; the reason is in
        --     the event and not in the message.
        IF @FailureReason IS NOT NULL
        BEGIN
            INSERT logs.AuthenticationEvent
                (EventUtc, EventType, EventSeverity, ApplicationId, UserId, UserSessionId
               , UserName, ClientAddress, Actor, DetailJson)
            VALUES (@Now, 'MfaFailed', 'Warning', @ApplicationId, @UserId, @SessionId
                  , @UserName, @ClientAddress, @Actor
                  , CONCAT (N'{"context":"stepUp","route":"', @Route
                          , N'","reportedStep":', COALESCE (CAST (@TimeStep     AS NVARCHAR (20)), N'null')
                          , N',"serverStep":',    COALESCE (CAST (@ServerStep   AS NVARCHAR (20)), N'null')
                          , N',"windowSteps":',   COALESCE (CAST (@WindowSteps  AS NVARCHAR (11)), N'null')
                          , N',"lastUsedStep":',  COALESCE (CAST (@LastUsedStep AS NVARCHAR (20)), N'null')
                          , N',"reason":"', @FailureReason, N'"}'));

            SET @Threshold     = COALESCE (TRY_CAST ((SELECT SettingValue FROM config.ApplicationSetting
                                                       WHERE SettingKey = N'Authn.LockoutThreshold'
                                                         AND IsDeleted  = 0) AS INT), 5);
            SET @LockoutWindow = COALESCE (TRY_CAST ((SELECT SettingValue FROM config.ApplicationSetting
                                                       WHERE SettingKey = N'Authn.LockoutWindowMinutes'
                                                         AND IsDeleted  = 0) AS INT), 15);

            -- Scoped by UserSessionId, which makes the count exact rather than approximate: auth.uspVerifyMfa's
            -- failures carry a LoginAttemptId and no session, so the two populations cannot be mistaken for one.
            SELECT @RecentFailures = COUNT (*)
              FROM logs.AuthenticationEvent AS e
             WHERE e.UserSessionId = @SessionId
               AND e.EventType     = 'MfaFailed'
               AND e.EventUtc      >= DATEADD (MINUTE, -@LockoutWindow, @Now)
               AND e.IsDeleted     = 0;

            IF @Threshold > 0 AND @RecentFailures >= @Threshold
            BEGIN
                -- The session goes and the account stays.  auth.uspEndSession opens its own transaction and this
                -- procedure has none open, which is the whole reason step 3 sits outside one.
                EXEC auth.uspEndSession @UserSessionId  = @SessionId
                                      , @EndReason      = 'Revoked'
                                      , @SessionsEnded  = @SessionsEnded OUTPUT;

                SET @Failure = CONCAT (N'Too many failed step-up attempts on this session: ', @RecentFailures
                                     , N' inside the last ', @LockoutWindow
                                     , N' minute(s), which is at or above Authn.LockoutThreshold. THE SESSION HAS BEEN '
                                     , N'REVOKED and the account has NOT been locked -- deliberately, because a step-up '
                                     , N'brute force is evidence about one stolen token, and locking the account would '
                                     , N'let whoever holds that token deny service to its owner. Sign in again.');
                ;THROW 50129, @Failure, 1;
            END;

            ;THROW 50128, N'The second factor was refused, so this session has not been elevated. A TOTP step must be within Authn.TotpWindowSteps of the server''s own step and strictly later than the last step this factor accepted; a recovery code must be one this account holds and has not spent. Which of those it was is in logs.AuthenticationEvent, where a reviewer can read it and a caller cannot. Failed step-ups are counted per session and revoke it at Authn.LockoutThreshold -- E-50129.', 1;
        END;

        -- 4.  The window.  Clamped, then never shortened, then bounded by the session -- the notes argue all three.
        SET @WindowMinutes = COALESCE (TRY_CAST ((SELECT SettingValue FROM config.ApplicationSetting
                                                   WHERE SettingKey = N'Authn.StepUpElevationMinutes'
                                                     AND IsDeleted  = 0) AS INT), 15);
        SET @WindowMinutes = CASE WHEN @WindowMinutes < 1   THEN 1
                                  WHEN @WindowMinutes > 480 THEN 480
                                  ELSE @WindowMinutes END;

        SET @FreshUntilUtc = DATEADD (MINUTE, @WindowMinutes, @Now);
        SET @NewUntilUtc   = LEAST (GREATEST (@FreshUntilUtc, COALESCE (@HeldUntilUtc, @FreshUntilUtc))
                                  , @AbsoluteExpiryUtc);

        BEGIN TRANSACTION;
        -- Spending the factor and elevating the session are ONE unit.  Either order of a partial failure is worse than
        -- the failure: a spent code with no elevation costs the user a code and a round trip, and an elevation with an
        -- unspent code is a step-up that can be replayed for as long as its window is open.

        IF @Route = N'Totp'
        BEGIN
            -- 5a.  Spend the step.  The replay test is repeated in the WHERE clause so two connections presenting the
            --      same code in the same instant cannot both be elevated by it.  LastUsedUtc and LastUsedTimeStep move
            --      together because the pair CHECK on auth.UserMfaFactor requires it.
            UPDATE auth.UserMfaFactor
               SET LastUsedUtc      = @Now
                 , LastUsedTimeStep = @TimeStep
                 , auditModifiedBy  = @Actor
             WHERE UserMfaFactorId  = @FactorId
               AND (LastUsedTimeStep IS NULL OR LastUsedTimeStep < @TimeStep);

            IF @@ROWCOUNT <> 1
            BEGIN
                ;THROW 50128, N'That TOTP step was spent by another connection between the check and the update, so nothing has been elevated. The winning connection''s logs.AuthenticationEvent row is the record of that presentation; a second row here would read as a second code. Wait for the next step and try again.', 1;
            END;
        END
        ELSE
        BEGIN
            -- 5b.  Spend the code.  UsedUtc is write-once at the trigger; it is repeated in the WHERE clause against
            --      the same race the TOTP route guards.
            UPDATE auth.UserMfaRecoveryCode
               SET UsedUtc         = @Now
                 , auditModifiedBy = @Actor
             WHERE UserMfaRecoveryCodeId = @RecoveryCodeId
               AND UsedUtc               IS NULL;

            IF @@ROWCOUNT <> 1
            BEGIN
                ;THROW 50128, N'That recovery code was spent by another connection between the check and the update, so nothing has been elevated. Single-use means single-use in the sense that matters: presented, observed to work, and not presentable a second time.', 1;
            END;

            SET @RemainingCodes = (SELECT COUNT (*)
                                     FROM auth.UserMfaRecoveryCode AS r
                                    WHERE r.UserId    = @UserId
                                      AND r.UsedUtc   IS NULL
                                      AND r.IsDeleted = 0);

            -- Alert, not Info, exactly as auth.uspVerifyMfa raises it -- and with more reason here: a recovery code
            -- spent to reach a PRIVILEGED profile is either a lost authenticator or somebody working from a stolen
            -- list, and the two look identical from inside this procedure.
            INSERT logs.AuthenticationEvent
                (EventUtc, EventType, EventSeverity, ApplicationId, UserId, UserSessionId
               , UserName, ClientAddress, Actor, DetailJson)
            VALUES (@Now, 'RecoveryCodeUsed', 'Alert', @ApplicationId, @UserId, @SessionId
                  , @UserName, @ClientAddress, @Actor
                  , CONCAT (N'{"context":"stepUp","remainingUnusedCodes":', @RemainingCodes, N'}'));
        END;

        -- 6.  The write gap G-48 was about.  auth.uspSwitchProfile reads this column and nothing the caller asserts,
        --     which is what makes section 12.3 enforceable at all.  EndedUtc IS NULL is re-asserted because the session
        --     could have been revoked by another connection while the factor was being checked.
        UPDATE auth.UserSession
           SET ElevatedUntilUtc = @NewUntilUtc
             , auditModifiedBy  = @Actor
         WHERE UserSessionId = @SessionId
           AND EndedUtc      IS NULL;

        IF @@ROWCOUNT <> 1
        BEGIN
            ;THROW 50126, N'The session was ended by another connection while its second factor was being verified -- a sign-out, a revoke, or an incident response. Nothing has been elevated AND nothing has been spent: the spend and the elevation are one transaction, so the code that was presented is still usable on the session the caller signs in to next. Sign in again.', 1;
        END;

        SET @ElevatedUntilUtc = @NewUntilUtc;

        INSERT logs.AuthenticationEvent
            (EventUtc, EventType, EventSeverity, ApplicationId, UserId, UserSessionId
           , UserName, ClientAddress, Actor, DetailJson)
        VALUES (@Now, 'SessionElevated', 'Info', @ApplicationId, @UserId, @SessionId
              , @UserName, @ClientAddress, @Actor
              , CONCAT (N'{"route":"', @Route, N'","elevatedUntilUtc":"'
                      , CONVERT (NVARCHAR (23), @NewUntilUtc, 126)
                      , N'","windowMinutes":', @WindowMinutes
                      , N',"boundedByAbsoluteExpiry":'
                      , CASE WHEN @NewUntilUtc = @AbsoluteExpiryUtc THEN N'true' ELSE N'false' END
                      , N',"extendedAnOpenWindow":'
                      , CASE WHEN @HeldUntilUtc > @Now THEN N'true' ELSE N'false' END, N'}'));

        SET @Comments = CONCAT (N'Session ', @SessionId, N' (user ', @UserId, N') elevated until '
                              , CONVERT (NVARCHAR (23), @NewUntilUtc, 126), N' by the ', @Route, N' route. Window '
                              , @WindowMinutes, N' minute(s)'
                              , CASE WHEN @NewUntilUtc = @AbsoluteExpiryUtc
                                     THEN N', truncated to the session''s absolute expiry.' ELSE N'.' END
                              , CASE WHEN @Route = N'RecoveryCode'
                                     THEN CONCAT (N' ', @RemainingCodes, N' unused recovery code(s) remain.')
                                     ELSE N'' END);

        -- =========================================================================================
        -- ===== End of the procedure's own work. ===================================================
        -- =========================================================================================
        IF @@TRANCOUNT > 0
        BEGIN
            COMMIT TRANSACTION;
        END;

        SET @EndTimeUtc = SYSUTCDATETIME ();

        IF @ExecutionId IS NOT NULL
        BEGIN
            UPDATE logs.ExecutionLog
               SET EndDateUtc           = @EndTimeUtc
                 , ElapsedMilliseconds  = CAST (LEAST (DATEDIFF_BIG (MILLISECOND, @StartTimeUtc, @EndTimeUtc)
                                                     , CAST (2147483647 AS BIGINT)) AS INT)
                 , Successful           = 1
                 , Comments             = @Comments
                 , auditModifiedBy      = ORIGINAL_LOGIN ()
                 , auditModifiedDateUtc = @EndTimeUtc
             WHERE ExecutionLogId = @ExecutionId;
        END;
    END TRY
    BEGIN CATCH
        SELECT @ErrorNumber = ERROR_NUMBER ()
             , @ErrorProc   = ERROR_PROCEDURE ()
             , @ErrorLine   = ERROR_LINE ()
             , @ErrorMsg    = ERROR_MESSAGE ()
                            + N' (error '  + CAST (ERROR_NUMBER () AS NVARCHAR (11))
                            + N', line '   + CAST (ERROR_LINE ()   AS NVARCHAR (11)) + N')';

        IF XACT_STATE () <> 0
        BEGIN
            ROLLBACK TRANSACTION;
        END;

        BEGIN TRY
            IF @ExecutionId IS NULL
               OR NOT EXISTS (SELECT 1 FROM logs.ExecutionLog WHERE ExecutionLogId = @ExecutionId)
            BEGIN
                EXEC logs.uspStartExecutionLogging
                      @ProcedureName          = @ProcName
                    , @KeyParameters          = @KeyParameters
                    , @StartDateUtc           = @StartTimeUtc
                    , @ReCreatedAfterRollback = 1
                    , @ExecutionLogId         = @ExecutionId OUTPUT;
            END;
        END TRY
        BEGIN CATCH
            SET @ExecutionId = NULL;
        END CATCH;

        EXEC logs.uspRecordExecutionError
              @ProcedureName   = @ProcName
            , @KeyParameters   = @KeyParameters
            , @ExecutionLogId  = @ExecutionId
            , @ErrorMessage    = @ErrorMsg
            , @ErrorProcedure  = @ErrorProc
            , @ErrorNumber     = @ErrorNumber
            , @ErrorLine       = @ErrorLine
            , @DynamicSql      = @DynamicSql
            , @ContextMessage  = @ContextMessage;

        ;THROW;
    END CATCH;

    RETURN 0;
END;
GO


-- *** 6. Descriptions ***
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

    -- Rows rather than five EXEC calls with concatenated arguments: an EXEC argument takes a constant or a variable and
    -- never an expression, so a '+' in the parameter position is a parse error (102), exactly as it is for THROW.
    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    VALUES
      (N'auth', N'PROCEDURE', N'uspEnrolMfaFactor', NULL
     , N'Records a second factor the application has already generated and encrypted. T-041, section 6.4. The factor '
     + N'arrives UNCONFIRMED and cannot satisfy MFA until uspConfirmMfaFactor has seen a working code. The secret is a '
     + N'parameter and the key is not: the engine holds ciphertext it has no key for, which is the whole of the G-07 '
     + N'decision. @KeyReference must EQUAL Authn.MfaKeyReferenceCurrent -- stricter than "grammatical" on purpose, '
     + N'because an application still encrypting under a retired key is invisible until that key is deleted and every '
     + N'factor stops decrypting at once. The actor is either a live session or a sign-in the database itself refused '
     + N'for want of MFA: exactly one, because a first factor has to be enrolled by somebody who cannot yet satisfy '
     + N'MFA. A CONFIRMED factor of the same type is refused (E-50119) so the bootstrap window is a route to a FIRST '
     + N'factor and to nothing else; an UNCONFIRMED one is overwritten, because one live row per user per type would '
     + N'otherwise let an abandoned enrolment block every later attempt. Raises 50100, 50114, 50115, 50117, 50118, 50119, '
     + N'50122.')
    , (N'auth', N'PROCEDURE', N'uspConfirmMfaFactor', NULL
     , N'Turns an enrolment in progress into a usable factor. T-041, section 6.4. The application verifies one code and '
     + N'reports which TOTP time step it verified at; the step is bounded against the SERVER clock exactly as '
     + N'uspVerifyMfa bounds it, because a step the caller chose is otherwise a free pass. DOES NOT SPEND THE STEP, '
     + N'deliberately: a first factor is enrolled from a refused exchange, so the user''s next act is to sign in and '
     + N'present a code, and a spent step would refuse the only code their authenticator is currently showing. Does not '
     + N'touch auth.LoginAttempt at all -- uspVerifyMfa remains the only writer of MfaSatisfied, because a procedure on '
     + N'the enrolment path that could satisfy MFA would be a second authentication route with none of the throttles in '
     + N'front of it. E-50120 covers both "nothing enrolled" and "already confirmed" without saying which, since that '
     + N'answer reveals whether the account holds a working factor. Raises 50111, 50114, 50115, 50117, 50120, 50122.')
    , (N'auth', N'PROCEDURE', N'uspIssueMfaRecoveryCodes', NULL
     , N'Replaces a user''s batch of one-time recovery codes. T-041, section 6.4. Hashes arrive as a JSON array of '
     + N'64-character hex strings and the codes themselves never reach the database, for the same reason passwords do '
     + N'not (D-08). JSON rather than a delimited string because OPENJSON reports each element''s TYPE, which is how a '
     + N'malformed entry is caught rather than silently coerced to NULL. A confirmed factor is required first (E-50110): '
     + N'codes issued before one exists are one-time passwords that satisfy an MFA requirement the account has never '
     + N'satisfied. The batch is atomic -- ten codes on one screen, and a partial issue means a printout that is half '
     + N'wrong. Unused codes are SOFT-deleted, which is also what lets a coincidentally identical code be re-issued '
     + N'without colliding on the filtered unique index; USED codes are left alone, because a row with UsedUtc set is '
     + N'the record that somebody recovered an account on a particular date. The payload is never written to '
     + N'logs.ExecutionLog -- only its length. Raises 50046, 50110, 50114, 50115, 50117, 50121, 50122.')
    , (N'auth', N'PROCEDURE', N'uspRotateMfaFactorKey', NULL
     , N'Replaces the ciphertext and key label of ONE factor, for a deployment that has re-encrypted it under a new key. '
     + N'T-041, section 6.4. The only procedure in 112 with no actor proof, because re-encrypting needs the old key and '
     + N'the new one and only the application layer holds either -- a rotation sweep runs over rows belonging to people '
     + N'who are asleep. What bounds it is what it cannot do: it cannot create a factor (E-50120), cannot confirm one '
     + N'(IsConfirmed is not in the UPDATE), cannot move one between accounts (the trigger makes UserId immutable), '
     + N'cannot name a key other than Authn.MfaKeyReferenceCurrent (E-50118), and cannot be used as a probe for which '
     + N'identifiers exist, because an already-current label or an identical ciphertext is E-50123. A rotation therefore '
     + N'moves the setting FIRST and sweeps second. Clears LastUsedUtc and LastUsedTimeStep because '
     + N'trg_au_updt_UserMfaFactor requires it of any change to the secret, which leaves one TOTP window replayable -- '
     + N'accepted and documented as UI-32 rather than engineered around. Raises 50100, 50118, 50120, 50123.')
    , (N'auth', N'PROCEDURE', N'uspElevateSession', NULL
     , N'Satisfies a step-up challenge on a session that is already live and writes its elevation window, '
     + N'auth.UserSession.ElevatedUntilUtc. T-125, sections 12.3 and 14.5, gap G-48 -- auth.uspSwitchProfile has raised '
     + N'E-50052 since Phase 3 and nothing could answer it. The ONLY writer of that column: a caller cannot assert its '
     + N'own step-up. Deliberately does NOT call auth.uspSetSessionContext, because the connection asking for a step-up '
     + N'is usually the one that was just refused and is therefore already contexted, where a second call is E-50022 '
     + N'(UI-06). It validates the session by reading auth.UserSession and does not slide IdleExpiryUtc -- one writer '
     + N'per policy rule. The window is LEAST (now + Authn.StepUpElevationMinutes, AbsoluteExpiryUtc), GREATEST against '
     + N'any window still open, so a step-up cannot outlive its session and re-elevating cannot shorten it. Failed '
     + N'step-ups are counted per session over Authn.LockoutWindowMinutes and REVOKE the session at '
     + N'Authn.LockoutThreshold (E-50129) -- without an exchange to conclude there is nothing else counting, and an '
     + N'unthrottled step-up is a TOTP oracle. The account is never locked: that would let a stolen token deny service '
     + N'to its owner. Raises 50125, 50126, 50127, 50128, 50129.');

    DECLARE @RowNo       INT = 1
          , @MaxRowNo    INT = (SELECT MAX (RowNo) FROM @Descriptions)
          , @SchemaName  SYSNAME
          , @ObjectType  SYSNAME
          , @ObjectName  SYSNAME
          , @ColumnName  SYSNAME
          , @Description NVARCHAR (3750);

    WHILE @RowNo <= @MaxRowNo
    BEGIN
        SELECT @SchemaName  = SchemaName
             , @ObjectType  = ObjectType
             , @ObjectName  = ObjectName
             , @ColumnName  = ColumnName
             , @Description = Description
          FROM @Descriptions
         WHERE RowNo = @RowNo;

        EXEC util.uspSetObjectDescription @SchemaName  = @SchemaName
                                        , @ObjectType  = @ObjectType
                                        , @ObjectName  = @ObjectName
                                        , @Description = @Description
                                        , @ColumnName  = @ColumnName;

        SET @RowNo += 1;
    END;
END
ELSE
BEGIN
    PRINT N'util.uspSetObjectDescription is absent, so no descriptions were set. Run templates/extended-properties.sql '
        + N'and then re-run this file to add them.';
END
GO


-- *** 7. Grants ***
-- EXECUTE on all five, and nothing on the tables -- INV-11.  DENY SELECT, INSERT, UPDATE, DELETE ON SCHEMA::auth stands,
-- and ownership chaining is what lets these procedures write auth.UserMfaFactor and auth.UserMfaRecoveryCode on the
-- application's behalf while applicationRole itself holds no access to either.
--
-- auth.uspRotateMfaFactorKey IS GRANTED to the same role as the other three, and that deserves a sentence because it is
-- the one with no actor proof.  It is granted because the application layer is the only party that CAN call it usefully
-- -- it needs both keys -- and because withholding it would mean a rotation sweep had to run as db_owner, which is a
-- larger privilege to hand a deployment script than the one being avoided.  What makes that safe is the list in the
-- procedure's own notes: it cannot create, confirm, move or mislabel a factor, and it cannot probe for identifiers.
--
-- Each grant is guarded so the file stays re-runnable against a database where 170_permissions.sql has not run.  The
-- same guard is how a typo'd role name produces procedures nobody can execute and no error to say why -- check these
-- names against the report at the end of 170_permissions.sql.
IF DATABASE_PRINCIPAL_ID (N'applicationRole') IS NOT NULL
BEGIN
    GRANT EXECUTE ON auth.uspEnrolMfaFactor        TO applicationRole;
    GRANT EXECUTE ON auth.uspConfirmMfaFactor      TO applicationRole;
    GRANT EXECUTE ON auth.uspIssueMfaRecoveryCodes TO applicationRole;
    GRANT EXECUTE ON auth.uspRotateMfaFactorKey    TO applicationRole;
    GRANT EXECUTE ON auth.uspElevateSession        TO applicationRole;
END;
GO


-- *** 8. Closing report ***
DECLARE @Report TABLE
(
    Seq        INT            NOT NULL,
    Status     VARCHAR (10)   NOT NULL,
    Item       NVARCHAR (200) NOT NULL,
    Detail     NVARCHAR (400)     NULL
);

INSERT @Report (Seq, Status, Item, Detail)
SELECT 1
     , CASE WHEN OBJECT_ID (N'auth.' + x.ProcName, N'P') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Procedure auth.' + x.ProcName
     , x.Purpose
  FROM (VALUES (N'uspEnrolMfaFactor',        N'T-041. Accept an encrypted secret and a key LABEL. Unconfirmed on arrival.')
             , (N'uspConfirmMfaFactor',      N'T-041. Bound the reported step, set IsConfirmed, and do not spend the step.')
             , (N'uspIssueMfaRecoveryCodes', N'T-041. Replace the batch. Hashes only; used codes are kept as the trail.')
             , (N'uspRotateMfaFactorKey',    N'T-041. The sweep half of rotation. No actor, and a short list of what it cannot do.')
             , (N'uspElevateSession',        N'T-125. Writes ElevatedUntilUtc. Without it E-50052 has no answer -- G-48.')
       ) AS x (ProcName, Purpose);

-- Rule 8 is asserted rather than assumed, as it is in 110: a procedure that changes somebody's second factor and does
-- not log its own failures is a procedure whose failures are invisible in exactly the incident somebody is investigating.
INSERT @Report (Seq, Status, Item, Detail)
SELECT 2
     , CASE WHEN SUM (CASE WHEN m.definition LIKE N'%uspRecordExecutionError%'  THEN 1 ELSE 0 END) = 5
             AND SUM (CASE WHEN m.definition LIKE N'%uspStartExecutionLogging%' THEN 1 ELSE 0 END) = 5
            THEN 'OK' ELSE 'PROBLEM' END
     , N'All five procedures are instrumented (rule 8)'
     , CONCAT (N'Start logging: '
             , SUM (CASE WHEN m.definition LIKE N'%uspStartExecutionLogging%' THEN 1 ELSE 0 END)
             , N'/5. Error recording: '
             , SUM (CASE WHEN m.definition LIKE N'%uspRecordExecutionError%' THEN 1 ELSE 0 END), N'/5.')
  FROM sys.sql_modules AS m
  JOIN sys.objects     AS o ON o.object_id = m.object_id
 WHERE o.type      = 'P'
   AND o.schema_id = SCHEMA_ID (N'auth')
   AND o.name IN (N'uspEnrolMfaFactor', N'uspConfirmMfaFactor', N'uspIssueMfaRecoveryCodes'
                , N'uspRotateMfaFactorKey', N'uspElevateSession');

-- THE SECRET GOES IN AND NEVER COMES OUT, asserted at the parameter list, which is the one place it could leave by
-- accident.  A binary OUTPUT parameter on any of these five would be a channel for the ciphertext -- and a caller that
-- can read the ciphertext plus a caller that holds the key is the whole of the protection this design has.
--
-- The parameter list rather than the body text: a LIKE against sys.sql_modules would have to match 'SELECT ...
-- SecretCiphertext ... FROM' across a whole module, and with wildcards that spans unrelated statements and reports a
-- problem on a healthy install.  A check that cries wolf is worse than no check, because it is the reason people stop
-- reading reports.
INSERT @Report (Seq, Status, Item, Detail)
SELECT 2
     , CASE WHEN COUNT (*) = 0 THEN 'OK' ELSE 'PROBLEM' END
     , N'No procedure here can hand the ciphertext back: no binary OUTPUT parameters'
     , CONCAT (COUNT (*), N' binary OUTPUT parameter(s) found across the five. uspRotateMfaFactorKey reads the stored '
             , N'ciphertext once, to refuse a re-key whose bytes did not change, and that read never leaves the '
             , N'procedure. The engine has no use for the secret: the only party that can read it is the party that can '
             , N'decrypt it, and that party already has it.')
  FROM sys.parameters AS p
  JOIN sys.objects    AS o ON o.object_id = p.object_id
  JOIN sys.types      AS t ON t.user_type_id = p.user_type_id
 WHERE o.type      = 'P'
   AND o.schema_id = SCHEMA_ID (N'auth')
   AND o.name IN (N'uspEnrolMfaFactor', N'uspConfirmMfaFactor', N'uspIssueMfaRecoveryCodes'
                , N'uspRotateMfaFactorKey', N'uspElevateSession')
   AND p.is_output = 1
   AND t.name IN (N'varbinary', N'binary', N'image');

INSERT @Report (Seq, Status, Item, Detail)
SELECT 3
     , CASE WHEN COUNT (*) = 4 THEN 'OK' ELSE 'PROBLEM' END
     , N'The four Authn.Mfa* settings these procedures read are present'
     , CONCAT (COUNT (*), N' of 4 found in config.ApplicationSetting. Authn.MfaKeyReferenceCurrent fails CLOSED when '
             , N'absent -- E-50118 -- because a factor stored under a guessed label is a factor nobody can prove they '
             , N'can still decrypt. The other three degrade to their documented defaults.')
  FROM config.ApplicationSetting AS s
 WHERE s.IsDeleted = 0
   AND s.SettingKey IN (N'Authn.MfaKeyReferenceCurrent', N'Authn.MfaKeyReferenceSchemes'
                      , N'Authn.MfaEnrolmentWindowSeconds', N'Authn.MfaRecoveryCodeCount');

-- T-125.  auth.uspElevateSession degrades to 15 minutes when this key is absent, so its absence is a REVIEW and not a
-- PROBLEM -- but it is worth saying, because a deployment that has thought about how long a step-up lasts will have
-- written the number down, and one that has not is running on a template author's guess.
INSERT @Report (Seq, Status, Item, Detail)
SELECT 3
     , CASE WHEN COUNT (*) = 1 THEN 'OK' ELSE 'REVIEW' END
     , N'Authn.StepUpElevationMinutes is present for auth.uspElevateSession'
     , CONCAT (COUNT (*), N' of 1 found in config.ApplicationSetting. Absent, the procedure elevates for 15 minutes and '
             , N'says so in logs.ExecutionLog.Comments. The value is clamped to 1..480 whatever it holds: zero would '
             , N'open a window that has already closed, which CK_auth_UserSession_ElevatedUntilUtc refuses with error '
             , N'547 -- an operator''s typo arriving as a constraint violation from inside a security procedure.')
  FROM config.ApplicationSetting AS s
 WHERE s.IsDeleted  = 0
   AND s.SettingKey = N'Authn.StepUpElevationMinutes';

-- Severity is deliberately mild.  On a workstation a dev: key is the CORRECT state, and a script that declared PROBLEMS
-- on every clean install would teach its readers to stop reading the line that says it.
INSERT @Report (Seq, Status, Item, Detail)
SELECT 3, 'REVIEW', N'The current MFA key reference names a development key'
     , CONCAT (N'Authn.MfaKeyReferenceCurrent is ', s.SettingValue, N'. Correct on a workstation and wrong in '
             , N'production: the dev: scheme marks a key that is not TPM-backed. Set it to a cng: reference on the '
             , N'application-layer server -- or a vault: one if HashiCorp Vault is adopted -- and sweep with '
             , N'auth.uspRotateMfaFactorKey.')
  FROM config.ApplicationSetting AS s
 WHERE s.SettingKey  = N'Authn.MfaKeyReferenceCurrent'
   AND s.IsDeleted   = 0
   AND s.SettingValue LIKE N'dev:%';

INSERT @Report (Seq, Status, Item, Detail)
SELECT 4, 'INFO', N'The bootstrap enrolment window is open for '
       + CAST (COALESCE (TRY_CAST (s.SettingValue AS INT), 900) AS NVARCHAR (10)) + N' second(s)'
     , CASE WHEN COALESCE (TRY_CAST (s.SettingValue AS INT), 900) = 0
            THEN N'Zero, so the bootstrap route is CLOSED: a user with no factor, under a policy requiring MFA, cannot '
               + N'enrol one without an administrator. That is an administrative choice and is recorded here so it is '
               + N'not mistaken for a defect.'
            ELSE N'Measured from auth.LoginAttempt.AttemptedUtc on an exchange the database refused for want of MFA. It '
               + N'grants an identity, not a permission: E-50119 still refuses to touch an account that already holds a '
               + N'confirmed factor.' END
  FROM config.ApplicationSetting AS s
 WHERE s.SettingKey = N'Authn.MfaEnrolmentWindowSeconds'
   AND s.IsDeleted  = 0;

INSERT @Report (Seq, Status, Item, Detail)
VALUES (4, 'INFO', N'G-07 is closed, and this file is what closing it looks like'
      , N'Application-side envelope encryption, TPM-backed CNG on the application-layer server, secrets held encrypted '
      + N'in appsettings.secrets.json, and a vault: scheme reserved for a self-hosted HashiCorp Vault if management '
      + N'adopts one. SQL Server Always Encrypted was rejected: external readers such as Power BI must keep working.')
     , (4, 'INFO', N'G-48 is closed: E-50052 now has an answer'
      , N'auth.uspElevateSession is the only writer of auth.UserSession.ElevatedUntilUtc. Before T-125 '
      + N'auth.uspSwitchProfile could refuse a privileged profile for want of elevation and no procedure could supply '
      + N'it, so every privileged profile under a step-up policy was unreachable. Failed step-ups revoke the session at '
      + N'Authn.LockoutThreshold, because a step-up has no exchange for section 7.4 to conclude.')
     , (5, 'NEXT', N'database/_tests/040_identity_and_authn.sql, then 170_permissions.sql'
      , N'The test script enrols, confirms, issues and spends a recovery code, re-keys, and signs in as the fixture user '
      + N'who could not sign in at all while T-041 was blocked. 170_permissions.sql grants these five alongside the '
      + N'eleven it already knows about.');

SELECT Seq
     , Status
     , Item
     , Detail
  FROM @Report
 ORDER BY Seq, Status DESC, Item;

IF EXISTS (SELECT 1 FROM @Report WHERE Status IN ('MISSING', 'PROBLEM'))
BEGIN
    DECLARE @Problems NVARCHAR (2000) =
        N'One or more checks above reported MISSING or PROBLEM. The MFA enrolment procedures are not installed as '
      + N'expected. Read the report rows and fix the cause rather than re-running blind.';

    THROW 50000, @Problems, 1;
END;

PRINT N'auth MFA procedures: no problems found. T-041 is implemented and gap G-07 is closed -- the secret arrives '
    + N'encrypted, the key is named and never held, and a first factor can be enrolled from the exchange the policy '
    + N'refused. T-125 is implemented and gap G-48 is closed -- a live session can prove its second factor again, and '
    + N'the step-up challenge auth.uspSwitchProfile raises can now be answered.';
GO
