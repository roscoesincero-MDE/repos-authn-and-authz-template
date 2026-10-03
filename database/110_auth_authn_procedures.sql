/***********************************************************************************************************************
Script:         110_auth_authn_procedures.sql
Purpose:        The authentication protocol.  Eleven procedures, three routes, the password lifecycle, and the only
                cross-boundary conversation in the design:
                  auth.uspGetLoginVerifier   -- step 1 of the local route (T-034)
                  auth.uspCompleteLogin      -- step 2 of the local route (T-035)
                  auth.uspRecordLoginFailure -- the lockout arithmetic (T-036)
                  auth.uspVerifyMfa          -- the second factor, TOTP or recovery code (T-037)
                  auth.uspBeginSsoLogin      -- step 1 of the federated route (T-038)
                  auth.uspCompleteSsoLogin   -- step 2 of the federated route (T-038)
                  auth.uspEndSession         -- signing out, and revoking (T-039)
                  auth.uspSetPassword        -- the administrative reset (T-112, gap G-42)
                  auth.uspGetPasswordChangeContext
                                             -- what the application must know to change one (T-112, gap G-42)
                  auth.uspChangePassword     -- the self-service change (T-112, gap G-42)
                  auth.uspExpireCredentials  -- the scheduled expiry sweep (T-112, gap G-12)
Target:         SQL Server 2022.
Run as:         db_owner in the target database.
Run with:       sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/110_auth_authn_procedures.sql
Idempotent:     Yes.  CREATE OR ALTER throughout.  Creates nothing that holds state and seeds nothing.
Depends on:     025_config_tables.sql, 030_auth_tenant.sql, 035_auth_tenant_policy.sql, 040_auth_userprofile.sql,
                045_auth_identity.sql, 070_auth_session.sql, 085_logs_auth_tables.sql, 100_auth_functions.sql,
                010_logging_objects.sql (logs.uspStartExecutionLogging, logs.uspRecordExecutionError),
                templates/extended-properties.sql.
                AND, AT RUN TIME ONLY: 105_auth_session_procedures.sql (auth.uspSetSessionContext) and
                150_auth_query_procedures.sql (auth.uspDemandPermission), which the password procedures call and which
                this file is INSTALLED BEFORE -- 110 is step 24 of the manifest, 105 is step 26 and 150 is step 34.
                That is legal and deliberate: T-SQL resolves a procedure name at execution and not at CREATE, so the
                forward reference compiles.  It is also why the closing report probes E-50224 and leaves the other four
                password numbers to _tests/040_identity_and_authn.sql: on a FIRST deployment the two procedures such a
                probe would need do not exist yet, and a report that failed on a correct install teaches people to
                ignore reports.
Implements:     DES-AUTH-001 sections 7.1, 7.2, 7.3, 7.4, 6.2, 6.3, 14.5, 16.2, 19.2.  D-08, D-14, INV-07, INV-08,
                INV-09.
                PLAN-AUTH-001 tasks T-034 through T-039, and T-112 (gaps G-42 and G-12).
To retarget:    Pass it per run:  sqlcmd -d <database> -v DbName=<database>.  There is no in-file default.

SIGNING IN IS TWO ROUND TRIPS AND THAT IS THE WHOLE SHAPE OF THIS FILE
--------------------------------------------------------------------
D-08, section 19.2.  The database holds the verifier and cannot check it: a memory-hard KDF run inside the engine spends
the server's working set on every guess, and the plaintext password would land in a T-SQL parameter, which means the
plan cache, Query Store, and any Extended Events session somebody left running.

So the local route is:

    1.  auth.uspGetLoginVerifier   -- application says who is trying; database hands back a verifier string and opens
                                      an exchange (one auth.LoginAttempt row, Outcome 'VerifierIssued').
    2.  application computes        -- Argon2id, against the string it was given.
    3.  auth.uspCompleteLogin      -- application reports the boolean; database decides what that means.

Step 3 is where every rule lives.  The application reports ONE fact -- did the digest match -- and is trusted for
nothing else: not for whether the user is active, not for whether MFA was satisfied, not for whether the account is
locked, not for how long the session lasts.  Each of those is read here from the tables.

AN UNKNOWN USER COSTS THE SAME WORK AND YIELDS THE SAME MESSAGE
--------------------------------------------------------------
Section 19.2, and Phase 2's exit criterion.  auth.uspGetLoginVerifier ALWAYS returns a verifier string.  For a name
nobody holds it returns a DERIVED DUMMY -- a PHC string built by hashing a configured pepper with the user name, in the
configured template, with the salt and digest fields at the correct lengths.

Derived, not constant, and the difference matters: a constant dummy means every unknown name yields byte-identical
output, so an attacker who has seen one unknown-name response can recognise every other unknown name for free.  Derived
per name, the responses differ from each other exactly as real ones do.

The lengths must match too.  A dummy with a 16-character salt where the real ones carry 22 is distinguishable without
any timing analysis at all -- just by looking.

WHICH ERRORS COME OUT OF HERE, AND WHY THEY ALL LOOK THE SAME ON SCREEN
---------------------------------------------------------------------
Every SIGN-IN failure in this file is in the E-50100 range, and section 14.5 requires the UI to show ONE generic message
for every number in it -- UI-26.  The numbers are for the log, not the screen.  That is not defensive vagueness: a page
that says "no such user" for 50102 and "wrong password" for 50106 is an account-enumeration oracle with a friendly
tone, and it defeats everything the dummy verifier is for.

The real reason is recorded in two places nobody unauthenticated can read: auth.LoginAttempt.FailureReason and
logs.AuthenticationEvent.

THE PASSWORD-LIFECYCLE NUMBERS ARE THE OTHER WAY ROUND, AND ON PURPOSE.  T-112 added E-50220 to E-50224 and UI-26 does
NOT apply to them: their messages are meant to be shown as written.  The reason the sign-in numbers are hidden is that
the person reading the screen may not be the account holder.  By the time E-50222 is raised they have proved that they
are -- they signed in, and then proved the current password again -- so "that password has been used before, choose
another" tells an attacker nothing and tells the account holder the one thing that will get them out of the loop.  A
generic "could not change password" here is the message that generates the support call.

The single exception is E-50115 -- the account is deleted, inactive or locked out -- and it is the exception only because
it is raised AFTER the credential has been verified.  At that point the caller has already proved they hold the
password, so telling them their account is locked reveals nothing they did not know.

THE TWO COUNTS ARE TAKEN INDEPENDENTLY, AND ONLY ONE OF THEM IS A STATE CHANGE
----------------------------------------------------------------------------
Section 7.4.  auth.uspRecordLoginFailure recomputes both from auth.LoginAttempt on every failure, and neither is derived
from the other.

  *  The per-ACCOUNT count crossing Authn.LockoutThreshold writes to auth.User: IsLockedOut = 1 and a LockoutEndUtc.
     That is a lockout, it persists, and an administrator can see and clear it.
  *  The per-ADDRESS count crossing Authn.AddressThreshold writes NOTHING.  There is no table of addresses and no
     blocked-address flag; the verdict is recomputed from the attempt rows every time it is needed.  An address that
     stops attacking stops being throttled, with no sweep and no expiry job.

E-50116 is the refusal the address throttle produces, and it is raised at the START of an exchange, before any lookup,
because the point of a throttle is not to do the work.

WHAT THE APPLICATION IS TRUSTED FOR, EXHAUSTIVELY
------------------------------------------------
Worth listing, because it is the security boundary and a reader should be able to check it in one place.

  *  Did the password digest match (auth.uspCompleteLogin, @PasswordVerified).
  *  Did a TOTP code verify, and at which time step (auth.uspVerifyMfa, @TimeStep) -- and the step is then bounded
     against the SERVER clock and against LastUsedTimeStep, so a client cannot present a step from next year or replay
     one it has already used.
  *  What the client address and user agent were.
  *  A session token's SHA-256, which the application generates because it is the party that has to send the token to
     the browser.  The token itself never crosses into the database.

Everything else -- policy, lockout, usability, MFA requirement, session lifetime, INV-08, INV-09 -- is decided here.

WHY auth.LoginAttempt.UserName SAYS '(sso pending)' ON THE FEDERATED ROUTE
------------------------------------------------------------------------
auth.uspBeginSsoLogin opens an exchange before anybody knows which account will come back from the identity provider --
that is what a redirect to an identity provider means.  UserName is NOT NULL and immutable, so the row is opened with
the login hint if the application had one and with '(sso pending)' if it did not, and auth.uspCompleteSsoLogin fills in
UserId, which is mutable.

The alternative -- letting UserName be rewritten once, while the exchange is pending -- was rejected: the immutability
guard on that column is what stops an attempt being moved between accounts' lockout tallies, and a guard with an
exception is a guard somebody will find the exception in.  The cost is that the per-account lockout count does not see
federated failures, which is correct anyway: a federated failure is not a password guess, and the identity provider
owns the throttling of its own credentials.

THE PASSWORD LIFECYCLE IS IN THIS FILE AND NOT IN 130_auth_user_procedures.sql
----------------------------------------------------------------------------
T-112, gaps G-42 and G-12.  130 creates people; this file owns the things people prove themselves with.  130's closing
report ASSERTS that none of its procedures touches auth.UserCredential, and that assertion is the reason the password
procedures are here rather than there: moving them into 130 would have meant deleting a mechanical check that protects a
real distinction -- a person and a credential have two lifecycles, and one file owning both is how "remove the user"
quietly becomes "remove the evidence".  auth.uspGetLoginVerifier already reads VerifierPhc.  Writing it belongs beside
reading it.

The four of them divide as follows, and the division IS the design:

  *  auth.uspSetPassword demands User.ResetCredential and forces MustChangePassword = 1.  Somebody other than the
     account holder chose the value, so the account holder must replace it.
  *  auth.uspGetPasswordChangeContext demands nothing and takes no parameter naming a user.  The session decides whose
     verifiers come back, and they come back at all because the database CANNOT check password reuse itself: every PHC
     string carries its own random salt, so the same password hashed twice gives two different strings.
  *  auth.uspChangePassword demands nothing either, for the same reason -- the session IS the authorization.  It takes
     @CurrentPasswordVerified, which is the same contract as uspCompleteLogin's @PasswordVerified, and it CLEARS
     MustChangePassword.  It is the only thing in the database that clears it.
  *  auth.uspExpireCredentials is a job, is granted to nobody, and is the only thing that makes
     Authn.PasswordLifetimeDays mean anything.  Nothing in the sign-in path reads ExpiresUtc: expiry that refuses a
     sign-in locks people out of the very screen that would have fixed it, and expiry that sets MustChangePassword does
     not.

WHAT THIS FILE STILL DOES NOT DO, STATED SO NOBODY ASSUMES IT DOES
  *  It does not revoke sessions when a password changes.  auth.uspEndSession @UserId, @EndReason = 'PasswordChanged'
     is a SEPARATE call, because uspEndSession's CATCH rolls back the outermost transaction and it raises E-50114 when
     the user holds no live session -- so calling it from inside the change would let the most ordinary failure
     imaginable silently undo the password change it was meant to protect.  Section 16.2 puts the two calls in order.
  *  It does not judge password STRENGTH.  It cannot: it never sees a password (D-08).  Length, character classes,
     dictionary and breach checks belong to the application, and section 16.2 records that as an obligation rather than
     pretending a CHECK constraint on a hash could stand in for it.
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

-- Asserted, not gated.  A PROCEDURE gets deferred name resolution, so every one of these would install happily against
-- a missing table and fail at CALL time with error 2812 -- which is the failure this project has already been bitten by
-- once, and the reason install order is a manifest rather than a set of IF OBJECT_ID gates (finding F-07).
IF OBJECT_ID (N'auth.[User]', N'U') IS NULL
   OR OBJECT_ID (N'auth.UserCredential', N'U') IS NULL
   OR OBJECT_ID (N'auth.UserFederatedIdentity', N'U') IS NULL
   OR OBJECT_ID (N'auth.UserMfaFactor', N'U') IS NULL
   OR OBJECT_ID (N'auth.UserMfaRecoveryCode', N'U') IS NULL
   OR OBJECT_ID (N'auth.LoginAttempt', N'U') IS NULL
   OR OBJECT_ID (N'auth.UserSession', N'U') IS NULL
   OR OBJECT_ID (N'logs.AuthenticationEvent', N'U') IS NULL
   OR OBJECT_ID (N'config.ApplicationSetting', N'U') IS NULL
   OR OBJECT_ID (N'auth.TenantAuthenticationPolicy', N'U') IS NULL
   OR OBJECT_ID (N'auth.TenantTrustedIssuer', N'U') IS NULL
BEGIN
    DECLARE @MsgTables NVARCHAR (2000) =
        N'One or more parent tables are missing. Run database/025_config_tables.sql, 035_auth_tenant_policy.sql, '
      + N'040_auth_userprofile.sql, 045_auth_identity.sql, 070_auth_session.sql and 085_logs_auth_tables.sql first. '
      + N'Nothing has been changed.';

    THROW 50000, @MsgTables, 1;
END
GO

IF OBJECT_ID (N'auth.udfIsUserUsable', N'FN') IS NULL
   OR OBJECT_ID (N'auth.udfIsTenantUsable', N'FN') IS NULL
   OR OBJECT_ID (N'auth.udfResolveAuthPolicy', N'FN') IS NULL
BEGIN
    DECLARE @MsgFunctions NVARCHAR (2000) =
        N'auth.udfIsUserUsable, auth.udfIsTenantUsable or auth.udfResolveAuthPolicy is missing. Run '
      + N'database/100_auth_functions.sql first. Nothing has been changed.';

    THROW 50000, @MsgFunctions, 1;
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


-- *** 1. auth.uspGetLoginVerifier ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspGetLoginVerifier
Author:       rsincero
CreateDate:   2026-09-19
========================================================================================================================
Description:

Step 1 of the local password route.  Opens a sign-in exchange and hands the application the PHC verifier string to
compute against.  Returns the LoginAttemptId that every later step of this exchange must present.

ALWAYS returns a verifier.  For a user name nobody holds, it returns a dummy derived from that name -- see the notes.

========================================================================================================================
Notes:

THE ORDER OF THE CHECKS IS THE DESIGN, not an accident of writing.

  1.  Empty user name           -- E-50100, raised before any lookup at all.  No row is written: there is nothing to
                                   attribute the attempt to, and a table of attempts against the empty string is noise.
  2.  Address throttle          -- E-50116, raised before the user is looked up, because the point of a throttle is not
                                   to do the work.  Recomputed from auth.LoginAttempt; nothing is stored.
  3.  Unknown application       -- E-50101.  A deployment error, not an attack, and it cannot leak anything about users.
  4.  Unknown or unusable tenant-- E-50102, via auth.udfIsTenantUsable, which refuses a tenant under a deactivated
                                   ancestor (section 5.4).
  5.  Local route not permitted -- E-50103, from the resolved policy.
  6.  THEN the user lookup, which never fails.

THE ACCOUNT LOCKOUT IS DELIBERATELY *NOT* CHECKED HERE.  It is checked in auth.uspCompleteLogin, after the credential
has been verified -- E-50115.  Refusing early would be faster and would be an oracle: "this name is locked out" is
"this name exists", offered to anybody who asks twice.  A locked account therefore still costs a verifier fetch, and
that is the price of not answering the question.

THE DUMMY VERIFIER IS DERIVED FROM THE USER NAME, NOT A CONSTANT.  Two hashes of Authn.DummyVerifierPepper with the
user name -- domain-separated, so the salt field and the digest field are not the same value -- substituted into
Authn.DummyVerifierPhcTemplate at the same field lengths the real verifiers use.  A constant dummy would mean every
unknown name produced byte-identical output, so one probe would identify every other unknown name for free.  Equal
lengths matter as much as equal shape: a short salt is visible without any timing analysis.

The pepper is a config.ApplicationSetting row with IsSensitive = 1 and no shipped default -- 025_config_tables.sql
generates one per deployment with CRYPT_GEN_RANDOM.  It is not a secret whose disclosure breaks anything: it makes the
dummies unpredictable to somebody who cannot read the table, and somebody who CAN read the table has the real verifiers.

@RequiresMfa IS THE POLICY'S ANSWER, NOT PERMISSION TO SKIP.  It is returned so the application can decide which screen
to show next.  auth.uspCompleteLogin re-reads the policy and enforces it regardless of what the application did with
this flag, and INV-08 is unconditional on the bypass route whatever any policy says.

========================================================================================================================
Example Usage and Performance:

declare @AttemptId bigint, @Phc nvarchar (512), @Mfa bit;
exec auth.uspGetLoginVerifier @ApplicationCode = N'DEMO', @UserName = N'alice', @ClientAddress = N'203.0.113.7'
   , @LoginAttemptId = @AttemptId output, @VerifierPhc = @Phc output, @RequiresMfa = @Mfa output;

Two filtered-index seeks for the throttle count, one seek per lookup, one insert.

========================================================================================================================
Modification History:

Date:		2026-09-19
Author:		rsincero
Ticket:		T-034
Description:
Created.  Phase 2.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspGetLoginVerifier
      @ApplicationCode NVARCHAR (50)
    , @UserName        NVARCHAR (256)
    , @ClientAddress   NVARCHAR (45)
    , @TenantCode      NVARCHAR (50)  = NULL
    , @UserAgent       NVARCHAR (512) = NULL
    , @LoginAttemptId  BIGINT         = NULL OUTPUT
    , @VerifierPhc     NVARCHAR (512) = NULL OUTPUT
    , @RequiresMfa     BIT            = NULL OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspGetLoginVerifier]')
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

    -- The user name is a key parameter and is recorded.  The password is not a parameter of this procedure at all --
    -- that is the point of D-08 -- so there is nothing secret to keep out of the log here.
    SET @KeyParameters = CONCAT (N'@ApplicationCode=', @ApplicationCode
                               , N', @TenantCode=', COALESCE (@TenantCode, N'(root)')
                               , N', @UserName=', @UserName
                               , N', @ClientAddress=', @ClientAddress);
    SET @ContextMessage = N'Step 1 of the local password route: open an exchange and issue a verifier. D-08, 19.2.';

    DECLARE @ApplicationId    INT            = NULL
          , @TenantId         INT            = NULL
          , @PolicyId         INT            = NULL
          , @UserId           INT            = NULL
          , @AllowLocal       BIT            = NULL
          , @RequireMfaLocal  BIT            = NULL
          , @AddressThreshold INT            = NULL
          , @AddressWindowMin INT            = NULL
          , @AddressFailures  INT            = NULL
          , @Pepper           NVARCHAR (256) = NULL
          , @Template         NVARCHAR (256) = NULL
          , @SaltRaw          VARBINARY (32) = NULL
          , @HashRaw          VARBINARY (32) = NULL
          , @SaltText         VARCHAR (128)  = NULL
          , @HashText         VARCHAR (128)  = NULL;

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

        -- 1.  Empty user name.  No attempt row: there is nothing to attribute it to.
        IF @UserName IS NULL OR LEN (LTRIM (RTRIM (@UserName))) = 0 OR @ClientAddress IS NULL
           OR LEN (LTRIM (RTRIM (@ClientAddress))) = 0
        BEGIN
            ;THROW 50100, N'A user name and a client address are both required before a sign-in exchange can be opened. Raised before any lookup, so nothing has been recorded.', 1;
        END;

        SET @UserName      = LTRIM (RTRIM (@UserName));
        SET @ClientAddress = LTRIM (RTRIM (@ClientAddress));

        -- 2.  The address throttle, before any user lookup.  Scalar subqueries rather than aggregates over a filtered
        --     set, because MAX (CASE ...) over an absent key raises the null-eliminated warning (BL-024).
        SET @AddressThreshold = COALESCE (TRY_CAST ((SELECT SettingValue FROM config.ApplicationSetting
                                                      WHERE SettingKey = N'Authn.AddressThreshold'
                                                        AND IsDeleted  = 0) AS INT), 20);
        SET @AddressWindowMin = COALESCE (TRY_CAST ((SELECT SettingValue FROM config.ApplicationSetting
                                                      WHERE SettingKey = N'Authn.AddressWindowMinutes'
                                                        AND IsDeleted  = 0) AS INT), 15);

        SET @AddressFailures = (SELECT COUNT (*)
                                  FROM auth.LoginAttempt AS a
                                 WHERE a.ClientAddress = @ClientAddress
                                   AND a.Outcome       = 'Failure'
                                   AND a.IsDeleted     = 0
                                   AND a.AttemptedUtc >= DATEADD (MINUTE, -@AddressWindowMin, @Now));

        IF @AddressFailures >= @AddressThreshold
        BEGIN
            -- Recorded as an event, not as a state change: there is no table of blocked addresses, and an address that
            -- stops attacking stops being throttled with no sweep and no expiry job.  Section 7.4.
            INSERT logs.AuthenticationEvent
                (EventUtc, EventType, EventSeverity, UserName, ClientAddress, Actor, DetailJson)
            VALUES (@Now, 'AddressThrottled', 'Warning', @UserName, @ClientAddress, @Actor
                  , CONCAT (N'{"failures":', @AddressFailures, N',"threshold":', @AddressThreshold
                          , N',"windowMinutes":', @AddressWindowMin, N',"stage":"GetLoginVerifier"}'));

            COMMIT TRANSACTION;

            ;THROW 50116, N'Refused by the per-address throttle. The count is recomputed from auth.LoginAttempt and nothing is stored, so the refusal lapses on its own once the window passes -- section 7.4. Show the generic sign-in failure message (UI-26).', 1;
        END;

        -- 3.  The application.
        SELECT @ApplicationId = a.ApplicationId
          FROM auth.Application AS a
         WHERE a.ApplicationCode = @ApplicationCode
           AND a.IsActive        = 1
           AND a.IsDeleted       = 0;

        IF @ApplicationId IS NULL
        BEGIN
            ;THROW 50101, N'No such application, or it is inactive. This is a deployment error rather than an attack, and it leaks nothing about users -- but it still shows the generic sign-in message (UI-26).', 1;
        END;

        -- 4.  The tenant.  An omitted @TenantCode means the application's root tenant -- section 7.2: policy hangs off
        --     a tenant, profiles are Phase 3, and the root is the only tenant every application is guaranteed to have.
        IF @TenantCode IS NULL
        BEGIN
            SELECT @TenantId = t.TenantId
              FROM auth.Tenant AS t
             WHERE t.ApplicationId  = @ApplicationId
               AND t.ParentTenantId IS NULL
               AND t.IsDeleted      = 0;
        END
        ELSE
        BEGIN
            SELECT @TenantId = t.TenantId
              FROM auth.Tenant AS t
             WHERE t.ApplicationId = @ApplicationId
               AND t.TenantCode    = @TenantCode
               AND t.IsDeleted     = 0;
        END;

        IF @TenantId IS NULL OR auth.udfIsTenantUsable (@TenantId) = 0
        BEGIN
            INSERT logs.AuthenticationEvent
                (EventUtc, EventType, EventSeverity, ApplicationId, UserName, ClientAddress, Actor, DetailJson)
            VALUES (@Now, 'PolicyResolutionFailed', 'Warning', @ApplicationId, @UserName, @ClientAddress, @Actor
                  , CONCAT (N'{"tenantCode":', CASE WHEN @TenantCode IS NULL THEN N'null'
                                                    ELSE N'"' + STRING_ESCAPE (@TenantCode, 'json') + N'"' END
                          , N',"reason":"unknown or unusable tenant"}'));

            COMMIT TRANSACTION;

            ;THROW 50102, N'No such tenant for this application, or the tenant is not usable -- which includes a tenant whose ancestor has been deactivated (section 5.4, auth.udfIsTenantUsable). Generic message on screen (UI-26).', 1;
        END;

        -- 5.  The policy.  NULL means no policy row applies, which is not a denial: fall back to the shipped defaults.
        SET @PolicyId = auth.udfResolveAuthPolicy (@TenantId);

        SELECT @AllowLocal      = p.AllowLocalPassword
             , @RequireMfaLocal = p.RequireMfaForLocal
          FROM auth.TenantAuthenticationPolicy AS p
         WHERE p.TenantAuthenticationPolicyId = @PolicyId;

        SET @AllowLocal      = COALESCE (@AllowLocal, CAST (1 AS BIT));
        SET @RequireMfaLocal = COALESCE (@RequireMfaLocal, CAST (1 AS BIT));

        IF @AllowLocal = 0
        BEGIN
            ;THROW 50103, N'Local password sign-in is not permitted for this tenant by the resolved authentication policy -- section 7.2. Generic message on screen (UI-26); the real reason is in logs.AuthenticationEvent.', 1;
        END;

        -- 6.  The user.  This lookup NEVER fails the request.  See the notes: the lockout is not checked here either.
        SELECT @UserId = u.UserId
          FROM auth.[User] AS u
         WHERE u.UserName  = @UserName
           AND u.IsDeleted = 0;

        SELECT @VerifierPhc = c.VerifierPhc
          FROM auth.UserCredential AS c
         WHERE c.UserId         = @UserId
           AND c.CredentialType = 'Password'
           AND c.IsDeleted      = 0;

        IF @VerifierPhc IS NULL
        BEGIN
            -- The derived dummy.  Two domain-separated hashes so the salt field and the digest field differ, then
            -- substituted into the configured template at the real field lengths.
            SET @Pepper   = (SELECT SettingValue FROM config.ApplicationSetting
                              WHERE SettingKey = N'Authn.DummyVerifierPepper' AND IsDeleted = 0);
            SET @Template = (SELECT SettingValue FROM config.ApplicationSetting
                              WHERE SettingKey = N'Authn.DummyVerifierPhcTemplate' AND IsDeleted = 0);

            -- Fail CLOSED on a missing pepper: a predictable dummy is worse than no dummy, because it is a reliable
            -- signal rather than an absent one.  A deployment that has not seeded 025_config_tables.sql gets an error.
            IF @Pepper IS NULL OR LEN (@Pepper) < 16 OR @Template IS NULL
            BEGIN
                ;THROW 50100, N'Authn.DummyVerifierPepper or Authn.DummyVerifierPhcTemplate is missing from config.ApplicationSetting, so no dummy verifier can be derived. Run database/025_config_tables.sql. Failing closed deliberately: a predictable dummy is a reliable signal that a name is unknown, which is worse than having none.', 1;
            END;

            SET @SaltRaw = HASHBYTES ('SHA2_256', @Pepper + N'|salt|' + @UserName);
            SET @HashRaw = HASHBYTES ('SHA2_256', @Pepper + N'|hash|' + @UserName);

            -- Base64 through XML, then the three non-alphanumeric characters folded away, so the result is the same
            -- alphabet a PHC field uses and the same length every time.
            SET @SaltText = REPLACE (REPLACE (REPLACE (
                                CAST (N'' AS XML).value ('xs:base64Binary(sql:variable("@SaltRaw"))', 'VARCHAR(128)')
                              , '=', ''), '+', 'x'), '/', 'y');
            SET @HashText = REPLACE (REPLACE (REPLACE (
                                CAST (N'' AS XML).value ('xs:base64Binary(sql:variable("@HashRaw"))', 'VARCHAR(128)')
                              , '=', ''), '+', 'x'), '/', 'y');

            SET @VerifierPhc = REPLACE (REPLACE (@Template
                                 , N'{salt:22}', LEFT (@SaltText, 22))
                                 , N'{hash:43}', LEFT (@HashText, 43));
        END;

        -- 7.  Open the exchange.  One row, Outcome 'VerifierIssued', and its identifier is what every later step of this
        --     sign-in must present -- D-14.
        INSERT auth.LoginAttempt
            (ApplicationId, UserName, UserId, PolicyTenantId, ClientAddress, UserAgent
           , AuthenticationMethod, IsBypassRoute, Outcome, PasswordVerified, MfaSatisfied, AttemptedUtc
           , auditCreatedBy, auditModifiedBy)
        VALUES (@ApplicationId, @UserName, @UserId, @TenantId, @ClientAddress, @UserAgent
              , 'LocalPassword', 0, 'VerifierIssued', 0, 0, @Now
              , @Actor, @Actor);

        SET @LoginAttemptId = CAST (SCOPE_IDENTITY () AS BIGINT);

        SET @RequiresMfa = @RequireMfaLocal;

        SET @Comments = CONCAT (N'Exchange ', @LoginAttemptId, N' opened. Verifier '
                              , CASE WHEN @UserId IS NULL THEN N'derived (unknown user name)' ELSE N'live' END
                              , N'. RequiresMfa=', @RequiresMfa, N'. Address failures in window: '
                              , @AddressFailures, N'/', @AddressThreshold, N'.');

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

-- *** 2. auth.uspRecordLoginFailure ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspRecordLoginFailure
Author:       rsincero
CreateDate:   2026-09-19
========================================================================================================================
Description:

Concludes a sign-in exchange as a failure, recomputes both failure counts, applies the per-account lockout if the
account count has crossed its threshold, and reports the per-address verdict.  Section 7.4.

Called by auth.uspCompleteLogin and auth.uspCompleteSsoLogin.  Also callable directly, which is how the application
records a failure it detected itself -- a malformed verifier string, or a client that abandoned the exchange.

========================================================================================================================
Notes:

THE TWO COUNTS ARE RECOMPUTED FROM auth.LoginAttempt EVERY TIME, from two filtered indexes built for exactly this --
IX_auth_LoginAttempt_Account and IX_auth_LoginAttempt_Address.  Neither is a running total in a column, because a
running total is a number that can be wrong, and a number that can be wrong in a lockout counter either locks out an
innocent account or fails to lock a guessed one.

THEY ARE INDEPENDENT.  Phase 2's exit criterion says "lockout fires per account and per address independently", and the
two arms of this procedure share no variable but @Now.  The account arm may fire while the address arm does not (one
person mistyping their own password); the address arm may fire while the account arm does not (credential stuffing, one
guess per account across hundreds of accounts -- which is the case the per-account threshold cannot see at all).

ONLY THE ACCOUNT ARM WRITES STATE.  auth.User.IsLockedOut and LockoutEndUtc, which persist, are visible to an
administrator, and can be cleared.  The address arm writes a logs.AuthenticationEvent row and nothing else: the verdict
is recomputed wherever it matters, so there is no blocked-address table to sweep and no expiry job to forget to
schedule.  An address that stops attacking stops being throttled.

THE COUNT INCLUDES THE ROW THIS CALL IS WRITING.  The attempt is concluded first, then counted, so a threshold of 5
locks the account on the fifth failure and not the sixth.  Obvious once stated; the other order is the classic
off-by-one in this exact procedure.

AN ALREADY-LOCKED ACCOUNT IS NOT RE-LOCKED ONTO A LATER END TIME.  Extending LockoutEndUtc on every subsequent failure
turns a fixed-duration lockout into an indefinite one that an attacker can sustain against a victim's account for free
-- denial of service as a feature.  The lockout window is set once, when the threshold is crossed.

CONCLUDING AN ALREADY-CONCLUDED EXCHANGE IS NOT AN ERROR HERE, it is a no-op on the attempt row plus the counts.  The
trigger on auth.LoginAttempt would refuse the UPDATE (a terminal Outcome is final -- D-14), so this procedure tests for
it rather than provoking E-50011.  A double-reported failure is a retry, not an attack, and it must not be the thing
that makes the sign-in page fall over.

========================================================================================================================
Example Usage and Performance:

declare @Acct int, @Addr int, @Locked bit, @Throttled bit;
exec auth.uspRecordLoginFailure @LoginAttemptId = 42, @FailureReason = 'PasswordMismatch'
   , @AccountFailureCount = @Acct output, @AddressFailureCount = @Addr output
   , @AccountLockedOut = @Locked output, @AddressThrottled = @Throttled output;

FailureReason vocabulary, closed by convention rather than by constraint: PasswordMismatch, UnknownUser,
AccountUnusable, MfaRequired, MfaFailed, RecoveryCodeInvalid, BypassNotPermitted, ExchangeExpired, FederatedNoLink,
PolicyDenied, Abandoned.

Two index seeks and one narrow update.

========================================================================================================================
Modification History:

Date:		2026-09-19
Author:		rsincero
Ticket:		T-036
Description:
Created.  Phase 2.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspRecordLoginFailure
      @LoginAttemptId      BIGINT
    , @FailureReason       VARCHAR (40) = 'PasswordMismatch'
    , @AccountFailureCount INT          = NULL OUTPUT
    , @AddressFailureCount INT          = NULL OUTPUT
    , @AccountLockedOut    BIT          = NULL OUTPUT
    , @AddressThrottled    BIT          = NULL OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspRecordLoginFailure]')
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

    SET @KeyParameters = CONCAT (N'@LoginAttemptId=', @LoginAttemptId, N', @FailureReason=', @FailureReason);
    SET @ContextMessage = N'Conclude an exchange as a failure and take both counts independently. Section 7.4.';

    DECLARE @ApplicationId     INT           = NULL
          , @UserName          NVARCHAR (256) = NULL
          , @UserId            INT           = NULL
          , @ClientAddress     NVARCHAR (45) = NULL
          , @Outcome           VARCHAR (20)  = NULL
          , @AlreadyConcluded  BIT           = 0
          , @LockThreshold     INT           = NULL
          , @LockWindowMin     INT           = NULL
          , @LockDurationMin   INT           = NULL
          , @AddressThreshold  INT           = NULL
          , @AddressWindowMin  INT           = NULL
          , @WasLockedAlready  BIT           = 0;

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

        SET @AccountLockedOut = 0;
        SET @AddressThrottled = 0;

        IF @FailureReason IS NULL OR LEN (LTRIM (RTRIM (@FailureReason))) = 0
        BEGIN
            SET @FailureReason = 'Unspecified';
        END;

        SELECT @ApplicationId    = a.ApplicationId
             , @UserName         = a.UserName
             , @UserId           = a.UserId
             , @ClientAddress    = a.ClientAddress
             , @Outcome          = a.Outcome
          FROM auth.LoginAttempt AS a
         WHERE a.LoginAttemptId = @LoginAttemptId
           AND a.IsDeleted      = 0;

        IF @UserName IS NULL
        BEGIN
            ;THROW 50105, N'No such sign-in exchange, so there is nothing to conclude. Every step after uspGetLoginVerifier or uspBeginSsoLogin must present the LoginAttemptId that call returned -- D-14.', 1;
        END;

        -- A terminal Outcome is final (D-14, and the trigger enforces it).  Tested rather than provoked: a
        -- double-reported failure is a retry, and a retry must not be the thing that breaks the sign-in page.
        IF @Outcome IN ('Success', 'Failure')
        BEGIN
            SET @AlreadyConcluded = 1;
        END
        ELSE
        BEGIN
            UPDATE auth.LoginAttempt
               SET Outcome         = 'Failure'
                 , FailureReason   = @FailureReason
                 , ConcludedUtc    = @Now
                 , auditModifiedBy = @Actor
             WHERE LoginAttemptId = @LoginAttemptId;
        END;

        -- Thresholds.  Scalar subqueries, not aggregates: MAX (CASE ...) over an absent key raises the null-eliminated
        -- warning (BL-024).  The COALESCE second arguments are the values 025_config_tables.sql ships, repeated here so
        -- a deleted row degrades to the documented default rather than to NULL -- and NULL >= NULL is never true, which
        -- would silently disable the lockout entirely.
        SET @LockThreshold    = COALESCE (TRY_CAST ((SELECT SettingValue FROM config.ApplicationSetting
                                                      WHERE SettingKey = N'Authn.LockoutThreshold'
                                                        AND IsDeleted  = 0) AS INT), 5);
        SET @LockWindowMin    = COALESCE (TRY_CAST ((SELECT SettingValue FROM config.ApplicationSetting
                                                      WHERE SettingKey = N'Authn.LockoutWindowMinutes'
                                                        AND IsDeleted  = 0) AS INT), 15);
        SET @LockDurationMin  = COALESCE (TRY_CAST ((SELECT SettingValue FROM config.ApplicationSetting
                                                      WHERE SettingKey = N'Authn.LockoutDurationMinutes'
                                                        AND IsDeleted  = 0) AS INT), 15);
        SET @AddressThreshold = COALESCE (TRY_CAST ((SELECT SettingValue FROM config.ApplicationSetting
                                                      WHERE SettingKey = N'Authn.AddressThreshold'
                                                        AND IsDeleted  = 0) AS INT), 20);
        SET @AddressWindowMin = COALESCE (TRY_CAST ((SELECT SettingValue FROM config.ApplicationSetting
                                                      WHERE SettingKey = N'Authn.AddressWindowMinutes'
                                                        AND IsDeleted  = 0) AS INT), 15);

        -- The per-ACCOUNT count.  Keyed on UserName, not UserId, so failures against a name nobody holds are counted
        -- too -- otherwise the count is itself an oracle: an attacker learns a name exists by whether it can be locked.
        SET @AccountFailureCount = (SELECT COUNT (*)
                                      FROM auth.LoginAttempt AS a
                                     WHERE a.UserName      = @UserName
                                       AND a.Outcome       = 'Failure'
                                       AND a.IsDeleted     = 0
                                       AND a.AttemptedUtc >= DATEADD (MINUTE, -@LockWindowMin, @Now));

        -- The per-ADDRESS count.  Independent of the above: different key, different index, different window setting,
        -- and no shared intermediate.  Section 7.4.
        SET @AddressFailureCount = (SELECT COUNT (*)
                                      FROM auth.LoginAttempt AS a
                                     WHERE a.ClientAddress  = @ClientAddress
                                       AND a.Outcome        = 'Failure'
                                       AND a.IsDeleted      = 0
                                       AND a.AttemptedUtc  >= DATEADD (MINUTE, -@AddressWindowMin, @Now));

        -- The account arm.  The only arm that writes state, and only if there is an account to write it on.
        IF @AccountFailureCount >= @LockThreshold AND @UserId IS NOT NULL
        BEGIN
            SELECT @WasLockedAlready = CASE WHEN u.IsLockedOut = 1
                                             AND (u.LockoutEndUtc IS NULL OR u.LockoutEndUtc > @Now)
                                            THEN 1 ELSE 0 END
              FROM auth.[User] AS u
             WHERE u.UserId = @UserId;

            SET @AccountLockedOut = 1;

            -- Not re-locked onto a later end time: see the notes.  Extending the window on every further failure lets
            -- an attacker hold somebody else's account shut indefinitely at no cost.
            IF @WasLockedAlready = 0
            BEGIN
                UPDATE auth.[User]
                   SET IsLockedOut     = 1
                     , LockoutEndUtc   = DATEADD (MINUTE, @LockDurationMin, @Now)
                     , auditModifiedBy = @Actor
                 WHERE UserId = @UserId;

                INSERT logs.AuthenticationEvent
                    (EventUtc, EventType, EventSeverity, ApplicationId, UserId, LoginAttemptId
                   , UserName, ClientAddress, Actor, DetailJson)
                VALUES (@Now, 'LockoutApplied', 'Alert', @ApplicationId, @UserId, @LoginAttemptId
                      , @UserName, @ClientAddress, @Actor
                      , CONCAT (N'{"failures":', @AccountFailureCount, N',"threshold":', @LockThreshold
                              , N',"windowMinutes":', @LockWindowMin, N',"durationMinutes":', @LockDurationMin, N'}'));
            END;
        END;

        -- The address arm.  Writes no state at all, deliberately.
        IF @AddressFailureCount >= @AddressThreshold
        BEGIN
            SET @AddressThrottled = 1;

            INSERT logs.AuthenticationEvent
                (EventUtc, EventType, EventSeverity, ApplicationId, UserId, LoginAttemptId
               , UserName, ClientAddress, Actor, DetailJson)
            VALUES (@Now, 'AddressThrottled', 'Warning', @ApplicationId, @UserId, @LoginAttemptId
                  , @UserName, @ClientAddress, @Actor
                  , CONCAT (N'{"failures":', @AddressFailureCount, N',"threshold":', @AddressThreshold
                          , N',"windowMinutes":', @AddressWindowMin, N',"stage":"RecordLoginFailure"}'));
        END;

        -- The failure itself.  'LoginBlocked' rather than 'LoginFailed' when a control fired, so the two are separable
        -- in the log without parsing DetailJson: a wrong password is ordinary, a control firing is not.
        INSERT logs.AuthenticationEvent
            (EventUtc, EventType, EventSeverity, ApplicationId, UserId, LoginAttemptId
           , UserName, ClientAddress, Actor, DetailJson)
        VALUES (@Now
              , CASE WHEN @AccountLockedOut = 1 OR @AddressThrottled = 1 THEN 'LoginBlocked' ELSE 'LoginFailed' END
              , CASE WHEN @AccountLockedOut = 1 OR @AddressThrottled = 1 THEN 'Warning'      ELSE 'Info'        END
              , @ApplicationId, @UserId, @LoginAttemptId, @UserName, @ClientAddress, @Actor
              , CONCAT (N'{"failureReason":"', @FailureReason
                      , N'","accountFailures":', @AccountFailureCount
                      , N',"addressFailures":', @AddressFailureCount
                      , N',"accountLockedOut":', @AccountLockedOut
                      , N',"addressThrottled":', @AddressThrottled
                      , N',"alreadyConcluded":', @AlreadyConcluded, N'}'));

        SET @Comments = CONCAT (N'Exchange ', @LoginAttemptId, N' failed: ', @FailureReason
                              , N'. Account ', @AccountFailureCount, N'/', @LockThreshold
                              , N', address ', @AddressFailureCount, N'/', @AddressThreshold
                              , N'. Locked=', @AccountLockedOut, N', throttled=', @AddressThrottled
                              , CASE WHEN @AlreadyConcluded = 1
                                     THEN N'. The exchange was already concluded; the attempt row was left alone.'
                                     ELSE N'.' END);

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

-- *** 3. auth.uspCompleteLogin ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspCompleteLogin
Author:       rsincero
CreateDate:   2026-09-19
========================================================================================================================
Description:

Step 2 of the local password route, and the procedure where every authentication rule is actually enforced.  Takes one
fact from the application -- did the digest match -- and decides what it means: whether the account may sign in, whether
the second factor was satisfied, how long the session lasts, and whether INV-08 and INV-09 permit the route.

On success, writes the auth.UserSession row and concludes the exchange.  On any refusal, concludes the exchange as a
failure through auth.uspRecordLoginFailure and raises an E-50100-range error.

========================================================================================================================
Notes:

THE APPLICATION IS TRUSTED FOR @PasswordVerified AND @SessionTokenHash, AND FOR NOTHING ELSE IN THIS CALL.  Not for the
user's identity -- that comes off the exchange row.  Not for MfaSatisfied -- that is read from the exchange row, where
only auth.uspVerifyMfa can have set it.  Not for the lifetimes, the policy, or the lockout state.  @IsBypassRoute is a
REQUEST to use that route, not a permission to: INV-09 is checked here against auth.User.IsPlatformAdmin.

EVERY REFUSAL CONCLUDES THE EXCHANGE, THEN COMMITS, THEN THROWS -- in that order, and the order is load-bearing.  The
CATCH block rolls back if a transaction is still open, so throwing inside the transaction that recorded the failure
would erase the failure record and the lockout increment along with it.  An attacker who can make the refusal roll
itself back has an unlimited number of guesses.  Hence: write the failure, COMMIT, and only then raise.

WHY A MISSING SECOND FACTOR IS A FAILURE AND NOT A "TRY AGAIN".  If the resolved policy requires MFA and the exchange
does not have MfaSatisfied = 1, this call does not wait -- it fails the exchange (E-50109) and the user starts over.
uspGetLoginVerifier already told the application MFA was required, via @RequiresMfa, so arriving here without it is
either a broken client or an attempt to skip the factor, and the two are indistinguishable from in here.  Making it cost
the whole exchange means skipping the factor is never cheaper than performing it.

THE UNKNOWN-USER BRANCH SHOULD BE UNREACHABLE, AND IS STILL WRITTEN.  A name nobody holds was issued a dummy verifier,
so @PasswordVerified arrives 0 and the password branch fires first with the same generic message.  Reaching the
unknown-user branch means the application reported a match against a verifier no account owns -- a bug or a lie.  It is
handled rather than assumed away, and it is E-50115 like the other unusable-account cases.

A LAPSED LOCKOUT IS CLEARED HERE, LAZILY.  auth.udfIsUserUsable already treats IsLockedOut = 1 with a LockoutEndUtc in
the past as usable, so the sign-in succeeds either way; this just tidies the flag so an administrator's screen does not
show a lockout that is not in force.  There is no sweep job, by design: state that expires by comparison needs no
gardener, and a gardener that fails leaves the estate in a state nothing else is testing.

BOTH EXPIRY COLUMNS ARE COMPUTED HERE AND STORED.  070_auth_session.sql argues the storage; this is where the arithmetic
happens.  The policy row wins if one resolves, the config.ApplicationSetting defaults apply if none does, and whichever
was used is fixed into the row so that editing a policy tomorrow neither shortens nor lengthens a session issued today.

INV-08 IS CHECKED HERE, IS A CHECK CONSTRAINT ON auth.LoginAttempt, AND IS A CHECK CONSTRAINT ON auth.UserSession.
Three times, deliberately.  This is the only one of the three that can produce a sensible error number and a log entry;
the other two are what catches a future procedure that forgets to call this one.

========================================================================================================================
Example Usage and Performance:

declare @Sid bigint, @Uid int, @Change bit, @Abs datetime2 (3), @Idle datetime2 (3);
exec auth.uspCompleteLogin @LoginAttemptId = 42, @PasswordVerified = 1
   , @SessionTokenHash = 0x9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08
   , @UserSessionId = @Sid output, @UserId = @Uid output, @MustChangePassword = @Change output
   , @AbsoluteExpiryUtc = @Abs output, @IdleExpiryUtc = @Idle output;

Clustered seek on the exchange, one seek per lookup, two inserts, one narrow update.

========================================================================================================================
Modification History:

Date:		2026-09-19
Author:		rsincero
Ticket:		T-035
Description:
Created.  Phase 2.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspCompleteLogin
      @LoginAttemptId     BIGINT
    , @PasswordVerified   BIT
    , @SessionTokenHash   VARBINARY (32)
    , @IsBypassRoute      BIT           = 0
    , @UserSessionId      BIGINT        = NULL OUTPUT
    , @UserId             INT           = NULL OUTPUT
    , @MustChangePassword BIT           = NULL OUTPUT
    , @AbsoluteExpiryUtc  DATETIME2 (3) = NULL OUTPUT
    , @IdleExpiryUtc      DATETIME2 (3) = NULL OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspCompleteLogin]')
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

    -- @SessionTokenHash is a hash, not the token, so logging its presence costs nothing.  The token itself is never a
    -- parameter of anything in this file -- see 070_auth_session.sql.
    SET @KeyParameters = CONCAT (N'@LoginAttemptId=', @LoginAttemptId
                               , N', @PasswordVerified=', @PasswordVerified
                               , N', @IsBypassRoute=', @IsBypassRoute);
    SET @ContextMessage = N'Step 2 of the local password route: decide what the application''s boolean means. 7.1, 19.2.';

    DECLARE @ApplicationId    INT            = NULL
          , @UserName         NVARCHAR (256) = NULL
          , @PolicyTenantId   INT            = NULL
          , @ClientAddress    NVARCHAR (45)  = NULL
          , @Method           VARCHAR (20)   = NULL
          , @Outcome          VARCHAR (20)   = NULL
          , @AttemptedUtc     DATETIME2 (3)  = NULL
          , @MfaSatisfied     BIT            = NULL
          , @ExchangeTimeout  INT            = NULL
          , @PolicyId         INT            = NULL
          , @RequireMfaLocal  BIT            = NULL
          , @AllowLocal       BIT            = NULL
          , @LifetimeMinutes  INT            = NULL
          , @IdleMinutes      INT            = NULL
          , @PolicySource     NVARCHAR (40)  = NULL
          , @IsPlatformAdmin  BIT            = NULL
          , @IsLockedOut      BIT            = NULL
          , @LockoutEndUtc    DATETIME2 (3)  = NULL
          , @HasMfaFactor     BIT            = 0;

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

        IF @SessionTokenHash IS NULL OR DATALENGTH (@SessionTokenHash) <> 32
        BEGIN
            ;THROW 50100, N'@SessionTokenHash must be exactly 32 bytes -- the SHA-256 of a token the APPLICATION generated. Raised before the exchange is touched, so nothing has been concluded and the caller may retry with a correct hash.', 1;
        END;

        -- 1.  The exchange.  Everything about who is signing in comes from this row, not from the caller.
        SELECT @ApplicationId  = a.ApplicationId
             , @UserName       = a.UserName
             , @UserId         = a.UserId
             , @PolicyTenantId = a.PolicyTenantId
             , @ClientAddress  = a.ClientAddress
             , @Method         = a.AuthenticationMethod
             , @Outcome        = a.Outcome
             , @AttemptedUtc   = a.AttemptedUtc
             , @MfaSatisfied   = a.MfaSatisfied
          FROM auth.LoginAttempt AS a
         WHERE a.LoginAttemptId = @LoginAttemptId
           AND a.IsDeleted      = 0;

        IF @UserName IS NULL OR @Outcome <> 'VerifierIssued' OR @Method <> 'LocalPassword'
        BEGIN
            ;THROW 50105, N'No open local-password exchange with that identifier. It does not exist, it has already been concluded, or it belongs to the federated route -- one exchange is one row and a concluded one is final (D-14). Start again at auth.uspGetLoginVerifier.', 1;
        END;

        SET @ExchangeTimeout = COALESCE (TRY_CAST ((SELECT SettingValue FROM config.ApplicationSetting
                                                     WHERE SettingKey = N'Authn.LoginExchangeTimeoutSeconds'
                                                       AND IsDeleted  = 0) AS INT), 300);

        -- 2.  The exchange window.  An exchange left open is not a credential, but it is a loose end, and a verifier
        --     handed out an hour ago has been sitting in a client's memory for an hour.
        IF DATEADD (SECOND, @ExchangeTimeout, @AttemptedUtc) < @Now
        BEGIN
            EXEC auth.uspRecordLoginFailure @LoginAttemptId = @LoginAttemptId, @FailureReason = 'ExchangeExpired';

            INSERT logs.AuthenticationEvent
                (EventUtc, EventType, EventSeverity, ApplicationId, UserId, LoginAttemptId
               , UserName, ClientAddress, Actor, DetailJson)
            VALUES (@Now, 'ExchangeExpired', 'Info', @ApplicationId, @UserId, @LoginAttemptId
                  , @UserName, @ClientAddress, @Actor
                  , CONCAT (N'{"timeoutSeconds":', @ExchangeTimeout, N',"ageSeconds":'
                          , DATEDIFF_BIG (SECOND, @AttemptedUtc, @Now), N'}'));

            -- Commit the record BEFORE raising: see the notes.  The CATCH rolls back an open transaction, which would
            -- otherwise erase the failure this call just recorded.
            IF @@TRANCOUNT > 0 COMMIT TRANSACTION;

            ;THROW 50105, N'This sign-in exchange is older than Authn.LoginExchangeTimeoutSeconds and has been concluded as a failure. Start again at auth.uspGetLoginVerifier. Generic message on screen (UI-26).', 1;
        END;

        -- 3.  The one fact the application is trusted for.  A name nobody holds was given a dummy verifier, so it
        --     arrives here as 0 and leaves through this branch -- identically to a wrong password, which is the point.
        IF @PasswordVerified = 0
        BEGIN
            EXEC auth.uspRecordLoginFailure @LoginAttemptId = @LoginAttemptId, @FailureReason = 'PasswordMismatch';

            IF @@TRANCOUNT > 0 COMMIT TRANSACTION;

            ;THROW 50106, N'The credential was not verified in this exchange. Identical treatment, message and cost whether the user name exists or not -- section 19.2. The real reason is in auth.LoginAttempt.FailureReason and logs.AuthenticationEvent.', 1;
        END;

        -- Recorded on the exchange before the account checks, so the log distinguishes "wrong password" from "right
        -- password, account not permitted" without either being distinguishable on screen.
        UPDATE auth.LoginAttempt
           SET PasswordVerified = 1
             , auditModifiedBy  = @Actor
         WHERE LoginAttemptId = @LoginAttemptId;

        -- 4.  Should be unreachable -- see the notes.  Written anyway, because "unreachable" is an assumption about the
        --     application and this procedure's whole job is not to make those.
        IF @UserId IS NULL
        BEGIN
            EXEC auth.uspRecordLoginFailure @LoginAttemptId = @LoginAttemptId, @FailureReason = 'UnknownUser';

            IF @@TRANCOUNT > 0 COMMIT TRANSACTION;

            ;THROW 50115, N'The caller reported a verified credential for a user name no account holds, which means it matched against the derived dummy verifier. That is a client bug or a lie; either way no session is issued.', 1;
        END;

        SELECT @IsPlatformAdmin    = u.IsPlatformAdmin
             , @IsLockedOut        = u.IsLockedOut
             , @LockoutEndUtc      = u.LockoutEndUtc
             , @MustChangePassword = u.MustChangePassword
          FROM auth.[User] AS u
         WHERE u.UserId = @UserId;

        -- 5.  Deleted, deactivated, or locked out with the lockout still in force.  The one error in the range that is
        --     safe to be specific about, because the caller has already proved they hold the password.
        IF auth.udfIsUserUsable (@UserId) = 0
        BEGIN
            EXEC auth.uspRecordLoginFailure @LoginAttemptId = @LoginAttemptId, @FailureReason = 'AccountUnusable';

            IF @@TRANCOUNT > 0 COMMIT TRANSACTION;

            ;THROW 50115, N'The credential was correct but the account cannot sign in: it is deleted, deactivated, or locked out with the lockout still in force. Safe to state plainly -- the caller has already proved they hold the password, so this reveals nothing they did not know (section 19.2).', 1;
        END;

        -- 6.  The lapsed lockout, cleared lazily.  udfIsUserUsable has already accepted the sign-in; this only tidies
        --     the flag so an administrator is not shown a lockout that is not in force.  No sweep job by design.
        IF @IsLockedOut = 1
        BEGIN
            UPDATE auth.[User]
               SET IsLockedOut     = 0
                 , LockoutEndUtc   = NULL
                 , auditModifiedBy = @Actor
             WHERE UserId = @UserId;

            INSERT logs.AuthenticationEvent
                (EventUtc, EventType, EventSeverity, ApplicationId, UserId, LoginAttemptId
               , UserName, ClientAddress, Actor, DetailJson)
            VALUES (@Now, 'LockoutCleared', 'Info', @ApplicationId, @UserId, @LoginAttemptId
                  , @UserName, @ClientAddress, @Actor
                  , CONCAT (N'{"reason":"lapsed","lockoutEndUtc":"'
                          , CONVERT (NVARCHAR (30), @LockoutEndUtc, 126), N'"}'));
        END;

        -- 7.  The policy.  Re-read here rather than taken from step 1's output: the policy may have changed while the
        --     user was typing, and in any case the application was never trusted to report it.
        SET @PolicyId = auth.udfResolveAuthPolicy (@PolicyTenantId);

        SELECT @AllowLocal      = p.AllowLocalPassword
             , @RequireMfaLocal = p.RequireMfaForLocal
             , @LifetimeMinutes = p.SessionLifetimeMinutes
             , @IdleMinutes     = p.IdleTimeoutMinutes
          FROM auth.TenantAuthenticationPolicy AS p
         WHERE p.TenantAuthenticationPolicyId = @PolicyId;

        SET @PolicySource = CASE WHEN @PolicyId IS NULL
                                 THEN N'config.ApplicationSetting defaults'
                                 ELSE N'policy ' + CAST (@PolicyId AS NVARCHAR (11)) END;

        SET @AllowLocal      = COALESCE (@AllowLocal,      CAST (1 AS BIT));
        SET @RequireMfaLocal = COALESCE (@RequireMfaLocal, CAST (1 AS BIT));
        SET @LifetimeMinutes = COALESCE (@LifetimeMinutes
                                       , TRY_CAST ((SELECT SettingValue FROM config.ApplicationSetting
                                                     WHERE SettingKey = N'Authn.SessionLifetimeMinutes'
                                                       AND IsDeleted  = 0) AS INT), 480);
        SET @IdleMinutes     = COALESCE (@IdleMinutes
                                       , TRY_CAST ((SELECT SettingValue FROM config.ApplicationSetting
                                                     WHERE SettingKey = N'Authn.IdleTimeoutMinutes'
                                                       AND IsDeleted  = 0) AS INT), 60);

        -- Checked in uspGetLoginVerifier too.  Checked again because the policy can be edited between the two calls,
        -- and because an exchange opened before local sign-in was switched off must not outlive the decision.
        IF @AllowLocal = 0
        BEGIN
            EXEC auth.uspRecordLoginFailure @LoginAttemptId = @LoginAttemptId, @FailureReason = 'PolicyDenied';

            IF @@TRANCOUNT > 0 COMMIT TRANSACTION;

            ;THROW 50103, N'Local password sign-in is not permitted for this tenant by the resolved authentication policy. Re-read here as well as at uspGetLoginVerifier, because the policy can change while the user is typing.', 1;
        END;

        -- 8.  INV-09, and INV-08's harder half.  @IsBypassRoute is a request, not a permission.
        IF @IsBypassRoute = 1
        BEGIN
            IF @IsPlatformAdmin = 0
            BEGIN
                EXEC auth.uspRecordLoginFailure @LoginAttemptId = @LoginAttemptId
                   , @FailureReason = 'BypassNotPermitted';

                IF @@TRANCOUNT > 0 COMMIT TRANSACTION;

                ;THROW 50108, N'The bypass route was requested for an account that is not a platform administrator. INV-09: the route exists so a platform administrator can get in when a tenant''s federation is broken, and it is not a general-purpose alternative sign-in.', 1;
            END;

            -- INV-08.  Unconditional, and independent of what any policy says: the whole point of the bypass route is
            -- that it skips the tenant's identity provider, so the second factor is the only thing left.
            IF @MfaSatisfied = 0
            BEGIN
                EXEC auth.uspRecordLoginFailure @LoginAttemptId = @LoginAttemptId, @FailureReason = 'MfaRequired';

                IF @@TRANCOUNT > 0 COMMIT TRANSACTION;

                ;THROW 50107, N'INV-08: the bypass route always requires a second factor, whatever the tenant policy says, because it is the route that skips the tenant''s identity provider. Call auth.uspVerifyMfa for this exchange first. Also a CHECK constraint on both auth.LoginAttempt and auth.UserSession.', 1;
            END;
        END;

        -- 9.  The policy's MFA requirement on the ordinary route.  A refusal, not a wait -- see the notes.
        IF @RequireMfaLocal = 1 AND @MfaSatisfied = 0
        BEGIN
            SET @HasMfaFactor = CASE WHEN EXISTS (SELECT 1 FROM auth.UserMfaFactor AS f
                                                   WHERE f.UserId      = @UserId
                                                     AND f.IsConfirmed = 1
                                                     AND f.IsDeleted   = 0)
                                     THEN 1 ELSE 0 END;

            -- Whether the account even HAS a confirmed factor is the difference between "the user skipped the step" and
            -- "the user cannot complete the step and is now locked out of a tenant that requires it".  The second is an
            -- operational problem for the service desk, not a security event, and it is invisible unless recorded here.
            INSERT logs.AuthenticationEvent
                (EventUtc, EventType, EventSeverity, ApplicationId, UserId, LoginAttemptId
               , UserName, ClientAddress, Actor, DetailJson)
            VALUES (@Now, 'MfaChallenged', CASE WHEN @HasMfaFactor = 1 THEN 'Info' ELSE 'Warning' END
                  , @ApplicationId, @UserId, @LoginAttemptId, @UserName, @ClientAddress, @Actor
                  , CONCAT (N'{"requiredBy":"', @PolicySource
                          , N'","satisfied":false,"hasConfirmedFactor":'
                          , CASE WHEN @HasMfaFactor = 1 THEN N'true' ELSE N'false' END, N'}'));

            EXEC auth.uspRecordLoginFailure @LoginAttemptId = @LoginAttemptId, @FailureReason = 'MfaRequired';

            IF @@TRANCOUNT > 0 COMMIT TRANSACTION;

            ;THROW 50109, N'The resolved policy requires a second factor and this exchange has not satisfied one. uspGetLoginVerifier returned @RequiresMfa = 1, so arriving here without it is a broken client or an attempt to skip the factor; either way it costs the exchange, so skipping is never cheaper than complying. If the account has no confirmed factor, THIS EXCHANGE is what it enrols one with: pass this LoginAttemptId to auth.uspEnrolMfaFactor as @BootstrapLoginAttemptId, within Authn.MfaEnrolmentWindowSeconds -- 112_auth_mfa_procedures.sql, T-041.', 1;
        END;

        -- 10.  The session.  Both expiries computed now and stored, so editing a policy tomorrow cannot retroactively
        --      shorten or lengthen a session issued today -- 070_auth_session.sql argues the storage.
        SET @AbsoluteExpiryUtc = DATEADD (MINUTE, @LifetimeMinutes, @Now);
        SET @IdleExpiryUtc     = DATEADD (MINUTE, @IdleMinutes,     @Now);

        -- CK_auth_UserSession_Expiries requires idle <= absolute.  A policy with an idle timeout longer than its
        -- lifetime is nonsense the table refuses; clamping rather than failing, because the user did nothing wrong and
        -- the misconfiguration is visible in the report either way.
        IF @IdleExpiryUtc > @AbsoluteExpiryUtc
        BEGIN
            SET @IdleExpiryUtc = @AbsoluteExpiryUtc;
        END;

        INSERT auth.UserSession
            (UserId, ActiveUserProfileId, LoginAttemptId, ApplicationId, SessionTokenHash, ClientAddress
           , AuthenticationMethod, IsBypassRoute, MfaSatisfied, StartedUtc, LastSeenUtc
           , AbsoluteExpiryUtc, IdleExpiryUtc, auditCreatedBy, auditModifiedBy)
        VALUES (@UserId, NULL, @LoginAttemptId, @ApplicationId, @SessionTokenHash, @ClientAddress
              , 'LocalPassword', @IsBypassRoute, @MfaSatisfied, @Now, @Now
              , @AbsoluteExpiryUtc, @IdleExpiryUtc, @Actor, @Actor);

        SET @UserSessionId = CAST (SCOPE_IDENTITY () AS BIGINT);

        -- 11.  Conclude the exchange.  Success is terminal, and the trigger will refuse any later change to it.
        UPDATE auth.LoginAttempt
           SET Outcome         = 'Success'
             , ConcludedUtc    = @Now
             , auditModifiedBy = @Actor
         WHERE LoginAttemptId = @LoginAttemptId;

        INSERT logs.AuthenticationEvent
            (EventUtc, EventType, EventSeverity, ApplicationId, UserId, LoginAttemptId, UserSessionId
           , UserName, ClientAddress, Actor, DetailJson)
        VALUES (@Now, 'LoginSucceeded', 'Info', @ApplicationId, @UserId, @LoginAttemptId, @UserSessionId
              , @UserName, @ClientAddress, @Actor
              , CONCAT (N'{"method":"LocalPassword","isBypassRoute":', @IsBypassRoute
                      , N',"mfaSatisfied":', @MfaSatisfied
                      , N',"policy":"', @PolicySource, N'"}'))
             , (@Now, 'SessionStarted', 'Info', @ApplicationId, @UserId, @LoginAttemptId, @UserSessionId
              , @UserName, @ClientAddress, @Actor
              , CONCAT (N'{"absoluteExpiryUtc":"', CONVERT (NVARCHAR (30), @AbsoluteExpiryUtc, 126)
                      , N'","idleExpiryUtc":"',    CONVERT (NVARCHAR (30), @IdleExpiryUtc, 126)
                      , N'","lifetimeMinutes":', @LifetimeMinutes
                      , N',"idleMinutes":', @IdleMinutes, N'}'));

        SET @Comments = CONCAT (N'Session ', @UserSessionId, N' issued to user ', @UserId, N' from exchange '
                              , @LoginAttemptId, N'. ', @PolicySource, N'. Lifetime ', @LifetimeMinutes
                              , N'm, idle ', @IdleMinutes, N'm, bypass=', @IsBypassRoute
                              , N', mfa=', @MfaSatisfied, N', mustChangePassword=', @MustChangePassword, N'.');

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

-- *** 4. auth.uspVerifyMfa ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspVerifyMfa
Author:       rsincero
CreateDate:   2026-09-19
========================================================================================================================
Description:

Marks a pending sign-in exchange as having satisfied its second factor, by one of two routes: a TOTP code the
application has already verified against the shared secret, or a single-use recovery code.  Section 6.2.

Sets auth.LoginAttempt.MfaSatisfied = 1.  That column is the ONLY thing auth.uspCompleteLogin will accept as evidence of
a second factor, and this procedure is the only writer of it.

========================================================================================================================
Notes:

THE DATABASE CANNOT VERIFY A TOTP CODE AND DOES NOT PRETEND TO.  The secret is stored as ciphertext it holds no key for
(045_auth_identity.sql), so HMAC-ing it here is impossible by construction rather than by policy.  The application
verifies the code and reports WHICH TIME STEP it verified at.  Two things are then checked here, and they are the reason
the step is a parameter at all:

  *  Against the SERVER's clock.  @TimeStep must be within Authn.TotpWindowSteps of the step SYSUTCDATETIME () is in.
     A client that reports a step from next year has either a broken clock or a forged answer, and without this check
     the parameter would be a free pass.
  *  Against auth.UserMfaFactor.LastUsedTimeStep.  A step must be strictly greater than the last one accepted, so a code
     observed over the user's shoulder -- or in a proxy log -- cannot be used a second time inside its own window.

Neither check can tell a broken clock from an attack, and neither needs to: the response is the same.

THE RECOVERY CODE ARRIVES AS A HASH, NOT AS TEXT.  Same argument as D-08 for passwords: a recovery code in a T-SQL
parameter is a recovery code in the plan cache, in Query Store, and in any Extended Events session somebody left
running.  The application computes SHA-256 and passes 32 bytes.  It is a plain hash and not a KDF because the code is
machine-generated with full entropy -- the same argument 045_auth_identity.sql makes for the column.

EVERY FAILED ATTEMPT CONCLUDES THE EXCHANGE, and that is the load-bearing decision in this procedure.  A six-digit code
has a million values; an exchange that survived a failed code would let an attacker who already holds the password walk
the whole space inside one Authn.LoginExchangeTimeoutSeconds window, and neither throttle would see it, because both
count CONCLUDED failures.  Failing the exchange makes every guess cost a full round trip that both counters observe.
The cost to an honest user who fat-fingers a code is starting over -- which is what every authenticator app's UI already
expects.

A USED RECOVERY CODE IS SPENT EVEN THOUGH THE EXCHANGE MAY STILL FAIL LATER.  UsedUtc is write-once (the trigger
enforces it), and it is set here rather than at auth.uspCompleteLogin.  If the sign-in then fails for an unrelated
reason the code is gone -- deliberately.  The alternative is a code that can be presented, observed to work, and
presented again, which is not single-use in any sense that matters.

THE FEDERATED ROUTE HAS NO USER YET, so a step-up on an exchange still at 'SsoBegun' cannot be resolved to an account
and is refused.  MFA on the federated route belongs to the identity provider -- section 7.3.  Step-up re-authentication
of an ESTABLISHED session is auth.UserSession.ElevatedUntilUtc, which is Phase 5's business, not this procedure's.

========================================================================================================================
Example Usage and Performance:

declare @Ok bit;
exec auth.uspVerifyMfa @LoginAttemptId = 42, @TimeStep = 58312345, @MfaSatisfied = @Ok output;

exec auth.uspVerifyMfa @LoginAttemptId = 42
   , @RecoveryCodeHash = 0x2C26B46B68FFC68FF99B453C1D30413413422D706483BFA0F98A5E886266E7AE
   , @MfaSatisfied = @Ok output;

One seek on the exchange, one on the factor or the code, one narrow update.

========================================================================================================================
Modification History:

Date:		2026-09-19
Author:		rsincero
Ticket:		T-037
Description:
Created.  Phase 2.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspVerifyMfa
      @LoginAttemptId   BIGINT
    , @TimeStep         BIGINT         = NULL
    , @RecoveryCodeHash VARBINARY (32) = NULL
    , @FactorType       VARCHAR (20)   = 'Totp'
    , @MfaSatisfied     BIT            = NULL OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspVerifyMfa]')
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

    -- The time step is not a secret -- it is a clock reading -- so it is logged.  The recovery code hash is logged as a
    -- presence flag only: a hash is not the code, but a log of which hashes were tried is still a log worth not keeping.
    SET @KeyParameters = CONCAT (N'@LoginAttemptId=', @LoginAttemptId
                               , N', @TimeStep=', COALESCE (CAST (@TimeStep AS NVARCHAR (20)), N'(null)')
                               , N', @RecoveryCodeHash=', CASE WHEN @RecoveryCodeHash IS NULL
                                                               THEN N'(null)' ELSE N'(supplied)' END
                               , N', @FactorType=', @FactorType);
    SET @ContextMessage = N'Satisfy the second factor for a pending exchange. Section 6.2; the engine cannot verify TOTP.';

    DECLARE @ApplicationId     INT            = NULL
          , @UserName          NVARCHAR (256) = NULL
          , @UserId            INT            = NULL
          , @ClientAddress     NVARCHAR (45)  = NULL
          , @Outcome           VARCHAR (20)   = NULL
          , @AttemptedUtc      DATETIME2 (3)  = NULL
          , @ExchangeTimeout   INT            = NULL
          , @StepSeconds       INT            = NULL
          , @WindowSteps       INT            = NULL
          , @ServerStep        BIGINT         = NULL
          , @FactorId          INT            = NULL
          , @LastUsedStep      BIGINT         = NULL
          , @RecoveryCodeId    INT            = NULL
          , @RemainingCodes    INT            = NULL
          , @Route             NVARCHAR (20)  = NULL;

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

        SET @MfaSatisfied = 0;

        -- Exactly one route per call.  Both supplied is a client that does not know which factor it used, and guessing
        -- on its behalf would mean a failed TOTP silently spending a recovery code.
        IF (@TimeStep IS NULL AND @RecoveryCodeHash IS NULL)
           OR (@TimeStep IS NOT NULL AND @RecoveryCodeHash IS NOT NULL)
        BEGIN
            ;THROW 50100, N'Supply exactly one of @TimeStep (a TOTP step the application has already verified) or @RecoveryCodeHash (the SHA-256 of a recovery code). Both together would mean a failed code silently spending a recovery code. Raised before the exchange is touched.', 1;
        END;

        SET @Route = CASE WHEN @TimeStep IS NOT NULL THEN N'Totp' ELSE N'RecoveryCode' END;

        IF @Route = N'Totp' AND (@FactorType <> 'Totp' OR @TimeStep <= 0)
        BEGIN
            ;THROW 50100, N'@FactorType must be ''Totp'' -- the only value auth.UserMfaFactor accepts today -- and @TimeStep must be a positive step number, not a Unix time in seconds. Raised before the exchange is touched.', 1;
        END;

        IF @Route = N'RecoveryCode' AND DATALENGTH (@RecoveryCodeHash) <> 32
        BEGIN
            ;THROW 50100, N'@RecoveryCodeHash must be exactly 32 bytes -- the SHA-256 of the code, computed by the application. The code itself is never a parameter here, for the same reason a password is not (D-08).', 1;
        END;

        -- 1.  The exchange.  Either route's exchange may be stepped up, but only while it is still pending.
        SELECT @ApplicationId = a.ApplicationId
             , @UserName      = a.UserName
             , @UserId        = a.UserId
             , @ClientAddress = a.ClientAddress
             , @Outcome       = a.Outcome
             , @AttemptedUtc  = a.AttemptedUtc
          FROM auth.LoginAttempt AS a
         WHERE a.LoginAttemptId = @LoginAttemptId
           AND a.IsDeleted      = 0;

        IF @UserName IS NULL OR @Outcome NOT IN ('VerifierIssued', 'SsoBegun')
        BEGIN
            ;THROW 50105, N'No pending sign-in exchange with that identifier: it does not exist or it has already been concluded, and a concluded exchange is final (D-14). Start again at auth.uspGetLoginVerifier.', 1;
        END;

        SET @ExchangeTimeout = COALESCE (TRY_CAST ((SELECT SettingValue FROM config.ApplicationSetting
                                                     WHERE SettingKey = N'Authn.LoginExchangeTimeoutSeconds'
                                                       AND IsDeleted  = 0) AS INT), 300);

        IF DATEADD (SECOND, @ExchangeTimeout, @AttemptedUtc) < @Now
        BEGIN
            EXEC auth.uspRecordLoginFailure @LoginAttemptId = @LoginAttemptId, @FailureReason = 'ExchangeExpired';

            IF @@TRANCOUNT > 0 COMMIT TRANSACTION;

            ;THROW 50105, N'This sign-in exchange is older than Authn.LoginExchangeTimeoutSeconds and has been concluded as a failure. Start again. The failure record was committed before this error was raised, deliberately.', 1;
        END;

        -- 2.  The account.  A federated exchange has no user until auth.uspCompleteSsoLogin runs -- see the notes.
        IF @UserId IS NULL
        BEGIN
            EXEC auth.uspRecordLoginFailure @LoginAttemptId = @LoginAttemptId, @FailureReason = 'MfaFailed';

            IF @@TRANCOUNT > 0 COMMIT TRANSACTION;

            ;THROW 50111, N'This exchange has no account to verify a factor against: either the submitted user name is held by nobody -- in which case it was issued a derived dummy verifier and fails identically here, by design (19.2) -- or it is a federated exchange, where the second factor belongs to the identity provider (section 7.3).', 1;
        END;

        IF @Route = N'Totp'
        BEGIN
            -- 3a.  The factor.  An unconfirmed factor is enrolment in progress and cannot satisfy anything: that is
            --      what IsConfirmed is for, and confirming it is auth.uspConfirmMfaFactor's job (112, T-041).
            SELECT @FactorId     = f.UserMfaFactorId
                 , @LastUsedStep = f.LastUsedTimeStep
              FROM auth.UserMfaFactor AS f
             WHERE f.UserId      = @UserId
               AND f.FactorType  = @FactorType
               AND f.IsConfirmed = 1
               AND f.IsDeleted   = 0;

            IF @FactorId IS NULL
            BEGIN
                EXEC auth.uspRecordLoginFailure @LoginAttemptId = @LoginAttemptId, @FailureReason = 'MfaFailed';

                IF @@TRANCOUNT > 0 COMMIT TRANSACTION;

                ;THROW 50110, N'This account has no confirmed factor of that type, so there is nothing for the reported time step to have been verified against. Either nothing is enrolled, or what is enrolled has never been confirmed -- auth.uspEnrolMfaFactor and auth.uspConfirmMfaFactor are the two procedures that fix that, in 112_auth_mfa_procedures.sql.', 1;
            END;

            SET @StepSeconds = COALESCE (TRY_CAST ((SELECT SettingValue FROM config.ApplicationSetting
                                                     WHERE SettingKey = N'Authn.TotpStepSeconds'
                                                       AND IsDeleted  = 0) AS INT), 30);
            SET @WindowSteps = COALESCE (TRY_CAST ((SELECT SettingValue FROM config.ApplicationSetting
                                                     WHERE SettingKey = N'Authn.TotpWindowSteps'
                                                       AND IsDeleted  = 0) AS INT), 1);

            -- The server's own step.  DATEDIFF_BIG because DATEDIFF in seconds from 1970 overflows an INT in 2038, and
            -- a template that stops working on a date is a template with a fuse in it.
            SET @ServerStep = DATEDIFF_BIG (SECOND, CAST (N'1970-01-01T00:00:00' AS DATETIME2 (0)), @Now)
                            / @StepSeconds;

            -- 4a.  Bounded against the clock, then against the last step accepted.  Both failures are E-50111 and both
            --      cost the exchange: a code from the wrong century and a replayed code are the same answer on screen.
            IF ABS (@TimeStep - @ServerStep) > @WindowSteps
               OR @TimeStep <= COALESCE (@LastUsedStep, 0)
            BEGIN
                INSERT logs.AuthenticationEvent
                    (EventUtc, EventType, EventSeverity, ApplicationId, UserId, LoginAttemptId
                   , UserName, ClientAddress, Actor, DetailJson)
                VALUES (@Now, 'MfaFailed', 'Warning', @ApplicationId, @UserId, @LoginAttemptId
                      , @UserName, @ClientAddress, @Actor
                      , CONCAT (N'{"route":"Totp","reportedStep":', @TimeStep
                              , N',"serverStep":', @ServerStep
                              , N',"windowSteps":', @WindowSteps
                              , N',"lastUsedStep":', COALESCE (CAST (@LastUsedStep AS NVARCHAR (20)), N'null')
                              , N',"reason":"'
                              , CASE WHEN ABS (@TimeStep - @ServerStep) > @WindowSteps
                                     THEN N'outside the server clock window' ELSE N'replay of a used or older step' END
                              , N'"}'));

                EXEC auth.uspRecordLoginFailure @LoginAttemptId = @LoginAttemptId, @FailureReason = 'MfaFailed';

                IF @@TRANCOUNT > 0 COMMIT TRANSACTION;

                ;THROW 50111, N'The reported TOTP time step is outside Authn.TotpWindowSteps of the server''s own step, or is not strictly later than the last step accepted for this factor. Either way the exchange has been concluded as a failure, so a guess costs a full round trip that both throttles can count. The distinguishing detail is in logs.AuthenticationEvent.', 1;
            END;

            -- 5a.  Spend the step.  The pair CHECK on auth.UserMfaFactor requires both columns together.
            UPDATE auth.UserMfaFactor
               SET LastUsedUtc      = @Now
                 , LastUsedTimeStep = @TimeStep
                 , auditModifiedBy  = @Actor
             WHERE UserMfaFactorId = @FactorId;
        END
        ELSE
        BEGIN
            -- 3b.  The recovery code.  Matched on (UserId, CodeHash), which is what the unique index is on: a global
            --      unique index on CodeHash would refuse a coincidental collision between two users and be an oracle in
            --      its own right (045_auth_identity.sql argues it).
            SELECT @RecoveryCodeId = r.UserMfaRecoveryCodeId
              FROM auth.UserMfaRecoveryCode AS r
             WHERE r.UserId    = @UserId
               AND r.CodeHash  = @RecoveryCodeHash
               AND r.UsedUtc   IS NULL
               AND r.IsDeleted = 0;

            IF @RecoveryCodeId IS NULL
            BEGIN
                -- No distinction is drawn, here or on screen, between a code that never existed and one already spent.
                -- "That code has been used" tells an attacker holding a leaked list which entries are still live.
                INSERT logs.AuthenticationEvent
                    (EventUtc, EventType, EventSeverity, ApplicationId, UserId, LoginAttemptId
                   , UserName, ClientAddress, Actor, DetailJson)
                VALUES (@Now, 'MfaFailed', 'Warning', @ApplicationId, @UserId, @LoginAttemptId
                      , @UserName, @ClientAddress, @Actor
                      , N'{"route":"RecoveryCode","reason":"no unused code with that hash for this account"}');

                EXEC auth.uspRecordLoginFailure @LoginAttemptId = @LoginAttemptId
                   , @FailureReason = 'RecoveryCodeInvalid';

                IF @@TRANCOUNT > 0 COMMIT TRANSACTION;

                ;THROW 50112, N'No unused recovery code with that hash belongs to this account. Never existed and already spent are the same answer deliberately: the difference would tell somebody holding a leaked list which entries are still live. The exchange has been concluded as a failure.', 1;
            END;

            -- 4b.  Spend it now, not at uspCompleteLogin -- see the notes.  UsedUtc is write-once at the trigger.
            UPDATE auth.UserMfaRecoveryCode
               SET UsedUtc         = @Now
                 , auditModifiedBy = @Actor
             WHERE UserMfaRecoveryCodeId = @RecoveryCodeId;

            SET @RemainingCodes = (SELECT COUNT (*)
                                     FROM auth.UserMfaRecoveryCode AS r
                                    WHERE r.UserId    = @UserId
                                      AND r.UsedUtc   IS NULL
                                      AND r.IsDeleted = 0);

            -- Alert, not Info.  A recovery code being used is either a lost authenticator or somebody working from a
            -- stolen list, and the two look identical from here -- so a human should see it either way.
            INSERT logs.AuthenticationEvent
                (EventUtc, EventType, EventSeverity, ApplicationId, UserId, LoginAttemptId
               , UserName, ClientAddress, Actor, DetailJson)
            VALUES (@Now, 'RecoveryCodeUsed', 'Alert', @ApplicationId, @UserId, @LoginAttemptId
                  , @UserName, @ClientAddress, @Actor
                  , CONCAT (N'{"remainingUnusedCodes":', @RemainingCodes, N'}'));
        END;

        -- 6.  The only write to MfaSatisfied anywhere in the system.  auth.uspCompleteLogin reads this column and
        --     nothing the application says, which is what makes INV-08 enforceable at all.
        UPDATE auth.LoginAttempt
           SET MfaSatisfied    = 1
             , auditModifiedBy = @Actor
         WHERE LoginAttemptId = @LoginAttemptId;

        SET @MfaSatisfied = 1;

        INSERT logs.AuthenticationEvent
            (EventUtc, EventType, EventSeverity, ApplicationId, UserId, LoginAttemptId
           , UserName, ClientAddress, Actor, DetailJson)
        VALUES (@Now, 'MfaSucceeded', 'Info', @ApplicationId, @UserId, @LoginAttemptId
              , @UserName, @ClientAddress, @Actor
              , CONCAT (N'{"route":"', @Route, N'"}'));

        SET @Comments = CONCAT (N'Exchange ', @LoginAttemptId, N' satisfied its second factor via ', @Route
                              , N' for user ', @UserId
                              , CASE WHEN @Route = N'Totp'
                                     THEN CONCAT (N'. Step ', @TimeStep, N' accepted against server step ', @ServerStep
                                                , N' (window ', @WindowSteps, N').')
                                     ELSE CONCAT (N'. ', @RemainingCodes, N' unused recovery code(s) remain.') END);

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

-- *** 5. auth.uspBeginSsoLogin ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspBeginSsoLogin
Author:       rsincero
CreateDate:   2026-09-19
========================================================================================================================
Description:

Step 1 of the federated route.  Checks that the tenant permits federation and that the address is not throttled, then
opens an exchange (Outcome 'SsoBegun') and returns its identifier for the callback to present.  Section 7.3.

========================================================================================================================
Notes:

@Issuer IS CHECKED AGAINST auth.TenantTrustedIssuer, AND THE LIST INHERITS THE WAY A POLICY ROW INHERITS.  This closes
G-21.  For two phases this procedure took no @Issuer at all, on the argument that a parameter it could only record and
never validate would create the impression of a check that was not happening -- which was the right call given the
schema, and the wrong thing to leave in the schema: a tenant that federates with one identity provider would accept an
assertion the application attributed to any other, because the database had no way to know the difference.  035 now holds
the list, this procedure resolves it by walking auth.TenantClosure upward and taking the NEAREST ancestor that has one,
and an issuer off that list is refused with E-50124.

AN UNCONFIGURED LIST IS NOT AN EMPTY LIST.  If no ancestor holds a live row, nothing resolves, the issuer is not checked,
and this procedure behaves exactly as it did before G-21.  Refusing everything instead would mean upgrading the template
turns federated sign-in off for every deployment that already had it working.  The trade is that the control is opt-in,
and it is paid for by reporting: 035's closing report says ACTION at severity 2 on any deployment where a policy permits
federation and no list exists, so the absence is loud rather than silent.  That is the distinction G-30 exists to record.

ONCE A LIST RESOLVES IT IS STRICT IN BOTH DIRECTIONS.  An issuer that is not on it is refused; so is a call that supplies
no issuer.  A tenant that has named its providers has said the question is answerable, and a caller that declines to
answer cannot be given the benefit of the doubt.  Both are E-50124, because from the tenant's side they are one fact:
this exchange cannot be shown to be with a provider the tenant trusts.

The issuer remains load-bearing at the callback too, where it is half of INV-07's key.  The check here is the earlier of
the two and the cheaper one: it refuses before the redirect rather than after the round trip.

UserName IS '(sso pending)' UNLESS THE APPLICATION HAD A LOGIN HINT.  The banner at the top of this file argues why it is
never rewritten afterwards.  A hint is worth passing when the sign-in page has a user name box before the redirect: it
makes the exchange greppable by the name the person typed, and it costs nothing, because nothing trusts it.

THE ADDRESS THROTTLE APPLIES HERE TOO.  The federated route does not check passwords, so it cannot be used to guess
them -- but it can be used to open exchanges by the thousand, and an unthrottled entry point next to a throttled one is
just the unthrottled entry point.

========================================================================================================================
Example Usage and Performance:

declare @AttemptId bigint;
exec auth.uspBeginSsoLogin @ApplicationCode = N'DEMO', @TenantCode = N'ACME', @ClientAddress = N'203.0.113.7'
   , @Issuer = N'https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0'
   , @UserNameHint = N'alice@acme.example', @LoginAttemptId = @AttemptId output;

CALL IT BY NAME.  @Issuer was added after @TenantCode in the parameter list rather than at the end, because it belongs
with the other two values that decide WHICH tenant and WHICH provider this exchange is for; a positional caller written
against the pre-G-21 signature would pass its user-name hint as an issuer.  Every call in this template and its tests is
by name, and so should yours be.

One filtered-index seek for the throttle, one seek per lookup, one insert.  The issuer check adds one seek on
UX_auth_TenantTrustedIssuer_TenantIssuer per ancestor examined, and stops at the first tenant that has a list -- which on
the normal deployment shape (a list at the root and nowhere else) is one seek at the last ancestor.

========================================================================================================================
Modification History:

Date:		2026-09-19
Author:		rsincero
Ticket:		T-038
Description:
Created.  Phase 2.

-----------------------------------------------------------------------------------------------------------------------

Date:		2026-09-21
Author:		rsincero
Ticket:		G-21
Description:
Added @Issuer and the auth.TenantTrustedIssuer check -- E-50124.  The paragraph in Notes that argued the parameter should
not exist is kept, rewritten, because the argument was sound and what changed was the schema rather than the reasoning.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspBeginSsoLogin
      @ApplicationCode NVARCHAR (50)
    , @ClientAddress   NVARCHAR (45)
    , @TenantCode      NVARCHAR (50)  = NULL
    , @Issuer          NVARCHAR (512) = NULL
    , @UserNameHint    NVARCHAR (256) = NULL
    , @UserAgent       NVARCHAR (512) = NULL
    , @LoginAttemptId  BIGINT         = NULL OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspBeginSsoLogin]')
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

    -- @Issuer is a public provider URL, not a secret: it appears in every token and in the metadata document the
    -- application fetches, so it belongs in @KeyParameters.  A refused exchange is diagnosed by knowing which issuer was
    -- offered, and rule 8's prohibition is on credentials, not identifiers.
    SET @KeyParameters = CONCAT (N'@ApplicationCode=', @ApplicationCode
                               , N', @TenantCode=', COALESCE (@TenantCode, N'(root)')
                               , N', @Issuer=', COALESCE (@Issuer, N'(none)')
                               , N', @UserNameHint=', COALESCE (@UserNameHint, N'(none)')
                               , N', @ClientAddress=', @ClientAddress);
    SET @ContextMessage = N'Step 1 of the federated route: open an exchange before the redirect. Section 7.3.';

    DECLARE @ApplicationId      INT            = NULL
          , @TenantId           INT            = NULL
          , @PolicyId           INT            = NULL
          , @AllowFederated     BIT            = NULL
          , @AddressThreshold   INT            = NULL
          , @AddressWindowMin   INT            = NULL
          , @AddressFailures    INT            = NULL
          , @UserName           NVARCHAR (256) = NULL
          , @IssuerListTenantId INT            = NULL
          , @IssuerTrusted      BIT            = NULL;

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

        IF @ClientAddress IS NULL OR LEN (LTRIM (RTRIM (@ClientAddress))) = 0
        BEGIN
            ;THROW 50100, N'A client address is required before a sign-in exchange can be opened: it is one of the two throttle keys and it is immutable on the attempt row.', 1;
        END;

        SET @ClientAddress = LTRIM (RTRIM (@ClientAddress));
        SET @UserName      = COALESCE (NULLIF (LTRIM (RTRIM (@UserNameHint)), N''), N'(sso pending)');

        SET @AddressThreshold = COALESCE (TRY_CAST ((SELECT SettingValue FROM config.ApplicationSetting
                                                      WHERE SettingKey = N'Authn.AddressThreshold'
                                                        AND IsDeleted  = 0) AS INT), 20);
        SET @AddressWindowMin = COALESCE (TRY_CAST ((SELECT SettingValue FROM config.ApplicationSetting
                                                      WHERE SettingKey = N'Authn.AddressWindowMinutes'
                                                        AND IsDeleted  = 0) AS INT), 15);

        SET @AddressFailures = (SELECT COUNT (*)
                                  FROM auth.LoginAttempt AS a
                                 WHERE a.ClientAddress = @ClientAddress
                                   AND a.Outcome       = 'Failure'
                                   AND a.IsDeleted     = 0
                                   AND a.AttemptedUtc >= DATEADD (MINUTE, -@AddressWindowMin, @Now));

        IF @AddressFailures >= @AddressThreshold
        BEGIN
            INSERT logs.AuthenticationEvent
                (EventUtc, EventType, EventSeverity, UserName, ClientAddress, Actor, DetailJson)
            VALUES (@Now, 'AddressThrottled', 'Warning', @UserName, @ClientAddress, @Actor
                  , CONCAT (N'{"failures":', @AddressFailures, N',"threshold":', @AddressThreshold
                          , N',"windowMinutes":', @AddressWindowMin, N',"stage":"BeginSsoLogin"}'));

            IF @@TRANCOUNT > 0 COMMIT TRANSACTION;

            ;THROW 50116, N'Refused by the per-address throttle. The federated route is throttled on the same count as the local one: an unthrottled entry point beside a throttled one is simply the unthrottled entry point.', 1;
        END;

        SELECT @ApplicationId = a.ApplicationId
          FROM auth.Application AS a
         WHERE a.ApplicationCode = @ApplicationCode
           AND a.IsActive        = 1
           AND a.IsDeleted       = 0;

        IF @ApplicationId IS NULL
        BEGIN
            ;THROW 50101, N'No such application, or it is inactive. A deployment error rather than an attack, and it leaks nothing about users -- but it still shows the generic sign-in message (UI-26).', 1;
        END;

        IF @TenantCode IS NULL
        BEGIN
            SELECT @TenantId = t.TenantId
              FROM auth.Tenant AS t
             WHERE t.ApplicationId  = @ApplicationId
               AND t.ParentTenantId IS NULL
               AND t.IsDeleted      = 0;
        END
        ELSE
        BEGIN
            SELECT @TenantId = t.TenantId
              FROM auth.Tenant AS t
             WHERE t.ApplicationId = @ApplicationId
               AND t.TenantCode    = @TenantCode
               AND t.IsDeleted     = 0;
        END;

        IF @TenantId IS NULL OR auth.udfIsTenantUsable (@TenantId) = 0
        BEGIN
            ;THROW 50102, N'No such tenant for this application, or the tenant is not usable -- which includes a tenant under a deactivated ancestor (section 5.4). Generic message on screen (UI-26).', 1;
        END;

        SET @PolicyId = auth.udfResolveAuthPolicy (@TenantId);

        SELECT @AllowFederated = p.AllowFederated
          FROM auth.TenantAuthenticationPolicy AS p
         WHERE p.TenantAuthenticationPolicyId = @PolicyId;

        -- The default when no policy row applies is 0, and it is the one default in this file that differs from the
        -- permissive reading: federation requires somebody to have configured an identity provider, so "no policy
        -- resolved" means "nobody has said which provider", not "any provider will do".  AllowLocalPassword defaults the
        -- other way for exactly the same reason -- a local password needs no configuration beyond a credential row.
        SET @AllowFederated = COALESCE (@AllowFederated, CAST (0 AS BIT));

        IF @AllowFederated = 0
        BEGIN
            INSERT logs.AuthenticationEvent
                (EventUtc, EventType, EventSeverity, ApplicationId, UserName, ClientAddress, Actor, DetailJson)
            VALUES (@Now, 'PolicyResolutionFailed', 'Warning', @ApplicationId, @UserName, @ClientAddress, @Actor
                  , CONCAT (N'{"reason":"federation not permitted","policy":'
                          , COALESCE (CAST (@PolicyId AS NVARCHAR (11)), N'null'), N'}'));

            IF @@TRANCOUNT > 0 COMMIT TRANSACTION;

            ;THROW 50104, N'Federated sign-in is not permitted for this tenant: either the resolved policy sets AllowFederated = 0, or no policy row applies at all -- and for federation the absence of a policy is a refusal, because federation needs an identity provider somebody has configured. Section 7.3.', 1;
        END;

        -- G-21.  Resolve the trusted-issuer list the way auth.udfResolveAuthPolicy resolves a policy: the NEAREST
        -- ancestor holding at least one live row owns the list WHOLE.  The EXISTS is what makes "has a list" the thing
        -- inherited, rather than the union of every ancestor's rows -- a tenant that states its own list has overridden
        -- its parent's, not added to it, which is the same rule the policy row follows and the only one an operator can
        -- reason about from a single table.
        SET @Issuer = NULLIF (LTRIM (RTRIM (@Issuer)), N'');

        SELECT TOP (1) @IssuerListTenantId = c.AncestorTenantId
          FROM auth.TenantClosure AS c
         WHERE c.DescendantTenantId = @TenantId
           AND c.IsDeleted          = 0
           AND EXISTS (SELECT 1
                         FROM auth.TenantTrustedIssuer AS ti
                        WHERE ti.TenantId  = c.AncestorTenantId
                          AND ti.IsDeleted = 0)
         ORDER BY c.Depth ASC;

        IF @IssuerListTenantId IS NOT NULL
        BEGIN
            SET @IssuerTrusted = CASE WHEN @Issuer IS NOT NULL
                                       AND EXISTS (SELECT 1
                                                     FROM auth.TenantTrustedIssuer AS ti
                                                    WHERE ti.TenantId  = @IssuerListTenantId
                                                      AND ti.Issuer    = @Issuer
                                                      AND ti.IsDeleted = 0)
                                      THEN 1 ELSE 0 END;

            IF @IssuerTrusted = 0
            BEGIN
                -- The event carries the issuer that was offered and the tenant whose list was consulted, because the
                -- first question asked of this refusal is always "whose list, and what was on it" -- and the second is
                -- whether an operator revoked a row this morning.
                INSERT logs.AuthenticationEvent
                    (EventUtc, EventType, EventSeverity, ApplicationId, UserName, ClientAddress, Actor, DetailJson)
                VALUES (@Now, 'PolicyResolutionFailed', 'Warning', @ApplicationId, @UserName, @ClientAddress, @Actor
                      , CONCAT (N'{"reason":"issuer not trusted","issuerListTenantId":', @IssuerListTenantId
                              , N',"issuerSupplied":', CASE WHEN @Issuer IS NULL THEN N'false' ELSE N'true' END
                              , N',"issuer":"', REPLACE (COALESCE (@Issuer, N''), N'"', N'\"'), N'"}'));

                IF @@TRANCOUNT > 0 COMMIT TRANSACTION;

                ;THROW 50124, N'That issuer is not trusted by this tenant, or no issuer was named. The nearest ancestor holding a trusted-issuer list owns it whole, and an exchange that cannot be shown to be with a provider on that list is refused before the redirect rather than after it. Add the issuer to auth.TenantTrustedIssuer, or pass the one you configured -- exactly as it appears in the token. Section 7.3, gap G-21.', 1;
            END;
        END;

        INSERT auth.LoginAttempt
            (ApplicationId, UserName, UserId, PolicyTenantId, ClientAddress, UserAgent
           , AuthenticationMethod, IsBypassRoute, Outcome, PasswordVerified, MfaSatisfied, AttemptedUtc
           , auditCreatedBy, auditModifiedBy)
        VALUES (@ApplicationId, @UserName, NULL, @TenantId, @ClientAddress, @UserAgent
              , 'Federated', 0, 'SsoBegun', 0, 0, @Now
              , @Actor, @Actor);

        SET @LoginAttemptId = CAST (SCOPE_IDENTITY () AS BIGINT);

        INSERT logs.AuthenticationEvent
            (EventUtc, EventType, EventSeverity, ApplicationId, LoginAttemptId
           , UserName, ClientAddress, Actor, DetailJson)
        VALUES (@Now, 'SsoBegun', 'Info', @ApplicationId, @LoginAttemptId
              , @UserName, @ClientAddress, @Actor
              , CONCAT (N'{"tenantId":', @TenantId, N',"policy":'
                      , COALESCE (CAST (@PolicyId AS NVARCHAR (11)), N'null')
                      , N',"issuerListTenantId":'
                      , COALESCE (CAST (@IssuerListTenantId AS NVARCHAR (11)), N'null')
                      , N',"hintSupplied":', CASE WHEN @UserNameHint IS NULL THEN N'false' ELSE N'true' END, N'}'));

        -- issuerListTenantId = null on the event above, and "no trusted-issuer list applied" here, is the one line that
        -- distinguishes a deployment that has opted into G-21's check from one that has not.  Neither is an error, and
        -- only one of them proves anything, so the transcript has to say which happened.
        SET @Comments = CONCAT (N'Federated exchange ', @LoginAttemptId, N' opened for tenant ', @TenantId
                              , N' as ', @UserName, N'. Address failures in window: ', @AddressFailures, N'/'
                              , @AddressThreshold, N'. '
                              , CASE WHEN @IssuerListTenantId IS NULL
                                     THEN N'No trusted-issuer list applied (G-21 check not configured).'
                                     ELSE CONCAT (N'Issuer trusted by tenant ', @IssuerListTenantId, N'''s list.')
                                END);

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

-- *** 6. auth.uspCompleteSsoLogin ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspCompleteSsoLogin
Author:       rsincero
CreateDate:   2026-09-19
========================================================================================================================
Description:

Step 2 of the federated route.  Resolves the assertion the application received into a local account through
auth.UserFederatedIdentity, then issues the session.  Section 7.3, INV-07.

========================================================================================================================
Notes:

INV-07 IS THIS PROCEDURE'S ONLY LOOKUP, AND EMAIL IS NOT A PARAMETER OF IT.  The account is found by (Issuer, SubjectId)
and by nothing else.  That is not a preference about join keys: an identity provider's email claim is mutable, is often
unverified, and is sometimes reassigned when a person leaves an organisation -- so a system that matches on it hands the
next holder of alice@acme.example the previous holder's account, silently, as a feature.  There is no parameter here that
would allow the mistake to be made, which is the strongest form the invariant can take in a procedure.

AN UNRECOGNISED SUBJECT IS A FAILURE AND NOT AN AUTO-ENROLMENT.  E-50113.  Linking a federated identity to an account is
a deliberate administrative or self-service act with its own audit trail (Phase 3); doing it implicitly on first sign-in
means whoever controls the identity provider -- or whoever can make the application believe an assertion -- creates local
accounts at will.  The application is trusted to report WHAT the provider said, never to decide what it entitles.

THE ISSUER IS CHECKED AT uspBeginSsoLogin, NOT AGAIN HERE, AND THAT IS NOT AN OVERSIGHT.  G-21's list is consulted when
the exchange is opened -- see auth.uspBeginSsoLogin's notes -- and this procedure concludes an exchange that already
passed it, presenting the @LoginAttemptId as proof.  What this procedure checks instead is that the PAIR is linked, which
is the stronger statement for its purpose: an unrecognised issuer cannot resolve to an account unless somebody has
previously linked that exact issuer to it, whatever any list says.

Re-resolving the list here was considered and rejected.  It would refuse a callback for an exchange the database itself
authorised minutes earlier, because an operator revoked an issuer in between -- turning a configuration change into a
partial outage for people already mid-redirect, and leaving no exchange in a terminal state.  Revocation takes effect on
the NEXT sign-in, which is how every other policy value in this file behaves.

MfaSatisfied IS CARRIED FROM THE EXCHANGE AND IS NORMALLY 0 HERE, which is correct rather than lax: on the federated
route the second factor is the identity provider's business, and recording a factor this database never saw would be a
lie in an audit table.  The bypass route -- the one place where this database insists on a factor itself -- is the LOCAL
route by definition, because its whole purpose is getting in when federation is broken.  INV-08 is therefore satisfied
here trivially and still enforced by the CHECK constraint on auth.UserSession.

LastSeenUtc ON THE LINK IS STAMPED HERE and nowhere else.  It is the only way to answer "is this federated link still in
use", which is the question that has to be answered before anybody will agree to remove one.

========================================================================================================================
Example Usage and Performance:

declare @Sid bigint, @Uid int, @Abs datetime2 (3), @Idle datetime2 (3);
exec auth.uspCompleteSsoLogin @LoginAttemptId = 43
   , @Issuer = N'https://login.microsoftonline.com/9188040d-.../v2.0'
   , @SubjectId = N'AAAAAAAAAAAAAAAAAAAAAIkzqFVrSaSaFHy782bbtaQ'
   , @SessionTokenHash = 0x9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08
   , @UserSessionId = @Sid output, @UserId = @Uid output
   , @AbsoluteExpiryUtc = @Abs output, @IdleExpiryUtc = @Idle output;

One seek on UX_auth_UserFederatedIdentity_Issuer_Subject, one on the exchange, two inserts, two narrow updates.

========================================================================================================================
Modification History:

Date:		2026-09-19
Author:		rsincero
Ticket:		T-038
Description:
Created.  Phase 2.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspCompleteSsoLogin
      @LoginAttemptId     BIGINT
    , @Issuer             NVARCHAR (512)
    , @SubjectId          NVARCHAR (256)
    , @SessionTokenHash   VARBINARY (32)
    , @UserSessionId      BIGINT        = NULL OUTPUT
    , @UserId             INT           = NULL OUTPUT
    , @MustChangePassword BIT           = NULL OUTPUT
    , @AbsoluteExpiryUtc  DATETIME2 (3) = NULL OUTPUT
    , @IdleExpiryUtc      DATETIME2 (3) = NULL OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspCompleteSsoLogin]')
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

    -- The issuer and subject are identifiers, not secrets, and they are exactly what an operator needs in order to work
    -- out why a federated sign-in did not resolve.  Logging them is the point.
    SET @KeyParameters = CONCAT (N'@LoginAttemptId=', @LoginAttemptId
                               , N', @Issuer=', @Issuer
                               , N', @SubjectId=', @SubjectId);
    SET @ContextMessage = N'Step 2 of the federated route: resolve (Issuer, SubjectId) to an account. INV-07, 7.3.';

    DECLARE @ApplicationId    INT            = NULL
          , @UserName         NVARCHAR (256) = NULL
          , @PolicyTenantId   INT            = NULL
          , @ClientAddress    NVARCHAR (45)  = NULL
          , @Method           VARCHAR (20)   = NULL
          , @Outcome          VARCHAR (20)   = NULL
          , @AttemptedUtc     DATETIME2 (3)  = NULL
          , @MfaSatisfied     BIT            = NULL
          , @ExchangeTimeout  INT            = NULL
          , @LinkId           INT            = NULL
          , @PolicyId         INT            = NULL
          , @AllowFederated   BIT            = NULL
          , @LifetimeMinutes  INT            = NULL
          , @IdleMinutes      INT            = NULL
          , @PolicySource     NVARCHAR (40)  = NULL
          , @AccountUserName  NVARCHAR (256) = NULL;

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

        IF @SessionTokenHash IS NULL OR DATALENGTH (@SessionTokenHash) <> 32
        BEGIN
            ;THROW 50100, N'@SessionTokenHash must be exactly 32 bytes -- the SHA-256 of a token the APPLICATION generated. Raised before the exchange is touched.', 1;
        END;

        IF @Issuer IS NULL OR LEN (LTRIM (RTRIM (@Issuer))) = 0
           OR @SubjectId IS NULL OR LEN (LTRIM (RTRIM (@SubjectId))) = 0
        BEGIN
            ;THROW 50100, N'Both @Issuer and @SubjectId are required: they are INV-07''s key, and a federated sign-in with half of it is not a federated sign-in.', 1;
        END;

        SELECT @ApplicationId  = a.ApplicationId
             , @UserName       = a.UserName
             , @PolicyTenantId = a.PolicyTenantId
             , @ClientAddress  = a.ClientAddress
             , @Method         = a.AuthenticationMethod
             , @Outcome        = a.Outcome
             , @AttemptedUtc   = a.AttemptedUtc
             , @MfaSatisfied   = a.MfaSatisfied
          FROM auth.LoginAttempt AS a
         WHERE a.LoginAttemptId = @LoginAttemptId
           AND a.IsDeleted      = 0;

        IF @UserName IS NULL OR @Outcome <> 'SsoBegun' OR @Method <> 'Federated'
        BEGIN
            ;THROW 50105, N'No open federated exchange with that identifier. It does not exist, it has already been concluded, or it belongs to the local route. Start again at auth.uspBeginSsoLogin.', 1;
        END;

        SET @ExchangeTimeout = COALESCE (TRY_CAST ((SELECT SettingValue FROM config.ApplicationSetting
                                                     WHERE SettingKey = N'Authn.LoginExchangeTimeoutSeconds'
                                                       AND IsDeleted  = 0) AS INT), 300);

        -- The same window as the local route, and it is the redirect round trip that has to fit inside it.  A user who
        -- was asked to re-authenticate at the identity provider, or to approve a push, can easily exceed five minutes --
        -- so this is the setting an operator is most likely to need to raise, and it is a setting for that reason.
        IF DATEADD (SECOND, @ExchangeTimeout, @AttemptedUtc) < @Now
        BEGIN
            EXEC auth.uspRecordLoginFailure @LoginAttemptId = @LoginAttemptId, @FailureReason = 'ExchangeExpired';

            IF @@TRANCOUNT > 0 COMMIT TRANSACTION;

            ;THROW 50105, N'This federated exchange is older than Authn.LoginExchangeTimeoutSeconds and has been concluded as a failure. The whole redirect round trip must fit inside that window, including any re-authentication the identity provider asked for -- raise the setting if that is too tight for a real provider.', 1;
        END;

        -- INV-07.  The pair, and nothing else.  Note there is no Email in scope in this procedure at all.
        SELECT @LinkId = fi.UserFederatedIdentityId
             , @UserId = fi.UserId
          FROM auth.UserFederatedIdentity AS fi
         WHERE fi.Issuer    = @Issuer
           AND fi.SubjectId = @SubjectId
           AND fi.IsDeleted = 0;

        IF @LinkId IS NULL
        BEGIN
            INSERT logs.AuthenticationEvent
                (EventUtc, EventType, EventSeverity, ApplicationId, LoginAttemptId
               , UserName, ClientAddress, Actor, DetailJson)
            VALUES (@Now, 'SsoFailed', 'Warning', @ApplicationId, @LoginAttemptId
                  , @UserName, @ClientAddress, @Actor
                  , CONCAT (N'{"issuer":"', STRING_ESCAPE (@Issuer, 'json')
                          , N'","subjectId":"', STRING_ESCAPE (@SubjectId, 'json')
                          , N'","reason":"no live link for this issuer and subject"}'));

            EXEC auth.uspRecordLoginFailure @LoginAttemptId = @LoginAttemptId, @FailureReason = 'FederatedNoLink';

            IF @@TRANCOUNT > 0 COMMIT TRANSACTION;

            ;THROW 50113, N'That (Issuer, SubjectId) pair is not linked to any account. Deliberately not an auto-enrolment: linking is an administrative act with its own audit trail (Phase 3), because implicit linking lets whoever controls the identity provider create local accounts at will. The pair is in logs.AuthenticationEvent so an administrator can link it if it is genuine.', 1;
        END;

        SELECT @AccountUserName    = u.UserName
             , @MustChangePassword = u.MustChangePassword
          FROM auth.[User] AS u
         WHERE u.UserId = @UserId;

        IF auth.udfIsUserUsable (@UserId) = 0
        BEGIN
            EXEC auth.uspRecordLoginFailure @LoginAttemptId = @LoginAttemptId, @FailureReason = 'AccountUnusable';

            IF @@TRANCOUNT > 0 COMMIT TRANSACTION;

            ;THROW 50115, N'The federated identity resolved to an account that cannot sign in: deleted, deactivated, or locked out with the lockout still in force. Note that a lockout earned by password guessing does stop the federated route too -- the lock is on the account, not on the credential.', 1;
        END;

        -- Re-read, like the local route's AllowLocalPassword: an exchange opened before federation was switched off must
        -- not outlive the decision.
        SET @PolicyId = auth.udfResolveAuthPolicy (@PolicyTenantId);

        SELECT @AllowFederated  = p.AllowFederated
             , @LifetimeMinutes = p.SessionLifetimeMinutes
             , @IdleMinutes     = p.IdleTimeoutMinutes
          FROM auth.TenantAuthenticationPolicy AS p
         WHERE p.TenantAuthenticationPolicyId = @PolicyId;

        SET @AllowFederated = COALESCE (@AllowFederated, CAST (0 AS BIT));
        SET @PolicySource   = CASE WHEN @PolicyId IS NULL
                                   THEN N'config.ApplicationSetting defaults'
                                   ELSE N'policy ' + CAST (@PolicyId AS NVARCHAR (11)) END;

        IF @AllowFederated = 0
        BEGIN
            EXEC auth.uspRecordLoginFailure @LoginAttemptId = @LoginAttemptId, @FailureReason = 'PolicyDenied';

            IF @@TRANCOUNT > 0 COMMIT TRANSACTION;

            ;THROW 50104, N'Federated sign-in is no longer permitted for this tenant. Checked again here because the policy can be edited during the redirect round trip, and a decision to stop federating should take effect on the exchanges already in flight.', 1;
        END;

        SET @LifetimeMinutes = COALESCE (@LifetimeMinutes
                                       , TRY_CAST ((SELECT SettingValue FROM config.ApplicationSetting
                                                     WHERE SettingKey = N'Authn.SessionLifetimeMinutes'
                                                       AND IsDeleted  = 0) AS INT), 480);
        SET @IdleMinutes     = COALESCE (@IdleMinutes
                                       , TRY_CAST ((SELECT SettingValue FROM config.ApplicationSetting
                                                     WHERE SettingKey = N'Authn.IdleTimeoutMinutes'
                                                       AND IsDeleted  = 0) AS INT), 60);

        SET @AbsoluteExpiryUtc = DATEADD (MINUTE, @LifetimeMinutes, @Now);
        SET @IdleExpiryUtc     = DATEADD (MINUTE, @IdleMinutes,     @Now);

        IF @IdleExpiryUtc > @AbsoluteExpiryUtc
        BEGIN
            SET @IdleExpiryUtc = @AbsoluteExpiryUtc;
        END;

        -- The link's last use.  The only writer of this column -- see the notes.
        UPDATE auth.UserFederatedIdentity
           SET LastSeenUtc     = @Now
             , auditModifiedBy = @Actor
         WHERE UserFederatedIdentityId = @LinkId;

        INSERT auth.UserSession
            (UserId, ActiveUserProfileId, LoginAttemptId, ApplicationId, SessionTokenHash, ClientAddress
           , AuthenticationMethod, IsBypassRoute, MfaSatisfied, StartedUtc, LastSeenUtc
           , AbsoluteExpiryUtc, IdleExpiryUtc, auditCreatedBy, auditModifiedBy)
        VALUES (@UserId, NULL, @LoginAttemptId, @ApplicationId, @SessionTokenHash, @ClientAddress
              , 'Federated', 0, @MfaSatisfied, @Now, @Now
              , @AbsoluteExpiryUtc, @IdleExpiryUtc, @Actor, @Actor);

        SET @UserSessionId = CAST (SCOPE_IDENTITY () AS BIGINT);

        -- UserId is set in the same statement that concludes the exchange.  UserName keeps whatever it was opened with
        -- -- '(sso pending)' or the hint -- because it is immutable, and the banner argues why that is the right trade.
        UPDATE auth.LoginAttempt
           SET UserId          = @UserId
             , Outcome         = 'Success'
             , ConcludedUtc    = @Now
             , auditModifiedBy = @Actor
         WHERE LoginAttemptId = @LoginAttemptId;

        INSERT logs.AuthenticationEvent
            (EventUtc, EventType, EventSeverity, ApplicationId, UserId, LoginAttemptId, UserSessionId
           , UserName, ClientAddress, Actor, DetailJson)
        VALUES (@Now, 'SsoSucceeded', 'Info', @ApplicationId, @UserId, @LoginAttemptId, @UserSessionId
              , @AccountUserName, @ClientAddress, @Actor
              , CONCAT (N'{"issuer":"', STRING_ESCAPE (@Issuer, 'json')
                      , N'","openedAs":"', STRING_ESCAPE (@UserName, 'json'), N'"}'))
             , (@Now, 'LoginSucceeded', 'Info', @ApplicationId, @UserId, @LoginAttemptId, @UserSessionId
              , @AccountUserName, @ClientAddress, @Actor
              , CONCAT (N'{"method":"Federated","mfaSatisfied":', @MfaSatisfied
                      , N',"policy":"', @PolicySource, N'"}'))
             , (@Now, 'SessionStarted', 'Info', @ApplicationId, @UserId, @LoginAttemptId, @UserSessionId
              , @AccountUserName, @ClientAddress, @Actor
              , CONCAT (N'{"absoluteExpiryUtc":"', CONVERT (NVARCHAR (30), @AbsoluteExpiryUtc, 126)
                      , N'","idleExpiryUtc":"',    CONVERT (NVARCHAR (30), @IdleExpiryUtc, 126)
                      , N'","lifetimeMinutes":', @LifetimeMinutes
                      , N',"idleMinutes":', @IdleMinutes, N'}'));

        SET @Comments = CONCAT (N'Session ', @UserSessionId, N' issued to user ', @UserId, N' (', @AccountUserName
                              , N') from federated exchange ', @LoginAttemptId, N'. ', @PolicySource
                              , N'. Lifetime ', @LifetimeMinutes, N'm, idle ', @IdleMinutes, N'm.');

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

-- *** 7. auth.uspEndSession ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspEndSession
Author:       rsincero
CreateDate:   2026-09-19
========================================================================================================================
Description:

Ends one session, or every live session belonging to one user.  Sets EndedUtc and EndReason, which 070_auth_session.sql
makes write-once, and records the act in logs.AuthenticationEvent.

Three ways to name what to end, exactly one per call:
  @SessionTokenHash -- the ordinary sign-out: the caller has the token, so it can hash it.
  @UserSessionId    -- an administrator revoking a session they can see in a report.
  @UserId           -- every live session that user holds: a password change, a deactivation, a suspected compromise.

========================================================================================================================
Notes:

ENDING A SESSION IS A WRITE, NOT A DELETE, and this is the only procedure that performs it.  The row stays: it is how
"who was signed in when this happened" is answered afterwards, and a deleted session row makes that question
unanswerable at exactly the moment somebody is asking it.

@UserId ENDS THEM ALL, AND THAT CASE IS THE REASON THIS PROCEDURE TAKES A REASON.  A password change that leaves the old
sessions alive has not changed anything for whoever already has one -- which is the entire point of changing a password
after a compromise.  The Phase 2 procedures do not change passwords (that is section 15.3, later), so nothing calls this
with 'PasswordChanged' yet; the parameter exists so that when something does, it does not have to invent a mechanism.

THE REASON VOCABULARY IS CLOSED HERE, BY A CHECK IN CODE, and is not a constraint on the table.  The column is a
VARCHAR (40) so that an operational script can write a reason nobody thought of during an incident; this procedure is the
supported path and it is strict, so ordinary use cannot silently invent a seventh reason that no report knows to group.

E-50114 IS RAISED WHEN NOTHING MATCHED, because Appendix B says it is -- "no such session, or it has already ended".
Worth noting for whoever writes the sign-out handler: a user who clicks sign out twice, or whose session has just idled
out, will produce it, and that is not a failure they should be shown.  Treat 50114 on a user-initiated sign-out as
success; it is an error number for administrators and for tests, not a message for a person.

NO EXPIRY SWEEP IS IMPLIED BY 'IdleExpired' OR 'AbsoluteExpired'.  An expired session is already unusable -- both expiry
columns are compared on read -- so nothing needs to run for expiry to take effect.  Those reasons exist for a housekeeping
job that tidies the rows so a live-session report is not full of sessions that ended by arithmetic, and whether that job
is worth having is a Phase 8 operational decision, not a correctness one.

========================================================================================================================
Example Usage and Performance:

declare @Ended int;
exec auth.uspEndSession @SessionTokenHash = 0x9F86..., @SessionsEnded = @Ended output;
exec auth.uspEndSession @UserId = 7, @EndReason = 'PasswordChanged', @SessionsEnded = @Ended output;

One seek on UX_auth_UserSession_TokenHash or IX_auth_UserSession_UserLive, and one narrow update.

========================================================================================================================
Modification History:

Date:		2026-09-19
Author:		rsincero
Ticket:		T-039
Description:
Created.  Phase 2.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspEndSession
      @SessionTokenHash VARBINARY (32) = NULL
    , @UserSessionId    BIGINT         = NULL
    , @UserId           INT            = NULL
    , @EndReason        VARCHAR (40)   = 'SignedOut'
    , @SessionsEnded    INT            = NULL OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspEndSession]')
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

    SET @KeyParameters = CONCAT (N'@SessionTokenHash=', CASE WHEN @SessionTokenHash IS NULL
                                                            THEN N'(null)' ELSE N'(supplied)' END
                               , N', @UserSessionId=', COALESCE (CAST (@UserSessionId AS NVARCHAR (20)), N'(null)')
                               , N', @UserId=', COALESCE (CAST (@UserId AS NVARCHAR (11)), N'(null)')
                               , N', @EndReason=', @EndReason);
    SET @ContextMessage = N'End one session or every live session for a user. EndedUtc is write-once (070).';

    -- The rows about to be ended, captured before the UPDATE, because after it they are no longer distinguishable from
    -- sessions that ended earlier -- and the event rows need one per session.
    DECLARE @Ended TABLE
    (
        UserSessionId  BIGINT         NOT NULL PRIMARY KEY,
        UserId         INT            NOT NULL,
        ApplicationId  INT                NULL,
        ClientAddress  NVARCHAR (45)      NULL,
        StartedUtc     DATETIME2 (3)  NOT NULL
    );

    DECLARE @Identifiers  INT           = 0
          , @IsRevocation BIT           = 0;

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

        SET @SessionsEnded = 0;

        SET @Identifiers = CASE WHEN @SessionTokenHash IS NULL THEN 0 ELSE 1 END
                         + CASE WHEN @UserSessionId    IS NULL THEN 0 ELSE 1 END
                         + CASE WHEN @UserId           IS NULL THEN 0 ELSE 1 END;

        IF @Identifiers <> 1
        BEGIN
            ;THROW 50100, N'Supply exactly one of @SessionTokenHash, @UserSessionId or @UserId. Two of them together is a caller that does not know which session it means, and ending the intersection or the union would both be guesses -- one of which ends more sessions than anybody asked for.', 1;
        END;

        IF @SessionTokenHash IS NOT NULL AND DATALENGTH (@SessionTokenHash) <> 32
        BEGIN
            ;THROW 50100, N'@SessionTokenHash must be exactly 32 bytes -- the SHA-256 of the session token. The token itself is never a parameter here (070_auth_session.sql).', 1;
        END;

        -- The closed vocabulary.  070_auth_session.sql documents these six and no more.
        IF @EndReason NOT IN ('SignedOut', 'IdleExpired', 'AbsoluteExpired', 'Revoked', 'PasswordChanged'
                            , 'UserDeactivated')
        BEGIN
            ;THROW 50100, N'@EndReason must be one of SignedOut, IdleExpired, AbsoluteExpired, Revoked, PasswordChanged or UserDeactivated. The column itself is a wider VARCHAR (40) so an incident script can write something nobody anticipated; this procedure is the supported path and is strict, so ordinary use cannot invent a seventh reason that no report knows how to group.', 1;
        END;

        SET @IsRevocation = CASE WHEN @EndReason IN ('Revoked', 'PasswordChanged', 'UserDeactivated')
                                 THEN 1 ELSE 0 END;

        -- One UPDATE for all three routes.  EndedUtc IS NULL is what makes it idempotent: a session already ended is
        -- not re-ended onto a later timestamp, and the trigger would refuse it anyway (write-once).
        UPDATE s
           SET s.EndedUtc        = @Now
             , s.EndReason       = @EndReason
             , s.auditModifiedBy = @Actor
          OUTPUT inserted.UserSessionId, inserted.UserId, inserted.ApplicationId, inserted.ClientAddress
               , inserted.StartedUtc
            INTO @Ended (UserSessionId, UserId, ApplicationId, ClientAddress, StartedUtc)
          FROM auth.UserSession AS s
         WHERE s.EndedUtc  IS NULL
           AND s.IsDeleted = 0
           AND ((@SessionTokenHash IS NOT NULL AND s.SessionTokenHash = @SessionTokenHash)
             OR (@UserSessionId    IS NOT NULL AND s.UserSessionId    = @UserSessionId)
             OR (@UserId           IS NOT NULL AND s.UserId           = @UserId));

        SET @SessionsEnded = (SELECT COUNT (*) FROM @Ended);

        IF @SessionsEnded = 0
        BEGIN
            ;THROW 50114, N'No live session matched, so nothing was ended: it does not exist, it has already ended, or the user holds none. Appendix B defines this number as an error, and it is one for an administrator or a test -- but a person clicking sign out twice will produce it too, so a sign-out handler should treat it as success rather than showing it.', 1;
        END;

        -- One event per session ended.  'SessionRevoked' when somebody else ended it, 'SessionEnded' when it ran out or
        -- the holder signed out -- the distinction a security review asks for first and cannot reconstruct afterwards.
        INSERT logs.AuthenticationEvent
            (EventUtc, EventType, EventSeverity, ApplicationId, UserId, UserSessionId
           , UserName, ClientAddress, Actor, DetailJson)
        SELECT @Now
             , CASE WHEN @IsRevocation = 1 THEN 'SessionRevoked' ELSE 'SessionEnded' END
             , CASE WHEN @IsRevocation = 1 THEN 'Warning'        ELSE 'Info'         END
             , e.ApplicationId
             , e.UserId
             , e.UserSessionId
             , u.UserName
             , e.ClientAddress
             , @Actor
             , CONCAT (N'{"endReason":"', @EndReason
                     , N'","liveForSeconds":', DATEDIFF_BIG (SECOND, e.StartedUtc, @Now)
                     , N',"endedInThisCall":', @SessionsEnded, N'}')
          FROM @Ended        AS e
          JOIN auth.[User]   AS u ON u.UserId = e.UserId;

        SET @Comments = CONCAT (N'Ended ', @SessionsEnded, N' session(s) with reason ', @EndReason
                              , N', identified by '
                              , CASE WHEN @SessionTokenHash IS NOT NULL THEN N'token hash'
                                     WHEN @UserSessionId    IS NOT NULL THEN N'session id'
                                     ELSE N'user id ' + CAST (@UserId AS NVARCHAR (11)) END, N'.');

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


-- *** 8. auth.uspSetPassword ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspSetPassword
Author:       rsincero
CreateDate:   2026-09-21
========================================================================================================================
Description:

The administrative reset.  Replaces a user's local password verifier with one the APPLICATION computed, retires the old
one into auth.PasswordHistory, and forces MustChangePassword = 1 so the person it belongs to must replace it at the next
sign-in.  Demands User.ResetCredential.  Section 16.2.  G-42.

========================================================================================================================
Requirements and Key Dependencies:

auth.[User], auth.UserCredential, auth.PasswordHistory, config.ApplicationSetting (Authn.PasswordLifetimeDays),
auth.uspSetSessionContext, auth.uspDemandPermission, logs.AuthenticationEvent, logs.uspStartExecutionLogging,
logs.uspRecordExecutionError.  Granted to applicationRole.

========================================================================================================================
Notes:

IT NEVER SEES A PASSWORD, EXACTLY AS SIGN-IN NEVER DOES.  D-08.  @NewVerifierPhc is a finished PHC string -- algorithm,
parameters, salt and hash -- computed by the application from a value this database is never told.  There is no
@Password parameter, there is no hashing here, and CK_auth_UserCredential_VerifierPhc refuses a bare hex digest pasted
into the column by a migration that thought otherwise.  The verifier is not written to @KeyParameters, to @Comments, to
DetailJson or to any report row: UI-16.

MustChangePassword = 1 IS THE POINT OF THE PROCEDURE AND NOT A COURTESY.  Whoever runs a reset knows the value they
just set, and that is one person too many -- the same argument 900_bootstrap_first_admin.sql makes about the first
administrator.  The flag lives on auth.[User] rather than as an expiry on the credential because an expiry would forbid
the very sign-in that performs the change.

THE OLD VERIFIER IS RETIRED, NOT OVERWRITTEN.  The current string is copied into auth.PasswordHistory before the UPDATE,
which is what gives auth.uspChangePassword something to refuse a reuse against (E-50222).  A reset that discarded it
would make the history depth mean "the last N passwords you chose yourself", which is not what a policy says.

A USER WITH NO CREDENTIAL GETS ONE.  A federated-only person being given local access is the same operation as a reset
from the database's point of view, and refusing it would leave the only route to a first password as a hand-written
INSERT.  The event trail distinguishes the two cases: 'CredentialCreated' where there was nothing, 'PasswordReset' where
there was.

IT DOES NOT END THE USER'S SESSIONS, AND THAT IS AN OBLIGATION ON THE CALLER
A reset performed because an account was compromised leaves the attacker's live session working.  The fix is one further
call -- auth.uspEndSession @UserId = <the user>, @EndReason = 'PasswordChanged' -- and it is deliberately NOT made from
inside here: uspEndSession raises E-50114 when the user holds no live session, and an inner procedure's CATCH rolls back
the OUTERMOST transaction, so a revocation that failed for the most ordinary reason imaginable would silently undo the
password change it was protecting.  Section 16.2 states the two calls in order; the register records the obligation.

IT DOES NOT CLEAR IsLockedOut EITHER.  130_auth_user_procedures.sql makes the same argument about User.Update, and it
holds here: a permission holder who could clear a lockout by hand would be able to undo the throttle section 7.4 exists
to impose.  A reset on a locked-out account
succeeds, and the account stays locked until the window passes.

ExpiresUtc IS SET FROM Authn.PasswordLifetimeDays, WHICH SHIPS AS 0 AND THEREFORE SETS NOTHING.  Where a deployment has
raised it, the new credential gets an expiry and auth.uspExpireCredentials (G-12) is what acts on it.  Nothing in the
sign-in path reads ExpiresUtc, by design: expiry that refuses a sign-in locks people out, expiry that forces a change
does not.

WHY THE TRAIL IS logs.AuthenticationEvent AND NOT logs.DataChangeLog.  130_auth_user_procedures.sql writes its business
audit through logs.uspRecordDataChange, and a credential is the one thing that must not go there: that trail carries a
ChangedColumnsJson, and a column-level trail of auth.UserCredential is a table of verifier strings.  Section 15.5's
authentication trail carries the event and no verifier, which is the whole distinction, and it is why the password
procedures live in this file rather than beside the other writers of auth.[User] -- see the file header.

ERROR NUMBERS THIS ADDS: E-50220 (the verifier is missing or is not a PHC string) and E-50152 (no such live user, the
same number and the same reasoning as auth.uspGetUser).

========================================================================================================================
Example Usage and Performance:

declare @Sid varbinary (32) = 0x9F86..., @Revoked int;

exec auth.uspSetPassword @SessionTokenHash = @Sid
                       , @UserId           = 42
                       , @NewVerifierPhc   = N'$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$<hash>'
                       , @Reason           = N'Service desk ticket 88191, identity confirmed by callback.';

-- The second half of a compromise response, and it is a SEPARATE call. See the notes.
exec auth.uspEndSession @UserId = 42, @EndReason = 'PasswordChanged', @SessionsEnded = @Revoked output;

One seek per table.  The history INSERT and the credential UPDATE are one row each.

========================================================================================================================
Modification History:

Date:		2026-09-21
Author:		rsincero
Ticket:		T-112
Description:
Created.  Closes G-42, which had blocked production go-live: the design named a password lifecycle in section 16.2 and
the database had no procedure that could change a password at all.  Every deployment's answer was a hand-written UPDATE
against auth.UserCredential, with no history row, no trail row and no forced change.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspSetPassword
      @SessionTokenHash VARBINARY (32)
    , @UserId           INT
    , @NewVerifierPhc   NVARCHAR (512)
    , @Reason           NVARCHAR (400) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspSetPassword]')
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

    DECLARE @Actor          NVARCHAR (255)  = NULL
          , @ActorProfileId INT             = NULL
          , @ActingTenantId INT             = NULL
          , @Now            DATETIME2 (3)   = SYSUTCDATETIME ()
          , @UserName       NVARCHAR (256)  = NULL
          , @CredentialId   INT             = NULL
          , @OldVerifier    NVARCHAR (512)  = NULL
          , @LifetimeDays   INT             = NULL
          , @ExpiresUtc     DATETIME2 (3)   = NULL
          , @Created        BIT             = 0
          , @Failure        NVARCHAR (2000) = NULL;

    -- Identifiers and counts. @NewVerifierPhc is a credential and appears nowhere -- not here, not in @Comments, not in
    -- DetailJson (UI-16). @Reason is an administrator's own sentence about a ticket, which is why its LENGTH is logged
    -- and its text is not: it is free entry, and free entry is where a password ends up pasted by accident.
    SET @KeyParameters = CONCAT (N'UserId=', @UserId
                               , N', VerifierSupplied=', CASE WHEN @NewVerifierPhc IS NULL THEN N'0' ELSE N'1' END
                               , N', ReasonChars=', COALESCE (CAST (LEN (@Reason) AS NVARCHAR (11)), N'0'));
    SET @ContextMessage = N'Administrative password reset. The verifier is computed by the application (D-08) and is '
                        + N'never logged. Section 16.2, G-42.';

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

        -- Section 14.1: establish context here and trust no previous call. UI-05.
        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        SET @ActorProfileId = TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT);
        SET @ActingTenantId = TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT);

        -- At the ACTOR'S OWN tenant, for the reason the file header gives: a user has no tenant to demand it at.
        EXEC auth.uspDemandPermission @PermissionCode = N'User.ResetCredential', @TenantId = @ActingTenantId;

        SET @Actor = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N''), ORIGINAL_LOGIN ());

        SET @NewVerifierPhc = NULLIF (LTRIM (RTRIM (@NewVerifierPhc)), N'');
        SET @Reason         = NULLIF (LTRIM (RTRIM (@Reason)),         N'');

        -- The same shape CK_auth_UserCredential_VerifierPhc enforces, tested here so the caller gets a number to
        -- branch on and a sentence to read rather than constraint error 547 naming a column.
        IF @NewVerifierPhc IS NULL
           OR LEN (@NewVerifierPhc) < 16
           OR @NewVerifierPhc NOT LIKE N'$%$%'
        BEGIN
            SET @Failure = N'@NewVerifierPhc must be a PHC string the application computed -- it starts with $, names '
                         + N'its algorithm, and carries its own salt and hash (for example '
                         + N'$argon2id$v=19$m=...$<salt>$<hash>). A bare hex digest, a plaintext password or a blank '
                         + N'string is refused: this database never receives a password and cannot hash one (D-08). '
                         + N'Nothing was changed.';
            ;THROW 50220, @Failure, 1;
        END;

        SELECT @UserName = u.UserName
          FROM auth.[User] AS u
         WHERE u.UserId    = @UserId
           AND u.IsDeleted = 0;

        IF @UserName IS NULL
        BEGIN
            SET @Failure = N'No live user has that UserId. A deactivated user still has one -- this is the soft-delete '
                         + N'test, not the IsActive test -- so a row that is gone is gone. Nothing was changed.';
            ;THROW 50152, @Failure, 1;
        END;

        -- 0 is the shipped value and means "passwords do not expire", so ExpiresUtc stays NULL and
        -- CK_auth_UserCredential_ExpiresUtc is never asked to compare it with anything.
        SET @LifetimeDays = TRY_CAST ((SELECT s.SettingValue
                                         FROM config.ApplicationSetting AS s
                                        WHERE s.SettingKey = N'Authn.PasswordLifetimeDays'
                                          AND s.IsDeleted  = 0) AS INT);

        SET @ExpiresUtc = CASE WHEN COALESCE (@LifetimeDays, 0) > 0
                               THEN DATEADD (DAY, @LifetimeDays, @Now) END;

        SELECT @CredentialId = c.UserCredentialId
             , @OldVerifier  = c.VerifierPhc
          FROM auth.UserCredential AS c
         WHERE c.UserId         = @UserId
           AND c.CredentialType = 'Password'
           AND c.IsDeleted      = 0;

        IF @CredentialId IS NULL
        BEGIN
            INSERT auth.UserCredential (UserId, CredentialType, VerifierPhc, LastChangedUtc, ExpiresUtc
                                      , auditCreatedBy, auditModifiedBy)
            VALUES (@UserId, 'Password', @NewVerifierPhc, @Now, @ExpiresUtc, @Actor, @Actor);

            SET @CredentialId = CAST (SCOPE_IDENTITY () AS INT);
            SET @Created      = 1;
        END
        ELSE
        BEGIN
            -- Retired BEFORE the overwrite, because after it the old string is unrecoverable and the reuse check has
            -- nothing to compare against.
            INSERT auth.PasswordHistory (UserId, VerifierPhc, RetiredUtc, auditCreatedBy, auditModifiedBy)
            VALUES (@UserId, @OldVerifier, @Now, @Actor, @Actor);

            UPDATE c
               SET c.VerifierPhc          = @NewVerifierPhc
                 , c.LastChangedUtc       = @Now
                 , c.ExpiresUtc           = @ExpiresUtc
                 , c.auditModifiedBy      = @Actor
                 , c.auditModifiedDateUtc = @Now
              FROM auth.UserCredential AS c
             WHERE c.UserCredentialId = @CredentialId;
        END;

        UPDATE u
           SET u.MustChangePassword   = 1
             , u.auditModifiedBy      = @Actor
             , u.auditModifiedDateUtc = @Now
          FROM auth.[User] AS u
         WHERE u.UserId = @UserId;

        -- 'Warning', not 'Info': somebody other than the account holder replaced the means of proving who they are, and
        -- that is a row a review should stop on. The reason text is NOT carried into DetailJson -- see @KeyParameters.
        INSERT logs.AuthenticationEvent
            (EventUtc, EventType, EventSeverity, UserId, UserName, Actor, DetailJson)
        VALUES (@Now
              , CASE WHEN @Created = 1 THEN 'CredentialCreated' ELSE 'PasswordReset' END
              , 'Warning'
              , @UserId, @UserName, @Actor
              , CONCAT (N'{"userCredentialId":', @CredentialId
                      , N',"credentialCreated":', CASE WHEN @Created = 1 THEN N'true' ELSE N'false' END
                      , N',"mustChangePassword":true'
                      , N',"expiresUtc":', CASE WHEN @ExpiresUtc IS NULL THEN N'null'
                                                ELSE CONCAT (N'"', CONVERT (NVARCHAR (30), @ExpiresUtc, 127), N'"') END
                      , N',"reasonChars":', COALESCE (CAST (LEN (@Reason) AS NVARCHAR (11)), N'0')
                      , N',"actorUserProfileId":', COALESCE (CAST (@ActorProfileId AS NVARCHAR (11)), N'null')
                      , N'}'));

        SET @Comments = CONCAT (N'Reset the password of UserId=', @UserId, N'. Credential '
                              , CASE WHEN @Created = 1 THEN N'created' ELSE N'replaced and the old verifier retired '
                                                          + N'into auth.PasswordHistory' END
                              , N'. MustChangePassword=1. ExpiresUtc='
                              , COALESCE (CONVERT (NVARCHAR (30), @ExpiresUtc, 127), N'(none -- '
                                        + N'Authn.PasswordLifetimeDays is 0)')
                              , N'. Live sessions were NOT ended: call auth.uspEndSession @UserId = ', @UserId
                              , N', @EndReason = ''PasswordChanged'' if this reset is a compromise response.');

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


-- *** 9. auth.uspGetPasswordChangeContext ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspGetPasswordChangeContext
Author:       rsincero
CreateDate:   2026-09-21
========================================================================================================================
Description:

What the application needs in order to change the SESSION'S OWN password: the policy numbers, and the verifier strings
the new password must not match.  Two result sets, no permission, no parameter naming a user.  Section 16.2.  G-42.

========================================================================================================================
Requirements and Key Dependencies:

auth.[User], auth.UserCredential, auth.PasswordHistory, config.ApplicationSetting (Authn.PasswordHistoryDepth,
Authn.PasswordLifetimeDays, Authn.PasswordExpiryWarningDays), auth.uspSetSessionContext,
logs.uspRecordExecutionError.  Granted to applicationRole.

========================================================================================================================
Notes:

IT EXISTS BECAUSE THE DATABASE CANNOT CHECK REUSE BY ITSELF, AND PRETENDING OTHERWISE WOULD BE THE WORSE DESIGN.  Every
PHC string carries its own random salt, so the same password hashed twice produces two different strings: comparing a new
verifier with a stored one proves nothing at all.  Only the side holding the plaintext can test a candidate against a
stored hash, and that side is the application (D-08).  So the database hands over the strings to test and takes the
answer back as a bit -- which is exactly how sign-in already works, where auth.uspGetLoginVerifier hands over the current
verifier and auth.uspCompleteLogin takes @PasswordVerified.

THERE IS NO @UserId PARAMETER AND THERE MUST NOT BE ONE.  The session decides whose verifiers these are.  A parameter
would make this procedure a way for any application login to read any user's stored hashes, and no permission check would
make that a good idea -- the narrowest possible contract is the security here.  auth.uspGetLoginVerifier is keyed by user
name because sign-in has no session yet; this has one, so it uses it.

THE CURRENT VERIFIER IS ALWAYS IN THE SECOND RESULT SET AND IS NOT COUNTED BY THE DEPTH.  Authn.PasswordHistoryDepth
counts RETIRED verifiers; "may I set my password to the one I am already using" is not a question about history, and the
answer is no whatever the depth says.  Depth 0 therefore still returns one row.

RESULT SET ONE IS ALWAYS EXACTLY ONE ROW, so QuerySingle is safe (UI-04).  HasLiveCredential = 0 is the federated-only
case: there is nothing to change, and auth.uspChangePassword will refuse with E-50223.

ERROR-ONLY INSTRUMENTED, like every read.

WHAT IT DOES NOT DO: it does not prove the old password, it does not reserve anything, and its answer goes stale the
moment another session changes the same credential.  The refusals are auth.uspChangePassword's, which re-reads
everything inside its own transaction.

========================================================================================================================
Example Usage and Performance:

exec auth.uspGetPasswordChangeContext @SessionTokenHash = 0x9F86...;

-- Result set 1: UserId, UserName, HasLiveCredential, MustChangePassword, PasswordLastChangedUtc, PasswordExpiresUtc,
--               DaysUntilExpiry, HistoryDepth, LifetimeDays, WarningDays.
-- Result set 2: IsCurrent, VerifierPhc, RetiredUtc -- the current verifier first, then the newest HistoryDepth retired
--               ones. Test the candidate password against every row; if any verifies, do not call uspChangePassword
--               with @NewVerifierReusesHistory = 0.

Two seeks and a TOP (n) read of IX_auth_PasswordHistory_UserRetired.  n is a policy depth, so single digits.

========================================================================================================================
Modification History:

Date:		2026-09-21
Author:		rsincero
Ticket:		T-112
Description:
Created.  G-42.  Without it E-50222 could not be raised honestly by anything: the reuse decision belongs to the side
that holds the plaintext, and that side had no way to obtain the strings to test.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspGetPasswordChangeContext
      @SessionTokenHash VARBINARY (32)
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation, READ variant: error-only. No start row is opened.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspGetPasswordChangeContext]')
          , @KeyParameters  NVARCHAR (MAX) = NULL
          , @ContextMessage NVARCHAR (MAX) = NULL
          , @DynamicSql     NVARCHAR (MAX) = NULL
          , @ErrorMsg       NVARCHAR (MAX) = NULL
          , @ErrorProc      NVARCHAR (300) = NULL
          , @ErrorNumber    INT            = NULL
          , @ErrorLine      INT            = NULL;

    DECLARE @UserId       INT           = NULL
          , @Now          DATETIME2 (3) = SYSUTCDATETIME ()
          , @HistoryDepth INT           = NULL
          , @LifetimeDays INT           = NULL
          , @WarningDays  INT           = NULL;

    SET @KeyParameters  = N'SessionTokenHash=(32 bytes, not logged)';
    SET @ContextMessage = N'Self-service password change context. Hands the application the verifier strings to test a '
                        + N'candidate password against; no verifier is ever logged. G-42.';

    BEGIN TRY

        -- =========================================================================================
        -- ===== The procedure's own work starts here. Everything above and below is boilerplate. ==
        -- =========================================================================================

        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        SET @UserId = TRY_CAST (SESSION_CONTEXT (N'UserId') AS INT);

        SET @HistoryDepth = COALESCE (TRY_CAST ((SELECT s.SettingValue
                                                   FROM config.ApplicationSetting AS s
                                                  WHERE s.SettingKey = N'Authn.PasswordHistoryDepth'
                                                    AND s.IsDeleted  = 0) AS INT), 0);

        SET @LifetimeDays = COALESCE (TRY_CAST ((SELECT s.SettingValue
                                                   FROM config.ApplicationSetting AS s
                                                  WHERE s.SettingKey = N'Authn.PasswordLifetimeDays'
                                                    AND s.IsDeleted  = 0) AS INT), 0);

        SET @WarningDays  = COALESCE (TRY_CAST ((SELECT s.SettingValue
                                                   FROM config.ApplicationSetting AS s
                                                  WHERE s.SettingKey = N'Authn.PasswordExpiryWarningDays'
                                                    AND s.IsDeleted  = 0) AS INT), 0);

        -- One row always. LEFT JOIN because a federated-only user has no credential and still deserves an answer --
        -- an empty result set would be indistinguishable from an ended session, which is an error and not a state.
        SELECT UserId                 = u.UserId
             , UserName               = u.UserName
             , HasLiveCredential      = CAST (CASE WHEN c.UserCredentialId IS NULL THEN 0 ELSE 1 END AS BIT)
             , MustChangePassword     = u.MustChangePassword
             , PasswordLastChangedUtc = c.LastChangedUtc
             , PasswordExpiresUtc     = c.ExpiresUtc
             , DaysUntilExpiry        = CASE WHEN c.ExpiresUtc IS NULL THEN NULL
                                             ELSE DATEDIFF (DAY, @Now, c.ExpiresUtc) END
             , HistoryDepth           = @HistoryDepth
             , LifetimeDays           = @LifetimeDays
             , WarningDays            = @WarningDays
          FROM auth.[User] AS u
          LEFT JOIN auth.UserCredential AS c
                 ON c.UserId         = u.UserId
                AND c.CredentialType = 'Password'
                AND c.IsDeleted      = 0
         WHERE u.UserId    = @UserId
           AND u.IsDeleted = 0;

        -- The strings to test, current one first. The UNION ALL rather than a single query over two tables is
        -- deliberate: TOP applies to the retired half only, and the current verifier is not subject to the depth.
        SELECT IsCurrent   = CAST (1 AS BIT)
             , x.VerifierPhc
             , RetiredUtc  = CAST (NULL AS DATETIME2 (3))
          FROM (SELECT c.VerifierPhc
                  FROM auth.UserCredential AS c
                 WHERE c.UserId         = @UserId
                   AND c.CredentialType = 'Password'
                   AND c.IsDeleted      = 0) AS x

        UNION ALL

        SELECT IsCurrent = CAST (0 AS BIT)
             , h.VerifierPhc
             , h.RetiredUtc
          FROM (SELECT TOP (@HistoryDepth) ph.VerifierPhc, ph.RetiredUtc
                  FROM auth.PasswordHistory AS ph
                 WHERE ph.UserId    = @UserId
                   AND ph.IsDeleted = 0
                 ORDER BY ph.RetiredUtc DESC, ph.PasswordHistoryId DESC) AS h
         ORDER BY IsCurrent DESC, RetiredUtc DESC;

        -- =========================================================================================
        -- ===== End of the procedure's own work. ===================================================
        -- =========================================================================================

    END TRY
    BEGIN CATCH

        SELECT @ErrorNumber = ERROR_NUMBER ()
             , @ErrorProc   = ERROR_PROCEDURE ()
             , @ErrorLine   = ERROR_LINE ()
             , @ErrorMsg    = ERROR_MESSAGE ()
                            + N' (error '  + CAST (ERROR_NUMBER () AS NVARCHAR (11))
                            + N', line '   + CAST (ERROR_LINE ()   AS NVARCHAR (11)) + N')';

        EXEC logs.uspRecordExecutionError
              @ProcedureName   = @ProcName
            , @KeyParameters   = @KeyParameters
            , @ExecutionLogId  = NULL
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


-- *** 10. auth.uspChangePassword ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspChangePassword
Author:       rsincero
CreateDate:   2026-09-21
========================================================================================================================
Description:

The self-service change.  The session says who, the application says the current password was proved and the new one is
not a reused one, and this procedure retires the old verifier into auth.PasswordHistory, installs the new one and clears
MustChangePassword.  Section 16.2.  G-42.

========================================================================================================================
Requirements and Key Dependencies:

auth.[User], auth.UserCredential, auth.PasswordHistory, config.ApplicationSetting (Authn.PasswordLifetimeDays),
auth.uspSetSessionContext, auth.uspGetPasswordChangeContext (the caller's previous step),
logs.AuthenticationEvent, logs.uspStartExecutionLogging, logs.uspRecordExecutionError.  Granted to applicationRole.

========================================================================================================================
Notes:

@CurrentPasswordVerified IS THE SAME CONTRACT AS auth.uspCompleteLogin's @PasswordVerified, AND FOR THE SAME REASON.
D-08: the application holds the plaintext and the hashing library, this database holds neither, so the verification
happens there and arrives here as a bit.  Passing 0 is refused with E-50221 rather than ignored, so a caller that has
not checked cannot change a password by leaving the parameter out -- there is no default.

WHAT THAT BIT IS AND IS NOT WORTH.  It is worth exactly as much as the application login that sent it, which is why the
credential tables are denied to readOnlyRole (170) and why every one of these procedures is reached through EXECUTE and
never through table access. A compromised application login can change any password it holds a session for; that is
true of sign-in as well, and the answer is the same in both places -- the session, the trail row, and the fact that
nothing here can be reached without both.

E-50222 IS RAISED ON THE APPLICATION'S ANSWER, NOT ON A COMPARISON DONE HERE.  Salted hashes cannot be compared;
auth.uspGetPasswordChangeContext's header explains it at length.  @NewVerifierReusesHistory defaults to 0 -- "no reuse"
-- because a caller that never asks is the caller that ships first, and a default of 1 would refuse every change.  That
is a stated weakness of the control: the reuse check is only as real as the caller's diligence, and section 16.2 puts
the obligation in writing.  Authn.PasswordHistoryDepth = 0 turns it off entirely and is checked here, so passing 1 with
a depth of 0 is accepted rather than refused -- a deployment that does not keep history cannot have a reuse policy.

IT DOES NOT COMPARE THE NEW VERIFIER WITH THE OLD ONE EITHER, for the same reason -- a new PHC string of the SAME
password differs from the stored one in every character after the algorithm name.

IT CLEARS MustChangePassword, WHICH IS THE WHOLE POINT OF THE FORCED-CHANGE FLOW.  Sign in with the flag set, change the
password, the flag goes.  auth.uspSetPassword sets it; this is the only thing in the database that clears it, which is
why there is no "administrator clears the flag" procedure: clearing it without a change would mean the reset value stays
in use, and that value is known to whoever performed the reset.

IT DOES NOT END THE SESSION IT WAS CALLED ON.  A change performed by the account holder is not a compromise response,
and signing somebody out of the page they just used is a cost with no security gain here -- the session was already
proved before the change. Where a deployment wants the stricter behaviour, auth.uspEndSession @UserId = <the user> is
one call away and section 16.2 says so; it is not made here for the transaction reason auth.uspSetPassword's notes give.

ERROR NUMBERS THIS ADDS: E-50220 (the new verifier is missing or is not a PHC string), E-50221 (called without the
current password proved), E-50222 (the application reported the new password as a reused one), E-50223 (there is no
live password credential to change -- a federated-only account, and the route is auth.uspSetPassword).

========================================================================================================================
Example Usage and Performance:

-- Step 1, done first: read the policy and the strings to test.
exec auth.uspGetPasswordChangeContext @SessionTokenHash = 0x9F86...;

-- Step 2: the application verified the old password and tested the new one against every row it was handed.
exec auth.uspChangePassword @SessionTokenHash         = 0x9F86...
                          , @CurrentPasswordVerified  = 1
                          , @NewVerifierPhc           = N'$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$<hash>'
                          , @NewVerifierReusesHistory = 0;

One seek per table and two single-row writes.

========================================================================================================================
Modification History:

Date:		2026-09-21
Author:		rsincero
Ticket:		T-112
Description:
Created.  G-42, with auth.uspSetPassword and auth.uspGetPasswordChangeContext.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspChangePassword
      @SessionTokenHash         VARBINARY (32)
    , @CurrentPasswordVerified  BIT
    , @NewVerifierPhc           NVARCHAR (512)
    , @NewVerifierReusesHistory BIT = 0
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspChangePassword]')
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

    DECLARE @Actor          NVARCHAR (255)  = NULL
          , @UserId         INT             = NULL
          , @UserSessionId  BIGINT          = NULL
          , @UserName       NVARCHAR (256)  = NULL
          , @Now            DATETIME2 (3)   = SYSUTCDATETIME ()
          , @CredentialId   INT             = NULL
          , @OldVerifier    NVARCHAR (512)  = NULL
          , @HistoryDepth   INT             = NULL
          , @LifetimeDays   INT             = NULL
          , @ExpiresUtc     DATETIME2 (3)   = NULL
          , @HistoryRows    INT             = 0
          , @Failure        NVARCHAR (2000) = NULL;

    -- Two bits and no strings. The verifier is a credential (UI-16); the bits are the two decisions the application
    -- made, and a trail that cannot tell "verified" from "not checked" is a trail that cannot explain E-50221.
    SET @KeyParameters = CONCAT (N'CurrentPasswordVerified=', @CurrentPasswordVerified
                               , N', NewVerifierReusesHistory=', @NewVerifierReusesHistory
                               , N', VerifierSupplied=', CASE WHEN @NewVerifierPhc IS NULL THEN N'0' ELSE N'1' END);
    SET @ContextMessage = N'Self-service password change. The old-password proof and the reuse test are the '
                        + N'application''s, exactly as at sign-in (D-08). Section 16.2, G-42.';

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

        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        SET @UserId = TRY_CAST (SESSION_CONTEXT (N'UserId') AS INT);
        SET @Actor  = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N''), ORIGINAL_LOGIN ());

        -- No permission is demanded and no target is named: the session IS the authorization, and the only password
        -- this procedure can reach is the one belonging to the user the session was issued to.
        SELECT @UserName = u.UserName
          FROM auth.[User] AS u
         WHERE u.UserId    = @UserId
           AND u.IsDeleted = 0;

        SET @NewVerifierPhc = NULLIF (LTRIM (RTRIM (@NewVerifierPhc)), N'');

        IF @NewVerifierPhc IS NULL
           OR LEN (@NewVerifierPhc) < 16
           OR @NewVerifierPhc NOT LIKE N'$%$%'
        BEGIN
            SET @Failure = N'@NewVerifierPhc must be a PHC string the application computed -- it starts with $, names '
                         + N'its algorithm, and carries its own salt and hash. This database never receives a password '
                         + N'and cannot hash one (D-08). Nothing was changed.';
            ;THROW 50220, @Failure, 1;
        END;

        -- Refused, not ignored. A caller that has not proved the current password is a caller that does not know
        -- whether the person at the keyboard is the account holder, and "change my password" without that proof is
        -- the whole of account takeover in one call.
        IF @CurrentPasswordVerified <> 1
        BEGIN
            SET @Failure = N'@CurrentPasswordVerified must be 1. The current password has to be proved by the '
                         + N'application before the new one is installed -- the same contract auth.uspCompleteLogin''s '
                         + N'@PasswordVerified carries, and for the same reason: this database never sees a password '
                         + N'and cannot check one itself. An administrative reset that does not need the old password '
                         + N'is auth.uspSetPassword, which demands User.ResetCredential. Nothing was changed.';
            ;THROW 50221, @Failure, 1;
        END;

        SET @HistoryDepth = COALESCE (TRY_CAST ((SELECT s.SettingValue
                                                   FROM config.ApplicationSetting AS s
                                                  WHERE s.SettingKey = N'Authn.PasswordHistoryDepth'
                                                    AND s.IsDeleted  = 0) AS INT), 0);

        -- The depth is consulted before the refusal because a deployment keeping no history cannot have a reuse
        -- policy, and refusing on a caller's report of a rule nobody configured would be a control nobody asked for.
        IF @NewVerifierReusesHistory = 1 AND @HistoryDepth > 0
        BEGIN
            SET @Failure = CONCAT (N'That password has been used before. Authn.PasswordHistoryDepth is '
                                 , @HistoryDepth, N', so the last ', @HistoryDepth, N' retired verifier(s) and the '
                                 , N'current one are all refused. The comparison is the application''s -- salted '
                                 , N'hashes cannot be compared by this database, so it asked and was told 1 '
                                 , N'(auth.uspGetPasswordChangeContext). Choose a different password. Nothing was '
                                 , N'changed.');
            ;THROW 50222, @Failure, 1;
        END;

        SELECT @CredentialId = c.UserCredentialId
             , @OldVerifier  = c.VerifierPhc
          FROM auth.UserCredential AS c
         WHERE c.UserId         = @UserId
           AND c.CredentialType = 'Password'
           AND c.IsDeleted      = 0;

        IF @CredentialId IS NULL
        BEGIN
            SET @Failure = N'There is no live password credential on this account, so there is nothing to change. A '
                         + N'federated-only user signs in through an identity provider and has no verifier here '
                         + N'(section 7.3). Giving the account a first password is an administrative act: '
                         + N'auth.uspSetPassword, which demands User.ResetCredential. Nothing was changed.';
            ;THROW 50223, @Failure, 1;
        END;

        SET @LifetimeDays = TRY_CAST ((SELECT s.SettingValue
                                         FROM config.ApplicationSetting AS s
                                        WHERE s.SettingKey = N'Authn.PasswordLifetimeDays'
                                          AND s.IsDeleted  = 0) AS INT);

        SET @ExpiresUtc = CASE WHEN COALESCE (@LifetimeDays, 0) > 0
                               THEN DATEADD (DAY, @LifetimeDays, @Now) END;

        INSERT auth.PasswordHistory (UserId, VerifierPhc, RetiredUtc, auditCreatedBy, auditModifiedBy)
        VALUES (@UserId, @OldVerifier, @Now, @Actor, @Actor);

        UPDATE c
           SET c.VerifierPhc          = @NewVerifierPhc
             , c.LastChangedUtc       = @Now
             , c.ExpiresUtc           = @ExpiresUtc
             , c.auditModifiedBy      = @Actor
             , c.auditModifiedDateUtc = @Now
          FROM auth.UserCredential AS c
         WHERE c.UserCredentialId = @CredentialId;

        -- Cleared here and nowhere else. See the notes.
        UPDATE u
           SET u.MustChangePassword   = 0
             , u.auditModifiedBy      = @Actor
             , u.auditModifiedDateUtc = @Now
          FROM auth.[User] AS u
         WHERE u.UserId = @UserId;

        SET @HistoryRows = (SELECT COUNT (*) FROM auth.PasswordHistory AS ph
                             WHERE ph.UserId = @UserId AND ph.IsDeleted = 0);

        -- Read from the table and not from SESSION_CONTEXT: auth.uspSetSessionContext publishes five keys and the
        -- session's own id is not one of them (UserId, AppUser, ApplicationId, UserProfileId, ActingTenantId). The
        -- trail row is worth stitching to the session anyway -- "which sign-in changed it" is the first question asked
        -- of a password change nobody remembers making -- so it is fetched by the hash the caller handed us.
        SELECT @UserSessionId = us.UserSessionId
          FROM auth.UserSession AS us
         WHERE us.SessionTokenHash = @SessionTokenHash
           AND us.IsDeleted        = 0;

        -- 'Info': the account holder changed their own password, which is the system working. The reset is the Warning.
        INSERT logs.AuthenticationEvent
            (EventUtc, EventType, EventSeverity, UserId, UserName, UserSessionId, Actor, DetailJson)
        VALUES (@Now, 'PasswordChanged', 'Info', @UserId, @UserName, @UserSessionId, @Actor
              , CONCAT (N'{"userCredentialId":', @CredentialId
                      , N',"historyRows":', @HistoryRows
                      , N',"historyDepth":', @HistoryDepth
                      , N',"reuseCheckedByCaller":'
                      , CASE WHEN @HistoryDepth > 0 THEN N'true' ELSE N'false' END
                      , N',"mustChangePasswordCleared":true'
                      , N',"expiresUtc":', CASE WHEN @ExpiresUtc IS NULL THEN N'null'
                                                ELSE CONCAT (N'"', CONVERT (NVARCHAR (30), @ExpiresUtc, 127), N'"') END
                      , N'}'));

        SET @Comments = CONCAT (N'Changed the password of UserId=', @UserId, N'. Old verifier retired; '
                              , @HistoryRows, N' history row(s) now held against a depth of ', @HistoryDepth
                              , N'. MustChangePassword cleared. ExpiresUtc='
                              , COALESCE (CONVERT (NVARCHAR (30), @ExpiresUtc, 127), N'(none)')
                              , N'. The session was not ended.');

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


-- *** 11. auth.uspExpireCredentials ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspExpireCredentials
Author:       rsincero
CreateDate:   2026-09-21
========================================================================================================================
Description:

The scheduled half of password expiry.  Sets MustChangePassword = 1 on every live active user whose password credential
has an ExpiresUtc in the past, one batch at a time, and records a 'CredentialExpired' event per user.  G-12, section
16.2.  Nothing calls it: it is a job.

========================================================================================================================
Requirements and Key Dependencies:

auth.[User], auth.UserCredential, logs.AuthenticationEvent, logs.uspStartExecutionLogging,
logs.uspRecordExecutionError.  GRANTED TO NOBODY -- see the notes.

========================================================================================================================
Notes:

IT IS THE ONLY THING THAT MAKES Authn.PasswordLifetimeDays MEAN ANYTHING.  Nothing in the sign-in path reads
auth.UserCredential.ExpiresUtc, and that is deliberate: a sign-in refused because a password aged out is a person locked
out of the only screen that could have fixed it.  Expiry therefore acts by setting the flag the forced-change flow
already honours -- the sign-in succeeds, MustChangePassword comes back 1, the application sends them to the change page.
Until this procedure is SCHEDULED, a deployment that raised Authn.PasswordLifetimeDays has an expiry policy that expires
nothing, which is why 025_config_tables.sql reports an ACTION row the moment the setting is non-zero.

NO SESSION, NO PERMISSION, AND NO GRANT.  It is run by SQL Server Agent, or by whatever scheduler a deployment uses, as
a principal that already holds db_owner -- so there is no session token to establish context from and nobody to demand a
permission of.  Granting EXECUTE to applicationRole would hand the application a way to force a password change on every
user in the database in one call, which is the kind of thing an application login should not be able to do even by
accident.  105_auth_session_procedures.sql makes the same argument about the maintenance pair and rlsBypassRole.

@BatchSize EXISTS SO THE JOB CANNOT TAKE THE DATABASE WITH IT.  One UPDATE over every expired credential in a large
deployment is one lock escalation away from blocking every sign-in, and the event rows are written in the same
transaction.  The job loops until @UsersFlagged comes back 0; @RemainingDue says how many are still waiting, so a
schedule can be judged rather than guessed.  Out of range is E-50224 rather than a silent clamp: a job configured with
0 would run forever doing nothing, and one configured with 10,000,000 has not been thought about.

RE-RUNNING IT IS FREE.  The predicate includes MustChangePassword = 0, so a user already flagged is not flagged again
and no second event row is written.  That also means the count in the transcript is "newly expired", which is the number
worth having.

IT IGNORES INACTIVE AND SOFT-DELETED USERS.  A deactivated account cannot sign in at all, so forcing a change on it
would write a trail row about an event that can never happen, and the report that counts expiries would overstate.

ERROR NUMBERS THIS ADDS: E-50224 (@BatchSize out of range).

========================================================================================================================
Example Usage and Performance:

declare @Flagged int, @Due int;

exec auth.uspExpireCredentials @BatchSize = 1000, @UsersFlagged = @Flagged output, @RemainingDue = @Due output;
-- Loop while @Flagged > 0. A job step is three lines and needs no cursor.

One seek of IX_auth_UserCredential_Expires -- filtered on the credentials that HAVE an expiry, which is none of them in
a default deployment -- then an UPDATE and an INSERT of at most @BatchSize rows each.

========================================================================================================================
Modification History:

Date:		2026-09-21
Author:		rsincero
Ticket:		T-112
Description:
Created.  G-12.  Authn.PasswordLifetimeDays and Authn.PasswordExpiryWarningDays were seeded by 025_config_tables.sql
with nothing in the database that read either of them; this is the half that acts, and auth.uspGetProfileContext is the
half that warns.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspExpireCredentials
      @BatchSize    INT = 1000
    , @UsersFlagged INT = NULL OUTPUT
    , @RemainingDue INT = NULL OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspExpireCredentials]')
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

    DECLARE @Now     DATETIME2 (3)   = SYSUTCDATETIME ()
          , @Actor   NVARCHAR (255)  = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                               , ORIGINAL_LOGIN ())
          , @Failure NVARCHAR (2000) = NULL;

    -- The rows flagged, captured by the UPDATE, because afterwards they are indistinguishable from users flagged by an
    -- administrative reset and the event rows need one per user.
    DECLARE @Flagged TABLE
    (
        UserId     INT            NOT NULL PRIMARY KEY,
        UserName   NVARCHAR (256) NOT NULL,
        ExpiresUtc DATETIME2 (3)  NOT NULL
    );

    SET @KeyParameters  = CONCAT (N'BatchSize=', @BatchSize);
    SET @ContextMessage = N'Scheduled password expiry (G-12). Sets MustChangePassword rather than refusing a sign-in: '
                        + N'nothing in the sign-in path reads ExpiresUtc, by design.';

    SET @UsersFlagged = 0;
    SET @RemainingDue = 0;

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

        IF @BatchSize IS NULL OR @BatchSize < 1 OR @BatchSize > 100000
        BEGIN
            SET @Failure = N'@BatchSize must be between 1 and 100000. It is the number of users flagged per call, and '
                         + N'the job loops until @UsersFlagged comes back 0. A batch of 0 would loop forever doing '
                         + N'nothing; a batch larger than this would hold locks on auth.[User] long enough to block '
                         + N'sign-in. Nothing was changed.';
            ;THROW 50224, @Failure, 1;
        END;

        -- The batch is chosen first and flagged second, both inside the one transaction, so the set cannot move
        -- between the two statements. Oldest expiry first: a batch that picked at random would leave the most overdue
        -- accounts for last on every run, which is the opposite of what a batched job is for.
        INSERT @Flagged (UserId, UserName, ExpiresUtc)
        SELECT TOP (@BatchSize) u.UserId, u.UserName, c.ExpiresUtc
          FROM auth.[User]              AS u
         INNER JOIN auth.UserCredential AS c
                 ON c.UserId         = u.UserId
                AND c.CredentialType = 'Password'
                AND c.IsDeleted      = 0
         WHERE u.IsDeleted          = 0
           AND u.IsActive           = 1
           AND u.MustChangePassword = 0
           AND c.ExpiresUtc         IS NOT NULL
           AND c.ExpiresUtc        <= @Now
         ORDER BY c.ExpiresUtc ASC, u.UserId ASC;

        UPDATE u
           SET u.MustChangePassword   = 1
             , u.auditModifiedBy      = @Actor
             , u.auditModifiedDateUtc = @Now
          FROM auth.[User] AS u
         INNER JOIN @Flagged AS f
                 ON f.UserId = u.UserId;

        SET @UsersFlagged = @@ROWCOUNT;

        IF @UsersFlagged > 0
        BEGIN
            -- 'CredentialExpired' and not 'CredentialRetired': the credential still verifies. 085_logs_auth_tables.sql
            -- says why the vocabulary grew a value rather than borrowing one.
            INSERT logs.AuthenticationEvent
                (EventUtc, EventType, EventSeverity, UserId, UserName, Actor, DetailJson)
            SELECT @Now, 'CredentialExpired', 'Info', f.UserId, f.UserName, @Actor
                 , CONCAT (N'{"expiresUtc":"', CONVERT (NVARCHAR (30), f.ExpiresUtc, 127)
                         , N'","daysOverdue":', DATEDIFF (DAY, f.ExpiresUtc, @Now)
                         , N',"mustChangePassword":true,"job":"auth.uspExpireCredentials"}')
              FROM @Flagged AS f;
        END;

        -- What a schedule is judged by: how many are still waiting after this batch.
        SELECT @RemainingDue = COUNT (*)
          FROM auth.[User]              AS u
         INNER JOIN auth.UserCredential AS c
                 ON c.UserId         = u.UserId
                AND c.CredentialType = 'Password'
                AND c.IsDeleted      = 0
         WHERE u.IsDeleted          = 0
           AND u.IsActive           = 1
           AND u.MustChangePassword = 0
           AND c.ExpiresUtc         IS NOT NULL
           AND c.ExpiresUtc        <= @Now;

        SET @Comments = CONCAT (N'Flagged ', @UsersFlagged, N' user(s) whose password expired on or before '
                              , CONVERT (NVARCHAR (30), @Now, 127), N'; ', @RemainingDue
                              , N' still due after this batch of ', @BatchSize
                              , N'. One CredentialExpired event per user flagged. Re-running is free: the predicate '
                              , N'excludes users already carrying the flag.');

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


-- *** 12. Descriptions ***
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

    -- Rows rather than eleven EXEC calls with concatenated arguments: an EXEC argument takes a constant or a variable
    -- and never an expression, so a '+' in the parameter position is a parse error (102), exactly as it is for THROW.
    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    VALUES
      (N'auth', N'PROCEDURE', N'uspGetLoginVerifier', NULL
     , N'Step 1 of the local password route: opens a sign-in exchange and returns the PHC verifier string for the '
     + N'application to compute against. D-08, sections 7.1 and 19.2. ALWAYS returns a verifier -- for a user name '
     + N'nobody holds it derives a dummy from Authn.DummyVerifierPepper and the submitted name, at the real field '
     + N'lengths, so that an unknown name costs the same work and yields the same shape as a wrong password. The dummy '
     + N'is derived rather than constant because a constant one lets a single probe identify every unknown name for '
     + N'free. DOES NOT check the account lockout: that is uspCompleteLogin''s job, after the credential has been '
     + N'verified, because refusing early is an enumeration oracle. Raises 50100, 50101, 50102, 50103, 50116.')
    , (N'auth', N'PROCEDURE', N'uspCompleteLogin', NULL
     , N'Step 2 of the local password route, and where every authentication rule is actually enforced. Section 7.1. '
     + N'Trusts the application for @PasswordVerified and @SessionTokenHash and for nothing else: the account comes off '
     + N'the exchange row, MfaSatisfied is read from it (only uspVerifyMfa writes it), and the policy, lockout and '
     + N'lifetimes are read from the tables. @IsBypassRoute is a request, not a permission -- INV-09 is checked against '
     + N'auth.User.IsPlatformAdmin and INV-08 against the exchange. Every refusal concludes the exchange through '
     + N'uspRecordLoginFailure, COMMITS, and only then raises, because the CATCH rolls back an open transaction and a '
     + N'refusal that rolls itself back is an unlimited number of guesses. Raises 50100, 50103, 50105, 50106, 50107, '
     + N'50108, 50109, 50115.')
    , (N'auth', N'PROCEDURE', N'uspRecordLoginFailure', NULL
     , N'Concludes an exchange as a failure and takes both failure counts independently. Section 7.4. The per-account '
     + N'count is keyed on UserName rather than UserId, so failures against a name nobody holds are counted too -- '
     + N'otherwise the count is itself an oracle. Crossing Authn.LockoutThreshold writes auth.User.IsLockedOut and a '
     + N'LockoutEndUtc; crossing Authn.AddressThreshold writes NOTHING, because the address verdict is recomputed '
     + N'wherever it is needed and an address that stops attacking stops being throttled with no sweep job. An '
     + N'already-locked account is NOT re-locked onto a later end time: extending the window on every further failure '
     + N'lets an attacker hold a victim''s account shut indefinitely for free. Concluding an already-concluded exchange '
     + N'is a no-op, not an error: a double-reported failure is a retry. Raises 50105.')
    , (N'auth', N'PROCEDURE', N'uspVerifyMfa', NULL
     , N'Satisfies the second factor for a pending exchange, by TOTP time step or by recovery code hash, and is the '
     + N'ONLY writer of auth.LoginAttempt.MfaSatisfied. Section 6.2. The engine cannot verify a TOTP code -- it holds '
     + N'the secret as ciphertext it has no key for -- so the application reports which step it verified at, and the '
     + N'step is then bounded against the SERVER clock (Authn.TotpWindowSteps) and against LastUsedTimeStep, so a '
     + N'shoulder-surfed code cannot be replayed inside its own window. Recovery codes arrive as SHA-256, never as '
     + N'text, for the same reason passwords do not (D-08), and are spent here rather than at uspCompleteLogin. EVERY '
     + N'FAILED ATTEMPT CONCLUDES THE EXCHANGE: a six-digit code has a million values and an exchange that survived a '
     + N'failed code would let the whole space be walked without either throttle seeing it. Raises 50100, 50105, '
     + N'50110, 50111, 50112.')
    , (N'auth', N'PROCEDURE', N'uspBeginSsoLogin', NULL
     , N'Step 1 of the federated route: checks the tenant permits federation, checks the issuer is one it trusts, and '
     + N'opens an exchange before the redirect. Section 7.3. @Issuer is resolved against auth.TenantTrustedIssuer by '
     + N'walking auth.TenantClosure upward to the NEAREST ancestor holding a list, which is then owned WHOLE -- gap G-21. '
     + N'A list nowhere above the tenant means NOT CONFIGURED and the issuer is not checked, so upgrading the template '
     + N'does not switch federation off where it already worked; 035''s closing report says ACTION on any deployment in '
     + N'that state. Once a list resolves it is strict both ways: an issuer off it and a call naming none are both '
     + N'E-50124. AllowFederated defaults to 0 when no policy row resolves, the opposite way from '
     + N'AllowLocalPassword, because federation needs a provider somebody configured whereas a password needs only a '
     + N'credential row. UserName is the login hint if the application had one and ''(sso pending)'' if not, and is '
     + N'never rewritten afterwards. Raises 50100, 50101, 50102, 50104, 50116, 50124.')
    , (N'auth', N'PROCEDURE', N'uspCompleteSsoLogin', NULL
     , N'Step 2 of the federated route: resolves the assertion to a local account through auth.UserFederatedIdentity '
     + N'and issues the session. Section 7.3, INV-07. The lookup is (Issuer, SubjectId) and there is no Email parameter '
     + N'in scope at all, which is the strongest form the invariant can take in a procedure -- an email claim is '
     + N'mutable, often unverified, and sometimes reassigned, so matching on it hands the next holder of an address the '
     + N'previous holder''s account. An unrecognised subject is E-50113 and NOT an auto-enrolment: implicit linking '
     + N'lets whoever controls the identity provider create local accounts at will. Stamps LastSeenUtc on the link, '
     + N'which is the only way to answer whether a link is still in use. Raises 50100, 50104, 50105, 50113, 50115.')
    , (N'auth', N'PROCEDURE', N'uspEndSession', NULL
     , N'Ends one session by token hash or session id, or every live session a user holds, and is the only writer of '
     + N'auth.UserSession.EndedUtc and EndReason -- both write-once. Exactly one identifier per call: ending the union '
     + N'or the intersection of two would both be guesses, one of which ends more sessions than anybody asked for. The '
     + N'@UserId route is what a password change or a deactivation needs, and it is why the procedure takes a reason at '
     + N'all. The reason vocabulary is closed HERE rather than at the table, so an incident script can still write '
     + N'something nobody anticipated while ordinary use cannot invent a seventh reason no report knows to group. '
     + N'Raises 50100 and 50114 -- and 50114 is what a person clicking sign out twice produces, so a sign-out handler '
     + N'should treat it as success.')
    , (N'auth', N'PROCEDURE', N'uspSetPassword', NULL
     , N'The administrative password reset -- T-112, gap G-42, section 16.2. Demands User.ResetCredential at the '
     + N'ACTOR''S OWN acting tenant, because a user is not tenant-scoped (section 11.4). Takes a PHC string the '
     + N'application computed and never a password (D-08); the verifier appears in no log, no report row and no '
     + N'DetailJson (UI-16). Retires the old verifier into auth.PasswordHistory BEFORE overwriting it, which is what '
     + N'gives uspChangePassword something to refuse a reuse against. FORCES MustChangePassword = 1: whoever ran the '
     + N'reset knows the value, and that is one person too many. Creates the credential where there was none, so a '
     + N'federated-only account can be given local access -- ''CredentialCreated'' rather than ''PasswordReset'' in '
     + N'the trail. Does NOT clear IsLockedOut and does NOT end the user''s sessions: the second is a separate '
     + N'uspEndSession call, and the notes explain why doing it here would let a failed revocation undo the reset. '
     + N'Raises 50152, 50220.')
    , (N'auth', N'PROCEDURE', N'uspGetPasswordChangeContext', NULL
     , N'What the application needs to change the SESSION''S OWN password: two result sets, no permission, and no '
     + N'parameter naming a user -- T-112, gap G-42. Result set 1 is always exactly one row (policy numbers, '
     + N'HasLiveCredential, MustChangePassword, DaysUntilExpiry). Result set 2 is the verifier strings a candidate '
     + N'password must be tested against: the current one, then the newest Authn.PasswordHistoryDepth retired ones. It '
     + N'exists because the database CANNOT check reuse itself -- every PHC string carries its own random salt, so '
     + N'comparing two of them proves nothing, and only the side holding the plaintext can test a candidate. There is '
     + N'deliberately no @UserId: one would make this a way for any application login to read any user''s stored '
     + N'hashes, and no permission check would make that a good idea. Error-only instrumented.')
    , (N'auth', N'PROCEDURE', N'uspChangePassword', NULL
     , N'The self-service password change -- T-112, gap G-42, section 16.2. The session says who; there is no @UserId '
     + N'and no permission, because the only password it can reach is the one belonging to the user the session was '
     + N'issued to. @CurrentPasswordVerified is the same contract as uspCompleteLogin''s @PasswordVerified and has no '
     + N'default: 0 or NULL is E-50221, so a caller that has not checked cannot change a password by omission. '
     + N'@NewVerifierReusesHistory is the application''s answer to the reuse question and is only acted on where '
     + N'Authn.PasswordHistoryDepth is greater than 0 -- a deployment keeping no history cannot have a reuse policy. '
     + N'Retires the old verifier, installs the new one, and CLEARS MustChangePassword: the only thing in the database '
     + N'that does. Does not end the session it was called on. Raises 50220, 50221, 50222, 50223.')
    , (N'auth', N'PROCEDURE', N'uspExpireCredentials', NULL
     , N'The scheduled expiry sweep -- T-112, gap G-12. Sets MustChangePassword = 1 on live, active users whose '
     + N'auth.UserCredential.ExpiresUtc has passed, oldest first, @BatchSize at a time, and writes one '
     + N'''CredentialExpired'' event per user. It is the ONLY thing that makes Authn.PasswordLifetimeDays mean '
     + N'anything: nothing in the sign-in path reads ExpiresUtc, because a sign-in refused for an aged password locks '
     + N'the person out of the screen that would fix it. GRANTED TO NOBODY -- it is a job, run by a scheduler that '
     + N'already holds db_owner, and granting it to applicationRole would hand the application a way to force a '
     + N'password change on every user in one call. Re-running is free: the predicate excludes users already carrying '
     + N'the flag, so the count reported is the newly expired. @UsersFlagged and @RemainingDue are OUTPUT parameters '
     + N'so a job can loop until the first is 0 and judge its schedule by the second. Raises 50224.');

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


-- *** 13. Grants ***
-- EXECUTE on ten of the eleven, and nothing on the tables -- INV-11.  The application reaches authentication only
-- through these entry points, and ownership chaining is what lets them read auth.[User] and auth.UserCredential on its
-- behalf while applicationRole itself holds no access to either.
--
-- THE ELEVENTH, auth.uspExpireCredentials, IS GRANTED TO NOBODY, AND THAT IS THE POINT OF IT (T-112, G-12).  It is a
-- scheduled job: no session to establish context from, nobody to demand a permission of, and a single call that can set
-- MustChangePassword on every user whose password has aged out.  An application login holding EXECUTE on it holds a way
-- to force a password change across the whole database, which is not something an application should be able to do even
-- by accident -- so the scheduler runs it as a principal that already holds db_owner and the grant is withheld on
-- purpose.  105_auth_session_procedures.sql withholds a grant for the same kind of reason and says so in the same place;
-- a withheld grant that is not explained looks exactly like a forgotten one.
--
-- SEVEN OF THE TEN ARE THE AUTHENTICATION PATH, INCLUDING uspRecordLoginFailure.  It is unlike 125's uspRebuildTenantClosure, which is not
-- granted because it is a whole-table rebuild with no authorization check in front of it: this one concludes a single
-- named exchange as a failure, which is the least harmful thing a caller can do with an exchange, and the application
-- genuinely needs it for failures it detects itself -- a malformed verifier string, an abandoned form.
--
-- None of them demands a permission, and that is not an omission either: they ARE the authentication path, so there is
-- no session and no authenticated identity to demand a permission of yet.  What guards them is that the application
-- login is the only principal holding applicationRole, and that every one of them decides for itself what it will do.
--
-- Each grant is guarded so the file stays re-runnable against a database where scripts/permissions.sql has not run.  The
-- same guard is how a typo'd role name produces procedures nobody can execute and no error to say why -- check these
-- names against the report at the end of scripts/permissions.sql.
IF DATABASE_PRINCIPAL_ID (N'applicationRole') IS NOT NULL
BEGIN
    GRANT EXECUTE ON auth.uspGetLoginVerifier   TO applicationRole;
    GRANT EXECUTE ON auth.uspCompleteLogin      TO applicationRole;
    GRANT EXECUTE ON auth.uspRecordLoginFailure TO applicationRole;
    GRANT EXECUTE ON auth.uspVerifyMfa          TO applicationRole;
    GRANT EXECUTE ON auth.uspBeginSsoLogin      TO applicationRole;
    GRANT EXECUTE ON auth.uspCompleteSsoLogin   TO applicationRole;
    GRANT EXECUTE ON auth.uspEndSession         TO applicationRole;

    -- T-112. The three password procedures the application calls. uspExpireCredentials is NOT here -- see above.
    GRANT EXECUTE ON auth.uspSetPassword              TO applicationRole;
    GRANT EXECUTE ON auth.uspGetPasswordChangeContext TO applicationRole;
    GRANT EXECUTE ON auth.uspChangePassword           TO applicationRole;
END;
GO


-- *** 14. Closing report ***
DECLARE @Report TABLE
(
    Seq        INT            NOT NULL,
    Status     VARCHAR (10)   NOT NULL,
    Item       NVARCHAR (200) NOT NULL,
    -- 1200 and not 400.  T-112 found the 400 the hard way: the G-21 row added at T-111 is 750 characters, so the first
    -- deployment after it failed with error 2628 -- "string or binary data would be truncated" -- naming a temporary
    -- object nobody can look at.  A report row is a paragraph of explanation by design, and the column has to be sized
    -- for the longest one somebody will reasonably write rather than for the shortest one written so far.
    Detail     NVARCHAR (1200)    NULL
);

INSERT @Report (Seq, Status, Item, Detail)
SELECT 1
     , CASE WHEN OBJECT_ID (N'auth.' + x.ProcName, N'P') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Procedure auth.' + x.ProcName
     , x.Purpose
  FROM (VALUES (N'uspGetLoginVerifier',   N'T-034. Local route step 1: open the exchange, issue a verifier, real or derived.')
             , (N'uspCompleteLogin',      N'T-035. Local route step 2: every rule, INV-08 and INV-09 among them.')
             , (N'uspRecordLoginFailure', N'T-036. Both counts, independently. Only the account arm writes state.')
             , (N'uspVerifyMfa',          N'T-037. TOTP step bounded against the clock and against replay; recovery codes.')
             , (N'uspBeginSsoLogin',      N'T-038. Federated route step 1: policy and throttle, then open the exchange.')
             , (N'uspCompleteSsoLogin',   N'T-038. Federated route step 2: INV-07, (Issuer, SubjectId) and nothing else.')
             , (N'uspEndSession',         N'T-039. The only writer of EndedUtc. One session, or all of a user''s.')
             , (N'uspSetPassword',       N'T-112, G-42. Administrative reset. User.ResetCredential; forces MustChangePassword.')
             , (N'uspGetPasswordChangeContext', N'T-112, G-42. The verifiers the application must test a candidate password against.')
             , (N'uspChangePassword',    N'T-112, G-42. Self-service change. Clears MustChangePassword; writes history.')
             , (N'uspExpireCredentials', N'T-112, G-12. The expiry sweep. Granted to nobody: it is a job.')
       ) AS x (ProcName, Purpose);

-- Rule 8 is asserted rather than assumed: a procedure on the authentication path that does not log its own failures is
-- a procedure whose failures are invisible in exactly the incident somebody is investigating.
--
-- T-112 made this TWO numbers instead of one.  Ten of the eleven WRITE and carry the full instrumentation; the eleventh,
-- auth.uspGetPasswordChangeContext, is a read and is error-only BY RULE, so it must not open a start row.  Asserting
-- 11/11 would have quietly demanded the wrong thing of it, and the next person to "fix" the report would have added the
-- start row and made a read look like a write in every performance summary built on logs.ExecutionLog.
INSERT @Report (Seq, Status, Item, Detail)
SELECT 2
     , CASE WHEN SUM (CASE WHEN m.definition LIKE N'%uspRecordExecutionError%' THEN 1 ELSE 0 END) = 11
             AND SUM (CASE WHEN m.definition LIKE N'%uspStartExecutionLogging%' THEN 1 ELSE 0 END) = 10
            THEN 'OK' ELSE 'PROBLEM' END
     , N'All eleven procedures are instrumented (rule 8)'
     , CONCAT (N'Start logging: '
             , SUM (CASE WHEN m.definition LIKE N'%uspStartExecutionLogging%' THEN 1 ELSE 0 END)
             , N'/10 -- the ten writers. uspGetPasswordChangeContext is a read and is error-only. Error recording: '
             , SUM (CASE WHEN m.definition LIKE N'%uspRecordExecutionError%' THEN 1 ELSE 0 END), N'/11.')
  FROM sys.sql_modules AS m
  JOIN sys.objects     AS o ON o.object_id = m.object_id
 WHERE o.type = 'P'
   AND o.schema_id = SCHEMA_ID (N'auth')
   AND o.name IN (N'uspGetLoginVerifier', N'uspCompleteLogin', N'uspRecordLoginFailure', N'uspVerifyMfa'
                , N'uspBeginSsoLogin', N'uspCompleteSsoLogin', N'uspEndSession'
                , N'uspSetPassword', N'uspGetPasswordChangeContext', N'uspChangePassword'
                , N'uspExpireCredentials');

-- The same kind of check as the INV-07 one above, and for the same reason: the invariant would be broken in the
-- PARAMETER LIST, so that is where it is asserted.  auth.uspGetPasswordChangeContext hands back stored verifier strings,
-- and the only thing stopping it handing back somebody else's is that it cannot be told whose to fetch -- the session
-- decides.  A well-meaning @UserId added later, with a permission check in front of it, would turn a procedure that
-- CANNOT leak into one that leaks whenever the check is wrong.
INSERT @Report (Seq, Status, Item, Detail)
SELECT 2
     , CASE WHEN (SELECT COUNT (*) FROM sys.parameters AS p
                   WHERE p.object_id = OBJECT_ID (N'auth.uspGetPasswordChangeContext', N'P')) = 1
            THEN 'OK' ELSE 'PROBLEM' END
     , N'auth.uspGetPasswordChangeContext takes the session and nothing else'
     , CONCAT ((SELECT COUNT (*) FROM sys.parameters AS p
                 WHERE p.object_id = OBJECT_ID (N'auth.uspGetPasswordChangeContext', N'P'))
             , N' parameter(s); exactly 1 (@SessionTokenHash) is required. It returns stored verifiers, so the session '
             , N'must be the only thing that can choose whose.');

-- INV-07 with teeth: the procedure that resolves a federated assertion must not be able to match on an email address.
-- A catalog check rather than a comment, because the parameter list is where the invariant would be broken.
INSERT @Report (Seq, Status, Item, Detail)
SELECT 2
     , CASE WHEN EXISTS (SELECT 1 FROM sys.parameters AS p
                          WHERE p.object_id = OBJECT_ID (N'auth.uspCompleteSsoLogin', N'P')
                            AND p.name LIKE N'%Email%')
            THEN 'PROBLEM' ELSE 'OK' END
     , N'INV-07: auth.uspCompleteSsoLogin takes no email parameter'
     , N'The federated lookup is (Issuer, SubjectId). An email claim is mutable, often unverified and sometimes '
     + N'reassigned, so matching on it hands the next holder of an address the previous holder''s account.';

INSERT @Report (Seq, Status, Item, Detail)
SELECT 3
     , CASE WHEN COUNT (*) = 14 THEN 'OK' ELSE 'PROBLEM' END
     , N'The fourteen Authn.* settings these procedures read are present'
     , CONCAT (COUNT (*), N' of 14 found in config.ApplicationSetting. A missing row degrades to the documented default '
             , N'rather than to NULL, except Authn.DummyVerifierPepper, where uspGetLoginVerifier fails CLOSED. The '
             , N'fourteenth is Authn.PasswordLifetimeDays, which T-112 brought into this file.')
  FROM config.ApplicationSetting AS s
 WHERE s.IsDeleted = 0
   AND s.SettingKey IN (N'Authn.LockoutThreshold', N'Authn.LockoutWindowMinutes', N'Authn.LockoutDurationMinutes'
                      , N'Authn.AddressThreshold', N'Authn.AddressWindowMinutes', N'Authn.LoginExchangeTimeoutSeconds'
                      , N'Authn.SessionLifetimeMinutes', N'Authn.IdleTimeoutMinutes', N'Authn.PasswordHistoryDepth'
                      , N'Authn.TotpStepSeconds', N'Authn.TotpWindowSteps', N'Authn.DummyVerifierPhcTemplate'
                      , N'Authn.DummyVerifierPepper'
                      -- T-112. The fourteenth: uspSetPassword and uspChangePassword stamp ExpiresUtc from it, and
                      -- uspExpireCredentials is what acts on what they stamped. 0 ships, and 0 means no expiry.
                      , N'Authn.PasswordLifetimeDays');

-- E-50224 IS PROBED HERE, ON EVERY DEPLOYMENT, and the other four password numbers are not -- see the file header.
-- This one needs nothing: no session, no permission, no user.  A batch size of 0 is refused before any work, so the
-- probe costs one rolled-back transaction and lands the number in logs.ExecutionLog, which is what keeps
-- _tests/080_error_catalogue.sql's ledger balanced without a hand-maintained entry.
DECLARE @BatchRefused BIT = 0
      , @BatchNumber  INT = NULL
      , @ProbeFlagged INT = NULL
      , @ProbeDue     INT = NULL;

BEGIN TRY
    EXEC auth.uspExpireCredentials @BatchSize    = 0
                                , @UsersFlagged  = @ProbeFlagged OUTPUT
                                , @RemainingDue  = @ProbeDue     OUTPUT;
END TRY
BEGIN CATCH
    SET @BatchNumber  = ERROR_NUMBER ();
    SET @BatchRefused = CASE WHEN ERROR_NUMBER () = 50224 THEN 1 ELSE 0 END;
END CATCH;

INSERT @Report (Seq, Status, Item, Detail)
SELECT 2
     , CASE WHEN @BatchRefused = 1 THEN 'OK' ELSE 'PROBLEM' END
     , N'auth.uspExpireCredentials refuses @BatchSize = 0 (E-50224)'
     , CONCAT (N'Raised error ', COALESCE (CAST (@BatchNumber AS NVARCHAR (11)), N'(none -- it ACCEPTED 0)')
             , N', where 50224 is required. A batch of 0 would loop forever doing nothing.');

INSERT @Report (Seq, Status, Item, Detail)
VALUES (4, 'INFO', N'No policy row is required for the local route, and one IS required for the federated route'
      , N'auth.udfResolveAuthPolicy returning NULL means "no policy applies", not "deny". AllowLocalPassword then '
      + N'defaults to 1 and AllowFederated to 0: a password needs only a credential row, federation needs a provider '
      + N'somebody configured. A fresh deployment can therefore sign in locally and cannot sign in by SSO.')
     , (4, 'INFO', N'Enrolment lives in 112_auth_mfa_procedures.sql, not here'
      , N'T-041, gap G-07 closed. This file PRESENTS a factor; 112 enrols, confirms, issues recovery codes and re-keys. '
      + N'The join between them is the refused exchange: uspCompleteLogin writes PasswordVerified = 1 before it raises '
      + N'E-50109, and that row is what auth.uspEnrolMfaFactor accepts as @BootstrapLoginAttemptId.')
     , (4, 'INFO', N'G-21 closed: auth.uspBeginSsoLogin now takes @Issuer and checks it'
      , N'auth.TenantTrustedIssuer (035_auth_tenant_policy.sql) holds the list; this file resolves it by walking '
      + N'auth.TenantClosure upward to the nearest ancestor that has one and refuses an issuer off it -- E-50124. The '
      + N'check is opt-in by design: no list anywhere above the tenant means not configured, because refusing everything '
      + N'would turn federated sign-in off on upgrade for every deployment that already had it working. 035''s closing '
      + N'report is where a deployment finds out it has not opted in -- see the "Trusted issuers (G-21)" row there. '
      + N'uspCompleteSsoLogin still resolves the assertion only through an existing link, which is INV-07 and unchanged.')
     , (4, 'INFO', N'G-42 closed: the password lifecycle is four procedures in this file'
      , N'uspSetPassword (reset, User.ResetCredential, forces MustChangePassword), uspGetPasswordChangeContext (the '
      + N'verifiers to test against), uspChangePassword (self-service, clears the flag). Section 16.2. Two obligations '
      + N'stay with the caller: JUDGE PASSWORD STRENGTH -- this database never sees a password -- and call '
      + N'auth.uspEndSession @EndReason = ''PasswordChanged'' after a reset made in response to a compromise.')
     , (4, 'INFO', N'G-12: the expiry sweep exists and MUST BE SCHEDULED to do anything'
      , N'auth.uspExpireCredentials is granted to nobody and called by nothing. Where '
      + N'Authn.PasswordLifetimeDays is non-zero, a deployment that has not scheduled it has an expiry policy that '
      + N'expires nothing -- 025_config_tables.sql reports ACTION on exactly that state. The warning window is '
      + N'auth.uspGetProfileContext''s (150), driven by Authn.PasswordExpiryWarningDays.')
     , (5, 'NEXT', N'database/112_auth_mfa_procedures.sql, then _tests/040_identity_and_authn.sql, then 170_permissions.sql'
      , N'112 is the other half of MFA: enrol, confirm, issue recovery codes, re-key. The test script then exercises all '
      + N'three routes, both counts independently, the replay refusal, and T-042 enumeration resistance. '
      + N'170_permissions.sql closes SCHEMA::config and states the util decision -- gap G-19.');

SELECT Seq
     , Status
     , Item
     , Detail
  FROM @Report
 ORDER BY Seq, Status DESC, Item;

IF EXISTS (SELECT 1 FROM @Report WHERE Status IN ('MISSING', 'PROBLEM'))
BEGIN
    DECLARE @Problems NVARCHAR (2000) =
        N'One or more checks above reported MISSING or PROBLEM. The authentication procedures are not installed as '
      + N'expected. Read the report rows and fix the cause rather than re-running blind.';

    THROW 50000, @Problems, 1;
END;

PRINT N'auth authentication procedures: no problems found. Enrolment is now in 112_auth_mfa_procedures.sql (T-041, gap '
    + N'G-07 closed); the trusted-issuer check is in uspBeginSsoLogin (G-21 closed), and whether THIS deployment has a '
    + N'list for it to consult is reported by 035_auth_tenant_policy.sql rather than here. T-112 added the password '
    + N'lifecycle: uspSetPassword, uspGetPasswordChangeContext and uspChangePassword (G-42), and uspExpireCredentials '
    + N'(G-12), which is granted to nobody and must be SCHEDULED -- it is the only thing that acts on '
    + N'Authn.PasswordLifetimeDays.';
GO
