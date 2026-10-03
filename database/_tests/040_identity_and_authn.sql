/***********************************************************************************************************************
Script:         _tests/040_identity_and_authn.sql
Purpose:        The Phase 2 exit criteria, all four of them, as experiments rather than assertions about code:
                  *  All three routes authenticate -- local password, federated, and the platform-admin bypass.
                  *  An unknown user costs the same work and yields the same message as a wrong password (DES 19.2).
                  *  Lockout fires per account and per address INDEPENDENTLY -- proved in both directions.
                  *  INV-07 holds: a federated identity resolves on (Issuer, SubjectId) and email cannot enter into it.
                  *  INV-08 holds: the bypass route always requires a second factor -- in the procedure AND at the table.
                Also proves the TOTP replay refusal, the recovery-code single-use refusal, the exchange timeout, and that
                auth.UserSession.EndedUtc is write-once.  Section 13 is the G-42 password lifecycle: a change retires the
                old verifier into auth.PasswordHistory, stamps the G-12 expiry, clears MustChangePassword and leaves the
                session alone.
Target:         SQL Server 2022 or newer.
Run as:         db_owner in the target database.
Run in:         The target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/_tests/040_identity_and_authn.sql
Idempotent:     Yes, and unconditionally -- see "WHY IT SOFT-DELETES FIRST" below.
Depends on:     025_config_tables.sql, 030_auth_tenant.sql, 035_auth_tenant_policy.sql, 040_auth_userprofile.sql,
                045_auth_identity.sql, 070_auth_session.sql, 085_logs_auth_tables.sql, 100_auth_functions.sql,
                110_auth_authn_procedures.sql.  Builds its own fixture and depends on no other test file.
Implements:     PLAN-AUTH-001 Phase 2 exit criteria.  Task T-042.  DES-AUTH-001 sections 6.2, 7.1, 7.2, 7.3, 7.4, 19.2.
                INV-07, INV-08, INV-09.
To retarget:    Pass it per run:  -d <database> -v DbName=<database>.  There is no in-file default.

WHY IT SOFT-DELETES FIRST, AND WHY THAT IS THE ONLY HONEST WAY TO RUN THIS TWICE
------------------------------------------------------------------------------
Both lockout counts are taken over auth.LoginAttempt inside a time window.  A second run of this file inside fifteen
minutes of the first would therefore start with the previous run's failures already counted, and the account-lockout
experiment would fire two failures early -- or the run would report a pass it had not earned, because the threshold had
already been crossed before the experiment began.

So section 2 SOFT-DELETES every attempt, session and recovery code belonging to the fixture's user names, and clears the
lockout flag and the last TOTP step.  Nothing is hard-deleted anywhere in this file: the counts all filter IsDeleted = 0,
so a soft delete is exactly the reset they need, and the rows stay for anybody reading the audit trail afterwards.  That
is the whole argument for soft deletion as a house rule, exercised here on the table where it matters most.

It does NOT skip work when the state already looks right.  A test that checks whether an experiment is necessary and
skips it becomes a test of the previous run's leftovers, and nothing in its output says which of the two happened.

WHY THE FIXTURE HAS SIX USERS AND NOT ONE
-----------------------------------------
Each one exists for a refusal that cannot be produced with the others:

  authtest.alice   ordinary local account.  The happy path, and the control in the independence experiments.
  authtest.bob     the account driven into lockout.  Separate from alice so that alice can prove, DURING bob's lockout,
                   that a per-account lock is per-account.
  authtest.carol   IsActive = 0.  The only way to reach E-50115 with a correct password and no lockout involved.
  authtest.dave    IsPlatformAdmin = 1 with a confirmed TOTP factor and recovery codes.  The bypass route, INV-08, the
                   replay refusal and the single-use refusal all need this one account.
  authtest.erin    a federated link and no interest in passwords.  INV-07.
  authtest.frank   a local account with NO confirmed factor, under a policy that requires one.  E-50109 -- and then the
                   way OUT of E-50109: frank is the account that enrols a first factor from the refusal itself, which is
                   what T-041 added and what gap G-07 used to block.  Section 12 is his, end to end.

WHY THE POLICY IS ON THE CHILD TENANT AND NOT ON THE ROOT
--------------------------------------------------------
ACME carries the policy; AUTHTEST_ROOT carries none.  Two things fall out of that arrangement and both are asserted:

  *  A sign-in scoped to ACME resolves ACME's policy -- AllowFederated = 1 -- and the federated route works.
  *  The same sign-in scoped to the root resolves NO policy, and federation is refused with E-50104, because
     auth.udfResolveAuthPolicy returns NULL for "nothing applies" and uspBeginSsoLogin reads NULL as a refusal.

That asymmetry between the two routes' defaults is a deliberate decision in 110_auth_authn_procedures.sql, and this file
is where it is demonstrated rather than asserted in a comment.

WHAT IT CANNOT TEST, AND SAYS SO RATHER THAN PRETENDING
------------------------------------------------------
  *  THE ENCRYPTION OF THE MFA SECRET.  Enrolment itself IS tested now -- section 12 runs the four T-041 procedures --
     but every @SecretCiphertext this file passes is random bytes, not a wrapped secret, and that is not a shortcut: the
     wrapping is the application's by decision (G-07, resolved in favour of application-side envelope encryption under a
     TPM-backed CNG key).  The database is a store of opaque bytes and a label saying which key made them, and this file
     can therefore assert everything about the LABEL and nothing whatever about the bytes.  That is the whole point.
     dave's factor is still inserted directly as db_owner, deliberately: it is the control that proves the consuming
     experiments do not depend on the enrolling ones.
  *  THE ARGON2ID COMPUTATION.  It happens in the application by construction (D-08).  The fixture's verifier strings
     are well-formed PHC strings that no password produces, and every call here reports @PasswordVerified explicitly --
     which is exactly the boundary the design draws.  T-040's .NET harness is where a real digest is computed.
  *  THE PASSING OF TIME.  The exchange-timeout experiment sets Authn.LoginExchangeTimeoutSeconds to -1 for one call and
     restores it immediately, rather than waiting five minutes.  The lockout DURATION is likewise not waited out; what is
     asserted is that LockoutEndUtc was set to the configured distance ahead, which is the part code decides.
***********************************************************************************************************************/

:on error exit

-- THE TARGET DATABASE IS SUPPLIED ON THE COMMAND LINE AND HAS NO DEFAULT.  There is deliberately no `:setvar DbName`
-- line: measured on sqlcmd 17, a :setvar in the file OVERRIDES -v rather than acting as a fallback for its absence.

SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;
GO


-- *** 0. Assert the target ***
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


-- *** 1. Assert the machinery ***
-- Asserted, not gated.  A test file that silently skips the experiments it cannot run is worse than no test file: it
-- reports a pass for work it did not do.  Finding F-07's shape, in a _tests directory.
IF OBJECT_ID (N'auth.uspGetLoginVerifier', N'P') IS NULL
   OR OBJECT_ID (N'auth.uspCompleteLogin', N'P') IS NULL
   OR OBJECT_ID (N'auth.uspRecordLoginFailure', N'P') IS NULL
   OR OBJECT_ID (N'auth.uspVerifyMfa', N'P') IS NULL
   OR OBJECT_ID (N'auth.uspBeginSsoLogin', N'P') IS NULL
   OR OBJECT_ID (N'auth.uspCompleteSsoLogin', N'P') IS NULL
   OR OBJECT_ID (N'auth.uspEndSession', N'P') IS NULL
BEGIN
    DECLARE @MsgProcs NVARCHAR (2000) =
        N'One or more of the seven authentication procedures is missing. Run '
      + N'database/110_auth_authn_procedures.sql first. Nothing has been changed.';

    THROW 50000, @MsgProcs, 1;
END
GO

IF OBJECT_ID (N'auth.udfIsUserUsable', N'FN') IS NULL
   OR OBJECT_ID (N'auth.udfResolveAuthPolicy', N'FN') IS NULL
   OR NOT EXISTS (SELECT 1 FROM config.ApplicationSetting
                   WHERE SettingKey = N'Authn.DummyVerifierPepper' AND IsDeleted = 0)
BEGIN
    DECLARE @MsgParts NVARCHAR (2000) =
        N'auth.udfIsUserUsable, auth.udfResolveAuthPolicy or the Authn.DummyVerifierPepper setting is missing. Run '
      + N'database/100_auth_functions.sql and database/025_config_tables.sql first. Nothing has been changed.';

    THROW 50000, @MsgParts, 1;
END
GO

-- The T-041 enrolment surface, asserted in its own batch so that its absence names its own script.  Section 12 is the
-- only section that needs these four, and it is also the only section that can prove frank has a way out of E-50109.
IF OBJECT_ID (N'auth.uspEnrolMfaFactor', N'P') IS NULL
   OR OBJECT_ID (N'auth.uspConfirmMfaFactor', N'P') IS NULL
   OR OBJECT_ID (N'auth.uspIssueMfaRecoveryCodes', N'P') IS NULL
   OR OBJECT_ID (N'auth.uspRotateMfaFactorKey', N'P') IS NULL
   OR OBJECT_ID (N'auth.udfResolveEnrolmentActor', N'FN') IS NULL
   OR NOT EXISTS (SELECT 1 FROM config.ApplicationSetting
                   WHERE SettingKey = N'Authn.MfaKeyReferenceCurrent' AND IsDeleted = 0)
BEGIN
    DECLARE @MsgMfa NVARCHAR (2000) =
        N'One or more of the four MFA enrolment procedures, auth.udfResolveEnrolmentActor, or the '
      + N'Authn.MfaKeyReferenceCurrent setting is missing. Run database/112_auth_mfa_procedures.sql (and '
      + N'database/100_auth_functions.sql, database/025_config_tables.sql) first. Nothing has been changed.';

    THROW 50000, @MsgMfa, 1;
END
GO


-- *** 2. The fixture, and the reset ***
-- Restated every run rather than created once, for the same reason _tests/020 restates every tenant's parent: a fixture
-- that exists only on the first run is a fixture whose absence is a silent skip on the second.
DECLARE @Now      DATETIME2 (3)  = SYSUTCDATETIME ()
      , @Actor    NVARCHAR (255) = N'_tests/040_identity_and_authn.sql'
      , @AppId    INT
      , @RootId   INT
      , @AcmeId   INT
      , @PolicyId INT;

-- 2a. The application and two tenants.  INV-02: exactly one parentless tenant per application.
IF NOT EXISTS (SELECT 1 FROM auth.Application WHERE ApplicationCode = N'AUTHTEST')
BEGIN
    INSERT auth.Application (ApplicationCode, ApplicationName, IsActive, auditCreatedBy, auditModifiedBy)
    VALUES (N'AUTHTEST', N'Phase 2 authentication test fixture', 1, @Actor, @Actor);
END;

SELECT @AppId = ApplicationId FROM auth.Application WHERE ApplicationCode = N'AUTHTEST';

-- TenantTypeId and TenantTypeCode are both written: 030_auth_tenant.sql carries the code alongside the key deliberately,
-- so that a CHECK constraint can tie ParentTenantId IS NULL to 'Root' -- a CHECK may only read its own row.
DECLARE @RootTypeId INT = (SELECT TenantTypeId FROM auth.TenantType WHERE TenantTypeCode = N'Root')
      , @OrgTypeId  INT = (SELECT TenantTypeId FROM auth.TenantType WHERE TenantTypeCode = N'ExternalOrganization');

IF NOT EXISTS (SELECT 1 FROM auth.Tenant WHERE ApplicationId = @AppId AND TenantCode = N'AUTHTEST_ROOT')
BEGIN
    INSERT auth.Tenant (ApplicationId, ParentTenantId, TenantCode, TenantName, TenantTypeId, TenantTypeCode, IsActive
                      , auditCreatedBy, auditModifiedBy)
    VALUES (@AppId, NULL, N'AUTHTEST_ROOT', N'Authentication test root', @RootTypeId, N'Root', 1, @Actor, @Actor);
END;

SELECT @RootId = TenantId FROM auth.Tenant WHERE ApplicationId = @AppId AND TenantCode = N'AUTHTEST_ROOT';

IF NOT EXISTS (SELECT 1 FROM auth.Tenant WHERE ApplicationId = @AppId AND TenantCode = N'AUTHTEST_ACME')
BEGIN
    INSERT auth.Tenant (ApplicationId, ParentTenantId, TenantCode, TenantName, TenantTypeId, TenantTypeCode, IsActive
                      , auditCreatedBy, auditModifiedBy)
    VALUES (@AppId, @RootId, N'AUTHTEST_ACME', N'Acme, a federating tenant', @OrgTypeId, N'ExternalOrganization', 1
          , @Actor, @Actor);
END;

SELECT @AcmeId = TenantId FROM auth.Tenant WHERE ApplicationId = @AppId AND TenantCode = N'AUTHTEST_ACME';

IF OBJECT_ID (N'auth.uspRebuildTenantClosure', N'P') IS NOT NULL
BEGIN
    EXEC auth.uspRebuildTenantClosure;
END;

-- 2b. The policy, on ACME and NOT on the root -- see the banner.  RequireMfaForLocal = 0 so that the ordinary local
-- route can be tested without a factor; the MFA requirement is tested by overriding this row in section 8.
IF NOT EXISTS (SELECT 1 FROM auth.TenantAuthenticationPolicy WHERE TenantId = @AcmeId AND IsDeleted = 0)
BEGIN
    INSERT auth.TenantAuthenticationPolicy
        (TenantId, AllowFederated, AllowLocalPassword, RequireMfaForLocal, PreferredMethod
       , SessionLifetimeMinutes, IdleTimeoutMinutes, RequireStepUpForPrivileged, PolicyNote
       , auditCreatedBy, auditModifiedBy)
    VALUES (@AcmeId, 1, 1, 0, 'LocalPassword', 60, 15, 0
          , N'Phase 2 test fixture. 60/15 chosen to differ from the shipped 480/60 defaults, so an assertion that the '
          + N'session took ITS lifetime from the policy cannot pass by coincidence.'
          , @Actor, @Actor);
END
ELSE
BEGIN
    UPDATE auth.TenantAuthenticationPolicy
       SET AllowFederated         = 1
         , AllowLocalPassword     = 1
         , RequireMfaForLocal     = 0
         , SessionLifetimeMinutes = 60
         , IdleTimeoutMinutes     = 15
         , auditModifiedBy        = @Actor
     WHERE TenantId  = @AcmeId
       AND IsDeleted = 0;
END;

SELECT @PolicyId = TenantAuthenticationPolicyId
  FROM auth.TenantAuthenticationPolicy
 WHERE TenantId = @AcmeId AND IsDeleted = 0;

-- 2c. Six users.  Each exists for a refusal the others cannot produce -- the banner lists them.
DECLARE @Users TABLE
(
    UserName        NVARCHAR (256) NOT NULL PRIMARY KEY,
    DisplayName     NVARCHAR (256) NOT NULL,
    IsActive        BIT            NOT NULL,
    IsPlatformAdmin BIT            NOT NULL
);

INSERT @Users (UserName, DisplayName, IsActive, IsPlatformAdmin)
VALUES (N'authtest.alice', N'Alice, ordinary local account',        1, 0)
     , (N'authtest.bob',   N'Bob, the account driven into lockout', 1, 0)
     , (N'authtest.carol', N'Carol, deactivated',                   0, 0)
     , (N'authtest.dave',  N'Dave, platform administrator',         1, 1)
     , (N'authtest.erin',  N'Erin, federated only',                 1, 0)
     , (N'authtest.frank', N'Frank, no second factor',              1, 0);

INSERT auth.[User] (UserName, DisplayName, Email, IsActive, IsPlatformAdmin, IsLockedOut, MustChangePassword
                  , auditCreatedBy, auditModifiedBy)
SELECT u.UserName, u.DisplayName, u.UserName + N'@authtest.invalid', u.IsActive, u.IsPlatformAdmin, 0, 0
     , @Actor, @Actor
  FROM @Users AS u
 WHERE NOT EXISTS (SELECT 1 FROM auth.[User] AS x WHERE x.UserName = u.UserName);

-- Restated, because a previous run deactivated nobody but a previous EXPERIMENT might have locked somebody.  This is
-- the reset for auth.User: IsActive back to what the fixture says, and the lockout cleared unconditionally.
UPDATE t
   SET t.IsActive        = u.IsActive
     , t.IsPlatformAdmin = u.IsPlatformAdmin
     , t.IsLockedOut     = 0
     , t.LockoutEndUtc   = NULL
     , t.auditModifiedBy = @Actor
  FROM auth.[User] AS t
  JOIN @Users      AS u ON u.UserName = t.UserName;

-- 2d. Credentials.  Well-formed PHC strings that no password produces: the digest field is random per run, so nothing
-- in this file can accidentally depend on a constant, and D-08 means the database never computes against them anyway.
-- The field lengths are the template's -- 22 and 43 -- which is what lets section 5 compare a real verifier's length
-- with a derived dummy's and have the comparison mean something.
DECLARE @PhcPrefix NVARCHAR (64) = N'$argon2id$v=19$m=19456,t=2,p=1$';

INSERT auth.UserCredential (UserId, CredentialType, VerifierPhc, LastChangedUtc, auditCreatedBy, auditModifiedBy)
SELECT u.UserId
     , 'Password'
     , @PhcPrefix
     + LEFT (REPLACE (REPLACE (CONVERT (VARCHAR (64), HASHBYTES ('SHA2_256', u.UserName + N'|fixture|salt'), 2)
                             , '0', 'q'), '1', 'w'), 22)
     + N'$'
     + LEFT (REPLACE (REPLACE (CONVERT (VARCHAR (64), HASHBYTES ('SHA2_256', u.UserName + N'|fixture|hash'), 2)
                             , '0', 'e'), '1', 'r'), 43)
     , @Now
     , @Actor, @Actor
  FROM auth.[User] AS u
  JOIN @Users      AS f ON f.UserName = u.UserName
 WHERE u.UserName <> N'authtest.erin'   -- federated only, deliberately has no password at all
   AND NOT EXISTS (SELECT 1 FROM auth.UserCredential AS c
                    WHERE c.UserId = u.UserId AND c.CredentialType = 'Password' AND c.IsDeleted = 0);

-- 2e. Erin's federated link.  INV-07's key, and note that Email plays no part in it -- erin has an Email column value
-- like everybody else, and nothing in the federated route reads it.
DECLARE @Issuer    NVARCHAR (512) = N'https://idp.authtest.invalid/authtest/v2.0'
      , @SubjErin  NVARCHAR (256) = N'SUBJECT-ERIN-0000000000000000000000000'
      , @ErinId    INT            = (SELECT UserId FROM auth.[User] WHERE UserName = N'authtest.erin');

IF NOT EXISTS (SELECT 1 FROM auth.UserFederatedIdentity
                WHERE Issuer = @Issuer AND SubjectId = @SubjErin AND IsDeleted = 0)
BEGIN
    INSERT auth.UserFederatedIdentity (UserId, Issuer, SubjectId, LinkedUtc, auditCreatedBy, auditModifiedBy)
    VALUES (@ErinId, @Issuer, @SubjErin, @Now, @Actor, @Actor);
END;

-- 2f. Dave's confirmed TOTP factor.  Still inserted DIRECTLY, as db_owner, now that T-041 exists -- and deliberately so.
-- dave is the CONTROL: every experiment that consumes a factor (the clock window, the replay refusal, single-use
-- recovery codes, INV-08) must be provable without depending on the enrolling procedures, so that a defect in section 12
-- cannot silently disarm sections 6 to 8.  frank is the one who enrols properly, through auth.uspEnrolMfaFactor.
--
-- The ciphertext is random bytes, which is not a shortcut either: under G-07's resolution the wrapping is the
-- application's and this server never holds the key, so random bytes are exactly as meaningful to the database as a real
-- wrapped secret is.  What the database DOES insist on is the LABEL, and the label therefore comes from the same setting
-- auth.uspEnrolMfaFactor reads, never a literal -- a fixture that stamps its own invented reference is a fixture that
-- teaches the constraint to be wrong.
DECLARE @DaveId  INT            = (SELECT UserId FROM auth.[User] WHERE UserName = N'authtest.dave')
      , @KeyRef  NVARCHAR (256) = (SELECT NULLIF (LTRIM (RTRIM (SettingValue)), N'')
                                     FROM config.ApplicationSetting
                                    WHERE SettingKey = N'Authn.MfaKeyReferenceCurrent' AND IsDeleted = 0);

-- The repair, and it is scoped to the fixture's own users on purpose.  Earlier runs of this file stamped the literal
-- N'test-fixture-no-real-key', which predates T-041's grammar; 045_auth_identity.sql cannot ADD
-- CK_auth_UserMfaFactor_KeyReferenceFormat while a row violates it, and the constraint is a Phase 2 exit criterion.  So
-- the fixture repairs what the fixture wrote -- re-labelling, not re-keying, because the bytes were never under a real
-- key to begin with.  Anything outside these six user names is somebody else's row and this file does not touch it.
UPDATE f
   SET f.KeyReference    = @KeyRef
     , f.auditModifiedBy = @Actor
  FROM auth.UserMfaFactor AS f
  JOIN auth.[User]        AS u ON u.UserId   = f.UserId
  JOIN @Users             AS x ON x.UserName = u.UserName
 WHERE f.IsDeleted    = 0
   AND f.KeyReference <> @KeyRef;

IF NOT EXISTS (SELECT 1 FROM auth.UserMfaFactor WHERE UserId = @DaveId AND FactorType = 'Totp' AND IsDeleted = 0)
BEGIN
    INSERT auth.UserMfaFactor (UserId, FactorType, SecretCiphertext, KeyReference, IsConfirmed, ConfirmedUtc
                             , auditCreatedBy, auditModifiedBy)
    VALUES (@DaveId, 'Totp', CRYPT_GEN_RANDOM (48), @KeyRef, 1, @Now, @Actor, @Actor);
END;

-- 2f-ii. frank starts every run with NO factor at all, live or otherwise.  Section 12 enrols one through the procedures
-- and section 10b needs him refused first, so a factor left behind by the previous run would turn both into no-ops --
-- and a no-op that reports OK is the failure mode this whole file is arranged against.  Soft-deleted, like everything.
DECLARE @FrankIdReset INT = (SELECT UserId FROM auth.[User] WHERE UserName = N'authtest.frank');

UPDATE auth.UserMfaFactor
   SET IsDeleted           = 1
     , auditDeletedBy      = @Actor
     , auditDeletedDateUtc = @Now
     , auditModifiedBy     = @Actor
 WHERE UserId    = @FrankIdReset
   AND IsDeleted = 0;

UPDATE auth.UserMfaRecoveryCode
   SET IsDeleted           = 1
     , auditDeletedBy      = @Actor
     , auditDeletedDateUtc = @Now
     , auditModifiedBy     = @Actor
 WHERE UserId    = @FrankIdReset
   AND IsDeleted = 0;

-- The reset for the factor: LastUsedTimeStep back to NULL, so the replay experiment starts from a known floor rather
-- than from whatever step the previous run consumed.  The pair CHECK requires both columns move together.
UPDATE auth.UserMfaFactor
   SET LastUsedUtc      = NULL
     , LastUsedTimeStep = NULL
     , auditModifiedBy  = @Actor
 WHERE UserId    = @DaveId
   AND IsDeleted = 0;

-- 2g. The reset proper.  Soft deletes, never hard ones -- the banner argues it.  Order matters only in that the attempt
-- rows must be retired before any count is taken.
UPDATE s
   SET s.IsDeleted           = 1
     , s.auditDeletedBy      = @Actor
     , s.auditDeletedDateUtc = @Now
     , s.auditModifiedBy     = @Actor
  FROM auth.UserSession AS s
  JOIN auth.[User]      AS u ON u.UserId = s.UserId
  JOIN @Users           AS f ON f.UserName = u.UserName
 WHERE s.IsDeleted = 0;

UPDATE a
   SET a.IsDeleted           = 1
     , a.auditDeletedBy      = @Actor
     , a.auditDeletedDateUtc = @Now
     , a.auditModifiedBy     = @Actor
  FROM auth.LoginAttempt AS a
 WHERE a.IsDeleted = 0
   AND (a.UserName LIKE N'authtest.%' OR a.ClientAddress LIKE N'198.51.100.%' OR a.UserName = N'(sso pending)');

-- Recovery codes cannot be un-used -- UsedUtc is write-once at the trigger -- so a fresh set is issued every run and the
-- previous set retired.  Four of them: one to spend on the happy path, one to spend and then replay, two spare so the
-- "remaining" count in the event detail is not zero and therefore not ambiguous.
UPDATE auth.UserMfaRecoveryCode
   SET IsDeleted           = 1
     , auditDeletedBy      = @Actor
     , auditDeletedDateUtc = @Now
     , auditModifiedBy     = @Actor
 WHERE UserId    = @DaveId
   AND IsDeleted = 0;

-- Derived from the run's start time, so each run's codes differ from every other run's and the unique index on
-- (UserId, CodeHash) filtered to live rows is never asked to accept a repeat.
DECLARE @CodeSeed NVARCHAR (64) = CONVERT (NVARCHAR (30), @Now, 126);

INSERT auth.UserMfaRecoveryCode (UserId, CodeHash, auditCreatedBy, auditModifiedBy)
SELECT @DaveId, HASHBYTES ('SHA2_256', @CodeSeed + N'|code|' + x.Ordinal), @Actor, @Actor
  FROM (VALUES (N'1'), (N'2'), (N'3'), (N'4')) AS x (Ordinal);

PRINT N'Fixture restated and reset: 1 application, 2 tenants, 1 policy on the child only, 6 users, 5 credentials, '
    + N'1 federated link, 1 confirmed TOTP factor, 4 fresh recovery codes. Prior attempts and sessions soft-deleted.';
GO


-- *** 3. The observation log, and the local password route ***
-- A TEMPORARY TABLE AND NOT A TABLE VARIABLE, because the experiments span several batches and a table variable does not
-- survive GO.  There is no IF OBJECT_ID ... DROP guard in front of it on purpose: a fresh sqlcmd connection cannot have
-- one already, and a conditional guard around a CREATE is the shape this project refuses everywhere else.  Running this
-- file twice down one INTERACTIVE session will therefore fail here, loudly, which is the correct outcome -- the second
-- run wants its own connection, so that #Observation starts empty and the transcript is not two runs interleaved.
CREATE TABLE #Observation
(
    RowNo     INT IDENTITY (1, 1) PRIMARY KEY,
    Section   NVARCHAR (60)  NOT NULL,
    Severity  INT            NOT NULL,   -- 1 = exit criterion violated, 2 = defect, 3 = note, 4 = observed as intended
    Status    VARCHAR (10)   NOT NULL,
    Item      NVARCHAR (200) NOT NULL,
    Detail    NVARCHAR (2000)    NULL
);
GO

-- NOTHING IN THIS FILE CALLS AN AUTHENTICATION PROCEDURE INSIDE A TRANSACTION, and that is a constraint on every caller
-- rather than a stylistic choice here.  Each procedure COMMITS a recorded failure before it raises, precisely so that the
-- raise cannot erase the record -- but a caller holding an outer transaction makes XACT_STATE () non-zero at that moment,
-- so the procedure's own CATCH rolls the CALLER's transaction back and the lockout increment goes with it.  A .NET caller
-- inside a TransactionScope would hand an attacker unlimited guesses, silently, and no test in the database would see it.
INSERT #Observation (Section, Severity, Status, Item, Detail)
VALUES (N'0 Preconditions', 3, 'NOTE'
      , N'No experiment here wraps a procedure call in a transaction, and no caller may either'
      , N'The procedures commit a recorded failure before raising, so an ambient transaction would be rolled back by '
      + N'the procedure''s own CATCH and the failure count -- and therefore the lockout -- would never rise. Recorded '
      + N'as UI-27 for the .NET side, where TransactionScope makes this easy to do by accident.');
GO

DECLARE @AttemptId   BIGINT
      , @Phc         NVARCHAR (512)
      , @PhcAlice    NVARCHAR (512)
      , @RequiresMfa BIT
      , @SessionId   BIGINT
      , @UserIdOut   INT
      , @MustChange  BIT
      , @AbsExpiry   DATETIME2 (3)
      , @IdleExpiry  DATETIME2 (3)
      , @Token       VARBINARY (32) = CRYPT_GEN_RANDOM (32);

-- 3a.  ROUTE 1 OF 3: the local password route, both round trips.
EXEC auth.uspGetLoginVerifier @ApplicationCode = N'AUTHTEST', @TenantCode = N'AUTHTEST_ACME'
   , @UserName = N'authtest.alice', @ClientAddress = N'198.51.100.10', @UserAgent = N'_tests/040'
   , @LoginAttemptId = @AttemptId OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @RequiresMfa OUTPUT;

SET @PhcAlice = @Phc;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'3 Local route'
     , CASE WHEN @Phc = c.VerifierPhc AND @RequiresMfa = 0 AND @AttemptId IS NOT NULL THEN 4 ELSE 2 END
     , CASE WHEN @Phc = c.VerifierPhc AND @RequiresMfa = 0 AND @AttemptId IS NOT NULL THEN 'OK' ELSE 'DEFECT' END
     , N'Round trip 1 returned the LIVE verifier for a known user'
     , CONCAT (N'Exchange ', @AttemptId, N'. Verifier equals auth.UserCredential.VerifierPhc: '
             , CASE WHEN @Phc = c.VerifierPhc THEN N'yes' ELSE N'NO' END
             , N'. @RequiresMfa = ', @RequiresMfa, N', which is the ACME policy''s RequireMfaForLocal = 0 and not a '
             , N'property of alice.')
  FROM auth.UserCredential AS c
  JOIN auth.[User]         AS u ON u.UserId = c.UserId
 WHERE u.UserName  = N'authtest.alice'
   AND c.IsDeleted = 0;

EXEC auth.uspCompleteLogin @LoginAttemptId = @AttemptId, @PasswordVerified = 1, @SessionTokenHash = @Token
   , @UserSessionId = @SessionId OUTPUT, @UserId = @UserIdOut OUTPUT, @MustChangePassword = @MustChange OUTPUT
   , @AbsoluteExpiryUtc = @AbsExpiry OUTPUT, @IdleExpiryUtc = @IdleExpiry OUTPUT;

-- The two lifetimes are what make this more than a smoke test.  60 and 15 are the POLICY's numbers and they differ from
-- the shipped defaults of 480 and 60, so agreement cannot be a coincidence of the fallback path.
INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'3 Local route'
     , CASE WHEN s.UserSessionId IS NOT NULL
             AND DATEDIFF (MINUTE, s.StartedUtc, s.AbsoluteExpiryUtc) = 60
             AND DATEDIFF (MINUTE, s.StartedUtc, s.IdleExpiryUtc)     = 15
             AND a.Outcome = 'Success' AND a.PasswordVerified = 1
            THEN 4 ELSE 1 END
     , CASE WHEN s.UserSessionId IS NOT NULL
             AND DATEDIFF (MINUTE, s.StartedUtc, s.AbsoluteExpiryUtc) = 60
             AND DATEDIFF (MINUTE, s.StartedUtc, s.IdleExpiryUtc)     = 15
             AND a.Outcome = 'Success' AND a.PasswordVerified = 1
            THEN 'OK' ELSE 'VIOLATED' END
     , N'EXIT CRITERION: route 1 of 3, the local password route, authenticates'
     , CONCAT (N'Session ', s.UserSessionId, N' for user ', s.UserId, N', method ', s.AuthenticationMethod
             , N'. Absolute lifetime ', DATEDIFF (MINUTE, s.StartedUtc, s.AbsoluteExpiryUtc)
             , N' minute(s) against 60 in the policy -- the shipped default is 480, so this cannot agree by accident. '
             , N'Idle ', DATEDIFF (MINUTE, s.StartedUtc, s.IdleExpiryUtc), N' against 15 (default 60). Exchange '
             , N'outcome ', a.Outcome, N', PasswordVerified ', a.PasswordVerified, N'.')
  FROM auth.UserSession  AS s
  JOIN auth.LoginAttempt AS a ON a.LoginAttemptId = s.LoginAttemptId
 WHERE s.UserSessionId = @SessionId;

-- 3b.  ENUMERATION RESISTANCE -- half of an exit criterion, and task T-042.  Three probes against two names nobody holds.
DECLARE @PhcGhost1 NVARCHAR (512), @PhcGhost1Again NVARCHAR (512), @PhcGhost2 NVARCHAR (512), @Ghost BIGINT;

EXEC auth.uspGetLoginVerifier @ApplicationCode = N'AUTHTEST', @TenantCode = N'AUTHTEST_ACME'
   , @UserName = N'authtest.ghost.one', @ClientAddress = N'198.51.100.10'
   , @LoginAttemptId = @Ghost OUTPUT, @VerifierPhc = @PhcGhost1 OUTPUT, @RequiresMfa = @RequiresMfa OUTPUT;

EXEC auth.uspGetLoginVerifier @ApplicationCode = N'AUTHTEST', @TenantCode = N'AUTHTEST_ACME'
   , @UserName = N'authtest.ghost.one', @ClientAddress = N'198.51.100.10'
   , @LoginAttemptId = @Ghost OUTPUT, @VerifierPhc = @PhcGhost1Again OUTPUT, @RequiresMfa = @RequiresMfa OUTPUT;

EXEC auth.uspGetLoginVerifier @ApplicationCode = N'AUTHTEST', @TenantCode = N'AUTHTEST_ACME'
   , @UserName = N'authtest.ghost.two', @ClientAddress = N'198.51.100.10'
   , @LoginAttemptId = @Ghost OUTPUT, @VerifierPhc = @PhcGhost2 OUTPUT, @RequiresMfa = @RequiresMfa OUTPUT;

INSERT #Observation (Section, Severity, Status, Item, Detail)
VALUES (N'3 Enumeration'
      , CASE WHEN @PhcGhost1 IS NOT NULL AND LEN (@PhcGhost1) = LEN (@PhcAlice)
                                         AND LEFT (@PhcGhost1, 31) = LEFT (@PhcAlice, 31) THEN 4 ELSE 1 END
      , CASE WHEN @PhcGhost1 IS NOT NULL AND LEN (@PhcGhost1) = LEN (@PhcAlice)
                                         AND LEFT (@PhcGhost1, 31) = LEFT (@PhcAlice, 31) THEN 'OK' ELSE 'VIOLATED' END
      , N'EXIT CRITERION: an unknown name yields a verifier of identical shape and length'
      , CONCAT (N'Unknown name: ', COALESCE (CAST (LEN (@PhcGhost1) AS NVARCHAR (11)), N'(null returned)')
              , N' characters. Known name: ', LEN (@PhcAlice)
              , N'. Algorithm and cost prefix identical: '
              , CASE WHEN LEFT (@PhcGhost1, 31) = LEFT (@PhcAlice, 31) THEN N'yes' ELSE N'NO' END
              , N'. A dummy with a shorter salt field is distinguishable by eye, with no timing analysis at all.'))
     , (N'3 Enumeration'
      , CASE WHEN @PhcGhost1 = @PhcGhost1Again AND @PhcGhost1 <> @PhcGhost2 THEN 4 ELSE 1 END
      , CASE WHEN @PhcGhost1 = @PhcGhost1Again AND @PhcGhost1 <> @PhcGhost2 THEN 'OK' ELSE 'VIOLATED' END
      , N'EXIT CRITERION: the dummy is DERIVED per name -- stable for one name, different between two'
      , CONCAT (N'The same unknown name twice: '
              , CASE WHEN @PhcGhost1 = @PhcGhost1Again THEN N'identical, as a real account would be'
                     ELSE N'DIFFERENT, which is itself the signal that the name is unknown' END
              , N'. Two different unknown names: '
              , CASE WHEN @PhcGhost1 <> @PhcGhost2 THEN N'different, as two real accounts would be'
                     ELSE N'IDENTICAL, so one probe fingerprints every unknown name at once' END, N'.'));
GO


-- *** 4. The same answer for a wrong password and for a name nobody holds ***
DECLARE @AttemptId BIGINT, @Phc NVARCHAR (512), @Mfa BIT, @Token VARBINARY (32)
      , @SessionId BIGINT, @UserIdOut INT, @MustChange BIT, @Abs DATETIME2 (3), @Idle DATETIME2 (3)
      , @ErrKnown INT, @ErrUnknown INT, @MsgKnown NVARCHAR (2000), @MsgUnknown NVARCHAR (2000)
      , @KnownAttempt BIGINT, @UnknownAttempt BIGINT;

-- 4a.  A real account, the wrong password.
SET @Token = CRYPT_GEN_RANDOM (32);

EXEC auth.uspGetLoginVerifier @ApplicationCode = N'AUTHTEST', @TenantCode = N'AUTHTEST_ACME'
   , @UserName = N'authtest.alice', @ClientAddress = N'198.51.100.10'
   , @LoginAttemptId = @AttemptId OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;

SET @KnownAttempt = @AttemptId;

BEGIN TRY
    EXEC auth.uspCompleteLogin @LoginAttemptId = @AttemptId, @PasswordVerified = 0, @SessionTokenHash = @Token
       , @UserSessionId = @SessionId OUTPUT, @UserId = @UserIdOut OUTPUT, @MustChangePassword = @MustChange OUTPUT
       , @AbsoluteExpiryUtc = @Abs OUTPUT, @IdleExpiryUtc = @Idle OUTPUT;
END TRY
BEGIN CATCH
    SET @ErrKnown = ERROR_NUMBER ();
    SET @MsgKnown = ERROR_MESSAGE ();
END CATCH;

-- 4b.  A name nobody holds, reported the only way the application CAN report it: the digest did not match the verifier it
-- was given.  The application does not know the verifier was derived, which is the whole point of deriving one.
SET @Token = CRYPT_GEN_RANDOM (32);

EXEC auth.uspGetLoginVerifier @ApplicationCode = N'AUTHTEST', @TenantCode = N'AUTHTEST_ACME'
   , @UserName = N'authtest.ghost.three', @ClientAddress = N'198.51.100.10'
   , @LoginAttemptId = @AttemptId OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;

SET @UnknownAttempt = @AttemptId;

BEGIN TRY
    EXEC auth.uspCompleteLogin @LoginAttemptId = @AttemptId, @PasswordVerified = 0, @SessionTokenHash = @Token
       , @UserSessionId = @SessionId OUTPUT, @UserId = @UserIdOut OUTPUT, @MustChangePassword = @MustChange OUTPUT
       , @AbsoluteExpiryUtc = @Abs OUTPUT, @IdleExpiryUtc = @Idle OUTPUT;
END TRY
BEGIN CATCH
    SET @ErrUnknown = ERROR_NUMBER ();
    SET @MsgUnknown = ERROR_MESSAGE ();
END CATCH;

INSERT #Observation (Section, Severity, Status, Item, Detail)
VALUES (N'4 Same answer'
      , CASE WHEN @ErrKnown = 50106 AND @ErrUnknown = 50106 AND @MsgKnown = @MsgUnknown THEN 4 ELSE 1 END
      , CASE WHEN @ErrKnown = 50106 AND @ErrUnknown = 50106 AND @MsgKnown = @MsgUnknown THEN 'OK' ELSE 'VIOLATED' END
      , N'EXIT CRITERION: a wrong password and an unknown name give the same number AND the same text'
      , CONCAT (N'Known account: ', COALESCE (CAST (@ErrKnown AS NVARCHAR (11)), N'no error -- it SUCCEEDED')
              , N'. Unknown name: ', COALESCE (CAST (@ErrUnknown AS NVARCHAR (11)), N'no error -- it SUCCEEDED')
              , N'. Texts identical: ', CASE WHEN @MsgKnown = @MsgUnknown THEN N'yes' ELSE N'NO' END
              , N'. Both are E-50106; section 14.5 requires the UI to flatten the whole range into one message (UI-26).'));

-- The other half of "the same work": both exchanges were concluded, so both COUNT.  An unknown name that cost no attempt
-- row would be an unknown name that could be probed for nothing, whatever the two round trips looked like from outside.
INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'4 Same answer'
     , CASE WHEN COUNT (*) = 2 THEN 4 ELSE 1 END
     , CASE WHEN COUNT (*) = 2 THEN 'OK' ELSE 'VIOLATED' END
     , N'EXIT CRITERION: both cost an attempt row, concluded as a failure and therefore counted'
     , CONCAT (COUNT (*), N' of 2 exchanges carry Outcome = ''Failure''. Reasons recorded: '
             , STRING_AGG (CONCAT (a.UserName, N' -> ', COALESCE (a.FailureReason, '(none)')), N', ')
             , N'. The reasons differ in the audit trail, which is where the difference belongs -- and nowhere in what '
             , N'the caller can see.')
  FROM auth.LoginAttempt AS a
 WHERE a.LoginAttemptId IN (@KnownAttempt, @UnknownAttempt)
   AND a.Outcome   = 'Failure'
   AND a.IsDeleted = 0;
GO


-- *** 5. The per-account lockout, and that it is per ACCOUNT ***
DECLARE @i INT = 1, @AttemptId BIGINT, @Phc NVARCHAR (512), @Mfa BIT, @Token VARBINARY (32)
      , @SessionId BIGINT, @UserIdOut INT, @MustChange BIT, @Abs DATETIME2 (3), @Idle DATETIME2 (3)
      , @ErrAfterLock INT
      , @Threshold INT = TRY_CAST ((SELECT SettingValue FROM config.ApplicationSetting
                                     WHERE SettingKey = N'Authn.LockoutThreshold' AND IsDeleted = 0) AS INT)
      , @DurationMin INT = TRY_CAST ((SELECT SettingValue FROM config.ApplicationSetting
                                       WHERE SettingKey = N'Authn.LockoutDurationMinutes' AND IsDeleted = 0) AS INT)
      , @BobId INT = (SELECT UserId FROM auth.[User] WHERE UserName = N'authtest.bob');

-- Exactly @Threshold failing exchanges for bob, all from one address nowhere near the ADDRESS threshold.  The threshold is
-- read from config rather than written as 5, because the experiment is "it fires on the configured number", not "it fires
-- on five" -- and an installation that retuned the setting should still pass this file.
WHILE @i <= @Threshold
BEGIN
    SET @Token = CRYPT_GEN_RANDOM (32);

    EXEC auth.uspGetLoginVerifier @ApplicationCode = N'AUTHTEST', @TenantCode = N'AUTHTEST_ACME'
       , @UserName = N'authtest.bob', @ClientAddress = N'198.51.100.20'
       , @LoginAttemptId = @AttemptId OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;

    BEGIN TRY
        EXEC auth.uspCompleteLogin @LoginAttemptId = @AttemptId, @PasswordVerified = 0, @SessionTokenHash = @Token
           , @UserSessionId = @SessionId OUTPUT, @UserId = @UserIdOut OUTPUT, @MustChangePassword = @MustChange OUTPUT
           , @AbsoluteExpiryUtc = @Abs OUTPUT, @IdleExpiryUtc = @Idle OUTPUT;
    END TRY
    BEGIN CATCH
        IF ERROR_NUMBER () <> 50106
        BEGIN
            INSERT #Observation (Section, Severity, Status, Item, Detail)
            VALUES (N'5 Account lockout', 2, 'DEFECT', N'Unexpected error while driving bob into lockout'
                  , CONCAT (N'Failure ', @i, N' of ', @Threshold, N' raised ', ERROR_NUMBER (), N' rather than 50106: '
                          , ERROR_MESSAGE ()));
        END;
    END CATCH;

    SET @i += 1;
END;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'5 Account lockout'
     , CASE WHEN u.IsLockedOut = 1 AND u.LockoutEndUtc IS NOT NULL
             AND DATEDIFF (MINUTE, SYSUTCDATETIME (), u.LockoutEndUtc) BETWEEN @DurationMin - 1 AND @DurationMin
            THEN 4 ELSE 1 END
     , CASE WHEN u.IsLockedOut = 1 AND u.LockoutEndUtc IS NOT NULL
             AND DATEDIFF (MINUTE, SYSUTCDATETIME (), u.LockoutEndUtc) BETWEEN @DurationMin - 1 AND @DurationMin
            THEN 'OK' ELSE 'VIOLATED' END
     , N'EXIT CRITERION: the lockout fires per ACCOUNT, on the threshold failure and not one later'
     , CONCAT (N'After exactly ', @Threshold, N' failures: IsLockedOut = ', u.IsLockedOut, N', LockoutEndUtc = '
             , COALESCE (CONVERT (NVARCHAR (30), u.LockoutEndUtc, 126), N'(null)'), N', which is '
             , COALESCE (CAST (DATEDIFF (MINUTE, SYSUTCDATETIME (), u.LockoutEndUtc) AS NVARCHAR (11)), N'?')
             , N' minute(s) ahead against a configured ', @DurationMin, N'. The attempt is concluded BEFORE it is '
             , N'counted, which is why the threshold and not the threshold plus one.')
  FROM auth.[User] AS u
 WHERE u.UserId = @BobId;

-- 5b.  The CORRECT password now.  This is the one case section 19.2 permits us to name, E-50115.
SET @Token = CRYPT_GEN_RANDOM (32);

EXEC auth.uspGetLoginVerifier @ApplicationCode = N'AUTHTEST', @TenantCode = N'AUTHTEST_ACME'
   , @UserName = N'authtest.bob', @ClientAddress = N'198.51.100.20'
   , @LoginAttemptId = @AttemptId OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;

-- Observe what just happened: a LOCKED account was issued its real verifier, without complaint.
INSERT #Observation (Section, Severity, Status, Item, Detail)
VALUES (N'5 Account lockout', CASE WHEN @Phc IS NOT NULL THEN 4 ELSE 2 END
      , CASE WHEN @Phc IS NOT NULL THEN 'OK' ELSE 'DEFECT' END
      , N'A locked account is still issued a verifier at round trip 1'
      , N'Deliberate. Refusing at round trip 1 would make "this name is locked out", and therefore "this name exists", '
      + N'free to anybody willing to ask twice. The lockout is enforced at round trip 2, after the caller has proved '
      + N'they hold the password, which is exactly what makes E-50115 safe to name in the UI.');

BEGIN TRY
    EXEC auth.uspCompleteLogin @LoginAttemptId = @AttemptId, @PasswordVerified = 1, @SessionTokenHash = @Token
       , @UserSessionId = @SessionId OUTPUT, @UserId = @UserIdOut OUTPUT, @MustChangePassword = @MustChange OUTPUT
       , @AbsoluteExpiryUtc = @Abs OUTPUT, @IdleExpiryUtc = @Idle OUTPUT;
END TRY
BEGIN CATCH
    SET @ErrAfterLock = ERROR_NUMBER ();
END CATCH;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'5 Account lockout'
     , CASE WHEN @ErrAfterLock = 50115 AND NOT EXISTS (SELECT 1 FROM auth.UserSession
                                                        WHERE LoginAttemptId = @AttemptId) THEN 4 ELSE 1 END
     , CASE WHEN @ErrAfterLock = 50115 AND NOT EXISTS (SELECT 1 FROM auth.UserSession
                                                        WHERE LoginAttemptId = @AttemptId) THEN 'OK' ELSE 'VIOLATED' END
     , N'A correct password on a locked account is refused E-50115 and issues no session'
     , CONCAT (N'Error ', COALESCE (CAST (@ErrAfterLock AS NVARCHAR (11)), N'(none raised)'), N', expected 50115. '
             , N'Sessions created by that exchange: '
             , (SELECT COUNT (*) FROM auth.UserSession WHERE LoginAttemptId = @AttemptId), N', expected 0.');

-- 5c.  INDEPENDENCE, DIRECTION 1: bob is locked, and alice -- from THE SAME address -- is untouched.
SET @Token = CRYPT_GEN_RANDOM (32);

EXEC auth.uspGetLoginVerifier @ApplicationCode = N'AUTHTEST', @TenantCode = N'AUTHTEST_ACME'
   , @UserName = N'authtest.alice', @ClientAddress = N'198.51.100.20'
   , @LoginAttemptId = @AttemptId OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;

EXEC auth.uspCompleteLogin @LoginAttemptId = @AttemptId, @PasswordVerified = 1, @SessionTokenHash = @Token
   , @UserSessionId = @SessionId OUTPUT, @UserId = @UserIdOut OUTPUT, @MustChangePassword = @MustChange OUTPUT
   , @AbsoluteExpiryUtc = @Abs OUTPUT, @IdleExpiryUtc = @Idle OUTPUT;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'5 Independence'
     , CASE WHEN @SessionId IS NOT NULL AND b.IsLockedOut = 1 THEN 4 ELSE 1 END
     , CASE WHEN @SessionId IS NOT NULL AND b.IsLockedOut = 1 THEN 'OK' ELSE 'VIOLATED' END
     , N'EXIT CRITERION: independence, direction 1 -- one account''s lock reaches no other account'
     , CONCAT (N'bob IsLockedOut = ', b.IsLockedOut, N' while alice signed in from THE SAME address, 198.51.100.20, '
             , N'and received session ', COALESCE (CAST (@SessionId AS NVARCHAR (20)), N'(none)'), N'. That address now '
             , N'carries ', @Threshold + 1, N' failures against an address threshold of 20, so the address arm has not '
             , N'fired and cannot be what is being observed here.')
  FROM auth.[User] AS b
 WHERE b.UserId = @BobId;
GO


-- *** 6. The per-address throttle, and that it is per ADDRESS ***
-- This section calls auth.uspRecordLoginFailure DIRECTLY rather than going through uspCompleteLogin with
-- @PasswordVerified = 0.  Both record the failure identically; only this one hands back the four counters, and the four
-- counters ARE the evidence for independence.  An experiment that inferred them from the lockout flag afterwards could
-- not tell "the address count reached twenty" from "the address count is not being taken at all".
DECLARE @i INT = 1, @AttemptId BIGINT, @Phc NVARCHAR (512), @Mfa BIT, @Token VARBINARY (32)
      , @SessionId BIGINT, @UserIdOut INT, @MustChange BIT, @Abs DATETIME2 (3), @Idle DATETIME2 (3)
      , @AcctCount INT, @AddrCount INT, @Locked BIT, @Throttled BIT, @ErrThrottled INT
      , @AddrThreshold INT = TRY_CAST ((SELECT SettingValue FROM config.ApplicationSetting
                                         WHERE SettingKey = N'Authn.AddressThreshold' AND IsDeleted = 0) AS INT)
      , @LockedBefore INT
      , @SwarmName NVARCHAR (256);   -- built into a variable per iteration: EXEC takes a constant or a variable, never
                                     -- an expression, so a CONCAT in the parameter position is a parse error (102).

SET @LockedBefore = (SELECT COUNT (*) FROM auth.[User]
                      WHERE UserName LIKE N'authtest.%' AND IsLockedOut = 1 AND IsDeleted = 0);

-- @AddrThreshold failures from one address, each against a DIFFERENT name nobody holds.  Different names on purpose: one
-- name repeated twenty times would lock that account at five and the address result would be unreadable underneath it.
WHILE @i <= @AddrThreshold
BEGIN
    SET @SwarmName = CONCAT (N'authtest.swarm.', @i);

    EXEC auth.uspGetLoginVerifier @ApplicationCode = N'AUTHTEST', @TenantCode = N'AUTHTEST_ACME'
       , @UserName = @SwarmName, @ClientAddress = N'198.51.100.30'
       , @LoginAttemptId = @AttemptId OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;

    EXEC auth.uspRecordLoginFailure @LoginAttemptId = @AttemptId, @FailureReason = 'PasswordMismatch'
       , @AccountFailureCount = @AcctCount OUTPUT, @AddressFailureCount = @AddrCount OUTPUT
       , @AccountLockedOut = @Locked OUTPUT, @AddressThrottled = @Throttled OUTPUT;

    SET @i += 1;
END;

INSERT #Observation (Section, Severity, Status, Item, Detail)
VALUES (N'6 Address throttle'
      , CASE WHEN @Throttled = 1 AND @Locked = 0 AND @AddrCount = @AddrThreshold AND @AcctCount = 1 THEN 4 ELSE 1 END
      , CASE WHEN @Throttled = 1 AND @Locked = 0 AND @AddrCount = @AddrThreshold AND @AcctCount = 1
             THEN 'OK' ELSE 'VIOLATED' END
      , N'EXIT CRITERION: the throttle fires per ADDRESS, on the configured count, locking nothing'
      , CONCAT (N'After ', @AddrThreshold, N' failures from 198.51.100.30 against ', @AddrThreshold, N' distinct names: '
              , N'@AddressFailureCount = ', @AddrCount, N' (threshold ', @AddrThreshold, N'), @AddressThrottled = '
              , @Throttled, N', @AccountFailureCount = ', @AcctCount, N' -- one each, which is why nothing locked -- and '
              , N'@AccountLockedOut = ', @Locked, N'. The address arm writes NO state anywhere: there is no table of '
              , N'addresses, only the count, so a throttle cannot be a denial of service that outlives its window.'));

-- Round trip 1 from that address is now refused outright, BEFORE any user lookup -- which is the point of putting the
-- address check first: a throttled address cannot be used to probe names either.
BEGIN TRY
    EXEC auth.uspGetLoginVerifier @ApplicationCode = N'AUTHTEST', @TenantCode = N'AUTHTEST_ACME'
       , @UserName = N'authtest.alice', @ClientAddress = N'198.51.100.30'
       , @LoginAttemptId = @AttemptId OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;
END TRY
BEGIN CATCH
    SET @ErrThrottled = ERROR_NUMBER ();
END CATCH;

INSERT #Observation (Section, Severity, Status, Item, Detail)
VALUES (N'6 Address throttle', CASE WHEN @ErrThrottled = 50116 THEN 4 ELSE 1 END
      , CASE WHEN @ErrThrottled = 50116 THEN 'OK' ELSE 'VIOLATED' END
      , N'A throttled address is refused at round trip 1, before the name is looked up'
      , CONCAT (N'Error ', COALESCE (CAST (@ErrThrottled AS NVARCHAR (11)), N'(none -- a verifier was issued)')
              , N', expected 50116. Note the name used was alice, who is a real, unlocked, usable account: the refusal '
              , N'is about the address and says nothing whatsoever about her.'));

-- 6b.  INDEPENDENCE, DIRECTION 2: the address is throttled, no account was locked by it, and alice signs in from
--      somewhere else during it.
SET @Token = CRYPT_GEN_RANDOM (32);

EXEC auth.uspGetLoginVerifier @ApplicationCode = N'AUTHTEST', @TenantCode = N'AUTHTEST_ACME'
   , @UserName = N'authtest.alice', @ClientAddress = N'198.51.100.10'
   , @LoginAttemptId = @AttemptId OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;

EXEC auth.uspCompleteLogin @LoginAttemptId = @AttemptId, @PasswordVerified = 1, @SessionTokenHash = @Token
   , @UserSessionId = @SessionId OUTPUT, @UserId = @UserIdOut OUTPUT, @MustChangePassword = @MustChange OUTPUT
   , @AbsoluteExpiryUtc = @Abs OUTPUT, @IdleExpiryUtc = @Idle OUTPUT;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'6 Independence'
     , CASE WHEN @SessionId IS NOT NULL AND COUNT (*) = @LockedBefore THEN 4 ELSE 1 END
     , CASE WHEN @SessionId IS NOT NULL AND COUNT (*) = @LockedBefore THEN 'OK' ELSE 'VIOLATED' END
     , N'EXIT CRITERION: independence, direction 2 -- an address throttle locks no account'
     , CONCAT (N'Locked fixture accounts before the twenty failures: ', @LockedBefore, N' (bob, from section 5). After: '
             , COUNT (*), N'. alice signed in from 198.51.100.10 while .30 was throttled and received session '
             , COALESCE (CAST (@SessionId AS NVARCHAR (20)), N'(none)')
             , N'. The two arms share no state but the clock, in both directions.')
  FROM auth.[User]
 WHERE UserName LIKE N'authtest.%' AND IsLockedOut = 1 AND IsDeleted = 0;
GO


-- *** 7. The second factor: the clock window, the replay refusal, and single-use recovery codes ***
DECLARE @AttemptId BIGINT, @Phc NVARCHAR (512), @Mfa BIT, @Satisfied BIT, @Err INT
      , @DaveId INT = (SELECT UserId FROM auth.[User] WHERE UserName = N'authtest.dave')
      , @StepSeconds INT = TRY_CAST ((SELECT SettingValue FROM config.ApplicationSetting
                                       WHERE SettingKey = N'Authn.TotpStepSeconds' AND IsDeleted = 0) AS INT)
      , @ServerStep BIGINT
      , @ErrFarStep INT, @ErrReplay INT, @ErrCodeReuse INT, @SatisfiedTotp BIT, @SatisfiedCode BIT
      , @CodeHash VARBINARY (32);

SET @ServerStep = DATEDIFF_BIG (SECOND, CAST (N'1970-01-01T00:00:00' AS DATETIME2 (0)), SYSUTCDATETIME ())
                / @StepSeconds;

-- Four hours ahead of the server, in steps.  A variable and not @ServerStep + 500 in the parameter position, for the
-- reason section 6 gives: EXEC takes a constant or a variable and nothing else.
DECLARE @FarStep BIGINT = @ServerStep + 500;

-- 7a.  A step from far outside the window.  The application claims it verified a code; the step says otherwise.
EXEC auth.uspGetLoginVerifier @ApplicationCode = N'AUTHTEST', @TenantCode = N'AUTHTEST_ACME'
   , @UserName = N'authtest.dave', @ClientAddress = N'198.51.100.40'
   , @LoginAttemptId = @AttemptId OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;

BEGIN TRY
    EXEC auth.uspVerifyMfa @LoginAttemptId = @AttemptId, @TimeStep = @FarStep
       , @MfaSatisfied = @Satisfied OUTPUT;
END TRY
BEGIN CATCH
    SET @ErrFarStep = ERROR_NUMBER ();
END CATCH;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'7 Second factor'
     , CASE WHEN @ErrFarStep = 50111 AND a.Outcome = 'Failure' AND COALESCE (a.MfaSatisfied, 0) = 0 THEN 4 ELSE 2 END
     , CASE WHEN @ErrFarStep = 50111 AND a.Outcome = 'Failure' AND COALESCE (a.MfaSatisfied, 0) = 0
            THEN 'OK' ELSE 'DEFECT' END
     , N'A time step outside the server''s window is refused E-50111 AND concludes the exchange'
     , CONCAT (N'Reported step ', @ServerStep + 500, N' against a server step near ', @ServerStep, N'. Error '
             , COALESCE (CAST (@ErrFarStep AS NVARCHAR (11)), N'(none)'), N', expected 50111. Exchange outcome '
             , a.Outcome, N', reason ', COALESCE (a.FailureReason, '(none)')
             , N'. Concluding it is what makes a million-value code space cost a million round trips that both throttles '
             , N'can see, instead of a million cheap tries inside one exchange window.')
  FROM auth.LoginAttempt AS a
 WHERE a.LoginAttemptId = @AttemptId;

-- 7b.  The current step, on a fresh exchange -- accepted -- and then ROUTE 3 OF 3, the platform-admin bypass.
EXEC auth.uspGetLoginVerifier @ApplicationCode = N'AUTHTEST', @TenantCode = N'AUTHTEST_ACME'
   , @UserName = N'authtest.dave', @ClientAddress = N'198.51.100.40'
   , @LoginAttemptId = @AttemptId OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;

EXEC auth.uspVerifyMfa @LoginAttemptId = @AttemptId, @TimeStep = @ServerStep, @MfaSatisfied = @SatisfiedTotp OUTPUT;

DECLARE @BypassSession BIGINT, @BypassUser INT, @BypassMustChange BIT, @BypassAbs DATETIME2 (3)
      , @BypassIdle DATETIME2 (3), @BypassToken VARBINARY (32) = CRYPT_GEN_RANDOM (32);

EXEC auth.uspCompleteLogin @LoginAttemptId = @AttemptId, @PasswordVerified = 1, @SessionTokenHash = @BypassToken
   , @IsBypassRoute = 1, @UserSessionId = @BypassSession OUTPUT, @UserId = @BypassUser OUTPUT
   , @MustChangePassword = @BypassMustChange OUTPUT, @AbsoluteExpiryUtc = @BypassAbs OUTPUT
   , @IdleExpiryUtc = @BypassIdle OUTPUT;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'7 Second factor'
     , CASE WHEN @SatisfiedTotp = 1 AND s.UserSessionId IS NOT NULL AND s.IsBypassRoute = 1 AND s.MfaSatisfied = 1
            THEN 4 ELSE 1 END
     , CASE WHEN @SatisfiedTotp = 1 AND s.UserSessionId IS NOT NULL AND s.IsBypassRoute = 1 AND s.MfaSatisfied = 1
            THEN 'OK' ELSE 'VIOLATED' END
     , N'EXIT CRITERION: route 3 of 3, the platform-admin bypass, authenticates -- with a factor (INV-08)'
     , CONCAT (N'Step ', @ServerStep, N' accepted, @MfaSatisfied = ', @SatisfiedTotp, N'. Session ', s.UserSessionId
             , N' for user ', s.UserId, N', method ', s.AuthenticationMethod, N', IsBypassRoute = ', s.IsBypassRoute
             , N', MfaSatisfied = ', s.MfaSatisfied
             , N'. dave holds IsPlatformAdmin = 1, which INV-09 requires before the route is even considered.')
  FROM auth.UserSession AS s
 WHERE s.LoginAttemptId = @AttemptId;

-- 7c.  THE REPLAY.  A new exchange, the same step -- the code an attacker read over a shoulder or out of a proxy log.
EXEC auth.uspGetLoginVerifier @ApplicationCode = N'AUTHTEST', @TenantCode = N'AUTHTEST_ACME'
   , @UserName = N'authtest.dave', @ClientAddress = N'198.51.100.40'
   , @LoginAttemptId = @AttemptId OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;

BEGIN TRY
    EXEC auth.uspVerifyMfa @LoginAttemptId = @AttemptId, @TimeStep = @ServerStep, @MfaSatisfied = @Satisfied OUTPUT;
END TRY
BEGIN CATCH
    SET @ErrReplay = ERROR_NUMBER ();
END CATCH;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'7 Second factor', CASE WHEN @ErrReplay = 50111 THEN 4 ELSE 2 END
     , CASE WHEN @ErrReplay = 50111 THEN 'OK' ELSE 'DEFECT' END
     , N'The same step replayed on a new exchange is refused E-50111, inside its own clock window'
     , CONCAT (N'Step ', @ServerStep, N' was accepted moments ago and is still within the server window, so the CLOCK '
             , N'check would pass it. Error ', COALESCE (CAST (@ErrReplay AS NVARCHAR (11)), N'(none -- it was ACCEPTED)')
             , N', expected 50111, which came from the second check: auth.UserMfaFactor.LastUsedTimeStep is now '
             , COALESCE (CAST (f.LastUsedTimeStep AS NVARCHAR (20)), N'(null)')
             , N' and a step must be strictly greater. Same number as the far-step refusal, deliberately.')
  FROM auth.UserMfaFactor AS f
 WHERE f.UserId = @DaveId AND f.IsDeleted = 0;

-- 7d.  A recovery code, then the SAME recovery code.  The hash is read out of the table because the fixture stands in
-- for a client that holds the plaintext -- the code itself never enters this file, for the same reason it never enters a
-- parameter list.
SELECT TOP (1) @CodeHash = r.CodeHash
  FROM auth.UserMfaRecoveryCode AS r
 WHERE r.UserId    = @DaveId
   AND r.UsedUtc   IS NULL
   AND r.IsDeleted = 0
 ORDER BY r.UserMfaRecoveryCodeId;

EXEC auth.uspGetLoginVerifier @ApplicationCode = N'AUTHTEST', @TenantCode = N'AUTHTEST_ACME'
   , @UserName = N'authtest.dave', @ClientAddress = N'198.51.100.40'
   , @LoginAttemptId = @AttemptId OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;

EXEC auth.uspVerifyMfa @LoginAttemptId = @AttemptId, @RecoveryCodeHash = @CodeHash
   , @MfaSatisfied = @SatisfiedCode OUTPUT;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'7 Second factor'
     , CASE WHEN @SatisfiedCode = 1 AND r.UsedUtc IS NOT NULL THEN 4 ELSE 2 END
     , CASE WHEN @SatisfiedCode = 1 AND r.UsedUtc IS NOT NULL THEN 'OK' ELSE 'DEFECT' END
     , N'A recovery code satisfies the second factor and is spent at that moment'
     , CONCAT (N'@MfaSatisfied = ', @SatisfiedCode, N'. UsedUtc = '
             , COALESCE (CONVERT (NVARCHAR (30), r.UsedUtc, 126), N'(still null)')
             , N', stamped by uspVerifyMfa and not by uspCompleteLogin: a code that is only spent once the whole sign-in '
             , N'succeeds can be presented, observed to work, and presented again. '
             , (SELECT COUNT (*) FROM auth.UserMfaRecoveryCode
                 WHERE UserId = @DaveId AND UsedUtc IS NULL AND IsDeleted = 0), N' unused code(s) remain of 4.')
  FROM auth.UserMfaRecoveryCode AS r
 WHERE r.UserId = @DaveId AND r.CodeHash = @CodeHash AND r.IsDeleted = 0;

EXEC auth.uspGetLoginVerifier @ApplicationCode = N'AUTHTEST', @TenantCode = N'AUTHTEST_ACME'
   , @UserName = N'authtest.dave', @ClientAddress = N'198.51.100.40'
   , @LoginAttemptId = @AttemptId OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;

BEGIN TRY
    EXEC auth.uspVerifyMfa @LoginAttemptId = @AttemptId, @RecoveryCodeHash = @CodeHash
       , @MfaSatisfied = @Satisfied OUTPUT;
END TRY
BEGIN CATCH
    SET @ErrCodeReuse = ERROR_NUMBER ();
END CATCH;

INSERT #Observation (Section, Severity, Status, Item, Detail)
VALUES (N'7 Second factor', CASE WHEN @ErrCodeReuse = 50112 THEN 4 ELSE 2 END
      , CASE WHEN @ErrCodeReuse = 50112 THEN 'OK' ELSE 'DEFECT' END
      , N'The same recovery code a second time is refused E-50112 -- as is one that never existed'
      , CONCAT (N'Error ', COALESCE (CAST (@ErrCodeReuse AS NVARCHAR (11)), N'(none -- it was ACCEPTED AGAIN)')
              , N', expected 50112. A spent code and a code that never existed give the same answer on purpose: the '
              , N'difference would tell somebody holding a leaked list which entries are still worth trying.'));
GO


-- *** 8. INV-08 and INV-09: the bypass route refuses, in the procedure and at the table ***
DECLARE @AttemptId BIGINT, @Phc NVARCHAR (512), @Mfa BIT, @Token VARBINARY (32)
      , @SessionId BIGINT, @UserIdOut INT, @MustChange BIT, @Abs DATETIME2 (3), @Idle DATETIME2 (3)
      , @ErrNoFactor INT, @ErrNotAdmin INT, @ErrTable INT, @BypassAttempt BIGINT
      , @DaveId INT = (SELECT UserId FROM auth.[User] WHERE UserName = N'authtest.dave')
      , @AppId  INT = (SELECT ApplicationId FROM auth.Application WHERE ApplicationCode = N'AUTHTEST');

-- 8a.  dave IS a platform administrator and DOES hold a confirmed factor -- but this exchange never satisfied it.
SET @Token = CRYPT_GEN_RANDOM (32);

EXEC auth.uspGetLoginVerifier @ApplicationCode = N'AUTHTEST', @TenantCode = N'AUTHTEST_ACME'
   , @UserName = N'authtest.dave', @ClientAddress = N'198.51.100.40'
   , @LoginAttemptId = @AttemptId OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;

SET @BypassAttempt = @AttemptId;

BEGIN TRY
    EXEC auth.uspCompleteLogin @LoginAttemptId = @AttemptId, @PasswordVerified = 1, @SessionTokenHash = @Token
       , @IsBypassRoute = 1, @UserSessionId = @SessionId OUTPUT, @UserId = @UserIdOut OUTPUT
       , @MustChangePassword = @MustChange OUTPUT, @AbsoluteExpiryUtc = @Abs OUTPUT, @IdleExpiryUtc = @Idle OUTPUT;
END TRY
BEGIN CATCH
    SET @ErrNoFactor = ERROR_NUMBER ();
END CATCH;

INSERT #Observation (Section, Severity, Status, Item, Detail)
VALUES (N'8 INV-08', CASE WHEN @ErrNoFactor = 50107 THEN 4 ELSE 1 END
      , CASE WHEN @ErrNoFactor = 50107 THEN 'OK' ELSE 'VIOLATED' END
      , N'INV-08: the bypass route with a CORRECT password and no second factor is refused E-50107'
      , CONCAT (N'Error ', COALESCE (CAST (@ErrNoFactor AS NVARCHAR (11)), N'(none -- a bypass session was ISSUED)')
              , N', expected 50107. dave is a platform administrator and holds a confirmed factor; what this exchange '
              , N'lacks is auth.LoginAttempt.MfaSatisfied, which only uspVerifyMfa writes. The tenant policy has '
              , N'RequireMfaForLocal = 0 and cannot relax this: INV-08 is about the route, not the tenant.'));

-- 8b.  alice has no factor either, and is not a platform administrator.  Which refusal comes first says which check the
--      system considers the more fundamental -- and E-50108 first is the right order: the route is not hers to take.
SET @Token = CRYPT_GEN_RANDOM (32);

EXEC auth.uspGetLoginVerifier @ApplicationCode = N'AUTHTEST', @TenantCode = N'AUTHTEST_ACME'
   , @UserName = N'authtest.alice', @ClientAddress = N'198.51.100.10'
   , @LoginAttemptId = @AttemptId OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;

BEGIN TRY
    EXEC auth.uspCompleteLogin @LoginAttemptId = @AttemptId, @PasswordVerified = 1, @SessionTokenHash = @Token
       , @IsBypassRoute = 1, @UserSessionId = @SessionId OUTPUT, @UserId = @UserIdOut OUTPUT
       , @MustChangePassword = @MustChange OUTPUT, @AbsoluteExpiryUtc = @Abs OUTPUT, @IdleExpiryUtc = @Idle OUTPUT;
END TRY
BEGIN CATCH
    SET @ErrNotAdmin = ERROR_NUMBER ();
END CATCH;

INSERT #Observation (Section, Severity, Status, Item, Detail)
VALUES (N'8 INV-09', CASE WHEN @ErrNotAdmin = 50108 THEN 4 ELSE 1 END
      , CASE WHEN @ErrNotAdmin = 50108 THEN 'OK' ELSE 'VIOLATED' END
      , N'INV-09: the bypass route taken by a non-administrator is refused E-50108, and that check comes first'
      , CONCAT (N'Error ', COALESCE (CAST (@ErrNotAdmin AS NVARCHAR (11)), N'(none -- a bypass session was ISSUED)')
              , N', expected 50108 and not 50107. alice fails BOTH tests -- not an administrator, no factor -- and the '
              , N'number she gets is the administrator one, because "this route is not yours" is the more fundamental '
              , N'refusal. Both flatten to the same message on screen (UI-26), so the ordering costs her nothing.'));

-- 8c.  INV-08 AT THE TABLE.  The procedure is not the only thing standing between a bypass session and no second factor:
--      a CHECK constraint says the same thing, so a future procedure, an ad-hoc fix, or a migration cannot quietly
--      create the row the procedures refuse to.  This inserts directly, as db_owner, and expects 547.
BEGIN TRY
    INSERT auth.UserSession
        (UserId, LoginAttemptId, ApplicationId, SessionTokenHash, ClientAddress, AuthenticationMethod
       , IsBypassRoute, MfaSatisfied, StartedUtc, LastSeenUtc, AbsoluteExpiryUtc, IdleExpiryUtc
       , auditCreatedBy, auditModifiedBy)
    VALUES (@DaveId, @BypassAttempt, @AppId, CRYPT_GEN_RANDOM (32), N'198.51.100.40', 'LocalPassword'
          , 1, 0, SYSUTCDATETIME (), SYSUTCDATETIME (), DATEADD (MINUTE, 60, SYSUTCDATETIME ())
          , DATEADD (MINUTE, 15, SYSUTCDATETIME ())
          , N'_tests/040_identity_and_authn.sql', N'_tests/040_identity_and_authn.sql');
END TRY
BEGIN CATCH
    SET @ErrTable = ERROR_NUMBER ();
END CATCH;

INSERT #Observation (Section, Severity, Status, Item, Detail)
VALUES (N'8 INV-08', CASE WHEN @ErrTable = 547 THEN 4 ELSE 1 END
      , CASE WHEN @ErrTable = 547 THEN 'OK' ELSE 'VIOLATED' END
      , N'INV-08 is also a CHECK constraint: a bypass session with MfaSatisfied = 0 cannot be inserted at all'
      , CONCAT (N'Direct INSERT as db_owner raised ', COALESCE (CAST (@ErrTable AS NVARCHAR (11)), N'nothing -- THE ROW '
              + N'WAS ACCEPTED'), N', expected 547 (constraint violation). This is the difference between an invariant '
              , N'and a convention: the procedures could all be rewritten tomorrow and this row would still be '
              , N'impossible. Nothing was inserted, so there is nothing to clean up.'));
GO


-- *** 9. The federated route, and INV-07 ***
DECLARE @AttemptId BIGINT, @Token VARBINARY (32), @SessionId BIGINT, @UserIdOut INT, @MustChange BIT
      , @Abs DATETIME2 (3), @Idle DATETIME2 (3)
      , @ErrWrongSubject INT, @ErrAtRoot INT
      , @Issuer   NVARCHAR (512) = N'https://idp.authtest.invalid/authtest/v2.0'
      , @SubjErin NVARCHAR (256) = N'SUBJECT-ERIN-0000000000000000000000000'
      , @SubjNone NVARCHAR (256) = N'SUBJECT-NOBODY-00000000000000000000000'
      , @ErinId   INT            = (SELECT UserId FROM auth.[User] WHERE UserName = N'authtest.erin');

-- 9a.  ROUTE 2 OF 3.  Note that erin has no auth.UserCredential row at all -- there is no password to be wrong.
SET @Token = CRYPT_GEN_RANDOM (32);

EXEC auth.uspBeginSsoLogin @ApplicationCode = N'AUTHTEST', @TenantCode = N'AUTHTEST_ACME'
   , @ClientAddress = N'198.51.100.50', @UserAgent = N'_tests/040'
   , @LoginAttemptId = @AttemptId OUTPUT;

EXEC auth.uspCompleteSsoLogin @LoginAttemptId = @AttemptId, @Issuer = @Issuer, @SubjectId = @SubjErin
   , @SessionTokenHash = @Token, @UserSessionId = @SessionId OUTPUT, @UserId = @UserIdOut OUTPUT
   , @MustChangePassword = @MustChange OUTPUT, @AbsoluteExpiryUtc = @Abs OUTPUT, @IdleExpiryUtc = @Idle OUTPUT;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'9 Federated route'
     , CASE WHEN s.UserSessionId IS NOT NULL AND @UserIdOut = @ErinId AND s.AuthenticationMethod = 'Federated'
             AND a.Outcome = 'Success' AND a.UserId = @ErinId
             AND NOT EXISTS (SELECT 1 FROM auth.UserCredential WHERE UserId = @ErinId AND IsDeleted = 0)
            THEN 4 ELSE 1 END
     , CASE WHEN s.UserSessionId IS NOT NULL AND @UserIdOut = @ErinId AND s.AuthenticationMethod = 'Federated'
             AND a.Outcome = 'Success' THEN 'OK' ELSE 'VIOLATED' END
     , N'EXIT CRITERION: route 2 of 3, the federated route, authenticates'
     , CONCAT (N'Session ', s.UserSessionId, N' for user ', s.UserId, N', method ', s.AuthenticationMethod
             , N'. Credential rows for erin: '
             , (SELECT COUNT (*) FROM auth.UserCredential WHERE UserId = @ErinId AND IsDeleted = 0)
             , N' -- she has no password, so nothing about this route can be a password check in disguise. The exchange '
             , N'recorded UserName ', a.UserName, N', which stays as it began: it is immutable, and at round trip 1 the '
             , N'identity provider had not yet said who this was.')
  FROM auth.UserSession  AS s
  JOIN auth.LoginAttempt AS a ON a.LoginAttemptId = s.LoginAttemptId
 WHERE s.UserSessionId = @SessionId;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'9 INV-07'
     , CASE WHEN f.LastSeenUtc IS NOT NULL THEN 4 ELSE 2 END
     , CASE WHEN f.LastSeenUtc IS NOT NULL THEN 'OK' ELSE 'DEFECT' END
     , N'INV-07: the link was matched on (Issuer, SubjectId) and stamped LastSeenUtc'
     , CONCAT (N'Link ', f.UserFederatedIdentityId, N' for issuer ', f.Issuer, N', LastSeenUtc = '
             , COALESCE (CONVERT (NVARCHAR (30), f.LastSeenUtc, 126), N'(still null)')
             , N'. uspCompleteSsoLogin is the only writer of that column, and its parameter list contains no email '
             , N'parameter at all -- checked against sys.parameters in 110_auth_authn_procedures.sql''s own report, '
             , N'which is the check that survives somebody adding one later.')
  FROM auth.UserFederatedIdentity AS f
 WHERE f.Issuer = @Issuer AND f.SubjectId = @SubjErin AND f.IsDeleted = 0;

-- 9b.  A subject the database has never seen.  NOT an auto-enrolment: a template that creates an account because an
--      identity provider asserted one is a template where the provider is the account store.
SET @Token = CRYPT_GEN_RANDOM (32);

EXEC auth.uspBeginSsoLogin @ApplicationCode = N'AUTHTEST', @TenantCode = N'AUTHTEST_ACME'
   , @ClientAddress = N'198.51.100.50', @LoginAttemptId = @AttemptId OUTPUT;

BEGIN TRY
    EXEC auth.uspCompleteSsoLogin @LoginAttemptId = @AttemptId, @Issuer = @Issuer, @SubjectId = @SubjNone
       , @SessionTokenHash = @Token, @UserSessionId = @SessionId OUTPUT, @UserId = @UserIdOut OUTPUT
       , @MustChangePassword = @MustChange OUTPUT, @AbsoluteExpiryUtc = @Abs OUTPUT, @IdleExpiryUtc = @Idle OUTPUT;
END TRY
BEGIN CATCH
    SET @ErrWrongSubject = ERROR_NUMBER ();
END CATCH;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'9 INV-07'
     , CASE WHEN @ErrWrongSubject = 50113 AND NOT EXISTS (SELECT 1 FROM auth.[User]
                                                           WHERE UserName = N'(sso pending)') THEN 4 ELSE 1 END
     , CASE WHEN @ErrWrongSubject = 50113 AND NOT EXISTS (SELECT 1 FROM auth.[User]
                                                           WHERE UserName = N'(sso pending)') THEN 'OK' ELSE 'VIOLATED' END
     , N'INV-07: an unlinked subject is refused E-50113 and enrols nobody'
     , CONCAT (N'Error ', COALESCE (CAST (@ErrWrongSubject AS NVARCHAR (11)), N'(none -- a session was ISSUED)')
             , N', expected 50113. Users created by that call: '
             , (SELECT COUNT (*) FROM auth.[User] WHERE UserName = N'(sso pending)')
             , N', expected 0. The subject differs from erin''s by a few characters and the email claim was never asked '
             , N'for, so there is no path by which a similar address could have matched her.');

-- 9c.  The same call, scoped to the root tenant, which carries no policy.  AllowFederated resolves to NOTHING, and the
--      procedure reads nothing as a refusal -- which is the asymmetry this file exists to demonstrate.
BEGIN TRY
    EXEC auth.uspBeginSsoLogin @ApplicationCode = N'AUTHTEST', @TenantCode = N'AUTHTEST_ROOT'
       , @ClientAddress = N'198.51.100.50', @LoginAttemptId = @AttemptId OUTPUT;
END TRY
BEGIN CATCH
    SET @ErrAtRoot = ERROR_NUMBER ();
END CATCH;

INSERT #Observation (Section, Severity, Status, Item, Detail)
VALUES (N'9 Federated route', CASE WHEN @ErrAtRoot = 50104 THEN 4 ELSE 2 END
      , CASE WHEN @ErrAtRoot = 50104 THEN 'OK' ELSE 'DEFECT' END
      , N'Federation under a tenant with no policy is refused E-50104 -- the default is closed'
      , CONCAT (N'Error ', COALESCE (CAST (@ErrAtRoot AS NVARCHAR (11)), N'(none -- an SSO exchange was BEGUN)')
              , N', expected 50104. The two policy defaults are deliberately asymmetric: AllowLocalPassword falls back '
              , N'to 1, because a password needs only a credential row that somebody already created, while '
              , N'AllowFederated falls back to 0, because federation needs an identity provider somebody configured '
              , N'and trusted. The same tenant that permits alice a password refuses erin a federation.'));
GO


-- *** 10. The accounts that cannot sign in, and the policy that cannot be satisfied ***
DECLARE @AttemptId BIGINT, @Phc NVARCHAR (512), @Mfa BIT, @Token VARBINARY (32)
      , @SessionId BIGINT, @UserIdOut INT, @MustChange BIT, @Abs DATETIME2 (3), @Idle DATETIME2 (3)
      , @ErrCarol INT, @ErrFrank INT, @MfaFlagged BIT
      , @AcmeId INT = (SELECT t.TenantId FROM auth.Tenant AS t
                         JOIN auth.Application AS ap ON ap.ApplicationId = t.ApplicationId
                        WHERE ap.ApplicationCode = N'AUTHTEST' AND t.TenantCode = N'AUTHTEST_ACME');

-- 10a.  carol is IsActive = 0 and her password is right.  E-50115, the same number a locked account gets, because the
--       caller does not need to know which of the two it was -- and a service desk reading logs.AuthenticationEvent does.
SET @Token = CRYPT_GEN_RANDOM (32);

EXEC auth.uspGetLoginVerifier @ApplicationCode = N'AUTHTEST', @TenantCode = N'AUTHTEST_ACME'
   , @UserName = N'authtest.carol', @ClientAddress = N'198.51.100.60'
   , @LoginAttemptId = @AttemptId OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;

BEGIN TRY
    EXEC auth.uspCompleteLogin @LoginAttemptId = @AttemptId, @PasswordVerified = 1, @SessionTokenHash = @Token
       , @UserSessionId = @SessionId OUTPUT, @UserId = @UserIdOut OUTPUT, @MustChangePassword = @MustChange OUTPUT
       , @AbsoluteExpiryUtc = @Abs OUTPUT, @IdleExpiryUtc = @Idle OUTPUT;
END TRY
BEGIN CATCH
    SET @ErrCarol = ERROR_NUMBER ();
END CATCH;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'10 Unusable accounts'
     , CASE WHEN @ErrCarol = 50115 AND u.IsLockedOut = 0 THEN 4 ELSE 2 END
     , CASE WHEN @ErrCarol = 50115 AND u.IsLockedOut = 0 THEN 'OK' ELSE 'DEFECT' END
     , N'A deactivated account with the CORRECT password is refused E-50115'
     , CONCAT (N'Error ', COALESCE (CAST (@ErrCarol AS NVARCHAR (11)), N'(none -- a session was ISSUED)')
             , N', expected 50115, with IsActive = ', u.IsActive, N' and IsLockedOut = ', u.IsLockedOut
             , N' -- so this is auth.udfIsUserUsable refusing, not the lockout, and the same number covers both. She was '
             , N'still issued a verifier at round trip 1, for the reason section 5 gives.')
  FROM auth.[User] AS u
 WHERE u.UserName = N'authtest.carol';

-- 10b.  frank under a policy that requires a factor he has not got.  The tenant policy is flipped for this one
--       experiment and restored immediately -- and restored OUTSIDE the TRY, so a failure cannot leave it flipped.
UPDATE auth.TenantAuthenticationPolicy
   SET RequireMfaForLocal = 1
     , auditModifiedBy    = N'_tests/040_identity_and_authn.sql'
 WHERE TenantId = @AcmeId AND IsDeleted = 0;

SET @Token = CRYPT_GEN_RANDOM (32);

EXEC auth.uspGetLoginVerifier @ApplicationCode = N'AUTHTEST', @TenantCode = N'AUTHTEST_ACME'
   , @UserName = N'authtest.frank', @ClientAddress = N'198.51.100.60'
   , @LoginAttemptId = @AttemptId OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @MfaFlagged OUTPUT;

BEGIN TRY
    EXEC auth.uspCompleteLogin @LoginAttemptId = @AttemptId, @PasswordVerified = 1, @SessionTokenHash = @Token
       , @UserSessionId = @SessionId OUTPUT, @UserId = @UserIdOut OUTPUT, @MustChangePassword = @MustChange OUTPUT
       , @AbsoluteExpiryUtc = @Abs OUTPUT, @IdleExpiryUtc = @Idle OUTPUT;
END TRY
BEGIN CATCH
    SET @ErrFrank = ERROR_NUMBER ();
END CATCH;

UPDATE auth.TenantAuthenticationPolicy
   SET RequireMfaForLocal = 0
     , auditModifiedBy    = N'_tests/040_identity_and_authn.sql'
 WHERE TenantId = @AcmeId AND IsDeleted = 0;

INSERT #Observation (Section, Severity, Status, Item, Detail)
VALUES (N'10 Unusable accounts', CASE WHEN @ErrFrank = 50109 AND @MfaFlagged = 1 THEN 4 ELSE 2 END
      , CASE WHEN @ErrFrank = 50109 AND @MfaFlagged = 1 THEN 'OK' ELSE 'DEFECT' END
      , N'A policy requiring MFA refuses an account that HAS no factor -- E-50109, and round trip 1 says so in advance'
      , CONCAT (N'@RequiresMfa at round trip 1 = ', @MfaFlagged, N', which is the flag a UI uses to decide whether to '
              , N'ask for a code at all. Error at round trip 2: '
              , COALESCE (CAST (@ErrFrank AS NVARCHAR (11)), N'(none -- a session was ISSUED)'), N', expected 50109. '
              , N'This used to be a dead end -- frank could not get out of it and nobody could get him out of it, '
              , N'because enrolment was T-041 and T-041 was blocked by G-07. It is now the FIRST HALF of a round trip: '
              , N'the refused attempt row this experiment just wrote is itself the proof of identity that '
              , N'auth.uspEnrolMfaFactor accepts, and section 12 walks frank the rest of the way to a session.'));
GO


-- *** 11. Ending a session, and the exchange window ***
DECLARE @AttemptId BIGINT, @Phc NVARCHAR (512), @Mfa BIT, @Token VARBINARY (32) = CRYPT_GEN_RANDOM (32)
      , @SessionId BIGINT, @UserIdOut INT, @MustChange BIT, @Abs DATETIME2 (3), @Idle DATETIME2 (3)
      , @Ended INT, @EndedAgain INT, @ErrEndAgain INT, @ErrWriteOnce INT, @ErrExpired INT
      , @AliceId INT = (SELECT UserId FROM auth.[User] WHERE UserName = N'authtest.alice')
      , @LiveBefore INT, @Timeout NVARCHAR (100);

EXEC auth.uspGetLoginVerifier @ApplicationCode = N'AUTHTEST', @TenantCode = N'AUTHTEST_ACME'
   , @UserName = N'authtest.alice', @ClientAddress = N'198.51.100.10'
   , @LoginAttemptId = @AttemptId OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;

EXEC auth.uspCompleteLogin @LoginAttemptId = @AttemptId, @PasswordVerified = 1, @SessionTokenHash = @Token
   , @UserSessionId = @SessionId OUTPUT, @UserId = @UserIdOut OUTPUT, @MustChangePassword = @MustChange OUTPUT
   , @AbsoluteExpiryUtc = @Abs OUTPUT, @IdleExpiryUtc = @Idle OUTPUT;

-- 11a.  Sign out, then sign out again.  The second call is what a person clicking the button twice produces.
EXEC auth.uspEndSession @SessionTokenHash = @Token, @EndReason = 'SignedOut', @SessionsEnded = @Ended OUTPUT;

BEGIN TRY
    EXEC auth.uspEndSession @SessionTokenHash = @Token, @EndReason = 'SignedOut'
       , @SessionsEnded = @EndedAgain OUTPUT;
END TRY
BEGIN CATCH
    SET @ErrEndAgain = ERROR_NUMBER ();
END CATCH;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'11 Sessions'
     , CASE WHEN @Ended = 1 AND @ErrEndAgain = 50114 AND s.EndedUtc IS NOT NULL AND s.EndReason = 'SignedOut'
            THEN 4 ELSE 2 END
     , CASE WHEN @Ended = 1 AND @ErrEndAgain = 50114 AND s.EndedUtc IS NOT NULL THEN 'OK' ELSE 'DEFECT' END
     , N'A session ends once by token hash; the second call finds nothing and raises E-50114'
     , CONCAT (N'First call ended ', @Ended, N' session(s); session ', s.UserSessionId, N' now carries EndedUtc '
             , CONVERT (NVARCHAR (30), s.EndedUtc, 126), N' and EndReason ', s.EndReason, N'. Second call: error '
             , COALESCE (CAST (@ErrEndAgain AS NVARCHAR (11)), N'(none)'), N', expected 50114. A handler should treat '
             , N'that number as success -- somebody clicked sign out twice -- which is why it is documented rather than '
             , N'swallowed here.')
  FROM auth.UserSession AS s
 WHERE s.UserSessionId = @SessionId;

-- 11b.  Ending everything one user has.  alice has accumulated live sessions across this file; all of them go.
SET @LiveBefore = (SELECT COUNT (*) FROM auth.UserSession
                    WHERE UserId = @AliceId AND EndedUtc IS NULL AND IsDeleted = 0);

EXEC auth.uspEndSession @UserId = @AliceId, @EndReason = 'Revoked', @SessionsEnded = @Ended OUTPUT;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'11 Sessions'
     , CASE WHEN @Ended = @LiveBefore AND @LiveBefore > 1 AND COUNT (*) = 0 THEN 4 ELSE 2 END
     , CASE WHEN @Ended = @LiveBefore AND @LiveBefore > 1 AND COUNT (*) = 0 THEN 'OK' ELSE 'DEFECT' END
     , N'Ending by user ends every live session that user holds, in one statement'
     , CONCAT (@LiveBefore, N' live session(s) before, @SessionsEnded = ', @Ended, N', live after: ', COUNT (*)
             , N'. One UPDATE ... OUTPUT drives all three of the procedure''s routes, which is what makes them all '
             , N'idempotent for the same reason rather than three reasons. EndReason Revoked rather than SignedOut, so '
             , N'the audit trail distinguishes "the user left" from "somebody took the session away".')
  FROM auth.UserSession
 WHERE UserId = @AliceId AND EndedUtc IS NULL AND IsDeleted = 0;

-- 11c.  An ended session cannot be un-ended, moved, or re-ended -- not by a procedure, and not by db_owner either.
BEGIN TRY
    UPDATE auth.UserSession
       SET EndedUtc        = DATEADD (MINUTE, 1, EndedUtc)
         , auditModifiedBy = N'_tests/040_identity_and_authn.sql'
     WHERE UserSessionId = @SessionId;
END TRY
BEGIN CATCH
    SET @ErrWriteOnce = ERROR_NUMBER ();
END CATCH;

INSERT #Observation (Section, Severity, Status, Item, Detail)
VALUES (N'11 Sessions', CASE WHEN @ErrWriteOnce = 50010 THEN 4 ELSE 2 END
      , CASE WHEN @ErrWriteOnce = 50010 THEN 'OK' ELSE 'DEFECT' END
      , N'auth.UserSession.EndedUtc is write-once at the trigger -- E-50010'
      , CONCAT (N'A direct UPDATE as db_owner raised '
              , COALESCE (CAST (@ErrWriteOnce AS NVARCHAR (11)), N'nothing -- THE END TIME WAS MOVED')
              , N', expected 50010. A session that can be un-ended can be resurrected by one UPDATE after a sign-out, a '
              , N'revoke, or an incident response, and the ended row is the evidence that it ended.'));

-- 11d.  THE EXCHANGE WINDOW, without waiting five minutes for it.  The setting goes to -1 for exactly one exchange,
--       which makes every exchange already older than its own timeout, and is restored OUTSIDE the TRY.
SET @Timeout = (SELECT SettingValue FROM config.ApplicationSetting
                 WHERE SettingKey = N'Authn.LoginExchangeTimeoutSeconds' AND IsDeleted = 0);

SET @Token = CRYPT_GEN_RANDOM (32);

EXEC auth.uspGetLoginVerifier @ApplicationCode = N'AUTHTEST', @TenantCode = N'AUTHTEST_ACME'
   , @UserName = N'authtest.alice', @ClientAddress = N'198.51.100.10'
   , @LoginAttemptId = @AttemptId OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;

UPDATE config.ApplicationSetting
   SET SettingValue    = N'-1'
     , auditModifiedBy = N'_tests/040_identity_and_authn.sql'
 WHERE SettingKey = N'Authn.LoginExchangeTimeoutSeconds' AND IsDeleted = 0;

BEGIN TRY
    EXEC auth.uspCompleteLogin @LoginAttemptId = @AttemptId, @PasswordVerified = 1, @SessionTokenHash = @Token
       , @UserSessionId = @SessionId OUTPUT, @UserId = @UserIdOut OUTPUT, @MustChangePassword = @MustChange OUTPUT
       , @AbsoluteExpiryUtc = @Abs OUTPUT, @IdleExpiryUtc = @Idle OUTPUT;
END TRY
BEGIN CATCH
    SET @ErrExpired = ERROR_NUMBER ();
END CATCH;

UPDATE config.ApplicationSetting
   SET SettingValue    = @Timeout
     , auditModifiedBy = N'_tests/040_identity_and_authn.sql'
 WHERE SettingKey = N'Authn.LoginExchangeTimeoutSeconds' AND IsDeleted = 0;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'11 Exchange window'
     , CASE WHEN @ErrExpired = 50105 AND a.Outcome = 'Failure' AND a.FailureReason = 'ExchangeExpired'
             AND (SELECT SettingValue FROM config.ApplicationSetting
                   WHERE SettingKey = N'Authn.LoginExchangeTimeoutSeconds' AND IsDeleted = 0) = @Timeout
            THEN 4 ELSE 2 END
     , CASE WHEN @ErrExpired = 50105 AND a.Outcome = 'Failure' AND a.FailureReason = 'ExchangeExpired'
            THEN 'OK' ELSE 'DEFECT' END
     , N'An exchange older than Authn.LoginExchangeTimeoutSeconds is refused E-50105 and concluded'
     , CONCAT (N'Error ', COALESCE (CAST (@ErrExpired AS NVARCHAR (11)), N'(none -- a session was ISSUED)')
             , N', expected 50105. Outcome ', a.Outcome, N', reason ', COALESCE (a.FailureReason, '(none)')
             , N'. The setting is back at ', (SELECT SettingValue FROM config.ApplicationSetting
                                               WHERE SettingKey = N'Authn.LoginExchangeTimeoutSeconds'
                                                 AND IsDeleted  = 0)
             , N', from ', @Timeout, N'. Concluding an expired exchange rather than leaving it pending matters: a '
             , N'pending row that never concludes is a row neither throttle ever counts.')
  FROM auth.LoginAttempt AS a
 WHERE a.LoginAttemptId = @AttemptId;
GO


-- *** 12. MFA enrolment: the way out of E-50109, and the key label that never leaves the database's sight ***
-- This section exists because of the account it rescues.  Section 10b leaves frank refused with E-50109 -- a policy that
-- requires a second factor, an account that has none -- and until T-041 that was terminal: nothing in the database could
-- give him one, so the policy was unsatisfiable by construction.  What closed it was not code but a DECISION (gap G-07):
-- the secret is encrypted by the APPLICATION, under a key this server never holds, and the database stores opaque bytes
-- plus the NAME of the key that made them.  Everything below follows from that split.
--
-- So the experiments here divide cleanly in two, and the division is the point:
--
--   *  What the database can prove.  Who is enrolling, that exactly one proof of identity was offered, that the key
--      LABEL is the current one, that a confirmed factor is never silently replaced, that a confirmation is bounded by
--      the same clock window a sign-in is, that a batch of recovery codes is well formed, that a re-key moves the label
--      and the bytes together and resets the replay high-water mark.  All of that is asserted below.
--   *  What it cannot, and does not pretend to.  That @SecretCiphertext is a real AES-GCM envelope of a real TOTP
--      secret.  Every ciphertext here is CRYPT_GEN_RANDOM, and under the G-07 decision that is not a weaker test of
--      the database -- it is the SAME test, because the database's only claims about those bytes are their length and
--      their label.  The .NET harness is where wrapping and unwrapping are exercised.
--
-- THE BOOTSTRAP PARADOX, AND WHY THE ANSWER IS NOT A NEW PERMISSION.  frank must prove who he is in order to enrol, and
-- the only proof he can produce is a sign-in that was REFUSED.  auth.udfResolveEnrolmentActor accepts exactly that row
-- and nothing else: a Failure whose reason is 'MfaRequired', on which the database itself wrote PasswordVerified = 1,
-- inside Authn.MfaEnrolmentWindowSeconds.  That is an IDENTITY and not a permission, which is why the procedures still
-- refuse an account that already holds a confirmed factor (E-50119) -- the window is a route to a FIRST factor only, and
-- setting it to 0 closes the route with no code change.  12b, 12d and 12i are the three halves of that argument.
DECLARE @T0                 DATETIME2 (3)  = SYSUTCDATETIME ()
      , @Actor              NVARCHAR (255) = N'_tests/040_identity_and_authn.sql'
      , @FrankId            INT            = (SELECT UserId FROM auth.[User] WHERE UserName = N'authtest.frank')
      , @AcmeId             INT            = (SELECT t.TenantId FROM auth.Tenant AS t
                                                JOIN auth.Application AS ap ON ap.ApplicationId = t.ApplicationId
                                               WHERE ap.ApplicationCode = N'AUTHTEST'
                                                 AND t.TenantCode       = N'AUTHTEST_ACME')
      , @KeyRefV1           NVARCHAR (256) = (SELECT NULLIF (LTRIM (RTRIM (SettingValue)), N'')
                                                FROM config.ApplicationSetting
                                               WHERE SettingKey = N'Authn.MfaKeyReferenceCurrent' AND IsDeleted = 0)
      , @KeyRefV2           NVARCHAR (256) = N'dev:local/authn-mfa-kek#v2'
      , @OtherKeyRef        NVARCHAR (256) = N'dev:local/somebody-elses-kek#v1'
      , @AttemptId          BIGINT
      , @AliceAttempt       BIGINT
      , @Phc                NVARCHAR (512)
      , @MfaFlagged         BIT
      , @Token              VARBINARY (32)
      , @SessionId          BIGINT
      , @UserIdOut          INT
      , @MustChange         BIT
      , @Abs                DATETIME2 (3)
      , @Idle               DATETIME2 (3)
      , @ResolvedActor      INT
      , @FactorId           INT
      , @FactorIdAgain      INT
      , @IsConfirmed        BIT
      , @StepSeconds        INT
      , @ServerStep         BIGINT
      , @FarStep            BIGINT
      , @Stored             VARBINARY (MAX)
      , @StepAfterSignIn    BIGINT
      , @RotatedUser        INT
      , @SatisfiedFrank     BIT
      , @IssuedCount        INT
      , @CodesJson          NVARCHAR (MAX)
      , @Seed               NVARCHAR (64)
      , @FirstHash          NVARCHAR (64)
      , @ErrRefused         INT, @ErrNeither    INT, @ErrBoth       INT, @ErrBadKey    INT
      , @ErrBadProof        INT, @ErrConfirmFar INT, @ErrSecond     INT, @ErrConfirmAgain INT
      , @ErrNotArray        INT, @ErrBadBatch   INT, @ErrRotateGone INT, @ErrRotateSame INT
      , @ErrRotateIdentical INT, @ErrRotateUp   INT, @ErrRotateBack INT
      , @RefusedEvents      INT, @EnrolledEvents INT, @RotatedEvents INT;

SET @StepSeconds = TRY_CAST ((SELECT SettingValue FROM config.ApplicationSetting
                               WHERE SettingKey = N'Authn.TotpStepSeconds' AND IsDeleted = 0) AS INT);

SET @ServerStep = DATEDIFF_BIG (SECOND, CAST (N'1970-01-01T00:00:00' AS DATETIME2 (0)), SYSUTCDATETIME ())
                / @StepSeconds;

SET @FarStep = @ServerStep + 500;

-- 12a.  The refusal, again, and this time for what it LEAVES BEHIND.  The policy is flipped for the whole section and
--       restored at the end, outside every TRY, exactly as section 10b does it.
UPDATE auth.TenantAuthenticationPolicy
   SET RequireMfaForLocal = 1
     , auditModifiedBy    = @Actor
 WHERE TenantId = @AcmeId AND IsDeleted = 0;

SET @Token = CRYPT_GEN_RANDOM (32);

EXEC auth.uspGetLoginVerifier @ApplicationCode = N'AUTHTEST', @TenantCode = N'AUTHTEST_ACME'
   , @UserName = N'authtest.frank', @ClientAddress = N'198.51.100.60'
   , @LoginAttemptId = @AttemptId OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @MfaFlagged OUTPUT;

BEGIN TRY
    EXEC auth.uspCompleteLogin @LoginAttemptId = @AttemptId, @PasswordVerified = 1, @SessionTokenHash = @Token
       , @UserSessionId = @SessionId OUTPUT, @UserId = @UserIdOut OUTPUT, @MustChangePassword = @MustChange OUTPUT
       , @AbsoluteExpiryUtc = @Abs OUTPUT, @IdleExpiryUtc = @Idle OUTPUT;
END TRY
BEGIN CATCH
    SET @ErrRefused = ERROR_NUMBER ();
END CATCH;

SET @ResolvedActor = auth.udfResolveEnrolmentActor (@AttemptId);

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'12 MFA enrolment'
     , CASE WHEN @ErrRefused = 50109 AND @ResolvedActor = @FrankId AND a.PasswordVerified = 1
                 AND a.FailureReason = 'MfaRequired' AND a.Outcome = 'Failure' THEN 4 ELSE 2 END
     , CASE WHEN @ErrRefused = 50109 AND @ResolvedActor = @FrankId THEN 'OK' ELSE 'DEFECT' END
     , N'A refused sign-in is itself the enrolment proof -- auth.udfResolveEnrolmentActor reads the row 110 wrote'
     , CONCAT (N'Error ', COALESCE (CAST (@ErrRefused AS NVARCHAR (11)), N'(none -- a session was ISSUED)')
             , N', expected 50109. The attempt row: Outcome ', a.Outcome, N', reason '
             , COALESCE (a.FailureReason, N'(none)'), N', PasswordVerified ', a.PasswordVerified
             , N'. udfResolveEnrolmentActor returned '
             , COALESCE (CAST (@ResolvedActor AS NVARCHAR (11)), N'(null)'), N', frank is ', @FrankId
             , N'. PasswordVerified = 1 is written BEFORE the MFA checks -- decision D-14 -- and that ordering is the '
             , N'whole reason a REFUSED exchange can carry an identity. Reverse it and this route does not exist.')
  FROM auth.LoginAttempt AS a
 WHERE a.LoginAttemptId = @AttemptId;

-- 12b.  Neither proof, then both.  One error number for two opposite mistakes, because the fault is the same one: the
--       procedure has been left to decide who is calling, and it will not.
BEGIN TRY
    EXEC auth.uspEnrolMfaFactor @SecretCiphertext = 0x00112233445566778899AABBCCDDEEFF
       , @UserMfaFactorId = @FactorId OUTPUT;
END TRY
BEGIN CATCH
    SET @ErrNeither = ERROR_NUMBER ();
END CATCH;

SET @Token = CRYPT_GEN_RANDOM (32);

BEGIN TRY
    EXEC auth.uspEnrolMfaFactor @SecretCiphertext = 0x00112233445566778899AABBCCDDEEFF
       , @SessionTokenHash = @Token, @BootstrapLoginAttemptId = @AttemptId
       , @UserMfaFactorId = @FactorId OUTPUT;
END TRY
BEGIN CATCH
    SET @ErrBoth = ERROR_NUMBER ();
END CATCH;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'12 MFA enrolment'
     , CASE WHEN @ErrNeither = 50117 AND @ErrBoth = 50117 AND COUNT (*) = 0 THEN 4 ELSE 2 END
     , CASE WHEN @ErrNeither = 50117 AND @ErrBoth = 50117 AND COUNT (*) = 0 THEN 'OK' ELSE 'DEFECT' END
     , N'Enrolment requires EXACTLY one actor proof -- neither and both are the same refusal, E-50117'
     , CONCAT (N'Neither: error ', COALESCE (CAST (@ErrNeither AS NVARCHAR (11)), N'(none)'), N'. Both: error '
             , COALESCE (CAST (@ErrBoth AS NVARCHAR (11)), N'(none)'), N'. Expected 50117 twice. Live factors for '
             , N'frank afterwards: ', COUNT (*), N', expected 0. Both-at-once is refused rather than resolved in some '
             , N'documented order of precedence, because a precedence rule is a thing callers come to rely on by '
             , N'accident and it decides who a factor belongs to.')
  FROM auth.UserMfaFactor AS f
 WHERE f.UserId = @FrankId AND f.IsDeleted = 0;

-- 12c.  A key label that is well-formed, resolvable-looking, and not the current one.  This is the refusal that catches
--       an application still encrypting under a key the deployment has retired -- a fault which is otherwise invisible
--       until the retired key is gone and every factor stops decrypting at the same moment.
BEGIN TRY
    EXEC auth.uspEnrolMfaFactor @SecretCiphertext = 0x00112233445566778899AABBCCDDEEFF
       , @BootstrapLoginAttemptId = @AttemptId, @KeyReference = @OtherKeyRef
       , @UserMfaFactorId = @FactorId OUTPUT;
END TRY
BEGIN CATCH
    SET @ErrBadKey = ERROR_NUMBER ();
END CATCH;

-- 12d.  A proof that is real, current, and the WRONG SHAPE: alice's SUCCESSFUL sign-in.  Note what would have happened
--       had it been accepted -- frank's enrolment screen would have enrolled a factor onto ALICE's account.  COALESCE
--       to -1 rather than leaving it NULL on purpose: a NULL here would be read as "no proof offered" and answered with
--       E-50117, and the test would then pass for the wrong reason.
SET @AliceAttempt = COALESCE ((SELECT MAX (a.LoginAttemptId) FROM auth.LoginAttempt AS a
                                WHERE a.UserName = N'authtest.alice' AND a.Outcome = 'Success' AND a.IsDeleted = 0)
                            , -1);

BEGIN TRY
    EXEC auth.uspEnrolMfaFactor @SecretCiphertext = 0x00112233445566778899AABBCCDDEEFF
       , @BootstrapLoginAttemptId = @AliceAttempt
       , @UserMfaFactorId = @FactorId OUTPUT;
END TRY
BEGIN CATCH
    SET @ErrBadProof = ERROR_NUMBER ();
END CATCH;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'12 MFA enrolment'
     , CASE WHEN @ErrBadKey = 50118 AND @ErrBadProof = 50122 AND COUNT (*) = 0 THEN 4 ELSE 2 END
     , CASE WHEN @ErrBadKey = 50118 AND @ErrBadProof = 50122 AND COUNT (*) = 0 THEN 'OK' ELSE 'DEFECT' END
     , N'A non-current key label is refused E-50118, and a SUCCESSFUL sign-in is not enrolment proof -- E-50122'
     , CONCAT (N'Key label ', @OtherKeyRef, N' (grammatical, and not Authn.MfaKeyReferenceCurrent = ', @KeyRefV1
             , N'): error ', COALESCE (CAST (@ErrBadKey AS NVARCHAR (11)), N'(none -- it was STORED)')
             , N', expected 50118. alice''s successful attempt ', @AliceAttempt, N' as proof: error '
             , COALESCE (CAST (@ErrBadProof AS NVARCHAR (11)), N'(none -- it was ACCEPTED)'), N', expected 50122. '
             , N'Live factors for alice and frank afterwards: ', COUNT (*), N', expected 0. The second refusal is the '
             , N'narrow one: only a Failure the database itself marked MfaRequired and PasswordVerified opens the '
             , N'window, so a working session is a route to enrolment only through @SessionTokenHash, where it belongs.')
  FROM auth.UserMfaFactor AS f
  JOIN auth.[User]        AS u ON u.UserId = f.UserId
 WHERE u.UserName IN (N'authtest.frank', N'authtest.alice') AND f.IsDeleted = 0;

-- 12e.  The enrolment proper, and 12f the RE-SEND: a user who closed the tab before scanning the QR code gets a new
--       secret on the same row rather than an account that can never enrol again.
EXEC auth.uspEnrolMfaFactor @SecretCiphertext = 0xA1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1
   , @BootstrapLoginAttemptId = @AttemptId
   , @UserMfaFactorId = @FactorId OUTPUT;

EXEC auth.uspEnrolMfaFactor @SecretCiphertext = 0xB2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2
   , @BootstrapLoginAttemptId = @AttemptId
   , @UserMfaFactorId = @FactorIdAgain OUTPUT;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'12 MFA enrolment'
     , CASE WHEN @FactorId IS NOT NULL AND @FactorIdAgain = @FactorId AND f.IsConfirmed = 0
                 AND f.KeyReference = @KeyRefV1 AND f.ConfirmedUtc IS NULL
                 AND f.SecretCiphertext = 0xB2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2 THEN 4 ELSE 2 END
     , CASE WHEN @FactorIdAgain = @FactorId AND f.IsConfirmed = 0 AND f.KeyReference = @KeyRefV1
            THEN 'OK' ELSE 'DEFECT' END
     , N'Enrolment writes an UNCONFIRMED factor stamped with the current key, and a re-send replaces it in place'
     , CONCAT (N'Factor ', COALESCE (CAST (@FactorId AS NVARCHAR (11)), N'(none)'), N' then '
             , COALESCE (CAST (@FactorIdAgain AS NVARCHAR (11)), N'(none)')
             , N' -- the same row, which is what the unique index filtered to live rows requires. IsConfirmed '
             , f.IsConfirmed, N', ConfirmedUtc '
             , COALESCE (CONVERT (NVARCHAR (30), f.ConfirmedUtc, 126), N'(null)'), N', KeyReference ', f.KeyReference
             , N'. An unconfirmed factor satisfies NOTHING: auth.uspVerifyMfa reads IsConfirmed = 1 and section 8 is '
             , N'where that is proved. Between these two calls the account is in the only state where a secret can be '
             , N'overwritten without an audited removal first, and it lasts exactly until the first confirmation.')
  FROM auth.UserMfaFactor AS f
 WHERE f.UserId = @FrankId AND f.FactorType = 'Totp' AND f.IsDeleted = 0;

-- 12g.  Confirmation is bounded by the same clock the sign-in is.  A step four hours ahead is refused -- and refused
--       WITHOUT concluding anything, because unlike E-50111 at sign-in there is no exchange here to walk.
BEGIN TRY
    EXEC auth.uspConfirmMfaFactor @TimeStep = @FarStep, @BootstrapLoginAttemptId = @AttemptId
       , @UserMfaFactorId = @FactorId OUTPUT, @IsConfirmed = @IsConfirmed OUTPUT;
END TRY
BEGIN CATCH
    SET @ErrConfirmFar = ERROR_NUMBER ();
END CATCH;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'12 MFA enrolment', CASE WHEN @ErrConfirmFar = 50111 AND f.IsConfirmed = 0 THEN 4 ELSE 2 END
     , CASE WHEN @ErrConfirmFar = 50111 AND f.IsConfirmed = 0 THEN 'OK' ELSE 'DEFECT' END
     , N'A confirmation step outside Authn.TotpWindowSteps is refused E-50111 and confirms nothing'
     , CONCAT (N'Step ', @FarStep, N' against a server step of ', @ServerStep, N': error '
             , COALESCE (CAST (@ErrConfirmFar AS NVARCHAR (11)), N'(none -- it was CONFIRMED)')
             , N', expected 50111. IsConfirmed is still ', f.IsConfirmed
             , N'. The same number as the sign-in refusal, deliberately: it is the same check, and a caller that has to '
             , N'learn two numbers for one fault learns neither.')
  FROM auth.UserMfaFactor AS f
 WHERE f.UserId = @FrankId AND f.FactorType = 'Totp' AND f.IsDeleted = 0;

-- 12h.  The confirmation, and the unobvious assertion that follows it: the step is NOT spent.  frank typed that code
--       into the enrolment screen and the sign-in it interrupted is still waiting for it.  Spending it here would refuse
--       the very next round trip with E-50111 and look, from the outside, exactly like a broken authenticator.
EXEC auth.uspConfirmMfaFactor @TimeStep = @ServerStep, @BootstrapLoginAttemptId = @AttemptId
   , @UserMfaFactorId = @FactorId OUTPUT, @IsConfirmed = @IsConfirmed OUTPUT;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'12 MFA enrolment'
     , CASE WHEN @IsConfirmed = 1 AND f.IsConfirmed = 1 AND f.ConfirmedUtc IS NOT NULL
                 AND f.LastUsedTimeStep IS NULL AND f.LastUsedUtc IS NULL THEN 4 ELSE 2 END
     , CASE WHEN @IsConfirmed = 1 AND f.IsConfirmed = 1 AND f.LastUsedTimeStep IS NULL THEN 'OK' ELSE 'DEFECT' END
     , N'Confirmation sets IsConfirmed and deliberately does NOT spend the time step'
     , CONCAT (N'@IsConfirmed = ', @IsConfirmed, N', ConfirmedUtc '
             , COALESCE (CONVERT (NVARCHAR (30), f.ConfirmedUtc, 126), N'(null)'), N', LastUsedTimeStep '
             , COALESCE (CAST (f.LastUsedTimeStep AS NVARCHAR (20)), N'(null)'), N' -- expected null. The replay '
             , N'high-water mark belongs to auth.uspVerifyMfa and to nothing else, because the code that proves an '
             , N'authenticator was set up correctly is the same code that finishes the sign-in that asked for it. '
             , N'12k is where the same step is then accepted, once.')
  FROM auth.UserMfaFactor AS f
 WHERE f.UserId = @FrankId AND f.FactorType = 'Totp' AND f.IsDeleted = 0;

-- 12i.  Now that there IS a confirmed factor, the window closes behind it: the bootstrap proof that worked twice a
--       moment ago will not replace a working authenticator.  This is what makes Authn.MfaEnrolmentWindowSeconds an
--       identity and not a permission.  The refusal is RECORDED -- 'MfaEnrolmentRefused', the only one of the three
--       T-041 event types that records something which did not happen.
BEGIN TRY
    EXEC auth.uspEnrolMfaFactor @SecretCiphertext = 0xC3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3
       , @BootstrapLoginAttemptId = @AttemptId
       , @UserMfaFactorId = @FactorIdAgain OUTPUT;
END TRY
BEGIN CATCH
    SET @ErrSecond = ERROR_NUMBER ();
END CATCH;

-- 12j.  And a second confirmation of the same factor -- the double-submitted form -- is E-50120, which deliberately
--       does not distinguish "nothing enrolled" from "already confirmed".
BEGIN TRY
    EXEC auth.uspConfirmMfaFactor @TimeStep = @ServerStep, @BootstrapLoginAttemptId = @AttemptId
       , @UserMfaFactorId = @FactorIdAgain OUTPUT, @IsConfirmed = @IsConfirmed OUTPUT;
END TRY
BEGIN CATCH
    SET @ErrConfirmAgain = ERROR_NUMBER ();
END CATCH;

SELECT @RefusedEvents  = SUM (CASE WHEN e.EventType = 'MfaEnrolmentRefused' THEN 1 ELSE 0 END)
     , @EnrolledEvents = SUM (CASE WHEN e.EventType = 'MfaEnrolled'         THEN 1 ELSE 0 END)
  FROM logs.AuthenticationEvent AS e
 WHERE e.UserId = @FrankId AND e.EventUtc >= @T0;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'12 MFA enrolment'
     , CASE WHEN @ErrSecond = 50119 AND @ErrConfirmAgain = 50120 AND @RefusedEvents = 1 AND @EnrolledEvents = 2
                 AND f.SecretCiphertext <> 0xC3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3 THEN 4 ELSE 2 END
     , CASE WHEN @ErrSecond = 50119 AND @ErrConfirmAgain = 50120 AND @RefusedEvents = 1 THEN 'OK' ELSE 'DEFECT' END
     , N'A confirmed factor is never silently replaced -- E-50119, logged -- and a repeated confirmation is E-50120'
     , CONCAT (N'Second enrolment on the same bootstrap proof: error '
             , COALESCE (CAST (@ErrSecond AS NVARCHAR (11)), N'(none -- the secret was REPLACED)')
             , N', expected 50119. Repeated confirmation: error '
             , COALESCE (CAST (@ErrConfirmAgain AS NVARCHAR (11)), N'(none)'), N', expected 50120. This run logged '
             , COALESCE (CAST (@EnrolledEvents AS NVARCHAR (11)), N'0'), N' MfaEnrolled (expected 2, the enrolment and '
             , N'the re-send) and ', COALESCE (CAST (@RefusedEvents AS NVARCHAR (11)), N'0')
             , N' MfaEnrolmentRefused (expected 1) for frank. The refusal survives its own rollback because the record '
             , N'is committed before the THROW -- a refusal that rolls away its evidence is one nobody can count.')
  FROM auth.UserMfaFactor AS f
 WHERE f.UserId = @FrankId AND f.FactorType = 'Totp' AND f.IsDeleted = 0;

-- 12k.  Recovery codes.  Two malformed batches first, and note that they are ONE error number covering six faults --
--       empty, over-long, non-string, wrong length, non-hex, duplicated -- because they are all the same fault in the
--       caller's generator, and one number it will actually look up beats six it will not.
SET @Seed = CONVERT (NVARCHAR (30), SYSUTCDATETIME (), 126);

-- NVARCHAR and not CHAR: STRING_AGG below refuses a varchar value with an nvarchar separator, and the two hex strings
-- have to agree on type or the batch does not compile at all.
SET @FirstHash = CONVERT (NVARCHAR (64), HASHBYTES ('SHA2_256', @Seed + N'|frank|1'), 2);

BEGIN TRY
    EXEC auth.uspIssueMfaRecoveryCodes @CodeHashesJson = N'{"codes":[]}', @BootstrapLoginAttemptId = @AttemptId
       , @IssuedCount = @IssuedCount OUTPUT;
END TRY
BEGIN CATCH
    SET @ErrNotArray = ERROR_NUMBER ();
END CATCH;

SET @CodesJson = N'["' + @FirstHash + N'","' + @FirstHash + N'"]';

BEGIN TRY
    EXEC auth.uspIssueMfaRecoveryCodes @CodeHashesJson = @CodesJson, @BootstrapLoginAttemptId = @AttemptId
       , @IssuedCount = @IssuedCount OUTPUT;
END TRY
BEGIN CATCH
    SET @ErrBadBatch = ERROR_NUMBER ();
END CATCH;

SET @CodesJson = (SELECT N'["' + STRING_AGG (CONVERT (NVARCHAR (64)
                                                    , HASHBYTES ('SHA2_256', @Seed + N'|frank|' + x.Ordinal), 2)
                                           , N'","') + N'"]'
                    FROM (VALUES (N'1'), (N'2'), (N'3'), (N'4')) AS x (Ordinal));

EXEC auth.uspIssueMfaRecoveryCodes @CodeHashesJson = @CodesJson, @BootstrapLoginAttemptId = @AttemptId
   , @IssuedCount = @IssuedCount OUTPUT;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'12 MFA enrolment'
     , CASE WHEN @ErrNotArray = 50046 AND @ErrBadBatch = 50121 AND @IssuedCount = 4 AND COUNT (*) = 4 THEN 4 ELSE 2 END
     , CASE WHEN @ErrNotArray = 50046 AND @ErrBadBatch = 50121 AND @IssuedCount = 4 THEN 'OK' ELSE 'DEFECT' END
     , N'A recovery-code batch is refused whole -- E-50046 for a non-array, E-50121 for duplicates -- or issued whole'
     , CONCAT (N'A JSON object rather than an array: error '
             , COALESCE (CAST (@ErrNotArray AS NVARCHAR (11)), N'(none)'), N', expected 50046. The same hash twice: '
             , N'error ', COALESCE (CAST (@ErrBadBatch AS NVARCHAR (11)), N'(none)'), N', expected 50121. Then four '
             , N'distinct hashes: @IssuedCount = ', COALESCE (CAST (@IssuedCount AS NVARCHAR (11)), N'(null)')
             , N', live unused codes for frank = ', COUNT (*), N'. What travels is the SHA-256 of each code and never '
             , N'the code, and the payload is never written to logs.ExecutionLog -- only its length. Issuing requires a '
             , N'CONFIRMED factor (E-50110): codes issued first would be one-time passwords satisfying a requirement '
             , N'the account had never satisfied at all.')
  FROM auth.UserMfaRecoveryCode AS r
 WHERE r.UserId = @FrankId AND r.UsedUtc IS NULL AND r.IsDeleted = 0;

-- 12l.  THE POINT OF THE WHOLE SECTION.  frank signs in, under the same policy that refused him at 12a, with the factor
--       he enrolled from that refusal -- and with the very step he confirmed it with, which 12h left unspent.
SET @Token     = CRYPT_GEN_RANDOM (32);
SET @SessionId = NULL;

EXEC auth.uspGetLoginVerifier @ApplicationCode = N'AUTHTEST', @TenantCode = N'AUTHTEST_ACME'
   , @UserName = N'authtest.frank', @ClientAddress = N'198.51.100.60'
   , @LoginAttemptId = @AttemptId OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @MfaFlagged OUTPUT;

EXEC auth.uspVerifyMfa @LoginAttemptId = @AttemptId, @TimeStep = @ServerStep, @MfaSatisfied = @SatisfiedFrank OUTPUT;

EXEC auth.uspCompleteLogin @LoginAttemptId = @AttemptId, @PasswordVerified = 1, @SessionTokenHash = @Token
   , @UserSessionId = @SessionId OUTPUT, @UserId = @UserIdOut OUTPUT, @MustChangePassword = @MustChange OUTPUT
   , @AbsoluteExpiryUtc = @Abs OUTPUT, @IdleExpiryUtc = @Idle OUTPUT;

SET @StepAfterSignIn = (SELECT f.LastUsedTimeStep FROM auth.UserMfaFactor AS f
                         WHERE f.UserId = @FrankId AND f.FactorType = 'Totp' AND f.IsDeleted = 0);

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'12 MFA enrolment'
     , CASE WHEN @MfaFlagged = 1 AND @SatisfiedFrank = 1 AND @SessionId IS NOT NULL AND @UserIdOut = @FrankId
                 AND s.MfaSatisfied = 1 AND @StepAfterSignIn = @ServerStep THEN 4 ELSE 1 END
     , CASE WHEN @SatisfiedFrank = 1 AND @SessionId IS NOT NULL AND @StepAfterSignIn = @ServerStep
            THEN 'OK' ELSE 'VIOLATED' END
     , N'frank, refused at 12a with E-50109, holds a session -- the round trip G-07 used to make impossible'
     , CONCAT (N'@RequiresMfa = ', @MfaFlagged, N', @MfaSatisfied = ', COALESCE (CAST (@SatisfiedFrank AS NCHAR (1))
                                                                              , N'?')
             , N', session ', COALESCE (CAST (@SessionId AS NVARCHAR (20)), N'(none)'), N' for user '
             , COALESCE (CAST (@UserIdOut AS NVARCHAR (11)), N'(none)'), N', frank is ', @FrankId
             , N'. LastUsedTimeStep is now ', COALESCE (CAST (@StepAfterSignIn AS NVARCHAR (20)), N'(null)')
             , N', which is the step 12h confirmed with and did not spend -- SPENT HERE, by uspVerifyMfa, exactly once. '
             , N'The policy was never relaxed to let him through: RequireMfaForLocal is still 1 on ACME as this row is '
             , N'written, and the account satisfied it.')
  FROM auth.UserSession AS s
 WHERE s.LoginAttemptId = @AttemptId;

-- 12m.  Re-keying, which is the only reason KeyReference exists at all: a stored label that cannot be moved is a label
--       that turns a key rotation into a data-loss event.  uspRotateMfaFactorKey takes NO actor proof, deliberately --
--       it is a sweep run by an operator over rows belonging to people who are not present, and inventing a session for
--       it would be inventing an authorization that does not exist.  The setting moves FIRST and the sweep follows.
BEGIN TRY
    EXEC auth.uspRotateMfaFactorKey @UserMfaFactorId = 2000000000
       , @SecretCiphertext = 0xD4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4, @UserId = @RotatedUser OUTPUT;
END TRY
BEGIN CATCH
    SET @ErrRotateGone = ERROR_NUMBER ();
END CATCH;

BEGIN TRY
    EXEC auth.uspRotateMfaFactorKey @UserMfaFactorId = @FactorId
       , @SecretCiphertext = 0xD4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4, @UserId = @RotatedUser OUTPUT;
END TRY
BEGIN CATCH
    SET @ErrRotateSame = ERROR_NUMBER ();
END CATCH;

UPDATE config.ApplicationSetting
   SET SettingValue    = @KeyRefV2
     , auditModifiedBy = @Actor
 WHERE SettingKey = N'Authn.MfaKeyReferenceCurrent' AND IsDeleted = 0;

SET @Stored = (SELECT f.SecretCiphertext FROM auth.UserMfaFactor AS f
                WHERE f.UserMfaFactorId = @FactorId);

BEGIN TRY
    EXEC auth.uspRotateMfaFactorKey @UserMfaFactorId = @FactorId, @SecretCiphertext = @Stored
       , @UserId = @RotatedUser OUTPUT;
END TRY
BEGIN CATCH
    SET @ErrRotateIdentical = ERROR_NUMBER ();
END CATCH;

BEGIN TRY
    EXEC auth.uspRotateMfaFactorKey @UserMfaFactorId = @FactorId
       , @SecretCiphertext = 0xE5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5, @UserId = @RotatedUser OUTPUT;
END TRY
BEGIN CATCH
    SET @ErrRotateUp = ERROR_NUMBER ();
END CATCH;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'12 MFA enrolment'
     , CASE WHEN @ErrRotateGone = 50120 AND @ErrRotateSame = 50123 AND @ErrRotateIdentical = 50123
                 AND @ErrRotateUp IS NULL AND @RotatedUser = @FrankId AND f.KeyReference = @KeyRefV2
                 AND f.LastUsedTimeStep IS NULL AND f.LastUsedUtc IS NULL AND f.IsConfirmed = 1 THEN 4 ELSE 2 END
     , CASE WHEN @ErrRotateGone = 50120 AND @ErrRotateSame = 50123 AND @ErrRotateIdentical = 50123
                 AND @ErrRotateUp IS NULL AND f.KeyReference = @KeyRefV2 AND f.LastUsedTimeStep IS NULL
            THEN 'OK' ELSE 'DEFECT' END
     , N'A re-key moves the label and the bytes together, refuses either alone, and resets the replay mark -- UI-32'
     , CONCAT (N'An identifier nobody holds: error ', COALESCE (CAST (@ErrRotateGone AS NVARCHAR (11)), N'(none)')
             , N', expected 50120. The label it already carries: error '
             , COALESCE (CAST (@ErrRotateSame AS NVARCHAR (11)), N'(none)'), N', expected 50123. The current label with '
             , N'BYTE-IDENTICAL ciphertext -- a caller that moved the label and forgot to re-encrypt: error '
             , COALESCE (CAST (@ErrRotateIdentical AS NVARCHAR (11)), N'(none -- the label MOVED and the bytes did not)')
             , N', expected 50123, and that refusal is the one the whole column exists for. Then a real sweep: error '
             , COALESCE (CAST (@ErrRotateUp AS NVARCHAR (11)), N'(none, as intended)'), N', KeyReference is now '
             , f.KeyReference, N', LastUsedTimeStep '
             , COALESCE (CAST (f.LastUsedTimeStep AS NVARCHAR (20)), N'(null)'), N' -- cleared, from '
             , COALESCE (CAST (@StepAfterSignIn AS NVARCHAR (20)), N'(null)')
             , N'. IsConfirmed is still ', f.IsConfirmed, N': a re-key is not a re-enrolment. Clearing the mark reopens '
             , N'a replay window of at most one time step for the code in flight, which is UI-32 -- accepted and '
             , N'documented rather than engineered around with a second high-water column.')
  FROM auth.UserMfaFactor AS f
 WHERE f.UserMfaFactorId = @FactorId;

-- 12m'.  G-52, BL-086: a refused sign-in is enrolment proof only for an account that had NO factor when it was
--        refused.  frank now holds a confirmed factor and ACME still requires one.  A thief with his password alone is
--        refused -- and before the fix that refusal still resolved to frank in auth.udfResolveEnrolmentActor, so
--        auth.uspIssueMfaRecoveryCodes, which only asks for a confirmed factor, issued the thief a batch of recovery
--        codes: one-time passwords that satisfy the MFA the thief does not have.  Account takeover with a password.
DECLARE @StealAttempt BIGINT, @ErrStealLogin INT, @ErrStealCodes INT, @StealIssued INT
      , @StealBefore  INT = (SELECT COUNT (*) FROM auth.UserMfaRecoveryCode AS r
                              WHERE r.UserId = @FrankId AND r.IsDeleted = 0)
      , @StealJson    NVARCHAR (400) = N'["' + CONVERT (NVARCHAR (64), HASHBYTES ('SHA2_256', @Seed + N'|thief'), 2) + N'"]';

BEGIN TRY
    EXEC auth.uspGetLoginVerifier @ApplicationCode = N'AUTHTEST', @TenantCode = N'AUTHTEST_ACME'
       , @UserName = N'authtest.frank', @ClientAddress = N'198.51.100.61'
       , @LoginAttemptId = @StealAttempt OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @MfaFlagged OUTPUT;
    SET @Token = CRYPT_GEN_RANDOM (32);
    EXEC auth.uspCompleteLogin @LoginAttemptId = @StealAttempt, @PasswordVerified = 1, @SessionTokenHash = @Token
       , @UserSessionId = @SessionId OUTPUT, @UserId = @UserIdOut OUTPUT, @MustChangePassword = @MustChange OUTPUT
       , @AbsoluteExpiryUtc = @Abs OUTPUT, @IdleExpiryUtc = @Idle OUTPUT;
END TRY
BEGIN CATCH
    SET @ErrStealLogin = ERROR_NUMBER ();
END CATCH;

BEGIN TRY
    EXEC auth.uspIssueMfaRecoveryCodes @CodeHashesJson = @StealJson, @BootstrapLoginAttemptId = @StealAttempt
       , @IssuedCount = @StealIssued OUTPUT;
END TRY
BEGIN CATCH
    SET @ErrStealCodes = ERROR_NUMBER ();
END CATCH;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'12 MFA enrolment'
     , CASE WHEN @ErrStealLogin IS NOT NULL AND @ErrStealCodes = 50122 AND x.N = @StealBefore
             AND auth.udfResolveEnrolmentActor (@StealAttempt) IS NULL THEN 4 ELSE 1 END
     , CASE WHEN @ErrStealLogin IS NOT NULL AND @ErrStealCodes = 50122 AND x.N = @StealBefore
             AND auth.udfResolveEnrolmentActor (@StealAttempt) IS NULL THEN 'OK' ELSE 'VIOLATED' END
     , N'G-52: the refused sign-in of an account that already holds a factor is not enrolment proof -- no recovery codes'
     , CONCAT (N'Password-only sign-in: error ', COALESCE (CAST (@ErrStealLogin AS NVARCHAR (11)), N'(none -- A SESSION)')
             , N'. Recovery codes on that refusal: error '
             , COALESCE (CAST (@ErrStealCodes AS NVARCHAR (11)), N'(none -- CODES WERE ISSUED TO WHOEVER HAD THE PASSWORD)')
             , N', expected 50122. Live codes for frank before ', @StealBefore, N', after ', x.N, N'.')
  FROM (SELECT COUNT (*) AS N FROM auth.UserMfaRecoveryCode AS r WHERE r.UserId = @FrankId AND r.IsDeleted = 0) AS x;

-- 12n.  And back again, which is the assertion that matters for the NEXT run of this file: the setting and the row end
--       where they started, so nothing here depends on having been run an even number of times.
UPDATE config.ApplicationSetting
   SET SettingValue    = @KeyRefV1
     , auditModifiedBy = @Actor
 WHERE SettingKey = N'Authn.MfaKeyReferenceCurrent' AND IsDeleted = 0;

BEGIN TRY
    EXEC auth.uspRotateMfaFactorKey @UserMfaFactorId = @FactorId
       , @SecretCiphertext = 0xF6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6, @UserId = @RotatedUser OUTPUT;
END TRY
BEGIN CATCH
    SET @ErrRotateBack = ERROR_NUMBER ();
END CATCH;

UPDATE auth.TenantAuthenticationPolicy
   SET RequireMfaForLocal = 0
     , auditModifiedBy    = @Actor
 WHERE TenantId = @AcmeId AND IsDeleted = 0;

SET @RotatedEvents = (SELECT COUNT (*) FROM logs.AuthenticationEvent AS e
                       WHERE e.UserId = @FrankId AND e.EventUtc >= @T0 AND e.EventType = 'MfaKeyRotated');

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'12 MFA enrolment'
     , CASE WHEN @ErrRotateBack IS NULL AND f.KeyReference = @KeyRefV1 AND @RotatedEvents = 2
                 AND (SELECT SettingValue FROM config.ApplicationSetting
                       WHERE SettingKey = N'Authn.MfaKeyReferenceCurrent' AND IsDeleted = 0) = @KeyRefV1
                 AND (SELECT RequireMfaForLocal FROM auth.TenantAuthenticationPolicy
                       WHERE TenantId = @AcmeId AND IsDeleted = 0) = 0 THEN 4 ELSE 2 END
     , CASE WHEN @ErrRotateBack IS NULL AND f.KeyReference = @KeyRefV1
                 AND (SELECT SettingValue FROM config.ApplicationSetting
                       WHERE SettingKey = N'Authn.MfaKeyReferenceCurrent' AND IsDeleted = 0) = @KeyRefV1
            THEN 'OK' ELSE 'DEFECT' END
     , N'The rotation is reversible and the section leaves no state behind -- key setting and tenant policy restored'
     , CONCAT (N'Sweep back onto ', @KeyRefV1, N': error '
             , COALESCE (CAST (@ErrRotateBack AS NVARCHAR (11)), N'(none, as intended)'), N'. KeyReference '
             , f.KeyReference, N', Authn.MfaKeyReferenceCurrent '
             , (SELECT SettingValue FROM config.ApplicationSetting
                 WHERE SettingKey = N'Authn.MfaKeyReferenceCurrent' AND IsDeleted = 0)
             , N', RequireMfaForLocal on ACME back to '
             , (SELECT CAST (RequireMfaForLocal AS NVARCHAR (1)) FROM auth.TenantAuthenticationPolicy
                 WHERE TenantId = @AcmeId AND IsDeleted = 0), N'. MfaKeyRotated events this run: '
             , COALESCE (CAST (@RotatedEvents AS NVARCHAR (11)), N'0'), N', expected 2. Rotation is the operation the '
             , N'whole G-07 decision rests on being possible: a TPM-backed CNG key is MACHINE-BOUND, so the day the '
             , N'application server is rebuilt is the day every one of these rows needs re-keying from escrow -- '
             , N'gotcha UI-28. A template that stored the label and provided no way to move it would have shipped that '
             , N'rebuild as an outage.')
  FROM auth.UserMfaFactor AS f
 WHERE f.UserMfaFactorId = @FactorId;
GO


-- *** 13. G-42 and G-12: changing a password, and the expiry a page header can warn about ***
-- THIS SECTION SPENDS THE CONNECTION'S IDENTITY, AND IT IS LAST FOR THAT REASON.  auth.uspChangePassword establishes
-- session context from the token it is handed (UI-05) and the five keys are read-only for the life of a connection
-- (E-50022, UI-06), so from the first call below to the end of the file this connection is authtest.alice.  Nothing
-- after it signs anybody in, and the report reads rows rather than raising errors.
--
-- WHAT THIS SECTION PROVES, AND WHY EACH PART OF IT IS HERE
--
--   *  E-50220: a new verifier that is not a PHC string is refused.  D-08 draws the line at the door -- this database
--      never receives a password -- and the shape check is what stops a plaintext one being stored as if it were a hash.
--   *  E-50221: a change with the current password UNPROVED is refused.  That call, accepted, is account takeover.
--   *  The change itself: the old verifier is retired into auth.PasswordHistory, the new one is installed, ExpiresUtc is
--      stamped from Authn.PasswordLifetimeDays (G-12), MustChangePassword is cleared, and THE SESSION SURVIVES -- which
--      is a decision, argued in 110_auth_authn_procedures.sql, and therefore worth an assertion rather than a comment.
--   *  E-50222: the application reporting a reused password is refused, and only while a history depth is configured.
--
-- WHAT IT DELIBERATELY LEAVES TO _tests/080_error_catalogue.sql, AND WHY
--
--   *  E-50223 (no live password credential) needs a federated-only account -- erin -- and erin's session would be a
--      SECOND identity on this connection, which is E-50022 by design.  080 spans seven connections and probes it there.
--   *  auth.uspSetPassword's administrative route demands User.ResetCredential, and this file's fixture has no profiles
--      and no role grants at all: it is a test of authentication, not of authorization.  080 holds that probe too.
--
-- Authn.PasswordLifetimeDays ships as 0, which means NO EXPIRY, so the expiry half of G-12 cannot be observed without
-- setting it.  It is saved, set to 30 for one call, and restored -- and alice's ExpiresUtc is put back to NULL with it,
-- because a fixture that leaves an expiring credential behind is a fixture that fails a later run for the wrong reason.
DECLARE @AttemptId BIGINT, @Phc NVARCHAR (512), @Mfa BIT, @Token VARBINARY (32) = CRYPT_GEN_RANDOM (32)
      , @SessionId BIGINT, @UserIdOut INT, @MustChange BIT, @Abs DATETIME2 (3), @Idle DATETIME2 (3)
      , @Actor        NVARCHAR (255) = N'_tests/040_identity_and_authn.sql'
      , @Now          DATETIME2 (3)  = SYSUTCDATETIME ()
      , @AliceId      INT            = (SELECT UserId FROM auth.[User] WHERE UserName = N'authtest.alice')
      , @Lifetime     INT            = 30
      , @OldVerifier  NVARCHAR (512) = NULL
      , @NewVerifier  NVARCHAR (512) = NULL
      , @SavedDays    NVARCHAR (100) = NULL
      , @Depth        INT            = NULL
      , @Err50220     INT            = NULL
      , @Err50221     INT            = NULL
      , @Err50222     INT            = NULL
      , @HistBefore   INT            = NULL
      , @HistAfter    INT            = NULL;

SELECT @OldVerifier = c.VerifierPhc
  FROM auth.UserCredential AS c
 WHERE c.UserId = @AliceId AND c.CredentialType = 'Password' AND c.IsDeleted = 0;

SELECT @HistBefore = COUNT (*) FROM auth.PasswordHistory WHERE UserId = @AliceId AND IsDeleted = 0;

SELECT @Depth = TRY_CAST (SettingValue AS INT) FROM config.ApplicationSetting
 WHERE SettingKey = N'Authn.PasswordHistoryDepth' AND IsDeleted = 0;

-- A well-formed PHC string that no password produces, derived from this run's start time so that two runs never install
-- the same verifier -- the same reasoning, and the same field widths, as the fixture in section 2d.
DECLARE @Seed NVARCHAR (64) = CONVERT (NVARCHAR (30), @Now, 126);

SET @NewVerifier = N'$argon2id$v=19$m=19456,t=2,p=1$'
                 + LEFT (REPLACE (REPLACE (CONVERT (VARCHAR (64)
                        , HASHBYTES ('SHA2_256', @Seed + N'|g42|salt'), 2), '0', 'q'), '1', 'w'), 22)
                 + N'$'
                 + LEFT (REPLACE (REPLACE (CONVERT (VARCHAR (64)
                        , HASHBYTES ('SHA2_256', @Seed + N'|g42|hash'), 2), '0', 'e'), '1', 'r'), 43);

EXEC auth.uspGetLoginVerifier @ApplicationCode = N'AUTHTEST', @TenantCode = N'AUTHTEST_ACME'
   , @UserName = N'authtest.alice', @ClientAddress = N'198.51.100.10', @UserAgent = N'_tests/040 section 13'
   , @LoginAttemptId = @AttemptId OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;

EXEC auth.uspCompleteLogin @LoginAttemptId = @AttemptId, @PasswordVerified = 1, @SessionTokenHash = @Token
   , @UserSessionId = @SessionId OUTPUT, @UserId = @UserIdOut OUTPUT, @MustChangePassword = @MustChange OUTPUT
   , @AbsoluteExpiryUtc = @Abs OUTPUT, @IdleExpiryUtc = @Idle OUTPUT;

-- 13a.  E-50220.  'hunter2' is the joke and it is also the exact mistake the check exists for: a caller that sends the
--       PASSWORD where the verifier belongs would otherwise store it, and the store would look like a hash to everybody.
BEGIN TRY
    EXEC auth.uspChangePassword @SessionTokenHash = @Token, @CurrentPasswordVerified = 1
                              , @NewVerifierPhc = N'hunter2';
END TRY
BEGIN CATCH
    SET @Err50220 = ERROR_NUMBER ();
END CATCH;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'13 Password change'
     , CASE WHEN @Err50220 = 50220 AND c.VerifierPhc = @OldVerifier THEN 4 ELSE 2 END
     , CASE WHEN @Err50220 = 50220 AND c.VerifierPhc = @OldVerifier THEN 'OK' ELSE 'DEFECT' END
     , N'A new verifier that is not a PHC string is refused E-50220 and nothing is stored'
     , CONCAT (N'Error ', COALESCE (CAST (@Err50220 AS NVARCHAR (11)), N'(none -- A PASSWORD WAS STORED AS A VERIFIER)')
             , N', expected 50220. The stored verifier is still the one section 2d wrote: '
             , CASE WHEN c.VerifierPhc = @OldVerifier THEN N'yes' ELSE N'NO' END
             , N'. The test is shape and length, not strength -- strength is Argon2id''s parameters and they are the '
             , N'application''s (D-08). A database that accepted anything here would be a database whose credential '
             , N'column means nothing, and the failure would not appear until the day somebody tried to sign in.')
  FROM auth.UserCredential AS c
 WHERE c.UserId = @AliceId AND c.CredentialType = 'Password' AND c.IsDeleted = 0;

-- 13b.  E-50221.  The whole of account takeover is this one call succeeding.
BEGIN TRY
    EXEC auth.uspChangePassword @SessionTokenHash = @Token, @CurrentPasswordVerified = 0
                              , @NewVerifierPhc = @NewVerifier;
END TRY
BEGIN CATCH
    SET @Err50221 = ERROR_NUMBER ();
END CATCH;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'13 Password change'
     , CASE WHEN @Err50221 = 50221 AND c.VerifierPhc = @OldVerifier THEN 4 ELSE 1 END
     , CASE WHEN @Err50221 = 50221 AND c.VerifierPhc = @OldVerifier THEN 'OK' ELSE 'VIOLATED' END
     , N'A change with the current password UNPROVED is refused E-50221'
     , CONCAT (N'Error ', COALESCE (CAST (@Err50221 AS NVARCHAR (11))
                                  , N'(none -- A PASSWORD WAS CHANGED WITHOUT THE OLD ONE)')
             , N', expected 50221. Verifier unchanged: ', CASE WHEN c.VerifierPhc = @OldVerifier THEN N'yes' ELSE N'NO' END
             , N'. @CurrentPasswordVerified carries exactly the contract @PasswordVerified carries at sign-in: the '
             , N'application proved it, this database believes the report and records that it was made. A default of 1, '
             , N'or an IF that ignored a 0, would make a live session enough to replace the password -- and a stolen '
             , N'session cookie is the commonest thing an attacker has.')
  FROM auth.UserCredential AS c
 WHERE c.UserId = @AliceId AND c.CredentialType = 'Password' AND c.IsDeleted = 0;

-- 13c.  The change itself, with an expiry configured so that G-12's stamp can be seen.
SELECT @SavedDays = SettingValue FROM config.ApplicationSetting
 WHERE SettingKey = N'Authn.PasswordLifetimeDays' AND IsDeleted = 0;

UPDATE config.ApplicationSetting
   SET SettingValue    = CAST (@Lifetime AS NVARCHAR (100))
     , auditModifiedBy = @Actor
 WHERE SettingKey = N'Authn.PasswordLifetimeDays' AND IsDeleted = 0;

EXEC auth.uspChangePassword @SessionTokenHash = @Token, @CurrentPasswordVerified = 1
                          , @NewVerifierPhc = @NewVerifier, @NewVerifierReusesHistory = 0;

SELECT @HistAfter = COUNT (*) FROM auth.PasswordHistory WHERE UserId = @AliceId AND IsDeleted = 0;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'13 Password change'
     , CASE WHEN c.VerifierPhc = @NewVerifier
             AND @HistAfter = @HistBefore + 1
             AND EXISTS (SELECT 1 FROM auth.PasswordHistory AS ph
                          WHERE ph.UserId = @AliceId AND ph.VerifierPhc = @OldVerifier AND ph.IsDeleted = 0)
             AND u.MustChangePassword = 0
            THEN 4 ELSE 2 END
     , CASE WHEN c.VerifierPhc = @NewVerifier
             AND @HistAfter = @HistBefore + 1
             AND EXISTS (SELECT 1 FROM auth.PasswordHistory AS ph
                          WHERE ph.UserId = @AliceId AND ph.VerifierPhc = @OldVerifier AND ph.IsDeleted = 0)
            THEN 'OK' ELSE 'DEFECT' END
     , N'G-42: the change installs the new verifier and RETIRES the old one into auth.PasswordHistory'
     , CONCAT (N'History rows for alice: ', @HistBefore, N' before, ', @HistAfter, N' after. The retired row holds the '
             , N'verifier section 2d wrote: '
             , CASE WHEN EXISTS (SELECT 1 FROM auth.PasswordHistory AS ph
                                  WHERE ph.UserId = @AliceId AND ph.VerifierPhc = @OldVerifier AND ph.IsDeleted = 0)
                    THEN N'yes' ELSE N'NO' END
             , N'. MustChangePassword is now ', u.MustChangePassword, N'. Before G-42 there was no procedure that could '
             , N'change a password at all: every deployment wrote its own UPDATE against auth.UserCredential, with no '
             , N'history row, no authentication event and no way to force the change. The history is not a nicety -- it '
             , N'is the only thing the reuse check in 13d has to compare against, and comparing is the application''s '
             , N'work because a salted hash cannot be compared by this database.')
  FROM auth.UserCredential AS c
  JOIN auth.[User]         AS u ON u.UserId = c.UserId
 WHERE c.UserId = @AliceId AND c.CredentialType = 'Password' AND c.IsDeleted = 0;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'13 G-12 expiry'
     , CASE WHEN c.ExpiresUtc IS NOT NULL AND DATEDIFF (DAY, c.LastChangedUtc, c.ExpiresUtc) = @Lifetime
            THEN 4 ELSE 2 END
     , CASE WHEN c.ExpiresUtc IS NOT NULL AND DATEDIFF (DAY, c.LastChangedUtc, c.ExpiresUtc) = @Lifetime
            THEN 'OK' ELSE 'DEFECT' END
     , N'G-12: ExpiresUtc is stamped from Authn.PasswordLifetimeDays at the moment of the change'
     , CONCAT (N'Authn.PasswordLifetimeDays was ', COALESCE (@SavedDays, N'(absent)'), N' and was set to ', @Lifetime
             , N' for this one call. LastChangedUtc ', CONVERT (NVARCHAR (30), c.LastChangedUtc, 126), N', ExpiresUtc '
             , COALESCE (CONVERT (NVARCHAR (30), c.ExpiresUtc, 126), N'(still null)'), N', which is '
             , CAST (DATEDIFF (DAY, c.LastChangedUtc, c.ExpiresUtc) AS NVARCHAR (11)), N' day(s) later. The shipped '
             , N'value is 0 and 0 means NO EXPIRY -- so this column stays NULL in a default deployment and '
             , N'auth.uspExpireCredentials has nothing to find, which is deliberate: a template that expired every '
             , N'password ninety days after installation would be a template nobody could demonstrate. What G-12 fixed '
             , N'is that there was no way to turn it ON. The warning half -- PasswordExpiresInDays and '
             , N'PasswordExpiryWarning from auth.uspGetProfileContext -- needs a PROFILE session, which this file has no '
             , N'profiles for; _tests/070_variants_end_to_end.sql is where a page header is assembled.')
  FROM auth.UserCredential AS c
 WHERE c.UserId = @AliceId AND c.CredentialType = 'Password' AND c.IsDeleted = 0;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'13 Password change'
     , CASE WHEN s.EndedUtc IS NULL AND s.IsDeleted = 0 THEN 4 ELSE 2 END
     , CASE WHEN s.EndedUtc IS NULL AND s.IsDeleted = 0 THEN 'OK' ELSE 'DEFECT' END
     , N'The session that changed the password is STILL LIVE, which is the decision and not an oversight'
     , CONCAT (N'Session ', s.UserSessionId, N', EndedUtc '
             , COALESCE (CONVERT (NVARCHAR (30), s.EndedUtc, 126), N'(null, as intended)'), N'. A change performed by '
             , N'the account holder is not a compromise response: the session was proved before the change, and signing '
             , N'somebody out of the page they just used costs them a re-login and buys nothing. A deployment that '
             , N'wants the stricter behaviour calls auth.uspEndSession @UserId next, and section 16.2 says so. The '
             , N'administrative reset -- auth.uspSetPassword -- takes the opposite decision for the opposite reason, '
             , N'and ends every session the account holds.')
  FROM auth.UserSession AS s
 WHERE s.SessionTokenHash = @Token;

-- 13d.  E-50222.  The refusal is the caller's report, believed -- and it is only consulted while a depth is configured,
--       because a deployment keeping no history cannot have a reuse policy to enforce.
BEGIN TRY
    EXEC auth.uspChangePassword @SessionTokenHash = @Token, @CurrentPasswordVerified = 1
                              , @NewVerifierPhc = @NewVerifier, @NewVerifierReusesHistory = 1;
END TRY
BEGIN CATCH
    SET @Err50222 = ERROR_NUMBER ();
END CATCH;

INSERT #Observation (Section, Severity, Status, Item, Detail)
VALUES (N'13 Password change', CASE WHEN @Err50222 = 50222 AND @Depth > 0 THEN 4 ELSE 2 END
      , CASE WHEN @Err50222 = 50222 AND @Depth > 0 THEN 'OK' ELSE 'DEFECT' END
      , N'A password the application reports as reused is refused E-50222'
      , CONCAT (N'Error ', COALESCE (CAST (@Err50222 AS NVARCHAR (11)), N'(none)'), N', expected 50222, with '
              , N'Authn.PasswordHistoryDepth = ', COALESCE (CAST (@Depth AS NVARCHAR (11)), N'(absent)')
              , N'. Set that setting to 0 and this same call succeeds, which is the intended behaviour and not a hole: '
              , N'refusing on a caller''s report of a rule nobody configured would be a control nobody asked for. Note '
              , N'which side does the comparing -- the application was handed the retired verifiers by '
              , N'auth.uspGetPasswordChangeContext and reported a verdict, because salted hashes cannot be compared '
              , N'here. The database''s job is to keep the history, hand it over, and believe the answer.'));

-- 13e.  Put the deployment back.  The verifier is deliberately NOT restored -- it is random per run by design, and
--       nothing in this file depends on its value -- but the expiry and the setting are, and so is the history.
UPDATE config.ApplicationSetting
   SET SettingValue    = COALESCE (@SavedDays, N'0')
     , auditModifiedBy = @Actor
 WHERE SettingKey = N'Authn.PasswordLifetimeDays' AND IsDeleted = 0;

UPDATE auth.UserCredential
   SET ExpiresUtc      = NULL
     , auditModifiedBy = @Actor
 WHERE UserId = @AliceId AND CredentialType = 'Password' AND IsDeleted = 0;

UPDATE auth.PasswordHistory
   SET IsDeleted           = 1
     , auditDeletedBy      = @Actor
     , auditDeletedDateUtc = SYSUTCDATETIME ()
     , auditModifiedBy     = @Actor
 WHERE UserId = @AliceId AND IsDeleted = 0;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'13 Password change'
     , CASE WHEN c.ExpiresUtc IS NULL
             AND (SELECT SettingValue FROM config.ApplicationSetting
                   WHERE SettingKey = N'Authn.PasswordLifetimeDays' AND IsDeleted = 0) = COALESCE (@SavedDays, N'0')
            THEN 4 ELSE 2 END
     , CASE WHEN c.ExpiresUtc IS NULL THEN 'OK' ELSE 'DEFECT' END
     , N'The section leaves no expiry and no setting behind'
     , CONCAT (N'ExpiresUtc is now '
             , COALESCE (CONVERT (NVARCHAR (30), c.ExpiresUtc, 126), N'(null, as intended)')
             , N' and Authn.PasswordLifetimeDays is back to '
             , (SELECT SettingValue FROM config.ApplicationSetting
                 WHERE SettingKey = N'Authn.PasswordLifetimeDays' AND IsDeleted = 0)
             , N'. The history rows this section created are soft-deleted, with the audit pair set in the same '
             , N'statement -- CK_auth_PasswordHistory_DeletedPair is checked before the AFTER trigger can fill it in, '
             , N'so a hand soft-delete anywhere in this schema sets IsDeleted, auditDeletedBy and auditDeletedDateUtc '
             , N'together or raises Msg 547.')
  FROM auth.UserCredential AS c
 WHERE c.UserId = @AliceId AND c.CredentialType = 'Password' AND c.IsDeleted = 0;
GO


-- *** 14. The report, and the verdict ***
-- Severity 1 is an exit criterion that did not hold; severity 2 is a defect that is not itself an exit criterion; 3 is a
-- note the reader needs; 4 is an observation that came out as intended.  The THROW at the end fires on 1 or 2, and on
-- nothing else, so a file full of notes still exits zero.
-- What this file did NOT test, recorded in its own output rather than only in its banner.  A reader who sees forty
-- passing rows and no mention of the gaps would reasonably conclude Phase 2 is finished, and it is not.
INSERT #Observation (Section, Severity, Status, Item, Detail)
VALUES (N'14 Not tested', 3, 'NOTE'
      , N'The ENCRYPTION of an MFA secret is the application''s work and is not tested here -- G-07, closed'
      , N'T-041 is no longer the blocked hole this row used to describe: section 12 enrols, confirms, issues codes and '
      + N're-keys, and frank signs in at the end of it. What remains untestable HERE is the one thing the G-07 decision '
      + N'moved out of this database on purpose -- the wrapping of the secret under a TPM-backed CNG key in the '
      + N'application layer. Every @SecretCiphertext above is CRYPT_GEN_RANDOM, and the database''s only claims about '
      + N'those bytes are their length and their key LABEL, both of which ARE asserted. tools/ and the .NET harness are '
      + N'where a real envelope is made and opened; a database test that claimed to check it would be checking nothing.')
     , (N'14 Not tested', 3, 'NOTE'
      , N'G-21 is closed: auth.TenantTrustedIssuer now constrains WHICH issuer may open an exchange'
      , N'This row used to be a filed gap. auth.uspBeginSsoLogin takes @Issuer and resolves the trusted-issuer list the '
      + N'way a policy row resolves -- the nearest ancestor holding a list owns it WHOLE -- and refuses an issuer that '
      + N'is not on it with E-50124, before the redirect rather than after it. It is not proved HERE because this '
      + N'fixture deliberately gives AUTHTEST_ACME no list, which is the OTHER half of the rule and the half section 9 '
      + N'needs: a tenant with no list anywhere above it trusts whatever link it already holds, so an existing '
      + N'deployment does not break the day the table arrives. The refusal is probed in '
      + N'_tests/080_error_catalogue.sql, which can afford to add a list to a tenant and take it away again.')
     , (N'14 Not tested', 3, 'NOTE'
      , N'The Argon2id computation is the application''s, by construction -- D-08'
      , N'Every uspCompleteLogin call here passes @PasswordVerified explicitly, which is exactly the boundary the '
      + N'design draws: the database decides what a verified password ENTITLES you to, and never what one IS. '
      + N'tools/T040-PasswordVerification is where a real Argon2id digest is computed, by a client, against a verifier '
      + N'string this database issued -- and where the derived dummy is shown to be indistinguishable from one.');

SELECT Severity, Status, Section, Item, Detail
  FROM #Observation
 ORDER BY RowNo;
GO

-- The exit criteria, restated and counted separately from the experiments, because "no failures" and "all four criteria
-- were actually exercised" are different claims and a test file that only makes the first one can pass by omission.
DECLARE @Criteria TABLE
(
    Criterion  NVARCHAR (200) NOT NULL,
    Marker     NVARCHAR (200) NOT NULL
);

INSERT @Criteria (Criterion, Marker)
VALUES (N'All three routes authenticate'
      , N'EXIT CRITERION: route ')
     , (N'An unknown user costs the same work and yields the same message as a wrong password'
      , N'EXIT CRITERION: a wrong password and an unknown name')
     , (N'Lockout fires per account and per address independently'
      , N'EXIT CRITERION: independence')
     , (N'INV-07 holds -- a federated identity resolves on (Issuer, SubjectId)'
      , N'INV-07')
     , (N'INV-08 holds -- the bypass route always requires a second factor'
      , N'INV-08');

SELECT c.Criterion
     , Exercised = (SELECT COUNT (*) FROM #Observation AS o WHERE o.Item LIKE N'%' + c.Marker + N'%')
     , Failed    = (SELECT COUNT (*) FROM #Observation AS o
                     WHERE o.Item LIKE N'%' + c.Marker + N'%' AND o.Severity <= 2)
  FROM @Criteria AS c;
GO

DECLARE @Violations INT = (SELECT COUNT (*) FROM #Observation WHERE Severity = 1)
      , @Defects    INT = (SELECT COUNT (*) FROM #Observation WHERE Severity = 2)
      , @Notes      INT = (SELECT COUNT (*) FROM #Observation WHERE Severity = 3)
      , @AsIntended INT = (SELECT COUNT (*) FROM #Observation WHERE Severity = 4);

IF @Violations > 0 OR @Defects > 0
BEGIN
    DECLARE @Fail NVARCHAR (2000) =
        CONCAT (N'Phase 2 identity and authentication: ', @Violations, N' exit-criterion violation(s) and ', @Defects
              , N' defect(s). The rows above carry the detail. Nothing has been cleaned up -- the fixture and every '
              , N'attempt row are still in place to be read, and the next run of this file resets them.');

    THROW 50000, @Fail, 1;
END;

PRINT CONCAT (N'Phase 2 identity and authentication: no problems found. ', @AsIntended, N' observation(s) came out as '
            , N'intended, with ', @Notes, N' note(s). All three routes authenticated, an unknown name was answered '
            , N'exactly as a wrong password was, and the two lockout arms were shown independent in both directions.');
GO
