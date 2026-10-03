/***********************************************************************************************************************
Script:         025_config_tables.sql
Purpose:        config.ApplicationSetting and config.TenantScopedTable, and the authentication settings Phase 2 reads.
Target:         SQL Server 2022.
Run as:         db_owner in the target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/025_config_tables.sql
Idempotent:     Yes.  Both CREATE TABLEs are guarded, every index is guarded, and the seed is INSERT-ONLY -- see the
                note on convergence below.  Nothing is ever dropped and no tuned value is ever overwritten.
Depends on:     database/005_schemas_and_roles.sql (schema config), templates/extended-properties.sql
                (util.uspSetObjectDescription).
Implements:     DES-AUTH-001 sections 6.4, 7.4, 10.1, 15.1 and 19.2.  PLAN-AUTH-001 task T-025 dependency -- see below,
                and T-041's four Authn.Mfa* key-custody settings (gap G-07, closed).
                Five later keys arrive in section 4 with the gaps that asked for them: Authn.PasswordLifetimeDays and
                Authn.PasswordExpiryWarningDays (G-12), Authn.RequireStepUpForPrivilegedDefault (G-30), and
                Registration.ThrottleThreshold with Registration.ThrottleWindowMinutes (G-06, G-24).  Two of them
                change a DEFAULT rather than adding a feature, and those are the ones to read: the step-up key exists
                because a missing policy row used to mean "no step-up required", and this database now fails closed.
To retarget:    Pass it per run:  sqlcmd -d <database> -v DbName=<database>.  There is no in-file default.

WHY THIS SCRIPT IS WRITTEN IN PHASE 2 WHEN ITS BUILD PHASE IS 4
---------------------------------------------------------------
The Scripts worksheet assigns 025_config_tables.sql to build phase 4, Configuration, and that is where the rest of its
content belongs: the UI catalogue settings, the RLS registry rows for the demo domain, everything an administrator
tunes on a running system.

Phase 2's exit criteria include "lockout fires per account and per address independently", and section 7.4 says in
terms that the thresholds and windows are config.ApplicationSetting rows and NOT constants.  Those two statements
cannot both be satisfied without this table.  The alternatives were to hard-code the numbers in
auth.uspRecordLoginFailure and change them later, or to declare the exit criterion met without ever having fired a
lockout.  The first is the shape that survives -- a constant nobody removes once the tests pass -- and the second is
not a criterion, it is a hope.

So the table is created here and the Authn.* keys are seeded here.  Build phase 4 adds rows and columns; it does not
revisit this decision.  The precedent is BL-021: auth.TenantType is seeded by 030_auth_tenant.sql rather than by
115_seed_reference_data.sql, for the same reason -- the phase that needs the data is earlier than the phase that owns
the seeding script, and moving the data is cheaper than moving the phase.

THE SEED IS INSERT-ONLY, AND THAT IS A DELIBERATE DEPARTURE FROM "MERGE SO IT CONVERGES"
----------------------------------------------------------------------------------------
Every other seed in this deployment is a MERGE with a WHEN MATCHED branch, so a re-run restores the shipped value.
This one has no WHEN MATCHED branch at all: WHEN NOT MATCHED BY TARGET THEN INSERT, and nothing else.

The reason is what the rows are.  A tenant type code is a fact about the design; if somebody edits it, the edit is the
defect and the re-run is the fix.  A lockout threshold is a decision about THIS deployment; an operator who raised
Authn.LockoutThreshold from 5 to 10 at the request of a service desk did not make a mistake, and a deployment that
silently put it back to 5 would be one.  Converging on the PRESENCE of the key is the whole of what this script may
assert.  Section 8 reports every seeded key with its current value next to the shipped default, so a divergence is
visible without being corrected.

IsSensitive DOES NOT ENCRYPT ANYTHING
-------------------------------------
It is a flag that says "do not put this value in a report, a log, or a screen an administrator can read".  Nothing in
the database enforces that -- config.vwApplicationSetting (phase 4) masks the value, the closing report below masks
it, and code that reads the table directly is on its honour.  Authn.DummyVerifierPepper is the one row in this script
that carries it, and the consequence of leaking that value is that the enumeration defence of section 19.2 stops
working: an attacker who knows the pepper can compute the dummy verifier for any name and compare.  That is a real
loss, and it is not a credential, so the flag is the right weight for it.

THE Authn.Mfa* KEYS NAME A KEY AND MUST NEVER CONTAIN ONE
---------------------------------------------------------
T-041 closed gap G-07 with a management decision: application-side envelope encryption, the key held by the application
layer in a TPM-backed CNG container, and NOTHING about the key in this database.  Always Encrypted was rejected because
Power BI and other external readers need the tables and because a template cannot know which columns a deployment will
add.  Section 6.4 records the whole decision.

What that leaves here is a NAME: Authn.MfaKeyReferenceCurrent holds the identifier of the key currently in use, in the
grammar auth.UserMfaFactor.KeyReference enforces.  It is not IsSensitive, because there is nothing sensitive in it -- and
marking it sensitive would be worse than useless, because it would suggest the value is the kind of thing that could be a
key.  A deployment that pastes key material into this row has defeated the design in one edit, and no constraint in SQL
Server can tell a 44-character base64 key from a 44-character key name.  The defence is that the name is short, obvious
and reviewed: cng:<container>#v<n>, vault:<path>#v<n>, or dev:<anything> on a workstation.
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

IF SCHEMA_ID (N'config') IS NULL
BEGIN
    DECLARE @Msg NVARCHAR (2000) =
        N'Schema [config] does not exist. Run database/005_schemas_and_roles.sql first. Nothing has been changed.';

    THROW 50000, @Msg, 1;
END
GO


-- *** 1. config.ApplicationSetting ***
-- SettingValue is NVARCHAR (4000) and every value in it is a string, including the integers.  A typed column per kind
-- was considered and rejected: five nullable columns with a CHECK tying exactly one of them to ValueKind is more
-- surface than CAST at the point of use, and the point of use is a handful of procedures that each want one key.
--
-- ValueKind is therefore documentation with teeth rather than storage: it tells a reader and an administration screen
-- what CAST is safe, and the CHECK stops a sixth kind appearing without anybody deciding it exists.
IF OBJECT_ID (N'config.ApplicationSetting', N'U') IS NULL
BEGIN
    CREATE TABLE config.ApplicationSetting
    (
        ApplicationSettingId INT            IDENTITY (1, 1) NOT NULL
      , SettingKey           NVARCHAR (128)                 NOT NULL
      , SettingValue         NVARCHAR (4000)                NOT NULL
      , ValueKind            VARCHAR (10)                   NOT NULL
            CONSTRAINT DF_config_ApplicationSetting_ValueKind DEFAULT ('String')
      , SettingDescription   NVARCHAR (1000)                NOT NULL
      , ShippedDefault       NVARCHAR (4000)                    NULL
      , IsSensitive          BIT                            NOT NULL
            CONSTRAINT DF_config_ApplicationSetting_IsSensitive DEFAULT (0)
      , IsDeleted            BIT                            NOT NULL
            CONSTRAINT DF_config_ApplicationSetting_IsDeleted DEFAULT (0)
      , auditDeletedBy       NVARCHAR (255)                     NULL
      , auditDeletedDateUtc  DATETIME2 (3)                      NULL
      , auditCreatedBy       NVARCHAR (255)                 NOT NULL
            CONSTRAINT DF_config_ApplicationSetting_auditCreatedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditCreatedDateUtc  DATETIME2 (3)                  NOT NULL
            CONSTRAINT DF_config_ApplicationSetting_auditCreatedDateUtc DEFAULT (SYSUTCDATETIME ())
      , auditModifiedBy      NVARCHAR (255)                 NOT NULL
            CONSTRAINT DF_config_ApplicationSetting_auditModifiedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditModifiedDateUtc DATETIME2 (3)                  NOT NULL
            CONSTRAINT DF_config_ApplicationSetting_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ())
      , CONSTRAINT PK_config_ApplicationSetting PRIMARY KEY CLUSTERED (ApplicationSettingId)
      , CONSTRAINT CK_config_ApplicationSetting_SettingKey
            CHECK (LEN (SettingKey) > 0 AND SettingKey = LTRIM (RTRIM (SettingKey)))
      , CONSTRAINT CK_config_ApplicationSetting_ValueKind
            CHECK (ValueKind IN ('Int', 'Bool', 'String', 'Json', 'Decimal'))
      , CONSTRAINT CK_config_ApplicationSetting_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS     NULL AND auditDeletedDateUtc IS     NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL))
    );
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'UX_config_ApplicationSetting_SettingKey'
                  AND object_id = OBJECT_ID (N'config.ApplicationSetting'))
BEGIN
    CREATE UNIQUE INDEX UX_config_ApplicationSetting_SettingKey
        ON config.ApplicationSetting (SettingKey) WHERE IsDeleted = 0;
END
GO


-- *** 2. config.TenantScopedTable ***
-- The registry 120_rls_policy.sql reads.  An unregistered tenant table is an UNPROTECTED tenant table -- section 10.1
-- -- which is why 950_verify_deployment.sql asserts the other direction as well: every table carrying a TenantId
-- column must appear here, so forgetting to register one is a reported finding rather than a silent hole.
--
-- TenantColumnName is stored rather than assumed to be 'TenantId' because the demo domain is not the only consumer
-- and a table that reaches its tenant through a profile column needs to say so.
IF OBJECT_ID (N'config.TenantScopedTable', N'U') IS NULL
BEGIN
    CREATE TABLE config.TenantScopedTable
    (
        TenantScopedTableId  INT            IDENTITY (1, 1) NOT NULL
      , SchemaName           SYSNAME                        NOT NULL
      , TableName            SYSNAME                        NOT NULL
      , TenantColumnName     SYSNAME                        NOT NULL
            CONSTRAINT DF_config_TenantScopedTable_TenantColumnName DEFAULT (N'TenantId')
      , IsActive             BIT                            NOT NULL
            CONSTRAINT DF_config_TenantScopedTable_IsActive DEFAULT (1)
      , RegistrationNote     NVARCHAR (1000)                    NULL
      , IsDeleted            BIT                            NOT NULL
            CONSTRAINT DF_config_TenantScopedTable_IsDeleted DEFAULT (0)
      , auditDeletedBy       NVARCHAR (255)                     NULL
      , auditDeletedDateUtc  DATETIME2 (3)                      NULL
      , auditCreatedBy       NVARCHAR (255)                 NOT NULL
            CONSTRAINT DF_config_TenantScopedTable_auditCreatedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditCreatedDateUtc  DATETIME2 (3)                  NOT NULL
            CONSTRAINT DF_config_TenantScopedTable_auditCreatedDateUtc DEFAULT (SYSUTCDATETIME ())
      , auditModifiedBy      NVARCHAR (255)                 NOT NULL
            CONSTRAINT DF_config_TenantScopedTable_auditModifiedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditModifiedDateUtc DATETIME2 (3)                  NOT NULL
            CONSTRAINT DF_config_TenantScopedTable_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ())
      , CONSTRAINT PK_config_TenantScopedTable PRIMARY KEY CLUSTERED (TenantScopedTableId)
      , CONSTRAINT CK_config_TenantScopedTable_SchemaName
            CHECK (LEN (SchemaName) > 0 AND SchemaName = LTRIM (RTRIM (SchemaName)))
      , CONSTRAINT CK_config_TenantScopedTable_TableName
            CHECK (LEN (TableName) > 0 AND TableName = LTRIM (RTRIM (TableName)))
      , CONSTRAINT CK_config_TenantScopedTable_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS     NULL AND auditDeletedDateUtc IS     NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL))
    );
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'UX_config_TenantScopedTable_Table'
                  AND object_id = OBJECT_ID (N'config.TenantScopedTable'))
BEGIN
    CREATE UNIQUE INDEX UX_config_TenantScopedTable_Table
        ON config.TenantScopedTable (SchemaName, TableName) WHERE IsDeleted = 0;
END
GO


-- *** 3. Audit triggers ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   config.trg_au_updt_ApplicationSetting
Author:       rsincero
CreateDate:   2026-09-19
Description:
AFTER UPDATE audit stamp for config.ApplicationSetting.  Sets auditModifiedBy and auditModifiedDateUtc on every update,
and the soft-delete pair on the 0 -> 1 transition of IsDeleted.  SettingKey is immutable: renaming a key is deleting
one and adding another, because every reader names the key as a literal and a rename breaks them silently.

Modification History:
2026-09-19  rsincero  Created.  PLAN-AUTH-001 T-036 dependency.
***********************************************************************************************************************/
CREATE OR ALTER TRIGGER config.trg_au_updt_ApplicationSetting
    ON config.ApplicationSetting
    AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    IF UPDATE (SettingKey)
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.ApplicationSettingId = i.ApplicationSettingId
                    WHERE i.SettingKey <> d.SettingKey)
    BEGIN
        ;THROW 50010, N'config.ApplicationSetting.SettingKey is immutable. Soft-delete the row and insert the new key: every reader names the key as a literal.', 1;
    END;

    DECLARE @Now   DATETIME2 (3)  = SYSUTCDATETIME ()
          , @Actor NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                            , ORIGINAL_LOGIN ());

    UPDATE s
       SET s.auditModifiedDateUtc = @Now
         , s.auditModifiedBy      = CASE WHEN UPDATE (auditModifiedBy)
                                         THEN COALESCE (NULLIF (i.auditModifiedBy, N''), @Actor)
                                         ELSE @Actor END
         , s.auditDeletedBy       = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Actor ELSE s.auditDeletedBy      END
         , s.auditDeletedDateUtc  = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Now   ELSE s.auditDeletedDateUtc END
      FROM config.ApplicationSetting AS s
      JOIN inserted                  AS i ON i.ApplicationSettingId = s.ApplicationSettingId
      JOIN deleted                   AS d ON d.ApplicationSettingId = s.ApplicationSettingId;
END;
GO

SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   config.trg_au_updt_TenantScopedTable
Author:       rsincero
CreateDate:   2026-09-19
Description:
AFTER UPDATE audit stamp for config.TenantScopedTable.  SchemaName and TableName are immutable for the same reason
SettingKey is: 120_rls_policy.sql resolves them to object identifiers, and a rename here would leave a live predicate
bound to an object this registry no longer claims to protect.

Modification History:
2026-09-19  rsincero  Created.  PLAN-AUTH-001 T-025 dependency.
***********************************************************************************************************************/
CREATE OR ALTER TRIGGER config.trg_au_updt_TenantScopedTable
    ON config.TenantScopedTable
    AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    IF (UPDATE (SchemaName) OR UPDATE (TableName))
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.TenantScopedTableId = i.TenantScopedTableId
                    WHERE i.SchemaName <> d.SchemaName
                       OR i.TableName  <> d.TableName)
    BEGIN
        ;THROW 50010, N'config.TenantScopedTable identifies a table and cannot be re-pointed. Soft-delete the row and register the other table.', 1;
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
      FROM config.TenantScopedTable AS t
      JOIN inserted                 AS i ON i.TenantScopedTableId = t.TenantScopedTableId
      JOIN deleted                  AS d ON d.TenantScopedTableId = t.TenantScopedTableId;
END;
GO


-- *** 4. Seed the settings Phase 2 reads ***
--
-- INSERT-ONLY.  See the header: there is no WHEN MATCHED branch, on purpose, because an operator who tuned one of
-- these did not make a mistake.  Re-running this script converges on the keys EXISTING and says nothing about their
-- values; section 8 reports any divergence from ShippedDefault without touching it.
--
-- ShippedDefault is stored alongside SettingValue so the report can do that.  Deriving it from this script would mean
-- reading the script, and the whole point of the report is that it runs against a database somebody else deployed.
DECLARE @Pepper NVARCHAR (100) = CONVERT (NVARCHAR (100), CRYPT_GEN_RANDOM (32), 2);

;WITH shipped (SettingKey, SettingValue, ValueKind, IsSensitive, SettingDescription) AS
(
    SELECT * FROM (VALUES
      -- Lockout.  Section 7.4.  auth.uspRecordLoginFailure reads all five on every failure.
        (N'Authn.LockoutThreshold',            N'5',   'Int',  0, N'Failures against one account inside Authn.LockoutWindowMinutes that lock it. Section 7.4.')
      , (N'Authn.LockoutWindowMinutes',        N'15',  'Int',  0, N'The window the per-account failure count is taken over, in minutes. Section 7.4.')
      , (N'Authn.LockoutDurationMinutes',      N'15',  'Int',  0, N'How far forward auth.User.LockoutEndUtc is set when an account locks, in minutes. Section 7.4.')
      , (N'Authn.AddressThreshold',            N'20',  'Int',  0, N'Failures from one client address inside Authn.AddressWindowMinutes that throttle it, regardless of which accounts were tried. This is the credential-stuffing control; the per-account threshold is not. Section 7.4.')
      , (N'Authn.AddressWindowMinutes',        N'15',  'Int',  0, N'The window the per-address failure count is taken over, in minutes. Section 7.4.')

      -- The sign-in exchange.  D-14.
      , (N'Authn.LoginExchangeTimeoutSeconds', N'300', 'Int',  0, N'How long an auth.LoginAttempt row issued by uspGetLoginVerifier or uspBeginSsoLogin may still be completed. An exchange older than this raises E-50105. D-14.')

      -- Sessions.  Used only when auth.udfResolveAuthPolicy finds no policy row anywhere above the tenant.
      , (N'Authn.SessionLifetimeMinutes',      N'480', 'Int',  0, N'Absolute session lifetime in minutes, used ONLY when no auth.TenantAuthenticationPolicy applies. A policy row overrides it. Section 7.3.')
      , (N'Authn.IdleTimeoutMinutes',          N'60',  'Int',  0, N'Idle timeout in minutes, used ONLY when no auth.TenantAuthenticationPolicy applies. A policy row overrides it. Section 7.3.')

      -- Credentials.
      , (N'Authn.PasswordHistoryDepth',        N'5',   'Int',  0, N'How many retired verifiers in auth.PasswordHistory a new password is compared against. Section 15.3.')

      -- Credential lifecycle.  Gap G-12.  auth.uspSetPassword and auth.uspChangePassword read the first of these to
      -- stamp auth.UserCredential.ExpiresUtc; auth.uspExpireCredentials acts on the stamp; auth.uspGetProfileContext
      -- reads the second to warn before the stamp is reached.  SHIPPED AT 0, which means passwords do not expire, and
      -- that is a POSITION rather than an oversight: current guidance prefers a reset driven by evidence of compromise
      -- over scheduled rotation, which mostly buys predictable password mutations.  A deployment whose policy says
      -- otherwise sets a number of days here and schedules auth.uspExpireCredentials; section 7 reports what it finds.
      , (N'Authn.PasswordLifetimeDays',        N'0',   'Int',  0, N'How many days a password set by auth.uspSetPassword or auth.uspChangePassword remains valid: the procedures stamp auth.UserCredential.ExpiresUtc this far ahead. 0 means NO EXPIRY and is the shipped value -- ExpiresUtc is left NULL and auth.uspExpireCredentials has nothing to find. Section 6.3, gap G-12.')
      , (N'Authn.PasswordExpiryWarningDays',   N'14',  'Int',  0, N'How many days before auth.UserCredential.ExpiresUtc auth.uspGetProfileContext begins returning PasswordExpiresInDays and PasswordExpiryWarning = 1, so the application can prompt before the sweep forces the change. Inert while Authn.PasswordLifetimeDays is 0, because nothing carries an ExpiresUtc to count down to. Section 6.3, gap G-12.')

      -- Step-up.  Gap G-30.  auth.udfResolveAuthPolicy returns NULL for a tenant with no policy row anywhere above it,
      -- and auth.uspSwitchProfile used to read that absence as the absence of the requirement -- a security template
      -- shipping the permissive default for a privileged operation.  It now falls back to THIS key, which ships at 1,
      -- so a deployment that has written no policy rows FAILS CLOSED and relaxing it is a decision somebody makes.
      , (N'Authn.RequireStepUpForPrivilegedDefault', N'1', 'Bool', 0, N'What RequireStepUpForPrivileged means when no auth.TenantAuthenticationPolicy row exists anywhere above the target tenant. Ships at 1 -- a privileged profile switch demands a step-up -- so the absence of configuration is the SAFE reading rather than the permissive one. A policy row that sets the flag explicitly always wins over this key; this is the fallback only. Sections 7.2 and 12.3, gap G-30.')

      -- HOW LONG THE STEP-UP LASTS ONCE IT IS SATISFIED.  Gap G-48, T-125.  The key above decides whether a challenge is
      -- raised; this one decides how long answering it is worth.  auth.uspElevateSession reads it, clamps it to 1..480
      -- and writes LEAST (now + this, the session's AbsoluteExpiryUtc) into auth.UserSession.ElevatedUntilUtc -- so an
      -- elevation can never outlive the session it elevates, and the one limit section 7.3 says activity may not extend
      -- is not extendable by a second factor either.  Fifteen minutes is short enough that a stolen session token is not
      -- also a stolen privilege, and long enough to do the piece of administrative work the prompt interrupted.
      , (N'Authn.StepUpElevationMinutes',      N'15',  'Int',  0, N'How long a session stays elevated after auth.uspElevateSession accepts a second factor, in minutes: ElevatedUntilUtc is set to LEAST (now + this, AbsoluteExpiryUtc). Clamped to 1..480 by the procedure whatever is written here -- 0 would open a window that has already closed and CK_auth_UserSession_ElevatedUntilUtc would refuse it with error 547. Re-elevating never shortens a window still open. Sections 12.3 and 14.5, gap G-48.')

      -- Registration throttle.  Gaps G-06 and G-24.  The per-address arm of the public registration entry points, in
      -- the shape section 11.5 uses for sign-in.  This is the DATABASE half only: a throttle behind an unlimited
      -- public form is one an attacker pays for once per address, so the gateway and the form still owe a rate limit
      -- and a CAPTCHA.  Section 16.4 says so in the place a deployment will read it.
      , (N'Registration.ThrottleThreshold',    N'10',  'Int',  0, N'Registration attempts from one client address inside Registration.ThrottleWindowMinutes that throttle it, counted over auth.RegistrationAttempt and regardless of outcome. Crossing it raises E-50068. Set to 0 to disable the database throttle entirely, which leaves the public form defended only at the edge. Section 16.4, gaps G-06 and G-24.')
      , (N'Registration.ThrottleWindowMinutes', N'60', 'Int',  0, N'The window the per-address registration count is taken over, in minutes. Wider than the sign-in window (Authn.AddressWindowMinutes) on purpose: a person registers an organization once, so an hour of history is not an inconvenience to anybody legitimate. Section 16.4, gap G-24.')

      -- The second factor.  Section 6.2.  The database cannot verify a TOTP code -- the secret is encrypted under a key
      -- the application holds and this server must never see (G-07, closed) -- so these two bound the time step the
      -- application reports.
      , (N'Authn.TotpStepSeconds',             N'30',  'Int',  0, N'The TOTP time step in seconds. auth.uspVerifyMfa uses it to convert its own clock into a step number and bound the step the application reports. Section 6.2.')
      , (N'Authn.TotpWindowSteps',             N'1',   'Int',  0, N'How many steps either side of the server''s current step auth.uspVerifyMfa will accept, for clock skew. 1 means a 90-second total window. Raising it widens the replay window as well. Section 6.2.')

      -- Key custody.  Section 6.4, task T-041, gap G-07 closed.  These name the key; they never contain it.  The value
      -- of MfaKeyReferenceCurrent is what auth.uspEnrolMfaFactor stamps on a new factor, and CK_auth_UserMfaFactor_
      -- KeyReferenceFormat is what stops a plausible-looking secret being stored under a reference nobody can resolve.
      , (N'Authn.MfaKeyReferenceCurrent',      N'dev:local/authn-mfa-kek#v1', 'String', 0, N'The KeyReference auth.uspEnrolMfaFactor stamps on a newly enrolled factor: which key encrypted its SecretCiphertext. An IDENTIFIER and never key material -- a deployment that put a key here has lost the property the whole design rests on. The shipped value begins dev:, which the closing reports of 025, 045 and 112 flag as NOT PRODUCTION; a real single-server deployment sets cng:<container>#v<n> for its TPM-backed CNG key, and a Vault deployment sets vault:<path>#v<n>. Section 6.4.')
      , (N'Authn.MfaKeyReferenceSchemes',      N'cng,vault,dev', 'String', 0, N'The scheme prefixes a KeyReference may use, as a comma-separated list, for the APPLICATION to validate against before it calls uspEnrolMfaFactor. cng = a TPM-backed CNG key on the application-layer server (the recommended single-server custody); vault = a self-hosted HashiCorp Vault, the seam left open in case management chooses it; dev = a development key with no hardware protection. The database enforces the GRAMMAR in a CHECK constraint, not this list, because SQL Server 2022 has no regex and a list-driven check would need dynamic SQL. Section 6.4.')
      , (N'Authn.MfaEnrolmentWindowSeconds',   N'900', 'Int',  0, N'How long after a sign-in that was refused with E-50109 (policy requires MFA, no confirmed factor) auth.uspEnrolMfaFactor will still accept that auth.LoginAttempt row as proof of who is enrolling. This is the bootstrap path and nothing else: it applies only to a FIRST factor, only when the database itself wrote PasswordVerified = 1 on that row, and it cannot enrol a second factor or replace an existing one. Lowering it shortens the window; setting it to 0 disables self-service bootstrap and makes first-factor enrolment an administrative act. Section 6.4.')
      , (N'Authn.MfaRecoveryCodeCount',        N'10',  'Int',  0, N'How many single-use recovery codes auth.uspIssueMfaRecoveryCodes expects in one batch. The application generates the codes, shows them once and sends only their SHA-256 hashes; this bounds the batch so a caller cannot fill the table, and the closing report of 112 compares it against what was actually issued. Section 6.2.')

      -- Enumeration resistance.  Section 19.2.
      , (N'Authn.DummyVerifierPhcTemplate',    N'$argon2id$v=19$m=19456,t=2,p=1${salt:22}${hash:43}', 'String', 0, N'The PHC string shape uspGetLoginVerifier returns for an account that cannot sign in. {salt:n} and {hash:n} are replaced with the first n characters of two domain-separated base64 hashes of Authn.DummyVerifierPepper and the submitted user name. The algorithm, parameters and FIELD LENGTHS must match a real verifier or the difference is itself the enumeration signal. Section 19.2.')
      , (N'Authn.DummyVerifierPepper',         @Pepper, 'String', 1, N'Per-install random value the dummy verifier is derived from, so the dummy differs per user name and cannot be recognised as a constant. Not a credential: leaking it costs the enumeration defence of section 19.2, nothing else. Generated by CRYPT_GEN_RANDOM (32) on first deployment and never regenerated.')

      -- Authorization.  Read in Phase 3 by auth.uspAssignRoleToProfile; seeded here because the key is named in 15.1.
      , (N'Authz.AllowSelfGrant',              N'0',   'Bool', 0, N'When 1, INV-06 is relaxed and a profile may grant a role to another profile of its own user. E-50044 is raised when this is 0. Section 11.3.')
    ) AS v (SettingKey, SettingValue, ValueKind, IsSensitive, SettingDescription)
)
MERGE config.ApplicationSetting AS tgt
USING shipped                    AS src
   ON tgt.SettingKey = src.SettingKey

WHEN NOT MATCHED BY TARGET
    THEN INSERT (SettingKey, SettingValue, ValueKind, IsSensitive, SettingDescription, ShippedDefault)
         VALUES (src.SettingKey, src.SettingValue, src.ValueKind, src.IsSensitive, src.SettingDescription
               -- The pepper has no shipped default: it is random per install, so there is nothing to diverge from.
               , CASE WHEN src.SettingKey = N'Authn.DummyVerifierPepper' THEN NULL ELSE src.SettingValue END);
GO

-- config.TenantScopedTable is deliberately left EMPTY here.  The only tenant-scoped tables this design ships are
-- dbo.CaseFile and dbo.CaseNote, which 090_dbo_application.sql creates, and registering a table that does not exist
-- would hand 120_rls_policy.sql a row it cannot resolve.  115_seed_reference_data.sql registers them, after 090.
GO


-- *** 5. Descriptions ***
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
      (N'config', N'TABLE', N'ApplicationSetting', NULL, N'Everything about a running deployment that must be tunable without a code change: lockout thresholds and windows, session lifetimes, TOTP window, Authz.AllowSelfGrant. Section 15.1. Seeded INSERT-ONLY by 025_config_tables.sql so a re-deployment never overwrites a tuned value.')
    , (N'config', N'TABLE', N'ApplicationSetting', N'SettingKey',         N'The key, as a dotted literal -- Authn.LockoutThreshold. Immutable: every reader names it as a literal, so a rename breaks them silently. Unique where IsDeleted = 0.')
    , (N'config', N'TABLE', N'ApplicationSetting', N'SettingValue',       N'The current value, always as a string. The caller CASTs according to ValueKind.')
    , (N'config', N'TABLE', N'ApplicationSetting', N'ValueKind',          N'Int, Bool, String, Json or Decimal. Tells a reader and an administration screen what CAST is safe; it is not storage.')
    , (N'config', N'TABLE', N'ApplicationSetting', N'SettingDescription', N'What the key controls and which design section defines it. Shown on the configuration screen.')
    , (N'config', N'TABLE', N'ApplicationSetting', N'ShippedDefault',     N'The value 025_config_tables.sql would have inserted. Kept so the closing report can name a divergence without correcting it. NULL for Authn.DummyVerifierPepper, which is random per install.')
    , (N'config', N'TABLE', N'ApplicationSetting', N'IsSensitive',        N'1 means do not put this value in a report, a log, or a screen. Enforced by convention and by the masking in the reports, not by the database.')

    , (N'config', N'TABLE', N'TenantScopedTable', NULL, N'The registry 120_rls_policy.sql reads to decide which tables get a row-level security predicate. An unregistered tenant table is an unprotected tenant table -- section 10.1 -- so 950_verify_deployment.sql asserts the other direction too.')
    , (N'config', N'TABLE', N'TenantScopedTable', N'SchemaName',       N'Schema of the protected table. Immutable together with TableName: a live predicate is bound to an object identifier.')
    , (N'config', N'TABLE', N'TenantScopedTable', N'TableName',        N'Name of the protected table. Unique with SchemaName where IsDeleted = 0.')
    , (N'config', N'TABLE', N'TenantScopedTable', N'TenantColumnName', N'The column on that table the predicate compares against the acting tenant. Stored rather than assumed to be TenantId, because a table that reaches its tenant another way still needs protecting.')
    , (N'config', N'TABLE', N'TenantScopedTable', N'IsActive',         N'0 suspends the predicate for this table without losing the registration. A suspended row is still reported by 950_verify_deployment.sql, which is the point.')
    , (N'config', N'TABLE', N'TenantScopedTable', N'RegistrationNote', N'Why this table is registered, or why a column other than TenantId was chosen. Read by whoever next audits the registry.');

    -- The seven audit columns carry the same description on every table, so they are generated rather than typed out.
    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    SELECT N'config', N'TABLE', t.TableName, c.ColumnName, c.Description
      FROM (VALUES (N'ApplicationSetting'), (N'TenantScopedTable')) AS t (TableName)
     CROSS JOIN (VALUES
          (N'IsDeleted',            N'Soft-delete flag. 1 means the row is gone as far as the application is concerned; nothing in this database hard-deletes.')
        , (N'auditDeletedBy',       N'Who soft-deleted the row. NULL unless IsDeleted = 1 -- the pair is enforced by CK_<table>_DeletedPair.')
        , (N'auditDeletedDateUtc',  N'When the row was soft-deleted, UTC. NULL unless IsDeleted = 1.')
        , (N'auditCreatedBy',       N'Who inserted the row. Defaults to ORIGINAL_LOGIN (); a procedure sets it to the acting profile instead.')
        , (N'auditCreatedDateUtc',  N'When the row was inserted, UTC.')
        , (N'auditModifiedBy',      N'Who last updated the row, set by the AFTER UPDATE trigger from SESSION_CONTEXT (''AppUser'') or ORIGINAL_LOGIN ().')
        , (N'auditModifiedDateUtc', N'When the row was last updated, UTC, set by the AFTER UPDATE trigger.')
       ) AS c (ColumnName, Description);

    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    VALUES
      (N'config', N'TRIGGER', N'trg_au_updt_ApplicationSetting', NULL, N'AFTER UPDATE audit stamp for config.ApplicationSetting. Also enforces that SettingKey is immutable -- E-50010.')
    , (N'config', N'TRIGGER', N'trg_au_updt_TenantScopedTable',  NULL, N'AFTER UPDATE audit stamp for config.TenantScopedTable. Also enforces that the table it identifies cannot be changed -- E-50010.');

    -- Assertion 11: the key and audit columns the list above left undescribed, found by 950_verify_deployment.sql,
    -- which fails a column without an MS_Description.
    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    VALUES
      (N'config', N'TABLE', N'ApplicationSetting', N'ApplicationSettingId', N'Surrogate key.')
    , (N'config', N'TABLE', N'TenantScopedTable', N'TenantScopedTableId', N'Surrogate key.');

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


-- *** 6. Grants ***
--
-- DELIBERATELY EMPTY, and not for the same reason as 030_auth_tenant.sql's empty grants section.
--
-- There, INV-11 forbids table access to SCHEMA::auth outright.  Here the position is narrower: config is READ by
-- almost everything and written by one administration procedure, so a schema-level SELECT for both application roles
-- is exactly right and a schema-level write grant is exactly wrong.  That is a single decision about the whole schema,
-- it is gap G-19's subject, and 170_permissions.sql is where it is made -- in one place, with the deny stated, next to
-- the same decision for every other schema.  Making half of it here would put the two halves in two files.
GO


-- *** 7. Closing report ***
DECLARE @Report TABLE
(
    RowNo    INT IDENTITY (1, 1) PRIMARY KEY,
    Severity INT             NOT NULL,
    Status   VARCHAR (10)    NOT NULL,
    Item     NVARCHAR (200)  NOT NULL,
    Detail   NVARCHAR (1000)     NULL
);

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (x.QualifiedName, N'U') IS NULL THEN 1 ELSE 4 END
     , CASE WHEN OBJECT_ID (x.QualifiedName, N'U') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Table ' + x.QualifiedName
     , x.Purpose
  FROM (VALUES (N'config.ApplicationSetting', N'Tunable settings. Section 15.1.')
             , (N'config.TenantScopedTable',  N'The row-level security registry read by 120_rls_policy.sql. Section 10.1.'))
       AS x (QualifiedName, Purpose);

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN i.name IS NULL THEN 2 ELSE 4 END
     , CASE WHEN i.name IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Unique index ' + x.IndexName
     , N'On ' + x.QualifiedName + N'. Filtered WHERE IsDeleted = 0, so a soft-deleted key can be reused.'
  FROM (VALUES (N'UX_config_ApplicationSetting_SettingKey', N'config.ApplicationSetting')
             , (N'UX_config_TenantScopedTable_Table',       N'config.TenantScopedTable'))
       AS x (IndexName, QualifiedName)
  LEFT JOIN sys.indexes AS i
         ON i.name = x.IndexName AND i.object_id = OBJECT_ID (x.QualifiedName);

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (x.QualifiedName, N'TR') IS NULL THEN 2 ELSE 4 END
     , CASE WHEN OBJECT_ID (x.QualifiedName, N'TR') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Trigger ' + x.QualifiedName
     , N'AFTER UPDATE audit stamp, and the immutability guard described in its header.'
  FROM (VALUES (N'config.trg_au_updt_ApplicationSetting')
             , (N'config.trg_au_updt_TenantScopedTable')) AS x (QualifiedName);

-- Every seeded key, present or not.  A MISSING key here means the seed in section 4 was edited and this list was not.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN s.SettingKey IS NULL THEN 1 ELSE 4 END
     , CASE WHEN s.SettingKey IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Setting ' + x.SettingKey
     , CASE WHEN s.SettingKey IS NULL
            THEN N'Not present. auth.uspRecordLoginFailure and auth.uspVerifyMfa read these keys and fail without them.'
            WHEN s.IsSensitive = 1
            THEN N'Present. Value withheld: IsSensitive = 1.'
            ELSE N'Present. Value: ' + s.SettingValue + N'.'
       END
  FROM (VALUES (N'Authn.LockoutThreshold'), (N'Authn.LockoutWindowMinutes'), (N'Authn.LockoutDurationMinutes')
             , (N'Authn.AddressThreshold'), (N'Authn.AddressWindowMinutes')
             , (N'Authn.LoginExchangeTimeoutSeconds')
             , (N'Authn.SessionLifetimeMinutes'), (N'Authn.IdleTimeoutMinutes')
             , (N'Authn.PasswordHistoryDepth')
             , (N'Authn.PasswordLifetimeDays'), (N'Authn.PasswordExpiryWarningDays')
             , (N'Authn.RequireStepUpForPrivilegedDefault')
             , (N'Registration.ThrottleThreshold'), (N'Registration.ThrottleWindowMinutes')
             , (N'Authn.TotpStepSeconds'), (N'Authn.TotpWindowSteps')
             , (N'Authn.MfaKeyReferenceCurrent'), (N'Authn.MfaKeyReferenceSchemes')
             , (N'Authn.MfaEnrolmentWindowSeconds'), (N'Authn.MfaRecoveryCodeCount')
             , (N'Authn.DummyVerifierPhcTemplate'), (N'Authn.DummyVerifierPepper')
             , (N'Authz.AllowSelfGrant')) AS x (SettingKey)
  LEFT JOIN config.ApplicationSetting AS s
         ON s.SettingKey = x.SettingKey AND s.IsDeleted = 0;

-- Task T-041, section 6.4.  The shipped key reference is a DEVELOPMENT one, and it is meant to be replaced.  This says
-- so on every deployment, because the failure it guards against is a production install that authenticates perfectly
-- well with its TOTP secrets encrypted under a key that has no hardware protection and no escrow.
--
-- Severity 3 and not 2, deliberately: on a workstation this is the CORRECT state, and a script that declared "PROBLEMS
-- found" on every clean install would teach its readers to stop reading the line that says it.
INSERT @Report (Severity, Status, Item, Detail)
SELECT 3, 'REVIEW', N'Authn.MfaKeyReferenceCurrent is still a development key'
     , N'Its value is ' + s.SettingValue + N', and the dev: scheme means a key with no TPM binding and no escrow. '
     + N'Correct for a workstation and WRONG for production: set it to cng:<container>#v<n> for the TPM-backed CNG key '
     + N'on the application-layer server, or vault:<path>#v<n> for a self-hosted HashiCorp Vault, and re-key existing '
     + N'factors with auth.uspRotateMfaFactorKey. The database never holds the key -- only this name for it. '
     + N'Section 6.4, gap G-07.'
  FROM config.ApplicationSetting AS s
 WHERE s.SettingKey = N'Authn.MfaKeyReferenceCurrent'
   AND s.IsDeleted  = 0
   AND s.SettingValue LIKE N'dev:%';

-- Gap G-12.  The credential lifecycle now EXISTS and ships INERT, and a control that ships off has to say so on every
-- deployment or it is indistinguishable from one that was never built.  Severity 3 for the same reason as the key
-- reference above: on a deployment that has decided against scheduled rotation this is the correct state.
INSERT @Report (Severity, Status, Item, Detail)
SELECT 3, 'INFO', N'Passwords do not expire in this deployment'
     , N'Authn.PasswordLifetimeDays is 0, so auth.uspSetPassword and auth.uspChangePassword leave '
     + N'auth.UserCredential.ExpiresUtc NULL and auth.uspExpireCredentials has nothing to act on. That is the shipped '
     + N'position, not a missing piece: rotation on a clock mostly buys predictable password mutations. To enforce a '
     + N'lifetime, set this key to a number of days AND schedule auth.uspExpireCredentials -- the sweep is a procedure, '
     + N'and nothing in the database runs it. Section 6.3, gap G-12.'
  FROM config.ApplicationSetting AS s
 WHERE s.SettingKey    = N'Authn.PasswordLifetimeDays'
   AND s.IsDeleted     = 0
   AND TRY_CAST (s.SettingValue AS INT) = 0;

-- The other half of the same honesty, for the deployment that DID set a lifetime: the stamp is worthless without the
-- sweep, and the sweep is a scheduled job this database cannot create for itself.
INSERT @Report (Severity, Status, Item, Detail)
SELECT 3, 'ACTION', N'Authn.PasswordLifetimeDays is set, so auth.uspExpireCredentials must be scheduled'
     , N'Its value is ' + s.SettingValue + N' days, so new passwords carry an ExpiresUtc. NOTHING ACTS ON THAT STAMP '
     + N'until auth.uspExpireCredentials runs on a schedule: an expired password keeps working, which is the shape of '
     + N'a control that is trusted and absent. Schedule it beside the G-01 job. Section 6.3, gap G-12.'
  FROM config.ApplicationSetting AS s
 WHERE s.SettingKey    = N'Authn.PasswordLifetimeDays'
   AND s.IsDeleted     = 0
   AND TRY_CAST (s.SettingValue AS INT) > 0;

-- A tuned value is REPORTED and NOT CORRECTED.  See the header.  Severity 3 rather than 2: this is information the
-- next reader of a deployment transcript wants, not a problem.
INSERT @Report (Severity, Status, Item, Detail)
SELECT 3, 'INFO', N'Tuned setting ' + s.SettingKey
     , N'Current value differs from the shipped default and was LEFT ALONE. Shipped: ' + s.ShippedDefault
     + N'. Current: ' + CASE WHEN s.IsSensitive = 1 THEN N'(withheld)' ELSE s.SettingValue END + N'.'
  FROM config.ApplicationSetting AS s
 WHERE s.IsDeleted = 0
   AND s.ShippedDefault IS NOT NULL
   AND s.SettingValue <> s.ShippedDefault;

INSERT @Report (Severity, Status, Item, Detail)
SELECT 3, 'INFO', N'config.TenantScopedTable is empty'
     , N'Expected until 090_dbo_application.sql and 115_seed_reference_data.sql have run. 120_rls_policy.sql reads '
     + N'this table and protects nothing while it is empty -- which is correct, because there is nothing to protect.'
 WHERE NOT EXISTS (SELECT 1 FROM config.TenantScopedTable WHERE IsDeleted = 0);

INSERT @Report (Severity, Status, Item, Detail)
VALUES (3, 'NEXT', N'Next scripts'
      , N'035_auth_tenant_policy.sql, then 040_auth_userprofile.sql, 045_auth_identity.sql, 070_auth_session.sql, '
      + N'085_logs_auth_tables.sql, 100_auth_functions.sql and 110_auth_authn_procedures.sql. '
      + N'database/Install-TemplateDatabase.ps1 runs the whole sequence in order.');

IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
    PRINT N'Configuration tables: PROBLEMS found. Read the report below before running the next script.';
ELSE
    PRINT N'Configuration tables: no problems found.';

PRINT N'';

SELECT Severity, Status, Item, Detail
  FROM @Report
 ORDER BY Severity, RowNo;
GO
