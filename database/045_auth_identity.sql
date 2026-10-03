/***********************************************************************************************************************
Script:         045_auth_identity.sql
Purpose:        Everything that proves who somebody is, and everything that records an attempt to prove it.
                auth.UserCredential, auth.PasswordHistory, auth.UserFederatedIdentity, auth.UserMfaFactor,
                auth.UserMfaRecoveryCode, auth.LoginAttempt.
Target:         SQL Server 2022.
Run as:         db_owner in the target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/045_auth_identity.sql
Idempotent:     Yes.  Every CREATE is guarded, every trigger is CREATE OR ALTER, nothing is dropped, nothing is seeded.
Depends on:     005_schemas_and_roles.sql (schema auth), 030_auth_tenant.sql (auth.Application, auth.Tenant),
                040_auth_userprofile.sql (auth.User), templates/extended-properties.sql (util.uspSetObjectDescription).
Implements:     DES-AUTH-001 sections 6.1, 6.2, 7.1, 7.4, 15.3 and 19.2.  PLAN-AUTH-001 tasks T-026, T-027, T-028, T-029.
To retarget:    Pass it per run:  sqlcmd -d <database> -v DbName=<database>.  There is no in-file default.

THIS DATABASE STORES VERIFIERS AND CANNOT CHECK THEM
----------------------------------------------------
Section 19.2, decision D-08.  auth.UserCredential.VerifierPhc holds a PHC string -- the algorithm, its parameters, the
salt and the digest, in one self-describing field.  The database never computes it and never compares it.  It hands the
string out (auth.uspGetLoginVerifier) and is told the answer (auth.uspCompleteLogin), which is why signing in is two
round trips and not one.

The reason is not squeamishness about T-SQL.  A memory-hard KDF is memory-hard: running Argon2id inside the engine
spends the server's working set on every sign-in attempt, including every attempt by somebody who is guessing.  It also
puts the plaintext password in a T-SQL parameter, where it lands in the plan cache, in Query Store, and in any Extended
Events session anybody has left running.  The application computes; the database remembers.

VerifierPhc IS NVARCHAR (512) AND THAT IS NOT ARBITRARY
-------------------------------------------------------
An Argon2id PHC string at the parameters section 19.2 names is about 96 characters.  512 leaves room for a future
parameter increase, a longer salt, and a migration in which two algorithms coexist -- because the PHC prefix is what
tells the application which one it is holding, so the column has to be able to hold the longer of the two at once.

It is NVARCHAR rather than VARCHAR because a PHC string is ASCII and staying in one string type across the schema costs
less than the four bytes saved here.  It is not VARBINARY because the salt and the parameters are part of the value and
splitting them into columns is how a deployment ends up with a digest whose parameters nobody recorded.

WHY THE HISTORY TABLE IS SEPARATE, AND WHY IT IS NOT A TEMPORAL TABLE
--------------------------------------------------------------------
auth.PasswordHistory exists so a reuse check can be made without reading the live verifier, and so the depth of the
check is a configuration value (Authn.PasswordHistoryDepth) rather than however many rows a system-versioned table
happens to hold.  A temporal history table would also record every unrelated UPDATE to the credential row -- an expiry
date changed, a soft delete -- and a reuse check that walks those is a reuse check that gets slower for reasons nobody
can see.

A history row has nothing mutable on it at all.  The trigger says so.

INV-07 HAS TEETH IN THIS FILE, AND THEY ARE IN A TRIGGER
--------------------------------------------------------
A federated identity joins on (Issuer, SubjectId) and never on email -- INV-07, section 6.1.  The unique index is the
half of that rule everybody remembers.  The half that matters is that RE-POINTING an existing row is account takeover
in a single UPDATE: one statement moves somebody else's directory identity onto your user row, and no row is inserted,
no row is deleted, and nothing about the attempt looks unusual.  So UserId, Issuer and SubjectId are immutable, and
unlinking is a soft delete followed by an insert, which leaves both halves in the trail.

THE DATABASE CANNOT VERIFY A TOTP CODE EITHER, AND LastUsedTimeStep IS WHY
-------------------------------------------------------------------------
auth.UserMfaFactor.SecretCiphertext is the shared secret encrypted under a key that the application layer holds and this
database must never see -- gap G-07, closed by task T-041 in favour of application-side envelope encryption under a
TPM-backed CNG key, section 6.4 -- so the engine cannot recompute the code even in principle.  That is the property, not
a limitation to work around: a database that could verify a TOTP code is a database whose backup contains every user's
authenticator.  The application verifies and reports which time
step it verified.  auth.uspVerifyMfa then does the two things the application cannot be trusted to do alone:

  *  it bounds the reported step against the SERVER clock, using Authn.TotpStepSeconds and Authn.TotpWindowSteps, so a
     client cannot present a step from next year; and
  *  it requires the step to be strictly GREATER than LastUsedTimeStep, so a code that has already been accepted cannot
     be replayed inside its own validity window.

Both checks raise E-50111.  The second is the reason this column exists rather than LastUsedUtc alone: a timestamp
answers "when did they last use it", which is an audit question, and the replay question is "which step was it".

THE TWO LOCKOUT COUNTS ARE TWO INDEXES, NOT ONE
-----------------------------------------------
Section 7.4.  The per-account count and the per-address count are taken independently and neither is derived from the
other, so auth.LoginAttempt carries two filtered indexes -- one leading on UserName, one leading on ClientAddress --
both filtered to failures.  An address throttle is NOT a state change: there is no table of addresses, the count is
recomputed from this table on every attempt, and nothing is stored that says an address is blocked.

UserName is recorded as a STRING as well as a nullable UserId, on purpose.  An attempt against an account that does not
exist has no UserId, and those attempts are exactly the ones an enumeration probe generates.  A schema that could only
record attempts against real accounts would be blind to the attack section 19.2 is written to defeat.

ONE EXCHANGE IS ONE ROW -- D-14, AND THE TRIGGER ENFORCES IT
------------------------------------------------------------
Section 7.1, D-14.  The first step of a sign-in inserts one row with Outcome 'VerifierIssued' or 'SsoBegun' and returns
its LoginAttemptId; every later step of the same sign-in UPDATES that row.  So Outcome may move forward out of a
pending state and may never move away from a terminal one, and ApplicationId, UserName, ClientAddress and AttemptedUtc
may never change at all.  That is the "an exchange cannot be reused" guarantee, and it is in the trigger rather than
only in auth.uspCompleteLogin because a procedure is a policy and a trigger is a wall.

INV-08 IS A CHECK CONSTRAINT HERE AS WELL AS AN ERROR NUMBER
------------------------------------------------------------
The bypass route always requires a second factor.  auth.uspCompleteLogin raises E-50107, and
CK_auth_LoginAttempt_BypassNeedsMfa refuses the row.  Two enforcements of one rule is not duplication when one of them
is the only one that survives somebody writing to the table directly.
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
BEGIN
    DECLARE @MsgUser NVARCHAR (2000) =
        N'Table auth.User does not exist. Run database/040_auth_userprofile.sql first. Nothing has been changed.';

    THROW 50000, @MsgUser, 1;
END
GO

-- auth.LoginAttempt is scoped to an application, not to a tenant: the sign-in page belongs to an application and the
-- tenant whose policy applied is recorded separately and may be NULL when no tenant could be resolved.  Section 7.2.
IF OBJECT_ID (N'auth.Application', N'U') IS NULL
   OR OBJECT_ID (N'auth.Tenant', N'U') IS NULL
BEGIN
    DECLARE @MsgTenant NVARCHAR (2000) =
        N'Tables auth.Application and auth.Tenant must both exist. Run database/030_auth_tenant.sql first. '
      + N'Nothing has been changed.';

    THROW 50000, @MsgTenant, 1;
END
GO


-- *** 1. auth.UserCredential ***
--
-- One live credential per user per type, and today there is exactly one type.  CredentialType is here rather than
-- implied so that adding 'Certificate' or 'ApiKey' later is a CHECK constraint change and not a new table with a
-- duplicate set of audit columns.
IF OBJECT_ID (N'auth.UserCredential', N'U') IS NULL
BEGIN
    CREATE TABLE auth.UserCredential
    (
        UserCredentialId     INT             IDENTITY (1, 1) NOT NULL
      , UserId               INT                             NOT NULL
      , CredentialType       VARCHAR (20)                    NOT NULL
            CONSTRAINT DF_auth_UserCredential_CredentialType DEFAULT ('Password')
      , VerifierPhc          NVARCHAR (512)                  NOT NULL
      , LastChangedUtc       DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_UserCredential_LastChangedUtc DEFAULT (SYSUTCDATETIME ())
      , ExpiresUtc           DATETIME2 (3)                       NULL
      , IsDeleted            BIT                             NOT NULL
            CONSTRAINT DF_auth_UserCredential_IsDeleted DEFAULT (0)
      , auditDeletedBy       NVARCHAR (255)                      NULL
      , auditDeletedDateUtc  DATETIME2 (3)                       NULL
      , auditCreatedBy       NVARCHAR (255)                  NOT NULL
            CONSTRAINT DF_auth_UserCredential_auditCreatedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditCreatedDateUtc  DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_UserCredential_auditCreatedDateUtc DEFAULT (SYSUTCDATETIME ())
      , auditModifiedBy      NVARCHAR (255)                  NOT NULL
            CONSTRAINT DF_auth_UserCredential_auditModifiedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditModifiedDateUtc DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_UserCredential_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ())
      , CONSTRAINT PK_auth_UserCredential PRIMARY KEY CLUSTERED (UserCredentialId)
      , CONSTRAINT FK_auth_UserCredential_User
            FOREIGN KEY (UserId) REFERENCES auth.[User] (UserId)
      , CONSTRAINT CK_auth_UserCredential_CredentialType
            CHECK (CredentialType IN ('Password'))
      -- A PHC string starts with $ and names its algorithm.  This refuses a bare hex digest pasted into the column,
      -- which is the migration mistake that makes every stored verifier unverifiable and undiagnosable at once.
      , CONSTRAINT CK_auth_UserCredential_VerifierPhc
            CHECK (LEN (VerifierPhc) >= 16 AND VerifierPhc LIKE N'$%$%')
      , CONSTRAINT CK_auth_UserCredential_ExpiresUtc
            CHECK (ExpiresUtc IS NULL OR ExpiresUtc > LastChangedUtc)
      , CONSTRAINT CK_auth_UserCredential_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS     NULL AND auditDeletedDateUtc IS     NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL))
    );
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'UX_auth_UserCredential_UserType' AND object_id = OBJECT_ID (N'auth.UserCredential'))
BEGIN
    CREATE UNIQUE INDEX UX_auth_UserCredential_UserType
        ON auth.UserCredential (UserId, CredentialType) WHERE IsDeleted = 0;
END
GO

-- T-112, G-12.  The index auth.uspExpireCredentials sweeps: "whose password has aged out."  Filtered to the rows that
-- HAVE an expiry, which in a default deployment is NONE of them -- Authn.PasswordLifetimeDays ships as 0, so the index
-- is empty, costs nothing to maintain, and the sweep is a single empty seek rather than a scan of every credential in
-- the database.  That asymmetry is the whole reason it is filtered: the deployments that never enable expiry pay for
-- nothing, and the ones that do get a seek.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_auth_UserCredential_Expires' AND object_id = OBJECT_ID (N'auth.UserCredential'))
BEGIN
    CREATE INDEX IX_auth_UserCredential_Expires
        ON auth.UserCredential (ExpiresUtc) INCLUDE (UserId)
     WHERE IsDeleted = 0 AND ExpiresUtc IS NOT NULL;
END
GO


-- *** 2. auth.PasswordHistory ***
--
-- Retired verifiers only.  The live one is in auth.UserCredential and is deliberately NOT duplicated here: two copies
-- of the current verifier is two places for a password change to go half-done.
IF OBJECT_ID (N'auth.PasswordHistory', N'U') IS NULL
BEGIN
    CREATE TABLE auth.PasswordHistory
    (
        PasswordHistoryId    INT             IDENTITY (1, 1) NOT NULL
      , UserId               INT                             NOT NULL
      , VerifierPhc          NVARCHAR (512)                  NOT NULL
      , RetiredUtc           DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_PasswordHistory_RetiredUtc DEFAULT (SYSUTCDATETIME ())
      , IsDeleted            BIT                             NOT NULL
            CONSTRAINT DF_auth_PasswordHistory_IsDeleted DEFAULT (0)
      , auditDeletedBy       NVARCHAR (255)                      NULL
      , auditDeletedDateUtc  DATETIME2 (3)                       NULL
      , auditCreatedBy       NVARCHAR (255)                  NOT NULL
            CONSTRAINT DF_auth_PasswordHistory_auditCreatedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditCreatedDateUtc  DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_PasswordHistory_auditCreatedDateUtc DEFAULT (SYSUTCDATETIME ())
      , auditModifiedBy      NVARCHAR (255)                  NOT NULL
            CONSTRAINT DF_auth_PasswordHistory_auditModifiedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditModifiedDateUtc DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_PasswordHistory_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ())
      , CONSTRAINT PK_auth_PasswordHistory PRIMARY KEY CLUSTERED (PasswordHistoryId)
      , CONSTRAINT FK_auth_PasswordHistory_User
            FOREIGN KEY (UserId) REFERENCES auth.[User] (UserId)
      , CONSTRAINT CK_auth_PasswordHistory_VerifierPhc
            CHECK (LEN (VerifierPhc) >= 16 AND VerifierPhc LIKE N'$%$%')
      , CONSTRAINT CK_auth_PasswordHistory_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS     NULL AND auditDeletedDateUtc IS     NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL))
    );
END
GO

-- There is no UNIQUE index here and there must not be one.  The same verifier string cannot recur -- every PHC string
-- carries its own random salt -- so a unique index would enforce nothing, and an index on (UserId, VerifierPhc) would
-- make the reuse check a seek on a 512-character key for no gain over reading the newest N rows.  DESC because the
-- check is always "the last Authn.PasswordHistoryDepth of them".
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_auth_PasswordHistory_UserRetired' AND object_id = OBJECT_ID (N'auth.PasswordHistory'))
BEGIN
    CREATE INDEX IX_auth_PasswordHistory_UserRetired
        ON auth.PasswordHistory (UserId, RetiredUtc DESC) WHERE IsDeleted = 0;
END
GO


-- *** 3. auth.UserFederatedIdentity ***
--
-- Issuer is NVARCHAR (512) because it is a URL and an issuer URL with a tenant GUID in it is long.  SubjectId is
-- NVARCHAR (256): an object identifier, not an email address, and never an email address -- INV-07.
IF OBJECT_ID (N'auth.UserFederatedIdentity', N'U') IS NULL
BEGIN
    CREATE TABLE auth.UserFederatedIdentity
    (
        UserFederatedIdentityId INT          IDENTITY (1, 1) NOT NULL
      , UserId               INT                             NOT NULL
      , Issuer               NVARCHAR (512)                  NOT NULL
      , SubjectId            NVARCHAR (256)                  NOT NULL
      , LinkedUtc            DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_UserFederatedIdentity_LinkedUtc DEFAULT (SYSUTCDATETIME ())
      , LastSeenUtc          DATETIME2 (3)                       NULL
      , IsDeleted            BIT                             NOT NULL
            CONSTRAINT DF_auth_UserFederatedIdentity_IsDeleted DEFAULT (0)
      , auditDeletedBy       NVARCHAR (255)                      NULL
      , auditDeletedDateUtc  DATETIME2 (3)                       NULL
      , auditCreatedBy       NVARCHAR (255)                  NOT NULL
            CONSTRAINT DF_auth_UserFederatedIdentity_auditCreatedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditCreatedDateUtc  DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_UserFederatedIdentity_auditCreatedDateUtc DEFAULT (SYSUTCDATETIME ())
      , auditModifiedBy      NVARCHAR (255)                  NOT NULL
            CONSTRAINT DF_auth_UserFederatedIdentity_auditModifiedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditModifiedDateUtc DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_UserFederatedIdentity_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ())
      , CONSTRAINT PK_auth_UserFederatedIdentity PRIMARY KEY CLUSTERED (UserFederatedIdentityId)
      , CONSTRAINT FK_auth_UserFederatedIdentity_User
            FOREIGN KEY (UserId) REFERENCES auth.[User] (UserId)
      , CONSTRAINT CK_auth_UserFederatedIdentity_Issuer
            CHECK (LEN (Issuer) > 0 AND Issuer = LTRIM (RTRIM (Issuer)))
      -- A subject identifier that looks like an email address is the INV-07 mistake arriving through the front door: a
      -- claim mapping configured to emit `email` instead of `oid` or `sub`.  Refused here, where it is one row, rather
      -- than discovered later, when it is the join key half the accounts were linked on.
      , CONSTRAINT CK_auth_UserFederatedIdentity_SubjectId
            CHECK (LEN (SubjectId) > 0 AND SubjectId = LTRIM (RTRIM (SubjectId)) AND SubjectId NOT LIKE N'%_@_%')
      , CONSTRAINT CK_auth_UserFederatedIdentity_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS     NULL AND auditDeletedDateUtc IS     NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL))
    );
END
GO

-- The INV-07 index.  (Issuer, SubjectId) and nothing else: this is the pair auth.uspCompleteSsoLogin looks up, and the
-- uniqueness is what stops one directory identity being linked to two people.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'UX_auth_UserFederatedIdentity_IssuerSubject'
                  AND object_id = OBJECT_ID (N'auth.UserFederatedIdentity'))
BEGIN
    CREATE UNIQUE INDEX UX_auth_UserFederatedIdentity_IssuerSubject
        ON auth.UserFederatedIdentity (Issuer, SubjectId) WHERE IsDeleted = 0;
END
GO

-- "Which directory accounts is this person linked to" is an administrative screen and a support question.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_auth_UserFederatedIdentity_User'
                  AND object_id = OBJECT_ID (N'auth.UserFederatedIdentity'))
BEGIN
    CREATE INDEX IX_auth_UserFederatedIdentity_User
        ON auth.UserFederatedIdentity (UserId) WHERE IsDeleted = 0;
END
GO

-- *** 4. auth.UserMfaFactor ***
--
-- SecretCiphertext is VARBINARY (MAX) and holds ciphertext produced OUTSIDE this database, by the application, under a
-- key held outside this database.  KeyReference names which key, so a key rotation can find the rows encrypted under
-- the old one; it is an identifier, never key material.
--
-- G-07 IS CLOSED, AND THIS IS WHERE THE DECISION LANDS.  Task T-041 settled where the key lives: the application layer
-- holds it in a TPM-backed CNG container and performs envelope encryption itself.  SQL Server Always Encrypted was
-- rejected, and the reasons are worth keeping next to the column -- Power BI and other external services must read
-- these tables, and a TEMPLATE cannot know which columns a deployment will add, so a feature that requires every
-- consumer to carry an enclave-capable driver and every protected column to be declared up front is the wrong shape.
-- What that means HERE is a property to defend rather than a gap to record: this database never holds the key, never
-- sees the plaintext secret, and cannot verify a TOTP code.  auth.uspVerifyMfa therefore checks the time step the
-- application reports rather than the code -- section 6.2 -- and everything this script can usefully enforce about the
-- key is that its NAME is well formed.  Section 8 does that, in one place.  Section 6.4 of the design records the whole
-- decision, including the appsettings.secrets.json contract and the HashiCorp Vault seam left open for later.
IF OBJECT_ID (N'auth.UserMfaFactor', N'U') IS NULL
BEGIN
    CREATE TABLE auth.UserMfaFactor
    (
        UserMfaFactorId      INT             IDENTITY (1, 1) NOT NULL
      , UserId               INT                             NOT NULL
      , FactorType           VARCHAR (20)                    NOT NULL
            CONSTRAINT DF_auth_UserMfaFactor_FactorType DEFAULT ('Totp')
      , SecretCiphertext     VARBINARY (MAX)                 NOT NULL
      , KeyReference         NVARCHAR (256)                  NOT NULL
      , IsConfirmed          BIT                             NOT NULL
            CONSTRAINT DF_auth_UserMfaFactor_IsConfirmed DEFAULT (0)
      , ConfirmedUtc         DATETIME2 (3)                       NULL
      , LastUsedUtc          DATETIME2 (3)                       NULL
      , LastUsedTimeStep     BIGINT                              NULL
      , IsDeleted            BIT                             NOT NULL
            CONSTRAINT DF_auth_UserMfaFactor_IsDeleted DEFAULT (0)
      , auditDeletedBy       NVARCHAR (255)                      NULL
      , auditDeletedDateUtc  DATETIME2 (3)                       NULL
      , auditCreatedBy       NVARCHAR (255)                  NOT NULL
            CONSTRAINT DF_auth_UserMfaFactor_auditCreatedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditCreatedDateUtc  DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_UserMfaFactor_auditCreatedDateUtc DEFAULT (SYSUTCDATETIME ())
      , auditModifiedBy      NVARCHAR (255)                  NOT NULL
            CONSTRAINT DF_auth_UserMfaFactor_auditModifiedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditModifiedDateUtc DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_UserMfaFactor_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ())
      , CONSTRAINT PK_auth_UserMfaFactor PRIMARY KEY CLUSTERED (UserMfaFactorId)
      , CONSTRAINT FK_auth_UserMfaFactor_User
            FOREIGN KEY (UserId) REFERENCES auth.[User] (UserId)
      , CONSTRAINT CK_auth_UserMfaFactor_FactorType
            CHECK (FactorType IN ('Totp'))
      -- An unconfirmed factor is an enrolment in progress and must not satisfy MFA.  E-50110 is raised when there is no
      -- CONFIRMED factor, not when there is no factor, and this pair is what makes that distinction readable.
      , CONSTRAINT CK_auth_UserMfaFactor_ConfirmedPair
            CHECK ((IsConfirmed = 0 AND ConfirmedUtc IS     NULL)
                OR (IsConfirmed = 1 AND ConfirmedUtc IS NOT NULL))
      -- Empty ciphertext is a failed encryption that was stored anyway.  An AES-GCM envelope of a 20-byte TOTP secret
      -- is never this short whatever the format, so the floor costs nothing and catches the whole class.
      , CONSTRAINT CK_auth_UserMfaFactor_SecretCiphertext
            CHECK (DATALENGTH (SecretCiphertext) >= 16)
      -- Non-empty and not padded.  The GRAMMAR -- scheme:name#vN -- is CK_auth_UserMfaFactor_KeyReferenceFormat, and it
      -- is added by the guarded block after this table rather than inline, so that there is exactly one copy of the
      -- predicate and an existing database gets the same rule as a fresh one.  See the note there.
      , CONSTRAINT CK_auth_UserMfaFactor_KeyReference
            CHECK (LEN (KeyReference) > 0 AND KeyReference = LTRIM (RTRIM (KeyReference)))
      -- A used step with no used timestamp, or the reverse, is a row whose replay window cannot be reasoned about.
      , CONSTRAINT CK_auth_UserMfaFactor_LastUsedPair
            CHECK ((LastUsedUtc IS NULL AND LastUsedTimeStep IS NULL)
                OR (LastUsedUtc IS NOT NULL AND LastUsedTimeStep IS NOT NULL))
      , CONSTRAINT CK_auth_UserMfaFactor_LastUsedTimeStep
            CHECK (LastUsedTimeStep IS NULL OR LastUsedTimeStep > 0)
      , CONSTRAINT CK_auth_UserMfaFactor_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS     NULL AND auditDeletedDateUtc IS     NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL))
    );
END
GO

-- One live factor per user per type.  Re-enrolling replaces the secret on this row -- and the trigger forces the step
-- to be cleared in the same statement, because a new secret with an old high-water step locks the user out of their own
-- new authenticator until the clock catches up.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'UX_auth_UserMfaFactor_UserType' AND object_id = OBJECT_ID (N'auth.UserMfaFactor'))
BEGIN
    CREATE UNIQUE INDEX UX_auth_UserMfaFactor_UserType
        ON auth.UserMfaFactor (UserId, FactorType) WHERE IsDeleted = 0;
END
GO

-- THE KeyReference GRAMMAR.  Task T-041.  A reference is  scheme:name#vN  -- cng:authn-mfa-kek#v1,
-- vault:secret/authn/mfa-kek#v3, dev:local/authn-mfa-kek#v1 -- and this constraint is the only thing standing between
-- that convention and a column full of whatever each deployment felt like typing.
--
-- WHY THE FORM MATTERS AT ALL.  Rotation is the reason.  auth.uspRotateMfaFactorKey has to answer "which rows are still
-- encrypted under the key we are retiring", and the only way to answer it is to compare this string.  A deployment that
-- wrote `prod key` on some rows and `Prod Key (new)` on others has not lost a label, it has lost the ability to retire a
-- compromised key -- and it will discover that on the day it needs to.  The #vN suffix exists so that re-keying under
-- the same container is still distinguishable, which is the common case: the key is replaced, its name is not.
--
-- WHY IT IS ADDED HERE AND NOT INSIDE THE CREATE TABLE.  Fewer copies of the predicate, and one path instead of two.
-- The CREATE TABLE above only runs on a database that does not have the table, so a constraint written inline would
-- never reach the databases built by an earlier run of this script -- they would need this block anyway, and the
-- predicate would then exist in three places rather than two.  It appears twice below, once to TEST and once to ENFORCE,
-- because ALTER TABLE cannot report which rows it objected to and this script would rather say than fail.  On a fresh
-- install the table has no rows, the test passes trivially, and the constraint is added in the same run -- so "fresh"
-- and "existing" follow exactly the same path, which is the property worth having.
--
-- WHY IT IS NOT A REGULAR EXPRESSION.  SQL Server 2022 has none.  REGEXP_LIKE arrived in SQL Server 2025 and this
-- template targets 2022 as a ceiling as well as a floor, so the grammar is spelled out in LIKE, CHARINDEX and the
-- REPLACE-length trick for counting a character.  It is longer to read and it runs on every deployment the template
-- claims to support, which is the trade this project makes everywhere else too.
--
-- WHAT IT DOES NOT DO.  It cannot tell a key NAME from key MATERIAL -- no constraint can, because a 44-character base64
-- key and a 44-character label are the same to SQL Server.  What it does is make the difference obvious to a reader: a
-- pasted key has no scheme prefix and no #vN suffix, so it is refused, and the refusal arrives at the INSERT rather than
-- at the audit six months later.  Case is NOT forced: a CNG container or a Vault path may legitimately carry uppercase,
-- and the application normalises the scheme before it calls.  Under the default case-insensitive collation the prefix
-- tests accept CNG: as readily as cng:, which is intended.
IF NOT EXISTS (SELECT 1 FROM sys.check_constraints
                WHERE name             = N'CK_auth_UserMfaFactor_KeyReferenceFormat'
                  AND parent_object_id = OBJECT_ID (N'auth.UserMfaFactor'))
BEGIN
    -- Live AND soft-deleted rows, because WITH CHECK validates every row and a deleted factor is still a row.  A
    -- database with non-conforming references is REPORTED and not rewritten: this script does not know what those
    -- strings were supposed to mean, and guessing would be the one edit that silently orphans a secret from its key.
    IF EXISTS (SELECT 1
                 FROM auth.UserMfaFactor
                WHERE NOT (LEN (KeyReference) BETWEEN 8 AND 256
                       AND (KeyReference LIKE N'cng:%' OR KeyReference LIKE N'vault:%' OR KeyReference LIKE N'dev:%')
                       AND LEN (KeyReference) - LEN (REPLACE (KeyReference, N'#', N'')) = 1
                       AND LEN (KeyReference) - LEN (REPLACE (KeyReference, N':', N'')) = 1
                       AND CHARINDEX (N'#', KeyReference) > CHARINDEX (N':', KeyReference) + 1
                       AND (KeyReference LIKE N'%#v[0-9]'
                         OR KeyReference LIKE N'%#v[0-9][0-9]'
                         OR KeyReference LIKE N'%#v[0-9][0-9][0-9]'
                         OR KeyReference LIKE N'%#v[0-9][0-9][0-9][0-9]')
                       AND KeyReference NOT LIKE N'% %'
                       AND KeyReference NOT LIKE N'%' + NCHAR (9)  + N'%'
                       AND KeyReference NOT LIKE N'%' + NCHAR (10) + N'%'
                       AND KeyReference NOT LIKE N'%' + NCHAR (13) + N'%'))
    BEGIN
        PRINT N'auth.UserMfaFactor holds KeyReference values that do not match the T-041 grammar scheme:name#vN, so '
            + N'CK_auth_UserMfaFactor_KeyReferenceFormat was NOT added. Nothing has been changed. Section 8 lists the '
            + N'offending rows. Correct them -- or re-key the factors with auth.uspRotateMfaFactorKey -- and re-run '
            + N'this script; it will add the constraint once every row conforms.';
    END
    ELSE
    BEGIN
        ALTER TABLE auth.UserMfaFactor WITH CHECK
            ADD CONSTRAINT CK_auth_UserMfaFactor_KeyReferenceFormat
                CHECK (LEN (KeyReference) BETWEEN 8 AND 256
                   AND (KeyReference LIKE N'cng:%' OR KeyReference LIKE N'vault:%' OR KeyReference LIKE N'dev:%')
                   AND LEN (KeyReference) - LEN (REPLACE (KeyReference, N'#', N'')) = 1
                   AND LEN (KeyReference) - LEN (REPLACE (KeyReference, N':', N'')) = 1
                   AND CHARINDEX (N'#', KeyReference) > CHARINDEX (N':', KeyReference) + 1
                   AND (KeyReference LIKE N'%#v[0-9]'
                     OR KeyReference LIKE N'%#v[0-9][0-9]'
                     OR KeyReference LIKE N'%#v[0-9][0-9][0-9]'
                     OR KeyReference LIKE N'%#v[0-9][0-9][0-9][0-9]')
                   AND KeyReference NOT LIKE N'% %'
                   AND KeyReference NOT LIKE N'%' + NCHAR (9)  + N'%'
                   AND KeyReference NOT LIKE N'%' + NCHAR (10) + N'%'
                   AND KeyReference NOT LIKE N'%' + NCHAR (13) + N'%');
    END
END
GO


-- *** 5. auth.UserMfaRecoveryCode ***
--
-- CodeHash is VARBINARY (32) -- a plain SHA-256 of the code, NOT a password hash.  That is a deliberate difference from
-- auth.UserCredential and the reason is entropy: a recovery code is machine-generated with enough randomness that
-- guessing it is not the attack, so a memory-hard KDF buys nothing and costs a second round trip on the one path a
-- locked-out user takes.  A user-chosen password has nothing like that entropy, which is why it gets Argon2id.
IF OBJECT_ID (N'auth.UserMfaRecoveryCode', N'U') IS NULL
BEGIN
    CREATE TABLE auth.UserMfaRecoveryCode
    (
        UserMfaRecoveryCodeId INT            IDENTITY (1, 1) NOT NULL
      , UserId               INT                             NOT NULL
      , CodeHash             VARBINARY (32)                  NOT NULL
      , UsedUtc              DATETIME2 (3)                       NULL
      , IsDeleted            BIT                             NOT NULL
            CONSTRAINT DF_auth_UserMfaRecoveryCode_IsDeleted DEFAULT (0)
      , auditDeletedBy       NVARCHAR (255)                      NULL
      , auditDeletedDateUtc  DATETIME2 (3)                       NULL
      , auditCreatedBy       NVARCHAR (255)                  NOT NULL
            CONSTRAINT DF_auth_UserMfaRecoveryCode_auditCreatedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditCreatedDateUtc  DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_UserMfaRecoveryCode_auditCreatedDateUtc DEFAULT (SYSUTCDATETIME ())
      , auditModifiedBy      NVARCHAR (255)                  NOT NULL
            CONSTRAINT DF_auth_UserMfaRecoveryCode_auditModifiedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditModifiedDateUtc DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_UserMfaRecoveryCode_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ())
      , CONSTRAINT PK_auth_UserMfaRecoveryCode PRIMARY KEY CLUSTERED (UserMfaRecoveryCodeId)
      , CONSTRAINT FK_auth_UserMfaRecoveryCode_User
            FOREIGN KEY (UserId) REFERENCES auth.[User] (UserId)
      , CONSTRAINT CK_auth_UserMfaRecoveryCode_CodeHash
            CHECK (DATALENGTH (CodeHash) = 32)
      , CONSTRAINT CK_auth_UserMfaRecoveryCode_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS     NULL AND auditDeletedDateUtc IS     NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL))
    );
END
GO

-- UNIQUE on (UserId, CodeHash) and NOT on CodeHash alone.  Two users may legitimately be issued the same code by
-- coincidence, and a global unique index would turn that coincidence into a refused enrolment for the second person --
-- which is also an oracle: the refusal tells the issuer that somebody else already holds that code.  The scoped index
-- still does the job that matters, which is that one person cannot hold the same code twice.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'UX_auth_UserMfaRecoveryCode_UserCode'
                  AND object_id = OBJECT_ID (N'auth.UserMfaRecoveryCode'))
BEGIN
    CREATE UNIQUE INDEX UX_auth_UserMfaRecoveryCode_UserCode
        ON auth.UserMfaRecoveryCode (UserId, CodeHash) WHERE IsDeleted = 0;
END
GO

-- "How many codes has this person got left" is asked on every recovery screen, and is a count of unused rows.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_auth_UserMfaRecoveryCode_Unused'
                  AND object_id = OBJECT_ID (N'auth.UserMfaRecoveryCode'))
BEGIN
    CREATE INDEX IX_auth_UserMfaRecoveryCode_Unused
        ON auth.UserMfaRecoveryCode (UserId) WHERE UsedUtc IS NULL AND IsDeleted = 0;
END
GO


-- *** 6. auth.LoginAttempt ***
--
-- One row per EXCHANGE -- D-14, section 7.1.  ClientAddress is NVARCHAR (45) because that is the longest textual IPv6
-- address including an IPv4-mapped tail, and it is a string rather than a binary or a numeric because what must be
-- recorded is what the application reported, exactly, including the form it reported it in.
IF OBJECT_ID (N'auth.LoginAttempt', N'U') IS NULL
BEGIN
    CREATE TABLE auth.LoginAttempt
    (
        LoginAttemptId       BIGINT          IDENTITY (1, 1) NOT NULL
      , ApplicationId        INT                             NOT NULL
      , UserName             NVARCHAR (256)                  NOT NULL
      , UserId               INT                                 NULL
      , PolicyTenantId       INT                                 NULL
      , ClientAddress        NVARCHAR (45)                   NOT NULL
      , UserAgent            NVARCHAR (512)                      NULL
      , AuthenticationMethod VARCHAR (20)                    NOT NULL
      , IsBypassRoute        BIT                             NOT NULL
            CONSTRAINT DF_auth_LoginAttempt_IsBypassRoute DEFAULT (0)
      , Outcome              VARCHAR (20)                    NOT NULL
      , FailureReason        VARCHAR (40)                        NULL
      , PasswordVerified     BIT                             NOT NULL
            CONSTRAINT DF_auth_LoginAttempt_PasswordVerified DEFAULT (0)
      , MfaSatisfied         BIT                             NOT NULL
            CONSTRAINT DF_auth_LoginAttempt_MfaSatisfied DEFAULT (0)
      , AttemptedUtc         DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_LoginAttempt_AttemptedUtc DEFAULT (SYSUTCDATETIME ())
      , ConcludedUtc         DATETIME2 (3)                       NULL
      , IsDeleted            BIT                             NOT NULL
            CONSTRAINT DF_auth_LoginAttempt_IsDeleted DEFAULT (0)
      , auditDeletedBy       NVARCHAR (255)                      NULL
      , auditDeletedDateUtc  DATETIME2 (3)                       NULL
      , auditCreatedBy       NVARCHAR (255)                  NOT NULL
            CONSTRAINT DF_auth_LoginAttempt_auditCreatedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditCreatedDateUtc  DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_LoginAttempt_auditCreatedDateUtc DEFAULT (SYSUTCDATETIME ())
      , auditModifiedBy      NVARCHAR (255)                  NOT NULL
            CONSTRAINT DF_auth_LoginAttempt_auditModifiedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditModifiedDateUtc DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_LoginAttempt_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ())
      , CONSTRAINT PK_auth_LoginAttempt PRIMARY KEY CLUSTERED (LoginAttemptId)
      , CONSTRAINT FK_auth_LoginAttempt_Application
            FOREIGN KEY (ApplicationId) REFERENCES auth.Application (ApplicationId)
      -- NULLABLE, and that is the point: an attempt against a user name that does not exist has no UserId, and those
      -- are precisely the attempts an enumeration probe generates.  Section 19.2.
      , CONSTRAINT FK_auth_LoginAttempt_User
            FOREIGN KEY (UserId) REFERENCES auth.[User] (UserId)
      -- Also nullable: no tenant could be resolved when the tenant code was wrong, and that failure must still record.
      , CONSTRAINT FK_auth_LoginAttempt_PolicyTenant
            FOREIGN KEY (PolicyTenantId) REFERENCES auth.Tenant (TenantId)
      , CONSTRAINT CK_auth_LoginAttempt_UserName
            CHECK (LEN (UserName) > 0)
      , CONSTRAINT CK_auth_LoginAttempt_ClientAddress
            CHECK (LEN (ClientAddress) > 0 AND ClientAddress = LTRIM (RTRIM (ClientAddress)))
      , CONSTRAINT CK_auth_LoginAttempt_AuthenticationMethod
            CHECK (AuthenticationMethod IN ('LocalPassword', 'Federated'))
      -- 'VerifierIssued' and 'SsoBegun' are the two pending states -- one per route.  'Success' and 'Failure' are
      -- terminal.  The trigger enforces that the move is one-way.
      , CONSTRAINT CK_auth_LoginAttempt_Outcome
            CHECK (Outcome IN ('VerifierIssued', 'SsoBegun', 'Success', 'Failure'))
      , CONSTRAINT CK_auth_LoginAttempt_PendingMethod
            CHECK (Outcome <> 'VerifierIssued' OR AuthenticationMethod = 'LocalPassword')
      , CONSTRAINT CK_auth_LoginAttempt_SsoMethod
            CHECK (Outcome <> 'SsoBegun' OR AuthenticationMethod = 'Federated')
      -- Concluded exactly when the outcome is terminal.  A pending row with a conclusion time, or a finished row
      -- without one, is a row that cannot be aged out by the exchange timeout and cannot be counted as a failure.
      , CONSTRAINT CK_auth_LoginAttempt_ConcludedPair
            CHECK ((Outcome IN ('Success', 'Failure') AND ConcludedUtc IS NOT NULL AND ConcludedUtc >= AttemptedUtc)
                OR (Outcome IN ('VerifierIssued', 'SsoBegun') AND ConcludedUtc IS NULL))
      -- A reason on a success is a contradiction, and a failure with no reason is a row nobody can act on.  The values
      -- are short tokens -- see auth.uspRecordLoginFailure -- and are NEVER shown to the user: section 14.5, UI-26.
      , CONSTRAINT CK_auth_LoginAttempt_FailureReason
            CHECK ((Outcome = 'Failure' AND FailureReason IS NOT NULL AND LEN (FailureReason) > 0)
                OR (Outcome <> 'Failure' AND FailureReason IS NULL))
      -- INV-08, at the table.  A successful sign-in on the bypass route without a satisfied second factor is refused by
      -- the engine, whatever wrote the row and whether or not it went through auth.uspCompleteLogin.
      , CONSTRAINT CK_auth_LoginAttempt_BypassNeedsMfa
            CHECK (Outcome <> 'Success' OR IsBypassRoute = 0 OR MfaSatisfied = 1)
      -- A successful local sign-in with no verified password is the mistake that makes the whole file decorative.
      , CONSTRAINT CK_auth_LoginAttempt_SuccessNeedsPassword
            CHECK (Outcome <> 'Success' OR AuthenticationMethod <> 'LocalPassword' OR PasswordVerified = 1)
      , CONSTRAINT CK_auth_LoginAttempt_SuccessNeedsUser
            CHECK (Outcome <> 'Success' OR UserId IS NOT NULL)
      , CONSTRAINT CK_auth_LoginAttempt_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS     NULL AND auditDeletedDateUtc IS     NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL))
    );
END
GO

-- The per-ACCOUNT lockout count.  Leading on UserName because the count is taken before the user name has been resolved
-- to a UserId -- and must be, because an unknown account has no UserId and still has to cost the same work (19.2).
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_auth_LoginAttempt_Account' AND object_id = OBJECT_ID (N'auth.LoginAttempt'))
BEGIN
    CREATE INDEX IX_auth_LoginAttempt_Account
        ON auth.LoginAttempt (UserName, AttemptedUtc) WHERE Outcome = 'Failure' AND IsDeleted = 0;
END
GO

-- The per-ADDRESS throttle count.  A separate index because it is a separate question: section 7.4 says the two counts
-- are taken independently and neither is derived from the other, and an index that served both would mean one of them
-- was a scan of the other's results.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_auth_LoginAttempt_Address' AND object_id = OBJECT_ID (N'auth.LoginAttempt'))
BEGIN
    CREATE INDEX IX_auth_LoginAttempt_Address
        ON auth.LoginAttempt (ClientAddress, AttemptedUtc) WHERE Outcome = 'Failure' AND IsDeleted = 0;
END
GO

-- "Show me this person's sign-in history" -- the administrative and incident-response read, which is by UserId and so
-- sees only the attempts that resolved to a real account.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_auth_LoginAttempt_User' AND object_id = OBJECT_ID (N'auth.LoginAttempt'))
BEGIN
    CREATE INDEX IX_auth_LoginAttempt_User
        ON auth.LoginAttempt (UserId, AttemptedUtc DESC) WHERE UserId IS NOT NULL AND IsDeleted = 0;
END
GO

-- The pending exchanges, for the timeout sweep and for E-50105.  Filtered to the two pending states, so the index holds
-- only the handful of rows an in-flight sign-in leaves behind rather than the whole history.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_auth_LoginAttempt_Pending' AND object_id = OBJECT_ID (N'auth.LoginAttempt'))
BEGIN
    CREATE INDEX IX_auth_LoginAttempt_Pending
        ON auth.LoginAttempt (AttemptedUtc)
        WHERE Outcome IN ('VerifierIssued', 'SsoBegun') AND IsDeleted = 0;
END
GO

-- *** 7. Audit triggers ***
--
-- Six tables, six triggers, and every one of them carries a substantive immutability guard rather than only the audit
-- stamp.  That is not ceremony: on these six tables the dangerous operation is an UPDATE that changes what a row MEANS
-- while leaving a plausible-looking row behind, and an UPDATE leaves no insert and no delete for a reviewer to notice.
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.trg_au_updt_UserCredential
Author:       rsincero
CreateDate:   2026-09-19
Description:
AFTER UPDATE audit stamp for auth.UserCredential, and the guard that makes UserId and CredentialType immutable
-- E-50010.

Moving a credential row to a different UserId is handing one person's password to another account, in one statement,
with no insert and no delete.  Changing CredentialType reinterprets the verifier under rules it was not produced by.

VerifierPhc IS mutable: changing it is what a password change is.  The procedure that does it copies the old value into
auth.PasswordHistory first -- this trigger deliberately does not, because a trigger that wrote history would also write
it for a soft delete and for an expiry change, and the reuse check would then be comparing against rows that were never
retired passwords.

Modification History:
2026-09-19  rsincero  Created.  PLAN-AUTH-001 T-026.
***********************************************************************************************************************/
CREATE OR ALTER TRIGGER auth.trg_au_updt_UserCredential
    ON auth.UserCredential
    AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    IF (UPDATE (UserId) OR UPDATE (CredentialType))
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.UserCredentialId = i.UserCredentialId
                    WHERE i.UserId <> d.UserId
                       OR i.CredentialType <> d.CredentialType)
    BEGIN
        ;THROW 50010, N'auth.UserCredential.UserId and CredentialType are immutable: re-pointing a credential row hands one person''s password to another account in a single UPDATE. Soft-delete the row and insert a new one.', 1;
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
      FROM auth.UserCredential AS t
      JOIN inserted AS i ON i.UserCredentialId = t.UserCredentialId
      JOIN deleted  AS d ON d.UserCredentialId = t.UserCredentialId;
END;
GO

/***********************************************************************************************************************
ObjectName:   auth.trg_au_updt_PasswordHistory
Author:       rsincero
CreateDate:   2026-09-19
Description:
AFTER UPDATE audit stamp for auth.PasswordHistory, and the guard that makes the whole row immutable -- E-50010.

A history row has nothing legitimately mutable on it except IsDeleted.  It records that a particular verifier was
retired at a particular moment for a particular person, and all three of those are statements about the past.  An
UPDATE to any of them is either a mistake or an attempt to make a reused password pass the reuse check, and the second
one is silent.

Modification History:
2026-09-19  rsincero  Created.  PLAN-AUTH-001 T-026.
***********************************************************************************************************************/
CREATE OR ALTER TRIGGER auth.trg_au_updt_PasswordHistory
    ON auth.PasswordHistory
    AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    IF (UPDATE (UserId) OR UPDATE (VerifierPhc) OR UPDATE (RetiredUtc))
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.PasswordHistoryId = i.PasswordHistoryId
                    WHERE i.UserId <> d.UserId
                       OR i.VerifierPhc <> d.VerifierPhc
                       OR i.RetiredUtc <> d.RetiredUtc)
    BEGIN
        ;THROW 50010, N'auth.PasswordHistory is immutable except for IsDeleted: every column on it is a statement about the past, and an UPDATE is how a reused password passes the reuse check silently.', 1;
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
      FROM auth.PasswordHistory AS t
      JOIN inserted AS i ON i.PasswordHistoryId = t.PasswordHistoryId
      JOIN deleted  AS d ON d.PasswordHistoryId = t.PasswordHistoryId;
END;
GO

/***********************************************************************************************************************
ObjectName:   auth.trg_au_updt_UserFederatedIdentity
Author:       rsincero
CreateDate:   2026-09-19
Description:
AFTER UPDATE audit stamp for auth.UserFederatedIdentity, and the guard that makes UserId, Issuer and SubjectId
immutable -- E-50010.  This is where INV-07 has teeth.

The unique index stops one directory identity being linked to two people.  It does NOT stop an existing link being
re-pointed, and re-pointing is the account takeover: one UPDATE moves somebody else's directory identity onto your user
row, or your row's subject identifier onto somebody else's identity, and the index is satisfied throughout because no
pair is duplicated at any instant.  Nothing is inserted and nothing is deleted, so there is nothing for a reviewer to
find afterwards.

Unlinking is therefore a soft delete, and linking is an insert, and both halves of a re-point leave a row behind.

LastSeenUtc IS mutable: auth.uspCompleteSsoLogin stamps it on every federated sign-in.

Modification History:
2026-09-19  rsincero  Created.  PLAN-AUTH-001 T-027.
***********************************************************************************************************************/
CREATE OR ALTER TRIGGER auth.trg_au_updt_UserFederatedIdentity
    ON auth.UserFederatedIdentity
    AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    IF (UPDATE (UserId) OR UPDATE (Issuer) OR UPDATE (SubjectId))
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.UserFederatedIdentityId = i.UserFederatedIdentityId
                    WHERE i.UserId <> d.UserId
                       OR i.Issuer <> d.Issuer
                       OR i.SubjectId <> d.SubjectId)
    BEGIN
        ;THROW 50010, N'auth.UserFederatedIdentity.UserId, Issuer and SubjectId are immutable -- INV-07: re-pointing a link is account takeover in one UPDATE, and the unique index is satisfied throughout because no pair is ever duplicated. Soft-delete the link and insert a new one.', 1;
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
      FROM auth.UserFederatedIdentity AS t
      JOIN inserted AS i ON i.UserFederatedIdentityId = t.UserFederatedIdentityId
      JOIN deleted  AS d ON d.UserFederatedIdentityId = t.UserFederatedIdentityId;
END;
GO

/***********************************************************************************************************************
ObjectName:   auth.trg_au_updt_UserMfaFactor
Author:       rsincero
CreateDate:   2026-09-19
Description:
AFTER UPDATE audit stamp for auth.UserMfaFactor, the guard that makes UserId and FactorType immutable, and the guard
that forces a re-enrolment to clear the replay high-water mark -- E-50010.

The second guard is the unobvious one.  LastUsedTimeStep is a high-water mark: auth.uspVerifyMfa refuses any step that
is not strictly greater (E-50111).  Re-enrolling installs a NEW secret, whose step numbers start from the current clock
and have nothing to do with the old secret's -- so a new SecretCiphertext left beside an old LastUsedTimeStep locks the
user out of the authenticator they have just set up, for as long as it takes the clock to pass the stale mark.  If the
stale mark came from a clock that was ahead, that is forever.

So changing SecretCiphertext requires setting LastUsedTimeStep to NULL in the SAME statement.  The trigger will not do
it silently, because a trigger that quietly cleared a replay guard would be a trigger that quietly cleared a replay
guard, and the next reader would have to know it did.

Modification History:
2026-09-19  rsincero  Created.  PLAN-AUTH-001 T-028.
***********************************************************************************************************************/
CREATE OR ALTER TRIGGER auth.trg_au_updt_UserMfaFactor
    ON auth.UserMfaFactor
    AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    IF (UPDATE (UserId) OR UPDATE (FactorType))
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.UserMfaFactorId = i.UserMfaFactorId
                    WHERE i.UserId <> d.UserId
                       OR i.FactorType <> d.FactorType)
    BEGIN
        ;THROW 50010, N'auth.UserMfaFactor.UserId and FactorType are immutable: re-pointing a factor row gives one person''s second factor to another account. Soft-delete the row and enrol again.', 1;
    END;

    IF UPDATE (SecretCiphertext)
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.UserMfaFactorId = i.UserMfaFactorId
                    WHERE DATALENGTH (i.SecretCiphertext) <> DATALENGTH (d.SecretCiphertext)
                       OR i.SecretCiphertext <> d.SecretCiphertext)
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.UserMfaFactorId = i.UserMfaFactorId
                    WHERE i.LastUsedTimeStep IS NOT NULL)
    BEGIN
        ;THROW 50010, N'auth.UserMfaFactor: changing SecretCiphertext requires setting LastUsedTimeStep = NULL and LastUsedUtc = NULL in the same statement. A new secret''s time steps are unrelated to the old secret''s, so a stale high-water mark locks the user out of the authenticator they have just enrolled -- E-50111.', 1;
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
      FROM auth.UserMfaFactor AS t
      JOIN inserted AS i ON i.UserMfaFactorId = t.UserMfaFactorId
      JOIN deleted  AS d ON d.UserMfaFactorId = t.UserMfaFactorId;
END;
GO

/***********************************************************************************************************************
ObjectName:   auth.trg_au_updt_UserMfaRecoveryCode
Author:       rsincero
CreateDate:   2026-09-19
Description:
AFTER UPDATE audit stamp for auth.UserMfaRecoveryCode, the guard that makes UserId and CodeHash immutable, and the guard
that makes UsedUtc WRITE-ONCE -- E-50010.

The write-once guard is the single-use guarantee, at the table.  A recovery code that can be un-used is a recovery code
that can be used twice, and "clear UsedUtc" is a one-line UPDATE that looks like an administrator being helpful.  The
correct way to give somebody a working code is to issue a new one -- which is an insert, and shows up as one.

Modification History:
2026-09-19  rsincero  Created.  PLAN-AUTH-001 T-028.
***********************************************************************************************************************/
CREATE OR ALTER TRIGGER auth.trg_au_updt_UserMfaRecoveryCode
    ON auth.UserMfaRecoveryCode
    AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    IF (UPDATE (UserId) OR UPDATE (CodeHash))
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.UserMfaRecoveryCodeId = i.UserMfaRecoveryCodeId
                    WHERE i.UserId <> d.UserId
                       OR i.CodeHash <> d.CodeHash)
    BEGIN
        ;THROW 50010, N'auth.UserMfaRecoveryCode.UserId and CodeHash are immutable: re-pointing a code row gives one person''s recovery code to another account. Soft-delete the row and issue a new code.', 1;
    END;

    IF UPDATE (UsedUtc)
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.UserMfaRecoveryCodeId = i.UserMfaRecoveryCodeId
                    WHERE d.UsedUtc IS NOT NULL
                      AND (i.UsedUtc IS NULL OR i.UsedUtc <> d.UsedUtc))
    BEGIN
        ;THROW 50010, N'auth.UserMfaRecoveryCode.UsedUtc is write-once: a code that can be un-used is a code that can be used twice. To give somebody a working code, issue a new one -- that is an insert, and it shows up as one.', 1;
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
      FROM auth.UserMfaRecoveryCode AS t
      JOIN inserted AS i ON i.UserMfaRecoveryCodeId = t.UserMfaRecoveryCodeId
      JOIN deleted  AS d ON d.UserMfaRecoveryCodeId = t.UserMfaRecoveryCodeId;
END;
GO

/***********************************************************************************************************************
ObjectName:   auth.trg_au_updt_LoginAttempt
Author:       rsincero
CreateDate:   2026-09-19
Description:
AFTER UPDATE audit stamp for auth.LoginAttempt, the guard that makes the identifying columns immutable, and the guard
that makes a terminal Outcome final -- E-50010.  This is D-14's enforcement.

One exchange is one row (section 7.1).  The first step inserts it pending; later steps update it.  That design is only
safe if a concluded exchange cannot be reopened: otherwise a 'Failure' row can be turned back into 'VerifierIssued' and
replayed, and -- worse and quieter -- a failure can be edited out of existence, which reduces both lockout counts
without deleting anything.

So Outcome may move from a pending state to a terminal one, and from there nowhere.  ApplicationId, UserName,
ClientAddress and AttemptedUtc may not change at all: each of them is an input to a lockout count, and changing one
moves an attempt from one account's tally, or one address's tally, to another's.

Modification History:
2026-09-19  rsincero  Created.  PLAN-AUTH-001 T-029.
***********************************************************************************************************************/
CREATE OR ALTER TRIGGER auth.trg_au_updt_LoginAttempt
    ON auth.LoginAttempt
    AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    IF (UPDATE (ApplicationId) OR UPDATE (UserName) OR UPDATE (ClientAddress) OR UPDATE (AttemptedUtc))
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.LoginAttemptId = i.LoginAttemptId
                    WHERE i.ApplicationId <> d.ApplicationId
                       OR i.UserName <> d.UserName
                       OR i.ClientAddress <> d.ClientAddress
                       OR i.AttemptedUtc <> d.AttemptedUtc)
    BEGIN
        ;THROW 50010, N'auth.LoginAttempt.ApplicationId, UserName, ClientAddress and AttemptedUtc are immutable: each is an input to a lockout count, and changing one moves a failed attempt from one account''s or one address''s tally to another''s -- section 7.4.', 1;
    END;

    IF UPDATE (Outcome)
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.LoginAttemptId = i.LoginAttemptId
                    WHERE d.Outcome IN ('Success', 'Failure')
                      AND i.Outcome <> d.Outcome)
    BEGIN
        ;THROW 50010, N'auth.LoginAttempt.Outcome is terminal once it is Success or Failure -- D-14: reopening a concluded exchange makes it replayable, and editing a Failure away reduces both lockout counts without deleting a row. Start a new exchange.', 1;
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
      FROM auth.LoginAttempt AS t
      JOIN inserted AS i ON i.LoginAttemptId = t.LoginAttemptId
      JOIN deleted  AS d ON d.LoginAttemptId = t.LoginAttemptId;
END;
GO

-- *** 8. Descriptions ***
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
      (N'auth', N'TABLE', N'UserCredential', NULL, N'The local password verifier, one live row per user per credential type. The database stores it and never computes or compares it -- D-08, section 19.2: a memory-hard KDF run in the engine spends the server on every guess, and the plaintext would land in the plan cache. auth.uspGetLoginVerifier hands the string out; auth.uspCompleteLogin is told the answer.')
    , (N'auth', N'TABLE', N'UserCredential', N'UserCredentialId', N'Surrogate key.')
    , (N'auth', N'TABLE', N'UserCredential', N'UserId',           N'The person. IMMUTABLE -- re-pointing a credential row hands one person''s password to another account in one UPDATE.')
    , (N'auth', N'TABLE', N'UserCredential', N'CredentialType',   N'''Password'' today. Present rather than implied so that adding another kind later is a CHECK constraint change, not a second table with its own audit columns. IMMUTABLE.')
    , (N'auth', N'TABLE', N'UserCredential', N'VerifierPhc',      N'The PHC string: algorithm, parameters, salt and digest in one self-describing field. NVARCHAR (512) so two algorithms can coexist during a migration -- the PHC prefix is what tells the application which one it is holding. Never split into columns: that is how a deployment ends up with a digest whose parameters nobody recorded.')
    , (N'auth', N'TABLE', N'UserCredential', N'LastChangedUtc',   N'When the verifier was last replaced, UTC. Read by the password-age rules and written by the change procedure, which copies the old value to auth.PasswordHistory in the same transaction.')
    , (N'auth', N'TABLE', N'UserCredential', N'ExpiresUtc',       N'When the password must be changed by, UTC. NULL means it does not expire, which is the shipped position: forced rotation drives people to predictable variations. Set it per deployment if a policy demands it.')

    , (N'auth', N'TABLE', N'PasswordHistory', NULL, N'Retired verifiers, so a reuse check can be made without reading the live one and to a depth that is configuration (Authn.PasswordHistoryDepth) rather than whatever a system-versioned table happens to hold. NOT a temporal history table: that would also record expiry changes and soft deletes, and a reuse check walking those gets slower for invisible reasons.')
    , (N'auth', N'TABLE', N'PasswordHistory', N'PasswordHistoryId', N'Surrogate key.')
    , (N'auth', N'TABLE', N'PasswordHistory', N'UserId',            N'The person. IMMUTABLE, like every column here.')
    , (N'auth', N'TABLE', N'PasswordHistory', N'VerifierPhc',       N'The retired PHC string. Compared by the application, never by the engine -- the same two-round-trip rule as auth.UserCredential.')
    , (N'auth', N'TABLE', N'PasswordHistory', N'RetiredUtc',        N'When this verifier stopped being the live one, UTC. IMMUTABLE: the reuse check reads the newest N rows, so an editable timestamp is an editable reuse check.')

    , (N'auth', N'TABLE', N'UserFederatedIdentity', NULL, N'The link between a person and a directory account. Joined on (Issuer, SubjectId) and never on email -- INV-07, section 6.1. The unique index stops one directory identity being linked to two people; the trigger stops an existing link being RE-POINTED, which is the account takeover the index cannot see.')
    , (N'auth', N'TABLE', N'UserFederatedIdentity', N'UserFederatedIdentityId', N'Surrogate key.')
    , (N'auth', N'TABLE', N'UserFederatedIdentity', N'UserId',      N'The person. IMMUTABLE -- INV-07.')
    , (N'auth', N'TABLE', N'UserFederatedIdentity', N'Issuer',      N'The identity provider, as the issuer value in the token. NVARCHAR (512) because an issuer URL with a directory tenant identifier in it is long. IMMUTABLE.')
    , (N'auth', N'TABLE', N'UserFederatedIdentity', N'SubjectId',   N'The provider''s immutable identifier for the account -- oid or sub, never email. A value containing @ is refused by CK_auth_UserFederatedIdentity_SubjectId, because that is INV-07 being broken by a claim mapping rather than by a decision. IMMUTABLE.')
    , (N'auth', N'TABLE', N'UserFederatedIdentity', N'LinkedUtc',   N'When the link was made, UTC.')
    , (N'auth', N'TABLE', N'UserFederatedIdentity', N'LastSeenUtc', N'When this link was last used to sign in, UTC. Mutable: stamped by auth.uspCompleteSsoLogin. Useful for finding links to directory accounts that no longer exist.')

    , (N'auth', N'TABLE', N'UserMfaFactor', NULL, N'An enrolled second factor. The secret is ciphertext produced outside this database under a key that must not live in it, so the engine cannot verify a code even in principle: the application verifies and reports which time step it verified, and auth.uspVerifyMfa bounds that step against the server clock and against LastUsedTimeStep. Task T-041 closed gap G-07 on where the key lives -- application-side envelope encryption with a TPM-backed CNG key on the application-layer server, NOT SQL Server Always Encrypted, because external readers such as Power BI need these tables and a template cannot know which columns a deployment will add. Section 6.4. Rows are written by auth.uspEnrolMfaFactor and confirmed by auth.uspConfirmMfaFactor in 112_auth_mfa_procedures.sql.')
    , (N'auth', N'TABLE', N'UserMfaFactor', N'UserMfaFactorId',  N'Surrogate key.')
    , (N'auth', N'TABLE', N'UserMfaFactor', N'UserId',           N'The person. IMMUTABLE.')
    , (N'auth', N'TABLE', N'UserMfaFactor', N'FactorType',       N'''Totp'' today. IMMUTABLE.')
    , (N'auth', N'TABLE', N'UserMfaFactor', N'SecretCiphertext', N'The shared secret, encrypted by the application under an external key. Never plaintext, never decrypted in T-SQL. Changing it requires clearing LastUsedTimeStep in the same statement -- see the trigger.')
    , (N'auth', N'TABLE', N'UserMfaFactor', N'KeyReference',     N'Which external key this row was encrypted under, so a rotation can find the rows still on the old one. An identifier. NEVER key material, and nothing in this database should ever be able to turn it into key material. Form is scheme:name#vN -- cng: for a TPM-backed CNG container on the application-layer server, vault: for a self-hosted HashiCorp Vault, dev: for a workstation key with no hardware protection -- enforced by CK_auth_UserMfaFactor_KeyReferenceFormat in LIKE and CHARINDEX rather than a regular expression, because SQL Server 2022 has none. The #vN suffix is what makes a re-key under the same container name distinguishable, which is the case rotation actually needs. Stamped from Authn.MfaKeyReferenceCurrent by auth.uspEnrolMfaFactor and changed only by auth.uspRotateMfaFactorKey. Section 6.4, task T-041.')
    , (N'auth', N'TABLE', N'UserMfaFactor', N'IsConfirmed',      N'0 is an enrolment in progress and does NOT satisfy MFA. E-50110 is raised when there is no CONFIRMED factor, which is a different condition from having no factor at all.')
    , (N'auth', N'TABLE', N'UserMfaFactor', N'ConfirmedUtc',     N'When the user proved they could produce a code from this secret, UTC. Paired with IsConfirmed by CK_auth_UserMfaFactor_ConfirmedPair.')
    , (N'auth', N'TABLE', N'UserMfaFactor', N'LastUsedUtc',      N'When the factor was last accepted, UTC. An audit answer to "when", not the replay guard.')
    , (N'auth', N'TABLE', N'UserMfaFactor', N'LastUsedTimeStep', N'The replay guard: the TOTP time step last accepted. auth.uspVerifyMfa requires a strictly GREATER step (E-50111), so a code already accepted cannot be replayed inside its own validity window. A timestamp cannot do this job -- the question is which step, not when.')

    , (N'auth', N'TABLE', N'UserMfaRecoveryCode', NULL, N'One-time codes for a user who has lost their authenticator. CodeHash is a plain SHA-256 and deliberately NOT a password hash: a recovery code is machine-generated with enough entropy that guessing is not the attack, so a memory-hard KDF buys nothing and costs a round trip on the one path a locked-out person takes.')
    , (N'auth', N'TABLE', N'UserMfaRecoveryCode', N'UserMfaRecoveryCodeId', N'Surrogate key.')
    , (N'auth', N'TABLE', N'UserMfaRecoveryCode', N'UserId',   N'The person. IMMUTABLE.')
    , (N'auth', N'TABLE', N'UserMfaRecoveryCode', N'CodeHash', N'SHA-256 of the code, 32 bytes exactly. UNIQUE per user, NOT globally: two people may be issued the same code by coincidence, and a global unique index would refuse the second enrolment -- which is also an oracle. IMMUTABLE.')
    , (N'auth', N'TABLE', N'UserMfaRecoveryCode', N'UsedUtc',  N'When the code was redeemed, UTC. NULL means unused. WRITE-ONCE, enforced by the trigger: a code that can be un-used is a code that can be used twice, and clearing this column is a one-line UPDATE that looks like helpfulness. Issue a new code instead.')

    , (N'auth', N'TABLE', N'LoginAttempt', NULL, N'One row per sign-in EXCHANGE, not per round trip -- D-14, section 7.1. The first step inserts it with Outcome ''VerifierIssued'' or ''SsoBegun'' and returns LoginAttemptId; later steps update the same row, and a terminal Outcome is final. Also the sole source for both lockout counts (section 7.4), which is why UserName is recorded as a string: an attempt against an account that does not exist has no UserId, and those are exactly the attempts an enumeration probe makes.')
    , (N'auth', N'TABLE', N'LoginAttempt', N'LoginAttemptId',       N'Surrogate key, BIGINT: this is the highest-volume table in the design and every failed guess in the estate lands here. Returned by the first step of an exchange and presented by every later step.')
    , (N'auth', N'TABLE', N'LoginAttempt', N'ApplicationId',        N'Which application''s sign-in page this was. Scoped to an application rather than a tenant because the page belongs to an application; the tenant whose policy applied is PolicyTenantId and may be NULL. IMMUTABLE.')
    , (N'auth', N'TABLE', N'LoginAttempt', N'UserName',             N'The name that was TYPED, whether or not it names a real account. A string and not only a UserId, on purpose -- section 19.2. Leading column of the per-account lockout index. IMMUTABLE.')
    , (N'auth', N'TABLE', N'LoginAttempt', N'UserId',               N'The account the name resolved to, or NULL if it resolved to nothing. Nullable by design: see UserName.')
    , (N'auth', N'TABLE', N'LoginAttempt', N'PolicyTenantId',       N'The tenant whose authentication policy was applied, resolved by auth.udfResolveAuthPolicy. NULL when no tenant could be resolved -- and that failure (E-50102) must still be recorded.')
    , (N'auth', N'TABLE', N'LoginAttempt', N'ClientAddress',        N'The client address as the application reported it. NVARCHAR (45): the longest textual IPv6 form including an IPv4-mapped tail. A string rather than binary because what must be recorded is exactly what was reported. Leading column of the per-address throttle index. IMMUTABLE.')
    , (N'auth', N'TABLE', N'LoginAttempt', N'UserAgent',            N'The reported user agent, truncated by the application to 512. Diagnostic only: nothing authenticates or authorizes on it.')
    , (N'auth', N'TABLE', N'LoginAttempt', N'AuthenticationMethod', N'''LocalPassword'' or ''Federated''. Tied to the pending Outcome by two CHECK constraints, so an SSO exchange cannot be concluded as a password one.')
    , (N'auth', N'TABLE', N'LoginAttempt', N'IsBypassRoute',        N'1 for the platform-administrator bypass route. Requires IsPlatformAdmin = 1 (E-50108, INV-09) and always requires a satisfied second factor -- INV-08, enforced here by CK_auth_LoginAttempt_BypassNeedsMfa as well as by E-50107.')
    , (N'auth', N'TABLE', N'LoginAttempt', N'Outcome',              N'''VerifierIssued'' and ''SsoBegun'' are pending, one per route. ''Success'' and ''Failure'' are terminal and final: the trigger refuses any move away from them, because reopening a concluded exchange makes it replayable and editing a Failure away silently reduces both lockout counts.')
    , (N'auth', N'TABLE', N'LoginAttempt', N'FailureReason',        N'A short token saying what actually went wrong -- present exactly when Outcome is ''Failure''. NEVER shown to the user: every failure in the E-50100 range shows one generic message (section 14.5, UI-26). This column is where the real reason is kept so that support can answer without the sign-in page becoming an oracle.')
    , (N'auth', N'TABLE', N'LoginAttempt', N'PasswordVerified',     N'1 once the application has reported a correct password for this exchange. A ''Success'' on the local route with 0 here is refused by CK_auth_LoginAttempt_SuccessNeedsPassword -- the mistake that would make the whole file decorative.')
    , (N'auth', N'TABLE', N'LoginAttempt', N'MfaSatisfied',         N'1 once a second factor has been accepted for this exchange, by TOTP or by a recovery code. Read by INV-08''s CHECK constraint.')
    , (N'auth', N'TABLE', N'LoginAttempt', N'AttemptedUtc',         N'When the exchange STARTED, UTC. IMMUTABLE. Both lockout windows and the exchange timeout (Authn.LoginExchangeTimeoutSeconds) are measured from it.')
    , (N'auth', N'TABLE', N'LoginAttempt', N'ConcludedUtc',         N'When the exchange reached a terminal Outcome, UTC. NULL exactly while it is pending -- CK_auth_LoginAttempt_ConcludedPair. A pending row with a conclusion time could be neither aged out nor counted.');

    -- The seven audit columns carry the same description on every table, so they are generated rather than typed six
    -- times.  Getting this wrong by hand on the sixth table is how a schema ends up with descriptions that disagree.
    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    SELECT N'auth', N'TABLE', t.TableName, c.ColumnName, c.Description
      FROM (VALUES (N'UserCredential'), (N'PasswordHistory'), (N'UserFederatedIdentity')
                 , (N'UserMfaFactor'), (N'UserMfaRecoveryCode'), (N'LoginAttempt')) AS t (TableName)
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
      (N'auth', N'TRIGGER', N'trg_au_updt_UserCredential', NULL, N'AFTER UPDATE audit stamp, and the guard that makes UserId and CredentialType immutable -- E-50010.')
    , (N'auth', N'TRIGGER', N'trg_au_updt_PasswordHistory', NULL, N'AFTER UPDATE audit stamp, and the guard that makes every column except IsDeleted immutable -- E-50010.')
    , (N'auth', N'TRIGGER', N'trg_au_updt_UserFederatedIdentity', NULL, N'AFTER UPDATE audit stamp, and INV-07''s teeth: UserId, Issuer and SubjectId are immutable, because re-pointing a link is account takeover in one UPDATE and the unique index cannot see it -- E-50010.')
    , (N'auth', N'TRIGGER', N'trg_au_updt_UserMfaFactor', NULL, N'AFTER UPDATE audit stamp, UserId and FactorType immutable, and the guard that forces a new SecretCiphertext to clear LastUsedTimeStep in the same statement -- E-50010.')
    , (N'auth', N'TRIGGER', N'trg_au_updt_UserMfaRecoveryCode', NULL, N'AFTER UPDATE audit stamp, UserId and CodeHash immutable, and UsedUtc write-once -- the single-use guarantee at the table. E-50010.')
    , (N'auth', N'TRIGGER', N'trg_au_updt_LoginAttempt', NULL, N'AFTER UPDATE audit stamp, the lockout-count inputs immutable, and a terminal Outcome made final -- D-14''s enforcement. E-50010.');

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


-- *** 9. Grants ***
--
-- DELIBERATELY EMPTY, and these are the six tables INV-11 exists for.  A SELECT grant on auth.UserCredential hands a
-- compromised application login every password verifier in the estate to crack offline at its leisure; one on
-- auth.UserMfaFactor hands over every TOTP secret, and the only thing standing between those and working codes is a key
-- this database is not allowed to hold.  auth.LoginAttempt is the audit trail of the attack, and an UPDATE grant on it
-- is the ability to erase it.
--
-- applicationRole reaches all six ONLY through ownership chaining, inside the procedures 110_auth_authn_procedures.sql
-- creates.  170_permissions.sql grants EXECUTE on those, and states the absence as a schema-level DENY so that the
-- catalog shows a decision rather than a gap -- G-19.
GO


-- *** 10. Closing report ***
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
  FROM (VALUES
        (N'auth.UserCredential',        N'The local password verifier. Stored here, computed and compared by the application -- D-08.')
      , (N'auth.PasswordHistory',       N'Retired verifiers, to the depth Authn.PasswordHistoryDepth names.')
      , (N'auth.UserFederatedIdentity', N'(Issuer, SubjectId) and never email -- INV-07.')
      , (N'auth.UserMfaFactor',         N'The enrolled second factor. Secret encrypted outside this database -- T-041, section 6.4.')
      , (N'auth.UserMfaRecoveryCode',   N'One-time codes. UsedUtc is write-once.')
      , (N'auth.LoginAttempt',          N'One row per exchange -- D-14. The sole source for both lockout counts.'))
       AS x (QualifiedName, Purpose);

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN i.name IS NULL THEN 2 ELSE 4 END
     , CASE WHEN i.name IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Index ' + x.IndexName
     , x.Purpose
  FROM (VALUES
        (N'auth.UserCredential',        N'UX_auth_UserCredential_UserType',             N'UNIQUE. One live credential per user per type.')
      , (N'auth.UserCredential',        N'IX_auth_UserCredential_Expires',              N'The auth.uspExpireCredentials sweep (G-12). Filtered to credentials that have an expiry at all, so it is EMPTY -- and free -- wherever Authn.PasswordLifetimeDays is left at 0.')
      , (N'auth.PasswordHistory',       N'IX_auth_PasswordHistory_UserRetired',         N'RetiredUtc DESC: the check is always the newest N rows. Deliberately NOT unique -- every PHC string carries its own salt, so uniqueness would enforce nothing.')
      , (N'auth.UserFederatedIdentity', N'UX_auth_UserFederatedIdentity_IssuerSubject', N'UNIQUE. The INV-07 index: one directory identity cannot be linked to two people.')
      , (N'auth.UserFederatedIdentity', N'IX_auth_UserFederatedIdentity_User',          N'"Which directory accounts is this person linked to."')
      , (N'auth.UserMfaFactor',         N'UX_auth_UserMfaFactor_UserType',              N'UNIQUE. One live factor per user per type.')
      , (N'auth.UserMfaRecoveryCode',   N'UX_auth_UserMfaRecoveryCode_UserCode',        N'UNIQUE on (UserId, CodeHash) and NOT on CodeHash alone: a global index would refuse a coincidental duplicate, which is also an oracle.')
      , (N'auth.UserMfaRecoveryCode',   N'IX_auth_UserMfaRecoveryCode_Unused',          N'"How many codes are left" -- filtered to unused.')
      , (N'auth.LoginAttempt',          N'IX_auth_LoginAttempt_Account',                N'The per-ACCOUNT lockout count. Leads on UserName because the count is taken before the name is resolved, and must be -- section 19.2.')
      , (N'auth.LoginAttempt',          N'IX_auth_LoginAttempt_Address',                N'The per-ADDRESS throttle count. Separate because section 7.4 takes the two counts independently.')
      , (N'auth.LoginAttempt',          N'IX_auth_LoginAttempt_User',                   N'"Show me this person''s sign-in history."')
      , (N'auth.LoginAttempt',          N'IX_auth_LoginAttempt_Pending',                N'The in-flight exchanges, for the timeout sweep and E-50105.'))
       AS x (QualifiedName, IndexName, Purpose)
  LEFT JOIN sys.indexes AS i ON i.name = x.IndexName AND i.object_id = OBJECT_ID (x.QualifiedName);

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (x.TriggerName, N'TR') IS NULL THEN 2 ELSE 4 END
     , CASE WHEN OBJECT_ID (x.TriggerName, N'TR') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Trigger ' + x.TriggerName
     , x.Guard
  FROM (VALUES
        (N'auth.trg_au_updt_UserCredential',        N'UserId, CredentialType immutable.')
      , (N'auth.trg_au_updt_PasswordHistory',       N'Everything except IsDeleted immutable.')
      , (N'auth.trg_au_updt_UserFederatedIdentity', N'UserId, Issuer, SubjectId immutable -- INV-07''s teeth.')
      , (N'auth.trg_au_updt_UserMfaFactor',         N'UserId, FactorType immutable; a new secret must clear LastUsedTimeStep.')
      , (N'auth.trg_au_updt_UserMfaRecoveryCode',   N'UserId, CodeHash immutable; UsedUtc write-once.')
      , (N'auth.trg_au_updt_LoginAttempt',          N'Lockout-count inputs immutable; a terminal Outcome is final -- D-14.'))
       AS x (TriggerName, Guard);

-- INV-08 at the table, not only in a procedure.  Checked by name, because a constraint that was dropped during a
-- migration and never put back is exactly the kind of absence nothing else in the deployment would notice.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN EXISTS (SELECT 1 FROM sys.check_constraints
                          WHERE name = N'CK_auth_LoginAttempt_BypassNeedsMfa'
                            AND parent_object_id = OBJECT_ID (N'auth.LoginAttempt'))
            THEN 4 ELSE 1 END
     , CASE WHEN EXISTS (SELECT 1 FROM sys.check_constraints
                          WHERE name = N'CK_auth_LoginAttempt_BypassNeedsMfa'
                            AND parent_object_id = OBJECT_ID (N'auth.LoginAttempt'))
            THEN 'OK' ELSE 'VIOLATION' END
     , N'INV-08 is enforced by a CHECK constraint'
     , N'The bypass route always requires a second factor. auth.uspCompleteLogin raises E-50107 and '
     + N'CK_auth_LoginAttempt_BypassNeedsMfa refuses the row. Two enforcements of one rule is not duplication when one '
     + N'of them is the only one that survives somebody writing to the table directly.';

-- T-041's teeth.  The grammar constraint is the whole of what this database can enforce about key custody, so its
-- ABSENCE is a severity-1 finding: without it, KeyReference is a free-text column and rotation stops being possible.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN EXISTS (SELECT 1 FROM sys.check_constraints
                          WHERE name = N'CK_auth_UserMfaFactor_KeyReferenceFormat'
                            AND parent_object_id = OBJECT_ID (N'auth.UserMfaFactor'))
            THEN 4 ELSE 1 END
     , CASE WHEN EXISTS (SELECT 1 FROM sys.check_constraints
                          WHERE name = N'CK_auth_UserMfaFactor_KeyReferenceFormat'
                            AND parent_object_id = OBJECT_ID (N'auth.UserMfaFactor'))
            THEN 'OK' ELSE 'MISSING' END
     , N'Task T-041 -- the KeyReference grammar is enforced'
     , N'scheme:name#vN, with scheme in (cng, vault, dev). Gap G-07 closed with application-side envelope encryption, so '
     + N'the key is never here and this NAME is the only handle a rotation has on it. Without the constraint the column '
     + N'is free text, and a deployment that wrote the key''s name three different ways cannot retire a compromised key. '
     + N'If this says MISSING, section 4 refused to add it because existing rows do not conform -- the rows are listed '
     + N'below. Section 6.4.';

-- The rows that stopped it, named.  Nothing in this script rewrites them: this script does not know what those strings
-- were supposed to mean, and a guess would orphan a secret from its key silently.
INSERT @Report (Severity, Status, Item, Detail)
SELECT 1, 'VIOLATION', N'KeyReference does not match the T-041 grammar: UserMfaFactorId ' + CAST (f.UserMfaFactorId AS NVARCHAR (10))
     , N'Value: ' + f.KeyReference + N'. Expected scheme:name#vN with scheme in (cng, vault, dev), no whitespace, '
     + N'exactly one colon and one hash, and a numeric version of one to four digits. Correct it, or re-key the factor '
     + N'with auth.uspRotateMfaFactorKey, then re-run this script to add the constraint.'
  FROM auth.UserMfaFactor AS f
 WHERE NOT EXISTS (SELECT 1 FROM sys.check_constraints
                    WHERE name = N'CK_auth_UserMfaFactor_KeyReferenceFormat'
                      AND parent_object_id = OBJECT_ID (N'auth.UserMfaFactor'))
   AND NOT (LEN (f.KeyReference) BETWEEN 8 AND 256
        AND (f.KeyReference LIKE N'cng:%' OR f.KeyReference LIKE N'vault:%' OR f.KeyReference LIKE N'dev:%')
        AND LEN (f.KeyReference) - LEN (REPLACE (f.KeyReference, N'#', N'')) = 1
        AND LEN (f.KeyReference) - LEN (REPLACE (f.KeyReference, N':', N'')) = 1
        AND CHARINDEX (N'#', f.KeyReference) > CHARINDEX (N':', f.KeyReference) + 1
        AND (f.KeyReference LIKE N'%#v[0-9]'
          OR f.KeyReference LIKE N'%#v[0-9][0-9]'
          OR f.KeyReference LIKE N'%#v[0-9][0-9][0-9]'
          OR f.KeyReference LIKE N'%#v[0-9][0-9][0-9][0-9]')
        AND f.KeyReference NOT LIKE N'% %'
        AND f.KeyReference NOT LIKE N'%' + NCHAR (9)  + N'%'
        AND f.KeyReference NOT LIKE N'%' + NCHAR (10) + N'%'
        AND f.KeyReference NOT LIKE N'%' + NCHAR (13) + N'%');

-- Which key the live factors are actually on.  This is the question a rotation starts from, and the answer is one GROUP
-- BY -- which is the entire practical reason KeyReference is a disciplined string rather than a comment.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN f.KeyReference LIKE N'dev:%' THEN 3 ELSE 4 END
     , CASE WHEN f.KeyReference LIKE N'dev:%' THEN 'REVIEW' ELSE 'OK' END
     , N'MFA factors under key ' + f.KeyReference
     , CAST (COUNT (*) AS NVARCHAR (10)) + N' live factor(s), '
     + CAST (SUM (CASE WHEN f.IsConfirmed = 1 THEN 1 ELSE 0 END) AS NVARCHAR (10)) + N' of them confirmed.'
     + CASE WHEN f.KeyReference LIKE N'dev:%'
            THEN N' The dev: scheme means a key with no hardware protection and no escrow -- correct on a workstation '
               + N'and wrong in production. Re-key with auth.uspRotateMfaFactorKey once a cng: or vault: key exists.'
            ELSE N''
       END
  FROM auth.UserMfaFactor AS f
 WHERE f.IsDeleted = 0
 GROUP BY f.KeyReference;

INSERT @Report (Severity, Status, Item, Detail)
SELECT 3, 'INFO', N'Credentials and factors'
     , CAST ((SELECT COUNT (*) FROM auth.UserCredential      WHERE IsDeleted = 0) AS NVARCHAR (10)) + N' credential(s), '
     + CAST ((SELECT COUNT (*) FROM auth.UserFederatedIdentity WHERE IsDeleted = 0) AS NVARCHAR (10)) + N' federated link(s), '
     + CAST ((SELECT COUNT (*) FROM auth.UserMfaFactor       WHERE IsDeleted = 0) AS NVARCHAR (10)) + N' MFA factor(s), '
     + CAST ((SELECT COUNT (*) FROM auth.LoginAttempt        WHERE IsDeleted = 0) AS NVARCHAR (10)) + N' login attempt(s). '
     + N'All zero on a first deployment: this script seeds nothing. '
     + N'database/_tests/040_identity_and_authn.sql creates throwaway fixtures for a development database.';

INSERT @Report (Severity, Status, Item, Detail)
VALUES (3, 'NEXT', N'Next scripts'
      , N'070_auth_session.sql (auth.UserSession), 085_logs_auth_tables.sql (logs.AuthenticationEvent), '
      + N'100_auth_functions.sql (auth.udfResolveAuthPolicy, auth.udfIsUserUsable, auth.udfResolveSessionUser), '
      + N'110_auth_authn_procedures.sql (the seven authentication procedures) and 112_auth_mfa_procedures.sql (the four '
      + N'enrolment procedures, T-041).');

IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
    PRINT N'auth identity tables: PROBLEMS found. Read the report below before running the next script.';
ELSE
    PRINT N'auth identity tables: no problems found.';

PRINT N'';

SELECT Severity, Status, Item, Detail
  FROM @Report
 ORDER BY Severity, RowNo;
GO
