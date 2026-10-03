/***********************************************************************************************************************
Script:         040_auth_userprofile.sql
Purpose:        auth.User -- the person -- and auth.UserProfile -- the hat they wear at one organization.
Target:         SQL Server 2022.
Run as:         db_owner in the target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/040_auth_userprofile.sql
Idempotent:     Yes.  Every CREATE is guarded, every trigger is CREATE OR ALTER, nothing is dropped, nothing is seeded.
Depends on:     database/005_schemas_and_roles.sql (schema auth), database/030_auth_tenant.sql (auth.Tenant, which
                auth.UserProfile references), templates/extended-properties.sql (util.uspSetObjectDescription).
Implements:     DES-AUTH-001 sections 6.1, 6.3, 7.2, 8.3, 8.5, 15.3 and 15.4.  PLAN-AUTH-001 tasks T-025 and T-046.
To retarget:    Pass it per run:  sqlcmd -d <database> -v DbName=<database>.  There is no in-file default.

THE FILE HOLDS TWO PHASES' WORK, AND WHY IS WORTH READING BEFORE ANYTHING ELSE
-----------------------------------------------------------------------------
The Scripts worksheet gives this file build phase "2, 3".  Phase 2 created auth.User (task T-025).  Phase 3 adds
auth.UserProfile (task T-046), because a profile is bound to a tenant AND carries role grants, and the authorization
tables it belongs with did not exist until Phase 3.

Until Phase 3 ran, two consequences held, and both had already caught this project once.  They are recorded here
because the report at the end of this script used to state them on every run and no longer does:

  1.  090_dbo_application.sql WAS SKIPPED BY THE RUNNER.  It asserts BOTH auth.Tenant and auth.UserProfile, because
      its composite foreign key stops cross-tenant assignment.  auth.Tenant arrived in Phase 1 and auth.UserProfile
      only now, so the dependency was half met.  BL-023 is the defect that came from a probe testing only the first of
      two required tables; BL-025 is the correction of two files that said auth.UserProfile was Phase 2 work.

  2.  A PHASE 2 SESSION HAD NO ACTIVE PROFILE.  auth.UserSession.ActiveUserProfileId is nullable and stayed NULL, so
      Phase 2 could authenticate a person and could not authorize anything they did.  That was the correct boundary --
      authentication is who you are, authorization is what you may do, and this project builds them in that order.

auth.UserProfile CARRIES A UNIQUE CONSTRAINT THAT IS NOT FILTERED, AND IT IS THE ONLY ONE IN THE DATABASE
-------------------------------------------------------------------------------------------------------
UX_auth_UserProfile_Id_Tenant is UNIQUE (UserProfileId, TenantId) with no WHERE clause, and every other uniqueness
rule here is a filtered index on IsDeleted = 0.  Three separate facts force it:

  *  dbo.CaseFile and dbo.CaseNote carry FOREIGN KEY (AssignedToProfileId, TenantId) REFERENCES
     auth.UserProfile (UserProfileId, TenantId).  That pair is what makes it structurally impossible to assign an
     Anne Arundel record to a Baltimore City profile -- the mis-tenanted assignment is not caught by a trigger, it
     cannot be written.
  *  A FOREIGN KEY in SQL Server may reference only a PRIMARY KEY or a UNIQUE CONSTRAINT.  A unique INDEX, filtered or
     not, is not eligible.  So this has to be a constraint, not the CREATE UNIQUE INDEX the rest of the database uses.
  *  A constraint cannot be filtered at all.

It is named UX_ rather than UQ_ because auth.TenantType already carries the identical arrangement for the identical
reason -- UX_auth_TenantType_Id_Code, so that auth.Tenant can denormalise the type code and keep
CK_auth_Tenant_RootHasNoParent row-local -- and one prefix for one thing is worth more than a prefix that distinguishes
a constraint from an index nobody was going to confuse it with.

The filtered-unique convention exists so a soft-deleted row cannot block re-creation of the same key.  Nothing is at
risk here: UserProfileId is an IDENTITY, so the pair is unique for a reason that has nothing to do with IsDeleted, and
there is no "same key again" case to make room for.  The convention gate is told about this in the same breath, which
is why the constraint is spelled out in the CREATE TABLE rather than added as an index afterwards.

DEACTIVATING A PROFILE IS NOT DEACTIVATING A USER, AND THE TWO COLUMNS LIVE ON DIFFERENT TABLES ON PURPOSE
---------------------------------------------------------------------------------------------------------
Section 8.5.  auth.User.IsActive = 0 stops the person signing in at all.  auth.UserProfile.IsActive = 0 removes one
hat: they still sign in and still use their other profiles.  A user whose every profile is inactive authenticates
successfully and then reaches a screen that has to tell them so -- UI-09 -- rather than crashing or, far worse,
defaulting to an unscoped view.

auth.User IS NOT TENANT-SCOPED, AND THAT IS THE DESIGN'S LOAD-BEARING IDENTITY DECISION
--------------------------------------------------------------------------------------
Section 6.1.  One person, one row, however many organizations they act for.  The alternative -- a user row per tenant
-- makes "the same person" a join across rows nobody can perform reliably, and turns the two-organization case the
source requirements describe into two accounts with two passwords that drift apart.

So there is no TenantId on this table and there must never be one.  Everything organizational hangs off
auth.UserProfile: the tenant, the role grants, the scope.  A column added here "just for convenience" would be the
first authority that is not visible in auth.vwProfilePermission.

EMAIL IS NOT A KEY, AND HAS NO UNIQUE INDEX
-------------------------------------------
Deliberately, and for the same reason INV-07 exists.  Email addresses are reassigned when people leave and changed
when people marry.  A unique index here would refuse a legitimate new starter who inherited a predecessor's address
and would refuse a marriage, and the workaround for both is an edit to somebody else's row.  There is a NON-unique
index, because "who is bob@example.gov" is a real support question.

UserName IS the key, is unique where IsDeleted = 0, and is immutable -- see the trigger.

THE TWO LOCKOUT COLUMNS SAY DIFFERENT THINGS AND THE EFFECTIVE STATE IS NEITHER OF THEM ALONE
--------------------------------------------------------------------------------------------
IsLockedOut is the flag.  LockoutEndUtc is when it lapses, and NULL means never -- an administrative lock, held until
somebody clears it.  So a user is EFFECTIVELY locked when

    IsLockedOut = 1 AND (LockoutEndUtc IS NULL OR LockoutEndUtc > SYSUTCDATETIME ())

and a row whose LockoutEndUtc has passed is a lapsed lock that nothing has tidied up.  NOTHING TIDIES IT UP ON A
SCHEDULE, on purpose: a background job that clears lapsed locks is a job that has to run, and the trail is more useful
with the lapsed lock left in place.  auth.uspCompleteLogin clears it lazily, on the next successful sign-in.

That expression appears in exactly one place -- auth.udfIsUserUsable, 100_auth_functions.sql -- for the same reason
auth.udfIsTenantUsable exists.  A second copy is a second IsDeleted filter to get wrong, and this one fails OPEN.
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

IF SCHEMA_ID (N'auth') IS NULL
BEGIN
    DECLARE @MsgSchema NVARCHAR (2000) =
        N'Schema [auth] does not exist. Run database/005_schemas_and_roles.sql first. Nothing has been changed.';

    THROW 50000, @MsgSchema, 1;
END
GO

-- auth.User needs nothing but the schema.  auth.UserProfile needs auth.Tenant, so the assertion arrived with section 2
-- rather than with the file, and it names the script that supplies it -- BL-023 is the defect that came from a probe
-- checking one of two required tables and reporting success.
IF OBJECT_ID (N'auth.Tenant', N'U') IS NULL
BEGIN
    DECLARE @MsgTenant NVARCHAR (2000) =
        N'auth.Tenant does not exist. auth.UserProfile has a foreign key to it. Run database/030_auth_tenant.sql '
      + N'first. Nothing has been changed.';

    THROW 50000, @MsgTenant, 1;
END
GO


-- *** 1. auth.User ***
--
-- UserName is NVARCHAR (256) because a federated deployment will use the userPrincipalName, and Email is NVARCHAR (320)
-- because that is the longest an address can be (64 local part + @ + 255 domain).
--
-- AuthPolicyOverrideJson is NVARCHAR (MAX) with an ISJSON check and NOT the native json type: the type is SQL Server
-- 2025 and the floor -- and the ceiling -- of this design is 2022.  Section 7.2.
IF OBJECT_ID (N'auth.User', N'U') IS NULL
BEGIN
    CREATE TABLE auth.[User]
    (
        UserId               INT             IDENTITY (1, 1) NOT NULL
      , UserName             NVARCHAR (256)                  NOT NULL
      , DisplayName          NVARCHAR (256)                  NOT NULL
      , Email                NVARCHAR (320)                      NULL
      , IsActive             BIT                             NOT NULL
            CONSTRAINT DF_auth_User_IsActive DEFAULT (1)
      , IsPlatformAdmin      BIT                             NOT NULL
            CONSTRAINT DF_auth_User_IsPlatformAdmin DEFAULT (0)
      , IsLockedOut          BIT                             NOT NULL
            CONSTRAINT DF_auth_User_IsLockedOut DEFAULT (0)
      , LockoutEndUtc        DATETIME2 (3)                       NULL
      , MustChangePassword   BIT                             NOT NULL
            CONSTRAINT DF_auth_User_MustChangePassword DEFAULT (0)
      , AuthPolicyOverrideJson NVARCHAR (MAX)                    NULL
      , IsDeleted            BIT                             NOT NULL
            CONSTRAINT DF_auth_User_IsDeleted DEFAULT (0)
      , auditDeletedBy       NVARCHAR (255)                      NULL
      , auditDeletedDateUtc  DATETIME2 (3)                       NULL
      , auditCreatedBy       NVARCHAR (255)                  NOT NULL
            CONSTRAINT DF_auth_User_auditCreatedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditCreatedDateUtc  DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_User_auditCreatedDateUtc DEFAULT (SYSUTCDATETIME ())
      , auditModifiedBy      NVARCHAR (255)                  NOT NULL
            CONSTRAINT DF_auth_User_auditModifiedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditModifiedDateUtc DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_User_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ())
      , CONSTRAINT PK_auth_User PRIMARY KEY CLUSTERED (UserId)
      , CONSTRAINT CK_auth_User_UserName
            CHECK (LEN (UserName) > 0 AND UserName = LTRIM (RTRIM (UserName)))
      , CONSTRAINT CK_auth_User_DisplayName
            CHECK (LEN (DisplayName) > 0 AND DisplayName = LTRIM (RTRIM (DisplayName)))
      -- An address with no @ is a typo, and a typo in this column is a password-reset mail nobody receives.  This is
      -- the whole of the validation attempted here: a regular expression for RFC 5322 in a CHECK constraint is a
      -- famous way to refuse valid addresses, and REGEXP_LIKE is SQL Server 2025.
      , CONSTRAINT CK_auth_User_Email
            CHECK (Email IS NULL OR (LEN (Email) >= 3 AND Email LIKE N'%_@_%' AND Email = LTRIM (RTRIM (Email))))
      -- A lockout end with no lockout is a row whose state cannot be read.  See the header: the lock may have no end.
      , CONSTRAINT CK_auth_User_LockoutPair
            CHECK (IsLockedOut = 1 OR LockoutEndUtc IS NULL)
      , CONSTRAINT CK_auth_User_AuthPolicyOverrideJson
            CHECK (AuthPolicyOverrideJson IS NULL OR ISJSON (AuthPolicyOverrideJson) = 1)
      , CONSTRAINT CK_auth_User_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS     NULL AND auditDeletedDateUtc IS     NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL))
    );
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'UX_auth_User_UserName' AND object_id = OBJECT_ID (N'auth.User'))
BEGIN
    CREATE UNIQUE INDEX UX_auth_User_UserName ON auth.[User] (UserName) WHERE IsDeleted = 0;
END
GO

-- NON-unique, deliberately.  See the header: a unique index on email refuses a legitimate new starter and a marriage.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_auth_User_Email' AND object_id = OBJECT_ID (N'auth.User'))
BEGIN
    CREATE INDEX IX_auth_User_Email ON auth.[User] (Email) WHERE IsDeleted = 0;
END
GO

-- Every Platform permission is gated on IsPlatformAdmin = 1 (INV-09) and 950_verify_deployment.sql enumerates the
-- holders, so the filtered index exists to make that enumeration a seek rather than a scan of every person.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_auth_User_PlatformAdmin' AND object_id = OBJECT_ID (N'auth.User'))
BEGIN
    CREATE INDEX IX_auth_User_PlatformAdmin ON auth.[User] (UserName)
        WHERE IsPlatformAdmin = 1 AND IsDeleted = 0;
END
GO


-- *** 2. auth.UserProfile ***
--
-- Section 8.3 and 15.4.  One row per (person, organization they act for).  A user may hold many; exactly one of them is
-- IsDefault = 1, and that is the one activated at sign-in.
--
-- ProfileName is what the profile switcher shows (UI-01).  It defaults to the tenant name in auth.uspCreateProfile --
-- not by a DEFAULT constraint, because the tenant name is not available to one -- and is editable, because a user with
-- two profiles at the same tenant has to be able to tell them apart.
IF OBJECT_ID (N'auth.UserProfile', N'U') IS NULL
BEGIN
    CREATE TABLE auth.UserProfile
    (
        UserProfileId        INT             IDENTITY (1, 1) NOT NULL
      , UserId               INT                             NOT NULL
      , TenantId             INT                             NOT NULL
      , ProfileName          NVARCHAR (256)                  NOT NULL
      , IsDefault            BIT                             NOT NULL
            CONSTRAINT DF_auth_UserProfile_IsDefault DEFAULT (0)
      , IsActive             BIT                             NOT NULL
            CONSTRAINT DF_auth_UserProfile_IsActive DEFAULT (1)
      , IsDeleted            BIT                             NOT NULL
            CONSTRAINT DF_auth_UserProfile_IsDeleted DEFAULT (0)
      , auditDeletedBy       NVARCHAR (255)                      NULL
      , auditDeletedDateUtc  DATETIME2 (3)                       NULL
      , auditCreatedBy       NVARCHAR (255)                  NOT NULL
            CONSTRAINT DF_auth_UserProfile_auditCreatedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditCreatedDateUtc  DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_UserProfile_auditCreatedDateUtc DEFAULT (SYSUTCDATETIME ())
      , auditModifiedBy      NVARCHAR (255)                  NOT NULL
            CONSTRAINT DF_auth_UserProfile_auditModifiedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditModifiedDateUtc DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_UserProfile_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ())
      , CONSTRAINT PK_auth_UserProfile PRIMARY KEY CLUSTERED (UserProfileId)
      -- THE ONE UNFILTERED UNIQUENESS RULE IN THE DATABASE.  See the header: the demo domain's composite foreign key
      -- needs it, a FOREIGN KEY may reference only a PK or a UNIQUE CONSTRAINT, and a constraint cannot be filtered.
      , CONSTRAINT UX_auth_UserProfile_Id_Tenant UNIQUE (UserProfileId, TenantId)
      , CONSTRAINT FK_auth_UserProfile_User
            FOREIGN KEY (UserId)   REFERENCES auth.[User] (UserId)
      -- No ON DELETE action, here or anywhere: there are no hard deletes in this database, so there is nothing to
      -- cascade, and a cascade would be a hard delete arriving through the back door.
      , CONSTRAINT FK_auth_UserProfile_Tenant
            FOREIGN KEY (TenantId) REFERENCES auth.Tenant (TenantId)
      , CONSTRAINT CK_auth_UserProfile_ProfileName
            CHECK (LEN (ProfileName) > 0 AND ProfileName = LTRIM (RTRIM (ProfileName)))
      -- A soft-deleted profile that is still somebody's default would be activated at their next sign-in.  The filtered
      -- index below cannot say this, because it excludes exactly the rows this forbids.
      , CONSTRAINT CK_auth_UserProfile_DeletedIsNotDefault
            CHECK (IsDeleted = 0 OR IsDefault = 0)
      , CONSTRAINT CK_auth_UserProfile_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS     NULL AND auditDeletedDateUtc IS     NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL))
    );
END
GO

-- INV-03.  Exactly one default profile per user -- filtered, because a soft-deleted row must not hold the slot and an
-- inactive one must: deactivating a profile does not silently promote another to default, and a user whose default is
-- inactive is a case auth.uspSetSessionContext refuses with a message rather than a case this index prevents.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'UX_auth_UserProfile_Default' AND object_id = OBJECT_ID (N'auth.UserProfile'))
BEGIN
    CREATE UNIQUE INDEX UX_auth_UserProfile_Default ON auth.UserProfile (UserId)
        WHERE IsDefault = 1 AND IsDeleted = 0;
END
GO

-- Two profiles of one person at one tenant bearing the same name are indistinguishable in the switcher, which is the
-- one place the name is used (UI-01).  This is NOT in section 15.4 -- it is an addition, recorded in BL-036 -- and it
-- is deliberately on the NAME rather than on (UserId, TenantId): a second profile at the same tenant is legitimate,
-- section 8.3 says so explicitly, and it is only the collision of labels that is not.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'UX_auth_UserProfile_UserTenantName' AND object_id = OBJECT_ID (N'auth.UserProfile'))
BEGIN
    CREATE UNIQUE INDEX UX_auth_UserProfile_UserTenantName
        ON auth.UserProfile (UserId, TenantId, ProfileName) WHERE IsDeleted = 0;
END
GO

-- "Which profiles does this person hold", which is the profile switcher's only query and runs on every sign-in.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_auth_UserProfile_User' AND object_id = OBJECT_ID (N'auth.UserProfile'))
BEGIN
    CREATE INDEX IX_auth_UserProfile_User ON auth.UserProfile (UserId)
        INCLUDE (TenantId, ProfileName, IsDefault, IsActive) WHERE IsDeleted = 0;
END
GO

-- "Who acts for this organization", which is the administrative direction, and the seek
-- auth.uspRebuildProfilePermissionScope uses when a tenant is deactivated.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_auth_UserProfile_Tenant' AND object_id = OBJECT_ID (N'auth.UserProfile'))
BEGIN
    CREATE INDEX IX_auth_UserProfile_Tenant ON auth.UserProfile (TenantId)
        INCLUDE (UserId, IsActive) WHERE IsDeleted = 0;
END
GO


-- *** 3. Audit triggers ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.trg_au_updt_User
Author:       rsincero
CreateDate:   2026-09-19
Description:
AFTER UPDATE audit stamp for auth.User, and the guard that makes UserName immutable -- E-50010.

UserName is immutable because it is the sign-in name AND the natural key: auth.LoginAttempt records it as a string
rather than only as a UserId, precisely so that attempts against accounts that do not exist are still recorded
(section 15.3).  Renaming a user therefore rewrites the meaning of every historical attempt row bearing the old name,
and silently reattributes the new name's history to this person.  A rename is a soft delete and a new row.

DisplayName and Email are NOT immutable.  People marry and change what they are called; that is the ordinary case this
table exists to serve, and neither column is a key.

Modification History:
2026-09-19  rsincero  Created.  PLAN-AUTH-001 T-025.
***********************************************************************************************************************/
CREATE OR ALTER TRIGGER auth.trg_au_updt_User
    ON auth.[User]
    AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    IF UPDATE (UserName)
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.UserId = i.UserId
                    WHERE i.UserName <> d.UserName)
    BEGIN
        ;THROW 50010, N'auth.User.UserName is immutable: auth.LoginAttempt records it as a string, so a rename rewrites the meaning of every historical attempt. Soft-delete the user and create the new name.', 1;
    END;

    DECLARE @Now   DATETIME2 (3)  = SYSUTCDATETIME ()
          , @Actor NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                            , ORIGINAL_LOGIN ());

    UPDATE u
       SET u.auditModifiedDateUtc = @Now
         , u.auditModifiedBy      = CASE WHEN UPDATE (auditModifiedBy)
                                         THEN COALESCE (NULLIF (i.auditModifiedBy, N''), @Actor)
                                         ELSE @Actor END
         , u.auditDeletedBy       = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Actor ELSE u.auditDeletedBy      END
         , u.auditDeletedDateUtc  = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Now   ELSE u.auditDeletedDateUtc END
      FROM auth.[User] AS u
      JOIN inserted  AS i ON i.UserId = u.UserId
      JOIN deleted   AS d ON d.UserId = u.UserId;
END;
GO

/***********************************************************************************************************************
ObjectName:   auth.trg_au_updt_UserProfile
Author:       rsincero
CreateDate:   2026-09-20
Description:
AFTER UPDATE audit stamp for auth.UserProfile, and the guard that makes UserId and TenantId immutable -- E-50010.

BOTH COLUMNS ARE IMMUTABLE FOR THE SAME REASON AND IT IS NOT TIDINESS.  dbo.CaseFile and dbo.CaseNote carry
FOREIGN KEY (AssignedToProfileId, TenantId) REFERENCES auth.UserProfile (UserProfileId, TenantId).  Re-pointing a
profile at another tenant would leave every record it is named on referencing a pair that no longer exists -- which the
foreign key would refuse, noisily, on the UPDATE to this table, naming a table the administrator was not touching.  Far
worse is the case where the profile has no records yet: the update succeeds, and every grant in
auth.UserProfileRole scoped at the old tenant is now held by somebody at the new one.  A silent cross-tenant
escalation.

Re-pointing a profile at another PERSON is the same class of mistake with a shorter path to the same place: every row
auth.ProfilePermissionScope holds for it, and every record it is assigned, transfers to the new person with no trail.

The correct act in both cases is to deactivate this profile and create the right one, which leaves the history saying
what happened.  ProfileName and IsDefault are freely editable, because they are labels.

Modification History:
2026-09-20  rsincero  Created.  PLAN-AUTH-001 T-046.
***********************************************************************************************************************/
CREATE OR ALTER TRIGGER auth.trg_au_updt_UserProfile
    ON auth.UserProfile
    AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    IF (UPDATE (UserId) OR UPDATE (TenantId))
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.UserProfileId = i.UserProfileId
                    WHERE i.UserId <> d.UserId
                       OR i.TenantId <> d.TenantId)
    BEGIN
        ;THROW 50010, N'auth.UserProfile.UserId and TenantId are immutable: the demo domain references (UserProfileId, TenantId) as a pair, and re-pointing either column transfers every role grant the profile holds to a different person or a different organization with no trail. Deactivate this profile and create the correct one.', 1;
    END;

    DECLARE @Now   DATETIME2 (3)  = SYSUTCDATETIME ()
          , @Actor NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                            , ORIGINAL_LOGIN ());

    UPDATE p
       SET p.auditModifiedDateUtc = @Now
         , p.auditModifiedBy      = CASE WHEN UPDATE (auditModifiedBy)
                                         THEN COALESCE (NULLIF (i.auditModifiedBy, N''), @Actor)
                                         ELSE @Actor END
         , p.auditDeletedBy       = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Actor ELSE p.auditDeletedBy      END
         , p.auditDeletedDateUtc  = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Now   ELSE p.auditDeletedDateUtc END
      FROM auth.UserProfile AS p
      JOIN inserted         AS i ON i.UserProfileId = p.UserProfileId
      JOIN deleted          AS d ON d.UserProfileId = p.UserProfileId;
END;
GO


-- *** 4. Descriptions ***
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
      (N'auth', N'TABLE', N'User', NULL, N'The person. One row per human being, however many organizations they act for. NOT tenant-scoped and must never become so -- section 6.1: everything organizational hangs off auth.UserProfile, and a column added here for convenience would be authority that auth.vwProfilePermission cannot see. Carries no password: the verifier lives in auth.UserCredential.')
    , (N'auth', N'TABLE', N'User', N'UserId',                 N'Surrogate key. Referenced by every credential, session, profile and attempt row.')
    , (N'auth', N'TABLE', N'User', N'UserName',              N'The sign-in name, and the natural key. Unique where IsDeleted = 0. IMMUTABLE -- auth.LoginAttempt records it as a string so unknown-account attempts are still recorded, which means a rename rewrites history. A rename is a soft delete and a new row.')
    , (N'auth', N'TABLE', N'User', N'DisplayName',            N'What the person is called on screen. Not a key and not immutable: people change what they are called.')
    , (N'auth', N'TABLE', N'User', N'Email',                  N'Contact address. NON-UNIQUE INDEX ONLY, deliberately: addresses are reassigned when people leave and changed when people marry, and a unique index here would refuse both. Never a join key for federated identity -- INV-07.')
    , (N'auth', N'TABLE', N'User', N'IsActive',               N'0 suspends the person everywhere, immediately, across every profile they hold -- section 6.3. Deactivating one profile is the narrower act and lives on auth.UserProfile.')
    , (N'auth', N'TABLE', N'User', N'IsPlatformAdmin',        N'1 permits the platform-administrator bypass route (E-50108 otherwise) and is required for any Platform permission to take effect -- INV-09. 950_verify_deployment.sql enumerates every holder.')
    , (N'auth', N'TABLE', N'User', N'IsLockedOut',            N'The lockout flag, set by auth.uspRecordLoginFailure when the per-account threshold is reached and cleared lazily by auth.uspCompleteLogin. Effective lock is IsLockedOut = 1 AND (LockoutEndUtc IS NULL OR LockoutEndUtc > now) -- the single copy of that expression is auth.udfIsUserUsable.')
    , (N'auth', N'TABLE', N'User', N'LockoutEndUtc',          N'When the lock lapses, UTC. NULL means never: an administrative lock held until somebody clears it. Nothing clears a lapsed lock on a schedule, on purpose -- the trail is more useful with it left in place.')
    , (N'auth', N'TABLE', N'User', N'MustChangePassword',     N'1 forces a password change at the next successful local sign-in. Read by the application after auth.uspCompleteLogin returns.')
    , (N'auth', N'TABLE', N'User', N'AuthPolicyOverrideJson', N'Per-user exceptions to the resolved tenant policy -- section 7.2: the contractor with no directory account, the administrator who needs local access to a tenant that forbids it. NVARCHAR (MAX) with an ISJSON check, NOT the native json type, which is SQL Server 2025.')

    , (N'auth', N'TABLE', N'UserProfile', NULL, N'One hat: a person acting for one organization. The pivot of the whole authorization model -- every role grant, every scope and every effective permission hangs off a profile, never off a user, which is what lets one person hold different authority at two organizations without two accounts (section 8.3). Deactivating a profile removes one hat; deactivating the user stops them signing in at all (section 8.5).')
    , (N'auth', N'TABLE', N'UserProfile', N'UserProfileId', N'Surrogate key, and half of the pair the demo domain references. Recorded in SESSION_CONTEXT as UserProfileId and read by auth.udfTenantReadPredicate on every row of every protected query, which is why it is an INT and not a GUID.')
    , (N'auth', N'TABLE', N'UserProfile', N'UserId',        N'The person. IMMUTABLE -- E-50010: re-pointing a profile at somebody else transfers every grant and every assigned record with no trail.')
    , (N'auth', N'TABLE', N'UserProfile', N'TenantId',      N'The organization this hat is worn for, and the default scope of every role granted to it (section 8.4). IMMUTABLE -- E-50010, and additionally the second column of UX_auth_UserProfile_Id_Tenant, which the demo domain''s composite foreign key references so that a record cannot be assigned to a profile at another tenant.')
    , (N'auth', N'TABLE', N'UserProfile', N'ProfileName',   N'What the profile switcher shows -- UI-01. Defaults to the tenant name in auth.uspCreateProfile and is editable, because a user with two profiles at the same tenant has to be able to tell them apart. Unique per (UserId, TenantId) among live rows, which is an addition to section 15.4 recorded in BL-036: two identically named profiles at one tenant are indistinguishable in the one place the name is used.')
    , (N'auth', N'TABLE', N'UserProfile', N'IsDefault',     N'1 marks the profile activated at sign-in. Exactly one per user, enforced by UX_auth_UserProfile_Default filtered on IsDefault = 1 AND IsDeleted = 0 -- INV-03. A soft-deleted row may not be a default at all (CK_auth_UserProfile_DeletedIsNotDefault), because the filtered index excludes precisely the rows that would break the rule.')
    , (N'auth', N'TABLE', N'UserProfile', N'IsActive',      N'0 removes this one hat: the person still signs in and still uses their other profiles -- section 8.5. auth.uspSetSessionContext refuses an inactive profile with E-50021, and auth.uspRebuildProfilePermissionScope drops every row it holds, so an inactive profile has no effective authority anywhere.');

    -- The seven audit columns carry the same description on every table, so they are generated rather than typed out.
    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    SELECT N'auth', N'TABLE', t.TableName, c.ColumnName, c.Description
      FROM (VALUES (N'User'), (N'UserProfile')) AS t (TableName)
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
    VALUES (N'auth', N'TRIGGER', N'trg_au_updt_User', NULL, N'AFTER UPDATE audit stamp for auth.User, and the guard that makes UserName immutable -- E-50010.')
         , (N'auth', N'TRIGGER', N'trg_au_updt_UserProfile', NULL, N'AFTER UPDATE audit stamp for auth.UserProfile, and the guard that makes UserId and TenantId immutable -- E-50010.');

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


-- *** 5. Grants ***
--
-- DELIBERATELY EMPTY.  INV-11: applicationRole holds NO table-level permission on SCHEMA::auth.  auth.User is the
-- table that rule exists for -- a SELECT grant here would hand a compromised application login the whole staff list,
-- every platform administrator by name, and every locked account.  It reads this table only through ownership chaining
-- inside auth.uspGetLoginVerifier and auth.uspCompleteLogin.  170_permissions.sql grants EXECUTE on those and nothing
-- here, and makes the absence explicit with a schema-level DENY so the catalog shows the decision rather than a gap.
GO


-- *** 6. Closing report ***
DECLARE @Report TABLE
(
    RowNo    INT IDENTITY (1, 1) PRIMARY KEY,
    Severity INT             NOT NULL,
    Status   VARCHAR (10)    NOT NULL,
    Item     NVARCHAR (200)  NOT NULL,
    Detail   NVARCHAR (1000)     NULL
);

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (N'auth.User', N'U') IS NULL THEN 1 ELSE 4 END
     , CASE WHEN OBJECT_ID (N'auth.User', N'U') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Table auth.User'
     , N'The person. Not tenant-scoped -- section 6.1.';

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN i.name IS NULL THEN 2 ELSE 4 END
     , CASE WHEN i.name IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Index ' + x.IndexName
     , x.Purpose
  FROM (VALUES (N'UX_auth_User_UserName',      N'UNIQUE where IsDeleted = 0. UserName is the natural key.')
             , (N'IX_auth_User_Email',         N'NON-UNIQUE, deliberately: a unique index on email refuses a new starter who inherited an address, and refuses a marriage.')
             , (N'IX_auth_User_PlatformAdmin', N'Filtered on IsPlatformAdmin = 1, so enumerating the holders is a seek -- INV-09.'))
       AS x (IndexName, Purpose)
  LEFT JOIN sys.indexes AS i ON i.name = x.IndexName AND i.object_id = OBJECT_ID (N'auth.User');

-- The unique index on email must NOT exist.  This is the only check in the deployment that asserts the ABSENCE of a
-- constraint, and it is here because the constraint is the one a well-meaning reviewer adds.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN EXISTS (SELECT 1
                           FROM sys.indexes      AS i
                           JOIN sys.index_columns AS ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
                           JOIN sys.columns      AS c  ON c.object_id = ic.object_id AND c.column_id = ic.column_id
                          WHERE i.object_id = OBJECT_ID (N'auth.User')
                            AND i.is_unique = 1
                            AND c.name = N'Email')
            THEN 1 ELSE 4 END
     , CASE WHEN EXISTS (SELECT 1
                           FROM sys.indexes      AS i
                           JOIN sys.index_columns AS ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
                           JOIN sys.columns      AS c  ON c.object_id = ic.object_id AND c.column_id = ic.column_id
                          WHERE i.object_id = OBJECT_ID (N'auth.User')
                            AND i.is_unique = 1
                            AND c.name = N'Email')
            THEN 'VIOLATION' ELSE 'OK' END
     , N'auth.User.Email carries no UNIQUE index'
     , N'A unique index on Email refuses a legitimate new starter who inherited a predecessor''s address and refuses '
     + N'somebody who marries, and the workaround for both is an edit to another person''s row. Email is never an '
     + N'identity key here -- INV-07.';

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (N'auth.trg_au_updt_User', N'TR') IS NULL THEN 2 ELSE 4 END
     , CASE WHEN OBJECT_ID (N'auth.trg_au_updt_User', N'TR') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Trigger auth.trg_au_updt_User'
     , N'AFTER UPDATE audit stamp, and the guard that makes UserName immutable -- E-50010.';

-- The other half of this file.  T-046.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (N'auth.UserProfile', N'U') IS NULL THEN 1 ELSE 4 END
     , CASE WHEN OBJECT_ID (N'auth.UserProfile', N'U') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Table auth.UserProfile'
     , N'One hat: a person acting for one organization. The pivot of the authorization model -- section 8.3. Its '
     + N'presence is also what stops the runner skipping 090_dbo_application.sql.';

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN i.name IS NULL THEN 2 ELSE 4 END
     , CASE WHEN i.name IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Index ' + x.IndexName
     , x.Purpose
  FROM (VALUES (N'UX_auth_UserProfile_Default',        N'UNIQUE on (UserId) WHERE IsDefault = 1 AND IsDeleted = 0 -- INV-03, exactly one default profile per person.')
             , (N'UX_auth_UserProfile_UserTenantName', N'UNIQUE on (UserId, TenantId, ProfileName) where live. An addition to section 15.4 -- BL-036: two identically named profiles at one tenant are indistinguishable in the switcher.')
             , (N'IX_auth_UserProfile_User',           N'The profile switcher''s only query, run on every sign-in.')
             , (N'IX_auth_UserProfile_Tenant',         N'The administrative direction: who acts for this organization.'))
       AS x (IndexName, Purpose)
  LEFT JOIN sys.indexes AS i ON i.name = x.IndexName AND i.object_id = OBJECT_ID (N'auth.UserProfile');

-- The unfiltered UNIQUE CONSTRAINT, asserted by name and by shape.  It is the one uniqueness rule in the database that
-- is not a filtered index, the demo domain's composite foreign key cannot be created without it, and a well-meaning
-- reviewer converting it to the house style would break 090_dbo_application.sql two scripts later with an error that
-- names neither this table nor this line.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Present = 1 THEN 4 ELSE 1 END
     , CASE WHEN x.Present = 1 THEN 'OK' ELSE 'MISSING' END
     , N'Constraint UX_auth_UserProfile_Id_Tenant'
     , N'UNIQUE (UserProfileId, TenantId), deliberately NOT filtered. dbo.CaseFile and dbo.CaseNote reference the pair '
     + N'so a record cannot be assigned to a profile at another tenant, a FOREIGN KEY may reference only a PK or a '
     + N'UNIQUE CONSTRAINT, and a constraint cannot be filtered. Do not convert it to a filtered unique index.'
  FROM (SELECT Present = CASE WHEN EXISTS (SELECT 1
                                             FROM sys.key_constraints
                                            WHERE name = N'UX_auth_UserProfile_Id_Tenant'
                                              AND parent_object_id = OBJECT_ID (N'auth.UserProfile')
                                              AND type = 'UQ')
                              THEN 1 ELSE 0 END) AS x;

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (N'auth.trg_au_updt_UserProfile', N'TR') IS NULL THEN 2 ELSE 4 END
     , CASE WHEN OBJECT_ID (N'auth.trg_au_updt_UserProfile', N'TR') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Trigger auth.trg_au_updt_UserProfile'
     , N'AFTER UPDATE audit stamp, and the guard that makes UserId and TenantId immutable -- E-50010.';

-- auth.UserProfile is tenant-scoped and is NOT registered in config.TenantScopedTable, which is the opposite of the
-- rule section 10.1 states for tenant-scoped tables.  Said out loud here because the alternative is a reader noticing
-- the omission and fixing it.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN EXISTS (SELECT 1 FROM config.TenantScopedTable
                          WHERE SchemaName = N'auth' AND TableName = N'UserProfile' AND IsDeleted = 0)
            THEN 1 ELSE 4 END
     , CASE WHEN EXISTS (SELECT 1 FROM config.TenantScopedTable
                          WHERE SchemaName = N'auth' AND TableName = N'UserProfile' AND IsDeleted = 0)
            THEN 'VIOLATION' ELSE 'OK' END
     , N'auth.UserProfile is NOT registered for row-level security'
     , N'Correct, and it must stay that way. auth.udfTenantReadPredicate resolves the acting profile by reading '
     + N'SESSION_CONTEXT, and auth.uspSetSessionContext has to read THIS TABLE to set that context -- so a policy here '
     + N'would make every sign-in depend on a predicate that cannot yet be evaluated. Row security in this design '
     + N'protects dbo only; the auth schema is reached exclusively through ownership chaining inside procedures '
     + N'(INV-11), which is what makes that safe. 120_rls_policy.sql says the same thing from the other side.';

INSERT @Report (Severity, Status, Item, Detail)
SELECT 3, 'INFO', N'Users'
     , CASE WHEN COUNT (*) = 0
            THEN N'None. Expected: this script seeds nobody. 900_bootstrap_first_admin.sql creates the first '
               + N'administrator, by hand, once, and database/_tests/040_identity_and_authn.sql creates throwaway '
               + N'fixtures for a development database.'
            ELSE CAST (COUNT (*) AS NVARCHAR (10)) + N' live user(s), of whom '
               + CAST (SUM (CASE WHEN IsPlatformAdmin = 1 THEN 1 ELSE 0 END) AS NVARCHAR (10))
               + N' platform administrator(s) and '
               + CAST (SUM (CASE WHEN IsLockedOut = 1 THEN 1 ELSE 0 END) AS NVARCHAR (10)) + N' locked out.'
       END
  FROM auth.[User]
 WHERE IsDeleted = 0;

INSERT @Report (Severity, Status, Item, Detail)
SELECT 3, 'INFO', N'Profiles'
     , CASE WHEN COUNT (*) = 0
            THEN N'None. Expected: this script seeds nobody. 900_bootstrap_first_admin.sql creates the first '
               + N'administrator''s profile, by hand, once.'
            ELSE CAST (COUNT (*) AS NVARCHAR (10)) + N' live profile(s) across '
               + CAST (COUNT (DISTINCT TenantId) AS NVARCHAR (10)) + N' tenant(s) for '
               + CAST (COUNT (DISTINCT UserId) AS NVARCHAR (10)) + N' person(s), of which '
               + CAST (SUM (CASE WHEN IsActive = 0 THEN 1 ELSE 0 END) AS NVARCHAR (10)) + N' inactive.'
       END
  FROM auth.UserProfile
 WHERE IsDeleted = 0;

-- A person with no default profile signs in and lands nowhere.  INV-03 makes at most one possible; nothing makes one
-- exist, because auth.uspCreateProfile sets it on the first profile and there is no constraint that can span rows.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Orphans = 0 THEN 4 ELSE 2 END
     , CASE WHEN x.Orphans = 0 THEN 'OK' ELSE 'REVIEW' END
     , N'Every person with a profile has a default one'
     , CASE WHEN x.Orphans = 0
            THEN N'Yes, or nobody has a profile yet.'
            ELSE CAST (x.Orphans AS NVARCHAR (10)) + N' person(s) hold profiles and none of them is IsDefault = 1. They '
               + N'will authenticate and reach a screen with no active profile -- UI-09. INV-03 makes more than one '
               + N'default impossible and cannot make one exist; auth.uspCreateProfile sets it on the first profile.'
       END
  FROM (SELECT Orphans = COUNT (*)
          FROM (SELECT p.UserId
                  FROM auth.UserProfile AS p
                 WHERE p.IsDeleted = 0
                 GROUP BY p.UserId
                HAVING SUM (CASE WHEN p.IsDefault = 1 THEN 1 ELSE 0 END) = 0) AS u) AS x;

INSERT @Report (Severity, Status, Item, Detail)
VALUES (3, 'NEXT', N'Next scripts'
      , N'045_auth_identity.sql (credentials, federated identities, MFA, login attempts), then 050_auth_permission.sql, '
      + N'055_auth_role.sql, 060_auth_profile_role.sql and 065_auth_effective_permission.sql -- the authorization '
      + N'tables this one is the pivot of.');

IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
    PRINT N'auth.User: PROBLEMS found. Read the report below before running the next script.';
ELSE
    PRINT N'auth.User: no problems found.';

PRINT N'';

SELECT Severity, Status, Item, Detail
  FROM @Report
 ORDER BY Severity, RowNo;
GO
