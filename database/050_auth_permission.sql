/***********************************************************************************************************************
Script:         050_auth_permission.sql
Purpose:        auth.PermissionCategory and auth.Permission -- the vocabulary every authorization decision is expressed
                in.  The 35 rows themselves are seeded by 115_seed_reference_data.sql, NOT here; see section 3.
Target:         SQL Server 2022.
Run as:         db_owner in the target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/050_auth_permission.sql
Idempotent:     Yes.  Guarded CREATE TABLE and CREATE INDEX, CREATE OR ALTER triggers, and no seed data at all.
Depends on:     database/005_schemas_and_roles.sql (schema auth), database/030_auth_tenant.sql (auth.Application),
                templates/extended-properties.sql (util.uspSetObjectDescription).
Implements:     DES-AUTH-001 sections 8.1, 15.4 and Appendix A.  PLAN-AUTH-001 task T-043.
To retarget:    Pass it per run:  sqlcmd -d <database> -v DbName=<database>.  There is no in-file default.

PERMISSIONS ARE CODE, NOT CONFIGURATION, AND THE TABLE IS WHERE THAT STOPS BEING A SLOGAN
----------------------------------------------------------------------------------------
Section 16.1 item 3.  A permission code appears as a literal in stored-procedure bodies, as a literal in
120_rls_policy.sql, and as a literal in the .NET layer's screen wiring.  Adding a row here without adding the code that
demands it produces a permission nobody can exercise; deleting a row that procedures still name produces E-50031 at run
time on a screen that used to work.

So there is no administrative screen for this table and there must never be one.  auth.Role is the administrator's
vocabulary; auth.Permission is the developer's, and 115_seed_reference_data.sql is the only thing that writes it.

THE CATEGORY IS NOT SCOPED TO AN APPLICATION AND THE PERMISSION IS
-----------------------------------------------------------------
Seven families -- Data, User, Authz, Tenant, Config, Audit, Platform -- and they mean the same thing in every
application variant, so auth.PermissionCategory has no ApplicationId.  auth.Permission does, because D-09 makes the
application the outermost scope: a permission defined for one variant is not assignable in another, and two variants may
legitimately carry different subsets of the catalogue.

The consequence is one that caught this design during implementation and is worth stating where it will be read.  A
database serving FOUR applications holds FOUR rows whose PermissionCode is 'Data.Read', with four different
PermissionIds -- and section 10.2's row-level security predicate resolves 'Data.Read' to a LITERAL at deploy time.  A
single literal would protect one application and silently fail open for the other three.  120_rls_policy.sql therefore
substitutes the whole SET of matching ids as an IN list and asserts the list still matches on every deployment.  BL-039.

THE CODE CARRIES ITS OWN FAMILY, AND A CHECK CONSTRAINT MAKES THEM AGREE
-----------------------------------------------------------------------
PermissionCode is '<Family>.<Verb>' (Appendix C) and PermissionCategoryCode is denormalised onto this table so that
CK_auth_Permission_CodeMatchesCategory can be row-local.  Without it, 'Data.Read' could be filed under Audit -- which no
constraint would notice, which auth.vwProfilePermission would display, and which the role seed in 115 relies on: the
baseline roles USER_ADMIN, TENANT_ADMIN, AUDITOR, CONFIG_ADMIN and PLATFORM_ADMIN are defined as "the whole family" and
are seeded by joining on the category rather than by listing codes.  A misfiled permission silently changes what five
baseline roles mean.

This is the same arrangement, for the same reason, as auth.Tenant's denormalised TenantTypeCode: an unfiltered UNIQUE
constraint on (PermissionCategoryId, CategoryCode) for the composite foreign key to reference, because a FOREIGN KEY
cannot reference a filtered index.  BL-021's note in 030_auth_tenant.sql explains the pattern once; this is its second
use.

IsTenantScoped = 0 IS NOT A SYNONYM FOR "GRANTED TO EVERYBODY"
-------------------------------------------------------------
It means the permission is evaluated WITHOUT a tenant: auth.udfHasPermission ignores its @TenantId argument for such a
permission and looks only for a scope row.  The three Platform permissions are the whole of the set, and INV-09 adds a
second, independent condition to them -- auth.User.IsPlatformAdmin = 1 -- which is deliberately NOT expressed in this
table.  A grant of Platform.BypassRowSecurity to a profile whose user is not a platform administrator is a legal row
that confers nothing, and that is the intended behaviour: revoking the flag revokes the authority without unpicking
every grant.

CK_auth_Permission_PlatformIsNotTenantScoped enforces one direction only -- nothing in the Platform family may be
tenant-scoped.  The reverse is left open on purpose: a project that adds a family evaluated without a tenant should not
have to alter a constraint in the template to do it.
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

IF OBJECT_ID (N'auth.Application', N'U') IS NULL
BEGIN
    DECLARE @MsgApp NVARCHAR (2000) =
        N'auth.Application does not exist. auth.Permission has a foreign key to it -- D-09 makes the application the '
      + N'outermost scope. Run database/030_auth_tenant.sql first. Nothing has been changed.';

    THROW 50000, @MsgApp, 1;
END
GO


-- *** 1. auth.PermissionCategory ***
--
-- The seven families of section 8.1.  Descriptive groupings for the role editor and for the five baseline roles that are
-- defined as "the whole family" -- but ALSO structural, because auth.Permission's code has to agree with its category.
IF OBJECT_ID (N'auth.PermissionCategory', N'U') IS NULL
BEGIN
    CREATE TABLE auth.PermissionCategory
    (
        PermissionCategoryId INT             IDENTITY (1, 1) NOT NULL
      , CategoryCode         NVARCHAR (50)                   NOT NULL
      , CategoryName         NVARCHAR (100)                  NOT NULL

        -- Display order for the role editor.  The seven seeded families are spaced by ten so a project can insert its
        -- own between them without renumbering -- the same convention auth.TenantType uses.
      , SortOrder            INT                             NOT NULL
            CONSTRAINT DF_auth_PermissionCategory_SortOrder DEFAULT (0)

      , IsDeleted            BIT                             NOT NULL
            CONSTRAINT DF_auth_PermissionCategory_IsDeleted DEFAULT (0)
      , auditDeletedBy       NVARCHAR (255)                      NULL
      , auditDeletedDateUtc  DATETIME2 (3)                       NULL
      , auditCreatedBy       NVARCHAR (255)                  NOT NULL
            CONSTRAINT DF_auth_PermissionCategory_auditCreatedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditCreatedDateUtc  DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_PermissionCategory_auditCreatedDateUtc DEFAULT (SYSUTCDATETIME ())
      , auditModifiedBy      NVARCHAR (255)                  NOT NULL
            CONSTRAINT DF_auth_PermissionCategory_auditModifiedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditModifiedDateUtc DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_PermissionCategory_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ())

      , CONSTRAINT PK_auth_PermissionCategory PRIMARY KEY CLUSTERED (PermissionCategoryId)

        -- UNFILTERED, and that is the point of it: auth.Permission carries CategoryCode denormalised so that
        -- CK_auth_Permission_CodeMatchesCategory can be row-local, and a FOREIGN KEY cannot reference a filtered index.
        -- Safe because the pair contains the primary key, so it adds no constraint the primary key does not impose.
        -- Identical in shape and reason to UX_auth_TenantType_Id_Code.
      , CONSTRAINT UX_auth_PermissionCategory_Id_Code UNIQUE (PermissionCategoryId, CategoryCode)

        -- PascalCase with no dot: the dot is the separator in a permission code, and a family whose own code contained
        -- one would make CK_auth_Permission_CodeMatchesCategory accept 'Data.Read.Extra' as a member of 'Data.Read'.
      , CONSTRAINT CK_auth_PermissionCategory_CategoryCode
            CHECK (LEN (CategoryCode) > 0
                   AND CategoryCode = LTRIM (RTRIM (CategoryCode))
                   AND CHARINDEX (N'.', CategoryCode) = 0)

      , CONSTRAINT CK_auth_PermissionCategory_CategoryName
            CHECK (LEN (CategoryName) > 0 AND CategoryName = LTRIM (RTRIM (CategoryName)))

      , CONSTRAINT CK_auth_PermissionCategory_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS     NULL AND auditDeletedDateUtc IS     NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL))
    );
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'UX_auth_PermissionCategory_Code'
                  AND object_id = OBJECT_ID (N'auth.PermissionCategory'))
BEGIN
    CREATE UNIQUE INDEX UX_auth_PermissionCategory_Code
        ON auth.PermissionCategory (CategoryCode) WHERE IsDeleted = 0;
END
GO


-- *** 2. auth.Permission ***
--
-- One row per (application, permission code).  Appendix A is the catalogue; 115_seed_reference_data.sql writes it.
IF OBJECT_ID (N'auth.Permission', N'U') IS NULL
BEGIN
    CREATE TABLE auth.Permission
    (
        PermissionId          INT             IDENTITY (1, 1) NOT NULL
      , ApplicationId         INT                             NOT NULL
      , PermissionCategoryId  INT                             NOT NULL

        -- Denormalised from auth.PermissionCategory so the code/category agreement can be checked row-locally.  Kept
        -- honest by FK_auth_Permission_PermissionCategory, which references the pair.
      , PermissionCategoryCode NVARCHAR (50)                  NOT NULL

      , PermissionCode        NVARCHAR (100)                  NOT NULL
      , PermissionName        NVARCHAR (200)                  NOT NULL

        -- Appendix A's "Meaning" column.  An addition to section 15.4 -- BL-037 -- because the role editor has to show
        -- an administrator what 'Data.Reassign' means, and the alternative is 35 strings hard-coded in the UI project
        -- where nobody maintaining this catalogue would ever see them.
      , PermissionDescription NVARCHAR (1000)                     NULL

      , IsTenantScoped        BIT                             NOT NULL
            CONSTRAINT DF_auth_Permission_IsTenantScoped DEFAULT (1)

      , IsDeleted             BIT                             NOT NULL
            CONSTRAINT DF_auth_Permission_IsDeleted DEFAULT (0)
      , auditDeletedBy        NVARCHAR (255)                      NULL
      , auditDeletedDateUtc   DATETIME2 (3)                       NULL
      , auditCreatedBy        NVARCHAR (255)                  NOT NULL
            CONSTRAINT DF_auth_Permission_auditCreatedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditCreatedDateUtc   DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_Permission_auditCreatedDateUtc DEFAULT (SYSUTCDATETIME ())
      , auditModifiedBy       NVARCHAR (255)                  NOT NULL
            CONSTRAINT DF_auth_Permission_auditModifiedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditModifiedDateUtc  DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_Permission_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ())

      , CONSTRAINT PK_auth_Permission PRIMARY KEY CLUSTERED (PermissionId)

        -- UNFILTERED, contains the primary key, and therefore imposes nothing the primary key does not.  It exists to be
        -- referenced: auth.RolePermission in 055_auth_role.sql carries ApplicationId and pins it to BOTH its role and
        -- its permission, which is what makes "application 3's permission granted to application 2's role" impossible
        -- rather than merely unlikely.  Third use of the pattern -- UX_auth_TenantType_Id_Code, then
        -- UX_auth_UserProfile_Id_Tenant, then this.
      , CONSTRAINT UX_auth_Permission_Id_Application UNIQUE (PermissionId, ApplicationId)

      , CONSTRAINT FK_auth_Permission_Application
            FOREIGN KEY (ApplicationId) REFERENCES auth.Application (ApplicationId)

        -- The composite reference is what makes the denormalised code trustworthy.  No ON DELETE action of any kind:
        -- there is no delete path in this database.
      , CONSTRAINT FK_auth_Permission_PermissionCategory
            FOREIGN KEY (PermissionCategoryId, PermissionCategoryCode)
            REFERENCES auth.PermissionCategory (PermissionCategoryId, CategoryCode)

        -- '<Family>.<Verb>', exactly one dot, and the family half IS this row's category.  Written with CHARINDEX and
        -- LEN rather than a pattern because SQL Server 2022 has no regular expressions -- REGEXP_LIKE is 2025 and the
        -- ceiling of this design is 2022.
      , CONSTRAINT CK_auth_Permission_CodeMatchesCategory
            CHECK (PermissionCode = LTRIM (RTRIM (PermissionCode))
                   AND LEN (PermissionCode) > LEN (PermissionCategoryCode) + 1
                   AND LEFT (PermissionCode, LEN (PermissionCategoryCode) + 1)
                       = PermissionCategoryCode + N'.'
                   AND CHARINDEX (N'.', PermissionCode, LEN (PermissionCategoryCode) + 2) = 0)

      , CONSTRAINT CK_auth_Permission_PermissionName
            CHECK (LEN (PermissionName) > 0 AND PermissionName = LTRIM (RTRIM (PermissionName)))

        -- One direction only; see the header.  A Platform permission is evaluated without a tenant, so a tenant-scoped
        -- one would be a row auth.udfHasPermission cannot answer consistently.
      , CONSTRAINT CK_auth_Permission_PlatformIsNotTenantScoped
            CHECK (PermissionCategoryCode <> N'Platform' OR IsTenantScoped = 0)

      , CONSTRAINT CK_auth_Permission_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS     NULL AND auditDeletedDateUtc IS     NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL))
    );
END
GO

-- The natural key.  Section 15.4: unique on (ApplicationId, PermissionCode) filtered, so a withdrawn permission code
-- can be reissued -- which for a catalogue that is code rather than configuration means a renamed feature can reclaim
-- its old name after the procedures naming the old one are gone.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'UX_auth_Permission_Code' AND object_id = OBJECT_ID (N'auth.Permission'))
BEGIN
    CREATE UNIQUE INDEX UX_auth_Permission_Code
        ON auth.Permission (ApplicationId, PermissionCode) WHERE IsDeleted = 0;
END
GO

-- "Every permission in the User family", which is how five of the sixteen baseline roles are seeded and how the role
-- editor groups its checkboxes.  INCLUDE carries what both readers need so neither touches the table.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_auth_Permission_Category' AND object_id = OBJECT_ID (N'auth.Permission'))
BEGIN
    CREATE INDEX IX_auth_Permission_Category
        ON auth.Permission (PermissionCategoryId, ApplicationId)
        INCLUDE (PermissionCode, PermissionName, IsTenantScoped) WHERE IsDeleted = 0;
END
GO


/***********************************************************************************************************************
    3. THE 35 ROWS ARE NOT IN THIS FILE

    Section 16.1 item 3 puts the catalogue in 115_seed_reference_data.sql and it stays there, unlike auth.TenantType,
    which BL-021 moved forward into 030_auth_tenant.sql.  The difference is what the seed is FOR:

      *  auth.TenantType had to move because auth.Tenant's composite foreign key makes the 'Root' row a structural
         prerequisite -- Phase 1 could not create a single tenant without it.
      *  Nothing structural needs a permission row.  Tables reference auth.Permission by surrogate key and the first
         reader of an actual row is 120_rls_policy.sql, which runs five scripts after 115.

    So this file creates empty tables, on purpose, and the report below says so rather than letting a reader conclude
    the seed failed.  The one thing that DOES depend on the rows existing is stated where it can be acted on: the
    permission-id literals in 120_rls_policy.sql, which is why the install order is 050 -> 115 -> 120 and not otherwise.
***********************************************************************************************************************/


-- *** 4. Audit triggers ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.trg_au_updt_PermissionCategory
Author:       rsincero
CreateDate:   2026-09-20
Description:
AFTER UPDATE audit stamp for auth.PermissionCategory, and the guard that makes CategoryCode immutable -- E-50010.

CategoryCode is immutable because auth.Permission denormalises it and FK_auth_Permission_PermissionCategory references
the pair: a rename would be refused by the foreign key on this table, naming a table the administrator was not editing.
Renaming it in both places at once is a schema change, not an edit, and the seed in 115_seed_reference_data.sql is where
it belongs.  CategoryName and SortOrder are freely editable, which is what that seed's MERGE relies on.

Modification History:
2026-09-20  rsincero  Created.  PLAN-AUTH-001 T-043.
***********************************************************************************************************************/
CREATE OR ALTER TRIGGER auth.trg_au_updt_PermissionCategory
    ON auth.PermissionCategory
    AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    IF UPDATE (CategoryCode)
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.PermissionCategoryId = i.PermissionCategoryId
                    WHERE i.CategoryCode <> d.CategoryCode)
    BEGIN
        ;THROW 50010, N'auth.PermissionCategory.CategoryCode is immutable: auth.Permission denormalises it and the composite foreign key references the pair. Changing what a family is called is a schema change made in 115_seed_reference_data.sql, not an edit.', 1;
    END;

    DECLARE @Now   DATETIME2 (3)  = SYSUTCDATETIME ()
          , @Actor NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                            , ORIGINAL_LOGIN ());

    UPDATE c
       SET c.auditModifiedDateUtc = @Now
         , c.auditModifiedBy      = CASE WHEN UPDATE (auditModifiedBy)
                                         THEN COALESCE (NULLIF (i.auditModifiedBy, N''), @Actor)
                                         ELSE @Actor END
         , c.auditDeletedBy       = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Actor ELSE c.auditDeletedBy      END
         , c.auditDeletedDateUtc  = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Now   ELSE c.auditDeletedDateUtc END
      FROM auth.PermissionCategory AS c
      JOIN inserted                AS i ON i.PermissionCategoryId = c.PermissionCategoryId
      JOIN deleted                 AS d ON d.PermissionCategoryId = c.PermissionCategoryId;
END;
GO

/***********************************************************************************************************************
ObjectName:   auth.trg_au_updt_Permission
Author:       rsincero
CreateDate:   2026-09-20
Description:
AFTER UPDATE audit stamp for auth.Permission, and the guard that makes PermissionCode and ApplicationId immutable --
E-50010.

PermissionCode is immutable for the reason the header of this script gives: it is a literal in procedure bodies, in
120_rls_policy.sql and in the .NET layer.  Renaming it here renames nothing there, and the result is a permission that
exists and that no code demands -- together with E-50031 from every procedure still naming the old code.  A rename is a
new row and a soft delete, done in 115_seed_reference_data.sql alongside the code change that needs it.

ApplicationId is immutable because moving a permission between applications takes every auth.RolePermission row with
it, and D-09's whole claim is that authority defined for one variant does not reach another.

PermissionName, PermissionDescription and IsTenantScoped are editable.  The first two are labels.  The third is
deliberate: a project may discover that a permission it added should not be tenant-scoped, and the fix is one UPDATE
plus a rebuild of auth.ProfilePermissionScope -- not a new code.

Modification History:
2026-09-20  rsincero  Created.  PLAN-AUTH-001 T-043.
***********************************************************************************************************************/
CREATE OR ALTER TRIGGER auth.trg_au_updt_Permission
    ON auth.Permission
    AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    IF (UPDATE (PermissionCode) OR UPDATE (ApplicationId))
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.PermissionId = i.PermissionId
                    WHERE i.PermissionCode <> d.PermissionCode
                       OR i.ApplicationId  <> d.ApplicationId)
    BEGIN
        ;THROW 50010, N'auth.Permission.PermissionCode and ApplicationId are immutable: the code is a literal in procedure bodies, in 120_rls_policy.sql and in the application layer, and the application is the outermost scope of authority (D-09). Soft-delete the row and seed the replacement in 115_seed_reference_data.sql.', 1;
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
      FROM auth.Permission AS p
      JOIN inserted        AS i ON i.PermissionId = p.PermissionId
      JOIN deleted         AS d ON d.PermissionId = p.PermissionId;
END;
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
      (N'auth', N'TABLE', N'PermissionCategory', NULL
     , N'The seven permission families of section 8.1 -- Data, User, Authz, Tenant, Config, Audit, Platform. NOT scoped '
     + N'to an application, because a family means the same thing in every variant. Descriptive for the role editor and '
     + N'structural for CK_auth_Permission_CodeMatchesCategory, and five of the sixteen baseline roles are seeded by '
     + N'joining on it rather than by listing codes, so a misfiled permission changes what those roles mean.')
    , (N'auth', N'TABLE', N'PermissionCategory', N'PermissionCategoryId'
     , N'Surrogate key. Half of UX_auth_PermissionCategory_Id_Code, the unfiltered pair auth.Permission''s composite '
     + N'foreign key references.')
    , (N'auth', N'TABLE', N'PermissionCategory', N'CategoryCode'
     , N'The family, PascalCase and containing no dot -- the dot is the separator in a permission code. IMMUTABLE '
     + N'(E-50010): auth.Permission denormalises it. Unique among live rows.')
    , (N'auth', N'TABLE', N'PermissionCategory', N'CategoryName'
     , N'The display heading in the role editor. Freely editable, which is what the 115 seed''s MERGE relies on.')
    , (N'auth', N'TABLE', N'PermissionCategory', N'SortOrder'
     , N'Display order. The seven seeded families are spaced by ten so a project can insert its own between them '
     + N'without renumbering.')

    , (N'auth', N'TABLE', N'Permission', NULL
     , N'The vocabulary every authorization decision is expressed in -- the 35 rows of Appendix A, per application. '
     + N'CODE, NOT CONFIGURATION (section 16.1 item 3): every code is a literal in procedure bodies, in '
     + N'120_rls_policy.sql and in the .NET layer, so there is no administrative screen for this table and '
     + N'115_seed_reference_data.sql is the only thing that writes it. auth.Role is the administrator''s vocabulary.')
    , (N'auth', N'TABLE', N'Permission', N'PermissionId'
     , N'Surrogate key. Substituted as a LITERAL into auth.udfTenantReadPredicate at deploy time rather than looked up '
     + N'by code, because a join inside a per-row security predicate is a third seek for a value that never changes. A '
     + N'database serving several applications holds several rows per code, so 120_rls_policy.sql substitutes the whole '
     + N'set as an IN list and asserts it still matches -- BL-039.')
    , (N'auth', N'TABLE', N'Permission', N'ApplicationId'
     , N'The application this permission belongs to -- D-09, the outermost scope. IMMUTABLE (E-50010): moving a '
     + N'permission between applications takes every auth.RolePermission row with it.')
    , (N'auth', N'TABLE', N'Permission', N'PermissionCategoryId'
     , N'The family. Half of the composite foreign key that keeps PermissionCategoryCode honest.')
    , (N'auth', N'TABLE', N'Permission', N'PermissionCategoryCode'
     , N'The family code, denormalised from auth.PermissionCategory so that CK_auth_Permission_CodeMatchesCategory can '
     + N'be row-local. Kept truthful by FK_auth_Permission_PermissionCategory, which references the (id, code) pair. '
     + N'The same arrangement, for the same reason, as auth.Tenant.TenantTypeCode.')
    , (N'auth', N'TABLE', N'Permission', N'PermissionCode'
     , N'The code procedures name as a literal -- ''<Family>.<Verb>'', Appendix C, exactly one dot, and the family half '
     + N'must equal this row''s category. IMMUTABLE (E-50010): a rename here renames nothing in the code that demands '
     + N'it, and leaves E-50031 on every screen still using the old name. Unique per application among live rows.')
    , (N'auth', N'TABLE', N'Permission', N'PermissionName'
     , N'The short label shown in the role editor''s checkbox list. Editable.')
    , (N'auth', N'TABLE', N'Permission', N'PermissionDescription'
     , N'Appendix A''s "Meaning" column -- what an administrator is actually granting. An addition to section 15.4, '
     + N'BL-037: the alternative is 35 strings hard-coded in the UI project, where nobody maintaining this catalogue '
     + N'would see them. Nullable, because a project adding a permission should not be blocked for want of prose.')
    , (N'auth', N'TABLE', N'Permission', N'IsTenantScoped'
     , N'0 means the permission is evaluated WITHOUT a tenant: auth.udfHasPermission ignores its @TenantId for such a '
     + N'permission. The three Platform permissions are the whole of that set today, and INV-09 adds a second, '
     + N'independent condition to them -- auth.User.IsPlatformAdmin = 1 -- which is deliberately not recorded here, so '
     + N'that revoking the flag revokes the authority without unpicking every grant.');

    -- The seven audit columns carry the same description on every table, so they are generated rather than typed out.
    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    SELECT N'auth', N'TABLE', t.TableName, c.ColumnName, c.Description
      FROM (VALUES (N'PermissionCategory'), (N'Permission')) AS t (TableName)
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
    VALUES (N'auth', N'TRIGGER', N'trg_au_updt_PermissionCategory', NULL
          , N'AFTER UPDATE audit stamp for auth.PermissionCategory, and the guard that makes CategoryCode immutable -- E-50010.')
         , (N'auth', N'TRIGGER', N'trg_au_updt_Permission', NULL
          , N'AFTER UPDATE audit stamp for auth.Permission, and the guard that makes PermissionCode and ApplicationId immutable -- E-50010.');

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
-- DELIBERATELY EMPTY.  INV-11: applicationRole holds no table-level permission on SCHEMA::auth, and 170_permissions.sql
-- makes the absence explicit with a schema-level DENY.  The application reads this catalogue through ownership chaining
-- inside auth.uspGetProfileContext and the role-editor procedures, never directly -- which matters more here than it
-- looks: a SELECT grant on auth.Permission hands an attacker the complete list of everything the application can do,
-- which is the reconnaissance step for every later request.
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
  FROM (VALUES (N'auth.PermissionCategory', N'The seven families of section 8.1. Not scoped to an application.')
             , (N'auth.Permission',         N'The 35 codes of Appendix A, per application. Code, not configuration.'))
       AS x (QualifiedName, Purpose);

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN i.name IS NULL THEN 2 ELSE 4 END
     , CASE WHEN i.name IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Index ' + x.IndexName
     , x.Purpose
  FROM (VALUES (N'UX_auth_PermissionCategory_Code', N'auth.PermissionCategory', N'UNIQUE on CategoryCode where live.')
             , (N'UX_auth_Permission_Code',         N'auth.Permission',         N'UNIQUE on (ApplicationId, PermissionCode) where live -- the natural key of section 15.4.')
             , (N'IX_auth_Permission_Category',     N'auth.Permission',         N'"Every permission in the User family" -- how five baseline roles are seeded and how the role editor groups.'))
       AS x (IndexName, TableName, Purpose)
  LEFT JOIN sys.indexes AS i ON i.name = x.IndexName AND i.object_id = OBJECT_ID (x.TableName);

-- The composite foreign key and the unfiltered pair it references, asserted by name.  Between them they are the whole
-- of the code/category agreement, and a reviewer tidying either one away would leave a catalogue in which 'Data.Read'
-- can be filed under Audit.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Constraints = 2 THEN 4 ELSE 1 END
     , CASE WHEN x.Constraints = 2 THEN 'OK' ELSE 'MISSING' END
     , N'The code/category agreement is enforced structurally'
     , N'UX_auth_PermissionCategory_Id_Code (unfiltered UNIQUE, so a FOREIGN KEY may reference it) and '
     + N'FK_auth_Permission_PermissionCategory (which references the pair) together make '
     + N'PermissionCategoryCode trustworthy, which is what lets CK_auth_Permission_CodeMatchesCategory be row-local. '
     + N'Found ' + CAST (x.Constraints AS NVARCHAR (11)) + N' of 2.'
  FROM (SELECT Constraints =
                   (SELECT COUNT (*) FROM sys.key_constraints
                     WHERE name = N'UX_auth_PermissionCategory_Id_Code' AND type = 'UQ')
                 + (SELECT COUNT (*) FROM sys.foreign_keys
                     WHERE name = N'FK_auth_Permission_PermissionCategory')) AS x;

-- The other unfiltered pair, reported for the same reason UX_auth_Tenant_Id_Application is reported in 030: it looks
-- like a redundant copy of the primary key and is the target of a foreign key in another file.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN kc.name IS NULL THEN 2 ELSE 4 END
     , CASE WHEN kc.name IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'UX_auth_Permission_Id_Application'
     , N'The unfiltered (PermissionId, ApplicationId) pair that FK_auth_RolePermission_Permission references in '
     + N'055_auth_role.sql. With the matching pair on auth.Role it makes a cross-application grant structurally '
     + N'impossible -- D-09. Redundant against PK_auth_Permission to look at, and not: a FOREIGN KEY needs a declared '
     + N'key over exactly these two columns.'
  FROM (SELECT 1 AS one) AS o
  LEFT JOIN sys.key_constraints AS kc ON kc.name = N'UX_auth_Permission_Id_Application'
                                     AND kc.parent_object_id = OBJECT_ID (N'auth.Permission')
                                     AND kc.type = 'UQ';

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (x.QualifiedName, N'TR') IS NULL THEN 2 ELSE 4 END
     , CASE WHEN OBJECT_ID (x.QualifiedName, N'TR') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Trigger ' + x.QualifiedName
     , x.Purpose
  FROM (VALUES (N'auth.trg_au_updt_PermissionCategory', N'Audit stamp, and CategoryCode immutable -- E-50010.')
             , (N'auth.trg_au_updt_Permission',         N'Audit stamp, and PermissionCode and ApplicationId immutable -- E-50010.'))
       AS x (QualifiedName, Purpose);

-- The catalogue itself.  EMPTY IS THE EXPECTED STATE HERE and the report says so, because a file called
-- 050_auth_permission.sql that reports nothing about permissions invites the reader to assume a seed failed.
INSERT @Report (Severity, Status, Item, Detail)
SELECT 3, 'INFO', N'The catalogue'
     , CASE WHEN x.Permissions = 0
            THEN N'Empty. Expected at this point in the deployment: section 16.1 item 3 seeds the 35 rows in '
               + N'115_seed_reference_data.sql, six scripts later, and nothing structural needs them before then. '
               + N'Unlike auth.TenantType, which BL-021 had to move forward into 030 because auth.Tenant could not '
               + N'exist without the Root row.'
            ELSE CAST (x.Permissions AS NVARCHAR (11)) + N' live permission(s) across '
               + CAST (x.Applications AS NVARCHAR (11)) + N' application(s) in '
               + CAST (x.Categories AS NVARCHAR (11)) + N' family(ies). 115_seed_reference_data.sql has run. '
               + N'Appendix A is 35 per application.'
       END
  FROM (SELECT Permissions  = (SELECT COUNT (*) FROM auth.Permission WHERE IsDeleted = 0)
             , Applications = (SELECT COUNT (DISTINCT ApplicationId) FROM auth.Permission WHERE IsDeleted = 0)
             , Categories   = (SELECT COUNT (*) FROM auth.PermissionCategory WHERE IsDeleted = 0)) AS x;

-- Once the seed HAS run, this is the check that matters most and it costs nothing to leave in: a Platform permission
-- that is tenant-scoped, or a tenant-scoped permission in no family, is a row auth.udfHasPermission answers
-- inconsistently.  The CHECK constraint prevents the first; this reports it anyway, because a constraint added after
-- the rows would have been created WITH NOCHECK by somebody in a hurry.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Wrong = 0 THEN 4 ELSE 1 END
     , CASE WHEN x.Wrong = 0 THEN 'OK' ELSE 'VIOLATION' END
     , N'Every Platform permission is evaluated without a tenant'
     , CASE WHEN x.Wrong = 0
            THEN N'Yes, or the catalogue is not seeded yet. IsTenantScoped = 0 for the Platform family and 1 for '
               + N'everything else -- Appendix A. INV-09 adds IsPlatformAdmin = 1 on top, in auth.udfHasPermission.'
            ELSE CAST (x.Wrong AS NVARCHAR (11)) + N' Platform permission(s) are marked tenant-scoped. '
               + N'CK_auth_Permission_PlatformIsNotTenantScoped should have refused them, so it is either absent or '
               + N'was created WITH NOCHECK over existing rows.'
       END
  FROM (SELECT Wrong = (SELECT COUNT (*) FROM auth.Permission
                         WHERE IsDeleted = 0 AND PermissionCategoryCode = N'Platform' AND IsTenantScoped = 1)) AS x;

INSERT @Report (Severity, Status, Item, Detail)
VALUES (3, 'NEXT', N'Next scripts'
      , N'055_auth_role.sql (auth.Role and auth.RolePermission -- the administrator''s vocabulary), then '
      + N'060_auth_profile_role.sql and 065_auth_effective_permission.sql. The 35 rows arrive at '
      + N'115_seed_reference_data.sql and 120_rls_policy.sql is the first thing that reads one.');

IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
    PRINT N'Permission catalogue: PROBLEMS found. Read the report below before running the next script.';
ELSE
    PRINT N'Permission catalogue: no problems found.';

PRINT N'';

SELECT Severity, Status, Item, Detail
  FROM @Report
 ORDER BY Severity, RowNo;
GO
