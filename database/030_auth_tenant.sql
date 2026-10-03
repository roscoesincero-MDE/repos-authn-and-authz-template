/***********************************************************************************************************************
Script:         030_auth_tenant.sql
Purpose:        The tenant hierarchy: auth.Application, auth.TenantType, auth.Tenant and auth.TenantClosure.  The four
                tables every other table in the database is ultimately scoped by, and the two constraints that make
                INV-02 -- exactly one root per application, and only the root without a parent -- a property of the
                schema rather than a habit of the procedures.
Target:         SQL Server 2022.
Run as:         db_owner in the target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/030_auth_tenant.sql
Idempotent:     Yes.  Guarded CREATE TABLE and CREATE INDEX, CREATE OR ALTER triggers, MERGE for the seven tenant types.
                No rows deleted, ever.
Depends on:     database/005_schemas_and_roles.sql, templates/extended-properties.sql.
Implements:     T-014 through T-017 and T-024.  DES-AUTH-001 sections 5.1 to 5.4, 15.2, 15.6 and D-09.
                See docs/10-database-authn-authz-design.md.
To retarget:    Pass it per run:  sqlcmd -d <database> -v DbName=<database>.  There is no in-file default.

WHAT IS LOAD-BEARING HERE
-------------------------
  ONE HIERARCHY, NOT ONE PER VARIANT.  D-01.  The three application variants in section 1.3 are prunings of one shape,
  distinguished by an ApplicationId and nothing else.  That is why auth.Application exists and why the root is unique
  PER APPLICATION rather than per database: the three variant trees in the Phase 1 fixtures coexist in one database,
  which is the only way to test that a scope expressed at one root cannot reach another.

  THE ROOT IS DEFINED BY A ROW-LOCAL CHECK, NOT BY A FUNCTION OR A TRIGGER.  CK_auth_Tenant_RootHasNoParent ties
  ParentTenantId IS NULL to TenantTypeCode = 'Root' and back again.  A CHECK constraint may only read its own row, so
  the type CODE is carried on auth.Tenant beside the type ID and the pair is proved by a composite foreign key against
  an unfiltered UNIQUE on auth.TenantType -- the same device dbo.CaseNote uses for (CaseFileId, TenantId).
  Reaching the code through a scalar function was tried and MEASURED: a function referenced by a CHECK cannot afterwards
  be CREATE OR ALTERed (error 3729, "cannot ALTER because it is being referenced by object"), with or without
  SCHEMABINDING, which breaks the re-runnability every script here requires.  A trigger was rejected because it can be
  disabled and because the fixtures and 900_bootstrap_first_admin.sql insert as db_owner.  BL-019.

  THE CLOSURE INCLUDES SOFT-DELETED TENANTS.  auth.TenantClosure is a structural mirror of the parent edges and nothing
  else; it does not filter on IsDeleted, and auth.udfIsTenantUsable decides usability by reading auth.Tenant through it.
  If the closure omitted a soft-deleted mid-tree tenant, that tenant would vanish from its descendants' ancestor set and
  the usability test would FAIL OPEN -- a deactivated administration's programs would keep working.  BL-020.

  THE CLOSURE HAS NO TENANT-FACING SOFT DELETE PATH OF ITS OWN.  auth.uspRebuildTenantClosure rebuilds it whole, and
  "whole" is a MERGE whose NOT MATCHED BY SOURCE branch sets IsDeleted = 1.  Rows are never removed, so a re-parenting
  leaves the old ancestor pairs behind, flagged, as evidence.

  EVERY TABLE HERE IS IN auth, AND applicationRole GETS NOTHING ON IT.  INV-11.  The application reaches tenancy only
  through the procedures in 125_auth_tenant_procedures.sql, which are the ownership-chaining boundary.  Section 7 of
  this file grants nothing, deliberately.
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
    -- Built into a variable because THROW takes a constant or a variable, never an expression: a concatenation in the
    -- message position is a parse error (102, near '+').
    DECLARE @Msg NVARCHAR (2000) =
        N'Schema auth does not exist. Run database/005_schemas_and_roles.sql first -- it also forces schema ownership '
      + N'to dbo, without which ownership chaining through the auth procedures does not work.';

    THROW 50000, @Msg, 1;
END
GO


-- *** 1. auth.Application ***
-- D-09.  The application is the outermost scope: roles, permissions and UI elements all belong to one, so the same
-- database can serve the three variants without a role defined for one becoming assignable in another.  It is NOT a
-- tenant -- it has no parent, no closure and no rows scoped to it directly.
IF OBJECT_ID (N'auth.Application', N'U') IS NULL
BEGIN
    CREATE TABLE auth.Application
    (
        ApplicationId        INT            IDENTITY (1, 1) NOT NULL

        -- The stable identifier used in seed data and in deployment scripts, so a script can name an application
        -- without knowing what surrogate key it was given.  UPPER_SNAKE_CASE by convention (Appendix C).
      , ApplicationCode      NVARCHAR (50)                  NOT NULL
      , ApplicationName      NVARCHAR (200)                 NOT NULL

        -- Deactivating an application is an administrative act, not a deletion: its tenants, roles and audit trail all
        -- remain readable.  Nothing in this script reads it -- auth.udfIsTenantUsable deliberately tests the TENANT
        -- chain only, because an inactive application is a service decision and an inactive tenant is a scope decision.
      , IsActive             BIT                            NOT NULL
            CONSTRAINT DF_auth_Application_IsActive DEFAULT (1)

      , IsDeleted            BIT                            NOT NULL
            CONSTRAINT DF_auth_Application_IsDeleted DEFAULT (0)
      , auditDeletedBy       NVARCHAR (255)                     NULL
      , auditDeletedDateUtc  DATETIME2 (3)                      NULL
        -- The DEFAULT is a backstop for a direct insert during maintenance.  Under the pooled application login
        -- ORIGINAL_LOGIN () is the APPLICATION's name, identical on every row, so every inserting procedure sets this
        -- explicitly from SESSION_CONTEXT (N'AppUser') instead.  DES section 14.4.
      , auditCreatedBy       NVARCHAR (255)                 NOT NULL
            CONSTRAINT DF_auth_Application_auditCreatedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditCreatedDateUtc  DATETIME2 (3)                  NOT NULL
            CONSTRAINT DF_auth_Application_auditCreatedDateUtc DEFAULT (SYSUTCDATETIME ())
      , auditModifiedBy      NVARCHAR (255)                 NOT NULL
            CONSTRAINT DF_auth_Application_auditModifiedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditModifiedDateUtc DATETIME2 (3)                  NOT NULL
            CONSTRAINT DF_auth_Application_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ())

      , CONSTRAINT PK_auth_Application PRIMARY KEY CLUSTERED (ApplicationId)

      , CONSTRAINT CK_auth_Application_ApplicationCode
            CHECK (LEN (ApplicationCode) > 0 AND ApplicationCode = LTRIM (RTRIM (ApplicationCode)))

        -- The soft-delete triple moves together or not at all.  Without this an IsDeleted = 1 row with no
        -- auditDeletedBy is a legal state, and the audit trail then cannot say who withdrew it.
      , CONSTRAINT CK_auth_Application_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS     NULL AND auditDeletedDateUtc IS     NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL))
    );
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'UX_auth_Application_Code' AND object_id = OBJECT_ID (N'auth.Application'))
BEGIN
    -- Filtered, so a withdrawn application's code can be reissued.  A UNIQUE CONSTRAINT could not be filtered, which is
    -- the reason this is an index and the (Id, Code) pair below is a constraint.
    CREATE UNIQUE INDEX UX_auth_Application_Code
        ON auth.Application (ApplicationCode)
     WHERE IsDeleted = 0;
END
GO


-- *** 2. auth.TenantType ***
-- Section 5.2.  Descriptive, not functional: no authorization decision reads the type.  It exists so the UI can label a
-- node and so reports can group.  The ONE exception is structural rather than authorizing -- 'Root' identifies the node
-- with no parent, which is why section 5's trigger makes TenantTypeCode immutable.
IF OBJECT_ID (N'auth.TenantType', N'U') IS NULL
BEGIN
    CREATE TABLE auth.TenantType
    (
        TenantTypeId         INT            IDENTITY (1, 1) NOT NULL
      , TenantTypeCode       NVARCHAR (50)                  NOT NULL
      , TenantTypeName       NVARCHAR (100)                 NOT NULL

        -- Display order for a picker.  The seven seeded types are spaced by ten so a project can insert its own between
        -- them without renumbering.
      , SortOrder            INT                            NOT NULL
            CONSTRAINT DF_auth_TenantType_SortOrder DEFAULT (0)

      , IsDeleted            BIT                            NOT NULL
            CONSTRAINT DF_auth_TenantType_IsDeleted DEFAULT (0)
      , auditDeletedBy       NVARCHAR (255)                     NULL
      , auditDeletedDateUtc  DATETIME2 (3)                      NULL
      , auditCreatedBy       NVARCHAR (255)                 NOT NULL
            CONSTRAINT DF_auth_TenantType_auditCreatedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditCreatedDateUtc  DATETIME2 (3)                  NOT NULL
            CONSTRAINT DF_auth_TenantType_auditCreatedDateUtc DEFAULT (SYSUTCDATETIME ())
      , auditModifiedBy      NVARCHAR (255)                 NOT NULL
            CONSTRAINT DF_auth_TenantType_auditModifiedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditModifiedDateUtc DATETIME2 (3)                  NOT NULL
            CONSTRAINT DF_auth_TenantType_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ())

      , CONSTRAINT PK_auth_TenantType PRIMARY KEY CLUSTERED (TenantTypeId)

        -- UNFILTERED, and that is the whole point of it: auth.Tenant carries TenantTypeCode denormalised so
        -- CK_auth_Tenant_RootHasNoParent can be row-local, and a FOREIGN KEY cannot reference a filtered index.  Safe
        -- because the pair contains the primary key, so it adds no constraint the primary key does not already impose.
      , CONSTRAINT UX_auth_TenantType_Id_Code UNIQUE (TenantTypeId, TenantTypeCode)

      , CONSTRAINT CK_auth_TenantType_TenantTypeCode
            CHECK (LEN (TenantTypeCode) > 0 AND TenantTypeCode = LTRIM (RTRIM (TenantTypeCode)))

      , CONSTRAINT CK_auth_TenantType_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS     NULL AND auditDeletedDateUtc IS     NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL))
    );
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'UX_auth_TenantType_Code' AND object_id = OBJECT_ID (N'auth.TenantType'))
BEGIN
    CREATE UNIQUE INDEX UX_auth_TenantType_Code
        ON auth.TenantType (TenantTypeCode)
     WHERE IsDeleted = 0;
END
GO

-- The seven seeded types, section 5.2: extensible and inert.
--
-- SEEDED HERE RATHER THAN IN 115_seed_reference_data.sql, which is where section 16.1 originally put them.  Phase 1
-- cannot build a tenant tree before the types exist, and FK_auth_Tenant_TenantType makes the 'Root' row a structural
-- prerequisite of the first INSERT rather than reference data loaded later.  115 must NOT re-seed them.  BL-021.
--
-- The MERGE updates the display name and the sort order and nothing else.  It deliberately does NOT resurrect a
-- soft-deleted type: a project that withdrew 'Jurisdiction' because its tree has none should not have it reappear on
-- the next deployment.
MERGE auth.TenantType AS tgt
USING (VALUES (N'Root',                 N'Root',                  10)
            , (N'Agency',               N'Agency',                20)
            , (N'Administration',       N'Administration',        30)
            , (N'Program',              N'Program',               40)
            , (N'Jurisdiction',         N'Jurisdiction',          50)
            , (N'ExternalOrganization', N'External Organization', 60)
            , (N'Division',             N'Division',              70))
      AS src (TenantTypeCode, TenantTypeName, SortOrder)
   ON tgt.TenantTypeCode = src.TenantTypeCode
WHEN MATCHED AND tgt.IsDeleted = 0
             AND (tgt.TenantTypeName <> src.TenantTypeName OR tgt.SortOrder <> src.SortOrder)
    THEN UPDATE SET tgt.TenantTypeName = src.TenantTypeName
                  , tgt.SortOrder      = src.SortOrder
WHEN NOT MATCHED BY TARGET
    THEN INSERT (TenantTypeCode, TenantTypeName, SortOrder, auditCreatedBy)
         VALUES (src.TenantTypeCode, src.TenantTypeName, src.SortOrder, ORIGINAL_LOGIN ());
GO

-- *** 3. auth.Tenant ***
-- Section 5.1 and 15.2.  The tree, one row per node, adjacency only -- the transitive closure is a separate table
-- because a scope test has to be a seek rather than a recursion (section 5.3).
IF OBJECT_ID (N'auth.Tenant', N'U') IS NULL
BEGIN
    CREATE TABLE auth.Tenant
    (
        TenantId             INT            IDENTITY (1, 1) NOT NULL

        -- Immutable after insert; section 5's trigger raises 50010.  Moving a tenant between applications would move
        -- every profile, grant and row beneath it out from under the role definitions that scope them.
      , ApplicationId        INT                            NOT NULL

        -- The per-application natural key: what the organization is called in seed data, in a URL and in conversation.
        -- UPPER_SNAKE_CASE (Appendix C), enforced below.  Also the half of SESSION_CONTEXT (N'AppUser') that identifies
        -- the acting tenant -- <UserName>@<TenantCode>#<UserProfileId> -- which is why it may not contain a space.
      , TenantCode           NVARCHAR (50)                  NOT NULL
      , TenantName           NVARCHAR (200)                 NOT NULL

      , TenantTypeId         INT                            NOT NULL

        -- DENORMALISED FROM auth.TenantType, and proved by FK_auth_Tenant_TenantType against the unfiltered
        -- UX_auth_TenantType_Id_Code.  It exists so CK_auth_Tenant_RootHasNoParent can be row-local; see the file
        -- header for what was measured and rejected.  A caller never supplies it -- auth.uspCreateTenant resolves it
        -- from the code it was given, and the trigger in section 5 keeps it in step by refusing to let it change.
      , TenantTypeCode       NVARCHAR (50)                  NOT NULL

        -- NULL for the root and only for the root, which is the whole of INV-02's second half.  A self-referencing
        -- foreign key, so a parent cannot name a tenant that does not exist.
      , ParentTenantId       INT                                NULL

        -- Section 5.4.  Deactivation is NOT deletion and NOT cascaded: auth.udfIsTenantUsable walks the ancestor chain
        -- at read time, so deactivating an administration makes every program under it unusable without writing to any
        -- of them -- and reactivating it restores them, which a cascade could not.
      , IsActive             BIT                            NOT NULL
            CONSTRAINT DF_auth_Tenant_IsActive DEFAULT (1)

      , IsDeleted            BIT                            NOT NULL
            CONSTRAINT DF_auth_Tenant_IsDeleted DEFAULT (0)
      , auditDeletedBy       NVARCHAR (255)                     NULL
      , auditDeletedDateUtc  DATETIME2 (3)                      NULL
      , auditCreatedBy       NVARCHAR (255)                 NOT NULL
            CONSTRAINT DF_auth_Tenant_auditCreatedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditCreatedDateUtc  DATETIME2 (3)                  NOT NULL
            CONSTRAINT DF_auth_Tenant_auditCreatedDateUtc DEFAULT (SYSUTCDATETIME ())
      , auditModifiedBy      NVARCHAR (255)                 NOT NULL
            CONSTRAINT DF_auth_Tenant_auditModifiedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditModifiedDateUtc DATETIME2 (3)                  NOT NULL
            CONSTRAINT DF_auth_Tenant_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ())

      , CONSTRAINT PK_auth_Tenant PRIMARY KEY CLUSTERED (TenantId)

      , CONSTRAINT FK_auth_Tenant_Application
            FOREIGN KEY (ApplicationId) REFERENCES auth.Application (ApplicationId)

      , CONSTRAINT FK_auth_Tenant_TenantType
            FOREIGN KEY (TenantTypeId, TenantTypeCode)
            REFERENCES auth.TenantType (TenantTypeId, TenantTypeCode)

        -- No ON DELETE action of any kind, here or anywhere: there is no delete path in this database, and a cascade on
        -- a self-referencing key is rejected by SQL Server regardless.
      , CONSTRAINT FK_auth_Tenant_Parent_Tenant
            FOREIGN KEY (ParentTenantId) REFERENCES auth.Tenant (TenantId)

        -- INV-02, second half, and stated as a BICONDITIONAL on purpose.  Either direction alone is half a rule: without
        -- the first clause a non-root could have no parent and become a second root; without the second, a tenant typed
        -- 'Root' could be hung under another node and the tree would have a root that is not the root.
      , CONSTRAINT CK_auth_Tenant_RootHasNoParent
            CHECK ((ParentTenantId IS     NULL AND TenantTypeCode =  N'Root')
                OR (ParentTenantId IS NOT NULL AND TenantTypeCode <> N'Root'))

        -- A one-node cycle, which the closure's recursion would not survive.  Longer cycles cannot be expressed in a
        -- CHECK at all; auth.uspUpdateTenant tests for them with the closure and raises 50095.
      , CONSTRAINT CK_auth_Tenant_NotOwnParent
            CHECK (ParentTenantId IS NULL OR ParentTenantId <> TenantId)

        -- COLLATE Latin1_General_BIN2 on the uppercase test, deliberately.  The database collation is case-insensitive,
        -- so a plain  TenantCode = UPPER (TenantCode)  is a tautology that passes 'anne_arundel' silently.  The binary
        -- collation is what makes the comparison mean what it reads as meaning.
      , CONSTRAINT CK_auth_Tenant_TenantCode
            CHECK (LEN (TenantCode) > 0
               AND TenantCode = LTRIM (RTRIM (TenantCode))
               AND TenantCode NOT LIKE N'% %'
               AND TenantCode COLLATE Latin1_General_BIN2 = UPPER (TenantCode) COLLATE Latin1_General_BIN2)

      , CONSTRAINT CK_auth_Tenant_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS     NULL AND auditDeletedDateUtc IS     NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL))
    );
END
GO

-- ADDED IN PHASE 3, AND DELIBERATELY AS AN ALTER RATHER THAN A COLUMN OF THE CREATE TABLE ABOVE.  The table is guarded
-- by IF OBJECT_ID (...) IS NULL, so on every database where 030 has already run a constraint added inside that block
-- would never appear.  One convergent code path is worth more than the tidier-looking alternative.  BL-040.
--
-- UNFILTERED, and it contains the primary key, so it imposes nothing the primary key does not already impose.  It exists
-- to be the target of a composite foreign key: auth.Role in 055_auth_role.sql references (OwnerTenantId, ApplicationId)
-- so that a role cannot be owned by a tenant belonging to a DIFFERENT application.  Without it, D-09's claim that the
-- application is the outermost scope of authority is enforced only by the procedure that inserts the row -- and INV-04's
-- ancestor-or-self test would then be comparing tenants across two unrelated trees, where it is not merely false but
-- meaningless.  The same arrangement as UX_auth_TenantType_Id_Code above and UX_auth_UserProfile_Id_Tenant in 040.
IF NOT EXISTS (SELECT 1 FROM sys.key_constraints
                WHERE name = N'UX_auth_Tenant_Id_Application'
                  AND parent_object_id = OBJECT_ID (N'auth.Tenant')
                  AND type = 'UQ')
BEGIN
    ALTER TABLE auth.Tenant
        ADD CONSTRAINT UX_auth_Tenant_Id_Application UNIQUE (TenantId, ApplicationId);
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'UX_auth_Tenant_Application_Code' AND object_id = OBJECT_ID (N'auth.Tenant'))
BEGIN
    -- The per-application natural key.  Two organizations in two variants may both be called AGENCY; the same code
    -- twice in one application is a data-entry error that would make SESSION_CONTEXT (N'AppUser') ambiguous.
    CREATE UNIQUE INDEX UX_auth_Tenant_Application_Code
        ON auth.Tenant (ApplicationId, TenantCode)
     WHERE IsDeleted = 0;
END
GO

-- INV-02, FIRST half: exactly one root per application.  A filtered unique index is the only declarative way to say "at
-- most one row per ApplicationId satisfying this predicate" -- a CHECK cannot count rows and a trigger can be disabled.
-- Combined with CK_auth_Tenant_RootHasNoParent it gives "exactly one" as soon as one root exists.
--
-- The filter includes IsDeleted = 0 on purpose, and the consequence is intended: soft-deleting a root frees the slot so
-- a mis-seeded application can be corrected without a hard delete this database does not permit.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'UX_auth_Tenant_ApplicationRoot' AND object_id = OBJECT_ID (N'auth.Tenant'))
BEGIN
    CREATE UNIQUE INDEX UX_auth_Tenant_ApplicationRoot
        ON auth.Tenant (ApplicationId)
     WHERE ParentTenantId IS NULL AND IsDeleted = 0;
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_auth_Tenant_Parent' AND object_id = OBJECT_ID (N'auth.Tenant'))
BEGIN
    -- The edge list auth.uspRebuildTenantClosure walks, and the index auth.vwTenantHierarchy's recursion seeks on.
    CREATE INDEX IX_auth_Tenant_Parent
        ON auth.Tenant (ParentTenantId, TenantId)
     INCLUDE (ApplicationId, TenantCode, IsActive)
     WHERE IsDeleted = 0;
END
GO


-- *** 4. auth.TenantClosure ***
-- Section 5.3.  One row per (ancestor, descendant) pair INCLUDING the depth-0 self row, so "the scope of a grant at
-- tenant X" is one predicate -- AncestorTenantId = X -- with no special case for X itself.  Without the self row every
-- scope test would be  ancestor = X OR descendant = X,  and the OR is where somebody eventually writes AND.
IF OBJECT_ID (N'auth.TenantClosure', N'U') IS NULL
BEGIN
    CREATE TABLE auth.TenantClosure
    (
        AncestorTenantId     INT                            NOT NULL
      , DescendantTenantId   INT                            NOT NULL

        -- 0 for the self row, 1 for a direct child, and so on.  Carried so a query can ask for immediate children
        -- without a second table and so the re-parenting test has something to be wrong about.
      , Depth                INT                            NOT NULL

      , IsDeleted            BIT                            NOT NULL
            CONSTRAINT DF_auth_TenantClosure_IsDeleted DEFAULT (0)
      , auditDeletedBy       NVARCHAR (255)                     NULL
      , auditDeletedDateUtc  DATETIME2 (3)                      NULL
      , auditCreatedBy       NVARCHAR (255)                 NOT NULL
            CONSTRAINT DF_auth_TenantClosure_auditCreatedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditCreatedDateUtc  DATETIME2 (3)                  NOT NULL
            CONSTRAINT DF_auth_TenantClosure_auditCreatedDateUtc DEFAULT (SYSUTCDATETIME ())
      , auditModifiedBy      NVARCHAR (255)                 NOT NULL
            CONSTRAINT DF_auth_TenantClosure_auditModifiedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditModifiedDateUtc DATETIME2 (3)                  NOT NULL
            CONSTRAINT DF_auth_TenantClosure_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ())

        -- The pair IS the key.  Clustered on (ancestor, descendant) because the commonest read is "everything under
        -- this tenant", which is then a range seek.
      , CONSTRAINT PK_auth_TenantClosure PRIMARY KEY CLUSTERED (AncestorTenantId, DescendantTenantId)

      , CONSTRAINT FK_auth_TenantClosure_Ancestor
            FOREIGN KEY (AncestorTenantId)   REFERENCES auth.Tenant (TenantId)
      , CONSTRAINT FK_auth_TenantClosure_Descendant
            FOREIGN KEY (DescendantTenantId) REFERENCES auth.Tenant (TenantId)

      , CONSTRAINT CK_auth_TenantClosure_Depth CHECK (Depth >= 0)

        -- Depth 0 means the self row and nothing else, in both directions.  A pair (X, X, 3) or (X, Y, 0) is a defect in
        -- the rebuild, and this is where it is caught rather than in whatever read first believes it.
      , CONSTRAINT CK_auth_TenantClosure_SelfPair
            CHECK ((AncestorTenantId =  DescendantTenantId AND Depth =  0)
                OR (AncestorTenantId <> DescendantTenantId AND Depth >  0))

      , CONSTRAINT CK_auth_TenantClosure_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS     NULL AND auditDeletedDateUtc IS     NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL))
    );
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_auth_TenantClosure_Descendant' AND object_id = OBJECT_ID (N'auth.TenantClosure'))
BEGIN
    -- The other direction: "every ancestor of this tenant", which is what auth.udfIsTenantUsable asks and what the RLS
    -- predicate asks on every row of every query.  Covering, so neither has to touch the clustered index.
    CREATE INDEX IX_auth_TenantClosure_Descendant
        ON auth.TenantClosure (DescendantTenantId, AncestorTenantId)
     INCLUDE (Depth)
     WHERE IsDeleted = 0;
END
GO


-- *** 5. Audit triggers ***
-- One per table, and they ship HERE rather than waiting for 135_audit_triggers.sql, which is where the Scripts sheet
-- puts the domain triggers.  The audit column DEFAULTs fire on INSERT only, so between this script and that one every
-- UPDATE to a tenant would leave auditModifiedBy and auditModifiedDateUtc at their insert-time values and a soft delete
-- would record neither who nor when -- and auth.uspRebuildTenantClosure, three scripts later, is all UPDATEs.  A table
-- and the trigger that maintains it belong in the same file for the same reason the RLS registration does.  BL-022.

/***********************************************************************************************************************
ObjectName:   auth.trg_au_updt_Tenant
Author:       rsincero
CreateDate:   2026-09-19
========================================================================================================================
Description:

Maintains the audit columns on auth.Tenant and enforces ApplicationId immutability.

========================================================================================================================
Notes:

IMMUTABILITY.  ApplicationId (50010) must never change.  The application is the scope that owns roles, permissions and UI
elements (D-09), so moving a tenant between applications would leave every profile beneath it holding grants of roles
that are no longer assignable to it -- and nothing would report an error, because each row would still be internally
consistent.  Re-parenting WITHIN an application is legitimate and expected; auth.uspUpdateTenant does it, and
auth.uspRebuildTenantClosure is why it is safe.

TenantTypeCode IS NOT GUARDED HERE.  FK_auth_Tenant_TenantType and CK_auth_Tenant_RootHasNoParent already make every
illegitimate change to it impossible: the pair must exist in auth.TenantType, and the 'Root' half is tied to
ParentTenantId.  Retyping an Administration as a Division is an ordinary administrative correction.

WHY THROW AND NOT RAISERROR.  A branchable number, and a statement that is actually terminated.  RAISERROR (..., 16, 1)
followed by RETURN ends the module and nothing else: the UPDATE is silently not applied and the caller's batch runs on
believing it was.

RECURSION.  This trigger updates the table it is defined on.  RECURSIVE_TRIGGERS is OFF by default, but that is a
DATABASE option someone else can turn on, and the failure if they do is an infinite loop rather than a wrong value.

JOINING ON THE PRIMARY KEY is sound because TenantId is an IDENTITY column and SQL Server rejects an UPDATE against one
outright.

========================================================================================================================
Example Usage and Performance:

update auth.Tenant set TenantName = N'Land and Materials Administration' where TenantId = 4;

Set-based; one extra UPDATE per statement regardless of row count.

========================================================================================================================
Modification History:

Date:		2026-09-19
Author:		rsincero
Ticket:		T-014
Description:
Created with the table, Phase 1.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER TRIGGER auth.trg_au_updt_Tenant
ON auth.Tenant
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    -- An UPDATE that matched nothing still fires the trigger, with inserted and deleted both empty.
    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;

    -- See RECURSION in the notes.  Guarding on this trigger's own depth rather than on the database option, so the
    -- trigger cannot be made to loop by a setting changed elsewhere.
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    -- Immutability, before anything is stamped.  A rejected statement must leave no trace of having been attempted.
    IF UPDATE (ApplicationId)
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.TenantId = i.TenantId
                    WHERE i.ApplicationId <> d.ApplicationId)
    BEGIN
        ;THROW 50010, N'auth.Tenant.ApplicationId is immutable. A tenant cannot be moved between applications: the application scopes the roles, permissions and UI elements every profile beneath the tenant is granted through.', 1;
    END;

    -- One value per fact, hoisted: a soft delete arriving here must stamp auditDeletedDateUtc and auditModifiedDateUtc
    -- with the SAME instant, not two SYSUTCDATETIME () calls that a millisecond boundary can separate.
    DECLARE @Now   DATETIME2 (3)  = SYSUTCDATETIME (),
            @Actor NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N''), ORIGINAL_LOGIN ());

    UPDATE t
       SET t.auditModifiedDateUtc = @Now,

           -- Caller-overridable, and the only one that is.
           t.auditModifiedBy = CASE WHEN UPDATE (auditModifiedBy)
                                    THEN COALESCE (NULLIF (i.auditModifiedBy, N''), @Actor)
                                    ELSE @Actor
                               END,

           t.auditDeletedBy      = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Actor ELSE t.auditDeletedBy      END,
           t.auditDeletedDateUtc = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Now   ELSE t.auditDeletedDateUtc END
      FROM auth.Tenant AS t
      JOIN inserted    AS i ON i.TenantId = t.TenantId
      JOIN deleted     AS d ON d.TenantId = t.TenantId;
END;
GO


/***********************************************************************************************************************
ObjectName:   auth.trg_au_updt_TenantType
Author:       rsincero
CreateDate:   2026-09-19
========================================================================================================================
Description:

Maintains the audit columns on auth.TenantType and makes TenantTypeCode immutable.

========================================================================================================================
Notes:

WHY THE CODE IS IMMUTABLE HERE AND NOT ON auth.Tenant.  The literal N'Root' appears inside
CK_auth_Tenant_RootHasNoParent, which is compiled into the schema and cannot be parameterised.  Renaming the type row
from 'Root' to anything else would not break that constraint -- it would break every tenant that satisfies it, because
FK_auth_Tenant_TenantType carries the code onto auth.Tenant and a rename would have to propagate there.  50010 rather
than a new number: it is the same class of fault, an immutable key changed.

The display name and the sort order are freely editable, which is what the section 2 MERGE relies on.

Otherwise identical in shape to auth.trg_au_updt_Tenant; see that trigger's notes for every other clause.

========================================================================================================================
Example Usage and Performance:

update auth.TenantType set TenantTypeName = N'Programme' where TenantTypeCode = N'Program';   -- allowed

Set-based; one extra UPDATE per statement.

========================================================================================================================
Modification History:

Date:		2026-09-19
Author:		rsincero
Ticket:		T-015
Description:
Created with the table, Phase 1.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER TRIGGER auth.trg_au_updt_TenantType
ON auth.TenantType
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    IF UPDATE (TenantTypeCode)
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.TenantTypeId = i.TenantTypeId
                    WHERE i.TenantTypeCode <> d.TenantTypeCode)
    BEGIN
        ;THROW 50010, N'auth.TenantType.TenantTypeCode is immutable. The code is carried onto auth.Tenant by FK_auth_Tenant_TenantType and the literal Root is compiled into CK_auth_Tenant_RootHasNoParent. Add a type; do not rename one.', 1;
    END;

    DECLARE @Now   DATETIME2 (3)  = SYSUTCDATETIME (),
            @Actor NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N''), ORIGINAL_LOGIN ());

    UPDATE t
       SET t.auditModifiedDateUtc = @Now,
           t.auditModifiedBy = CASE WHEN UPDATE (auditModifiedBy)
                                    THEN COALESCE (NULLIF (i.auditModifiedBy, N''), @Actor)
                                    ELSE @Actor
                               END,
           t.auditDeletedBy      = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Actor ELSE t.auditDeletedBy      END,
           t.auditDeletedDateUtc = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Now   ELSE t.auditDeletedDateUtc END
      FROM auth.TenantType AS t
      JOIN inserted        AS i ON i.TenantTypeId = t.TenantTypeId
      JOIN deleted         AS d ON d.TenantTypeId = t.TenantTypeId;
END;
GO


/***********************************************************************************************************************
ObjectName:   auth.trg_au_updt_Application
Author:       rsincero
CreateDate:   2026-09-19
========================================================================================================================
Description:

Maintains the audit columns on auth.Application.  No immutability rule: the code is protected by
UX_auth_Application_Code and the name is meant to be editable.

========================================================================================================================
Notes:

Identical in shape to auth.trg_au_updt_Tenant with the immutability block removed; see that trigger's notes.

ApplicationCode is deliberately NOT immutable, which is the one decision worth stating.  Unlike a tenant code it does not
appear in SESSION_CONTEXT and is not referenced by a compiled constraint, so a rename costs nothing beyond re-seeding.

========================================================================================================================
Example Usage and Performance:

update auth.Application set IsActive = 0 where ApplicationCode = N'VARIANT3';

Set-based; one extra UPDATE per statement.

========================================================================================================================
Modification History:

Date:		2026-09-19
Author:		rsincero
Ticket:		T-014
Description:
Created with the table, Phase 1.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER TRIGGER auth.trg_au_updt_Application
ON auth.Application
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    DECLARE @Now   DATETIME2 (3)  = SYSUTCDATETIME (),
            @Actor NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N''), ORIGINAL_LOGIN ());

    UPDATE t
       SET t.auditModifiedDateUtc = @Now,
           t.auditModifiedBy = CASE WHEN UPDATE (auditModifiedBy)
                                    THEN COALESCE (NULLIF (i.auditModifiedBy, N''), @Actor)
                                    ELSE @Actor
                               END,
           t.auditDeletedBy      = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Actor ELSE t.auditDeletedBy      END,
           t.auditDeletedDateUtc = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Now   ELSE t.auditDeletedDateUtc END
      FROM auth.Application AS t
      JOIN inserted         AS i ON i.ApplicationId = t.ApplicationId
      JOIN deleted          AS d ON d.ApplicationId = t.ApplicationId;
END;
GO


/***********************************************************************************************************************
ObjectName:   auth.trg_au_updt_TenantClosure
Author:       rsincero
CreateDate:   2026-09-19
========================================================================================================================
Description:

Maintains the audit columns on auth.TenantClosure.

========================================================================================================================
Notes:

THE JOIN IS ON THE WHOLE PRIMARY KEY, and this table's key is a composite of two ordinary INT columns rather than an
IDENTITY -- so unlike the other three triggers here, nothing in the engine prevents an UPDATE from changing the columns
the join relies on.  auth.uspRebuildTenantClosure therefore NEVER updates AncestorTenantId or DescendantTenantId: it
matches on the pair and updates Depth and the soft-delete flag only.  A statement that did change a key column would
make this trigger stamp the wrong row, silently.  That constraint on the rebuild is a consequence of this trigger's
shape and is stated in both places on purpose.

THE REBUILD SETS auditDeletedBy AND auditDeletedDateUtc ITSELF, and does not rely on this trigger to do it.  CHECK
constraints are evaluated before AFTER triggers, so CK_auth_TenantClosure_DeletedPair would reject the soft delete
before the trigger ever ran.  The CASE branches below are kept anyway, for a soft delete arriving from anywhere else.

========================================================================================================================
Example Usage and Performance:

exec auth.uspRebuildTenantClosure;   -- the only thing that writes to this table

Set-based; one extra UPDATE per statement, which for a rebuild is one per MERGE branch.

========================================================================================================================
Modification History:

Date:		2026-09-19
Author:		rsincero
Ticket:		T-017
Description:
Created with the table, Phase 1.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER TRIGGER auth.trg_au_updt_TenantClosure
ON auth.TenantClosure
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    DECLARE @Now   DATETIME2 (3)  = SYSUTCDATETIME (),
            @Actor NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N''), ORIGINAL_LOGIN ());

    UPDATE t
       SET t.auditModifiedDateUtc = @Now,
           t.auditModifiedBy = CASE WHEN UPDATE (auditModifiedBy)
                                    THEN COALESCE (NULLIF (i.auditModifiedBy, N''), @Actor)
                                    ELSE @Actor
                               END,
           t.auditDeletedBy      = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Actor ELSE t.auditDeletedBy      END,
           t.auditDeletedDateUtc = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Now   ELSE t.auditDeletedDateUtc END
      FROM auth.TenantClosure AS t
      JOIN inserted           AS i ON i.AncestorTenantId   = t.AncestorTenantId
                                  AND i.DescendantTenantId = t.DescendantTenantId
      JOIN deleted            AS d ON d.AncestorTenantId   = t.AncestorTenantId
                                  AND d.DescendantTenantId = t.DescendantTenantId;
END;
GO


-- *** 6. Descriptions ***
-- Conventions rule 4: every table and every column carries an MS_Description.  T-024.
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
      (N'auth', N'TABLE', N'Application', NULL
     , N'One row per application variant served by this database. D-09: the application is the outermost scope, so a '
     + N'role, permission or UI element defined for one variant is not assignable in another. It is NOT a tenant -- it '
     + N'has no parent, no closure row and no data scoped directly to it. The template seeds none; the Phase 1 test '
     + N'fixtures create three so that three root tenants can coexist and a scope expressed at one root can be shown '
     + N'not to reach another.')
    , (N'auth', N'TABLE', N'Application', N'ApplicationId'
     , N'Surrogate key. Carried by auth.Tenant, auth.Role, auth.Permission and auth.UiElement, which is what makes the '
     + N'application a scope rather than a label.')
    , (N'auth', N'TABLE', N'Application', N'ApplicationCode'
     , N'The stable identifier used in seed data and deployment scripts, so a script can name an application without '
     + N'knowing its surrogate key. UPPER_SNAKE_CASE by convention. Unique among undeleted rows only, so a withdrawn '
     + N'code can be reissued. Editable, unlike a tenant code: it appears in no session context and in no compiled '
     + N'constraint.')
    , (N'auth', N'TABLE', N'Application', N'ApplicationName'
     , N'The display name, shown wherever a person has to choose between variants.')
    , (N'auth', N'TABLE', N'Application', N'IsActive'
     , N'0 = the application is no longer served. Deliberately NOT read by auth.udfIsTenantUsable: an inactive '
     + N'application is a service decision and an inactive tenant is a scope decision, and conflating them would make '
     + N'retiring a variant silently revoke authority rather than refuse a sign-in.')

    , (N'auth', N'TABLE', N'TenantType', NULL
     , N'The seven seeded tenant types, and any a project adds. Section 5.2: DESCRIPTIVE, NOT FUNCTIONAL -- no '
     + N'authorization decision reads the type, because the moment it does, the shape of one organization''s tree starts '
     + N'affecting another''s authority (P-04). The one structural use is the code Root, which identifies the node with '
     + N'no parent. Seeded by 030_auth_tenant.sql rather than by 115_seed_reference_data.sql, because a tenant cannot be '
     + N'inserted before its type exists.')
    , (N'auth', N'TABLE', N'TenantType', N'TenantTypeId'
     , N'Surrogate key, and the first column of UX_auth_TenantType_Id_Code -- the unfiltered UNIQUE that '
     + N'FK_auth_Tenant_TenantType points at so auth.Tenant can carry the code beside the id.')
    , (N'auth', N'TABLE', N'TenantType', N'TenantTypeCode'
     , N'The stable code. IMMUTABLE -- auth.trg_au_updt_TenantType raises 50010 -- because FK_auth_Tenant_TenantType '
     + N'carries it onto every tenant row and the literal Root is compiled into CK_auth_Tenant_RootHasNoParent. Add a '
     + N'type; never rename one.')
    , (N'auth', N'TABLE', N'TenantType', N'TenantTypeName'
     , N'The display label. Freely editable, which is what the seeding MERGE relies on to converge.')
    , (N'auth', N'TABLE', N'TenantType', N'SortOrder'
     , N'Display order in a picker. The seven seeded types are spaced by ten so a project can insert its own between '
     + N'them without renumbering.')

    , (N'auth', N'TABLE', N'Tenant', NULL
     , N'The tenant hierarchy: one row per node, parent edges only. Every scope in the authorization model is a tenant, '
     + N'including "everything", which is the root -- D-01 and section 5.1 explain why a root exists rather than a NULL '
     + N'or a magic zero meaning no limit. INV-02 is enforced declaratively by two objects together: '
     + N'UX_auth_Tenant_ApplicationRoot gives at most one parentless tenant per application, and '
     + N'CK_auth_Tenant_RootHasNoParent makes parentless and typed Root the same condition. The transitive closure lives '
     + N'in auth.TenantClosure so a scope test is a seek rather than a recursion.')
    , (N'auth', N'TABLE', N'Tenant', N'TenantId'
     , N'Surrogate key, and the single most widely referenced value in the database: every tenant-scoped table carries '
     + N'it, the row-level security predicate compares it, every role grant is scoped by it, and both columns of '
     + N'auth.TenantClosure are it. IDENTITY, so SQL Server rejects an UPDATE against it outright -- which is what makes '
     + N'the key join in auth.trg_au_updt_Tenant sound.')
    , (N'auth', N'TABLE', N'Tenant', N'ApplicationId'
     , N'The owning application. IMMUTABLE after insert; auth.trg_au_updt_Tenant raises 50010. Moving a tenant between '
     + N'applications would leave every profile beneath it holding roles no longer assignable to it, with every row '
     + N'still internally consistent and no error anywhere. Re-parenting WITHIN an application is legitimate and is what '
     + N'auth.uspUpdateTenant does.')
    , (N'auth', N'TABLE', N'Tenant', N'TenantCode'
     , N'The per-application natural key, UPPER_SNAKE_CASE and containing no space. Both rules are enforced by '
     + N'CK_auth_Tenant_TenantCode, the uppercase half under COLLATE Latin1_General_BIN2 because the database collation '
     + N'is case-insensitive and a plain comparison against UPPER() would be a tautology. No space because the code is '
     + N'the middle field of SESSION_CONTEXT(''AppUser''), which is UserName@TenantCode#UserProfileId.')
    , (N'auth', N'TABLE', N'Tenant', N'TenantName'
     , N'The display name. UI-01 requires the acting tenant to be shown on every screen; this is what is shown.')
    , (N'auth', N'TABLE', N'Tenant', N'TenantTypeId'
     , N'The tenant type. Half of the composite foreign key to auth.TenantType; the other half is TenantTypeCode.')
    , (N'auth', N'TABLE', N'Tenant', N'TenantTypeCode'
     , N'DENORMALISED from auth.TenantType and proved correct by FK_auth_Tenant_TenantType against the unfiltered '
     + N'UX_auth_TenantType_Id_Code. It exists so CK_auth_Tenant_RootHasNoParent can be row-local, which a CHECK '
     + N'constraint must be. Reaching the code through a scalar function was measured and rejected: a function '
     + N'referenced by a CHECK cannot afterwards be CREATE OR ALTERed (error 3729), with or without SCHEMABINDING, which '
     + N'breaks re-runnability. A trigger was rejected because it can be disabled and because the fixtures and the '
     + N'bootstrap script insert as db_owner. Never supplied by a caller: auth.uspCreateTenant resolves it from the code '
     + N'it was given. BL-019.')
    , (N'auth', N'TABLE', N'Tenant', N'ParentTenantId'
     , N'The parent node. NULL for the root and only for the root. Self-referencing foreign key, so a parent cannot be '
     + N'named that does not exist; CK_auth_Tenant_NotOwnParent rejects the one-node cycle. Longer cycles cannot be '
     + N'expressed in a CHECK and are rejected by auth.uspUpdateTenant with 50095, which tests the closure.')
    , (N'auth', N'TABLE', N'Tenant', N'IsActive'
     , N'0 = deactivated. Section 5.4: NOT deletion and NOT cascaded. auth.udfIsTenantUsable walks the ancestor chain at '
     + N'read time, so deactivating an administration makes every program under it unusable without writing to any of '
     + N'them -- and reactivating it restores them, which a cascade could not. auth.uspDeactivateTenant sets this and '
     + N'never IsDeleted, and refuses on the root.')

    , (N'auth', N'TABLE', N'TenantClosure', NULL
     , N'The transitive closure of auth.Tenant''s parent edges, INCLUDING the depth-0 self row, so "the scope of a grant '
     + N'at tenant X" is one predicate -- AncestorTenantId = X -- with no special case for X itself. Section 5.3. '
     + N'Rebuilt WHOLE by auth.uspRebuildTenantClosure in one transaction rather than patched incrementally, because a '
     + N're-parenting invalidates a subtree''s ancestors rather than adding to them, and an incremental algorithm that '
     + N'gets that wrong leaves a stale ancestor row that grants authority nobody granted. It deliberately mirrors '
     + N'soft-deleted tenants as well as live ones: if a deleted mid-tree tenant vanished from its descendants'' ancestor '
     + N'set, auth.udfIsTenantUsable would FAIL OPEN. Readers decide usability; this table only records shape. BL-020.')
    , (N'auth', N'TABLE', N'TenantClosure', N'AncestorTenantId'
     , N'The tenant at or above. Equal to DescendantTenantId on the depth-0 self row. Never updated by the rebuild: '
     + N'auth.trg_au_updt_TenantClosure joins inserted and deleted on the key pair, and unlike an IDENTITY column '
     + N'nothing in the engine would stop a statement from changing it and making the trigger stamp the wrong row.')
    , (N'auth', N'TABLE', N'TenantClosure', N'DescendantTenantId'
     , N'The tenant at or below. Leading column of IX_auth_TenantClosure_Descendant, which is the direction '
     + N'auth.udfIsTenantUsable and the row-level security predicate read in.')
    , (N'auth', N'TABLE', N'TenantClosure', N'Depth'
     , N'0 on the self row, 1 for a direct child, and so on. CK_auth_TenantClosure_SelfPair ties depth 0 to the self row '
     + N'in both directions, so a pair such as (X, X, 3) or (X, Y, 0) is rejected here rather than believed by whatever '
     + N'reads it next.');

    -- The audit block, 7 columns on each of 4 tables, generated rather than typed 28 times.  The text is identical on
    -- every table by design: a reviewer comparing two tables should see the same words, and 28 hand-written copies is
    -- how they stop being the same words.
    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    SELECT N'auth', N'TABLE', t.TableName, c.ColumnName, c.Description
      FROM (VALUES (N'Application'), (N'TenantType'), (N'Tenant'), (N'TenantClosure')) AS t (TableName)
     CROSS JOIN (VALUES
            (N'IsDeleted'
           , N'Soft delete. 1 = withdrawn and invisible to every filtered index and every read. There is no hard delete '
           + N'anywhere in this database: logs.DataChangeLog references rows by key, so a removed row would leave the '
           + N'audit trail describing something that no longer exists. Moves together with auditDeletedBy and '
           + N'auditDeletedDateUtc, which the table''s DeletedPair CHECK enforces.')
          , (N'auditDeletedBy'
           , N'Who withdrew the row, from SESSION_CONTEXT(''AppUser'') via the AFTER UPDATE trigger. NULL exactly when '
           + N'IsDeleted = 0.')
          , (N'auditDeletedDateUtc'
           , N'When the row was withdrawn, UTC. Stamped by the AFTER UPDATE trigger with the same instant as '
           + N'auditModifiedDateUtc, not a second SYSUTCDATETIME() call a millisecond boundary could separate.')
          , (N'auditCreatedBy'
           , N'Who created the row. The DEFAULT of ORIGINAL_LOGIN() is a backstop for a direct insert during '
           + N'maintenance: under the pooled application login it records the APPLICATION''s name on every row, '
           + N'identical everywhere and useless as attribution. Every inserting procedure therefore sets this '
           + N'explicitly from SESSION_CONTEXT(''AppUser''). DES-AUTH-001 section 14.4, F-02.')
          , (N'auditCreatedDateUtc'
           , N'When the row was created, UTC. Never updated.')
          , (N'auditModifiedBy'
           , N'Who last changed the row. Maintained by the AFTER UPDATE trigger, which is the only audit column a '
           + N'caller may override -- it passes a value and the trigger keeps it.')
          , (N'auditModifiedDateUtc'
           , N'When the row was last changed, UTC. The column DEFAULTs fire on INSERT only, so without the table''s '
           + N'AFTER UPDATE trigger this would sit at its insert-time value forever.')
          ) AS c (ColumnName, Description);

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
-- Nothing here, and that is INV-11 rather than an omission.  applicationRole holds no table access to SCHEMA::auth at
-- all: scripts/permissions.sql grants on SCHEMA::dbo and SCHEMA::logs only.  The application reaches tenancy through
-- the procedures in database/125_auth_tenant_procedures.sql, which are owned by dbo like every schema here, so
-- ownership chaining gives them access to these tables that their caller does not have.
--
-- That is the difference between "the application can read the tenant tree" and "the application can read the tenant
-- tree the way auth.uspGetTenantTree reads it, having first demanded Tenant.Read".  An object-level SELECT granted here
-- for convenience would remove that distinction permanently and nothing would report it.


-- *** 8. Closing report ***
DECLARE @Report TABLE
(
    RowNo    INT IDENTITY (1, 1) PRIMARY KEY,
    Severity INT             NOT NULL,
    Status   VARCHAR (10)    NOT NULL,
    Item     NVARCHAR (200)  NOT NULL,
    Detail   NVARCHAR (1000)     NULL
);

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (x.FullName, N'U') IS NULL THEN 1 ELSE 4 END
     , CASE WHEN OBJECT_ID (x.FullName, N'U') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Table ' + x.FullName
     , x.Purpose
  FROM (VALUES (N'auth.Application',   N'The outermost scope. D-09.')
             , (N'auth.TenantType',    N'Descriptive types. Section 5.2.')
             , (N'auth.Tenant',        N'The hierarchy. Sections 5.1 and 15.2.')
             , (N'auth.TenantClosure', N'The transitive closure. Section 5.3.')) AS x (FullName, Purpose);

-- The two halves of INV-02, reported separately because either one alone permits a second root.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (N'auth.CK_auth_Tenant_RootHasNoParent', N'C') IS NULL THEN 1 ELSE 4 END
     , CASE WHEN OBJECT_ID (N'auth.CK_auth_Tenant_RootHasNoParent', N'C') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'INV-02 (b) CK_auth_Tenant_RootHasNoParent'
     , N'Ties ParentTenantId IS NULL to TenantTypeCode = Root, in both directions. Without it a non-root could have no '
     + N'parent and become a second root, or a tenant typed Root could be hung under another node.';

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN ix.object_id IS NULL THEN 1 WHEN ix.is_disabled = 1 THEN 1 ELSE 4 END
     , CASE WHEN ix.object_id IS NULL THEN 'MISSING' WHEN ix.is_disabled = 1 THEN 'DISABLED' ELSE 'OK' END
     , N'INV-02 (a) UX_auth_Tenant_ApplicationRoot'
     , N'At most one parentless tenant per application. A filtered unique index is the only declarative way to say that '
     + N'-- a CHECK cannot count rows and a trigger can be disabled.'
  FROM (SELECT 1 AS one) AS o
  LEFT JOIN sys.indexes AS ix ON ix.object_id = OBJECT_ID (N'auth.Tenant') AND ix.name = N'UX_auth_Tenant_ApplicationRoot';

-- Added in Phase 3.  Reported because a reviewer looking at auth.Tenant will see a UNIQUE constraint that duplicates
-- the primary key and be tempted to drop it; the FK in 055 would then be the thing that breaks, in another file.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN kc.name IS NULL THEN 2 ELSE 4 END
     , CASE WHEN kc.name IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'UX_auth_Tenant_Id_Application'
     , N'The unfiltered (TenantId, ApplicationId) pair that FK_auth_Role_OwnerTenant references in '
     + N'055_auth_role.sql, so a role cannot be owned by a tenant belonging to another application. It looks redundant '
     + N'against PK_auth_Tenant and is not: a FOREIGN KEY needs a declared key over exactly these two columns. BL-040.'
  FROM (SELECT 1 AS one) AS o
  LEFT JOIN sys.key_constraints AS kc ON kc.name = N'UX_auth_Tenant_Id_Application'
                                     AND kc.parent_object_id = OBJECT_ID (N'auth.Tenant')
                                     AND kc.type = 'UQ';

-- The audit triggers.  A missing trigger raises no error and breaks nothing visibly: the tables work, and their audit
-- columns quietly stop being maintained on UPDATE.  That is why this is reported rather than left to be noticed.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN tr.object_id IS NULL THEN 1 WHEN tr.is_disabled = 1 THEN 2 ELSE 4 END
     , CASE WHEN tr.object_id IS NULL THEN 'MISSING' WHEN tr.is_disabled = 1 THEN 'DISABLED' ELSE 'OK' END
     , N'Audit trigger ' + x.TriggerName
     , N'Maintains auditModifiedBy, auditModifiedDateUtc and the soft-delete stamp. Without it every UPDATE leaves the '
     + N'audit columns at their insert-time values -- and auth.uspRebuildTenantClosure is all UPDATEs.'
  FROM (VALUES (N'auth.trg_au_updt_Application'), (N'auth.trg_au_updt_TenantType')
             , (N'auth.trg_au_updt_Tenant'),      (N'auth.trg_au_updt_TenantClosure')) AS x (TriggerName)
  LEFT JOIN sys.triggers AS tr ON tr.object_id = OBJECT_ID (x.TriggerName);

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Seeded = 7 THEN 4 WHEN x.Seeded = 0 THEN 1 ELSE 2 END
     , CASE WHEN x.Seeded = 7 THEN 'OK'  WHEN x.Seeded = 0 THEN 'MISSING' ELSE 'PARTIAL' END
     , N'Seeded tenant types'
     , CAST (x.Seeded AS NVARCHAR (10)) + N' of 7 live. Seeded here rather than in 115_seed_reference_data.sql because a '
     + N'tenant cannot be inserted before its type exists. Fewer than 7 is not necessarily wrong -- the MERGE does not '
     + N'resurrect a type a project deliberately withdrew -- but Root must be present or no tree can be built.'
  FROM (SELECT COUNT (*) AS Seeded FROM auth.TenantType WHERE IsDeleted = 0) AS x;

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN EXISTS (SELECT 1 FROM auth.TenantType WHERE TenantTypeCode = N'Root' AND IsDeleted = 0) THEN 4 ELSE 1 END
     , CASE WHEN EXISTS (SELECT 1 FROM auth.TenantType WHERE TenantTypeCode = N'Root' AND IsDeleted = 0) THEN 'OK' ELSE 'MISSING' END
     , N'Tenant type Root'
     , N'CK_auth_Tenant_RootHasNoParent names this code as a literal, so without the row no root tenant can be '
     + N'inserted and no tree can exist.';

-- Live violations, counted rather than assumed.  On a fresh install both are zero because the table is empty; on a
-- re-run against a populated database they are the only evidence that the constraints above have actually held.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Offenders = 0 THEN 4 ELSE 1 END
     , CASE WHEN x.Offenders = 0 THEN 'OK'  ELSE 'VIOLATED' END
     , N'Applications with more than one live root tenant'
     , CAST (x.Offenders AS NVARCHAR (10)) + N' found. Anything but 0 means INV-02 has been broken, which would make '
     + N'"the agency can see everything" ambiguous -- two roots means two answers to the same scope question.'
  FROM (SELECT COUNT (*) AS Offenders
          FROM (SELECT t.ApplicationId
                  FROM auth.Tenant AS t
                 WHERE t.ParentTenantId IS NULL AND t.IsDeleted = 0
                 GROUP BY t.ApplicationId
                HAVING COUNT (*) > 1) AS g) AS x;

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Offenders = 0 THEN 4 ELSE 1 END
     , CASE WHEN x.Offenders = 0 THEN 'OK'  ELSE 'VIOLATED' END
     , N'Live tenants whose parent is in another application'
     , CAST (x.Offenders AS NVARCHAR (10)) + N' found. No constraint can express this -- a composite foreign key onto '
     + N'(TenantId, ApplicationId) would do it, and is not worth a second unique index on a table this small -- so '
     + N'auth.uspUpdateTenant raises 50096 and this count is the standing check that nothing else got there first.'
  FROM (SELECT COUNT (*) AS Offenders
          FROM auth.Tenant AS c
          JOIN auth.Tenant AS p ON p.TenantId = c.ParentTenantId
         WHERE c.IsDeleted = 0 AND c.ApplicationId <> p.ApplicationId) AS x;

-- The closure, which this script creates empty on purpose: it is derived, and the thing that derives it does not exist
-- until database/125_auth_tenant_procedures.sql has run.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Tenants = 0 AND x.Pairs = 0 THEN 4
            WHEN x.Tenants > 0 AND x.Pairs = 0 THEN 2
            WHEN x.Missing  > 0                THEN 1
            ELSE 4 END
     , CASE WHEN x.Tenants = 0 AND x.Pairs = 0 THEN 'OK'
            WHEN x.Tenants > 0 AND x.Pairs = 0 THEN 'PENDING'
            WHEN x.Missing  > 0                THEN 'STALE'
            ELSE 'OK' END
     , N'auth.TenantClosure coverage'
     , CAST (x.Pairs AS NVARCHAR (10)) + N' live pairs for ' + CAST (x.Tenants AS NVARCHAR (10))
     + N' tenants, ' + CAST (x.Missing AS NVARCHAR (10)) + N' tenants with no depth-0 self row. Empty on a fresh '
     + N'install is expected: the closure is derived, and auth.uspRebuildTenantClosure arrives with '
     + N'database/125_auth_tenant_procedures.sql. A tenant with no self row is STALE -- every scope test against it '
     + N'fails closed, so authority silently disappears rather than leaking.'
  FROM (SELECT (SELECT COUNT (*) FROM auth.Tenant AS t WHERE t.IsDeleted = 0) AS Tenants
             , (SELECT COUNT (*) FROM auth.TenantClosure AS c WHERE c.IsDeleted = 0) AS Pairs
             , (SELECT COUNT (*) FROM auth.Tenant AS t
                 WHERE t.IsDeleted = 0
                   AND NOT EXISTS (SELECT 1 FROM auth.TenantClosure AS c
                                    WHERE c.AncestorTenantId = t.TenantId AND c.DescendantTenantId = t.TenantId
                                      AND c.Depth = 0 AND c.IsDeleted = 0)) AS Missing) AS x;

-- Description coverage, counted from sys rather than from the list above, so a column added later without a description
-- is reported by the very next run of this script instead of at review time.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Missing = 0 THEN 4 ELSE 3 END
     , CASE WHEN x.Missing = 0 THEN 'OK'  ELSE 'INCOMPLETE' END
     , N'Column descriptions on the four tenancy tables'
     , CAST (x.Total - x.Missing AS NVARCHAR (10)) + N' of ' + CAST (x.Total AS NVARCHAR (10))
     + N' columns carry MS_Description. Conventions rule 4. If Missing is not 0 and '
     + N'util.uspSetObjectDescription exists, a column was added to this script without a description row in section 6.'
  FROM (SELECT COUNT (*) AS Total
             , SUM (CASE WHEN ep.value IS NULL THEN 1 ELSE 0 END) AS Missing
          FROM sys.columns AS c
          JOIN sys.tables  AS t ON t.object_id = c.object_id
          LEFT JOIN sys.extended_properties AS ep
                 ON ep.major_id = c.object_id AND ep.minor_id = c.column_id AND ep.name = N'MS_Description'
         WHERE t.schema_id = SCHEMA_ID (N'auth')
           AND t.name IN (N'Application', N'TenantType', N'Tenant', N'TenantClosure')) AS x;

IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
    PRINT N'Tenancy tables: PROBLEMS found. Read the report below before running the next script.';
ELSE
    PRINT N'Tenancy tables: no problems found.';

PRINT N'';

SELECT Severity, Status, Item, Detail
  FROM @Report
 ORDER BY Severity, RowNo;
GO



