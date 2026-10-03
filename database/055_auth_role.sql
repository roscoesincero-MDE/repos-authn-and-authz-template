/***********************************************************************************************************************
Script:         055_auth_role.sql
Purpose:        auth.Role and auth.RolePermission -- the administrator's vocabulary, and the only part of the
                authorization model a human is expected to compose.
Target:         SQL Server 2022.
Run as:         db_owner in the target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/055_auth_role.sql
Idempotent:     Yes.  Guarded CREATE TABLE and CREATE INDEX, CREATE OR ALTER triggers, no seed data.
Depends on:     database/005_schemas_and_roles.sql (schema auth), database/030_auth_tenant.sql (auth.Application,
                auth.Tenant and UX_auth_Tenant_Id_Application), database/050_auth_permission.sql (auth.Permission and
                UX_auth_Permission_Id_Application), templates/extended-properties.sql.
Implements:     DES-AUTH-001 sections 8.2, 14.6, 15.4 and 16.2.  PLAN-AUTH-001 task T-044.
To retarget:    Pass it per run:  sqlcmd -d <database> -v DbName=<database>.  There is no in-file default.

THIS FILE CREATES NO TABLE TYPES
--------------------------------
Section 8.2 and section 14.6 D-13.  auth.uspSetRolePermissions and auth.uspAssignRolesToProfiles each take one
@Payload NVARCHAR (MAX) and shred it with OPENJSON, rejecting a malformed payload with E-50046 before touching a table.
G-20 records that this replaced an earlier table-valued-parameter design, and .claude/hooks/validate-sql.py rejects
CREATE TYPE ... AS TABLE outright, so it is not a preference a later script can quietly depart from.

WHY A ROLE IS OWNED BY A TENANT
-------------------------------
Section 8.2.  A role defined at the root is usable anywhere; a role Anne Arundel defines is usable only within Anne
Arundel.  That is INV-04:

    A role R may be granted at scope S only if R.OwnerTenantId is an ancestor-or-self of S.

Ownership is what makes role DEFINITION delegable without collision, and it disposes of a trap the source requirements
contain on purpose: the agency's role 'D' and Anne Arundel's role 'D1' are different rows in different scopes, and
Baltimore City's role 'E2' shares a name with an agency USER called E2, which matters not at all because they are in
different tables and no code anywhere compares a role code to a literal.

That last point is worth keeping in view, because it is the difference between this table and auth.Permission.  A
permission code IS a literal in procedure bodies; a role code is never one.  So auth.Permission has no administrative
screen and auth.Role is nothing but administrative screen, and RoleCode is editable where PermissionCode is not.

INV-04 IS NOT ENFORCED HERE, AND THE REASON IS NOT LAZINESS
-----------------------------------------------------------
"Ancestor-or-self" is a question about auth.TenantClosure, asked of a row in auth.UserProfileRole -- two tables away
from this one.  A role's owner tenant is legal whatever it is; what can be illegal is a GRANT of that role at a scope
the owner does not cover, and 060_auth_profile_role.sql is where that row lives and where the check belongs (E-50042).

What IS enforced here is the half of D-09 that can be: FK_auth_Role_OwnerTenant references the unfiltered pair
(TenantId, ApplicationId) on auth.Tenant, so a role cannot be owned by a tenant belonging to a different application.
Without it INV-04 would eventually be asked to compare tenants in two unrelated trees, where the answer is not false but
meaningless -- and E-50043 ("role and target profile belong to different applications") would be catching at grant time
something that should never have been storable.  BL-040.

auth.RolePermission carries ApplicationId for the same reason and gets more out of it: the column is pinned by TWO
composite foreign keys, one to auth.Role and one to auth.Permission, so the role and the permission it maps must agree
about the application.  Nothing needs to remember to check it.

WHAT IsSystemRole PROTECTS, AND FROM WHOM
-----------------------------------------
INV-10.  The sixteen baseline roles -- section 16.2's fourteen plus CRUD_ACCESS and PROFILE_ASSIGNER,
which T-128 added on 2026-09-21 for gaps G-46 and G-47 -- are seeded with IsSystemRole = 1 and E-50012 refuses an attempt to
modify one.  The protection is split deliberately:

  *  auth.trg_au_updt_Role refuses, on a system role, a change of RoleCode, a clearing of IsSystemRole, and a soft
     delete.  These are the changes that would break a later re-run of 115_seed_reference_data.sql or leave a deployment
     without a role that 900_bootstrap_first_admin.sql grants by name.  A trigger, because a trigger cannot be bypassed
     by an UPDATE that skips the procedure.
  *  RoleName and RoleDescription remain editable on a system role, because 115_seed_reference_data.sql converges them
     by MERGE: improving the wording of a shipped role's description is exactly what that MERGE is for.
  *  The system role's PERMISSION LIST is protected in auth.uspSetRolePermissions (145_auth_role_procedures.sql,
     Phase 6), NOT in a trigger -- because the same MERGE has to be able to add a permission to a baseline role when the
     template's definition of it changes.  An administrator reaching that table goes through the procedure; the seed
     does not.

The line is therefore "an administrator may not edit a system role; the template may".  A trigger cannot tell those two
apart, which is why only the changes the template never makes are enforced there.

IsAssignable IS NOT IsActive
----------------------------
IsAssignable = 0 means the role's definition stands and its existing grants keep working, but no NEW grant of it may be
made -- a role being retired, or one composed for a migration that should not spread.  Revoking it from everyone would
destroy the record of who held it (P-07), and soft-deleting it would take the answer to "what did this role mean last
March" with it (section 8.2).  The enforcement point is auth.uspAssignRoleToProfile in Phase 6, E-50047, and there is
nothing for this script to check: an unassignable role is a perfectly legal row.
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

IF OBJECT_ID (N'auth.Tenant', N'U') IS NULL OR OBJECT_ID (N'auth.Permission', N'U') IS NULL
BEGIN
    DECLARE @MsgParents NVARCHAR (2000) =
        N'auth.Tenant or auth.Permission is missing. Run database/030_auth_tenant.sql and '
      + N'database/050_auth_permission.sql first. Nothing has been changed.';

    THROW 50000, @MsgParents, 1;
END
GO

-- The two unfiltered pairs this file's composite foreign keys reference.  Asserted by name and BEFORE any DDL, because
-- the alternative is a CREATE TABLE that fails with SQL Server's own message -- "there are no primary or candidate keys
-- in the referenced table matching the referencing column list" -- which names neither the constraint that is missing
-- nor the script that creates it.
IF NOT EXISTS (SELECT 1 FROM sys.key_constraints
                WHERE name = N'UX_auth_Tenant_Id_Application' AND type = 'UQ')
   OR NOT EXISTS (SELECT 1 FROM sys.key_constraints
                   WHERE name = N'UX_auth_Permission_Id_Application' AND type = 'UQ')
BEGIN
    DECLARE @MsgPairs NVARCHAR (2000) =
        N'A required unfiltered UNIQUE constraint is missing. auth.Role needs UX_auth_Tenant_Id_Application on '
      + N'auth.Tenant (added by database/030_auth_tenant.sql) and auth.RolePermission needs '
      + N'UX_auth_Permission_Id_Application on auth.Permission (database/050_auth_permission.sql). They are what make a '
      + N'cross-application role definition structurally impossible -- D-09, BL-040. Re-run those two scripts. Nothing '
      + N'has been changed.';

    THROW 50000, @MsgPairs, 1;
END
GO


-- *** 1. auth.Role ***
IF OBJECT_ID (N'auth.Role', N'U') IS NULL
BEGIN
    CREATE TABLE auth.Role
    (
        RoleId               INT             IDENTITY (1, 1) NOT NULL
      , ApplicationId        INT                             NOT NULL

        -- Section 8.2.  Where the role was DEFINED, which bounds where it may be GRANTED (INV-04) -- not where it is
        -- granted, which is auth.UserProfileRole.ScopeTenantId and may be any descendant of this one.
      , OwnerTenantId        INT                             NOT NULL

      , RoleCode             NVARCHAR (100)                  NOT NULL
      , RoleName             NVARCHAR (200)                  NOT NULL

        -- BL-037, the same addition to section 15.4 as auth.Permission.PermissionDescription and for the same reason:
        -- the role editor has to tell an administrator what granting DATA_STEWARD actually confers, and the alternative
        -- is that sentence living in the UI project where nobody maintaining roles would find it.
      , RoleDescription      NVARCHAR (1000)                     NULL

        -- 0 retires the role without destroying it: existing grants keep working, no new grant may be made.  See the
        -- header -- this is not IsActive and not a soft delete.
      , IsAssignable         BIT                             NOT NULL
            CONSTRAINT DF_auth_Role_IsAssignable DEFAULT (1)

        -- INV-10.  Set only by 115_seed_reference_data.sql and 900_bootstrap_first_admin.sql.
      , IsSystemRole         BIT                             NOT NULL
            CONSTRAINT DF_auth_Role_IsSystemRole DEFAULT (0)

      , IsDeleted            BIT                             NOT NULL
            CONSTRAINT DF_auth_Role_IsDeleted DEFAULT (0)
      , auditDeletedBy       NVARCHAR (255)                      NULL
      , auditDeletedDateUtc  DATETIME2 (3)                       NULL
      , auditCreatedBy       NVARCHAR (255)                  NOT NULL
            CONSTRAINT DF_auth_Role_auditCreatedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditCreatedDateUtc  DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_Role_auditCreatedDateUtc DEFAULT (SYSUTCDATETIME ())
      , auditModifiedBy      NVARCHAR (255)                  NOT NULL
            CONSTRAINT DF_auth_Role_auditModifiedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditModifiedDateUtc DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_Role_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ())

      , CONSTRAINT PK_auth_Role PRIMARY KEY CLUSTERED (RoleId)

        -- Unfiltered, contains the primary key, exists to be referenced by auth.RolePermission below.  Fourth use of
        -- the pattern in this database; UX_auth_TenantType_Id_Code carries the argument in full.
      , CONSTRAINT UX_auth_Role_Id_Application UNIQUE (RoleId, ApplicationId)

      , CONSTRAINT FK_auth_Role_Application
            FOREIGN KEY (ApplicationId) REFERENCES auth.Application (ApplicationId)

        -- COMPOSITE, and that is the point: the owner tenant must belong to THIS role's application.  D-09.
      , CONSTRAINT FK_auth_Role_OwnerTenant
            FOREIGN KEY (OwnerTenantId, ApplicationId)
            REFERENCES auth.Tenant (TenantId, ApplicationId)

        -- UPPER_SNAKE_CASE, Appendix C.  COLLATE Latin1_General_BIN2 on the uppercase test for the reason
        -- CK_auth_Tenant_TenantCode gives: the database collation is case-insensitive and a plain comparison against
        -- UPPER () would be a tautology that passes everything.  The character-class test is what rejects a dot, which
        -- would make a role code look like a permission code in a log line.
      , CONSTRAINT CK_auth_Role_RoleCode
            CHECK (LEN (RoleCode) > 0
               AND RoleCode = LTRIM (RTRIM (RoleCode))
               AND RoleCode NOT LIKE N'%[^A-Z0-9_]%'
               AND RoleCode COLLATE Latin1_General_BIN2 = UPPER (RoleCode) COLLATE Latin1_General_BIN2)

      , CONSTRAINT CK_auth_Role_RoleName
            CHECK (LEN (RoleName) > 0 AND RoleName = LTRIM (RTRIM (RoleName)))

      , CONSTRAINT CK_auth_Role_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS     NULL AND auditDeletedDateUtc IS     NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL))
    );
END
GO

-- The natural key of section 15.4.  Filtered, so a retired role code can be reissued -- and scoped to the owner tenant,
-- which is what lets the agency and Anne Arundel each define a role called REVIEWER without either knowing about the
-- other.  That independence is the whole of section 8.2's delegation argument.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'UX_auth_Role_Code' AND object_id = OBJECT_ID (N'auth.Role'))
BEGIN
    CREATE UNIQUE INDEX UX_auth_Role_Code
        ON auth.Role (ApplicationId, OwnerTenantId, RoleCode) WHERE IsDeleted = 0;
END
GO

-- "Which roles may I grant here?" -- the role picker, which asks for every role whose owner is an ancestor-or-self of
-- the scope and therefore seeks this index once per ancestor.  IsAssignable is INCLUDEd rather than filtered on: the
-- role EDITOR needs the unassignable ones too, and one index serving both readers beats two.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_auth_Role_Owner' AND object_id = OBJECT_ID (N'auth.Role'))
BEGIN
    CREATE INDEX IX_auth_Role_Owner
        ON auth.Role (OwnerTenantId, ApplicationId)
        INCLUDE (RoleCode, RoleName, IsAssignable, IsSystemRole) WHERE IsDeleted = 0;
END
GO

-- FK_auth_TenantDefaultRole_Role.  035 builds auth.TenantDefaultRole before this table exists, so it can only add the
-- key on a later pass; without this block a single-pass install -- the normal one -- never had it.  Same guard and
-- same WITH CHECK as 035, so whichever runs second finds it present and adds nothing.
IF OBJECT_ID (N'auth.TenantDefaultRole', N'U') IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = N'FK_auth_TenantDefaultRole_Role')
BEGIN
    ALTER TABLE auth.TenantDefaultRole WITH CHECK
        ADD CONSTRAINT FK_auth_TenantDefaultRole_Role FOREIGN KEY (RoleId)
            REFERENCES auth.Role (RoleId);

    PRINT N'  FK_auth_TenantDefaultRole_Role added -- auth.TenantDefaultRole (035) now references auth.Role.';
END
GO


-- *** 2. auth.RolePermission ***
--
-- What a role MEANS.  Soft-deleted like everything else, so "what did this role confer last March" is answerable from
-- the audit columns without temporal tables -- D-11.
IF OBJECT_ID (N'auth.RolePermission', N'U') IS NULL
BEGIN
    CREATE TABLE auth.RolePermission
    (
        RolePermissionId     INT             IDENTITY (1, 1) NOT NULL
      , RoleId               INT                             NOT NULL
      , PermissionId         INT                             NOT NULL

        -- DENORMALISED, and load-bearing.  Pinned by both composite foreign keys below, so the role and the permission
        -- cannot disagree about which application they belong to.  A caller never supplies it -- auth.uspSetRolePermissions
        -- resolves it from the role -- and the trigger in section 3 refuses to let it change.
      , ApplicationId        INT                             NOT NULL

      , IsDeleted            BIT                             NOT NULL
            CONSTRAINT DF_auth_RolePermission_IsDeleted DEFAULT (0)
      , auditDeletedBy       NVARCHAR (255)                      NULL
      , auditDeletedDateUtc  DATETIME2 (3)                       NULL
      , auditCreatedBy       NVARCHAR (255)                  NOT NULL
            CONSTRAINT DF_auth_RolePermission_auditCreatedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditCreatedDateUtc  DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_RolePermission_auditCreatedDateUtc DEFAULT (SYSUTCDATETIME ())
      , auditModifiedBy      NVARCHAR (255)                  NOT NULL
            CONSTRAINT DF_auth_RolePermission_auditModifiedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditModifiedDateUtc DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_RolePermission_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ())

        -- A surrogate key rather than the (RoleId, PermissionId) pair, because the pair's uniqueness has to be FILTERED
        -- on IsDeleted = 0 -- removing a permission from a role and putting it back is an ordinary thing to do, and a
        -- primary key on the pair would refuse the second row and force a hard delete this database does not have.
      , CONSTRAINT PK_auth_RolePermission PRIMARY KEY CLUSTERED (RolePermissionId)

      , CONSTRAINT FK_auth_RolePermission_Role
            FOREIGN KEY (RoleId, ApplicationId)
            REFERENCES auth.Role (RoleId, ApplicationId)

      , CONSTRAINT FK_auth_RolePermission_Permission
            FOREIGN KEY (PermissionId, ApplicationId)
            REFERENCES auth.Permission (PermissionId, ApplicationId)

      , CONSTRAINT CK_auth_RolePermission_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS     NULL AND auditDeletedDateUtc IS     NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL))
    );
END
GO

-- One live mapping per (role, permission).  Also the index auth.uspRebuildProfilePermissionScope reads: RoleId leads,
-- so "every permission of these roles" is a seek per role rather than a scan, and PermissionId is in the key so the
-- seek is covering.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'UX_auth_RolePermission_Pair' AND object_id = OBJECT_ID (N'auth.RolePermission'))
BEGIN
    CREATE UNIQUE INDEX UX_auth_RolePermission_Pair
        ON auth.RolePermission (RoleId, PermissionId) WHERE IsDeleted = 0;
END
GO

-- The reverse question, which is an impact analysis rather than a permission check: "which roles confer Data.Export?"
-- Asked by the role editor and by anyone auditing a permission before removing it from the catalogue.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_auth_RolePermission_Permission' AND object_id = OBJECT_ID (N'auth.RolePermission'))
BEGIN
    CREATE INDEX IX_auth_RolePermission_Permission
        ON auth.RolePermission (PermissionId) INCLUDE (RoleId) WHERE IsDeleted = 0;
END
GO


-- *** 3. Audit triggers ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.trg_au_updt_Role
Author:       rsincero
CreateDate:   2026-09-20
Description:
AFTER UPDATE audit stamp for auth.Role, plus two guards.

E-50010: ApplicationId and OwnerTenantId are immutable.  Re-pointing either one changes INV-04's answer for every grant
the role already has -- moving ownership up the tree silently WIDENS every existing grant's legality, and moving it down
or sideways silently invalidates grants that remain in force because nothing re-checks a stored row.  Defining a new role
and retiring this one leaves a trail; editing this column does not.

E-50012: INV-10, narrowly.  On a row with IsSystemRole = 1 this refuses a change of RoleCode, a clearing of
IsSystemRole, and a soft delete.  It deliberately permits RoleName and RoleDescription to change, because
115_seed_reference_data.sql converges those by MERGE, and it says nothing at all about the permission list, which
auth.uspSetRolePermissions protects instead -- the file header explains why the line falls there.

Modification History:
2026-09-20  rsincero  Created.  PLAN-AUTH-001 T-044.
***********************************************************************************************************************/
CREATE OR ALTER TRIGGER auth.trg_au_updt_Role
    ON auth.Role
    AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    IF (UPDATE (ApplicationId) OR UPDATE (OwnerTenantId))
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.RoleId = i.RoleId
                    WHERE i.ApplicationId <> d.ApplicationId
                       OR i.OwnerTenantId <> d.OwnerTenantId)
    BEGIN
        ;THROW 50010, N'auth.Role.ApplicationId and OwnerTenantId are immutable: ownership bounds where the role may be granted (INV-04), and moving it silently widens or invalidates every grant already in force, because nothing re-checks a stored grant. Define the role you want and retire this one.', 1;
    END;

    IF EXISTS (SELECT 1
                 FROM inserted AS i
                 JOIN deleted  AS d ON d.RoleId = i.RoleId
                WHERE d.IsSystemRole = 1
                  AND (i.RoleCode COLLATE Latin1_General_BIN2 <> d.RoleCode COLLATE Latin1_General_BIN2
                       OR i.IsSystemRole = 0
                       OR (d.IsDeleted = 0 AND i.IsDeleted = 1)))
    BEGIN
        ;THROW 50012, N'INV-10: this is a system role. Its code cannot be changed, its IsSystemRole flag cannot be cleared, and it cannot be deleted -- 900_bootstrap_first_admin.sql grants several of them by code, and 115_seed_reference_data.sql re-seeds them on every deployment. RoleName and RoleDescription may be edited; the permission list is changed through auth.uspSetRolePermissions.', 1;
    END;

    DECLARE @Now   DATETIME2 (3)  = SYSUTCDATETIME ()
          , @Actor NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                            , ORIGINAL_LOGIN ());

    UPDATE r
       SET r.auditModifiedDateUtc = @Now
         , r.auditModifiedBy      = CASE WHEN UPDATE (auditModifiedBy)
                                         THEN COALESCE (NULLIF (i.auditModifiedBy, N''), @Actor)
                                         ELSE @Actor END
         , r.auditDeletedBy       = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Actor ELSE r.auditDeletedBy      END
         , r.auditDeletedDateUtc  = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Now   ELSE r.auditDeletedDateUtc END
      FROM auth.Role AS r
      JOIN inserted  AS i ON i.RoleId = r.RoleId
      JOIN deleted   AS d ON d.RoleId = r.RoleId;
END;
GO

/***********************************************************************************************************************
ObjectName:   auth.trg_au_updt_RolePermission
Author:       rsincero
CreateDate:   2026-09-20
Description:
AFTER UPDATE audit stamp for auth.RolePermission, and the guard that makes all three key columns immutable -- E-50010.

RoleId, PermissionId and ApplicationId are immutable because this table has no attributes: the row IS the mapping, and
"changing" it is removing one mapping and adding another.  Permitting an update would let a role's meaning change with
IsDeleted, auditCreatedDateUtc and auditDeletedDateUtc all still describing the OLD mapping -- which is precisely the
history D-11 says this table is the record of.  Soft-delete the row and insert the replacement.

Modification History:
2026-09-20  rsincero  Created.  PLAN-AUTH-001 T-044.
***********************************************************************************************************************/
CREATE OR ALTER TRIGGER auth.trg_au_updt_RolePermission
    ON auth.RolePermission
    AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    IF (UPDATE (RoleId) OR UPDATE (PermissionId) OR UPDATE (ApplicationId))
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.RolePermissionId = i.RolePermissionId
                    WHERE i.RoleId        <> d.RoleId
                       OR i.PermissionId  <> d.PermissionId
                       OR i.ApplicationId <> d.ApplicationId)
    BEGIN
        ;THROW 50010, N'auth.RolePermission.RoleId, PermissionId and ApplicationId are immutable: the row IS the mapping, so changing it would leave the audit columns describing a mapping that no longer exists -- and that history is what D-11 says this table is for. Soft-delete the row and insert the replacement.', 1;
    END;

    DECLARE @Now   DATETIME2 (3)  = SYSUTCDATETIME ()
          , @Actor NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                            , ORIGINAL_LOGIN ());

    UPDATE rp
       SET rp.auditModifiedDateUtc = @Now
         , rp.auditModifiedBy      = CASE WHEN UPDATE (auditModifiedBy)
                                          THEN COALESCE (NULLIF (i.auditModifiedBy, N''), @Actor)
                                          ELSE @Actor END
         , rp.auditDeletedBy       = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Actor ELSE rp.auditDeletedBy      END
         , rp.auditDeletedDateUtc  = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Now   ELSE rp.auditDeletedDateUtc END
      FROM auth.RolePermission AS rp
      JOIN inserted            AS i ON i.RolePermissionId = rp.RolePermissionId
      JOIN deleted             AS d ON d.RolePermissionId = rp.RolePermissionId;
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
      (N'auth', N'TABLE', N'Role', NULL
     , N'A named bundle of permissions, OWNED BY A TENANT and scoped to an application -- section 8.2. Ownership is '
     + N'what makes role definition delegable without collision: a role defined at the root is grantable anywhere, one '
     + N'defined at Anne Arundel only within Anne Arundel (INV-04). Unlike auth.Permission this table is entirely '
     + N'administrative -- no code anywhere compares a role code to a literal.')
    , (N'auth', N'TABLE', N'Role', N'RoleId'
     , N'Surrogate key. Half of UX_auth_Role_Id_Application, the unfiltered pair auth.RolePermission''s composite '
     + N'foreign key references.')
    , (N'auth', N'TABLE', N'Role', N'ApplicationId'
     , N'The application the role belongs to -- D-09. IMMUTABLE (E-50010). Pinned to OwnerTenantId''s application by '
     + N'FK_auth_Role_OwnerTenant, so a role cannot be owned by a tenant in another application''s tree.')
    , (N'auth', N'TABLE', N'Role', N'OwnerTenantId'
     , N'Where the role was DEFINED, which bounds where it may be GRANTED: INV-04 requires the owner to be an '
     + N'ancestor-or-self of the grant''s scope, and 060_auth_profile_role.sql enforces it with E-50042. Not where it '
     + N'IS granted -- that is auth.UserProfileRole.ScopeTenantId. IMMUTABLE (E-50010): moving ownership would silently '
     + N'widen or invalidate every grant already in force, because nothing re-checks a stored grant.')
    , (N'auth', N'TABLE', N'Role', N'RoleCode'
     , N'UPPER_SNAKE_CASE (Appendix C), unique per (application, owner tenant) among live rows. Editable for an '
     + N'ordinary role, because no code compares it to a literal; frozen on a system role (E-50012), because '
     + N'900_bootstrap_first_admin.sql grants several by code.')
    , (N'auth', N'TABLE', N'Role', N'RoleName'
     , N'The label in the role picker. Editable even on a system role, because 115_seed_reference_data.sql converges '
     + N'it by MERGE.')
    , (N'auth', N'TABLE', N'Role', N'RoleDescription'
     , N'What granting this role actually confers, in a sentence an administrator can act on. An addition to section '
     + N'15.4, BL-037, on the same argument as auth.Permission.PermissionDescription.')
    , (N'auth', N'TABLE', N'Role', N'IsAssignable'
     , N'0 retires the role: its definition stands, its existing grants keep working, and no NEW grant may be made '
     + N'(E-50047, auth.uspAssignRoleToProfile). NOT a soft delete and not IsActive -- revoking from everyone would '
     + N'destroy the record of who held it (P-07) and deleting would take "what did this role mean last March" with it.')
    , (N'auth', N'TABLE', N'Role', N'IsSystemRole'
     , N'1 marks one of the sixteen baseline roles: section 16.2''s fourteen plus CRUD_ACCESS and PROFILE_ASSIGNER (T-128). INV-10: the trigger refuses a change of RoleCode, '
     + N'a clearing of this flag, and a soft delete (E-50012); RoleName and RoleDescription stay editable so the seed '
     + N'MERGE converges; the permission list is protected in auth.uspSetRolePermissions instead, because that same '
     + N'MERGE has to be able to change what a baseline role means when the template does.')

    , (N'auth', N'TABLE', N'RolePermission', NULL
     , N'What a role MEANS -- its permission list. Soft-deleted like everything else, which is what makes "what did '
     + N'this role confer last March" answerable without temporal tables (D-11). Written only by '
     + N'auth.uspSetRolePermissions and by 115_seed_reference_data.sql.')
    , (N'auth', N'TABLE', N'RolePermission', N'RolePermissionId'
     , N'Surrogate key, used in preference to the (RoleId, PermissionId) pair because that pair''s uniqueness must be '
     + N'FILTERED on IsDeleted = 0: removing a permission from a role and later restoring it is ordinary, and a primary '
     + N'key on the pair would refuse the second row and force a hard delete this database does not have.')
    , (N'auth', N'TABLE', N'RolePermission', N'RoleId'
     , N'The role. IMMUTABLE (E-50010) -- the row IS the mapping, so changing it would leave the audit columns '
     + N'describing a mapping that no longer exists.')
    , (N'auth', N'TABLE', N'RolePermission', N'PermissionId'
     , N'The permission. IMMUTABLE (E-50010).')
    , (N'auth', N'TABLE', N'RolePermission', N'ApplicationId'
     , N'Denormalised and load-bearing: pinned by BOTH composite foreign keys, so the role and the permission cannot '
     + N'disagree about which application they belong to. Without it, granting application 3''s permission to '
     + N'application 2''s role would be a storable row that auth.udfHasPermission would then answer with. IMMUTABLE '
     + N'(E-50010); resolved from the role by auth.uspSetRolePermissions, never supplied by a caller.');

    -- The seven audit columns carry the same description on every table, so they are generated rather than typed out.
    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    SELECT N'auth', N'TABLE', t.TableName, c.ColumnName, c.Description
      FROM (VALUES (N'Role'), (N'RolePermission')) AS t (TableName)
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
    VALUES (N'auth', N'TRIGGER', N'trg_au_updt_Role', NULL
          , N'AFTER UPDATE audit stamp for auth.Role. E-50010 makes ApplicationId and OwnerTenantId immutable; E-50012 '
          + N'is INV-10, narrowly -- on a system role it refuses a change of code, a clearing of the flag, and a soft '
          + N'delete, while leaving the name and description editable for the seed MERGE.')
         , (N'auth', N'TRIGGER', N'trg_au_updt_RolePermission', NULL
          , N'AFTER UPDATE audit stamp for auth.RolePermission, and the guard that makes all three key columns '
          + N'immutable -- E-50010.');

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
-- DELIBERATELY EMPTY.  INV-11: the application reaches auth.Role and auth.RolePermission only through the role-editor
-- procedures, by ownership chaining, and 170_permissions.sql states the absence with a schema-level DENY.  A direct
-- SELECT grant here would let a client read every role definition in every tenant, which is the map an attacker needs
-- before choosing which grant to try to obtain.
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
SELECT CASE WHEN OBJECT_ID (x.QualifiedName, N'U') IS NULL THEN 1 ELSE 4 END
     , CASE WHEN OBJECT_ID (x.QualifiedName, N'U') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Table ' + x.QualifiedName
     , x.Purpose
  FROM (VALUES (N'auth.Role',           N'The administrator''s vocabulary, owned by a tenant. Sections 8.2 and 15.4.')
             , (N'auth.RolePermission', N'What a role means. Soft-deleted, so last March is answerable -- D-11.'))
       AS x (QualifiedName, Purpose);

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN i.name IS NULL THEN 2 WHEN i.is_disabled = 1 THEN 2 ELSE 4 END
     , CASE WHEN i.name IS NULL THEN 'MISSING' WHEN i.is_disabled = 1 THEN 'DISABLED' ELSE 'OK' END
     , N'Index ' + x.IndexName
     , x.Purpose
  FROM (VALUES (N'UX_auth_Role_Code',                 N'auth.Role',           N'UNIQUE on (ApplicationId, OwnerTenantId, RoleCode) where live -- the natural key. Scoped to the owner, which is what lets two tenants each define REVIEWER.')
             , (N'IX_auth_Role_Owner',                N'auth.Role',           N'"Which roles may I grant here?" -- one seek per ancestor tenant.')
             , (N'UX_auth_RolePermission_Pair',       N'auth.RolePermission', N'One live mapping per (role, permission), and the index auth.uspRebuildProfilePermissionScope seeks.')
             , (N'IX_auth_RolePermission_Permission', N'auth.RolePermission', N'"Which roles confer Data.Export?" -- impact analysis before a permission is retired.'))
       AS x (IndexName, TableName, Purpose)
  LEFT JOIN sys.indexes AS i ON i.name = x.IndexName AND i.object_id = OBJECT_ID (x.TableName);

-- The three composite foreign keys that carry D-09 structurally.  Reported by name because each one looks like it could
-- be simplified to a single-column reference, and each simplification opens a different cross-application hole.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN fk.name IS NULL THEN 1 WHEN fk.is_disabled = 1 THEN 1 ELSE 4 END
     , CASE WHEN fk.name IS NULL THEN 'MISSING' WHEN fk.is_disabled = 1 THEN 'DISABLED' ELSE 'OK' END
     , N'D-09 ' + x.ConstraintName
     , x.Purpose
  FROM (VALUES (N'FK_auth_Role_OwnerTenant',          N'(OwnerTenantId, ApplicationId) -> auth.Tenant. A role cannot be owned by a tenant in another application''s tree, so INV-04 is never asked to compare tenants across two unrelated trees.')
             , (N'FK_auth_RolePermission_Role',       N'(RoleId, ApplicationId) -> auth.Role. Pins the mapping''s application to the role''s.')
             , (N'FK_auth_RolePermission_Permission', N'(PermissionId, ApplicationId) -> auth.Permission. Pins the same column to the permission''s, so the two must agree.'))
       AS x (ConstraintName, Purpose)
  LEFT JOIN sys.foreign_keys AS fk ON fk.name = x.ConstraintName;

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN tr.object_id IS NULL THEN 1 WHEN tr.is_disabled = 1 THEN 1 ELSE 4 END
     , CASE WHEN tr.object_id IS NULL THEN 'MISSING' WHEN tr.is_disabled = 1 THEN 'DISABLED' ELSE 'OK' END
     , N'Trigger ' + x.QualifiedName
     , x.Purpose
  FROM (VALUES (N'auth.trg_au_updt_Role',           N'Audit stamp, E-50010 on ApplicationId and OwnerTenantId, and INV-10/E-50012 on a system role. DISABLED here is a security finding, not a performance choice.')
             , (N'auth.trg_au_updt_RolePermission', N'Audit stamp, and E-50010 on all three key columns.'))
       AS x (QualifiedName, Purpose)
  LEFT JOIN sys.triggers AS tr ON tr.object_id = OBJECT_ID (x.QualifiedName);

-- No table types, asserted rather than assumed.  G-20 and D-13: the gate rejects CREATE TYPE ... AS TABLE, but a type
-- created by hand on a live database would not be caught by a gate that only reads files.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.TableTypes = 0 THEN 4 ELSE 2 END
     , CASE WHEN x.TableTypes = 0 THEN 'OK' ELSE 'VIOLATION' END
     , N'No table types exist in schema auth'
     , CASE WHEN x.TableTypes = 0
            THEN N'Correct. The bulk shapes take one @Payload NVARCHAR (MAX) shredded by OPENJSON and reject a '
               + N'malformed payload with E-50046 -- D-13, G-20. The .claude/hooks/validate-sql.py gate rejects '
               + N'CREATE TYPE ... AS TABLE, but a type created by hand on a live database would not be caught by a '
               + N'gate that only reads files, so it is checked here too.'
            ELSE CAST (x.TableTypes AS NVARCHAR (11)) + N' table type(s) exist in schema auth. Something created one '
               + N'outside the scripted path. D-13 and G-20 say why they are not used here.'
       END
  FROM (SELECT TableTypes = (SELECT COUNT (*) FROM sys.table_types AS tt
                              WHERE SCHEMA_NAME (tt.schema_id) = N'auth')) AS x;

INSERT @Report (Severity, Status, Item, Detail)
SELECT 3, 'INFO', N'Roles defined'
     , CASE WHEN x.Roles = 0
            THEN N'None. Expected at this point: the sixteen baseline roles (section 16.2''s fourteen plus CRUD_ACCESS and PROFILE_ASSIGNER, T-128) are seeded by '
               + N'115_seed_reference_data.sql, owned by the root tenant so they are grantable anywhere (INV-04), and '
               + N'nothing structural needs them before then.'
            ELSE CAST (x.Roles AS NVARCHAR (11)) + N' live role(s), of which '
               + CAST (x.SystemRoles AS NVARCHAR (11)) + N' system (section 16.2 ships 14 per application) and '
               + CAST (x.Unassignable AS NVARCHAR (11)) + N' retired (IsAssignable = 0). '
               + CAST (x.Mappings AS NVARCHAR (11)) + N' live role-permission mapping(s).'
       END
  FROM (SELECT Roles        = (SELECT COUNT (*) FROM auth.Role WHERE IsDeleted = 0)
             , SystemRoles  = (SELECT COUNT (*) FROM auth.Role WHERE IsDeleted = 0 AND IsSystemRole = 1)
             , Unassignable = (SELECT COUNT (*) FROM auth.Role WHERE IsDeleted = 0 AND IsAssignable = 0)
             , Mappings     = (SELECT COUNT (*) FROM auth.RolePermission WHERE IsDeleted = 0)) AS x;

-- A live mapping whose role or permission has been soft-deleted.  Not preventable declaratively -- a foreign key cannot
-- see IsDeleted -- and not an error: the mapping is filtered out wherever it matters, because
-- auth.uspRebuildProfilePermissionScope joins through both tables on IsDeleted = 0.  Reported because a growing count
-- means the procedures that soft-delete a role are not tidying up after themselves, and the role editor will show a
-- permission list with holes in it.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Orphans = 0 THEN 4 ELSE 3 END
     , CASE WHEN x.Orphans = 0 THEN 'OK' ELSE 'REVIEW' END
     , N'Every live mapping points at a live role and a live permission'
     , CASE WHEN x.Orphans = 0
            THEN N'Yes. A foreign key cannot see IsDeleted, so this is a convention rather than a constraint.'
            ELSE CAST (x.Orphans AS NVARCHAR (11)) + N' live auth.RolePermission row(s) reference a soft-deleted role '
               + N'or permission. Harmless to authorization -- auth.uspRebuildProfilePermissionScope joins through '
               + N'both on IsDeleted = 0 -- but it means whatever soft-deleted the parent did not tidy up, and the '
               + N'role editor will show a list with holes in it.'
       END
  FROM (SELECT Orphans = (SELECT COUNT (*)
                            FROM auth.RolePermission AS rp
                            LEFT JOIN auth.Role       AS r ON r.RoleId       = rp.RoleId       AND r.IsDeleted = 0
                            LEFT JOIN auth.Permission AS p ON p.PermissionId = rp.PermissionId AND p.IsDeleted = 0
                           WHERE rp.IsDeleted = 0
                             AND (r.RoleId IS NULL OR p.PermissionId IS NULL))) AS x;

INSERT @Report (Severity, Status, Item, Detail)
VALUES (3, 'NEXT', N'Next scripts'
      , N'060_auth_profile_role.sql (auth.UserProfileRole -- the grant itself, and where INV-04 is enforced with '
      + N'E-50042), then 065_auth_effective_permission.sql (auth.ProfilePermissionScope and its rebuild). The baseline '
      + N'roles arrive at 115_seed_reference_data.sql.');

IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
    PRINT N'Roles and role permissions: PROBLEMS found. Read the report below before running the next script.';
ELSE
    PRINT N'Roles and role permissions: no problems found.';

PRINT N'';

SELECT Severity, Status, Item, Detail
  FROM @Report
 ORDER BY Severity, RowNo;
GO
