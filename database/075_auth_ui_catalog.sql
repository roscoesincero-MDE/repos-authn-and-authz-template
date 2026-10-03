/***********************************************************************************************************************
Script:         075_auth_ui_catalog.sql
Purpose:        The UI authorization surface: auth.UiElement and auth.UiElementPermission.  The catalogue of navigable
                things -- areas, screens, tabs, sections and commands -- and the permissions that gate each one.
Target:         SQL Server 2022.
Run as:         db_owner in the target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/075_auth_ui_catalog.sql
Idempotent:     Yes.  Guarded CREATEs, CREATE OR ALTER on the triggers, descriptions through util.uspSetObjectDescription.
Depends on:     database/030_auth_tenant.sql (auth.Application), database/050_auth_permission.sql (auth.Permission),
                templates/extended-properties.sql.
Implements:     T-082.  DES-AUTH-001 sections 13.1, 13.2, 13.3, 15.4.
                See docs/10-database-authn-authz-design.md.
To retarget:    Pass it per run:  sqlcmd -d <database> -v DbName=<database>.  There is no in-file default.

THESE TWO TABLES HOLD NO ROWS UNTIL 115_seed_reference_data.sql RUNS
-------------------------------------------------------------------
Exactly as 050_auth_permission.sql builds auth.Permission and seeds none of it.  The starter catalogue covering the demo
domain is T-090, in 115.  An empty catalogue is not a fail-open state here -- auth.uspGetNavigationForProfile returns no
rows, so the application renders no navigation, which is visible on the first screen rather than silent.  That is the
opposite of what an empty auth.Permission does to 120_rls_policy.sql (UI-35), and the difference is worth knowing: a
missing NAVIGATION entry hides a screen, a missing PERMISSION entry denies every row.

THE DEFAULT FOR AN UNMAPPED ELEMENT IS "VISIBLE", AND IT IS THE RIGHT DEFAULT EXACTLY ONCE
-----------------------------------------------------------------------------------------
Section 13.1: "An element with no permission row is visible to every authenticated profile."  That is correct for a home
page and wrong for everything else, so this file does NOT enforce a mapping -- a CHECK constraint cannot span two tables,
and a trigger that refused an unmapped element would make the seed order matter.  950_verify_deployment.sql lists them as
a warning instead, and the closing report below counts them so the number is visible on every deployment.

WHY UiElementPermission CARRIES ApplicationId
---------------------------------------------
It is denormalised, deliberately, for the same reason auth.RolePermission carries it (BL-040): both foreign keys are then
composite and reference the unfiltered pairs UX_auth_UiElement_Id_Application and UX_auth_Permission_Id_Application, so a
screen in one application CANNOT be gated by a permission belonging to another.  D-09 makes the application the outermost
scope of authority; a single-column foreign key would leave that as a convention nobody enforces.  The cost is one
redundant int per row and a trigger guard making it immutable (E-50010).

WHY THE PARENT LINK IS ALSO COMPOSITE
-------------------------------------
Same argument one level down.  FK_auth_UiElement_Parent is on (ParentUiElementId, ApplicationId), so a tab cannot be hung
under a screen in a different application.  It is what makes the tree in section 13.1 one tree per application rather
than one tree with application labels scattered through it.
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

IF OBJECT_ID (N'auth.Application', N'U') IS NULL
BEGIN
    DECLARE @MsgApp NVARCHAR (2000) =
        N'auth.Application is missing. Run database/030_auth_tenant.sql first.';

    THROW 50000, @MsgApp, 1;
END
GO

IF OBJECT_ID (N'auth.Permission', N'U') IS NULL
BEGIN
    DECLARE @MsgPerm NVARCHAR (2000) =
        N'auth.Permission is missing. Run database/050_auth_permission.sql first: auth.UiElementPermission''s composite '
      + N'foreign key references UX_auth_Permission_Id_Application, which that file creates.';

    THROW 50000, @MsgPerm, 1;
END
GO


-- *** 1. auth.UiElement ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

IF OBJECT_ID (N'auth.UiElement', N'U') IS NULL
BEGIN
    CREATE TABLE auth.UiElement
    (
        UiElementId          INT             IDENTITY (1, 1) NOT NULL,

        -- D-09.  The outermost scope: two applications sharing this database have separate catalogues.
        ApplicationId        INT             NOT NULL,

        -- The string the UI binds to, and the ONLY thing it may bind to -- section 13.3.  Grammar is
        -- <Type>.<Name>, e.g. Screen.CaseList, enforced row-locally by CK_auth_UiElement_CodeMatchesType.
        ElementCode          NVARCHAR (200)  NOT NULL,

        -- Area | Screen | Tab | Section | Command.  Descriptive: no authorization decision reads it, exactly as
        -- auth.TenantType is descriptive (section 5.2).  It drives layout, and the grammar check above.
        ElementType          NVARCHAR (20)   NOT NULL,

        -- NULL for an Area and required for everything else -- CK_auth_UiElement_AreaHasNoParent.  Same shape as
        -- CK_auth_Tenant_RootHasNoParent, and for the same reason: the exception to the tree is a property of the
        -- type, so the constraint ties them together rather than trusting the seed.
        ParentUiElementId    INT                 NULL,

        DisplayLabel         NVARCHAR (400)  NOT NULL,

        -- Order among siblings.  Not unique: two commands at the same weight are a display detail, and a unique
        -- constraint here would make inserting an element between two others a renumbering exercise.
        SortOrder            INT             NOT NULL,

        -- ---------------------------------------------------------------------------------
        -- Standard audit columns.  Soft delete only; there is no hard delete anywhere here.
        -- ---------------------------------------------------------------------------------
        IsDeleted            BIT             NOT NULL CONSTRAINT DF_auth_UiElement_IsDeleted            DEFAULT (0),

        -- NULLABLE AND WITHOUT A DEFAULT, which is this project's shape rather than the conventions template's:
        -- CK_auth_UiElement_DeletedPair pairs them to the flag, so a live row carries NULL in both and a deleted row
        -- carries a value in both.  The consequence a caller has to know is that an UNDELETE must clear them in the
        -- same statement that clears the flag -- the CHECK is evaluated before the AFTER trigger, so the trigger
        -- cannot do it for you.
        auditDeletedBy       NVARCHAR (255)      NULL,
        auditDeletedDateUtc  DATETIME2 (3)       NULL,
        auditCreatedBy       NVARCHAR (255)  NOT NULL CONSTRAINT DF_auth_UiElement_auditCreatedBy       DEFAULT (ORIGINAL_LOGIN ()),
        auditCreatedDateUtc  DATETIME2 (3)   NOT NULL CONSTRAINT DF_auth_UiElement_auditCreatedDateUtc  DEFAULT (SYSUTCDATETIME ()),
        auditModifiedBy      NVARCHAR (255)  NOT NULL CONSTRAINT DF_auth_UiElement_auditModifiedBy      DEFAULT (ORIGINAL_LOGIN ()),
        auditModifiedDateUtc DATETIME2 (3)   NOT NULL CONSTRAINT DF_auth_UiElement_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ()),

        CONSTRAINT PK_auth_UiElement PRIMARY KEY CLUSTERED (UiElementId),

        -- The unfiltered pair auth.UiElementPermission and FK_auth_UiElement_Parent reference.  A table constraint
        -- rather than a filtered unique index, because a foreign key cannot reference a filtered index.
        CONSTRAINT UX_auth_UiElement_Id_Application UNIQUE (UiElementId, ApplicationId),

        CONSTRAINT CK_auth_UiElement_ElementType
            CHECK (ElementType IN (N'Area', N'Screen', N'Tab', N'Section', N'Command')),

        -- The code must announce its own type.  Row-local and therefore checkable without a subquery, which is the
        -- same trick CK_auth_Permission_CodeMatchesCategory uses.  ElementType is what the UI lays out by; the code
        -- is what it binds by, and a Screen.X that is actually a Command is a defect nobody sees until a button
        -- renders as a page.
        CONSTRAINT CK_auth_UiElement_CodeMatchesType
            CHECK (ElementCode LIKE ElementType + N'.%'
               AND LEN (ElementCode) > LEN (ElementType) + 1
               AND CHARINDEX (N'.', ElementCode, LEN (ElementType) + 2) = 0),

        CONSTRAINT CK_auth_UiElement_AreaHasNoParent
            CHECK ((ElementType = N'Area' AND ParentUiElementId IS NULL)
                OR (ElementType <> N'Area' AND ParentUiElementId IS NOT NULL)),

        CONSTRAINT CK_auth_UiElement_NotOwnParent
            CHECK (ParentUiElementId IS NULL OR ParentUiElementId <> UiElementId),

        CONSTRAINT CK_auth_UiElement_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS NULL     AND auditDeletedDateUtc IS NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL)),

        CONSTRAINT FK_auth_UiElement_auth_Application
            FOREIGN KEY (ApplicationId) REFERENCES auth.Application (ApplicationId),

        -- Composite, so a child cannot be hung under a parent in another application.  See the file header.
        CONSTRAINT FK_auth_UiElement_auth_UiElement
            FOREIGN KEY (ParentUiElementId, ApplicationId)
            REFERENCES auth.UiElement (UiElementId, ApplicationId)
    );
END;
GO

-- The natural key, filtered so a retired element does not block re-registering the same code.
IF NOT EXISTS (SELECT 1
                 FROM sys.indexes
                WHERE name      = N'UX_auth_UiElement_Code'
                  AND object_id = OBJECT_ID (N'auth.UiElement'))
BEGIN
    CREATE UNIQUE INDEX UX_auth_UiElement_Code
        ON auth.UiElement (ApplicationId, ElementCode)
        WHERE IsDeleted = 0;
END;
GO

-- The navigation read walks the tree parent-first and orders siblings.  Filtered on IsDeleted = 0 to match every
-- reader -- BL-039 makes that load-bearing rather than decorative.
IF NOT EXISTS (SELECT 1
                 FROM sys.indexes
                WHERE name      = N'IX_auth_UiElement_Parent'
                  AND object_id = OBJECT_ID (N'auth.UiElement'))
BEGIN
    CREATE INDEX IX_auth_UiElement_Parent
        ON auth.UiElement (ParentUiElementId, SortOrder)
        INCLUDE (ElementCode, ElementType, DisplayLabel, ApplicationId)
        WHERE IsDeleted = 0;
END;
GO


-- *** 2. auth.UiElementPermission ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

IF OBJECT_ID (N'auth.UiElementPermission', N'U') IS NULL
BEGIN
    CREATE TABLE auth.UiElementPermission
    (
        UiElementPermissionId INT            IDENTITY (1, 1) NOT NULL,

        UiElementId           INT            NOT NULL,
        PermissionId          INT            NOT NULL,

        -- Denormalised so BOTH foreign keys can be composite.  See the file header.
        ApplicationId         INT            NOT NULL,

        -- View or Edit.  Two modes and not three: section 13.2 computes exactly two booleans, and a third mode with
        -- no column to land in would be a row the UI silently ignores.
        AccessMode            NVARCHAR (10)  NOT NULL,

        IsDeleted            BIT             NOT NULL CONSTRAINT DF_auth_UiElementPermission_IsDeleted            DEFAULT (0),
        auditDeletedBy       NVARCHAR (255)      NULL,
        auditDeletedDateUtc  DATETIME2 (3)       NULL,
        auditCreatedBy       NVARCHAR (255)  NOT NULL CONSTRAINT DF_auth_UiElementPermission_auditCreatedBy       DEFAULT (ORIGINAL_LOGIN ()),
        auditCreatedDateUtc  DATETIME2 (3)   NOT NULL CONSTRAINT DF_auth_UiElementPermission_auditCreatedDateUtc  DEFAULT (SYSUTCDATETIME ()),
        auditModifiedBy      NVARCHAR (255)  NOT NULL CONSTRAINT DF_auth_UiElementPermission_auditModifiedBy      DEFAULT (ORIGINAL_LOGIN ()),
        auditModifiedDateUtc DATETIME2 (3)   NOT NULL CONSTRAINT DF_auth_UiElementPermission_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ()),

        CONSTRAINT PK_auth_UiElementPermission PRIMARY KEY CLUSTERED (UiElementPermissionId),

        CONSTRAINT CK_auth_UiElementPermission_AccessMode
            CHECK (AccessMode IN (N'View', N'Edit')),

        CONSTRAINT CK_auth_UiElementPermission_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS NULL     AND auditDeletedDateUtc IS NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL)),

        CONSTRAINT FK_auth_UiElementPermission_auth_UiElement
            FOREIGN KEY (UiElementId, ApplicationId)
            REFERENCES auth.UiElement (UiElementId, ApplicationId),

        CONSTRAINT FK_auth_UiElementPermission_auth_Permission
            FOREIGN KEY (PermissionId, ApplicationId)
            REFERENCES auth.Permission (PermissionId, ApplicationId)
    );
END;
GO

-- One live mapping per (element, permission, mode).  Filtered, so retiring a mapping and re-adding it later works.
IF NOT EXISTS (SELECT 1
                 FROM sys.indexes
                WHERE name      = N'UX_auth_UiElementPermission_Map'
                  AND object_id = OBJECT_ID (N'auth.UiElementPermission'))
BEGIN
    CREATE UNIQUE INDEX UX_auth_UiElementPermission_Map
        ON auth.UiElementPermission (UiElementId, PermissionId, AccessMode)
        WHERE IsDeleted = 0;
END;
GO

-- auth.uspGetNavigationForProfile's join: every mapping of one element, by mode.  Leading on the element because the
-- navigation read drives from the tree, not from the permission.
IF NOT EXISTS (SELECT 1
                 FROM sys.indexes
                WHERE name      = N'IX_auth_UiElementPermission_Element'
                  AND object_id = OBJECT_ID (N'auth.UiElementPermission'))
BEGIN
    CREATE INDEX IX_auth_UiElementPermission_Element
        ON auth.UiElementPermission (UiElementId, AccessMode)
        INCLUDE (PermissionId)
        WHERE IsDeleted = 0;
END;
GO


-- *** 3. Audit triggers ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.trg_au_updt_UiElement
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

AFTER UPDATE audit stamp for auth.UiElement, and the guard that makes ElementCode and ApplicationId immutable --
E-50010.

========================================================================================================================
Requirements and Key Dependencies:

auth.UiElement and its PRIMARY KEY.  No grant of its own: a trigger runs in the caller's security context against a
table the caller already holds UPDATE on.

========================================================================================================================
Notes:

WHY ElementCode IS IMMUTABLE.  Section 13.3 tells the UI project to bind to element codes and nothing else.  The code is
therefore a literal in application source that this database cannot see and cannot search.  Renaming it here silently
un-binds every screen that referenced it -- and the failure mode is a screen that no longer appears rather than an error,
because section 13.2 OMITS elements the profile cannot view and an unknown code is indistinguishable from a hidden one.
Retire the element and register the replacement.

WHY ApplicationId IS IMMUTABLE.  D-09 makes the application the outermost scope of authority.  Moving an element between
applications would move it out from under its parent and its permission mappings in one statement, and the composite
foreign keys would refuse it in most cases -- but "most" is not a guarantee, because an element with no parent and no
mapping has nothing to refuse it.

ElementType IS NOT IMMUTABLE, deliberately.  CK_auth_UiElement_CodeMatchesType ties it to the code, which IS immutable,
so the only type change the constraint permits is one that was already consistent with the code -- i.e. none.  The check
constraint is the enforcement; a trigger guard would be a second statement of the same rule, and two statements of one
rule is how they come to disagree.

========================================================================================================================
Example Usage and Performance:

update auth.UiElement set DisplayLabel = N'Case list' where UiElementId = 1;   -- audit columns follow automatically

Set-based; one extra UPDATE per statement touching four columns.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-082
Description:
Created.  Phase 6.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER TRIGGER auth.trg_au_updt_UiElement
    ON auth.UiElement
    AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    IF (UPDATE (ElementCode) OR UPDATE (ApplicationId))
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.UiElementId = i.UiElementId
                    WHERE i.ElementCode   <> d.ElementCode
                       OR i.ApplicationId <> d.ApplicationId)
    BEGIN
        ;THROW 50010, N'auth.UiElement.ElementCode and ApplicationId are immutable: DES section 13.3 makes the code a literal in application source this database cannot search, and a rename un-binds every screen that used it with no error to say so. Soft-delete the element and register the replacement.', 1;
    END;

    DECLARE @Now   DATETIME2 (3)  = SYSUTCDATETIME ()
          , @Actor NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                            , ORIGINAL_LOGIN ());

    UPDATE e
       SET e.auditModifiedDateUtc = @Now
         , e.auditModifiedBy      = CASE WHEN UPDATE (auditModifiedBy)
                                         THEN COALESCE (NULLIF (i.auditModifiedBy, N''), @Actor)
                                         ELSE @Actor END
         , e.auditDeletedBy       = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Actor ELSE e.auditDeletedBy      END
         , e.auditDeletedDateUtc  = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Now   ELSE e.auditDeletedDateUtc END
      FROM auth.UiElement AS e
      JOIN inserted       AS i ON i.UiElementId = e.UiElementId
      JOIN deleted        AS d ON d.UiElementId = e.UiElementId;
END;
GO


/***********************************************************************************************************************
ObjectName:   auth.trg_au_updt_UiElementPermission
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

AFTER UPDATE audit stamp for auth.UiElementPermission, and the guard that makes the mapping triple immutable --
E-50010.  UiElementId, PermissionId, ApplicationId and AccessMode are all write-once.

========================================================================================================================
Requirements and Key Dependencies:

auth.UiElementPermission and its PRIMARY KEY.

========================================================================================================================
Notes:

WHY THE WHOLE TRIPLE IS IMMUTABLE AND NOT JUST ApplicationId.  This table has no payload: every column except the audit
block is part of the mapping.  An UPDATE that changes any of them is not an edit of a mapping, it is the retirement of
one mapping and the creation of another -- and doing that as an UPDATE loses the fact, because auditCreatedDateUtc still
says when the OLD mapping was made.  So the only legal UPDATE here is a soft delete.  That reads as strict until you
notice the alternative: a screen's gate silently changing from Data.Read/View to Data.Update/Edit, with the trail
recording nothing but "row modified".

========================================================================================================================
Example Usage and Performance:

update auth.UiElementPermission set IsDeleted = 1 where UiElementPermissionId = 1;   -- the only legal UPDATE

Set-based; one extra UPDATE per statement touching four columns.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-082
Description:
Created.  Phase 6.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER TRIGGER auth.trg_au_updt_UiElementPermission
    ON auth.UiElementPermission
    AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    IF (UPDATE (UiElementId) OR UPDATE (PermissionId) OR UPDATE (ApplicationId) OR UPDATE (AccessMode))
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.UiElementPermissionId = i.UiElementPermissionId
                    WHERE i.UiElementId   <> d.UiElementId
                       OR i.PermissionId  <> d.PermissionId
                       OR i.ApplicationId <> d.ApplicationId
                       OR i.AccessMode    <> d.AccessMode)
    BEGIN
        ;THROW 50010, N'auth.UiElementPermission holds no payload: every column but the audit block is part of the mapping, so changing one is retiring a mapping and creating another. That is two rows, not an UPDATE -- an UPDATE would leave auditCreatedDateUtc claiming the NEW gate was set when the OLD one was. Soft-delete the row and insert the replacement.', 1;
    END;

    DECLARE @Now   DATETIME2 (3)  = SYSUTCDATETIME ()
          , @Actor NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                            , ORIGINAL_LOGIN ());

    UPDATE m
       SET m.auditModifiedDateUtc = @Now
         , m.auditModifiedBy      = CASE WHEN UPDATE (auditModifiedBy)
                                         THEN COALESCE (NULLIF (i.auditModifiedBy, N''), @Actor)
                                         ELSE @Actor END
         , m.auditDeletedBy       = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Actor ELSE m.auditDeletedBy      END
         , m.auditDeletedDateUtc  = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Now   ELSE m.auditDeletedDateUtc END
      FROM auth.UiElementPermission AS m
      JOIN inserted                 AS i ON i.UiElementPermissionId = m.UiElementPermissionId
      JOIN deleted                  AS d ON d.UiElementPermissionId = m.UiElementPermissionId;
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
      (N'auth', N'TABLE', N'UiElement', NULL
     , N'The catalogue of navigable things -- areas, screens, tabs, sections and commands -- one tree per application. '
     + N'Section 13.1. The UI project binds to ElementCode and to the two booleans auth.uspGetNavigationForProfile '
     + N'computes, and to NOTHING ELSE: not role names, not tenant names, not permission codes (section 13.3, UI-02). '
     + N'Seeded by 115_seed_reference_data.sql (T-090) with a starter catalogue covering the demo domain; empty until '
     + N'then, which renders no navigation rather than denying any row.')
    , (N'auth', N'TABLE', N'UiElement', N'UiElementId'
     , N'Surrogate key. The natural key is (ApplicationId, ElementCode).')
    , (N'auth', N'TABLE', N'UiElement', N'ApplicationId'
     , N'The application whose catalogue this element belongs to -- D-09, the outermost scope of authority. IMMUTABLE '
     + N'(E-50010): moving an element between applications would move it out from under its parent and its permission '
     + N'mappings in one statement.')
    , (N'auth', N'TABLE', N'UiElement', N'ElementCode'
     , N'The string the application binds to, e.g. Screen.CaseList. Grammar is <ElementType>.<Name> with exactly one '
     + N'dot, enforced row-locally by CK_auth_UiElement_CodeMatchesType. Unique per application among live rows. '
     + N'IMMUTABLE (E-50010): it is a literal in application source this database cannot search, and renaming it '
     + N'un-binds every screen that used it with no error -- section 13.2 omits elements the profile cannot view, so '
     + N'an unknown code and a hidden one look identical to the UI.')
    , (N'auth', N'TABLE', N'UiElement', N'ElementType'
     , N'Area, Screen, Tab, Section or Command -- section 13.1. Descriptive, like auth.TenantType: no authorization '
     + N'decision reads it. It drives layout and it constrains the code. Not separately immutable, because the code '
     + N'is, and CK_auth_UiElement_CodeMatchesType permits no type change the code does not already agree with.')
    , (N'auth', N'TABLE', N'UiElement', N'ParentUiElementId'
     , N'The element above this one. NULL for an Area and required for everything else -- '
     + N'CK_auth_UiElement_AreaHasNoParent, the same shape as CK_auth_Tenant_RootHasNoParent. The foreign key is '
     + N'COMPOSITE on (ParentUiElementId, ApplicationId), so a tab cannot be hung under a screen in another '
     + N'application.')
    , (N'auth', N'TABLE', N'UiElement', N'DisplayLabel'
     , N'What the user sees. The one column here an administrator may safely edit, and the reason the table is not '
     + N'a static list in application source.')
    , (N'auth', N'TABLE', N'UiElement', N'SortOrder'
     , N'Order among siblings. Deliberately not unique: two elements at the same weight are a display detail, and '
     + N'uniqueness would make inserting an element between two others a renumbering exercise.')
    , (N'auth', N'TABLE', N'UiElementPermission', NULL
     , N'Which permissions gate which element, and in which mode -- section 13.1. AN ELEMENT WITH NO ROW HERE IS '
     + N'VISIBLE TO EVERY AUTHENTICATED PROFILE, which is right for a home page and wrong for everything else; '
     + N'950_verify_deployment.sql lists unmapped elements as a warning and this file''s closing report counts them. '
     + N'Not enforced by a constraint, because a CHECK cannot span two tables and a trigger would make the seed '
     + N'order matter.')
    , (N'auth', N'TABLE', N'UiElementPermission', N'UiElementPermissionId'
     , N'Surrogate key. The natural key is (UiElementId, PermissionId, AccessMode) among live rows.')
    , (N'auth', N'TABLE', N'UiElementPermission', N'UiElementId'
     , N'The gated element. IMMUTABLE (E-50010) with the rest of the mapping: this table has no payload, so an '
     + N'UPDATE to any of these columns is the retirement of one mapping and the creation of another.')
    , (N'auth', N'TABLE', N'UiElementPermission', N'PermissionId'
     , N'The permission that opens the element. The foreign key is COMPOSITE on (PermissionId, ApplicationId) '
     + N'against UX_auth_Permission_Id_Application, so a screen in one application cannot be gated by a permission '
     + N'belonging to another -- the structural half of D-09, exactly as auth.RolePermission does it (BL-040). '
     + N'IMMUTABLE (E-50010).')
    , (N'auth', N'TABLE', N'UiElementPermission', N'ApplicationId'
     , N'Denormalised on purpose, so BOTH foreign keys on this table can be composite and carry the application. '
     + N'One redundant int per row buys enforcement of a rule that would otherwise be a convention. IMMUTABLE '
     + N'(E-50010).')
    , (N'auth', N'TABLE', N'UiElementPermission', N'AccessMode'
     , N'View or Edit. Two modes and not three: section 13.2 computes exactly two booleans, CanView and CanEdit, and '
     + N'a third mode would be a row the UI silently ignores. CanEdit = 0 with CanView = 1 is the read-only case and '
     + N'it is the common one. IMMUTABLE (E-50010).')
    , (N'auth', N'TRIGGER', N'trg_au_updt_UiElement', NULL
     , N'Audit stamp for auth.UiElement, and the guard that makes ElementCode and ApplicationId immutable -- '
     + N'E-50010.')
    , (N'auth', N'TRIGGER', N'trg_au_updt_UiElementPermission', NULL
     , N'Audit stamp for auth.UiElementPermission, and the guard that makes the whole mapping triple plus AccessMode '
     + N'immutable -- E-50010. The only legal UPDATE on this table is a soft delete.');

    -- The audit columns are identical on every table; written as rows for the same reason as above -- an EXEC
    -- argument takes a constant or a variable and never an expression.
    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    SELECT N'auth', N'TABLE', t.TableName, c.ColumnName, c.Description
      FROM (VALUES (N'UiElement'), (N'UiElementPermission')) AS t (TableName)
     CROSS JOIN (VALUES
            (N'IsDeleted',            N'Soft-delete flag. 1 = deleted, 0 = active. This database performs no hard deletes; every read filters IsDeleted = 0.')
          , (N'auditDeletedBy',       N'Login or acting profile that soft-deleted the row. NULL on a live row and NOT NULL on a deleted one -- CK_..._DeletedPair pairs it to the flag, so there is no ambiguous state. Stamped by the AFTER UPDATE trigger on an IsDeleted 0 -> 1 transition; an UNDELETE must clear it in the same statement, because the CHECK runs before the trigger.')
          , (N'auditDeletedDateUtc',  N'UTC timestamp of the soft delete, stamped with the same instant as auditModifiedDateUtc. NULL on a live row, paired to the flag by CK_..._DeletedPair.')
          , (N'auditCreatedBy',       N'Login or acting profile that inserted the row. Set explicitly by the seeding MERGE; the DEFAULT would record the pooled application login on every row -- section 14.4.')
          , (N'auditCreatedDateUtc',  N'UTC timestamp of row insert.')
          , (N'auditModifiedBy',      N'Login or acting profile that last modified the row. Maintained by the AFTER UPDATE trigger, and the one audit column a caller may override.')
          , (N'auditModifiedDateUtc', N'UTC timestamp of last modification. Recomputed by the AFTER UPDATE trigger on every update, so it cannot be back-dated by hand.')
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


-- *** 5. Grants ***
-- NONE, and that is INV-11.  applicationRole holds no table access to SCHEMA::auth: the catalogue is read through
-- auth.uspGetNavigationForProfile, which demands nothing (every authenticated profile may ask what it can see) and
-- returns only the elements the profile may view.  Ownership chaining is what lets that procedure read these tables.
--
-- A future auth.uspSetUiElement / auth.uspSetUiElementPermission pair gated on Config.UiCatalogUpdate is the write
-- path, and it does not exist yet: the catalogue is seed data today, changed by re-running 115_seed_reference_data.sql.
-- The closing report says so rather than leaving the omission to be discovered.
PRINT N'075_auth_ui_catalog.sql grants nothing. INV-11: the catalogue is reached through auth.uspGetNavigationForProfile '
    + N'only, by ownership chaining, and 170_permissions.sql denies applicationRole every table in SCHEMA::auth.';
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
SELECT CASE WHEN OBJECT_ID (x.ObjName, x.ObjType) IS NULL THEN 1 ELSE 4 END
     , CASE WHEN OBJECT_ID (x.ObjName, x.ObjType) IS NULL THEN 'MISSING' ELSE 'OK' END
     , x.Label + N' ' + x.ObjName
     , x.Detail
  FROM (VALUES (N'Table',   N'U',  N'auth.UiElement',                       N'Section 13.1. One tree per application; Area rows are the roots.')
             , (N'Table',   N'U',  N'auth.UiElementPermission',             N'Section 13.1. AccessMode View or Edit. Both foreign keys composite on ApplicationId.')
             , (N'Trigger', N'TR', N'auth.trg_au_updt_UiElement',           N'Audit stamp; ElementCode and ApplicationId immutable -- E-50010.')
             , (N'Trigger', N'TR', N'auth.trg_au_updt_UiElementPermission', N'Audit stamp; the whole mapping immutable -- E-50010.')
       ) AS x (Label, ObjType, ObjName, Detail);

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 5 THEN 4 ELSE 1 END
     , CASE WHEN COUNT (*) = 5 THEN 'OK' ELSE 'INCOMPLETE' END
     , N'Indexes and unique constraints'
     , CONCAT (COUNT (*), N' of 5 present: UX_auth_UiElement_Id_Application (unfiltered -- the composite foreign keys '
             , N'reference it), UX_auth_UiElement_Code, IX_auth_UiElement_Parent, '
             , N'UX_auth_UiElementPermission_Map, IX_auth_UiElementPermission_Element.')
  FROM sys.indexes
 WHERE name IN (N'UX_auth_UiElement_Id_Application', N'UX_auth_UiElement_Code', N'IX_auth_UiElement_Parent'
              , N'UX_auth_UiElementPermission_Map', N'IX_auth_UiElementPermission_Element');

-- The composite foreign keys are the structural half of D-09.  Reported by name because a single-column key would
-- deploy cleanly, pass every test that does not cross an application boundary, and be wrong.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.KeyCols = 2 THEN 4 ELSE 1 END
     , CASE WHEN x.KeyCols = 2 THEN 'OK' ELSE 'VIOLATED' END
     , N'Foreign key ' + x.KeyName + N' is composite'
     , CONCAT (x.KeyCols, N' column(s). Anything but 2 means D-09 is a convention here rather than a constraint: '
             , N'a screen in one application could be gated by another application''s permission, or hung under '
             , N'another application''s parent.')
  FROM (SELECT KeyName = fk.name
             , KeyCols = COUNT (*)
          FROM sys.foreign_keys        AS fk
          JOIN sys.foreign_key_columns AS fkc ON fkc.constraint_object_id = fk.object_id
         WHERE fk.name IN (N'FK_auth_UiElement_auth_UiElement', N'FK_auth_UiElementPermission_auth_UiElement'
                         , N'FK_auth_UiElementPermission_auth_Permission')
         GROUP BY fk.name) AS x;

-- Section 13.1's default, counted.  Zero elements is the expected state before 115 runs; the interesting number is
-- elements that exist and are gated by nothing.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN e.Total = 0 THEN 4
            WHEN e.Unmapped = 0 THEN 4
            ELSE 3 END
     , CASE WHEN e.Total = 0 THEN 'OK'
            WHEN e.Unmapped = 0 THEN 'OK'
            ELSE 'WARNING' END
     , N'Elements gated by no permission'
     , CONCAT (e.Unmapped, N' of ', e.Total, N' live element(s) have no auth.UiElementPermission row and are therefore '
             , N'VISIBLE TO EVERY AUTHENTICATED PROFILE -- section 13.1. That is the right default for a home page '
             , N'and the wrong one for everything else. Zero elements is expected until '
             , N'115_seed_reference_data.sql has run (T-090).')
  -- Two levels of derived table rather than SUM (CASE WHEN NOT EXISTS (...)): an aggregate may not contain a
  -- subquery (Msg 130), so the per-element verdict is computed first and counted second.
  FROM (SELECT Total    = COUNT (*)
             -- COALESCE because SUM over no rows is NULL, and an empty catalogue is the expected state before 115
             -- runs -- the report read "of 0 live element(s)" with the count missing entirely.
             , Unmapped = COALESCE (SUM (v.IsUnmapped), 0)
          FROM (SELECT IsUnmapped = CASE WHEN m.UiElementId IS NULL THEN 1 ELSE 0 END
                  FROM auth.UiElement AS el
                  LEFT JOIN (SELECT DISTINCT UiElementId
                               FROM auth.UiElementPermission
                              WHERE IsDeleted = 0) AS m ON m.UiElementId = el.UiElementId
                 WHERE el.IsDeleted = 0) AS v) AS e;

INSERT @Report (Severity, Status, Item, Detail)
SELECT 3, 'PENDING'
     , N'A write path for the catalogue'
     , N'Config.UiCatalogUpdate (Appendix A) has no procedure. The catalogue is seed data today: change it in '
     + N'115_seed_reference_data.sql and re-run that file. An auth.uspSetUiElement / auth.uspSetUiElementPermission '
     + N'pair is the obvious addition and is deliberately not in Phase 6 -- nothing calls it until the UI project '
     + N'has a screen to call it from, and a write procedure nobody calls is a write procedure nobody tests.';

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 30 THEN 4 ELSE 2 END
     , CASE WHEN COUNT (*) = 30 THEN 'OK' ELSE 'INCOMPLETE' END
     , N'MS_Description on the UI catalogue'
     , CONCAT (COUNT (*), N' of 30 descriptions present: 2 tables, 2 triggers, auth.UiElement''s 14 columns and '
             , N'auth.UiElementPermission''s 12. Conventions rule 4 is "the table and EVERY column", and the audit '
             , N'seven count.')
  FROM sys.extended_properties AS ep
  JOIN sys.objects             AS o ON o.object_id = ep.major_id
 WHERE ep.name     = N'MS_Description'
   AND o.schema_id = SCHEMA_ID (N'auth')
   AND o.name IN (N'UiElement', N'UiElementPermission', N'trg_au_updt_UiElement', N'trg_au_updt_UiElementPermission')
   AND (ep.minor_id = 0 OR o.type = N'U');

IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
    PRINT N'UI catalogue: PROBLEMS found. Read the report below before running the next script.';
ELSE
    PRINT N'UI catalogue: no problems found. Items listed as PENDING or WARNING belong to later work.';

PRINT N'';

SELECT Severity, Status, Item, Detail
  FROM @Report
 ORDER BY Severity, RowNo;
GO
