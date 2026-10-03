/***********************************************************************************************************************
Script:         115_seed_reference_data.sql
Purpose:        The reference data that is code rather than configuration: one application, the root tenant and the
                external-organizations branch, the thirty-five permissions in seven families, the sixteen baseline
                roles and their permission lists, the starter UI element catalogue, the catalogue's version digest, and
                the settings that 025 does not own.
Target:         SQL Server 2022.
Run as:         db_owner in the target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/115_seed_reference_data.sql
Idempotent:     Yes, and that is the whole point.  Every section is a MERGE, so it converges on a populated database and
                re-asserts the catalogue on every deployment.
Depends on:     025_config_tables.sql, 030_auth_tenant.sql, 050_auth_permission.sql, 055_auth_role.sql,
                075_auth_ui_catalog.sql.
Implements:     T-089, T-090, T-128.  DES-AUTH-001 sections 8.1, 8.2, 13.1, 16.1, 16.2, 22 (Appendix A).
                See docs/10-database-authn-authz-design.md.
To retarget:    Pass the database per run:  sqlcmd -d <database> -v DbName=<database>.

RUN 120_rls_policy.sql AFTER THIS FILE.  ALWAYS.
-----------------------------------------------
120_rls_policy.sql resolves `Data.Read`'s permission id from auth.Permission and bakes the integer into the predicate
functions.  On a database where this file has not run it finds nothing, substitutes the sentinel -1, and every predicate
then denies every non-maintenance session -- fail-closed, which is the right direction and a baffling experience
(section 16.1 item 3, UI-35).  Seeding the catalogue WITHOUT rebuilding the policy leaves the predicates on the
sentinel, so the two go together in that order.  Install-TemplateDatabase.ps1 has them in that order; a hand-run of
this file does not, and this is the reminder.

WHAT THIS FILE DELIBERATELY DOES NOT SEED
-----------------------------------------
  *  auth.TenantType -- 030_auth_tenant.sql owns it.  Phase 1 cannot build a tenant tree before the types exist and
     auth.Tenant's composite foreign key makes the `Root` row a structural prerequisite, not reference data.  A second
     MERGE here would be harmless and would be the thing that drifts.  BL-021, section 16.1 item 2.
  *  config.TenantScopedTable -- 025_config_tables.sql owns it, because 120_rls_policy.sql reads that registry on every
     deployment including one where this file has not run.  Section 16.1 item 7.
  *  MOST OF config.ApplicationSetting -- 025_config_tables.sql seeds the twenty-three authentication, authorization and
     registration tunables, because 110/112 read them and those files install long before this one.  Section 6 below adds
     only the three settings whose consumers arrived in Phases 5 and 6, plus Ui.CatalogueVersion, and there is
     deliberately no overlap: a setting seeded in two places is a setting with two defaults.  BL-050.

Ui.CatalogueVersion IS THE ONE SETTING VALUE THIS FILE OVERWRITES ON A MATCH
--------------------------------------------------------------------------
G-18.  Every other seeded setting in this database is left alone once it exists, because an operator who tuned it made a
decision and the deployment should not undo it.  Ui.CatalogueVersion is not a tunable: it is a DIGEST of the live
(ElementCode, PermissionCode, AccessMode) triples of this application's UI catalogue, recomputed by section 6 on every
run, and an operator editing it would be editing the answer rather than the question.  Labels, sort orders and parentage
are deliberately excluded from it -- UIH-AUTH-001 section 10 makes element CODES the published interface, and a version
that moved when somebody fixed a typo in a menu label would be a control everybody learns to ignore.  The application
reads the value at start-up and passes it to auth.uspGetNavigationForProfile, which raises E-50230 on a mismatch: the
assertion is made by the DATABASE, because one the caller may skip is advice and not a control.
  *  Any user, profile, credential or grant.  900_bootstrap_first_admin.sql does that, once, and refuses if a profile
     already exists.

THE BASELINE WENT FROM FOURTEEN ROLES TO SIXTEEN ON 2026-09-21, AND THE TWO ADDITIONS ARE THE ORDINARY ONES
----------------------------------------------------------------------------------------------------------
T-128, gaps G-46 and G-47.  Section 16.2's fourteen roles are all SPECIALISED, and scenario SCEN-AUTH-001 found the
consequence by trying to express an ordinary agency in them and failing before it inserted a single row:

  *  There was no role meaning "can do the work".  CRUD -- read, insert, update, soft delete, execute -- took
     CONTRIBUTOR + DATA_STEWARD + OPERATOR together, three grants where a project expects one, and DATA_STEWARD brings
     Data.Restore along uninvited.  Every working-level user in the estate would have held the power to UN-delete as a
     side effect of needing the power to delete.  CRUD_ACCESS is those five verbs and nothing else.
  *  There was no role meaning "can assign profiles".  ROLE_ADMIN is the near miss and also carries
     Authz.ProfileDeactivate, so granting it to the people whose job is handing out access hands them the one profile
     operation that TAKES access away -- 680 people per agency in the scenario.  PROFILE_ASSIGNER is ROLE_ADMIN without
     that one permission, which is the whole difference between provisioning and revocation.

The pool was not too small; it was specialised in the wrong direction.  Both of these are the first role a project
writes, every project writes them slightly differently, and divergence in the commonest case is the one thing a template
exists to prevent.  They are seeded as IsSystemRole = 1 like the other fourteen, which means INV-10 protects their codes
against a rename and section 9's closing report counts them -- it now expects sixteen and says INCOMPLETE at fourteen.

WHY THE ROLE MERGE NOW RE-ASSERTS IsSystemRole ON A MATCH, WHICH AN EARLIER COMMENT HERE CALLED POINTLESS
The earlier note was right on the evidence it had: E-50012 refuses CLEARING the flag, so re-asserting it could only be a
no-op or an error.  T-128 created a third case.  database/_scenarios/S1_load_agency.sql created both roles by hand while
they were missing, with IsSystemRole = 0 -- as any project that hit the same gap will have done -- and 055's trigger
permits 0 -> 1 while refusing 1 -> 0.  So the re-assertion is what ADOPTS a hand-made role into the baseline on the next
deployment, instead of leaving a database where the code is seeded and the flag says otherwise.  The narrow cost, stated:
a project that defined its own role at the ROOT tenant under one of these sixteen codes has it adopted, renamed and
re-described by this file.  That was already true of its name and description; the flag now follows.

THE SEED IDENTIFIERS ARE LITERALS IN SECTION 1, AND A PROJECT IS EXPECTED TO CHANGE THEM
---------------------------------------------------------------------------------------
@AppCode, @AppName, @RootCode, @RootName, @ExtCode and @ExtName are DECLAREd at the top of every batch that needs them.
They are not sqlcmd variables: a `:setvar` in the file OVERRIDES `-v` rather than acting as a fallback for its absence
(measured on sqlcmd 17), so a defaultable sqlcmd variable is not available, and making six of them mandatory on the
command line would mean the install script could not run this file without six more arguments.  Literals that a project
edits once, in one place, with the compiler checking nothing, is the honest version of that trade.

THIS FILE CREATES THE ROOT TENANT, WHICH SECTION 16.3 ATTRIBUTED TO 900_bootstrap_first_admin.sql
------------------------------------------------------------------------------------------------
The baseline roles are owned by the root tenant (INV-04, so they are assignable anywhere), and auth.Role.OwnerTenantId
is NOT NULL with a composite foreign key.  The roles therefore cannot be seeded before a root tenant exists, and the
roles must exist before 900 runs because 900 grants five of them by code (E-50087).  So the root tenant is created
here and 900 asserts it rather than creating it; 900 still owns the root tenant's AUTHENTICATION POLICY, which is a
bootstrap decision (password rules for the first administrator) and not reference data.  BL-051, G-25.
***********************************************************************************************************************/

:on error exit

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

DECLARE @Missing NVARCHAR (2000) = N'';

SELECT @Missing = @Missing + CASE WHEN OBJECT_ID (x.ObjName, N'U') IS NULL THEN x.ObjName + N' (' + x.Script + N'), ' ELSE N'' END
  FROM (VALUES (N'auth.Application',          N'030_auth_tenant.sql')
             , (N'auth.Tenant',               N'030_auth_tenant.sql')
             , (N'auth.TenantType',           N'030_auth_tenant.sql')
             , (N'auth.TenantDefaultRole',    N'040_auth_userprofile.sql')
             , (N'auth.PermissionCategory',   N'050_auth_permission.sql')
             , (N'auth.Permission',           N'050_auth_permission.sql')
             , (N'auth.Role',                 N'055_auth_role.sql')
             , (N'auth.RolePermission',       N'055_auth_role.sql')
             , (N'auth.UiElement',            N'075_auth_ui_catalog.sql')
             , (N'auth.UiElementPermission',  N'075_auth_ui_catalog.sql')
             , (N'config.ApplicationSetting', N'025_config_tables.sql')
       ) AS x (ObjName, Script);

IF LEN (@Missing) > 0
BEGIN
    DECLARE @MsgMissing NVARCHAR (2000) =
        N'115_seed_reference_data.sql cannot run: ' + LEFT (@Missing, LEN (@Missing) - 1)
      + N'. Run the named script(s) first.';

    THROW 50000, @MsgMissing, 1;
END
GO

-- The Root tenant type must be present, because the root tenant's composite foreign key names it by id AND by code.
IF NOT EXISTS (SELECT 1 FROM auth.TenantType WHERE TenantTypeCode = N'Root' AND IsDeleted = 0)
BEGIN
    DECLARE @MsgRootType NVARCHAR (2000) =
        N'auth.TenantType has no live Root row. 030_auth_tenant.sql seeds the seven types (BL-021); this file does not '
      + N'and must not. Re-run 030_auth_tenant.sql.';

    THROW 50000, @MsgRootType, 1;
END
GO


-- *** 1. auth.Application, and the tenant skeleton ***
-- ONE application row, the root tenant that owns the baseline roles, and the branch that approved external
-- organizations are created beneath.  Nothing else: the tenant tree a project actually needs is built through
-- auth.uspCreateTenant, by an administrator, with a trail.
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

DECLARE @AppCode  NVARCHAR (50)  = N'TEMPLATE'
      , @AppName  NVARCHAR (200) = N'Authentication and Authorization Template'
      , @RootCode NVARCHAR (50)  = N'ROOT'
      , @RootName NVARCHAR (200) = N'Platform Root'
      , @ExtCode  NVARCHAR (50)  = N'EXTORG'
      , @ExtName  NVARCHAR (200) = N'External Organizations';

MERGE auth.Application AS tgt
USING (SELECT ApplicationCode = @AppCode, ApplicationName = @AppName) AS src
   ON tgt.ApplicationCode = src.ApplicationCode
 WHEN MATCHED THEN
      UPDATE SET tgt.ApplicationName = src.ApplicationName
               , tgt.IsActive        = 1
               -- Resurrect rather than leave a deleted row and insert a duplicate: UX_auth_Application_Code is
               -- filtered on IsDeleted = 0, so both would be legal and the second would win every read silently.
               , tgt.IsDeleted           = 0
               , tgt.auditDeletedBy      = NULL
               , tgt.auditDeletedDateUtc = NULL
 WHEN NOT MATCHED BY TARGET THEN
      INSERT (ApplicationCode, ApplicationName, IsActive)
      VALUES (src.ApplicationCode, src.ApplicationName, 1);

DECLARE @ApplicationId INT = (SELECT ApplicationId FROM auth.Application WHERE ApplicationCode = @AppCode AND IsDeleted = 0)
      , @RootTypeId    INT = (SELECT TenantTypeId  FROM auth.TenantType  WHERE TenantTypeCode = N'Root' AND IsDeleted = 0)
      , @ExtTypeId     INT = (SELECT TenantTypeId  FROM auth.TenantType  WHERE TenantTypeCode = N'ExternalOrganization' AND IsDeleted = 0);

-- The root.  ParentTenantId IS NULL is what makes it the root, and
-- UX_auth_Tenant_ApplicationRoot (ApplicationId) WHERE IsDeleted = 0 AND ParentTenantId IS NULL allows exactly one.
MERGE auth.Tenant AS tgt
USING (SELECT ApplicationId = @ApplicationId, TenantCode = @RootCode, TenantName = @RootName
            , TenantTypeId = @RootTypeId, TenantTypeCode = N'Root') AS src
   ON tgt.ApplicationId = src.ApplicationId AND tgt.TenantCode = src.TenantCode
 WHEN MATCHED THEN
      UPDATE SET tgt.TenantName           = src.TenantName
               , tgt.IsActive             = 1
               , tgt.IsDeleted            = 0
               , tgt.auditDeletedBy       = NULL
               , tgt.auditDeletedDateUtc  = NULL
 WHEN NOT MATCHED BY TARGET THEN
      INSERT (ApplicationId, TenantCode, TenantName, TenantTypeId, TenantTypeCode, ParentTenantId, IsActive)
      VALUES (src.ApplicationId, src.TenantCode, src.TenantName, src.TenantTypeId, src.TenantTypeCode, NULL, 1);

DECLARE @RootTenantId INT = (SELECT TenantId FROM auth.Tenant
                              WHERE ApplicationId = @ApplicationId AND TenantCode = @RootCode AND IsDeleted = 0);

-- The external-organizations branch.  auth.uspApproveOrganization creates each approved organization BENEATH this
-- node, and reads the code from the Registration.ExternalBranchTenantCode setting (section 6) rather than a literal --
-- E-50067 is what a caller sees when the setting names no usable tenant.
MERGE auth.Tenant AS tgt
USING (SELECT ApplicationId = @ApplicationId, TenantCode = @ExtCode, TenantName = @ExtName
            , TenantTypeId = @ExtTypeId, TenantTypeCode = N'ExternalOrganization', ParentTenantId = @RootTenantId) AS src
   ON tgt.ApplicationId = src.ApplicationId AND tgt.TenantCode = src.TenantCode
 WHEN MATCHED THEN
      UPDATE SET tgt.TenantName           = src.TenantName
               , tgt.IsActive             = 1
               , tgt.IsDeleted            = 0
               , tgt.auditDeletedBy       = NULL
               , tgt.auditDeletedDateUtc  = NULL
 WHEN NOT MATCHED BY TARGET THEN
      INSERT (ApplicationId, TenantCode, TenantName, TenantTypeId, TenantTypeCode, ParentTenantId, IsActive)
      VALUES (src.ApplicationId, src.TenantCode, src.TenantName, src.TenantTypeId, src.TenantTypeCode
            , src.ParentTenantId, 1);

-- The closure is derived, so rebuild it rather than writing rows by hand.
-- It takes no arguments: the closure is rebuilt whole, for every application, because a partial rebuild is the version
-- that leaves a stale row nobody notices until a permission check denies something it should allow.
IF OBJECT_ID (N'auth.uspRebuildTenantClosure', N'P') IS NOT NULL
    EXEC auth.uspRebuildTenantClosure;
ELSE
    PRINT N'auth.uspRebuildTenantClosure is absent, so auth.TenantClosure was NOT rebuilt. Run 100_auth_functions.sql '
        + N'and 125_auth_tenant_procedures.sql, then re-run this file: every permission check walks the closure, and '
        + N'a stale one denies everything.';
GO


-- *** 2. auth.PermissionCategory -- the seven families ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

MERGE auth.PermissionCategory AS tgt
USING (VALUES (N'Data',     N'Business data',              10)
            , (N'User',     N'Person records',             20)
            , (N'Authz',    N'Profiles and role grants',   30)
            , (N'Tenant',   N'The tenant hierarchy',       40)
            , (N'Config',   N'Configuration and UI catalogue', 50)
            , (N'Audit',    N'The audit trails',           60)
            , (N'Platform', N'The platform itself',        70)
      ) AS src (CategoryCode, CategoryName, SortOrder)
   ON tgt.CategoryCode = src.CategoryCode
 WHEN MATCHED THEN
      UPDATE SET tgt.CategoryName         = src.CategoryName
               , tgt.SortOrder            = src.SortOrder
               , tgt.IsDeleted            = 0
               , tgt.auditDeletedBy       = NULL
               , tgt.auditDeletedDateUtc  = NULL
 WHEN NOT MATCHED BY TARGET THEN
      INSERT (CategoryCode, CategoryName, SortOrder)
      VALUES (src.CategoryCode, src.CategoryName, src.SortOrder);
GO


-- *** 3. auth.Permission -- Appendix A, all thirty-five, with their sentences ***
-- PermissionDescription carries the Appendix A sentence because otherwise the text beside a checkbox in a role editor
-- lives in the UI project, every application built from this template re-types the same thirty-five sentences, and they
-- drift from Appendix A with nothing detecting it.  BL-037, section 8.1.
--
-- IsTenantScoped = 0 on the three Platform permissions ONLY: they are evaluated without a tenant, because "may rebuild
-- the security cache" is not a thing you hold at a county.
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

DECLARE @AppCode NVARCHAR (50) = N'TEMPLATE';
DECLARE @ApplicationId INT = (SELECT ApplicationId FROM auth.Application WHERE ApplicationCode = @AppCode AND IsDeleted = 0);

DECLARE @Perms TABLE
(
    PermissionCode        NVARCHAR (200)  NOT NULL PRIMARY KEY,
    PermissionCategoryCode NVARCHAR (100) NOT NULL,
    PermissionName        NVARCHAR (400)  NOT NULL,
    IsTenantScoped        BIT             NOT NULL,
    PermissionDescription NVARCHAR (2000) NOT NULL
);

INSERT @Perms (PermissionCode, PermissionCategoryCode, PermissionName, IsTenantScoped, PermissionDescription)
VALUES
  (N'Data.Read',      N'Data', N'Read data',      1, N'See business rows. Drives the row-level security FILTER predicate, so a profile without it sees nothing at all rather than an empty screen with an error.')
, (N'Data.Insert',    N'Data', N'Insert data',    1, N'Create rows, anchored to the acting tenant. The BLOCK predicate refuses an insert carrying any other TenantId, so this permission cannot be used to plant a row elsewhere.')
, (N'Data.Update',    N'Data', N'Update data',    1, N'Modify existing rows.')
, (N'Data.SoftDelete', N'Data', N'Delete data',   1, N'Set IsDeleted = 1. Enforced in procedures only -- row-level security cannot tell a soft delete from an update, because both are UPDATE statements (section 10.4).')
, (N'Data.Restore',   N'Data', N'Restore data',   1, N'Clear IsDeleted. Separate from delete on purpose: the authority to undo a deletion is not the authority to perform one, and an auditor will want them apart.')
, (N'Data.Export',    N'Data', N'Export data',    1, N'Bulk extraction. The disclosure path that read permission alone does not distinguish -- reading one record and downloading every record are the same permission until you separate them.')
, (N'Data.Execute',   N'Data', N'Execute operations', 1, N'Run a registered operation -- a batch job, a recalculation, a nightly reconciliation triggered from a screen. NOT "may call stored procedures": every user calls stored procedures, because that is the only access path there is (section 8.1).')
, (N'Data.Approve',   N'Data', N'Approve records', 1, N'Make a decision recorded on a record.')
, (N'Data.Reassign',  N'Data', N'Reassign records', 1, N'Change who a record is assigned to.')
, (N'User.Read',      N'User', N'Read users',     1, N'See person records.')
, (N'User.Create',    N'User', N'Create users',   1, N'Create a person. Grants no profile anywhere and therefore no access to anything -- creating a user and giving them a hat are two authorities on purpose (section 11.4).')
, (N'User.Update',    N'User', N'Update users',   1, N'Change person details.')
, (N'User.Deactivate', N'User', N'Deactivate users', 1, N'Stop a person signing in at all, everywhere, regardless of how many profiles they hold. Distinct from deactivating one profile (section 8.5).')
, (N'User.ResetCredential', N'User', N'Reset credentials', 1, N'Reset a password (auth.uspSetPassword) or re-enrol a second factor. It never REVEALS a secret -- no procedure returns a stored verifier to a holder of this permission -- but T-112 made it honest about the other half: a reset installs a verifier the administrator chose, so the holder knows the value until the user replaces it. That is why auth.uspSetPassword forces MustChangePassword = 1 and why the event is filed as a Warning. Section 16.2, gap G-42.')
, (N'Authz.ProfileRead',      N'Authz', N'Read profiles',       1, N'See profiles and their grants.')
, (N'Authz.ProfileCreate',    N'Authz', N'Create profiles',     1, N'Create a profile at a tenant. Bounded by INV-05: only at a tenant the actor''s own authority covers.')
, (N'Authz.ProfileUpdate',    N'Authz', N'Update profiles',     1, N'Rename or re-default a profile.')
, (N'Authz.ProfileDeactivate', N'Authz', N'Deactivate profiles', 1, N'Remove one hat without removing the person.')
, (N'Authz.RoleRead',   N'Authz', N'Read roles',    1, N'See role definitions and what they contain.')
, (N'Authz.RoleDefine', N'Authz', N'Define roles',  1, N'Create or change what a role MEANS. Much larger than assigning one, and the requirement''s delegated county administrators should generally not have it (section 8.1).')
, (N'Authz.RoleAssign', N'Authz', N'Assign roles',  1, N'Grant a role to a profile. All four clauses of INV-05 apply, and the self-grant guard INV-06 refuses a grant to the actor''s own profile unless Authz.AllowSelfGrant is on.')
, (N'Authz.RoleRevoke', N'Authz', N'Revoke roles',  1, N'Withdraw a grant. The grant row is soft-deleted, not removed, because who held what last March is the question an audit asks (P-07).')
, (N'Tenant.Read',       N'Tenant', N'Read tenants',       1, N'See the hierarchy.')
, (N'Tenant.Create',     N'Tenant', N'Create tenants',     1, N'Add a tenant beneath one you administer. Also the permission that approves a self-service organization registration (section 16.4).')
, (N'Tenant.Update',     N'Tenant', N'Update tenants',     1, N'Rename or re-parent a tenant. Re-parenting rebuilds the closure and therefore changes what every existing grant beneath it reaches.')
, (N'Tenant.Deactivate', N'Tenant', N'Deactivate tenants', 1, N'Make a subtree unusable. Sessions at any tenant in the subtree stop working at their next auth.uspSetSessionContext call (E-50021), not at some later sweep.')
, (N'Config.Read',            N'Config', N'Read configuration',   1, N'Read application settings. Settings marked IsSensitive are withheld from the read path regardless of this permission.')
, (N'Config.Update',          N'Config', N'Update configuration', 1, N'Change application settings.')
, (N'Config.UiCatalogUpdate', N'Config', N'Update the UI catalogue', 1, N'Change the screen, tab and command catalogue that auth.uspGetNavigationForProfile returns. Changing what gates a screen is an authorization change, which is why it is not folded into Config.Update.')
, (N'Audit.ReadAuthentication', N'Audit', N'Read the authentication trail', 1, N'Read logs.AuthenticationEvent -- who signed in, from where, by which route, and what failed.')
, (N'Audit.ReadAuthorization',  N'Audit', N'Read the authorization trail',  1, N'Read logs.AuthorizationChange and logs.AuthorizationDenial -- who granted what to whom, and what was refused.')
, (N'Audit.ReadDataChange',     N'Audit', N'Read the data-change trail',    1, N'Read logs.DataChangeLog.')
, (N'Platform.ManageApplications',  N'Platform', N'Manage applications',      0, N'Register or retire an application. Evaluated without a tenant: an application is not owned by one.')
, (N'Platform.RebuildSecurityCache', N'Platform', N'Rebuild the security cache', 0, N'Force a rebuild of the derived tables -- auth.ProfilePermissionScope and auth.TenantClosure. Evaluated without a tenant, and requires IsPlatformAdmin as well (INV-09).')
, (N'Platform.BypassRowSecurity',   N'Platform', N'Bypass row security',      0, N'Open a maintenance session that row-level security does not filter (section 10.5). The single most dangerous permission in the catalogue; every session opened under it is recorded and IsPlatformAdmin is required on top (INV-09).');

MERGE auth.Permission AS tgt
USING (SELECT ApplicationId          = @ApplicationId
            , p.PermissionCode
            , p.PermissionName
            , p.PermissionDescription
            , p.IsTenantScoped
            , p.PermissionCategoryCode
            , c.PermissionCategoryId
         FROM @Perms                 AS p
         JOIN auth.PermissionCategory AS c ON c.CategoryCode = p.PermissionCategoryCode AND c.IsDeleted = 0) AS src
   ON tgt.ApplicationId = src.ApplicationId AND tgt.PermissionCode = src.PermissionCode
 WHEN MATCHED THEN
      UPDATE SET tgt.PermissionName        = src.PermissionName
               , tgt.PermissionDescription = src.PermissionDescription
               , tgt.IsTenantScoped        = src.IsTenantScoped
               , tgt.PermissionCategoryId  = src.PermissionCategoryId
               , tgt.PermissionCategoryCode = src.PermissionCategoryCode
               , tgt.IsDeleted             = 0
               , tgt.auditDeletedBy        = NULL
               , tgt.auditDeletedDateUtc   = NULL
 WHEN NOT MATCHED BY TARGET THEN
      INSERT (ApplicationId, PermissionCategoryId, PermissionCategoryCode, PermissionCode, PermissionName
            , PermissionDescription, IsTenantScoped)
      VALUES (src.ApplicationId, src.PermissionCategoryId, src.PermissionCategoryCode, src.PermissionCode
            , src.PermissionName, src.PermissionDescription, src.IsTenantScoped);

-- NO "WHEN NOT MATCHED BY SOURCE THEN soft delete".  A permission this file no longer names may still be held by a
-- live grant and named by a literal in 120_rls_policy.sql; removing it is a migration with a plan, not a line in a
-- MERGE.  A permission a project ADDS is therefore also safe here -- it survives every re-run.
-- Counted into a variable first: PRINT takes a scalar EXPRESSION and a subquery is not one (Msg 1046).
DECLARE @LivePermissions INT = (SELECT COUNT (*) FROM auth.Permission
                                 WHERE IsDeleted = 0 AND ApplicationId = @ApplicationId);

PRINT CONCAT (N'auth.Permission: ', @LivePermissions
            , N' live permission(s) for this application; Appendix A defines 35. A higher number is a project''s own '
            + N'additions and is expected; a lower one means this file was edited.');
GO


-- *** 4. auth.Role and auth.RolePermission -- the sixteen baseline roles ***
-- Owned by the root tenant so they are assignable anywhere (INV-04).  IsSystemRole = 1, which trg_au_updt_Role enforces
-- narrowly: the code, the flag and the row's existence are fixed (E-50012), while RoleName and RoleDescription stay
-- editable precisely so that the MERGE below can converge the labels on every deployment (BL-037).
--
-- DELIBERATELY SINGLE-PURPOSE, WITH TWO DELIBERATE EXCEPTIONS.  A tenant administrator composes authority by granting
-- several of these rather than by asking for a new role to be defined -- which is the difference between a template that
-- survives contact with a second project and one that accumulates a role per customer.  Section 16.2.
--
-- CRUD_ACCESS and PROFILE_ASSIGNER are the exceptions, and they earn it: composition only works when the pieces compose
-- to what somebody actually wants, and SCEN-AUTH-001 measured two cases where they do not -- "can do the work" and "can
-- assign profiles".  See the file header for the argument.  T-128, G-46, G-47.
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

DECLARE @AppCode NVARCHAR (50) = N'TEMPLATE', @RootCode NVARCHAR (50) = N'ROOT';
DECLARE @ApplicationId INT = (SELECT ApplicationId FROM auth.Application WHERE ApplicationCode = @AppCode AND IsDeleted = 0);
DECLARE @RootTenantId  INT = (SELECT TenantId FROM auth.Tenant
                               WHERE ApplicationId = @ApplicationId AND TenantCode = @RootCode AND IsDeleted = 0);

IF @RootTenantId IS NULL
BEGIN
    DECLARE @MsgRoot NVARCHAR (2000) =
        N'The root tenant is missing, so the baseline roles have no owner. Section 1 of this file creates it; if that '
      + N'section was skipped or the row was deleted, re-run this file from the top.';

    THROW 50000, @MsgRoot, 1;
END;

MERGE auth.Role AS tgt
USING (SELECT ApplicationId = @ApplicationId, OwnerTenantId = @RootTenantId, r.RoleCode, r.RoleName, r.RoleDescription
         FROM (VALUES
               (N'READ_ONLY',      N'Read only',          N'See business data and nothing else. The smallest useful grant, and the right starting point for an external organization''s users.')
             , (N'CONTRIBUTOR',    N'Contributor',        N'Read and create business data. Includes Data.Read because D-04 gives permissions no implication and a contributor who cannot read is useless -- the seed data is where that convenience belongs, not the evaluation rules.')
             , (N'EDITOR',         N'Editor',             N'Read and modify business data. Cannot create, delete or approve.')
             , (N'DATA_STEWARD',  N'Data steward',        N'Read, soft-delete and restore business data, and -- of necessity -- update it. The authority to tidy up. Data.Update is included because a soft delete IS an UPDATE and the row-security block predicate cannot tell the two apart (Msg 33504); see the comment above the role-permission map and gap G-38. The distinguishing grants are still Data.SoftDelete and Data.Restore, which EDITOR does not have.')
             , (N'OPERATOR',      N'Operator',            N'Read business data and run registered operations -- batch jobs and recalculations.')
             , (N'APPROVER',      N'Approver',            N'Read business data, approve records, reassign them and -- of necessity -- update them. The decision-making role. Data.Update is included because approving and reassigning are UPDATE statements and the row-security block predicate is built from Data.Update alone (Msg 33504); see the comment above the role-permission map and gap G-38. An auditor can still tell APPROVER from EDITOR, because only APPROVER holds Data.Approve, and dbo.uspApproveCaseFile demands it.')
             , (N'EXPORTER',      N'Exporter',            N'Read and bulk-export business data. Held apart from plain read because bulk extraction is the disclosure path read permission alone does not distinguish.')
             , (N'CRUD_ACCESS',   N'CRUD access',         N'Read, insert, update, soft-delete and execute. The ordinary working-level role, and the one this template shipped fourteen roles without: assembling it from CONTRIBUTOR + DATA_STEWARD + OPERATOR takes three grants and drags in Data.Restore, so every worker who needed to delete would also have been able to un-delete. Deliberately NOT Data.Restore, NOT Data.Approve, NOT Data.Reassign and NOT Data.Export -- undoing a deletion, making a decision, moving somebody else''s work and bulk extraction are each somebody''s job and none of them is this one. Gap G-46, T-128.')
             , (N'PROFILE_ASSIGNER', N'Profile assigner', N'Read, create and update profiles, and read, assign and revoke roles on them. What an agency means by "can assign profiles". It is ROLE_ADMIN minus Authz.ProfileDeactivate, and that one permission is the entire point of the separation: provisioning access and taking it away are different jobs, and the second is the one an audit asks about. INV-05 bounds every operation to the tenants the actor''s own authority covers and INV-06 still refuses a self-grant. Gap G-47, T-128.')
             , (N'USER_ADMIN',    N'User administrator',  N'The whole User family: read, create, update and deactivate people, and force a credential reset. Grants no profile to anyone anywhere (section 11.4).')
             , (N'ROLE_ADMIN',    N'Role administrator',  N'Hand out and withdraw existing roles, and manage profiles. Deliberately does NOT include Authz.RoleDefine: this is the delegated county administrator''s role, and defining what a role means is a larger authority than handing one out.')
             , (N'ROLE_ARCHITECT', N'Role architect',     N'Define what roles mean. Deliberately does NOT include Authz.RoleAssign, so the person who writes a role cannot silently hand it to themselves.')
             , (N'TENANT_ADMIN',  N'Tenant administrator', N'The whole Tenant family: read, create, update and deactivate tenants. Tenant.Create is also what approves a self-service organization registration.')
             , (N'AUDITOR',       N'Auditor',             N'The whole Audit family: all three trails, and nothing else. An auditor who can also change data is not an auditor.')
             , (N'CONFIG_ADMIN',  N'Configuration administrator', N'The whole Config family, including the UI element catalogue.')
             , (N'PLATFORM_ADMIN', N'Platform administrator', N'The whole Platform family, including the row-security bypass. INV-09 requires auth.User.IsPlatformAdmin = 1 as well, so this role alone confers nothing -- D-05 makes platform administration an authentication capability, not merely a role.')
              ) AS r (RoleCode, RoleName, RoleDescription)) AS src
   ON tgt.ApplicationId = src.ApplicationId
  AND tgt.OwnerTenantId = src.OwnerTenantId
  AND tgt.RoleCode      = src.RoleCode
 WHEN MATCHED THEN
      -- The two label columns, the resurrection, and -- since T-128 -- the system flag.  An earlier revision of this
      -- comment said setting IsSystemRole here could only ever be a no-op or an error, because E-50012 refuses CLEARING
      -- it.  That missed the case T-128 created: a database where a project or a scenario loader made one of these
      -- sixteen roles BY HAND while the seed was missing it, with IsSystemRole = 0.  055's trigger permits 0 -> 1 and
      -- refuses 1 -> 0, so this is the clause that adopts such a role into the baseline rather than leaving the flag
      -- disagreeing with the catalogue for the life of the database.  See the file header for the cost.
      UPDATE SET tgt.RoleName             = src.RoleName
               , tgt.RoleDescription       = src.RoleDescription
               , tgt.IsSystemRole          = 1
               , tgt.IsDeleted             = 0
               , tgt.auditDeletedBy        = NULL
               , tgt.auditDeletedDateUtc   = NULL
 WHEN NOT MATCHED BY TARGET THEN
      INSERT (ApplicationId, OwnerTenantId, RoleCode, RoleName, RoleDescription, IsAssignable, IsSystemRole)
      VALUES (src.ApplicationId, src.OwnerTenantId, src.RoleCode, src.RoleName, src.RoleDescription, 1, 1);
GO


-- The permission lists.  Five of the sixteen are expressed as WHOLE FAMILIES rather than as enumerated pairs --
-- USER_ADMIN, TENANT_ADMIN, AUDITOR, CONFIG_ADMIN and PLATFORM_ADMIN.  Section 16.2 words those five as "the User
-- family", "the Tenant family" and so on, and a category-driven row set says the same thing to the database: a project
-- that adds a permission to the Audit family gets it in AUDITOR on the next run of this file, which is what the wording
-- promises.  The other eleven are curated subsets and are enumerated.
--
-- CRUD_ACCESS IS ENUMERATED AND NOT "THE DATA FAMILY", which is the whole reason it is a useful role.  The Data family is
-- nine permissions; CRUD is five of them.  A family-driven row set would have handed every working-level profile
-- Data.Restore, Data.Approve, Data.Reassign and Data.Export as well, which is the failure the role exists to avoid and
-- which would silently get worse every time a project added a Data permission.  Same for PROFILE_ASSIGNER: six of the
-- eight Authz permissions, enumerated, because the two it omits are the point.  T-128.
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

DECLARE @AppCode NVARCHAR (50) = N'TEMPLATE', @RootCode NVARCHAR (50) = N'ROOT';
DECLARE @ApplicationId INT = (SELECT ApplicationId FROM auth.Application WHERE ApplicationCode = @AppCode AND IsDeleted = 0);
DECLARE @RootTenantId  INT = (SELECT TenantId FROM auth.Tenant
                               WHERE ApplicationId = @ApplicationId AND TenantCode = @RootCode AND IsDeleted = 0);

DECLARE @Map TABLE (RoleCode NVARCHAR (200) NOT NULL, PermissionCode NVARCHAR (200) NOT NULL
                  , PRIMARY KEY (RoleCode, PermissionCode));

-- ---------------------------------------------------------------------------------------------------------------------
-- WHY APPROVER AND DATA_STEWARD CARRY Data.Update, WHICH LOOKS LIKE IT DEFEATS THE POINT OF SEPARATING THEM
--
-- It does not, and the reason is measured rather than argued.  On a table bound by 120_rls_policy.sql, the BLOCK
-- predicate for UPDATE is auth.tvfTenantUpdatePredicate, and that function is built from Data.Update ALONE.  It has to
-- be: a block predicate is handed a row, not a statement, so it cannot tell an approval from a reassignment from a soft
-- delete from an ordinary edit.  All four are UPDATE statements touching different columns, and the predicate cannot see
-- columns.  The consequence is that a profile holding Data.Approve and NOT Data.Update cannot approve anything -- the
-- database refuses the UPDATE with Msg 33504, which is not catchable and carries no explanation a user could act on.
--
-- Seeded without the two rows below, this was measured on 2026-09-20: the APPROVER role could not approve, and could not
-- reassign, and DATA_STEWARD could not soft-delete or restore.  Three of the fourteen baseline roles were decorative.
--
-- The rejected alternative was to widen auth.tvfTenantUpdatePredicate's id list to accept any of the write verbs.  That
-- is worse, and for the same reason the predicate cannot help here: a Data.Restore holder would then be able to edit a
-- title, because once the row is released nothing checks which column moved.  So the coupling is honoured where it can be
-- stated precisely -- in the role grant and in the procedure -- and 180_dbo_application_procedures.sql demands the VERB
-- first and Data.Update second, so that the more specific refusal is the one the user reads.
--
-- What separation survives: Data.Update on its own still cannot approve, reassign, soft-delete or restore, because each
-- of those procedures demands its own verb too.  The EDITOR role is therefore still strictly weaker than APPROVER, and an
-- auditor can still tell the two apart.  What is lost is the ability to grant the authority to APPROVE a record without
-- also granting the authority to CORRECT one.  A project that needs that distinction cannot get it from row-level
-- security, and should get it from a column-level check in the procedure or from a trigger.  See gap G-38.
-- ---------------------------------------------------------------------------------------------------------------------
INSERT @Map (RoleCode, PermissionCode)
VALUES (N'READ_ONLY',      N'Data.Read')
     , (N'CONTRIBUTOR',    N'Data.Read'),       (N'CONTRIBUTOR',    N'Data.Insert')
     , (N'EDITOR',         N'Data.Read'),       (N'EDITOR',         N'Data.Update')
     , (N'DATA_STEWARD',   N'Data.Read'),       (N'DATA_STEWARD',   N'Data.SoftDelete'), (N'DATA_STEWARD', N'Data.Restore')
     , (N'DATA_STEWARD',   N'Data.Update')
     , (N'OPERATOR',       N'Data.Read'),       (N'OPERATOR',       N'Data.Execute')
     , (N'APPROVER',       N'Data.Read'),       (N'APPROVER',       N'Data.Approve'),    (N'APPROVER',     N'Data.Reassign')
     , (N'APPROVER',       N'Data.Update')
     , (N'EXPORTER',       N'Data.Read'),       (N'EXPORTER',       N'Data.Export')
     -- CRUD_ACCESS.  Data.Update is here on its own merits and not for the Msg 33504 reason APPROVER and DATA_STEWARD
     -- carry it: "update" is one of the five verbs the role is named for.  Data.SoftDelete still needs Data.Update
     -- beside it for the block predicate to release the row, which this role happens to satisfy already -- and that
     -- coincidence is worth naming, because it is why CRUD_ACCESS can soft-delete while a hand-rolled
     -- Read+Insert+SoftDelete role cannot.  G-46, T-128.
     , (N'CRUD_ACCESS',    N'Data.Read'),       (N'CRUD_ACCESS',    N'Data.Insert')
     , (N'CRUD_ACCESS',    N'Data.Update'),     (N'CRUD_ACCESS',    N'Data.SoftDelete')
     , (N'CRUD_ACCESS',    N'Data.Execute')
     -- PROFILE_ASSIGNER.  Six rows, and the two absences are the definition: no Authz.ProfileDeactivate (revocation is
     -- ROLE_ADMIN's, and a separate job) and no Authz.RoleDefine (ROLE_ARCHITECT's, and a much larger authority than
     -- handing an existing role out -- section 8.1).  G-47, T-128.
     , (N'PROFILE_ASSIGNER', N'Authz.ProfileRead'),   (N'PROFILE_ASSIGNER', N'Authz.ProfileCreate')
     , (N'PROFILE_ASSIGNER', N'Authz.ProfileUpdate'), (N'PROFILE_ASSIGNER', N'Authz.RoleRead')
     , (N'PROFILE_ASSIGNER', N'Authz.RoleAssign'),    (N'PROFILE_ASSIGNER', N'Authz.RoleRevoke')
     , (N'ROLE_ADMIN',     N'Authz.RoleRead'),  (N'ROLE_ADMIN',     N'Authz.RoleAssign')
     , (N'ROLE_ADMIN',     N'Authz.RoleRevoke'), (N'ROLE_ADMIN',    N'Authz.ProfileRead')
     , (N'ROLE_ADMIN',     N'Authz.ProfileCreate'), (N'ROLE_ADMIN', N'Authz.ProfileUpdate')
     , (N'ROLE_ADMIN',     N'Authz.ProfileDeactivate')
     , (N'ROLE_ARCHITECT', N'Authz.RoleDefine'), (N'ROLE_ARCHITECT', N'Authz.RoleRead');

-- The five whole-family roles.
INSERT @Map (RoleCode, PermissionCode)
SELECT f.RoleCode, p.PermissionCode
  FROM (VALUES (N'USER_ADMIN', N'User'), (N'TENANT_ADMIN', N'Tenant'), (N'AUDITOR', N'Audit')
             , (N'CONFIG_ADMIN', N'Config'), (N'PLATFORM_ADMIN', N'Platform')
       ) AS f (RoleCode, CategoryCode)
  JOIN auth.Permission AS p
    ON p.PermissionCategoryCode = f.CategoryCode
   AND p.ApplicationId          = @ApplicationId
   AND p.IsDeleted              = 0;

MERGE auth.RolePermission AS tgt
USING (SELECT ApplicationId = @ApplicationId, r.RoleId, p.PermissionId
         FROM @Map            AS m
         JOIN auth.Role       AS r ON r.RoleCode = m.RoleCode AND r.ApplicationId = @ApplicationId
                                  AND r.OwnerTenantId = @RootTenantId AND r.IsDeleted = 0
         JOIN auth.Permission AS p ON p.PermissionCode = m.PermissionCode AND p.ApplicationId = @ApplicationId
                                  AND p.IsDeleted = 0) AS src
   ON tgt.RoleId = src.RoleId AND tgt.PermissionId = src.PermissionId
 WHEN MATCHED AND tgt.IsDeleted = 1 THEN
      -- Resurrect in place.  UX_auth_RolePermission_Map is filtered on IsDeleted = 0 but the pair is still unique
      -- across the whole table in practice, and inserting a second row would leave two histories for one mapping.
      -- auditDeletedBy and auditDeletedDateUtc must be cleared in the SAME statement: CK_..._DeletedPair is evaluated
      -- before the AFTER trigger, so an UPDATE that only clears the flag fails the CHECK.
      UPDATE SET tgt.IsDeleted            = 0
               , tgt.auditDeletedBy       = NULL
               , tgt.auditDeletedDateUtc  = NULL
 WHEN NOT MATCHED BY TARGET THEN
      INSERT (RoleId, PermissionId, ApplicationId)
      VALUES (src.RoleId, src.PermissionId, src.ApplicationId);

DECLARE @Merged INT = @@ROWCOUNT;

-- WITHDRAW a baseline mapping this file no longer names -- soft, and ONLY from a system role owned by the root tenant.
-- A role a project defined is never touched, which is the only reason withdrawal is safe in a seed script at all.
--
-- This is a separate statement rather than a WHEN NOT MATCHED BY SOURCE clause on the MERGE above, because the "is it a
-- baseline role" test needs a subquery and a MERGE search condition is the wrong place to put one.  It also reads
-- better: "insert or resurrect what the catalogue names" and "withdraw what it no longer names" are two decisions.
UPDATE rp
   SET rp.IsDeleted           = 1
     , rp.auditDeletedBy      = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                        , ORIGINAL_LOGIN ())
     , rp.auditDeletedDateUtc = SYSUTCDATETIME ()
  FROM auth.RolePermission AS rp
  JOIN auth.Role           AS r ON r.RoleId = rp.RoleId
 WHERE rp.IsDeleted     = 0
   AND rp.ApplicationId = @ApplicationId
   AND r.IsSystemRole   = 1
   AND r.OwnerTenantId  = @RootTenantId
   AND NOT EXISTS (SELECT 1
                     FROM @Map            AS m
                     JOIN auth.Permission AS p ON p.PermissionCode = m.PermissionCode
                                              AND p.ApplicationId  = @ApplicationId
                                              AND p.IsDeleted      = 0
                    WHERE m.RoleCode = r.RoleCode
                      AND p.PermissionId = rp.PermissionId);

PRINT CONCAT (N'auth.RolePermission: ', @Merged, N' row(s) inserted or resurrected and ', @@ROWCOUNT
            , N' withdrawn this pass. Zero and zero on a second run is the expected result.');
GO


-- *** 5. The starter UI element catalogue -- T-090 ***
-- A tree the UI project extends rather than invents.  Section 13.1's five types, and both halves of the contract the UI
-- binds to: elements the profile cannot view are omitted by auth.uspGetNavigationForProfile entirely, and an element
-- with NO permission row is visible to every authenticated profile.
--
-- Area.Home AND Screen.Home ARE DELIBERATELY UNMAPPED.  They are the documented default, and 075's closing report and
-- 950_verify_deployment.sql both list unmapped elements -- so the expected state of a seeded database is "2 unmapped",
-- not "0 unmapped".  A project that adds a third and does not mean it will see the count move.
--
-- Area.Administration IS MAPPED TO SIX View PERMISSIONS, not one.  Section 13.2 defines CanView as "holds AT LEAST ONE
-- View-mode permission", so several rows on one element is an any-of, and the administration area appears to anybody
-- who administers anything.  Gating it on one permission would hide the whole area from a role administrator who has no
-- User.Read.
--
-- EVERY Command IS MAPPED TWICE, View AND Edit, TO THE SAME PERMISSION.  A button you can see but never press is a
-- support call; omitting it is the design's own answer (section 13.2).
--
-- THE CASE-FILE ELEMENTS ARE THE DEMO DOMAIN'S, AND ARE SEEDED ONLY WHERE THE DEMO DOMAIN IS INSTALLED.  Area.Cases and
-- everything beneath it (fourteen elements) are gated on Data.Read and its siblings, which a project's own roles will
-- hold for their own data -- so without 090's dbo.CaseFile they were a menu of screens that do not exist, shown to
-- every such role.  Where dbo.CaseFile is absent they are not seeded, and soft-deleted if an earlier run seeded them.
--
-- A GATE IS WITHDRAWN ONLY FROM AN ELEMENT THIS FILE SEEDS.  A project that keeps its own elements in its own script
-- (under its own ElementCode prefix) keeps their gates across a re-run of this file.  A project gate placed on one of
-- the starter elements above is withdrawn by a re-run, so the project's script must be re-run after this one -- which
-- is the install order anyway, because this file installs before any project catalogue.
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

DECLARE @AppCode NVARCHAR (50) = N'TEMPLATE';
DECLARE @ApplicationId INT = (SELECT ApplicationId FROM auth.Application WHERE ApplicationCode = @AppCode AND IsDeleted = 0);

DECLARE @Elements TABLE
(
    ElementCode  NVARCHAR (200) NOT NULL PRIMARY KEY,
    ElementType  NVARCHAR (20)  NOT NULL,
    ParentCode   NVARCHAR (200)     NULL,
    DisplayLabel NVARCHAR (400) NOT NULL,
    SortOrder    INT            NOT NULL,
    Depth        INT            NOT NULL   -- areas first, then screens, then tabs and commands: a parent must exist
);

INSERT @Elements (ElementCode, ElementType, ParentCode, DisplayLabel, SortOrder, Depth)
VALUES (N'Area.Home',           N'Area',    NULL,                 N'Home',            10, 0)
     , (N'Area.Cases',          N'Area',    NULL,                 N'Cases',           20, 0)
     , (N'Area.Administration', N'Area',    NULL,                 N'Administration',  90, 0)

     , (N'Screen.Home',         N'Screen',  N'Area.Home',           N'Home',              10, 1)
     , (N'Screen.CaseList',     N'Screen',  N'Area.Cases',          N'Case files',        10, 1)
     , (N'Screen.CaseDetail',   N'Screen',  N'Area.Cases',          N'Case file',         20, 1)
     , (N'Screen.UserAdmin',    N'Screen',  N'Area.Administration', N'Users',             10, 1)
     , (N'Screen.ProfileAdmin', N'Screen',  N'Area.Administration', N'Profiles',          20, 1)
     , (N'Screen.RoleAdmin',    N'Screen',  N'Area.Administration', N'Roles',             30, 1)
     , (N'Screen.TenantAdmin',  N'Screen',  N'Area.Administration', N'Tenants',           40, 1)
     , (N'Screen.AuditTrail',   N'Screen',  N'Area.Administration', N'Audit trails',      50, 1)
     , (N'Screen.Settings',     N'Screen',  N'Area.Administration', N'Settings',          60, 1)

     , (N'Tab.CaseSummary',     N'Tab',     N'Screen.CaseDetail',   N'Summary',           10, 2)
     , (N'Tab.CaseNotes',       N'Tab',     N'Screen.CaseDetail',   N'Notes',             20, 2)
     , (N'Tab.CaseHistory',     N'Tab',     N'Screen.CaseDetail',   N'History',           30, 2)

     , (N'Section.CaseApproval', N'Section', N'Tab.CaseSummary',    N'Approval',          10, 3)

     , (N'Command.CaseCreate',   N'Command', N'Screen.CaseList',    N'New case file',     10, 2)
     , (N'Command.CaseExport',   N'Command', N'Screen.CaseList',    N'Export',            20, 2)
     , (N'Command.CaseApprove',  N'Command', N'Section.CaseApproval', N'Approve',         10, 4)
     , (N'Command.CaseReassign', N'Command', N'Screen.CaseDetail',  N'Reassign',          30, 2)
     , (N'Command.CaseDelete',   N'Command', N'Screen.CaseDetail',  N'Delete',            40, 2)
     , (N'Command.CaseRestore',  N'Command', N'Screen.CaseDetail',  N'Restore',           50, 2)
     , (N'Command.NoteAdd',      N'Command', N'Tab.CaseNotes',      N'Add note',          10, 3)
     , (N'Command.UserCreate',   N'Command', N'Screen.UserAdmin',   N'New user',          10, 2)
     , (N'Command.RoleAssign',   N'Command', N'Screen.ProfileAdmin', N'Assign role',      10, 2)
     , (N'Command.RebuildCache', N'Command', N'Screen.Settings',    N'Rebuild security cache', 10, 2);

-- The demo domain's elements: Area.Cases and its descendants, taken from the tree above rather than listed twice.
DECLARE @HasDemo BIT = CASE WHEN OBJECT_ID (N'dbo.CaseFile') IS NULL THEN 0 ELSE 1 END;
DECLARE @Demo TABLE (ElementCode NVARCHAR (200) NOT NULL PRIMARY KEY);

WITH d AS (SELECT e.ElementCode FROM @Elements AS e WHERE e.ElementCode = N'Area.Cases'
           UNION ALL
           SELECT e.ElementCode FROM @Elements AS e JOIN d ON e.ParentCode = d.ElementCode)
INSERT @Demo (ElementCode)
SELECT d.ElementCode FROM d;

-- Insert by depth, because ParentUiElementId is a self-referencing foreign key and a set-based MERGE over the whole
-- tree cannot resolve a parent inserted by the same statement.
DECLARE @Depth INT = 0, @MaxDepth INT = (SELECT MAX (Depth) FROM @Elements);

WHILE @Depth <= @MaxDepth
BEGIN
    MERGE auth.UiElement AS tgt
    USING (SELECT ApplicationId = @ApplicationId
                , e.ElementCode, e.ElementType, e.DisplayLabel, e.SortOrder
                , ParentUiElementId = p.UiElementId
             FROM @Elements         AS e
             LEFT JOIN auth.UiElement AS p ON p.ElementCode = e.ParentCode
                                          AND p.ApplicationId = @ApplicationId AND p.IsDeleted = 0
            WHERE e.Depth = @Depth
              AND (@HasDemo = 1 OR NOT EXISTS (SELECT 1 FROM @Demo AS x WHERE x.ElementCode = e.ElementCode))) AS src
       ON tgt.ApplicationId = src.ApplicationId AND tgt.ElementCode = src.ElementCode
     WHEN MATCHED THEN
          -- ElementCode and ApplicationId are immutable (E-50010); the label, the order and the parent are not, because
          -- re-organising a menu is exactly what a project will want to do without re-keying the catalogue.
          UPDATE SET tgt.DisplayLabel        = src.DisplayLabel
                   , tgt.SortOrder           = src.SortOrder
                   , tgt.ParentUiElementId   = src.ParentUiElementId
                   , tgt.IsDeleted           = 0
                   , tgt.auditDeletedBy      = NULL
                   , tgt.auditDeletedDateUtc = NULL
     WHEN NOT MATCHED BY TARGET THEN
          INSERT (ApplicationId, ElementCode, ElementType, ParentUiElementId, DisplayLabel, SortOrder)
          VALUES (src.ApplicationId, src.ElementCode, src.ElementType, src.ParentUiElementId, src.DisplayLabel
                , src.SortOrder);

    SET @Depth += 1;
END;

IF @HasDemo = 0
BEGIN
    -- The pair is set in the same statement because CK_auth_UiElement_DeletedPair runs before the trigger.  Their gates
    -- drop out of the MERGE source below (it joins live elements only) and are withdrawn by its last clause.
    UPDATE e
       SET e.IsDeleted           = 1
         , e.auditDeletedBy      = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                           , ORIGINAL_LOGIN ())
         , e.auditDeletedDateUtc = SYSUTCDATETIME ()
      FROM auth.UiElement AS e
      JOIN @Demo          AS x ON x.ElementCode = e.ElementCode
     WHERE e.ApplicationId = @ApplicationId
       AND e.IsDeleted     = 0;

    PRINT CONCAT (N'auth.UiElement: no dbo.CaseFile, so the demo domain''s elements are not seeded; ', @@ROWCOUNT
                , N' soft-deleted this pass.');
END;

DECLARE @Gates TABLE (ElementCode NVARCHAR (200) NOT NULL, PermissionCode NVARCHAR (200) NOT NULL
                    , AccessMode NVARCHAR (10) NOT NULL, PRIMARY KEY (ElementCode, PermissionCode, AccessMode));

INSERT @Gates (ElementCode, PermissionCode, AccessMode)
VALUES (N'Area.Cases',          N'Data.Read',   N'View')
     , (N'Screen.CaseList',     N'Data.Read',   N'View')
     , (N'Screen.CaseDetail',   N'Data.Read',   N'View'), (N'Screen.CaseDetail', N'Data.Update', N'Edit')
     , (N'Tab.CaseSummary',     N'Data.Read',   N'View'), (N'Tab.CaseSummary',   N'Data.Update', N'Edit')
     , (N'Tab.CaseNotes',       N'Data.Read',   N'View'), (N'Tab.CaseNotes',     N'Data.Insert', N'Edit')
     , (N'Tab.CaseHistory',     N'Audit.ReadDataChange', N'View')
     , (N'Section.CaseApproval', N'Data.Read',  N'View'), (N'Section.CaseApproval', N'Data.Approve', N'Edit')

     , (N'Command.CaseCreate',   N'Data.Insert',   N'View'), (N'Command.CaseCreate',   N'Data.Insert',   N'Edit')
     , (N'Command.CaseExport',   N'Data.Export',   N'View'), (N'Command.CaseExport',   N'Data.Export',   N'Edit')
     , (N'Command.CaseApprove',  N'Data.Approve',  N'View'), (N'Command.CaseApprove',  N'Data.Approve',  N'Edit')
     , (N'Command.CaseReassign', N'Data.Reassign', N'View'), (N'Command.CaseReassign', N'Data.Reassign', N'Edit')
     , (N'Command.CaseDelete',   N'Data.SoftDelete', N'View'), (N'Command.CaseDelete', N'Data.SoftDelete', N'Edit')
     , (N'Command.CaseRestore',  N'Data.Restore',  N'View'), (N'Command.CaseRestore',  N'Data.Restore',  N'Edit')
     , (N'Command.NoteAdd',      N'Data.Insert',   N'View'), (N'Command.NoteAdd',      N'Data.Insert',   N'Edit')

     , (N'Area.Administration', N'User.Read',              N'View')
     , (N'Area.Administration', N'Authz.ProfileRead',      N'View')
     , (N'Area.Administration', N'Authz.RoleRead',         N'View')
     , (N'Area.Administration', N'Tenant.Read',            N'View')
     , (N'Area.Administration', N'Config.Read',            N'View')
     , (N'Area.Administration', N'Audit.ReadAuthorization', N'View')

     , (N'Screen.UserAdmin',    N'User.Read',         N'View'), (N'Screen.UserAdmin',    N'User.Update',         N'Edit')
     , (N'Screen.ProfileAdmin', N'Authz.ProfileRead', N'View'), (N'Screen.ProfileAdmin', N'Authz.ProfileUpdate', N'Edit')
     , (N'Screen.RoleAdmin',    N'Authz.RoleRead',    N'View'), (N'Screen.RoleAdmin',    N'Authz.RoleDefine',    N'Edit')
     , (N'Screen.TenantAdmin',  N'Tenant.Read',       N'View'), (N'Screen.TenantAdmin',  N'Tenant.Update',       N'Edit')
     , (N'Screen.AuditTrail',   N'Audit.ReadAuthentication', N'View')
     , (N'Screen.AuditTrail',   N'Audit.ReadAuthorization',  N'View')
     , (N'Screen.AuditTrail',   N'Audit.ReadDataChange',     N'View')
     , (N'Screen.Settings',     N'Config.Read',       N'View'), (N'Screen.Settings',     N'Config.Update',       N'Edit')

     , (N'Command.UserCreate',   N'User.Create',       N'View'), (N'Command.UserCreate',   N'User.Create',       N'Edit')
     , (N'Command.RoleAssign',   N'Authz.RoleAssign',  N'View'), (N'Command.RoleAssign',   N'Authz.RoleAssign',  N'Edit')
     , (N'Command.RebuildCache', N'Platform.RebuildSecurityCache', N'View')
     , (N'Command.RebuildCache', N'Platform.RebuildSecurityCache', N'Edit');

MERGE auth.UiElementPermission AS tgt
USING (SELECT ApplicationId = @ApplicationId, e.UiElementId, p.PermissionId, g.AccessMode
         FROM @Gates          AS g
         JOIN auth.UiElement  AS e ON e.ElementCode = g.ElementCode AND e.ApplicationId = @ApplicationId
                                  AND e.IsDeleted = 0
         JOIN auth.Permission AS p ON p.PermissionCode = g.PermissionCode AND p.ApplicationId = @ApplicationId
                                  AND p.IsDeleted = 0) AS src
   ON tgt.UiElementId = src.UiElementId AND tgt.PermissionId = src.PermissionId AND tgt.AccessMode = src.AccessMode
 WHEN MATCHED AND tgt.IsDeleted = 1 THEN
      UPDATE SET tgt.IsDeleted            = 0
               , tgt.auditDeletedBy       = NULL
               , tgt.auditDeletedDateUtc  = NULL
 WHEN NOT MATCHED BY TARGET THEN
      INSERT (UiElementId, PermissionId, ApplicationId, AccessMode)
      VALUES (src.UiElementId, src.PermissionId, src.ApplicationId, src.AccessMode)
 WHEN NOT MATCHED BY SOURCE AND tgt.IsDeleted = 0 AND tgt.ApplicationId = @ApplicationId
                            AND tgt.UiElementId IN (SELECT e.UiElementId
                                                      FROM auth.UiElement AS e
                                                      JOIN @Elements      AS s ON s.ElementCode = e.ElementCode
                                                     WHERE e.ApplicationId = @ApplicationId) THEN
      -- A gate this file no longer names, on an element this file seeds, is WITHDRAWN, soft.  The catalogue has no
      -- equivalent of IsSystemRole, so the guard is the element: a project that edits the starter catalogue edits THIS
      -- FILE, and a project that keeps its own elements in its own script keeps their gates (the section header).
      -- Deleted elements are in scope on purpose, so a demo element's gates go with it.
      UPDATE SET tgt.IsDeleted           = 1
               , tgt.auditDeletedBy      = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                                   , ORIGINAL_LOGIN ())
               , tgt.auditDeletedDateUtc = SYSUTCDATETIME ();
GO


-- *** 6. config.ApplicationSetting -- only the settings 025 does not own ***
-- 025_config_tables.sql seeds the twenty-three authentication, authorization and registration tunables, because
-- 110_auth_authn_procedures and 112_auth_mfa_procedures read them and both install long before this file.  These three
-- arrived with Phases 5 and 6 and belong to consumers that install AFTER 025, so they live here; Ui.CatalogueVersion
-- follows them, and belongs here for a different reason -- it is computed from the catalogue section 5 has just seeded,
-- so it could not be written anywhere earlier than this.  There is no overlap on purpose: a setting seeded in two places
-- is a setting with two defaults, and the second one to run wins silently.  BL-050.
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

MERGE config.ApplicationSetting AS tgt
USING (VALUES
       (N'Registration.ExternalBranchTenantCode', N'EXTORG', 'String', 0
      , N'The TenantCode of the tenant that approved external organizations are created beneath. auth.uspApproveOrganization reads it rather than carrying a literal, so a project can re-home the branch without a code change; E-50067 is what a caller sees when it names no usable tenant.')
     , (N'Perf.PermissionProbeSampleRate', N'0', 'Int', 0
      , N'One call in N to auth.uspDemandPermission is timed and recorded in logs.PermissionProbe. 0 disables the probe entirely and is the shipped default. The predicate FUNCTIONS never write -- a function cannot, and a schema-bound one must not -- so this is the caller-side measurement G-22 and section 10.6 call for. 1000 is a sensible production value; 1 is for a benchmark run and will itself distort the numbers.')
     , (N'Perf.PermissionProbeRetentionDays', N'14', 'Int', 0
      , N'How long logs.PermissionProbe rows are kept by logs.uspPurgePermissionProbe. The probe is a performance measurement, not an audit trail: nothing in Appendix B or section 18 depends on a row here surviving, which is why it has a retention at all when the audit tables do not.')
      ) AS src (SettingKey, SettingValue, ValueKind, IsSensitive, SettingDescription)
   ON tgt.SettingKey = src.SettingKey
 WHEN MATCHED THEN
      -- SettingValue is deliberately NOT updated on a match.  An operator who has tuned the sample rate should not have
      -- it reset by the next deployment; ShippedDefault is what records what the template intended, and
      -- 950_verify_deployment.sql is where a divergence gets reported.
      UPDATE SET tgt.SettingDescription   = src.SettingDescription
               , tgt.ValueKind            = src.ValueKind
               , tgt.ShippedDefault       = src.SettingValue
               , tgt.IsSensitive          = src.IsSensitive
               , tgt.IsDeleted            = 0
               , tgt.auditDeletedBy       = NULL
               , tgt.auditDeletedDateUtc  = NULL
 WHEN NOT MATCHED BY TARGET THEN
      INSERT (SettingKey, SettingValue, ValueKind, SettingDescription, ShippedDefault, IsSensitive)
      VALUES (src.SettingKey, src.SettingValue, src.ValueKind, src.SettingDescription, src.SettingValue
            , src.IsSensitive);
GO


-- Ui.CatalogueVersion -- G-18.  The one setting in this database whose SettingValue the seed DOES overwrite, and the
-- exception is the whole point of it.
--
-- WHY IT IS COMPUTED AND NOT TYPED.  A hand-bumped version number is a number somebody forgets: the element codes change
-- in one commit and the version in another, or in none, and the assertion it exists to support then passes on a database
-- it should have failed.  This value is DERIVED from the catalogue itself, so it cannot go stale and there is nothing to
-- remember.
--
-- WHAT IT IS DERIVED FROM IS THE PUBLISHED INTERFACE AND NOTHING ELSE.  UIH-AUTH-001 section 10 says element codes are an
-- interface: added to, never renamed.  So the digest covers the live (ElementCode, PermissionCode, AccessMode) triples
-- and NOT DisplayLabel, NOT SortOrder, NOT ParentUiElementId.  Renaming a label or reordering a menu is a change no
-- caller has bound to and must not invalidate anybody's build; adding, removing or renaming a CODE, or changing which
-- permission gates it, is a change to the contract and moves the value.  A digest over the whole row would have cried
-- wolf on every copy-edit, and a control that cries wolf is turned off.
--
-- WHY THE SEED OVERWRITES IT.  Every other key in 025 and in section 6 above is left alone on a match, because an
-- operator who tuned it did not make a mistake.  This one is not a tunable at all -- it is a FACT about the rows in
-- auth.UiElement and auth.UiElementPermission, and an operator editing it would be editing the answer to a question they
-- did not ask.  ShippedDefault gets the same value for the same reason: there is no divergence here for
-- 950_verify_deployment.sql to report, because the value is recomputed from the catalogue on every run of this file.
--
-- THE LIMIT, STATED RATHER THAN DISCOVERED.  The digest is taken over every live element of the TEMPLATE application at
-- the moment this file runs.  A project that seeds its own elements in its own later script must re-run this file
-- afterwards -- it is idempotent and that is the intended way -- or the value will describe a catalogue smaller than the
-- one the application is reading.  The closing report prints the value and the counts behind it so the mismatch is
-- visible on the transcript rather than at the next start-up.
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

DECLARE @CatalogueAppCode NVARCHAR (50) = N'TEMPLATE';
DECLARE @CatalogueAppId   INT = (SELECT ApplicationId FROM auth.Application
                                  WHERE ApplicationCode = @CatalogueAppCode AND IsDeleted = 0);

DECLARE @Contract    NVARCHAR (MAX) = NULL
      , @ElementCnt  INT            = 0
      , @MappingCnt  INT            = 0
      , @Version     NVARCHAR (100) = NULL;

-- LEFT JOIN, not INNER: an element with NO permission row is visible to every authenticated profile (section 13.1), which
-- is itself part of the contract -- mapping one later HIDES it from most callers, and that is exactly the kind of change
-- the version has to move for.  '-' stands in for the absent permission so the two states produce different digests.
SELECT @Contract = STRING_AGG (CAST (x.Triple AS NVARCHAR (MAX)), NCHAR (30))
                       WITHIN GROUP (ORDER BY x.Triple)
     , @MappingCnt = COUNT (*)
  FROM (SELECT Triple = CONCAT (e.ElementCode, NCHAR (31), COALESCE (p.PermissionCode, N'-')
                              , NCHAR (31), COALESCE (uep.AccessMode, N'-'))
          FROM auth.UiElement AS e
          LEFT JOIN auth.UiElementPermission AS uep ON uep.UiElementId = e.UiElementId
                                                   AND uep.IsDeleted   = 0
          LEFT JOIN auth.Permission          AS p   ON p.PermissionId  = uep.PermissionId
                                                   AND p.IsDeleted     = 0
         WHERE e.ApplicationId = @CatalogueAppId
           AND e.IsDeleted     = 0) AS x;

SELECT @ElementCnt = COUNT (*)
  FROM auth.UiElement
 WHERE ApplicationId = @CatalogueAppId
   AND IsDeleted     = 0;

-- Shape: <elements>.<mappings>.<16 hex>.  The counts are there so a human can read the value and a diff can be
-- interpreted without recomputing anything: two versions differing only in the count say "something was added or
-- removed", and two differing only in the digest say "something was renamed or re-gated".  Sixteen hex characters of
-- SHA-256 is not a security boundary -- nothing is authenticated by this string -- it is a change detector, and 64 bits
-- is far past the point where two catalogues collide by accident.
SET @Version = CONCAT (@ElementCnt, N'.', @MappingCnt, N'.'
                     , LOWER (CONVERT (NVARCHAR (64)
                                     , HASHBYTES ('SHA2_256', COALESCE (@Contract, N'(empty)')), 2)));
SET @Version = LEFT (@Version, LEN (CONCAT (@ElementCnt, N'.', @MappingCnt, N'.')) + 16);

MERGE config.ApplicationSetting AS tgt
USING (VALUES
       (N'Ui.CatalogueVersion', @Version, 'String', 0
      , N'A digest of the UI element catalogue as a published interface -- gap G-18. Computed by 115_seed_reference_data.sql from the live (ElementCode, PermissionCode, AccessMode) triples of the TEMPLATE application, and from nothing else: labels, sort orders and parentage are deliberately excluded, because renaming a menu item breaks no caller and must not invalidate anybody''s build. Shape is <elements>.<mappings>.<16 hex of SHA-256>. The application reads it at start-up and passes it to auth.uspGetNavigationForProfile as @ExpectedCatalogueVersion; a mismatch is E-50230, raised by the DATABASE rather than trusted to the application, because an assertion the caller may skip is not a control. THIS IS THE ONE SETTING THE SEED OVERWRITES ON A MATCH: it is a fact about the catalogue, not a tunable, so an operator editing it is editing the answer rather than the question. Re-run this file after seeding your own elements.')
      ) AS src (SettingKey, SettingValue, ValueKind, IsSensitive, SettingDescription)
   ON tgt.SettingKey = src.SettingKey
 WHEN MATCHED THEN
      UPDATE SET tgt.SettingValue         = src.SettingValue
               , tgt.SettingDescription   = src.SettingDescription
               , tgt.ValueKind            = src.ValueKind
               , tgt.ShippedDefault       = src.SettingValue
               , tgt.IsSensitive          = src.IsSensitive
               , tgt.IsDeleted            = 0
               , tgt.auditDeletedBy       = NULL
               , tgt.auditDeletedDateUtc  = NULL
 WHEN NOT MATCHED BY TARGET THEN
      INSERT (SettingKey, SettingValue, ValueKind, SettingDescription, ShippedDefault, IsSensitive)
      VALUES (src.SettingKey, src.SettingValue, src.ValueKind, src.SettingDescription, src.SettingValue
            , src.IsSensitive);

PRINT CONCAT (N'  Ui.CatalogueVersion = ', @Version, N'  (', @ElementCnt, N' live element(s), ', @MappingCnt
            , N' contract triple(s) including unmapped elements). G-18.');
GO


-- *** 7. auth.TenantDefaultRole for the external branch ***
-- Section 16.4 step 2 says an approved organization is seeded with READ_ONLY, CONTRIBUTOR and EDITOR.  Those three live
-- HERE, on the BRANCH, and every tenant approved beneath it INHERITS them -- section 11.5: auth.TenantDefaultRole is
-- "inherited from the nearest ancestor if absent".  So auth.uspApproveOrganization writes no default-role rows at all
-- and auth.uspCreateProfile resolves them by walking auth.TenantClosure upwards.  An agency user who changes this one
-- set therefore changes it for every external organization at once, including the ones already approved.  Copying the
-- rows down at approval time would have frozen each organization's defaults at the moment it was approved, which is the
-- behaviour nobody asks for and everybody discovers later.  BL-052.
--
-- ROLE_ADMIN IS NOT IN THE SET, and that is the requirement's own instruction: an agency user grants it by hand
-- (section 16.4 step 4).
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

DECLARE @AppCode NVARCHAR (50) = N'TEMPLATE', @RootCode NVARCHAR (50) = N'ROOT', @ExtCode NVARCHAR (50) = N'EXTORG';
DECLARE @ApplicationId INT = (SELECT ApplicationId FROM auth.Application WHERE ApplicationCode = @AppCode AND IsDeleted = 0);
DECLARE @RootTenantId  INT = (SELECT TenantId FROM auth.Tenant WHERE ApplicationId = @ApplicationId AND TenantCode = @RootCode AND IsDeleted = 0)
      , @ExtTenantId   INT = (SELECT TenantId FROM auth.Tenant WHERE ApplicationId = @ApplicationId AND TenantCode = @ExtCode  AND IsDeleted = 0);

MERGE auth.TenantDefaultRole AS tgt
USING (SELECT TenantId = @ExtTenantId, r.RoleId
            , GrantNote = N'Default for self-registered external organizations -- section 16.4 step 2. '
                        + N'ROLE_ADMIN is deliberately absent; an agency user grants it by hand.'
         FROM auth.Role AS r
        WHERE r.ApplicationId = @ApplicationId
          AND r.OwnerTenantId = @RootTenantId
          AND r.IsDeleted     = 0
          AND r.RoleCode IN (N'READ_ONLY', N'CONTRIBUTOR', N'EDITOR')) AS src
   ON tgt.TenantId = src.TenantId AND tgt.RoleId = src.RoleId
 WHEN MATCHED THEN
      UPDATE SET tgt.GrantNote            = src.GrantNote
               , tgt.IsDeleted            = 0
               , tgt.auditDeletedBy       = NULL
               , tgt.auditDeletedDateUtc  = NULL
 WHEN NOT MATCHED BY TARGET AND src.TenantId IS NOT NULL THEN
      INSERT (TenantId, RoleId, GrantNote)
      VALUES (src.TenantId, src.RoleId, src.GrantNote);
GO


-- *** 8. Grants ***
-- NONE.  Every table this file writes is reference data that applicationRole reads through views and procedures only;
-- 170_permissions.sql denies applicationRole the auth schema's tables outright (INV-11).
PRINT N'115_seed_reference_data.sql grants nothing. Every table it writes is reached through a view or a procedure; '
    + N'170_permissions.sql denies applicationRole the auth tables outright (INV-11).';
GO


-- *** 9. Closing report ***
DECLARE @AppCode NVARCHAR (50) = N'TEMPLATE', @RootCode NVARCHAR (50) = N'ROOT', @ExtCode NVARCHAR (50) = N'EXTORG';
DECLARE @ApplicationId INT = (SELECT ApplicationId FROM auth.Application WHERE ApplicationCode = @AppCode AND IsDeleted = 0);

DECLARE @Report TABLE
(
    RowNo    INT IDENTITY (1, 1) PRIMARY KEY,
    Severity INT             NOT NULL,
    Status   VARCHAR (10)    NOT NULL,
    Item     NVARCHAR (200)  NOT NULL,
    Detail   NVARCHAR (1000)     NULL
);

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN @ApplicationId IS NULL THEN 1 ELSE 4 END
     , CASE WHEN @ApplicationId IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Application ' + @AppCode
     , CONCAT (N'ApplicationId = ', COALESCE (CAST (@ApplicationId AS NVARCHAR (12)), N'(none)')
             , N'. One row, section 16.1 item 1. A project renames the two literals in section 1 of this file.');

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 2 THEN 4 ELSE 1 END
     , CASE WHEN COUNT (*) = 2 THEN 'OK' ELSE 'INCOMPLETE' END
     , N'Tenant skeleton'
     , CONCAT (COUNT (*), N' of 2 present: ', @RootCode, N' (the root, which OWNS the baseline roles -- INV-04) and '
             , @ExtCode, N' (the branch approved organizations are created beneath). Section 16.3 attributed the root '
             , N'to 900_bootstrap_first_admin.sql; the roles cannot be seeded without it, so it is created here and '
             , N'900 asserts it -- BL-051.')
  FROM auth.Tenant
 WHERE ApplicationId = @ApplicationId AND IsDeleted = 0 AND TenantCode IN (@RootCode, @ExtCode);

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 7 THEN 4 ELSE 1 END
     , CASE WHEN COUNT (*) = 7 THEN 'OK' ELSE 'INCOMPLETE' END
     , N'auth.PermissionCategory'
     , CONCAT (COUNT (*), N' of 7 families: Data, User, Authz, Tenant, Config, Audit, Platform. Section 8.1.')
  FROM auth.PermissionCategory WHERE IsDeleted = 0;

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Live >= 35 AND x.Undescribed = 0 AND x.Untenanted = 3 THEN 4 ELSE 1 END
     , CASE WHEN x.Live >= 35 AND x.Undescribed = 0 AND x.Untenanted = 3 THEN 'OK' ELSE 'INCOMPLETE' END
     , N'auth.Permission'
     , CONCAT (x.Live, N' live (Appendix A defines 35; more is a project''s own additions). '
             , x.Undescribed, N' without a PermissionDescription -- must be 0, BL-037: the sentence beside a checkbox '
             , N'in a role editor comes from the row, not the UI project. '
             , x.Untenanted, N' with IsTenantScoped = 0 -- must be 3, the Platform family.')
  FROM (SELECT Live        = COUNT (*)
             , Undescribed = SUM (CASE WHEN PermissionDescription IS NULL OR LEN (LTRIM (PermissionDescription)) = 0 THEN 1 ELSE 0 END)
             , Untenanted  = SUM (CASE WHEN IsTenantScoped = 0 THEN 1 ELSE 0 END)
          FROM auth.Permission
         WHERE ApplicationId = @ApplicationId AND IsDeleted = 0) AS x;

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Roles = 16 AND x.Undescribed = 0 AND x.Unmapped = 0 THEN 4 ELSE 1 END
     , CASE WHEN x.Roles = 16 AND x.Undescribed = 0 AND x.Unmapped = 0 THEN 'OK' ELSE 'INCOMPLETE' END
     , N'auth.Role -- the baseline'
     , CONCAT (x.Roles, N' of 16 system roles owned by the root (14 from section 16.2 plus CRUD_ACCESS and '
             , N'PROFILE_ASSIGNER -- T-128, G-46, G-47), ', x.Mappings, N' live permission mapping(s) between '
             , N'them. ', x.Undescribed, N' without a RoleDescription and ', x.Unmapped, N' granting no permission at '
             , N'all -- both must be 0. A baseline role with an empty permission list is the failure mode that looks '
             , N'like success: every grant of it succeeds and confers nothing.')
  FROM (SELECT Roles       = COUNT (*)
             , Undescribed = SUM (CASE WHEN r.RoleDescription IS NULL OR LEN (LTRIM (r.RoleDescription)) = 0 THEN 1 ELSE 0 END)
             , Unmapped    = SUM (CASE WHEN m.Mapped IS NULL THEN 1 ELSE 0 END)
             , Mappings    = SUM (COALESCE (m.Mapped, 0))
          FROM auth.Role AS r
          LEFT JOIN (SELECT RoleId, Mapped = COUNT (*)
                       FROM auth.RolePermission
                      WHERE IsDeleted = 0
                      GROUP BY RoleId) AS m ON m.RoleId = r.RoleId
         WHERE r.ApplicationId = @ApplicationId AND r.IsSystemRole = 1 AND r.IsDeleted = 0) AS x;

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Elements = x.Starter AND x.Unmapped = 2 AND x.Orphans = 0 THEN 4 ELSE 2 END
     , CASE WHEN x.Elements = x.Starter AND x.Unmapped = 2 AND x.Orphans = 0 THEN 'OK' ELSE 'REVIEW' END
     , N'auth.UiElement -- the starter catalogue'
     , CONCAT (x.Elements, N' of ', x.Starter, N' starter element(s) (26 with the demo domain, 12 without: section 5), '
             , x.Gates, N' gate(s). ', x.Unmapped
             , N' unmapped and therefore VISIBLE TO EVERY AUTHENTICATED PROFILE -- expected to be exactly 2, '
             , N'Area.Home and Screen.Home, which are the documented default (section 13.1). ', x.Orphans
             , N' non-Area element(s) with no parent -- must be 0. Any other count means the catalogue was '
             , N'extended, which is what T-090 intends; check the two unmapped ones are still the Home pair.')
  FROM (SELECT Starter  = CASE WHEN OBJECT_ID (N'dbo.CaseFile') IS NULL THEN 12 ELSE 26 END
             , Elements = (SELECT COUNT (*) FROM auth.UiElement WHERE ApplicationId = @ApplicationId AND IsDeleted = 0)
             , Gates    = (SELECT COUNT (*) FROM auth.UiElementPermission WHERE ApplicationId = @ApplicationId AND IsDeleted = 0)
             , Unmapped = (SELECT COUNT (*)
                             FROM auth.UiElement AS e
                            WHERE e.ApplicationId = @ApplicationId AND e.IsDeleted = 0
                              AND NOT EXISTS (SELECT 1 FROM auth.UiElementPermission AS g
                                               WHERE g.UiElementId = e.UiElementId AND g.IsDeleted = 0))
             , Orphans  = (SELECT COUNT (*) FROM auth.UiElement
                            WHERE ApplicationId = @ApplicationId AND IsDeleted = 0
                              AND ElementType <> N'Area' AND ParentUiElementId IS NULL)) AS x;

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 3 THEN 4 ELSE 1 END
     , CASE WHEN COUNT (*) = 3 THEN 'OK' ELSE 'INCOMPLETE' END
     , N'auth.TenantDefaultRole on the external branch'
     , CONCAT (COUNT (*), N' of 3: READ_ONLY, CONTRIBUTOR, EDITOR. Every tenant approved beneath the branch '
             , N'INHERITS them -- auth.uspCreateProfile walks auth.TenantClosure upwards to the nearest ancestor '
             , N'that has any (section 11.5), so changing this one set changes it for every external organization at '
             , N'once. BL-052. ROLE_ADMIN is deliberately absent (section 16.4 step 4).')
  FROM auth.TenantDefaultRole AS d
  JOIN auth.Tenant            AS t ON t.TenantId = d.TenantId
 WHERE t.ApplicationId = @ApplicationId AND t.TenantCode = @ExtCode AND t.IsDeleted = 0 AND d.IsDeleted = 0;

-- 27 is what exists at THIS point in the manifest: 23 from 025_config_tables.sql and 4 from this file.  The test is
-- >= and not =, because 175_perf_instrumentation.sql seeds Perf.PermissionProbeBurstCount at step 37 and this file is
-- step 27, so every deployment after the first one sees 28.  An = test would have reported REVIEW on every
-- re-deployment of a working database, which is the kind of false alarm that teaches people to skip the report.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) >= 27 THEN 4 ELSE 2 END
     , CASE WHEN COUNT (*) >= 27 THEN 'OK' ELSE 'REVIEW' END
     , N'config.ApplicationSetting'
     , CONCAT (COUNT (*), N' live setting(s); at least 27 expected here -- 23 seeded by 025_config_tables.sql and 4 by '
             , N'this file. 28 is normal on a re-deployment: 175_perf_instrumentation.sql adds '
             , N'Perf.PermissionProbeBurstCount later in the manifest. No key is seeded twice on purpose -- a setting '
             , N'with two defaults is a setting whose value depends on install order (BL-050).')
  FROM config.ApplicationSetting WHERE IsDeleted = 0;

-- Ui.CatalogueVersion (G-18).  Recomputed here rather than read from the variable section 6 used, because this is a
-- different batch and because the point of the row is to prove what LANDED, not to repeat what was calculated.  A
-- mismatch between the stored digest and the live catalogue means something seeded elements after this file ran and
-- did not re-run it -- which is precisely the condition E-50230 refuses at auth.uspGetNavigationForProfile.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Stored IS NULL THEN 1 WHEN x.Stored = x.Live THEN 4 ELSE 2 END
     , CASE WHEN x.Stored IS NULL THEN 'INCOMPLETE' WHEN x.Stored = x.Live THEN 'OK' ELSE 'REVIEW' END
     , N'Ui.CatalogueVersion -- the published catalogue contract'
     , CONCAT (N'Stored ', COALESCE (QUOTENAME (x.Stored, N''''), N'(absent)'), N', live ', QUOTENAME (x.Live, N'''')
             , N'. ', x.Elements, N' element(s) and ', x.Mappings, N' contract triple(s) behind it. The '
             , N'digest covers ElementCode, PermissionCode and AccessMode only -- a display label or a sort order '
             , N'moving does NOT move the version, because codes are the published interface (section 13.1, G-18). '
             , N'The application reads this key at start-up and passes it to auth.uspGetNavigationForProfile, which '
             , N'raises E-50230 when it disagrees. REVIEW here means a later seed added elements without re-running '
             , N'this file; re-run it, it is idempotent.')
  FROM (SELECT Stored   = (SELECT s.SettingValue
                             FROM config.ApplicationSetting AS s
                            WHERE s.SettingKey = N'Ui.CatalogueVersion' AND s.IsDeleted = 0)
             , Live     = v.Live
             , Elements = v.Elements
             , Mappings = v.Mappings
          FROM (SELECT Live = LEFT (CONCAT (c.Elements, N'.', c.Mappings, N'.'
                                          , LOWER (CONVERT (NVARCHAR (64)
                                                          , HASHBYTES ('SHA2_256', COALESCE (c.Contract, N'(empty)')), 2)))
                                  , LEN (CONCAT (c.Elements, N'.', c.Mappings, N'.')) + 16)
                     , c.Elements
                     , c.Mappings
                  FROM (SELECT Contract = STRING_AGG (CAST (t.Triple AS NVARCHAR (MAX)), NCHAR (30))
                                              WITHIN GROUP (ORDER BY t.Triple)
                             , Mappings = COUNT (*)
                             , Elements = COUNT (DISTINCT t.ElementCode)
                          FROM (SELECT e.ElementCode
                                     , Triple = CONCAT (e.ElementCode, NCHAR (31), COALESCE (p.PermissionCode, N'-')
                                                      , NCHAR (31), COALESCE (uep.AccessMode, N'-'))
                                  FROM auth.UiElement AS e
                                  LEFT JOIN auth.UiElementPermission AS uep
                                         ON uep.UiElementId = e.UiElementId AND uep.IsDeleted = 0
                                  LEFT JOIN auth.Permission          AS p
                                         ON p.PermissionId  = uep.PermissionId AND p.IsDeleted = 0
                                 WHERE e.ApplicationId = @ApplicationId AND e.IsDeleted = 0) AS t) AS c) AS v) AS x;

-- The one that matters most, and the one a hand-run gets wrong.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (N'auth.tvfTenantReadPredicate', N'IF') IS NULL THEN 3 ELSE 2 END
     , CASE WHEN OBJECT_ID (N'auth.tvfTenantReadPredicate', N'IF') IS NULL THEN 'PENDING' ELSE 'ACTION' END
     , N'Run 120_rls_policy.sql next'
     , N'It bakes Data.Read''s permission id into the predicate functions. Until it runs again they hold whatever id '
     + N'they were built with -- the sentinel -1 on a database seeded for the first time, which denies every '
     + N'non-maintenance session. Fail-closed, and baffling (UI-35). Install-TemplateDatabase.ps1 has the order right.';

IF EXISTS (SELECT 1 FROM @Report WHERE Severity = 1)
    PRINT N'Reference data: PROBLEMS found. Read the report below before running 120_rls_policy.sql.';
ELSE
    PRINT N'Reference data seeded. Run 120_rls_policy.sql next -- see the last row of the report.';

PRINT N'';

SELECT Severity, Status, Item, Detail
  FROM @Report
 ORDER BY Severity, RowNo;
GO
