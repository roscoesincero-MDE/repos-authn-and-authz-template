/***********************************************************************************************************************
Script:         _tests/070_variants_end_to_end.sql
Purpose:        The Phase 6 exit criterion "all three variants of section 17 build END TO END THROUGH THE PROCEDURES".
                _tests/020_tenancy_variant_trees.sql builds the three tenant SHAPES by writing auth.Tenant directly,
                and says in its own header that a later phase should switch the ordinary tenants over to
                auth.uspCreateTenant because "that is a better test than this one".  This is that file.  It takes one
                variant's skeleton and grows a whole working deployment on top of it -- catalogue, policy, an
                administrator, new tenants, new users, new profiles, role grants, self-service registration and real
                case work -- using nothing but the shipped procedures once the irreducible bootstrap is past.
Target:         SQL Server 2022 or newer.
Run as:         db_owner in the target database.  Sections 4 onwards act as ordinary application users.
Run in:         The target database.
Run with:       sqlcmd -S <server> -E -d <db> -I -C -b -v DbName=<db> -v Variant=VARIANT1 -v Seed=<unique-text> \
                       -i database/_tests/070_variants_end_to_end.sql
                Then again with -v Variant=VARIANT2, and again with -v Variant=VARIANT3.  A DIFFERENT -v Seed= each
                run: the seed becomes a session token, and a token is not reusable.
Idempotent:     Yes.  Every write is a MERGE or an existence-guarded call, and the case work is keyed on a case number
                derived from $(Variant), so a second run updates instead of duplicating.
Depends on:     _tests/020_tenancy_variant_trees.sql (the three skeletons), and a fully installed database -- every
                script through 180_dbo_application_procedures.sql.
Implements:     PLAN-AUTH-001 Phase 6.  Task T-093.  DES-AUTH-001 section 17 and sections 5, 8, 9, 11, 12, 13 and 16.
To retarget:    Pass it per run:  -d <db> -v DbName=<db>.  There is no in-file default.

ONE VARIANT PER RUN, AND FOUR CONNECTIONS PER RUN, AND NEITHER IS A CONVENIENCE
------------------------------------------------------------------------------
SESSION_CONTEXT keys are set with @read_only = 1, so they are fixed for the life of a connection: a second attempt to
set one fails with error 15664, which auth.uspSetSessionContext reports as E-50022 (G-36, BL-057).  The consequence is
not a limitation of this test, it is the shape of the product: ONE CONNECTION MAY NOT SERVE TWO ACTING PROFILES.  UI-06
has said so from the beginning, and auth.uspSwitchProfile writes the switch to auth.UserSession and then tells the
caller, in its own words, that the new hat arrives on the NEXT connection.

So a test that drives an administrator AND a worker cannot be one batch on one connection, and pretending otherwise
would mean the test silently exercises whichever profile got there first.  This file uses sqlcmd's  :connect  to open a
genuinely new session between stages, which is exactly what the application layer does between requests.

AND SIGNING IN COSTS TWO CONNECTIONS, NOT ONE, WHICH THIS FILE LEARNED BY FAILING
--------------------------------------------------------------------------------
auth.uspCompleteLogin does not choose a profile.  It opens a session and nothing else -- 110_auth_authn_procedures.sql
never mentions IsDefault and never sets session context -- so a freshly authenticated session is PROFILELESS, and the
acting hat is chosen afterwards by auth.uspSwitchProfile (section 12.1).  auth.uspSwitchProfile establishes context from
the token BEFORE it switches, which at that moment means a profileless context, and then commits the switch and returns
its two result sets WITHOUT re-establishing anything, because it cannot (G-36, BL-057).  The connection is therefore
holding a context that says "no profile" while the session row now says "profile N", and the next procedure call on it
fails with E-50022 naming exactly that disagreement.

That is not a defect, it is the round-trip boundary made visible, and the first draft of this file walked straight into
it: section 5 died at auth.uspCreateTenant with E-50022, not section 4.  The consequence for any client is worth stating
plainly, because it is not obvious from any one procedure's header: A SIGN-IN IS TWO ROUND TRIPS.  One to authenticate
and choose the hat, and a second, on a new connection, before the hat can do anything.

    connection 1   db_owner, no session       sections 0-3   preflight, catalogue clone, RLS policy, bootstrap admin
    connection 2   authenticating             section 4      the administrator logs in and switches profile; spent
    connection 3   the variant administrator  sections 5-7   tenants, users, profiles, role grants, registration
    connection 4   authenticating             section 8      the worker's credential, login and switch; spent
    connection 5   the variant worker         section 9      the demonstration domain, under row-level security
    connection 6   db_owner, no session       section 10     the closing report, which reads what the others wrote

Nothing is carried across a :connect except the sqlcmd -v variables.  Local variables and table variables are gone, so
each stage RE-RESOLVES the ids it needs from the database.  That is a feature: a stage that cannot find what the
previous stage claimed to create fails here, in a named section, instead of succeeding against a stale variable.

And one variant per run for the same reason at one remove: three variants means three administrators, and an
administrator is an acting profile.

WHAT IS STILL A DIRECT WRITE, AND WHY IT CANNOT BE ANYTHING ELSE
---------------------------------------------------------------
Section 3 writes auth.[User], auth.UserProfile, auth.UserProfileRole and auth.UserCredential directly.  This is not
laziness; it is the bootstrap problem, and it has three separate causes that no amount of procedure-writing removes:

  1.  Every administrative procedure demands a permission, and auth.uspDemandPermission reads the permission out of the
      session.  Before the first session exists there is no one to demand from.  900_bootstrap_first_admin.sql exists
      for precisely this reason and does precisely this, for the TEMPLATE application; section 3 is that script's logic
      aimed at a variant root.

  2.  auth.uspCreateTenant REFUSES to create a root (E-50094, INV-02), because a root has no parent at which the
      creation could be authorized.  A root arrives with its application, from a script running as db_owner.  020
      already made the three roots; this file never tries to.

  3.  There is NO PROCEDURE THAT WRITES auth.UserCredential.  auth.Permission seeds User.ResetCredential and
      USER_ADMIN carries it, but no shipped procedure demands it and none sets a verifier -- auth.uspCreateUser has no
      verifier parameter.  So a password verifier can only be written directly, by the installer or by the application
      layer's own data access.  Recorded as a gap by this file's section 9, which asserts it rather than describing it,
      so the day a credential procedure is written this test starts reporting the gap as closed.

Everything after section 3 goes through the procedures.  Where it could not, section 9 says so out loud.

WHY SECTION 2 REBUILDS THE ROW-SECURITY POLICY, AND WHY FORGETTING IT WOULD PASS
-------------------------------------------------------------------------------
'Data.Read' is not one permission.  auth.Permission is keyed on (ApplicationId, PermissionCode), so cloning the
catalogue into a variant application MINTS NEW PERMISSION IDS, and the three RLS predicates carry a LIST of literal ids
baked in when auth.uspRebuildTenantAccessPolicy last ran (BL-039).  A clone without a rebuild leaves the predicates
resolving the OLD list: the variant's Data.Read grant is real, the scope rows are real, and the predicate has never
heard of the id, so section 8 reads zero rows and nothing anywhere reports an error.  That is UI-35, and it is the
quietest failure in this schema.  Section 2 runs the rebuild and section 9 re-checks the id lists afterwards.

WHAT IT DELIBERATELY DOES NOT DO
--------------------------------
It does not clean up, and it is not in the install manifest.  It runs against the variant applications, which are
development fixtures with no business meaning, and it leaves its administrator, worker and case files in place so that
a failure can be investigated instead of reconstructed.  Re-running it is the reset.
***********************************************************************************************************************/
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;
GO


-- *** 0. Assert the target, the parameters and the machinery ***
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

-- 0a. The variant must be one of the three 020 builds.  Asserted against auth.Application rather than against a list
--     of three literals, because the real requirement is that the skeleton EXISTS, not that the spelling is familiar.
IF N'$(Variant)' NOT IN (N'VARIANT1', N'VARIANT2', N'VARIANT3')
BEGIN
    DECLARE @BadVariant NVARCHAR (2000) =
        N'-v Variant=$(Variant) is not one of VARIANT1, VARIANT2 or VARIANT3. Those are the three shapes section 17 '
      + N'names and the three applications _tests/020_tenancy_variant_trees.sql creates. Nothing has been changed.';

    THROW 50000, @BadVariant, 1;
END
GO

IF NOT EXISTS (SELECT 1 FROM auth.Application WHERE ApplicationCode = N'$(Variant)' AND IsActive = 1 AND IsDeleted = 0)
   OR NOT EXISTS (SELECT 1
                    FROM auth.Tenant AS t
                   INNER JOIN auth.Application AS a ON a.ApplicationId = t.ApplicationId
                   WHERE a.ApplicationCode = N'$(Variant)'
                     AND t.TenantCode      = N'ROOT'
                     AND t.IsDeleted       = 0)
   OR NOT EXISTS (SELECT 1
                    FROM auth.Tenant AS t
                   INNER JOIN auth.Application AS a ON a.ApplicationId = t.ApplicationId
                   WHERE a.ApplicationCode = N'$(Variant)'
                     AND t.TenantCode      = N'AGENCY'
                     AND t.IsDeleted       = 0)
BEGIN
    DECLARE @NoSkeleton NVARCHAR (2000) =
        N'The $(Variant) application, or its ROOT or AGENCY tenant, is absent. This file grows a deployment on top of '
      + N'a skeleton it does not build: run  database/_tests/020_tenancy_variant_trees.sql  first. Nothing has been '
      + N'changed.';

    THROW 50000, @NoSkeleton, 1;
END
GO

-- 0b. Every procedure this file calls, named before it is needed.  Without this the first missing object arrives as
--     "Could not find stored procedure" four hundred lines down, which reads as a defect in the test.
DECLARE @Absent NVARCHAR (2000) = NULL;

SELECT @Absent = STRING_AGG (x.ObjectName, N', ') WITHIN GROUP (ORDER BY x.ObjectName)
  FROM (VALUES (N'auth.uspRebuildTenantAccessPolicy')
             , (N'auth.uspRebuildProfilePermissionScope')
             , (N'auth.uspGetLoginVerifier')
             , (N'auth.uspCompleteLogin')
             , (N'auth.uspSwitchProfile')
             , (N'auth.uspCreateTenant')
             , (N'auth.uspCreateUser')
             , (N'auth.uspCreateProfile')
             , (N'auth.uspAssignRoleToProfile')
             , (N'auth.uspRegisterOrganization')
             , (N'auth.uspApproveOrganization')
             , (N'auth.uspRegisterExternalUser')
             , (N'dbo.uspCreateCaseFile')
             , (N'dbo.uspAddCaseNote')
             , (N'dbo.uspUpdateCaseFile')
             , (N'dbo.uspApproveCaseFile')
             , (N'dbo.uspGetCaseFile')
             , (N'dbo.uspListCaseFiles')) AS x (ObjectName)
 WHERE OBJECT_ID (x.ObjectName) IS NULL;

IF @Absent IS NOT NULL
BEGIN
    DECLARE @NotInstalled NVARCHAR (2000) =
        N'This test drives the whole shipped calling surface and some of it is not installed. Absent: ' + @Absent
      + N'. Run  database/Install-TemplateDatabase.ps1  first. Nothing has been changed.';

    THROW 50000, @NotInstalled, 1;
END
GO

-- 0c. TEMPLATE is the source the catalogue is cloned FROM, so an unseeded TEMPLATE is a precondition failure and not a
--     surprise in section 1.  Thirty-five permissions and sixteen roles is what 115_seed_reference_data.sql ships.
IF (SELECT COUNT (*)
      FROM auth.Permission AS p
     INNER JOIN auth.Application AS a ON a.ApplicationId = p.ApplicationId
     WHERE a.ApplicationCode = N'TEMPLATE'
       AND p.IsDeleted       = 0) < 35
   OR (SELECT COUNT (*)
         FROM auth.Role AS r
        INNER JOIN auth.Application AS a ON a.ApplicationId = r.ApplicationId
        WHERE a.ApplicationCode = N'TEMPLATE'
          AND r.IsDeleted       = 0) < 16
BEGIN
    DECLARE @NoCatalogue NVARCHAR (2000) =
        N'The TEMPLATE application does not hold the seeded catalogue this file clones from -- 35 permissions and 16 '
      + N'roles are expected. Run  database/115_seed_reference_data.sql. Nothing has been changed.';

    THROW 50000, @NoCatalogue, 1;
END
GO

PRINT N'--- 070_variants_end_to_end.sql: $(Variant) in [$(DbName)] ---';
PRINT N'Section 0: preflight passed. Skeleton, procedures and TEMPLATE catalogue all present.';
GO
-- *** 1. Clone TEMPLATE's catalogue into the variant application ***
-- A tenant tree without a permission catalogue is furniture.  020 creates the three variant applications and their
-- tenants and NOTHING ELSE, because 115_seed_reference_data.sql seeds TEMPLATE only -- which is correct for a template,
-- since a project's catalogue is a project's business.  This section does for a variant what 115 does for TEMPLATE, and
-- it does it by copying rather than by restating: a hand-written second copy of thirty-five permissions and sixteen
-- roles would drift from the first, and then the test would be testing the copy.
--
-- auth.PermissionCategory is NOT cloned, because it has no ApplicationId: the categories are a global vocabulary and
-- every application's permissions point at the same eight rows.  auth.UiElement and auth.UiElementPermission are not
-- cloned either, and that is a decision rather than an omission -- the UI catalogue describes screens, a variant has no
-- screens, and section 9 records the choice so nobody reads the empty tables as a failure.
DECLARE @SrcApp INT            = (SELECT ApplicationId FROM auth.Application WHERE ApplicationCode = N'TEMPLATE')
      , @DstApp INT            = (SELECT ApplicationId FROM auth.Application WHERE ApplicationCode = N'$(Variant)')
      , @Root   INT
      , @Actor  NVARCHAR (255) = CONCAT (N'fixture@070_variants_end_to_end#$(Variant)#', ORIGINAL_LOGIN ())
      , @Perms  INT
      , @Roles  INT
      , @Maps   INT;

SELECT @Root = t.TenantId
  FROM auth.Tenant AS t
 WHERE t.ApplicationId = @DstApp
   AND t.TenantCode    = N'ROOT'
   AND t.IsDeleted     = 0;

-- 1a. The permissions.  Matched on PermissionCode WITHIN the destination application, which is the whole of BL-039 in
--     one ON clause: the code is unique per application, not globally, so this MERGE mints new PermissionIds and the
--     ids the RLS predicates carry are now stale.  Section 2 is not optional.
MERGE auth.Permission AS tgt
USING (SELECT p.PermissionCategoryId
            , p.PermissionCategoryCode
            , p.PermissionCode
            , p.PermissionName
            , p.PermissionDescription
            , p.IsTenantScoped
         FROM auth.Permission AS p
        WHERE p.ApplicationId = @SrcApp
          AND p.IsDeleted     = 0) AS src
   ON tgt.ApplicationId  = @DstApp
  AND tgt.PermissionCode = src.PermissionCode
 WHEN MATCHED THEN
      UPDATE SET tgt.PermissionCategoryId   = src.PermissionCategoryId
               , tgt.PermissionCategoryCode = src.PermissionCategoryCode
               , tgt.PermissionName         = src.PermissionName
               , tgt.PermissionDescription  = src.PermissionDescription
               , tgt.IsTenantScoped         = src.IsTenantScoped
               , tgt.IsDeleted              = 0
               , tgt.auditDeletedBy         = NULL
               , tgt.auditDeletedDateUtc    = NULL
               , tgt.auditModifiedBy        = @Actor
 WHEN NOT MATCHED BY TARGET THEN
      INSERT (ApplicationId, PermissionCategoryId, PermissionCategoryCode, PermissionCode, PermissionName
            , PermissionDescription, IsTenantScoped, auditCreatedBy, auditModifiedBy)
      VALUES (@DstApp, src.PermissionCategoryId, src.PermissionCategoryCode, src.PermissionCode, src.PermissionName
            , src.PermissionDescription, src.IsTenantScoped, @Actor, @Actor);

SET @Perms = @@ROWCOUNT;

-- 1b. The roles.  OwnerTenantId is the variant's OWN root, not TEMPLATE's: a role is owned by a tenant, and a role
--     owned by another application's root would be reachable by nobody and would cross the application boundary that
--     020's own report calls the worst failure this schema can have.
MERGE auth.Role AS tgt
USING (SELECT r.RoleCode
            , r.RoleName
            , r.RoleDescription
            , r.IsAssignable
            , r.IsSystemRole
         FROM auth.Role AS r
        WHERE r.ApplicationId = @SrcApp
          AND r.IsDeleted     = 0) AS src
   ON tgt.ApplicationId = @DstApp
  AND tgt.RoleCode      = src.RoleCode
 WHEN MATCHED THEN
      UPDATE SET tgt.OwnerTenantId       = @Root
               , tgt.RoleName            = src.RoleName
               , tgt.RoleDescription     = src.RoleDescription
               , tgt.IsAssignable        = src.IsAssignable
               , tgt.IsSystemRole        = src.IsSystemRole
               , tgt.IsDeleted           = 0
               , tgt.auditDeletedBy      = NULL
               , tgt.auditDeletedDateUtc = NULL
               , tgt.auditModifiedBy     = @Actor
 WHEN NOT MATCHED BY TARGET THEN
      INSERT (ApplicationId, OwnerTenantId, RoleCode, RoleName, RoleDescription, IsAssignable, IsSystemRole
            , auditCreatedBy, auditModifiedBy)
      VALUES (@DstApp, @Root, src.RoleCode, src.RoleName, src.RoleDescription, src.IsAssignable, src.IsSystemRole
            , @Actor, @Actor);

SET @Roles = @@ROWCOUNT;

-- 1c. The map, joined through the CODES on both sides so the new ids are resolved rather than assumed.  Four joins
--     where two would do, because a map row copied by id would point at TEMPLATE's permission and silently grant the
--     wrong application's authority -- the one mistake in this file that row-level security could not catch.
MERGE auth.RolePermission AS tgt
USING (SELECT DstRoleId = dr.RoleId
            , DstPermId = dp.PermissionId
         FROM auth.RolePermission AS srp
        INNER JOIN auth.Role       AS sr ON sr.RoleId       = srp.RoleId       AND sr.ApplicationId = @SrcApp
        INNER JOIN auth.Permission AS sp ON sp.PermissionId = srp.PermissionId AND sp.ApplicationId = @SrcApp
        INNER JOIN auth.Role       AS dr ON dr.ApplicationId = @DstApp AND dr.RoleCode       = sr.RoleCode
        INNER JOIN auth.Permission AS dp ON dp.ApplicationId = @DstApp AND dp.PermissionCode = sp.PermissionCode
        WHERE srp.IsDeleted = 0
          AND sr.IsDeleted  = 0
          AND sp.IsDeleted  = 0) AS src
   ON tgt.RoleId       = src.DstRoleId
  AND tgt.PermissionId = src.DstPermId
 WHEN MATCHED AND tgt.IsDeleted = 1 THEN
      UPDATE SET tgt.IsDeleted           = 0
               , tgt.auditDeletedBy      = NULL
               , tgt.auditDeletedDateUtc = NULL
               , tgt.auditModifiedBy     = @Actor
 WHEN NOT MATCHED BY TARGET THEN
      INSERT (RoleId, PermissionId, ApplicationId, auditCreatedBy, auditModifiedBy)
      VALUES (src.DstRoleId, src.DstPermId, @DstApp, @Actor, @Actor);

SET @Maps = @@ROWCOUNT;

-- 1d. The authentication policy at the variant root, and this one was found by running the test rather than by reading
--     the schema.  auth.udfResolveAuthPolicy walks UP the closure from the login tenant and returns the nearest
--     auth.TenantAuthenticationPolicy row; when it finds none, 110_auth_authn_procedures.sql COALESCEs
--     RequireMfaForLocal to 1 -- fail closed, which is the right default and exactly what a template should ship.  The
--     consequence is that an application with no policy row anywhere demands a second factor from everybody, and the
--     first run of this file died at auth.uspCompleteLogin with E-50109 for that reason and no other.
--
--     So the policy is part of what "a deployment" means, and cloning it is not a workaround: it is the same thing
--     115_seed_reference_data.sql does for TEMPLATE's root, aimed at a variant root.  There is NO procedure that writes
--     this table -- it is seed data, and 035_auth_tenant_policy.sql makes TenantId immutable (E-50010) precisely because
--     re-pointing a policy row moves two subtrees at once -- so an INSERT here is the only way, and section 9 says so.
--
--     MFA itself is _tests/040_identity_and_authn.sql's subject.  This file inherits TEMPLATE's shipped answer for
--     local passwords rather than inventing a laxer one, which is why it clones the row instead of writing literals.
IF NOT EXISTS (SELECT 1 FROM auth.TenantAuthenticationPolicy WHERE TenantId = @Root AND IsDeleted = 0)
    INSERT auth.TenantAuthenticationPolicy (TenantId, AllowFederated, AllowLocalPassword, RequireMfaForLocal
                                          , PreferredMethod, SessionLifetimeMinutes, IdleTimeoutMinutes
                                          , RequireStepUpForPrivileged, PolicyNote, auditCreatedBy, auditModifiedBy)
    SELECT @Root, p.AllowFederated, p.AllowLocalPassword, p.RequireMfaForLocal, p.PreferredMethod
         , p.SessionLifetimeMinutes, p.IdleTimeoutMinutes, p.RequireStepUpForPrivileged
         , CONCAT (N'Cloned from TEMPLATE/ROOT by _tests/070_variants_end_to_end.sql. Without a policy row anywhere '
                 , N'above a login tenant, RequireMfaForLocal resolves to 1 by COALESCE and every local login is '
                 , N'refused with E-50109.')
         , @Actor, @Actor
      FROM auth.TenantAuthenticationPolicy AS p
     INNER JOIN auth.Tenant      AS t ON t.TenantId      = p.TenantId
     INNER JOIN auth.Application AS a ON a.ApplicationId = t.ApplicationId
     WHERE a.ApplicationCode = N'TEMPLATE'
       AND t.TenantCode      = N'ROOT'
       AND p.IsDeleted       = 0;

-- 1e. The default roles on the external-organizations branch, where the variant has one.  Section 17.3's rows F1 and F2
--     claim that a user arriving through self-service registration comes out with roles already, and they are right about
--     WHERE that comes from: auth.TenantDefaultRole on the branch, inherited by every organization created beneath it.
--     But auth.TenantDefaultRole is keyed on TenantId, so it is per-TENANT seed data and a cloned catalogue does not
--     bring it along -- 115_seed_reference_data.sql seeds three rows on TEMPLATE's EXTORG and nothing anywhere else.
--
--     Measured before this block existed: section 7 approved an organization, created its first user, gave them a
--     profile, and left them holding ZERO roles.  Nothing failed and nothing warned; the external user simply could not
--     do anything.  That is the same class of quiet failure as UI-35 and it is worth naming here because a project team
--     cloning this template into a second application will hit it in exactly the same place.
-- @Branch is resolved to an id in the DESTINATION application by joining the global setting's VALUE to a tenant CODE,
-- which is the whole of G-34 in one join.  It is deliberately left NULL when the variant has no such branch.
DECLARE @Branch INT = NULL, @Defaults INT = 0;

SELECT @Branch = t.TenantId
  FROM auth.Tenant AS t
 INNER JOIN config.ApplicationSetting AS s ON s.SettingKey = N'Registration.ExternalBranchTenantCode'
                                          AND s.IsDeleted  = 0
                                          AND s.SettingValue COLLATE DATABASE_DEFAULT = t.TenantCode
 WHERE t.ApplicationId = @DstApp
   AND t.IsDeleted     = 0;

IF @Branch IS NOT NULL
BEGIN
    MERGE auth.TenantDefaultRole AS tgt
    USING (SELECT DstRoleId = dr.RoleId
                , sd.GrantNote
             FROM auth.TenantDefaultRole AS sd
            INNER JOIN auth.Tenant      AS st ON st.TenantId      = sd.TenantId
            INNER JOIN auth.Application AS sa ON sa.ApplicationId = st.ApplicationId
            INNER JOIN auth.Role        AS sr ON sr.RoleId        = sd.RoleId
            INNER JOIN auth.Role        AS dr ON dr.ApplicationId = @DstApp AND dr.RoleCode = sr.RoleCode
            WHERE sa.ApplicationCode = N'TEMPLATE'
              AND st.TenantCode      = N'EXTORG'
              AND sd.IsDeleted       = 0
              AND dr.IsDeleted       = 0) AS src
       ON tgt.TenantId = @Branch
      AND tgt.RoleId   = src.DstRoleId
     WHEN MATCHED AND tgt.IsDeleted = 1 THEN
          UPDATE SET tgt.IsDeleted           = 0
                   , tgt.auditDeletedBy      = NULL
                   , tgt.auditDeletedDateUtc = NULL
                   , tgt.auditModifiedBy     = @Actor
     WHEN NOT MATCHED BY TARGET THEN
          INSERT (TenantId, RoleId, GrantNote, auditCreatedBy, auditModifiedBy)
          VALUES (@Branch, src.DstRoleId, src.GrantNote, @Actor, @Actor);

    SET @Defaults = @@ROWCOUNT;
END

DECLARE @PolicyId INT = auth.udfResolveAuthPolicy (@Root);

PRINT CONCAT (N'Section 1: catalogue cloned into $(Variant). auth.Permission ', @Perms, N' row(s) merged, auth.Role '
            , @Roles, N' row(s) merged, auth.RolePermission ', @Maps, N' row(s) merged. Roles owned by tenant '
            , @Root, N'. auth.udfResolveAuthPolicy resolves to policy '
            , COALESCE (CAST (@PolicyId AS NVARCHAR (11)), N'(none -- local logins will demand MFA)')
            , N'. auth.TenantDefaultRole: ', @Defaults, N' row(s) merged onto '
            , CASE WHEN @Branch IS NULL
                   THEN N'nothing, because this variant has no external-organizations branch'
                   ELSE CONCAT (N'branch tenant ', @Branch) END, N'.');
GO


-- *** 2. Re-resolve the row-security policy over the new permission ids ***
-- The file header explains why this is here.  In one line: section 1 created a Data.Read that the three predicates have
-- never heard of, and a predicate that has never heard of a permission does not complain, it returns nothing.  UI-35.
DECLARE @Bound INT, @Skipped INT;

EXEC auth.uspRebuildTenantAccessPolicy
      @Action        = N'Rebuild'
    , @TablesBound   = @Bound   OUTPUT
    , @TablesSkipped = @Skipped OUTPUT;

PRINT CONCAT (N'Section 2: auth.uspRebuildTenantAccessPolicy bound ', @Bound, N' table(s) and skipped ', @Skipped
            , N'. The predicates now carry one Data.* id per application, $(Variant) included.');
GO


-- *** 3. Bootstrap ONE administrator at the variant root, by direct write ***
-- The file header gives the three reasons this cannot go through the procedures.  This is 900_bootstrap_first_admin.sql
-- aimed at a variant root, and it is the LAST direct write in the file.
DECLARE @DstApp    INT            = (SELECT ApplicationId FROM auth.Application WHERE ApplicationCode = N'$(Variant)')
      , @Root      INT
      , @AdminName NVARCHAR (512) = N'e2e.admin.$(Variant)'
      , @UserId    INT
      , @ProfileId INT
      , @Actor     NVARCHAR (255) = CONCAT (N'fixture@070_variants_end_to_end#$(Variant)#', ORIGINAL_LOGIN ())
      , @Granted   INT;

SELECT @Root = t.TenantId
  FROM auth.Tenant AS t
 WHERE t.ApplicationId = @DstApp
   AND t.TenantCode    = N'ROOT'
   AND t.IsDeleted     = 0;

-- 3a. The user.  IsPlatformAdmin = 1 because INV-09 requires BOTH the flag AND a scope row before any Platform.*
--     permission is held -- the flag alone grants nothing and the role alone grants nothing, which is the point of
--     splitting them, and a test that set only one would pass section 3 and fail section 4 for the wrong reason.
IF NOT EXISTS (SELECT 1 FROM auth.[User] WHERE UserName = @AdminName AND IsDeleted = 0)
    INSERT auth.[User] (UserName, DisplayName, Email, IsActive, IsPlatformAdmin, MustChangePassword
                      , auditCreatedBy, auditModifiedBy)
    VALUES (@AdminName, N'End-to-end Administrator ($(Variant))', N'e2e.admin.$(Variant)@example.invalid', 1, 1, 0
          , @Actor, @Actor);

SELECT @UserId = UserId FROM auth.[User] WHERE UserName = @AdminName AND IsDeleted = 0;

-- 3b. The credential.  There is no procedure for this -- see the file header, cause 3 -- so it is written directly and
--     the verifier is a SYNTACTICALLY VALID Argon2id PHC string that hashes nothing.  It is never verified: the
--     password check belongs to the application layer, and auth.uspCompleteLogin is told the answer through
--     @PasswordVerified.  What this test asserts is authorization, not hashing, and a fake verifier makes that explicit
--     rather than implying a secret is stored here.
IF NOT EXISTS (SELECT 1 FROM auth.UserCredential WHERE UserId = @UserId AND CredentialType = 'Password')
    INSERT auth.UserCredential (UserId, CredentialType, VerifierPhc, LastChangedUtc, auditCreatedBy, auditModifiedBy)
    VALUES (@UserId, 'Password'
          , N'$argon2id$v=19$m=65536,t=3,p=4$MDcwLXZhcmlhbnRzLWZpeHR1cmU$bm90LWEtcmVhbC12ZXJpZmllci1ldmVyLWFueXdoZXJl'
          , SYSUTCDATETIME (), @Actor, @Actor);

-- 3c. The profile, at the root, default.
IF NOT EXISTS (SELECT 1 FROM auth.UserProfile WHERE UserId = @UserId AND TenantId = @Root AND IsDeleted = 0)
    INSERT auth.UserProfile (UserId, TenantId, ProfileName, IsDefault, IsActive, auditCreatedBy, auditModifiedBy)
    VALUES (@UserId, @Root, N'Administrator at the $(Variant) root', 1, 1, @Actor, @Actor);

SELECT @ProfileId = UserProfileId
  FROM auth.UserProfile
 WHERE UserId = @UserId AND TenantId = @Root AND IsDeleted = 0;

-- 3d. Four roles at the root, and each one earns its place in a later section:
--       TENANT_ADMIN    Tenant.Create, for section 5 and again for section 7's approval at the EXTORG branch
--       USER_ADMIN      User.Create, for section 6
--       ROLE_ADMIN      Authz.ProfileCreate and Authz.RoleAssign, for section 6's profile and its grants
--       PLATFORM_ADMIN  the Platform.* family, which is inert without 3a's flag
--     Not EDITOR, CONTRIBUTOR, APPROVER or DATA_STEWARD: an administrator who can also do the work proves nothing about
--     whether the work is authorized separately, and section 8 needs a DIFFERENT profile for exactly that reason.
INSERT auth.UserProfileRole (UserProfileId, RoleId, ScopeTenantId, ApplicationId, GrantedUtc
                          , auditCreatedBy, auditModifiedBy)
SELECT @ProfileId, r.RoleId, @Root, @DstApp, SYSUTCDATETIME (), @Actor, @Actor
  FROM auth.Role AS r
 WHERE r.ApplicationId = @DstApp
   AND r.IsDeleted     = 0
   AND r.RoleCode IN (N'TENANT_ADMIN', N'USER_ADMIN', N'ROLE_ADMIN', N'PLATFORM_ADMIN')
   AND NOT EXISTS (SELECT 1
                     FROM auth.UserProfileRole AS upr
                    WHERE upr.UserProfileId = @ProfileId
                      AND upr.RoleId        = r.RoleId
                      AND upr.ScopeTenantId = @Root
                      AND upr.IsDeleted     = 0);

SET @Granted = @@ROWCOUNT;

-- 3e. The grants are rows; the ANSWERS are auth.ProfilePermissionScope, and nothing reads a grant at request time.
EXEC auth.uspRebuildProfilePermissionScope @UserProfileId = @ProfileId;

PRINT CONCAT (N'Section 3: administrator bootstrapped. UserId ', @UserId, N', UserProfileId ', @ProfileId
            , N' at root tenant ', @Root, N'. ', @Granted, N' new role grant(s) this run. Permission scope rebuilt.');
GO
/*---------------------------------------------------------------------------------------------------------------------
CONNECTION 2.  Everything above ran as db_owner with no session.  Everything below acts as the variant's administrator,
and it needs a connection that has never had a SESSION_CONTEXT key set -- see the file header.  $(SQLCMDSERVER) is
sqlcmd's own record of the -S it was given, so the reconnection cannot drift from the original target.
---------------------------------------------------------------------------------------------------------------------*/
:connect $(SQLCMDSERVER)
USE [$(DbName)];
GO

SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;
GO


-- *** 4. Sign the administrator in, through the authentication procedures ***
-- Two calls and a switch, in the order the application layer makes them: ask for the verifier, tell the database how the
-- verification went, then declare which hat is being worn.  @PasswordVerified = 1 is not a shortcut -- the comparison is
-- the application's job by design (section 8.2), because a verifier the database can check is a verifier the database
-- can be made to leak.
DECLARE @App       INT            = (SELECT ApplicationId FROM auth.Application WHERE ApplicationCode = N'$(Variant)')
      , @Hash      VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)-admin')
      , @AdminName NVARCHAR (512) = N'e2e.admin.$(Variant)'
      , @ProfileId INT
      , @AttemptId BIGINT
      , @Phc       NVARCHAR (1024)
      , @Mfa       BIT
      , @SessionId BIGINT
      , @UserId    INT
      , @Must      BIT
      , @AbsExp    DATETIME2 (7)
      , @IdleExp   DATETIME2 (7);

SELECT @ProfileId = up.UserProfileId
  FROM auth.UserProfile AS up
 INNER JOIN auth.[User]  AS u ON u.UserId   = up.UserId
 INNER JOIN auth.Tenant  AS t ON t.TenantId = up.TenantId
 WHERE u.UserName      = @AdminName
   AND t.ApplicationId = @App
   AND t.TenantCode    = N'ROOT'
   AND up.IsDeleted    = 0
   AND u.IsDeleted     = 0;

EXEC auth.uspGetLoginVerifier
      @ApplicationCode = N'$(Variant)'
    , @UserName        = @AdminName
    , @ClientAddress   = N'203.0.113.70'
    , @TenantCode      = N'ROOT'
    , @UserAgent       = N'070_variants_end_to_end'
    , @LoginAttemptId  = @AttemptId OUTPUT
    , @VerifierPhc     = @Phc       OUTPUT
    , @RequiresMfa     = @Mfa       OUTPUT;

EXEC auth.uspCompleteLogin
      @LoginAttemptId     = @AttemptId
    , @PasswordVerified   = 1
    , @SessionTokenHash   = @Hash
    , @IsBypassRoute      = 0
    , @UserSessionId      = @SessionId OUTPUT
    , @UserId             = @UserId    OUTPUT
    , @MustChangePassword = @Must      OUTPUT
    , @AbsoluteExpiryUtc  = @AbsExp    OUTPUT
    , @IdleExpiryUtc      = @IdleExp   OUTPUT;

EXEC auth.uspSwitchProfile @SessionTokenHash = @Hash, @TargetUserProfileId = @ProfileId;

-- ActingTenantId is deliberately read and reported as (none): this connection's context was established before the
-- switch, so it still says profileless.  Printing it proves the claim in the file header rather than asserting it.
PRINT CONCAT (N'Section 4: authenticated and switched. UserSessionId ', @SessionId, N', session now points at '
            , N'UserProfileId ', @ProfileId, N', MFA required ', @Mfa, N', expires '
            , CONVERT (NVARCHAR (30), @AbsExp, 126), N'. This connection''s own ActingTenantId is still '
            , COALESCE (TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS NVARCHAR (20)), N'(none)')
            , N' and cannot be changed -- the hat arrives on the next connection.');
GO


/*---------------------------------------------------------------------------------------------------------------------
CONNECTION 3.  The administrator's WORKING connection.  Connection 2 authenticated and is spent; this one establishes
context from the same session token, which now resolves to a profile, and can therefore act.
---------------------------------------------------------------------------------------------------------------------*/
:connect $(SQLCMDSERVER)
USE [$(DbName)];
GO

SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;
GO


-- *** 5. Grow the tree THROUGH auth.uspCreateTenant ***
-- This is the switch-over _tests/020_tenancy_variant_trees.sql asked for in its own header.  Two tenants per variant and
-- the second is a child of the first, because one call proves the procedure runs and two prove the CLOSURE deepens --
-- the second tenant's ancestor set has to pick up the first, which the fixture never wrote and only
-- auth.uspRebuildTenantClosure, called from inside the procedure, can have produced.
--
-- The types differ per variant on purpose.  Section 17 gives each shape its own vocabulary and a test that created a
-- Jurisdiction under VARIANT2's AGENCY would be building a fourth shape nobody designed.
DECLARE @App     INT            = (SELECT ApplicationId FROM auth.Application WHERE ApplicationCode = N'$(Variant)')
      , @Hash    VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)-admin')
      , @Created INT            = 0
      , @Reused  INT            = 0;

DECLARE @New TABLE (Seq            INT           PRIMARY KEY
                  , TenantCode     NVARCHAR (100)
                  , TenantName     NVARCHAR (400)
                  , TenantTypeCode NVARCHAR (100)
                  , ParentCode     NVARCHAR (100)
                  , NewId          INT           NULL);

IF N'$(Variant)' = N'VARIANT1'
    INSERT @New (Seq, TenantCode, TenantName, TenantTypeCode, ParentCode)
    VALUES (1, N'E2E_COUNTY',   N'End-to-end County',          N'Jurisdiction', N'AGENCY')
         , (2, N'E2E_DISTRICT', N'End-to-end District Office', N'Division',     N'E2E_COUNTY');
ELSE
    INSERT @New (Seq, TenantCode, TenantName, TenantTypeCode, ParentCode)
    VALUES (1, N'E2E_ADMIN',    N'End-to-end Administration',  N'Administration', N'AGENCY')
         , (2, N'E2E_PROGRAM',  N'End-to-end Program',         N'Program',        N'E2E_ADMIN');

DECLARE @Seq      INT = 1
      , @MaxSeq   INT = (SELECT MAX (Seq) FROM @New)
      , @Code     NVARCHAR (100)
      , @Name     NVARCHAR (400)
      , @Type     NVARCHAR (100)
      , @PCode    NVARCHAR (100)
      , @ParentId INT
      , @NewId    INT;

WHILE @Seq <= @MaxSeq
BEGIN
    SELECT @Code  = n.TenantCode
         , @Name  = n.TenantName
         , @Type  = n.TenantTypeCode
         , @PCode = n.ParentCode
      FROM @New AS n
     WHERE n.Seq = @Seq;

    SELECT @ParentId = t.TenantId
      FROM auth.Tenant AS t
     WHERE t.ApplicationId = @App
       AND t.TenantCode    = @PCode
       AND t.IsDeleted     = 0;

    SET @NewId = NULL;

    -- Idempotence, and the guard is the honest one: auth.uspCreateTenant REFUSES a duplicate code within an application
    -- (E-50091), which is correct behaviour and would abort a second run.  So a second run re-resolves instead of
    -- re-creating, and reports which of the two happened rather than reporting success either way.
    SELECT @NewId = t.TenantId
      FROM auth.Tenant AS t
     WHERE t.ApplicationId = @App
       AND t.TenantCode    = @Code
       AND t.IsDeleted     = 0;

    IF @NewId IS NULL
    BEGIN
        EXEC auth.uspCreateTenant
              @SessionTokenHash = @Hash
            , @ParentTenantId   = @ParentId
            , @TenantCode       = @Code
            , @TenantName       = @Name
            , @TenantTypeCode   = @Type
            , @NewTenantId      = @NewId OUTPUT;

        SET @Created += 1;
    END
    ELSE
        SET @Reused += 1;

    UPDATE @New SET NewId = @NewId WHERE Seq = @Seq;

    SET @Seq += 1;
END

-- The closure assertion.  The deeper tenant must have a row for ITSELF and for every ancestor up to the root, and the
-- count is derived from the hierarchy view rather than written as a constant, so it stays true if section 17 changes.
DECLARE @DeepId    INT = (SELECT NewId FROM @New WHERE Seq = 2)
      , @Ancestors INT
      , @Depth     INT;

SELECT @Ancestors = COUNT (*) FROM auth.TenantClosure WHERE DescendantTenantId = @DeepId;
SELECT @Depth     = v.Depth  FROM auth.vwTenantHierarchy AS v WHERE v.TenantId = @DeepId;

IF @Ancestors IS NULL OR @Depth IS NULL OR @Ancestors <> @Depth + 1
BEGIN
    DECLARE @BadClosure NVARCHAR (2000) =
        CONCAT (N'The closure does not agree with the hierarchy for the tenant created by auth.uspCreateTenant. '
              , N'Tenant ', @DeepId, N' reads depth ', COALESCE (CAST (@Depth AS NVARCHAR (10)), N'(null)')
              , N' in auth.vwTenantHierarchy, which needs ', COALESCE (CAST (@Depth + 1 AS NVARCHAR (10)), N'(null)')
              , N' closure rows, and auth.TenantClosure holds '
              , COALESCE (CAST (@Ancestors AS NVARCHAR (10)), N'(null)')
              , N'. The procedure created the tenant and did not rebuild the closure, or rebuilt it incompletely.');

    THROW 50000, @BadClosure, 1;
END

PRINT CONCAT (N'Section 5: ', @Created, N' tenant(s) created through auth.uspCreateTenant, ', @Reused
            , N' already present and re-resolved. Deepest new tenant ', @DeepId, N' sits at depth ', @Depth
            , N' with ', @Ancestors, N' closure row(s) -- self plus every ancestor, as the hierarchy view requires.');
GO


-- *** 6. A user, a profile and its role grants, all through the procedures ***
-- The worker is created at the DEEPEST new tenant, not at the root, and that placement is the test: everything section 8
-- does has to travel up the closure from a leaf, through two tenants that section 5 created minutes ago, to a permission
-- granted at that leaf.  A worker at the root would pass even if the closure were empty.
DECLARE @App      INT            = (SELECT ApplicationId FROM auth.Application WHERE ApplicationCode = N'$(Variant)')
      , @Hash     VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)-admin')
      , @DeepCode NVARCHAR (100) = CASE WHEN N'$(Variant)' = N'VARIANT1' THEN N'E2E_DISTRICT' ELSE N'E2E_PROGRAM' END
      , @WorkName NVARCHAR (512) = N'e2e.worker.$(Variant)'
      , @DeepId   INT
      , @WorkerId INT
      , @WorkProf INT
      , @GrantId  INT
      , @NewRoles INT            = 0;

SELECT @DeepId = t.TenantId
  FROM auth.Tenant AS t
 WHERE t.ApplicationId = @App
   AND t.TenantCode    = @DeepCode
   AND t.IsDeleted     = 0;

-- 6a. The user.  auth.uspCreateUser demands User.Create AT THE ACTING TENANT, which is the root -- a user is not a
--     tenant-scoped thing, the authority to mint one is.
SELECT @WorkerId = u.UserId FROM auth.[User] AS u WHERE u.UserName = @WorkName AND u.IsDeleted = 0;

IF @WorkerId IS NULL
    EXEC auth.uspCreateUser
          @SessionTokenHash       = @Hash
        , @UserName               = @WorkName
        , @DisplayName            = N'End-to-end Worker ($(Variant))'
        , @Email                  = N'e2e.worker.$(Variant)@example.invalid'
        , @AuthPolicyOverrideJson = NULL
        , @IsPlatformAdmin        = 0
        , @NewUserId              = @WorkerId OUTPUT;

-- 6b. The profile.  auth.uspCreateProfile demands Authz.ProfileCreate at the TENANT THE HAT IS PLANTED IN, or above it,
--     and E-50045 is its own registered number rather than uspDemandPermission's E-50030 -- see 140's header.
SELECT @WorkProf = up.UserProfileId
  FROM auth.UserProfile AS up
 WHERE up.UserId = @WorkerId AND up.TenantId = @DeepId AND up.IsDeleted = 0;

-- Built into a variable first: EXEC will not take an expression for a parameter (Msg 102), which is a rule worth
-- remembering because the error names a '+' and not the call it belongs to.
DECLARE @WorkProfName NVARCHAR (512) = CONCAT (N'Worker at ', @DeepCode);

IF @WorkProf IS NULL
    EXEC auth.uspCreateProfile
          @SessionTokenHash  = @Hash
        , @UserId            = @WorkerId
        , @TenantId          = @DeepId
        , @ProfileName       = @WorkProfName
        , @IsDefault         = 1
        , @NewUserProfileId  = @WorkProf OUTPUT;

-- 6c. Four role grants, scoped at the leaf.  These four and not others, because they are exactly what section 8 needs
--     and between them they are the measured answer to gap G-38: APPROVER and DATA_STEWARD each carry Data.Update in the
--     seeded catalogue, since an RLS BLOCK predicate is handed a row and cannot tell an approval from an edit.  Cloned
--     from TEMPLATE in section 1, so if that seed fix were ever reverted, section 8 would fail here with E-50030 and
--     name the missing permission.
DECLARE @RoleSeq INT = 1, @RoleMax INT, @RoleCode NVARCHAR (200), @RoleId INT;

DECLARE @Wanted TABLE (Seq INT IDENTITY (1,1) PRIMARY KEY, RoleCode NVARCHAR (200));

INSERT @Wanted (RoleCode) VALUES (N'CONTRIBUTOR'), (N'EDITOR'), (N'APPROVER'), (N'DATA_STEWARD');

SET @RoleMax = (SELECT MAX (Seq) FROM @Wanted);

WHILE @RoleSeq <= @RoleMax
BEGIN
    SELECT @RoleCode = w.RoleCode FROM @Wanted AS w WHERE w.Seq = @RoleSeq;

    SELECT @RoleId = r.RoleId
      FROM auth.Role AS r
     WHERE r.ApplicationId = @App AND r.RoleCode = @RoleCode AND r.IsDeleted = 0;

    IF NOT EXISTS (SELECT 1
                     FROM auth.UserProfileRole AS upr
                    WHERE upr.UserProfileId = @WorkProf
                      AND upr.RoleId        = @RoleId
                      AND upr.ScopeTenantId = @DeepId
                      AND upr.IsDeleted     = 0)
    BEGIN
        SET @GrantId = NULL;

        EXEC auth.uspAssignRoleToProfile
              @SessionTokenHash     = @Hash
            , @UserProfileId        = @WorkProf
            , @RoleId               = @RoleId
            , @ScopeTenantId        = @DeepId
            , @ExpiresUtc           = NULL
            , @NewUserProfileRoleId = @GrantId OUTPUT;

        SET @NewRoles += 1;
    END

    SET @RoleSeq += 1;
END

-- The grants are rows; the answers are auth.ProfilePermissionScope.  auth.uspAssignRoleToProfile rebuilds the scope for
-- the profile it touched, so this reads the result rather than causing it.
DECLARE @Scoped INT, @Verbs NVARCHAR (1000);

SELECT @Scoped = COUNT (DISTINCT pps.PermissionId)
     , @Verbs  = STRING_AGG (CAST (p.PermissionCode AS NVARCHAR (MAX)), N', ')
                        WITHIN GROUP (ORDER BY p.PermissionCode)
  FROM auth.ProfilePermissionScope AS pps
 INNER JOIN auth.Permission        AS p ON p.PermissionId = pps.PermissionId
 WHERE pps.UserProfileId = @WorkProf
   AND pps.ScopeTenantId = @DeepId
   AND pps.IsDeleted     = 0
   AND p.PermissionCode LIKE N'Data.%';

IF @Scoped IS NULL OR @Scoped < 6
BEGIN
    DECLARE @ThinScope NVARCHAR (2000) =
        CONCAT (N'The worker profile holds only ', COALESCE (CAST (@Scoped AS NVARCHAR (10)), N'0')
              , N' distinct Data.* permission(s) at tenant ', @DeepId, N': '
              , COALESCE (@Verbs, N'(none)'), N'. CONTRIBUTOR, EDITOR, APPROVER and DATA_STEWARD together carry six '
              , N'distinct Data verbs -- Read, Insert, Update, Approve, Reassign, SoftDelete and Restore over four '
              , N'roles. Fewer means the role grants did not reach auth.ProfilePermissionScope, or section 1 cloned an '
              , N'incomplete map.');

    THROW 50000, @ThinScope, 1;
END

PRINT CONCAT (N'Section 6: UserId ', @WorkerId, N' and UserProfileId ', @WorkProf, N' created through the procedures at '
            , @DeepCode, N' (tenant ', @DeepId, N'). ', @NewRoles, N' new role grant(s) this run. The profile now holds '
            , @Scoped, N' Data.* permission(s) there: ', @Verbs, N'.');
GO
-- *** 7. The self-service registration path, VARIANT3 only ***
-- Section 17.3 is the only shape with an external-organizations branch, so it is the only shape where a stranger can ask
-- to be let in.  Three calls, and the first and third take NO session token because the caller has no session -- that is
-- the point of the path, and it is why auth.uspRegisterOrganization writes a REQUEST rather than a tenant.
--
-- This is also where the EXTORG / EXT_ORGS mismatch used to bite.  config.ApplicationSetting holds ONE global key,
-- Registration.ExternalBranchTenantCode = 'EXTORG', which auth.uspApproveOrganization resolves WITHIN the registering
-- application; section 17.3 of the design and this fixture's earlier drafts both spelled VARIANT3's division EXT_ORGS,
-- so the lookup found nothing and the approval failed with E-50067 as a configuration fault.  Both were corrected to
-- EXTORG on 2026-09-20 (gap G-34), and section 10 re-asserts the resolution so a future rename fails here rather than in
-- production.  The standing constraint, which is the real content of that gap: EVERY APPLICATION THAT ACCEPTS
-- SELF-SERVICE REGISTRATION MUST CODE ITS EXTERNAL BRANCH WITH THE SAME TENANT CODE, because the setting is global and
-- the tenant it names is not.
IF N'$(Variant)' <> N'VARIANT3'
    PRINT N'Section 7: skipped. Only VARIANT3 has an external-organizations branch, so only VARIANT3 can take a '
        + N'registration. Sections 8 onwards do not depend on this.';
ELSE
BEGIN
    DECLARE @App          INT            = (SELECT ApplicationId
                                              FROM auth.Application
                                             WHERE ApplicationCode = N'$(Variant)')
          , @Hash         VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)-admin')
          , @OrgCode      NVARCHAR (100) = N'E2E_ORG'
          , @RegId        INT
          , @OrgTenantId  INT
          , @ExtUserId    INT
          , @ExtProfileId INT
          , @BranchCode   NVARCHAR (100) = (SELECT s.SettingValue
                                              FROM config.ApplicationSetting AS s
                                             WHERE s.SettingKey = N'Registration.ExternalBranchTenantCode'
                                               AND s.IsDeleted  = 0)
          , @Path         NVARCHAR (200);

    -- G-24 gave this path a per-address budget, so this file returns its own allowance before spending it.  Two arrivals
    -- are all a run can cost -- 7a is skipped entirely once the registration exists -- and the shipped threshold is ten
    -- per hour, so this is hygiene rather than a fix: what it protects against is a run that soft-deletes E2E_ORG and
    -- then repeats the registration several times in one sitting, which is what a developer debugging section 7 does.
    -- Soft-deleted rather than removed, because the count behind E-50068 filters IsDeleted = 0 and the table is audited
    -- like every other.  The audit pair is set in the same statement as IsDeleted: CK_auth_RegistrationAttempt_DeletedPair
    -- is evaluated before the AFTER trigger that would otherwise fill it.
    UPDATE auth.RegistrationAttempt
       SET IsDeleted           = 1
         , auditDeletedBy      = N'070_variants_end_to_end returning its own G-24 allowance'
         , auditDeletedDateUtc = SYSUTCDATETIME ()
         , auditModifiedBy     = N'070_variants_end_to_end'
     WHERE ClientAddress = N'198.51.100.70'
       AND IsDeleted     = 0;

    -- 7a. The request, from a caller with no session and no account.
    SELECT @RegId = orr.OrganizationRegistrationId
         , @OrgTenantId = orr.TenantId
      FROM auth.OrganizationRegistration AS orr
     WHERE orr.ApplicationId      = @App
       AND orr.ProposedTenantCode = @OrgCode
       AND orr.IsDeleted          = 0;

    IF @RegId IS NULL
    BEGIN
        EXEC auth.uspRegisterOrganization
              @ApplicationCode            = N'$(Variant)'
            , @ProposedTenantCode         = @OrgCode
            , @OrganizationName           = N'End-to-end Partner Organization'
            , @ContactEmail               = N'contact@e2e-partner.example.invalid'
            , @ContactName                = N'E2E Contact'
            , @ClientAddress              = N'198.51.100.70'
            , @OrganizationRegistrationId = @RegId OUTPUT;

        SET @Path = N'registered, approved and staffed this run';
    END
    ELSE
        SET @Path = N'registration already present and re-resolved';

    -- 7b. The approval, by the administrator, which is what actually creates the tenant -- through
    --     auth.uspCreateTenant, inside auth.uspApproveOrganization's own transaction, at the branch resolved above.
    IF @OrgTenantId IS NULL
        EXEC auth.uspApproveOrganization
              @SessionTokenHash           = @Hash
            , @OrganizationRegistrationId = @RegId
            , @Approve                    = 1
            , @ReviewNote                 = N'Approved by _tests/070_variants_end_to_end.sql.'
            , @TenantId                   = @OrgTenantId OUTPUT;

    -- 7c. The first user of the new organization, again with no session: the contact named in the request is the only
    --     person who could plausibly be making this call, and the registration id is the only thing authorizing it.
    SELECT @ExtUserId = u.UserId
      FROM auth.[User] AS u
     WHERE u.UserName = N'e2e.external.$(Variant)' AND u.IsDeleted = 0;

    IF @ExtUserId IS NULL
        EXEC auth.uspRegisterExternalUser
              @OrganizationRegistrationId = @RegId
            , @UserName                   = N'e2e.external.$(Variant)'
            , @DisplayName                = N'End-to-end External User'
            , @Email                      = N'user@e2e-partner.example.invalid'
            , @ClientAddress              = N'198.51.100.70'
            , @NewUserId                  = @ExtUserId    OUTPUT
            , @NewUserProfileId           = @ExtProfileId OUTPUT;

    -- The assertion: the new tenant must hang off the resolved branch and carry the ExternalOrganization type, which is
    -- auth.uspApproveOrganization's decision and not this file's.  Derived from the closure rather than from the
    -- procedure's output, so it tests the result instead of the report.
    DECLARE @ParentCode NVARCHAR (100)
          , @TypeCode   NVARCHAR (100)
          , @DefRoles   INT;

    SELECT @ParentCode = pt.TenantCode
         , @TypeCode   = t.TenantTypeCode
      FROM auth.Tenant AS t
      LEFT JOIN auth.Tenant AS pt ON pt.TenantId = t.ParentTenantId
     WHERE t.TenantId = @OrgTenantId;

    SELECT @DefRoles = COUNT (*)
      FROM auth.UserProfileRole AS upr
     WHERE upr.UserProfileId = COALESCE (@ExtProfileId
                                       , (SELECT MIN (up.UserProfileId)
                                            FROM auth.UserProfile AS up
                                           WHERE up.UserId = @ExtUserId AND up.IsDeleted = 0))
       AND upr.IsDeleted     = 0;

    -- How many the branch OFFERS, so the assertion below can tell "the design says none" from "the design says three
    -- and the procedure conferred none".  Section 1e seeds these; before it existed this read 3 offered and 0 conferred.
    DECLARE @Offered INT = (SELECT COUNT (*)
                              FROM auth.TenantDefaultRole AS d
                             INNER JOIN auth.Tenant AS bt ON bt.TenantId = d.TenantId
                             WHERE bt.ApplicationId = @App
                               AND bt.TenantCode    = @BranchCode
                               AND d.IsDeleted      = 0);

    IF @Offered > 0 AND @DefRoles = 0
    BEGIN
        DECLARE @NoDefaults NVARCHAR (2000) =
            CONCAT (N'The external user arrived with no roles. auth.TenantDefaultRole offers ', @Offered
                  , N' role(s) on branch ', @BranchCode, N', and section 17.3 rows F1 and F2 say a self-registered '
                  , N'user inherits them, but the new profile holds 0 grant(s). Either auth.uspRegisterExternalUser '
                  , N'did not call auth.uspGrantTenantDefaultRoles, or the default roles were added AFTER this user '
                  , N'was created -- a second run of this file on fresh registration artefacts distinguishes the two.');

        THROW 50000, @NoDefaults, 1;
    END

    IF @OrgTenantId IS NULL OR @ParentCode IS DISTINCT FROM @BranchCode OR @TypeCode <> N'ExternalOrganization'
    BEGIN
        DECLARE @BadOrg NVARCHAR (2000) =
            CONCAT (N'The approved organization did not land where the design says it must. Tenant '
                  , COALESCE (CAST (@OrgTenantId AS NVARCHAR (11)), N'(none)'), N', parent '
                  , COALESCE (@ParentCode, N'(none)'), N', type ', COALESCE (@TypeCode, N'(none)')
                  , N'. Expected a child of ', COALESCE (@BranchCode, N'(the setting is missing)')
                  , N' with type ExternalOrganization. If the parent is wrong, the global setting '
                  , N'Registration.ExternalBranchTenantCode and this application''s branch tenant code disagree -- '
                  , N'gap G-34.');

        THROW 50000, @BadOrg, 1;
    END

    PRINT CONCAT (N'Section 7: self-service registration ', @Path, N'. OrganizationRegistrationId ', @RegId
                , N' became tenant ', @OrgTenantId, N' (', @TypeCode, N') under branch ', @ParentCode
                , N'. External UserId ', @ExtUserId, N' holds ', @DefRoles
                , N' role grant(s) from auth.TenantDefaultRole, conferred by the procedures and not by this file.');
END
GO
/*---------------------------------------------------------------------------------------------------------------------
CONNECTION 4.  The worker's AUTHENTICATING connection.  It starts as db_owner with no session, which is what section 8a
needs, and ends holding a profileless context, which is why section 9 gets a connection of its own.
---------------------------------------------------------------------------------------------------------------------*/
:connect $(SQLCMDSERVER)
USE [$(DbName)];
GO

SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;
GO


-- *** 8. Give the worker a credential and sign it in ***
-- 8a. THE LAST DIRECT WRITE IN THE FILE, and it is here rather than in section 6 for a reason worth stating: section 6
--     acted as the administrator, and slipping an un-procedured INSERT in among calls that all demand permissions would
--     blur the claim that everything after section 3 goes through the procedures.  It does -- except this, and this
--     cannot, because NO SHIPPED PROCEDURE WRITES auth.UserCredential.  auth.uspCreateUser takes no verifier;
--     User.ResetCredential is seeded and carried by USER_ADMIN and demanded by nothing.  Section 10 asserts that, so the
--     day a credential procedure exists this test reports the gap as closed instead of repeating a stale complaint.
DECLARE @WorkName NVARCHAR (512) = N'e2e.worker.$(Variant)'
      , @WorkerId INT
      , @Actor    NVARCHAR (255) = CONCAT (N'fixture@070_variants_end_to_end#$(Variant)#', ORIGINAL_LOGIN ());

SELECT @WorkerId = u.UserId FROM auth.[User] AS u WHERE u.UserName = @WorkName AND u.IsDeleted = 0;

IF NOT EXISTS (SELECT 1 FROM auth.UserCredential WHERE UserId = @WorkerId AND CredentialType = 'Password')
    INSERT auth.UserCredential (UserId, CredentialType, VerifierPhc, LastChangedUtc, auditCreatedBy, auditModifiedBy)
    VALUES (@WorkerId, 'Password'
          , N'$argon2id$v=19$m=65536,t=3,p=4$MDcwLXZhcmlhbnRzLWZpeHR1cmU$bm90LWEtcmVhbC12ZXJpZmllci1ldmVyLWFueXdoZXJl'
          , SYSUTCDATETIME (), @Actor, @Actor);

-- 8b. The same two calls and a switch as section 4, with one difference that matters: @TenantCode is the LEAF the
--     profile lives at, not the root.  auth.uspGetLoginVerifier uses it to resolve the authentication policy, which
--     auth.udfResolveAuthPolicy finds by walking UP the closure -- so this login is also a live test of the closure
--     section 5 built, and it would fail with E-50109 if the walk did not reach the root's policy row.
DECLARE @App       INT            = (SELECT ApplicationId
                                       FROM auth.Application
                                      WHERE ApplicationCode = N'$(Variant)')
      , @Hash      VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)-worker')
      , @DeepCode  NVARCHAR (100) = CASE WHEN N'$(Variant)' = N'VARIANT1' THEN N'E2E_DISTRICT' ELSE N'E2E_PROGRAM' END
      , @WorkProf  INT
      , @AttemptId BIGINT
      , @Phc       NVARCHAR (1024)
      , @Mfa       BIT
      , @SessionId BIGINT
      , @LoginUser INT
      , @Must      BIT
      , @AbsExp    DATETIME2 (7)
      , @IdleExp   DATETIME2 (7);

SELECT @WorkProf = up.UserProfileId
  FROM auth.UserProfile AS up
 INNER JOIN auth.Tenant AS t ON t.TenantId = up.TenantId
 WHERE up.UserId       = @WorkerId
   AND t.TenantCode    = @DeepCode
   AND t.ApplicationId = @App
   AND up.IsDeleted    = 0;

EXEC auth.uspGetLoginVerifier
      @ApplicationCode = N'$(Variant)'
    , @UserName        = @WorkName
    , @ClientAddress   = N'203.0.113.71'
    , @TenantCode      = @DeepCode
    , @UserAgent       = N'070_variants_end_to_end'
    , @LoginAttemptId  = @AttemptId OUTPUT
    , @VerifierPhc     = @Phc       OUTPUT
    , @RequiresMfa     = @Mfa       OUTPUT;

EXEC auth.uspCompleteLogin
      @LoginAttemptId     = @AttemptId
    , @PasswordVerified   = 1
    , @SessionTokenHash   = @Hash
    , @IsBypassRoute      = 0
    , @UserSessionId      = @SessionId OUTPUT
    , @UserId             = @LoginUser OUTPUT
    , @MustChangePassword = @Must      OUTPUT
    , @AbsoluteExpiryUtc  = @AbsExp    OUTPUT
    , @IdleExpiryUtc      = @IdleExp   OUTPUT;

EXEC auth.uspSwitchProfile @SessionTokenHash = @Hash, @TargetUserProfileId = @WorkProf;

PRINT CONCAT (N'Section 8: worker credential present and signed in. UserSessionId ', @SessionId
            , N', session now points at UserProfileId ', @WorkProf, N' at ', @DeepCode
            , N'. The policy resolved through the closure section 5 built, so MFA required ', @Mfa, N'.');
GO


/*---------------------------------------------------------------------------------------------------------------------
CONNECTION 5.  The worker's WORKING connection, and the only one in this file that row-level security has anything to
say about.  Everything below runs under the three predicates section 2 rebuilt.
---------------------------------------------------------------------------------------------------------------------*/
:connect $(SQLCMDSERVER)
USE [$(DbName)];
GO

SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;
GO


-- *** 9. Real case work, through 180's procedures, at a tenant that did not exist an hour ago ***
-- This section is the point of the whole file.  Everything before it was arrangement; this is the part that fails if any
-- of it was arranged wrongly, because a case file INSERT has to satisfy auth.tvfTenantInsertPredicate -- which demands
-- both a Data.Insert id resolved in THIS application (section 2) and @TenantId = ActingTenantId (P-06) -- and then the
-- reads have to satisfy auth.tvfTenantReadPredicate over the closure section 5 built.
DECLARE @Hash    VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)-worker')
      , @CaseNum NVARCHAR (100) = N'E2E-$(Variant)-001'
      , @CaseId  INT
      , @NoteId  BIGINT
      , @Acting  INT
      , @Fresh   BIT            = 0
      , @Title   NVARCHAR (800) = N'End-to-end case file for $(Variant)';

-- A read of dbo.CaseFile is enough to establish the session context AND to prove the read predicate lets the worker see
-- its own tenant, so the idempotence check does double duty.  It also has to come through a procedure call first, since
-- nothing has set session context on this connection yet -- hence the deliberate order below.
EXEC dbo.uspListCaseFiles @SessionTokenHash = @Hash, @TopN = 10;

SET @Acting = TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT);

SELECT @CaseId = cf.CaseFileId
  FROM dbo.CaseFile AS cf
 WHERE cf.CaseNumber = @CaseNum
   AND cf.IsDeleted  = 0;

IF @CaseId IS NULL
BEGIN
    SET @Fresh = 1;

    -- 9a. Insert.  Data.Insert from CONTRIBUTOR, and the block predicate pins the row to the acting tenant.
    EXEC dbo.uspCreateCaseFile
          @SessionTokenHash    = @Hash
        , @CaseNumber          = @CaseNum
        , @Title               = @Title
        , @AssignedToProfileId = NULL
        , @CaseFileId          = @CaseId OUTPUT;

    -- 9b. A note, which is the second policy-bound table and a different Data verb on the same row scope.
    EXEC dbo.uspAddCaseNote
          @SessionTokenHash = @Hash
        , @CaseFileId       = @CaseId
        , @NoteText         = N'Opened by _tests/070_variants_end_to_end.sql on the $(Variant) tree.'
        , @IsInternal       = 1
        , @CaseNoteId       = @NoteId OUTPUT;

    -- 9c. An edit, to 'pending'.  Not 'approved': that status is not this procedure's to write (E-50207), because
    --     approval sets ApprovedUtc and ApprovedByProfileId in the same statement and is a different verb.
    EXEC dbo.uspUpdateCaseFile
          @SessionTokenHash = @Hash
        , @CaseFileId       = @CaseId
        , @Title            = @Title
        , @CaseStatus       = 'pending';

    -- 9d. Approval, which needs Data.Approve AND Data.Update -- the measured coupling of G-38.  If the cloned catalogue
    --     had lost either, this call would raise E-50030 and name the one that is missing.
    EXEC dbo.uspApproveCaseFile
          @SessionTokenHash = @Hash
        , @CaseFileId       = @CaseId
        , @ApprovalNote     = N'Approved end to end on the $(Variant) tree.';
END

-- 9e. Read it back through the procedure, and assert the state rather than trusting the calls above to have worked.
DECLARE @Status VARCHAR (20), @Tenant INT, @Notes INT, @Approver INT;

SELECT @Status   = cf.CaseStatus
     , @Tenant   = cf.TenantId
     , @Approver = cf.ApprovedByProfileId
  FROM dbo.CaseFile AS cf
 WHERE cf.CaseFileId = @CaseId;

SELECT @Notes = COUNT (*) FROM dbo.CaseNote AS cn WHERE cn.CaseFileId = @CaseId AND cn.IsDeleted = 0;

IF @CaseId IS NULL OR @Status <> 'approved' OR @Tenant <> @Acting OR @Approver IS NULL OR @Notes < 1
BEGIN
    DECLARE @BadCase NVARCHAR (2000) =
        CONCAT (N'The case file did not come out as the procedures promised. CaseFileId '
              , COALESCE (CAST (@CaseId AS NVARCHAR (11)), N'(none)'), N', status '
              , COALESCE (@Status, N'(invisible to this profile)'), N', tenant '
              , COALESCE (CAST (@Tenant AS NVARCHAR (11)), N'(none)'), N' against acting tenant '
              , COALESCE (CAST (@Acting AS NVARCHAR (11)), N'(none)'), N', approver '
              , COALESCE (CAST (@Approver AS NVARCHAR (11)), N'(none)'), N', notes ', @Notes
              , N'. A NULL status with a non-NULL id means the row exists and the READ predicate hides it, which is '
              , N'UI-35: section 2''s policy rebuild did not take, or the Data.Read id for this application is not in '
              , N'the predicate''s list.');

    THROW 50000, @BadCase, 1;
END

-- 9f. The isolation assertion, and it is the one that would catch a predicate resolving the WRONG application's ids.
--     Everything this profile can see must belong to a tenant inside its own scope subtree -- so the count of visible
--     rows and the count of rows whose tenant is reachable from the profile's grants must be the same number.  If a
--     stale id list let another application's rows through, these two diverge.
DECLARE @Visible INT, @InScope INT;

SELECT @Visible = COUNT (*) FROM dbo.CaseFile;

SELECT @InScope = COUNT (*)
  FROM dbo.CaseFile AS cf
 WHERE EXISTS (SELECT 1
                 FROM auth.ProfilePermissionScope AS pps
                INNER JOIN auth.TenantClosure     AS tc ON tc.AncestorTenantId = pps.ScopeTenantId
                WHERE pps.UserProfileId      = TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT)
                  AND pps.IsDeleted          = 0
                  AND tc.DescendantTenantId  = cf.TenantId);

IF @Visible IS DISTINCT FROM @InScope
BEGIN
    DECLARE @Leak NVARCHAR (2000) =
        CONCAT (N'Row-level security and the permission scope disagree. The worker profile can see ', @Visible
              , N' row(s) of dbo.CaseFile, but only ', @InScope, N' of them sit at a tenant reachable from its own '
              , N'grants through auth.TenantClosure. More visible than in scope is a LEAK -- the read predicate is '
              , N'resolving a permission id belonging to another application (BL-039, UI-35). Fewer is a predicate '
              , N'narrower than the grants, which is safe but means the closure or the scope rebuild is incomplete.');

    THROW 50000, @Leak, 1;
END

PRINT CONCAT (N'Section 9: case work ', CASE WHEN @Fresh = 1 THEN N'performed' ELSE N'already present' END
            , N' through 180''s procedures. CaseFileId ', @CaseId, N' at tenant ', @Tenant, N' reads ', @Status
            , N', approved by profile ', @Approver, N', with ', @Notes, N' note(s). This profile sees ', @Visible
            , N' case file(s), all of them inside its own scope subtree.');
GO
/*---------------------------------------------------------------------------------------------------------------------
CONNECTION 6.  db_owner again, with no session, because the report has to be able to see EVERYTHING -- including the rows
the worker's own predicates would hide from it.  A report written on the worker's connection could not tell "the row is
absent" from "the row is invisible", which is the exact confusion section 9f exists to detect.

AND db_owner IS NOT ENOUGH, WHICH THIS FILE ALSO LEARNED BY FAILING.  Row-level security does not exempt privileged
logins: a filter predicate applies to sysadmin exactly as it applies to everybody, and with no session context at all,
auth.tvfTenantReadPredicate matches nothing.  The first draft of section 10 therefore reported the case file it had just
created as ABSENT -- a false failure produced by the security working correctly.  The escape hatch that 120_rls_policy.sql
builds for precisely this case is the right answer, and it is the ONE session key that is not read-only:

    EXEC sys.sp_set_session_context @key = N'BypassRowSecurity', @value = 1;

It is the right-hand side of an OR in all three predicates.  Used here it is honest -- this connection has no session, no
profile and no acting tenant, and it is reading in order to report, which is the case the hatch exists for -- and it is
worth noticing that a report is exactly the kind of code that reaches for it, which is why Platform.BypassRowSecurity is
a permission and not a convenience.
---------------------------------------------------------------------------------------------------------------------*/
:connect $(SQLCMDSERVER)
USE [$(DbName)];
GO

SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;
GO

EXEC sys.sp_set_session_context @key = N'BypassRowSecurity', @value = 1;
GO


-- *** 10. The closing report ***
DECLARE @Report TABLE (RowNo    INT IDENTITY (1,1) PRIMARY KEY
                     , Severity INT
                     , Status   VARCHAR (10)
                     , Item     NVARCHAR (200)
                     , Detail   NVARCHAR (1000));

DECLARE @App      INT            = (SELECT ApplicationId FROM auth.Application WHERE ApplicationCode = N'$(Variant)')
      , @DeepCode NVARCHAR (100) = CASE WHEN N'$(Variant)' = N'VARIANT1' THEN N'E2E_DISTRICT' ELSE N'E2E_PROGRAM' END
      , @CaseNum  NVARCHAR (100) = N'E2E-$(Variant)-001';

-- 10a. The catalogue.  Counted against TEMPLATE rather than against 35 and 14, so the check stays true when a project
--      adds a permission -- which is the first thing a project does.
DECLARE @SrcP INT, @SrcR INT, @SrcM INT, @DstP INT, @DstR INT, @DstM INT;

SELECT @SrcP = COUNT (*) FROM auth.Permission AS p
 INNER JOIN auth.Application AS a ON a.ApplicationId = p.ApplicationId
 WHERE a.ApplicationCode = N'TEMPLATE' AND p.IsDeleted = 0;

SELECT @DstP = COUNT (*) FROM auth.Permission WHERE ApplicationId = @App AND IsDeleted = 0;

SELECT @SrcR = COUNT (*) FROM auth.Role AS r
 INNER JOIN auth.Application AS a ON a.ApplicationId = r.ApplicationId
 WHERE a.ApplicationCode = N'TEMPLATE' AND r.IsDeleted = 0;

SELECT @DstR = COUNT (*) FROM auth.Role WHERE ApplicationId = @App AND IsDeleted = 0;

SELECT @SrcM = COUNT (*) FROM auth.RolePermission AS rp
 INNER JOIN auth.Application AS a ON a.ApplicationId = rp.ApplicationId
 WHERE a.ApplicationCode = N'TEMPLATE' AND rp.IsDeleted = 0;

SELECT @DstM = COUNT (*) FROM auth.RolePermission WHERE ApplicationId = @App AND IsDeleted = 0;

INSERT @Report (Severity, Status, Item, Detail)
VALUES (CASE WHEN @DstP = @SrcP AND @DstR = @SrcR AND @DstM = @SrcM THEN 4 ELSE 2 END
      , CASE WHEN @DstP = @SrcP AND @DstR = @SrcR AND @DstM = @SrcM THEN 'OK' ELSE 'SHORT' END
      , N'$(Variant) carries a complete clone of TEMPLATE''s catalogue'
      , CONCAT (N'Permissions ', @DstP, N' of ', @SrcP, N', roles ', @DstR, N' of ', @SrcR, N', role-permission rows '
              , @DstM, N' of ', @SrcM, N'. Cloned by section 1 from TEMPLATE rather than restated, because a '
              , N'hand-written second copy drifts and then the test tests the copy.'));

-- 10b. THE UI-35 CHECK, and the most valuable row in this report.  The three predicates carry LITERAL permission ids,
--      baked in when auth.uspRebuildTenantAccessPolicy last ran (BL-039).  Cloning the catalogue minted new ids for this
--      application; if the rebuild in section 2 had been skipped, every predicate would still resolve TEMPLATE's ids,
--      every grant in this application would be real, and every read would return nothing with no error anywhere.
--      Matched with PATINDEX and digit-class delimiters rather than LIKE '%id%', because id 12 is a substring of 120.
DECLARE @ReadId INT, @InsId INT, @UpdId INT, @Missing NVARCHAR (400) = NULL;

SELECT @ReadId = PermissionId FROM auth.Permission
 WHERE ApplicationId = @App AND PermissionCode = N'Data.Read'   AND IsDeleted = 0;
SELECT @InsId  = PermissionId FROM auth.Permission
 WHERE ApplicationId = @App AND PermissionCode = N'Data.Insert' AND IsDeleted = 0;
SELECT @UpdId  = PermissionId FROM auth.Permission
 WHERE ApplicationId = @App AND PermissionCode = N'Data.Update' AND IsDeleted = 0;

SELECT @Missing = STRING_AGG (x.Label, N', ') WITHIN GROUP (ORDER BY x.Label)
  FROM (VALUES (N'auth.tvfTenantReadPredicate/Data.Read',     N'auth.tvfTenantReadPredicate',   @ReadId)
             , (N'auth.tvfTenantInsertPredicate/Data.Insert', N'auth.tvfTenantInsertPredicate', @InsId)
             , (N'auth.tvfTenantUpdatePredicate/Data.Update', N'auth.tvfTenantUpdatePredicate', @UpdId))
                 AS x (Label, FunctionName, PermissionId)
 WHERE x.PermissionId IS NULL
    OR NOT EXISTS (SELECT 1
                     FROM sys.sql_modules AS m
                    WHERE m.object_id = OBJECT_ID (x.FunctionName)
                      AND PATINDEX (CONCAT (N'%[^0-9]', x.PermissionId, N'[^0-9]%'), m.definition) > 0);

INSERT @Report (Severity, Status, Item, Detail)
VALUES (CASE WHEN @Missing IS NULL THEN 4 ELSE 1 END
      , CASE WHEN @Missing IS NULL THEN 'OK' ELSE 'STALE' END
      , N'The row-security predicates resolve THIS application''s permission ids'
      , CONCAT (N'$(Variant) Data.Read = ', COALESCE (CAST (@ReadId AS NVARCHAR (11)), N'(absent)')
              , N', Data.Insert = ', COALESCE (CAST (@InsId AS NVARCHAR (11)), N'(absent)')
              , N', Data.Update = ', COALESCE (CAST (@UpdId AS NVARCHAR (11)), N'(absent)')
              , N'. Predicates not carrying their id: ', COALESCE (@Missing, N'(none)')
              , N'. A stale list here is UI-35: the grants are real, the predicate has never heard of the id, and '
              , N'every read returns nothing without raising anything. Fix by running '
              , N'auth.uspRebuildTenantAccessPolicy @Action = N''Rebuild''.'));

-- 10c. The tenants section 5 created, and the invariant 020 calls the worst failure this schema can have.
DECLARE @Grown INT, @Crossing INT, @Deep INT, @DeepDepth INT, @DeepClosure INT;

SELECT @Grown = COUNT (*)
  FROM auth.Tenant
 WHERE ApplicationId = @App AND TenantCode LIKE N'E2E[_]%' AND IsDeleted = 0;

SELECT @Deep = t.TenantId FROM auth.Tenant AS t
 WHERE t.ApplicationId = @App AND t.TenantCode = @DeepCode AND t.IsDeleted = 0;

SELECT @DeepDepth   = v.Depth  FROM auth.vwTenantHierarchy AS v WHERE v.TenantId = @Deep;
SELECT @DeepClosure = COUNT (*) FROM auth.TenantClosure WHERE DescendantTenantId = @Deep;

SELECT @Crossing = COUNT (*)
  FROM auth.TenantClosure AS tc
 INNER JOIN auth.Tenant   AS anc ON anc.TenantId = tc.AncestorTenantId
 INNER JOIN auth.Tenant   AS des ON des.TenantId = tc.DescendantTenantId
 WHERE anc.ApplicationId <> des.ApplicationId;

INSERT @Report (Severity, Status, Item, Detail)
VALUES (CASE WHEN @Grown >= 2 AND @Crossing = 0 AND @DeepClosure = @DeepDepth + 1 THEN 4 ELSE 1 END
      , CASE WHEN @Grown >= 2 AND @Crossing = 0 AND @DeepClosure = @DeepDepth + 1 THEN 'OK' ELSE 'BROKEN' END
      , N'Tenants created through auth.uspCreateTenant, with a closure that agrees'
      , CONCAT (@Grown, N' tenant(s) coded E2E_* exist in $(Variant). The deepest, ', @DeepCode, N' (id '
              , COALESCE (CAST (@Deep AS NVARCHAR (11)), N'absent'), N'), sits at depth '
              , COALESCE (CAST (@DeepDepth AS NVARCHAR (11)), N'?'), N' with '
              , COALESCE (CAST (@DeepClosure AS NVARCHAR (11)), N'?'), N' closure row(s) -- self plus every ancestor. '
              , @Crossing, N' closure pair(s) cross an application boundary, and the only acceptable number is 0. This '
              , N'is the switch-over _tests/020_tenancy_variant_trees.sql asked for in its own header.'));

-- 10d. The worker's authority, read from the answers table rather than from the grants.
DECLARE @Verbs INT, @VerbList NVARCHAR (600), @WProf INT;

SELECT @WProf = up.UserProfileId
  FROM auth.UserProfile AS up
 INNER JOIN auth.[User] AS u ON u.UserId = up.UserId
 WHERE u.UserName = N'e2e.worker.$(Variant)' AND up.TenantId = @Deep AND up.IsDeleted = 0;

SELECT @Verbs    = COUNT (DISTINCT p.PermissionId)
     , @VerbList = STRING_AGG (CAST (p.PermissionCode AS NVARCHAR (MAX)), N', ')
                          WITHIN GROUP (ORDER BY p.PermissionCode)
  FROM auth.ProfilePermissionScope AS pps
 INNER JOIN auth.Permission        AS p ON p.PermissionId = pps.PermissionId
 WHERE pps.UserProfileId = @WProf
   AND pps.IsDeleted     = 0
   AND p.PermissionCode LIKE N'Data.%';

INSERT @Report (Severity, Status, Item, Detail)
VALUES (CASE WHEN @Verbs >= 7 THEN 4 ELSE 2 END
      , CASE WHEN @Verbs >= 7 THEN 'OK' ELSE 'THIN' END
      , N'A user, a profile and four role grants made through the procedures'
      , CONCAT (N'UserProfileId ', COALESCE (CAST (@WProf AS NVARCHAR (11)), N'(absent)'), N' at ', @DeepCode
              , N' holds ', COALESCE (CAST (@Verbs AS NVARCHAR (11)), N'0'), N' Data.* permission(s): '
              , COALESCE (@VerbList, N'(none)'), N'. CONTRIBUTOR, EDITOR, APPROVER and DATA_STEWARD -- seven distinct '
              , N'verbs between them, and APPROVER and DATA_STEWARD carry Data.Update because an RLS block predicate '
              , N'is handed a row and cannot tell an approval from an edit. Gap G-38, measured 2026-09-20.'));

-- 10e. The case work, read WITHOUT the predicates, which is why this connection has no session.
DECLARE @CaseId INT, @CaseStatus VARCHAR (20), @CaseTenant INT, @CaseNotes INT;

SELECT @CaseId     = cf.CaseFileId
     , @CaseStatus = cf.CaseStatus
     , @CaseTenant = cf.TenantId
  FROM dbo.CaseFile AS cf
 WHERE cf.CaseNumber = @CaseNum AND cf.IsDeleted = 0;

SELECT @CaseNotes = COUNT (*) FROM dbo.CaseNote WHERE CaseFileId = @CaseId AND IsDeleted = 0;

INSERT @Report (Severity, Status, Item, Detail)
VALUES (CASE WHEN @CaseId IS NOT NULL AND @CaseStatus = 'approved' AND @CaseTenant = @Deep AND @CaseNotes >= 1
             THEN 4 ELSE 1 END
      , CASE WHEN @CaseId IS NOT NULL AND @CaseStatus = 'approved' AND @CaseTenant = @Deep AND @CaseNotes >= 1
             THEN 'OK' ELSE 'FAILED' END
      , N'Real case work under row-level security at a tenant minutes old'
      , CONCAT (N'CaseNumber ', @CaseNum, N' is CaseFileId '
              , COALESCE (CAST (@CaseId AS NVARCHAR (11)), N'(absent)'), N' at tenant '
              , COALESCE (CAST (@CaseTenant AS NVARCHAR (11)), N'?'), N' (expected ', @Deep, N'), status '
              , COALESCE (@CaseStatus, N'?'), N', ', @CaseNotes, N' note(s). Inserted under '
              , N'auth.tvfTenantInsertPredicate, which demands both a Data.Insert id resolved in THIS application and '
              , N'@TenantId = ActingTenantId (P-06), then approved under the update predicate bound twice.'));

-- 10f. The registration path, where the variant has one.
IF N'$(Variant)' = N'VARIANT3'
BEGIN
    DECLARE @BranchCode NVARCHAR (100) = (SELECT s.SettingValue
                                            FROM config.ApplicationSetting AS s
                                           WHERE s.SettingKey = N'Registration.ExternalBranchTenantCode'
                                             AND s.IsDeleted  = 0)
          , @OrgTenant  INT
          , @OrgParent  NVARCHAR (100)
          , @OrgType    NVARCHAR (100)
          , @ExtRoles   INT;

    SELECT @OrgTenant = t.TenantId
         , @OrgParent = pt.TenantCode
         , @OrgType   = t.TenantTypeCode
      FROM auth.Tenant AS t
      LEFT JOIN auth.Tenant AS pt ON pt.TenantId = t.ParentTenantId
     WHERE t.ApplicationId = @App AND t.TenantCode = N'E2E_ORG' AND t.IsDeleted = 0;

    SELECT @ExtRoles = COUNT (*)
      FROM auth.UserProfileRole AS upr
     INNER JOIN auth.UserProfile AS up ON up.UserProfileId = upr.UserProfileId
     INNER JOIN auth.[User]      AS u  ON u.UserId         = up.UserId
     WHERE u.UserName = N'e2e.external.$(Variant)' AND upr.IsDeleted = 0 AND up.IsDeleted = 0;

    INSERT @Report (Severity, Status, Item, Detail)
    VALUES (CASE WHEN @OrgTenant IS NOT NULL AND @OrgParent = @BranchCode
                  AND @OrgType = N'ExternalOrganization' AND @ExtRoles >= 1 THEN 4 ELSE 1 END
          , CASE WHEN @OrgTenant IS NOT NULL AND @OrgParent = @BranchCode
                  AND @OrgType = N'ExternalOrganization' AND @ExtRoles >= 1 THEN 'OK' ELSE 'FAILED' END
          , N'Self-service registration, approval and staffing (section 17.3 only)'
          , CONCAT (N'E2E_ORG is tenant ', COALESCE (CAST (@OrgTenant AS NVARCHAR (11)), N'(absent)'), N', type '
                  , COALESCE (@OrgType, N'?'), N', under branch ', COALESCE (@OrgParent, N'(no parent)')
                  , N' where the global setting Registration.ExternalBranchTenantCode says '
                  , COALESCE (@BranchCode, N'(missing)'), N'. The external user holds ', @ExtRoles
                  , N' role grant(s) from auth.TenantDefaultRole -- section 17.3 rows F1 and F2. The setting is GLOBAL '
                  , N'and the tenant it names is per application, so every registration-accepting application must '
                  , N'code its branch identically: gap G-34, which broke this path until 2026-09-20.'));
END
ELSE
    INSERT @Report (Severity, Status, Item, Detail)
    VALUES (4, 'N/A', N'Self-service registration, approval and staffing (section 17.3 only)'
          , N'$(Variant) has no external-organizations branch, so there is nothing for a stranger to register into. '
          + N'Only section 17.3 exercises auth.uspRegisterOrganization, and this row is here so that a run against '
          + N'VARIANT1 or VARIANT2 reports the absence deliberately rather than by silence.');

-- 10g. The credential gap, asserted so it closes itself.  If a procedure ever demands User.ResetCredential, this row
--      turns from a warning into an OK without anyone having to remember to come back and edit it.
DECLARE @CredProcs NVARCHAR (400) = NULL;

SELECT @CredProcs = STRING_AGG (CAST (CONCAT (SCHEMA_NAME (o.schema_id), N'.', o.name) AS NVARCHAR (MAX)), N', ')
  FROM sys.sql_modules AS m
 INNER JOIN sys.objects AS o ON o.object_id = m.object_id
 WHERE o.type = 'P'
   AND m.definition LIKE N'%User.ResetCredential%';

INSERT @Report (Severity, Status, Item, Detail)
VALUES (CASE WHEN @CredProcs IS NULL THEN 3 ELSE 4 END
      , CASE WHEN @CredProcs IS NULL THEN 'GAP' ELSE 'CLOSED' END
      , N'No shipped procedure writes auth.UserCredential'
      , CONCAT (N'Procedures demanding User.ResetCredential: ', COALESCE (@CredProcs, N'(none)')
              , N'. The permission is seeded by 115_seed_reference_data.sql and carried by USER_ADMIN, and '
              , N'auth.uspCreateUser has no verifier parameter, so a password verifier can only be written directly -- '
              , N'by the installer or by the application layer. Sections 3b and 8a of this file do exactly that and say '
              , N'so. Warning, not a failure: it may be a deliberate boundary, since a verifier the database can set '
              , N'is a verifier the database knows. But an unreachable seeded permission should be one or the other.'));

-- 10h. What was deliberately not cloned, stated so an empty table is not mistaken for a defect.
INSERT @Report (Severity, Status, Item, Detail)
VALUES (4, 'INFO', N'The UI catalogue is deliberately not cloned'
      , N'auth.UiElement and auth.UiElementPermission are per application and hold none of $(Variant)''s rows. That is '
      + N'a decision: the catalogue describes screens, and a tenancy-shape fixture has none. A project cloning this '
      + N'template into a real second application DOES need to populate them, or auth.uspGetNavigationForProfile '
      + N'returns an empty tree -- which sections 4 and 8 both demonstrated, harmlessly, on the way past.');

-- The verdict, in the house form: a line anyone can grep for, then the rows.
IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
    PRINT N'070_variants_end_to_end.sql ($(Variant)): PROBLEMS found -- see the report below.';
ELSE
    PRINT N'070_variants_end_to_end.sql ($(Variant)): no problems found.';

SELECT Severity, Status, Item, Detail FROM @Report ORDER BY Severity, RowNo;
GO

