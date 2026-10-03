/***********************************************************************************************************************
Script:         900_bootstrap_first_admin.sql
Purpose:        Create the first platform administrator on a database that has none -- one authentication policy at the
                root, one user, one credential, one profile, five role grants and seven trail rows -- and refuse, loudly
                and permanently, to do it a second time.
Target:         SQL Server 2022.
Run as:         db_owner in the target database.
Run with:       Six scripting variables, FIVE OF THEM THROUGH THE ENVIRONMENT -- see the note below, this is not a
                stylistic preference:

                    PowerShell:   $env:AppCode          = 'TEMPLATE'
                                  $env:AdminUserName    = 'first.admin'
                                  $env:AdminDisplayName = 'First Administrator'
                                  $env:AdminEmail       = 'first.admin@example.gov'
                                  $env:AdminVerifierPhc = '<the PHC string the application produced>'
                                  sqlcmd -S <server> -d <database> -I -C -b -v DbName=<database>
                                         -i database/900_bootstrap_first_admin.sql
Idempotent:     NO, and deliberately not.  It succeeds exactly once per database and raises E-50080 for ever after.
Depends on:     Every table script, 115_seed_reference_data.sql (the application, the root tenant and the five roles),
                165_logs_procedures.sql (logs.uspRecordAuthorizationChange) and 100_auth_functions.sql plus the script
                that builds auth.uspRebuildProfilePermissionScope.
Implements:     T-092.  DES-AUTH-001 sections 16.2, 16.3, 7.2.  Appendix B E-50080, E-50085, E-50086, E-50087.
                See docs/10-database-authn-authz-design.md.
To retarget:    Pass the database per run:  sqlcmd -d <database> -v DbName=<database>.

WHY FIVE OF THE SIX VARIABLES ARE PASSED THROUGH THE ENVIRONMENT AND NOT THROUGH -v
----------------------------------------------------------------------------------
Two measured facts about sqlcmd 17, both found the hard way while testing this file:

  1. A -v VALUE CANNOT CONTAIN A SPACE.  Not with double quotes, not with backslash-escaped double quotes, not as a
     single pre-quoted argv from PowerShell or from bash.  sqlcmd reports  'AdminDisplayName=First Administrator':
     Invalid argument  and exits.  A display name with a space in it is not an exotic input.
  2. sqlcmd RESOLVES A SCRIPTING VARIABLE FROM -v FIRST AND FROM THE PROCESS ENVIRONMENT SECOND.  An environment
     variable carries spaces, commas, equals signs and the several $ characters of a PHC string through untouched.

So DbName stays on the command line, where every other script in this template expects it, and the five values that can
contain anything go through the environment.  Install-TemplateDatabase.ps1 does the same, for the same reason.  UI-42.

A LITERAL REMINDER ABOUT THE PHC STRING: it contains $ characters, and sqlcmd substitutes only the sequence
"$" followed by "(".  An argon2id PHC string has no parentheses, so it passes through unexpanded -- but a credential
format that ever did contain one would be silently corrupted, and the check in section 1a would not catch it.

THE CHICKEN AND THE EGG, AND WHY THIS IS A SCRIPT RATHER THAN A PROCEDURE
------------------------------------------------------------------------
INV-05 says every authorization row names the profile that granted it, and every grant procedure enforces it by demanding
a live session and a permission.  On an empty database there is no profile, no session and no permission to hold, so the
first administrator cannot be created through the procedures -- not because the procedures are incomplete but because
they are correct.  Something has to write the first rows without a grantor, and that something must be:

  *  outside the permission system, so it cannot be reached by an authenticated caller;
  *  runnable only by a DBA holding db_owner at deployment time;
  *  incapable of running twice.

A stored procedure satisfies none of those: it would be a permanent object in the database, callable for ever, and the
only thing standing between it and a second back door would be a check inside itself.  A script that a DBA runs once
from the install media is the honest shape.  It is also why it is numbered 900 rather than 090: it is not part of the
schema, it is an act performed ON the schema.

E-50080 COUNTS EVERY auth.UserProfile ROW, INCLUDING SOFT-DELETED ONES
---------------------------------------------------------------------
Section 16.3 clause 1 says "refuses to run if any auth.UserProfile row already exists".  Read with the template's
soft-delete convention that means ALL rows and not merely the live ones, and the stricter reading is the one that is
implemented here.  If the count filtered on IsDeleted = 0 then the route back to a second bootstrap would be: soft-delete
every profile, re-run this file, get a fresh administrator with no trail connecting it to the old one.  Retiring every
profile in a database is already a catastrophe; it must not also be a privilege escalation.  A row here -- live, retired
or deleted -- is proof that this database has been bootstrapped, and proof is what clause 1 is asking for.

E-50080 ALSO COVERS A PRE-EXISTING USER OF THE REQUESTED NAME, WHICH IS A DOCUMENTED WIDENING OF APPENDIX B
---------------------------------------------------------------------------------------------------------
Appendix B registers E-50080 as "profiles already exist; bootstrap refused".  A database with no profiles but with a user
already called by the requested name is the same kind of fact -- rows that this file must not write over -- and it has no
number of its own.  Rather than invent one, E-50080 is raised with a different sentence, because a caller who reads
either sentence does the same thing: stop, and look at what is already there.  The alternative is a unique-index
violation on UX_auth_UserProfile_UserTenantName's sibling on auth.[User], reported by the engine, at a point where half
the transaction has been written.  G-37.  Same decision and same grounds as E-50084's widening in 160 (G-35).

WHY THIS FILE OWNS THE ROOT TENANT'S AUTHENTICATION POLICY WHEN 115 OWNS THE ROOT TENANT ITSELF
---------------------------------------------------------------------------------------------
The root tenant moved to 115_seed_reference_data.sql because auth.Role.OwnerTenantId is NOT NULL and the baseline roles
cannot be seeded before their owner exists (BL-051, G-25).  The root tenant's POLICY did not move, and this is the file
that needs it:

    auth.udfResolveAuthPolicy walks auth.TenantClosure upwards and returns the NEAREST policy, or NULL when no ancestor
    has one.  auth.uspCompleteLogin reads that policy and, when it is NULL, falls back to AllowLocalPassword = 1 and
    RequireMfaForLocal = 1 -- fail-closed, which is right in general and fatal here.  The account this file creates has
    no confirmed MFA factor, and enrolling one requires a live session, which requires a completed sign-in, which
    requires a second factor.  A bootstrap that does not write a policy row therefore produces an administrator who can
    never sign in, and the failure appears as E-50109 on the first attempt with nothing in the database to explain it.

So section 2 below writes the root policy with RequireMfaForLocal = 0 and says so on the screen in as many words.  THIS
IS THE ONE SECURITY DECISION IN THIS FILE THAT A DEPLOYMENT MUST REVISIT: the root policy is the ancestor of every
tenant, so until it is tightened, no tenant requires a second factor.  The instruction printed at the end is not
decoration -- enrol a factor for the administrator, then set RequireMfaForLocal = 1 on this row, before the deployment
holds anything real.  Recorded as G-37 so section 16.3 gains a clause saying it.

IF THE POLICY ROW ALREADY EXISTS, IT IS LEFT EXACTLY AS IT IS
------------------------------------------------------------
A project may have written its own root policy before running this file -- stricter lifetimes, federation, a note.  That
is a deliberate act and this file does not second-guess it: section 2 inserts only when no live policy names the root
tenant, and reports which of the two happened.  It is the only part of the script that is conditional, and it is the
reason the closing report distinguishes "created" from "found".

THE CREDENTIAL IS NOT DEFAULTED, NOT GENERATED HERE, AND NOT A PASSWORD
----------------------------------------------------------------------
Section 16.3 clause 6 requires the credential on the command line.  What is passed is the PHC string the APPLICATION
produced -- argon2id, from the application's own hasher, with the application's own parameters.  The database never sees
the password and has no hasher: T-041's requirement that secrets are held and encrypted on the application side is the
same principle one layer down.  The refusal sentinel REPLACE-ME is what the install runner passes when the operator has
not supplied one, and E-50085 rejects it, an empty value, and anything that does not have the shape
auth.UserCredential's CHECK constraint will accept (LEN >= 16 and two dollar-delimited fields).  A genuinely ABSENT
-v produces sqlcmd's own "scripting variable is not defined" and stops the file before its first batch; there is
deliberately no  :setvar  fallback, because a :setvar in the file OVERRIDES -v rather than yielding to it (measured on
sqlcmd 17 -- 000_prerequisites.sql records the same measurement for DbName), so a default would be unremovable.

MustChangePassword = 1 IS SET ON THE USER AND NOT ON THE CREDENTIAL
------------------------------------------------------------------
Whoever runs this file knows the password, and that is one person too many.  auth.[User].MustChangePassword is what
auth.uspCompleteLogin returns to the application, so the first sign-in lands on the change-password screen and the
operator's copy of the credential is dead within a minute of being used.  auth.UserCredential.ExpiresUtc is left NULL
deliberately: an expired credential cannot be used to sign in AT ALL, so it would lock the account rather than force a
change, and the two fields are not interchangeable.

THE ROOT PROFILE GETS FIVE ROLES AND NOT SIXTEEN
-----------------------------------------------
Section 16.3 clause 4 names PLATFORM_ADMIN, ROLE_ADMIN, USER_ADMIN, TENANT_ADMIN and ROLE_ARCHITECT: enough to build the
tenant tree, define roles, create users and profiles, and confer platform administration on a second person.  It does
not include AUDITOR, CONFIG_ADMIN, PROFILE_ASSIGNER or any of the Data roles -- and PROFILE_ASSIGNER is worth naming
among the absences even though T-128 added it after this file was written, because it is a SUBSET of the ROLE_ADMIN this
profile already holds, so granting it as well would confer nothing and only blur the five.  The first administrator's job
is to create the
people who hold those and then stop being the only account that can do anything.  E-50087 refuses when any of the five
is missing rather than granting the four that are present: a profile that cannot create the second administrator is not
a bootstrap, and finding that out on the first sign-in is worse than finding it out here.

THE SEVEN TRAIL ROWS ALL CARRY ActorUserProfileId = NULL
-------------------------------------------------------
One ProfileCreated, one PlatformAdminGranted, five RoleGranted -- and every one of them with a NULL actor and
"bootstrap":true in DetailJson, so a reader of logs.AuthorizationChange sees the discontinuity explained rather than a
story that starts in the middle.  NOTE THAT PASSING NULL IS NOT BY ITSELF ENOUGH: logs.uspRecordAuthorizationChange
defaults the actor from SESSION_CONTEXT when it is given NULL, so the rows are NULL only because this file never calls
auth.uspSetSessionContext and sqlcmd opened a fresh connection.  Section 5 asserts all seven are NULL rather than
assuming it.
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
  FROM (VALUES (N'auth.Application',                 N'030_auth_tenant.sql')
             , (N'auth.Tenant',                      N'030_auth_tenant.sql')
             , (N'auth.TenantAuthenticationPolicy',  N'035_auth_tenant_policy.sql')
             , (N'auth.TenantClosure',               N'030_auth_tenant.sql')
             , (N'auth.[User]',                      N'045_auth_identity.sql')
             , (N'auth.UserCredential',              N'045_auth_identity.sql')
             , (N'auth.UserProfile',                 N'040_auth_userprofile.sql')
             , (N'auth.UserProfileRole',             N'060_auth_profile_role.sql')
             , (N'auth.Role',                        N'055_auth_role.sql')
             , (N'logs.AuthorizationChange',         N'020_logs_tables.sql')
       ) AS x (ObjName, Script);

IF LEN (@Missing) > 0
BEGIN
    DECLARE @MsgMissing NVARCHAR (2000) =
        N'900_bootstrap_first_admin.sql cannot run: ' + LEFT (@Missing, LEN (@Missing) - 1)
      + N'. Run the named script(s) first. Nothing has been changed.';

    THROW 50000, @MsgMissing, 1;
END
GO

IF OBJECT_ID (N'logs.uspRecordAuthorizationChange', N'P') IS NULL
   OR OBJECT_ID (N'auth.uspRebuildProfilePermissionScope', N'P') IS NULL
BEGIN
    DECLARE @MsgProcs NVARCHAR (2000) =
        N'logs.uspRecordAuthorizationChange (165_logs_procedures.sql) or auth.uspRebuildProfilePermissionScope '
      + N'(095_auth_scope_maintenance.sql) is missing. The bootstrap writes the authorization trail through the one and '
      + N'materializes the new profile''s scope through the other, and a bootstrap that skips either leaves an '
      + N'administrator with no trail or with no permissions. Nothing has been changed.';

    THROW 50000, @MsgProcs, 1;
END
GO


-- *** 1. The refusals.  Every one of them BEFORE the transaction opens ***
-- E-50080, E-50085, E-50086 and E-50087 are all reasons not to start, so all four are settled here and nothing below
-- this section can refuse.  The order is: is the credential usable, is the ground prepared, and has this already been
-- done -- cheapest and most likely misuse first.
DECLARE @Failure NVARCHAR (2000);

-- 1a. E-50085.  The credential.
IF N'$(AdminVerifierPhc)' = N''
   OR N'$(AdminVerifierPhc)' = N'REPLACE-ME'
   OR LEN (N'$(AdminVerifierPhc)') < 16
   OR N'$(AdminVerifierPhc)' NOT LIKE N'$%$%'
BEGIN
    SET @Failure =
        N'AdminVerifierPhc (set it in the environment, not with -v -- see the file header) was empty, was left at the '
      + N'refusal sentinel REPLACE-ME, or does not have the shape of a '
      + N'PHC string (at least 16 characters, at least two dollar-delimited fields -- the same test '
      + N'CK_auth_UserCredential_VerifierPhc applies). Section 16.3 requires the credential on the command line and '
      + N'forbids a default: the application hashes the password with its own argon2id parameters and passes the '
      + N'result, and the database never sees the password itself. Nothing has been changed.';

    ;THROW 50085, @Failure, 1;
END;

-- 1b. E-50086.  The application, and the root tenant beneath it.  Resolved STRUCTURALLY -- the root is the tenant of
--     type Root with no parent -- so a project that renamed ROOT to its own code needs no extra argument here.
DECLARE @ApplicationId INT = (SELECT ApplicationId FROM auth.Application
                               WHERE ApplicationCode = N'$(AppCode)' AND IsDeleted = 0);

IF @ApplicationId IS NULL
BEGIN
    SET @Failure =
        N'-v AppCode=$(AppCode) names no live application. 115_seed_reference_data.sql seeds exactly one, so this '
      + N'means 115 has not run -- and without it there are no permissions, no baseline roles and no root tenant for '
      + N'the administrator''s profile to sit at. Run 115_seed_reference_data.sql and then 120_rls_policy.sql, in that '
      + N'order (section 16.1 item 3). Nothing has been changed.';

    ;THROW 50086, @Failure, 1;
END;

DECLARE @RootTenantId INT
      , @RootCount    INT;

SELECT @RootCount    = COUNT (*)
     , @RootTenantId = MIN (t.TenantId)
  FROM auth.Tenant AS t
 WHERE t.ApplicationId   = @ApplicationId
   AND t.TenantTypeCode  = N'Root'
   AND t.ParentTenantId IS NULL
   AND t.IsDeleted       = 0;

IF @RootCount <> 1
BEGIN
    SET @Failure =
        N'Application $(AppCode) has ' + CAST (COALESCE (@RootCount, 0) AS NVARCHAR (11))
      + N' live parentless tenants of type Root, and the bootstrap needs exactly one to put the administrator''s '
      + N'profile at. One means 115_seed_reference_data.sql has run; zero means it has not; more than one means the '
      + N'tenant tree has two roots, which INV-03 does not allow and 125_auth_tenant_procedures.sql does not create. '
      + N'Nothing has been changed.';

    ;THROW 50086, @Failure, 1;
END;

-- 1c. E-50087.  The five roles section 16.3 step 4 grants, all of them, owned by the root.
DECLARE @Roles TABLE (RowNo INT IDENTITY (1,1) PRIMARY KEY, RoleCode NVARCHAR (50) NOT NULL UNIQUE, RoleId INT NULL);

INSERT @Roles (RoleCode)
VALUES (N'PLATFORM_ADMIN'), (N'ROLE_ADMIN'), (N'USER_ADMIN'), (N'TENANT_ADMIN'), (N'ROLE_ARCHITECT');

UPDATE r
   SET r.RoleId = src.RoleId
  FROM @Roles AS r
 CROSS APPLY (SELECT TOP (1) ar.RoleId
                FROM auth.Role AS ar
               WHERE ar.RoleCode      = r.RoleCode
                 AND ar.ApplicationId = @ApplicationId
                 AND ar.OwnerTenantId = @RootTenantId
                 AND ar.IsDeleted     = 0
               ORDER BY ar.RoleId) AS src;

IF EXISTS (SELECT 1 FROM @Roles WHERE RoleId IS NULL)
BEGIN
    DECLARE @Absent NVARCHAR (500) = (SELECT STRING_AGG (RoleCode, N', ') WITHIN GROUP (ORDER BY RoleCode)
                                        FROM @Roles WHERE RoleId IS NULL);

    SET @Failure =
        N'These roles are missing from application $(AppCode) at the root tenant: ' + @Absent
      + N'. Section 16.3 step 4 grants all five, and the bootstrap will not create a profile it cannot make useful -- a '
      + N'first administrator who cannot create the second one is not a bootstrap. 115_seed_reference_data.sql seeds '
      + N'the sixteen baseline roles (section 16.2''s fourteen, plus CRUD_ACCESS and PROFILE_ASSIGNER from T-128) owned by the root tenant so they are assignable anywhere '
      + N'(INV-04); run it first. Nothing has been changed.';

    ;THROW 50087, @Failure, 1;
END;

-- 1d. E-50080.  Has this already been done?  Every row, not merely the live ones -- see the header.
DECLARE @ProfileRows INT = (SELECT COUNT (*) FROM auth.UserProfile);

IF @ProfileRows > 0
BEGIN
    SET @Failure =
        N'This database already holds ' + CAST (@ProfileRows AS NVARCHAR (11))
      + N' auth.UserProfile row(s), including soft-deleted ones, so it has been bootstrapped already and this file '
      + N'refuses (section 16.3 clause 1). The second and subsequent administrators are created through the ordinary '
      + N'procedures by the first: auth.uspCreateUser, auth.uspCreateProfile, auth.uspAssignRoleToProfile and '
      + N'auth.uspGrantPlatformAdmin. If every administrator account has been lost, that is a restore-from-backup '
      + N'problem and not a re-bootstrap problem. Nothing has been changed.';

    ;THROW 50080, @Failure, 1;
END;

IF EXISTS (SELECT 1 FROM auth.[User] WHERE UserName = N'$(AdminUserName)')
BEGIN
    SET @Failure =
        N'A user named $(AdminUserName) already exists in this database, so the bootstrap refuses rather than colliding '
      + N'with UX_auth_User_UserName half way through its transaction. There are no profiles, so this database has not '
      + N'been bootstrapped -- but it is not empty either, and somebody should look at what is already in auth.[User] '
      + N'before a privileged account is added to it. Pass a different -v AdminUserName= or clear the database. '
      + N'Nothing has been changed. (E-50080 widened -- G-37.)';

    ;THROW 50080, @Failure, 1;
END;


-- *** 2. The write.  One transaction: either there is an administrator or there is nothing ***
-- NOTE THAT THIS IS STILL THE SAME BATCH as section 1.  @ApplicationId, @RootTenantId and @Roles were resolved by the
-- refusals and a GO would discard them; re-deriving them after the checks would mean checking one thing and writing
-- another.  The audit columns are left to their defaults throughout, because their default IS ORIGINAL_LOGIN () and the
-- honest answer to "who created the first administrator" is the name of the DBA who ran this file.
DECLARE @Now           DATETIME2 (7) = SYSUTCDATETIME ()
      , @UserId        INT
      , @ProfileId     INT
      , @PolicyCreated BIT
      , @PolicyId      INT
      , @Detail        NVARCHAR (2000)
      , @ChangeId      BIGINT
      , @RowNo         INT = 1
      , @MaxRowNo      INT
      , @EachRoleId    INT
      , @EachCode      NVARCHAR (50);

BEGIN TRY
    BEGIN TRANSACTION;

    -- 2a.  The root tenant's authentication policy.  The ONLY conditional write in the file: a project that has already
    --      written its own root policy made a deliberate decision and this file does not overrule it.  See the header
    --      for why the absence of this row would lock the account it is about to create out of its own database.
    IF NOT EXISTS (SELECT 1 FROM auth.TenantAuthenticationPolicy
                    WHERE TenantId = @RootTenantId AND IsDeleted = 0)
    BEGIN
        INSERT auth.TenantAuthenticationPolicy
            (TenantId, AllowFederated, AllowLocalPassword, RequireMfaForLocal, PreferredMethod
           , SessionLifetimeMinutes, IdleTimeoutMinutes, RequireStepUpForPrivileged, PolicyNote)
        VALUES (@RootTenantId, 0, 1, 0, 'LocalPassword', 480, 60, 0
              -- The note must fit NVARCHAR (1000). The first version did not, and every fresh bootstrap failed with Msg 2628,
              -- so 070 and 080 could never run on a clean build (G-54, BL-086).
              , N'Created by 900_bootstrap_first_admin.sql so the first administrator can sign in. RequireMfaForLocal '
              + N'and RequireStepUpForPrivileged are 0 because the account has no confirmed factor yet; this row is the '
              + N'nearest ancestor of every tenant, so it shadows Authn.RequireStepUpForPrivilegedDefault. Set both to 1 '
              + N'once the administrator has a confirmed factor (G-30, G-37).');

        SET @PolicyCreated = 1;
    END
    ELSE
    BEGIN
        SET @PolicyCreated = 0;
    END;

    SELECT @PolicyId = p.TenantAuthenticationPolicyId
      FROM auth.TenantAuthenticationPolicy AS p
     WHERE p.TenantId = @RootTenantId AND p.IsDeleted = 0;

    -- 2b.  The user.  MustChangePassword = 1 on the USER, not ExpiresUtc on the credential -- see the header.
    INSERT auth.[User] (UserName, DisplayName, Email, IsActive, IsPlatformAdmin, MustChangePassword)
    VALUES (N'$(AdminUserName)', N'$(AdminDisplayName)', NULLIF (N'$(AdminEmail)', N''), 1, 1, 1);

    SET @UserId = CAST (SCOPE_IDENTITY () AS INT);

    -- 2c.  The credential the application hashed.  auth.uspCreateUser is not used anywhere in this file: it demands a
    --      session and refuses @IsPlatformAdmin = 1 outright (E-50155), both of which are correct and both of which
    --      are exactly what cannot be satisfied yet.
    INSERT auth.UserCredential (UserId, CredentialType, VerifierPhc, LastChangedUtc)
    VALUES (@UserId, 'Password', N'$(AdminVerifierPhc)', @Now);

    -- 2d.  The profile, at the root, default because it is the only one.
    INSERT auth.UserProfile (UserId, TenantId, ProfileName, IsDefault, IsActive)
    VALUES (@UserId, @RootTenantId, N'Platform Administrator', 1, 1);

    SET @ProfileId = CAST (SCOPE_IDENTITY () AS INT);

    -- 2e.  The five grants.  GrantedByProfileId IS NULL HERE AND NOWHERE ELSE IN THE DATABASE: INV-05 requires a
    --      granting profile and this is the one row set that has none, which is the whole reason this file exists.
    --      Scoped at the root, so the authority covers the entire tree (a scope row means "this tenant and below").
    INSERT auth.UserProfileRole
        (UserProfileId, RoleId, ScopeTenantId, ApplicationId, GrantedByProfileId, GrantedUtc)
    SELECT @ProfileId, r.RoleId, @RootTenantId, @ApplicationId, NULL, @Now
      FROM @Roles AS r;

    -- 2f.  The trail.  Seven rows, NULL actor, "bootstrap":true -- section 16.3 clause 5.
    SET @Detail = N'{"bootstrap":true,"tenantId":' + CAST (@RootTenantId AS NVARCHAR (11))
                + N',"profileName":"Platform Administrator","isDefault":true}';

    EXEC logs.uspRecordAuthorizationChange
          @ChangeType             = 'ProfileCreated'
        , @TargetUserId           = @UserId
        , @TargetUserProfileId    = @ProfileId
        , @RoleId                 = NULL
        , @ScopeTenantId          = @RootTenantId
        , @ActorUserProfileId     = NULL
        , @ActorAuthorityTenantId = NULL
        , @DetailJson             = @Detail
        , @AuthorizationChangeId  = @ChangeId OUTPUT;

    SET @Detail = N'{"bootstrap":true,"mustChangePassword":true,"administratorsBefore":0}';

    EXEC logs.uspRecordAuthorizationChange
          @ChangeType             = 'PlatformAdminGranted'
        , @TargetUserId           = @UserId
        , @TargetUserProfileId    = @ProfileId
        , @RoleId                 = NULL
        , @ScopeTenantId          = @RootTenantId
        , @ActorUserProfileId     = NULL
        , @ActorAuthorityTenantId = NULL
        , @DetailJson             = @Detail
        , @AuthorizationChangeId  = @ChangeId OUTPUT;

    SELECT @MaxRowNo = MAX (RowNo) FROM @Roles;

    WHILE @RowNo <= COALESCE (@MaxRowNo, 0)
    BEGIN
        SELECT @EachRoleId = r.RoleId
             , @EachCode   = r.RoleCode
          FROM @Roles AS r
         WHERE r.RowNo = @RowNo;

        SET @Detail = N'{"bootstrap":true,"roleCode":"' + @EachCode + N'","scopeTenantId":'
                    + CAST (@RootTenantId AS NVARCHAR (11)) + N',"grantedByProfileId":null}';

        EXEC logs.uspRecordAuthorizationChange
              @ChangeType             = 'RoleGranted'
            , @TargetUserId           = @UserId
            , @TargetUserProfileId    = @ProfileId
            , @RoleId                 = @EachRoleId
            , @ScopeTenantId          = @RootTenantId
            , @ActorUserProfileId     = NULL
            , @ActorAuthorityTenantId = NULL
            , @DetailJson             = @Detail
            , @AuthorizationChangeId  = @ChangeId OUTPUT;

        SET @RowNo += 1;
    END;

    IF @@TRANCOUNT > 0
    BEGIN
        COMMIT TRANSACTION;
    END;
END TRY
BEGIN CATCH
    IF XACT_STATE () <> 0
    BEGIN
        ROLLBACK TRANSACTION;
    END;

    ;THROW;
END CATCH

-- *** 3. Materialize the new profile's permission scope ***
-- AFTER the commit, deliberately: the maintainer is idempotent and restartable, so a failure here is a re-run rather
-- than a lost administrator.  It is the same procedure every grant procedure calls, and skipping it would leave a
-- profile holding five roles and resolving no permissions at all.
EXEC auth.uspRebuildProfilePermissionScope @UserProfileId = @ProfileId;

PRINT CONCAT (N'Bootstrapped user id ', @UserId, N', profile id ', @ProfileId, N' at root tenant id ', @RootTenantId
            , N'. Root authentication policy id ', @PolicyId
            , CASE WHEN @PolicyCreated = 1 THEN N' (created by this run).' ELSE N' (already present; left untouched).' END);
GO


-- *** 4. Closing report, and the hand-off ***
-- Everything is re-derived from the user name rather than carried in variables, so the report reads what was COMMITTED
-- rather than what this session believes it wrote.
SET NOCOUNT ON;

DECLARE @Report TABLE (RowNo INT IDENTITY (1,1) PRIMARY KEY, Severity INT, Status VARCHAR (10)
                     , Item NVARCHAR (200), Detail NVARCHAR (1000));

DECLARE @UserId    INT = (SELECT UserId FROM auth.[User] WHERE UserName = N'$(AdminUserName)' AND IsDeleted = 0)
      , @ProfileId INT
      , @RootId    INT
      , @PolicyId  INT
      , @Resolved  INT
      , @MfaOff    BIT
      , @StepUpOff BIT;

SELECT @ProfileId = up.UserProfileId
     , @RootId    = up.TenantId
  FROM auth.UserProfile AS up
 WHERE up.UserId = @UserId AND up.IsDeleted = 0;

SELECT @PolicyId  = p.TenantAuthenticationPolicyId
     , @MfaOff    = CASE WHEN p.RequireMfaForLocal         = 0 THEN 1 ELSE 0 END
     , @StepUpOff = CASE WHEN p.RequireStepUpForPrivileged = 0 THEN 1 ELSE 0 END
  FROM auth.TenantAuthenticationPolicy AS p
 WHERE p.TenantId = @RootId AND p.IsDeleted = 0;

SET @Resolved = auth.udfResolveAuthPolicy (@RootId);

-- 1. The account.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN u.UserId IS NULL THEN 1
            WHEN u.IsPlatformAdmin = 1 AND u.MustChangePassword = 1 AND u.IsActive = 1 THEN 4
            ELSE 1 END
     , CASE WHEN u.UserId IS NULL THEN 'MISSING'
            WHEN u.IsPlatformAdmin = 1 AND u.MustChangePassword = 1 AND u.IsActive = 1 THEN 'OK'
            ELSE 'WRONG' END
     , N'The administrator account'
     , CONCAT (N'UserName=$(AdminUserName), UserId=', COALESCE (CAST (u.UserId AS NVARCHAR (11)), N'(none)')
             , N', IsPlatformAdmin=', u.IsPlatformAdmin, N', MustChangePassword=', u.MustChangePassword
             , N', IsActive=', u.IsActive
             , N'. Section 16.3 step 3 requires all three: the flag, the forced change, and an enabled account.')
  FROM (SELECT 1 AS One) AS x
  LEFT JOIN auth.[User] AS u ON u.UserId = @UserId;

-- 2. The credential.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 1 THEN 4 ELSE 1 END
     , CASE WHEN COUNT (*) = 1 THEN 'OK' ELSE 'WRONG' END
     , N'The local password credential'
     , CONCAT (COUNT (*), N' live Password row(s) in auth.UserCredential for this user; exactly 1 is required by '
             , N'UX_auth_UserCredential_UserType. The verifier is the PHC string the application passed on the command '
             , N'line and is NOT printed anywhere by this file. ExpiresUtc is NULL by design -- MustChangePassword '
             , N'forces a change, an expiry would forbid the sign-in that performs it.')
  FROM auth.UserCredential AS c
 WHERE c.UserId = @UserId AND c.CredentialType = 'Password' AND c.IsDeleted = 0;

-- 3. The profile.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN up.UserProfileId IS NULL THEN 1
            WHEN up.IsDefault = 1 AND up.IsActive = 1 AND t.TenantTypeCode = N'Root' THEN 4
            ELSE 1 END
     , CASE WHEN up.UserProfileId IS NULL THEN 'MISSING'
            WHEN up.IsDefault = 1 AND up.IsActive = 1 AND t.TenantTypeCode = N'Root' THEN 'OK'
            ELSE 'WRONG' END
     , N'The profile, at the root tenant'
     , CONCAT (N'UserProfileId=', COALESCE (CAST (up.UserProfileId AS NVARCHAR (11)), N'(none)')
             , N', ProfileName=', up.ProfileName, N', TenantId=', up.TenantId, N' (', t.TenantCode, N', type '
             , t.TenantTypeCode, N'), IsDefault=', up.IsDefault, N', IsActive=', up.IsActive, N'.')
  FROM (SELECT 1 AS One) AS x
  LEFT JOIN auth.UserProfile AS up ON up.UserProfileId = @ProfileId
  LEFT JOIN auth.Tenant      AS t  ON t.TenantId       = up.TenantId;

-- 4. The five grants, and the one place in the database where GrantedByProfileId is NULL on purpose.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 5 AND SUM (CASE WHEN upr.GrantedByProfileId IS NULL THEN 1 ELSE 0 END) = 5 THEN 4
            ELSE 1 END
     , CASE WHEN COUNT (*) = 5 AND SUM (CASE WHEN upr.GrantedByProfileId IS NULL THEN 1 ELSE 0 END) = 5 THEN 'OK'
            ELSE 'WRONG' END
     , N'The five role grants section 16.3 step 4 names'
     , CONCAT (COUNT (*), N' of 5 live: '
             , COALESCE (STRING_AGG (r.RoleCode, N', ') WITHIN GROUP (ORDER BY r.RoleCode), N'(none)')
             , N'. All scoped at the root, so the authority covers the whole tree. '
             , SUM (CASE WHEN upr.GrantedByProfileId IS NULL THEN 1 ELSE 0 END)
             , N' of them have GrantedByProfileId NULL, which must be all of them: INV-05 has exactly this one '
             , N'exemption and it is the reason this file exists.')
  FROM auth.UserProfileRole AS upr
 INNER JOIN auth.Role       AS r ON r.RoleId = upr.RoleId
 WHERE upr.UserProfileId = @ProfileId
   AND upr.ScopeTenantId = @RootId
   AND upr.IsDeleted     = 0
   AND r.RoleCode IN (N'PLATFORM_ADMIN', N'ROLE_ADMIN', N'USER_ADMIN', N'TENANT_ADMIN', N'ROLE_ARCHITECT');

-- 5. The materialized scope, which is what auth.udfHasPermission actually reads.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 0 THEN 1
            WHEN SUM (CASE WHEN pm.PermissionCode = N'Platform.ManageApplications' THEN 1 ELSE 0 END) = 0 THEN 2
            ELSE 4 END
     , CASE WHEN COUNT (*) = 0 THEN 'EMPTY'
            WHEN SUM (CASE WHEN pm.PermissionCode = N'Platform.ManageApplications' THEN 1 ELSE 0 END) = 0 THEN 'THIN'
            ELSE 'OK' END
     , N'auth.ProfilePermissionScope for the new profile'
     , CONCAT (COUNT (*), N' live scope row(s), covering '
             , COUNT (DISTINCT pm.PermissionCode), N' distinct permission(s). Platform.ManageApplications present: '
             , CASE WHEN SUM (CASE WHEN pm.PermissionCode = N'Platform.ManageApplications' THEN 1 ELSE 0 END) > 0
                    THEN N'yes' ELSE N'NO -- the second administrator could not be created' END
             , N'. Empty means auth.uspRebuildProfilePermissionScope did not run or the roles hold no permissions '
             , N'(115_seed_reference_data.sql seeds auth.RolePermission).')
  FROM auth.ProfilePermissionScope AS pps
 INNER JOIN auth.Permission        AS pm ON pm.PermissionId = pps.PermissionId
 WHERE pps.UserProfileId = @ProfileId AND pps.IsDeleted = 0;

-- 6. The trail: seven rows, all NULL actor, all flagged as the bootstrap.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 7 AND SUM (CASE WHEN ac.ActorUserProfileId IS NULL THEN 1 ELSE 0 END) = 7
             AND SUM (CASE WHEN JSON_VALUE (ac.DetailJson, '$.bootstrap') = 'true' THEN 1 ELSE 0 END) = 7 THEN 4
            WHEN COUNT (*) = 0 THEN 1
            ELSE 2 END
     , CASE WHEN COUNT (*) = 7 AND SUM (CASE WHEN ac.ActorUserProfileId IS NULL THEN 1 ELSE 0 END) = 7
             AND SUM (CASE WHEN JSON_VALUE (ac.DetailJson, '$.bootstrap') = 'true' THEN 1 ELSE 0 END) = 7 THEN 'OK'
            WHEN COUNT (*) = 0 THEN 'MISSING'
            ELSE 'CHECK' END
     , N'logs.AuthorizationChange, section 16.3 clause 5'
     , CONCAT (COUNT (*), N' of 7 row(s) (1 ProfileCreated, 1 PlatformAdminGranted, 5 RoleGranted). NULL actor on '
             , SUM (CASE WHEN ac.ActorUserProfileId IS NULL THEN 1 ELSE 0 END), N' of them, "bootstrap":true on '
             , SUM (CASE WHEN JSON_VALUE (ac.DetailJson, '$.bootstrap') = 'true' THEN 1 ELSE 0 END)
             , N'. A non-NULL actor here means the file was run on a connection that had already established session '
             , N'context, because logs.uspRecordAuthorizationChange defaults the actor from SESSION_CONTEXT.')
  FROM logs.AuthorizationChange AS ac
 WHERE ac.TargetUserId = @UserId AND ac.IsDeleted = 0;

-- 7. The root policy, and the MFA decision this file makes on the deployment's behalf.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN @PolicyId IS NULL THEN 1 WHEN @MfaOff = 1 THEN 3 ELSE 4 END
     , CASE WHEN @PolicyId IS NULL THEN 'MISSING' WHEN @MfaOff = 1 THEN 'TIGHTEN' ELSE 'OK' END
     , N'The root tenant''s authentication policy'
     , CASE WHEN @PolicyId IS NULL
            THEN N'No live policy names the root tenant. auth.uspCompleteLogin then falls back to '
               + N'RequireMfaForLocal = 1 and this account has no confirmed factor, so it cannot sign in (E-50109).'
            WHEN @MfaOff = 1
            THEN CONCAT (N'Policy id ', @PolicyId, N' has RequireMfaForLocal = 0. THIS IS THE DECISION TO REVISIT: the '
                       , N'root policy is the ancestor of every tenant, so no tenant requires a second factor until it '
                       , N'is changed. Enrol a factor for the administrator (auth.uspEnrolMfaFactor), then set '
                       , N'RequireMfaForLocal = 1 on this row. Section 7.2, G-37.')
            ELSE CONCAT (N'Policy id ', @PolicyId, N' requires MFA for local sign-in. The administrator must have a '
                       , N'confirmed factor before the first sign-in will complete.') END;

-- 7b. The step-up flag on the same row, reported separately because it is a DIFFERENT decision with the same cause and
-- a consequence that only appeared when G-30 closed.  The permissive value here is no longer merely permissive: it
-- SHADOWS Authn.RequireStepUpForPrivilegedDefault, which 025_config_tables.sql now ships at 1, for every tenant in the
-- database -- because an explicit 0 in the nearest policy row beats the fallback by design.  A deployment that closed
-- G-30 by seeding the key and then ran this bootstrap has not closed it in practice, and the only honest place to say so
-- is here, on the run that writes the row.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN @PolicyId IS NULL THEN 3 WHEN @StepUpOff = 1 THEN 3 ELSE 4 END
     , CASE WHEN @PolicyId IS NULL THEN 'INFO' WHEN @StepUpOff = 1 THEN 'TIGHTEN' ELSE 'OK' END
     , N'RequireStepUpForPrivileged on the root policy (G-30)'
     , CASE WHEN @PolicyId IS NULL
            THEN N'No live root policy, so auth.uspSwitchProfile falls back to '
               + N'config.ApplicationSetting.Authn.RequireStepUpForPrivilegedDefault, which ships at 1.'
            WHEN @StepUpOff = 1
            THEN CONCAT (N'Policy id ', @PolicyId, N' has RequireStepUpForPrivileged = 0, written by this file because a '
                       , N'step-up is a FRESH SECOND FACTOR and this account has none -- a root policy demanding one '
                       , N'would refuse the first administrator the privileged profile they were created to hold. The '
                       , N'cost: this row is the nearest ancestor of every tenant, so it shadows '
                       , N'Authn.RequireStepUpForPrivilegedDefault = 1 everywhere, and NO privileged profile switch in '
                       , N'this deployment demands a factor. Set it to 1 on the same visit as RequireMfaForLocal, once '
                       , N'the administrator has a confirmed factor. Sections 7.2 and 12.3, G-30 and G-37.')
            ELSE CONCAT (N'Policy id ', @PolicyId, N' requires a step-up for privileged profile switches. Somebody has '
                       , N'been here since the bootstrap wrote 0, which is the intended end state.') END;

-- 8. The policy actually RESOLVES, which needs auth.TenantClosure to hold the root's self row.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN @Resolved IS NULL THEN 1 WHEN @Resolved = @PolicyId THEN 4 ELSE 2 END
     , CASE WHEN @Resolved IS NULL THEN 'UNRESOLVED' WHEN @Resolved = @PolicyId THEN 'OK' ELSE 'CHECK' END
     , N'auth.udfResolveAuthPolicy at the root'
     , CONCAT (N'Resolved policy id: ', COALESCE (CAST (@Resolved AS NVARCHAR (11)), N'NULL')
             , N', root policy id: ', COALESCE (CAST (@PolicyId AS NVARCHAR (11)), N'NULL')
             , N'. NULL means auth.TenantClosure has no self row for the root, so nothing inherits the policy and '
             , N'every sign-in falls back to MFA-required. Run auth.uspRebuildTenantClosure.');

-- 9. And exactly one platform administrator, which is what E-50082 will protect from now on.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 1 THEN 4 ELSE 2 END
     , CASE WHEN COUNT (*) = 1 THEN 'OK' ELSE 'CHECK' END
     , N'Live, active platform administrators in the database'
     , CONCAT (COUNT (*), N': ', COALESCE (STRING_AGG (u.UserName, N', ') WITHIN GROUP (ORDER BY u.UserName), N'(none)')
             , N'. One is expected immediately after the bootstrap, and one is also the number '
             , N'auth.uspRevokePlatformAdmin refuses to go below (E-50082). Create the second administrator through '
             , N'auth.uspCreateUser, auth.uspCreateProfile, auth.uspAssignRoleToProfile and auth.uspGrantPlatformAdmin before '
             , N'anybody depends on this deployment.')
  FROM auth.[User] AS u
 WHERE u.IsPlatformAdmin = 1 AND u.IsActive = 1 AND u.IsDeleted = 0;

IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
    PRINT '900_bootstrap_first_admin.sql: PROBLEMS found -- see the report below.';
ELSE
    PRINT '900_bootstrap_first_admin.sql: no problems found.';

-- Section 16.3 clause 6: print the account name.  The credential is never printed.
PRINT '';
PRINT '--------------------------------------------------------------------------------------------------------------';
PRINT 'The first administrator is  $(AdminUserName)  and it must change its password on first sign-in.';
PRINT 'Next, in this order:';
PRINT '  1. Sign in as $(AdminUserName) and change the password. The operator''s copy of it is now a liability.';
PRINT '  2. Enrol an MFA factor (auth.uspEnrolMfaFactor, auth.uspConfirmMfaFactor).';
PRINT '  3. Set RequireMfaForLocal = 1 AND RequireStepUpForPrivileged = 1 on the root authentication policy. Until then,';
PRINT '     NO tenant requires a factor to sign in and NO privileged profile switch requires a fresh one -- the root';
PRINT '     policy shadows Authn.RequireStepUpForPrivilegedDefault, which ships at 1 (G-30).';
PRINT '  4. Create the second administrator through the ordinary procedures, so this account stops being the only';
PRINT '     way into the deployment -- auth.uspRevokePlatformAdmin will not let you go back below one (E-50082).';
PRINT '  5. This file will refuse to run again (E-50080). That is deliberate and permanent.';
PRINT '--------------------------------------------------------------------------------------------------------------';
PRINT '';

SELECT Severity, Status, Item, Detail FROM @Report ORDER BY Severity, RowNo;
GO

