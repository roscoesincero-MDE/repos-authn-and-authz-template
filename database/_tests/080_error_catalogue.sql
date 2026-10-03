/***********************************************************************************************************************
Script:         080_error_catalogue.sql
Purpose:        Appendix B, executed.  Drives every error number the shipped modules can raise that a test can reach,
                asserts each one raises the number the appendix registers against it, and reports the remainder with a
                stated reason.  Task T-094.
Author:         rsincero
CreateDate:     2026-09-20
Run with:       sqlcmd -S MDE-55TT2J4 -E -d testTemplate -I -C -b -v DbName=testTemplate -v Seed=<unique text>
                        -i database/_tests/080_error_catalogue.sql

                -v Seed= must differ from every previous run of this file against the same database: the seed becomes
                two session token hashes, and a token is unique per live session.  A date and a time with no spaces is
                the convention the other files in this directory use -- UI-42, a -v value may not contain a space.

========================================================================================================================
WHAT THIS FILE IS FOR, AND WHY IT IS NOT A LIST OF NUMBERS

Appendix B of the design is a registry: a number, the procedure that raises it, and what it means.  A registry is a
promise, and nothing in it is a measurement.  This file is the measurement.  It does one thing per number -- it puts the
database into the state the appendix says raises it, calls the procedure the appendix names, and catches what comes out.
A probe passes when the number caught is the number promised.  It fails when the number is different, and it fails just
as loudly when NO error is raised, because a registered refusal that does not refuse is the worse of the two faults.

At the time this file was written the shipped modules carried 111 distinct numbers in the house `;THROW <n>, @Var, 1;`
style and logs.ExecutionLog had ever recorded 50 of them.  The 61 unmeasured numbers are the reason this file exists.

A COMMENT THAT MENTIONS A NUMBER IS NOT A THROW SITE, WHICH IS WHY THE HARVEST IS PICKY

Section 14 harvests throw sites out of sys.sql_modules by searching for N';THROW 5' and not for N'THROW 5'.  The looser
search finds the prose as well as the code -- this database's procedures explain their own refusals in comment blocks
that quote the numbers, and several of those blocks mention numbers the procedure does not raise.  Searching for the
leading semicolon finds the statement, because the leading semicolon is a house convention (it protects the THROW from
being parsed as a continuation of whatever preceded it) and no comment in this codebase writes one.

WHY A FAILED PROBE STOPS THE RUN, AND WHY THAT IS LOAD-BEARING

This file spans eight connections, and a table variable does not survive `:connect` (UI-42's neighbour: -v variables do,
local variables and table variables do not).  So each connection holds its own result table, prints it, and THROWs if
any probe in it disagreed with the appendix.  With sqlcmd -b that ends the run.

The consequence is what section 14 leans on.  The coverage report is the LAST thing in the file, and it can only run if
every connection before it finished without throwing, which means every probe before it passed.  So the report's list of
"numbers this file proved" needs no cross-connection plumbing: the list is written out as literals, and the fact that
the report is executing at all is the proof that the probes behind those literals passed.  Reorder the file and that
argument breaks, so do not move the report.

WHY THERE ARE EIGHT CONNECTIONS

    connection 1   db_owner, no session       sections 0-3    preflight, fixture, unauthenticated probes, session context
    connection 2   authenticating             section 4       errcat.admin signs in and switches profile; spent
    connection 3   errcat.admin               sections 5-9b   tenancy, users, profiles, roles, triggers, registration, flag
    connection 4   no session                 section 10     the three uspSwitchProfile refusals, on the admin's token
    connection 5   authenticating             section 11     errcat.limited signs in and switches profile; spent
    connection 6   errcat.limited             section 12     the two INV-05 refusals, E-50045, and E-50084
    connection 7   errcat.admin, no hat       section 12A    the step-up family, on a session wearing no profile
    connection 8   db_owner, no session       sections 13-14  the case-file probes under bypass, and the coverage report

Four separate reasons put those boundaries there, and none of them is tidiness.

One: a sign-in costs two connections.  auth.uspCompleteLogin leaves the session profileless and auth.uspSwitchProfile
deliberately does not re-establish the connection's context after committing the switch (140_auth_profile_procedures.sql
around line 1757, G-36/BL-057), so the connection that authenticates is SPENT -- the next procedure call on it raises
E-50022 naming the disagreement between what the connection believes and what the session row says.  Connections 2 and 5
exist to be spent.

Two: three of the probes are refusals from auth.uspSwitchProfile itself, and a connection already carrying a session
context cannot ask that procedure anything.  Connection 4 is a connection with no context, holding the administrator's
token, which is exactly what a second browser tab is.

Three: E-50040 and E-50041 are refusals of an actor who does NOT hold Authz.RoleAssign where they are pointing, and the
administrator of connection 3 holds it everywhere in the application.  No amount of argument juggling produces those two
numbers from an actor with root authority; only a second, deliberately smaller actor does.  errcat.limited is created by
connection 3 through the shipped procedures and holds ROLE_ADMIN at one deep tenant only.

Four: the step-up family needs a session that exists and is wearing NO hat, which is exactly what auth.uspCompleteLogin
leaves behind before anybody switches.  auth.uspElevateSession establishes the calling connection's context for the
session it is handed, so the first probe in section 12A that reaches a session pins connection 7 to it -- and connection
8 is pinned to the administrator's SWITCHED session by the first dbo call in section 13.  One connection cannot hold both
(UI-06), and a profileless session is also the only way to reach E-50032, so the two live apart.

WHAT IT DELIBERATELY DOES NOT PROBE, AND WHY EACH ONE IS A REASON AND NOT AN OMISSION

Every number this file does not drive is named in section 14 with its reason, carried as DATA in a Reason column rather
than left as a silent absence, so the gap is in the report and not in somebody's memory.  Four kinds:

  -- E-50080, E-50085, E-50086 and E-50087 belong to 900_bootstrap_first_admin.sql, and E-50210 and E-50211 to the
     validation block at the end of 135_audit_triggers.sql.  They are raised by SCRIPTS, not by modules, so they are not
     in sys.sql_modules and cannot be called.  Running the script is the test; the install manifest does that on every
     clean build.
  -- E-50141 is auth.uspRebuildTenantAccessPolicy's check on its own work.  Reaching it means rebuilding a policy that
     comes out wrong, which means breaking the procedure first.  A test that edits the thing it is testing measures the
     edit.
  -- E-50043 and E-50096 cannot be reached at all, and that is a finding rather than a limitation.  Both are shadowed by
     an earlier test that asks the same question in a wider way: see sections 8 and 5, and the reasons carried as data in
     section 14.
  -- The rest are numbers that need material this database does not hold: a federated identity, or a throttled client
     address inside its window.  A CONFIRMED SECOND FACTOR used to be on that list and is not any more: section 12A
     writes one, uses it and soft-deletes it again, because E-50128 and E-50129 cannot be reached without one, and a
     number nothing reaches is a number nothing protects.

WHAT IT LEAVES BEHIND, ON PURPOSE

errcat.admin, errcat.limited, their profiles and credentials, the ERRCAT_A/ERRCAT_B/ERRCAT_C tenants, one custom role
per shape the role probes need, and one case file.  NOT the second factor section 12A enrols: that one is put back,
because section 2e's E-50110 probe needs errcat.admin to have nothing confirmed, and a re-run has to find the database
the way the first run found it.  Re-running the file with a fresh -v Seed= finds all of it and
re-uses it; nothing here is cleaned up, because a fixture that deletes itself cannot be inspected after a failure and
because this directory's files are read as much as they are run.
***********************************************************************************************************************/

SET NOCOUNT ON;
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
GO

-- ======================================================================================================================
-- Connection 1.  db_owner, no session context.
-- ======================================================================================================================
USE [$(DbName)];
GO

PRINT '========================================================================================================';
PRINT '080_error_catalogue.sql -- connection 1: preflight, fixture, unauthenticated probes, session context';
PRINT '========================================================================================================';
GO

-- ----------------------------------------------------------------------------------------------------------------------
-- 0. Preflight.  What must already be true before a single probe means anything.
-- ----------------------------------------------------------------------------------------------------------------------
DECLARE @Failure NVARCHAR (2000)
      , @App     INT
      , @Root    INT
      , @Perms   INT
      , @Roles   INT
      , @Missing NVARCHAR (2000);

IF DB_NAME () <> N'$(DbName)'
BEGIN
    SET @Failure = CONCAT (N'This file must run in the database named by -v DbName=, and the connection is in ['
                         , DB_NAME (), N'] while -v DbName= says [$(DbName)].  Nothing was probed.');
    ;THROW 50000, @Failure, 1;
END;

SELECT @App = a.ApplicationId
  FROM auth.Application AS a
 WHERE a.ApplicationCode = N'TEMPLATE' AND a.IsDeleted = 0;

IF @App IS NULL
BEGIN
    SET @Failure = N'The TEMPLATE application is not present.  Run the install manifest through 115_seed_reference_data.sql first.';
    ;THROW 50000, @Failure, 1;
END;

SELECT @Root = t.TenantId
  FROM auth.Tenant AS t
 WHERE t.ApplicationId = @App AND t.TenantCode = N'ROOT' AND t.IsDeleted = 0;

IF @Root IS NULL
BEGIN
    SET @Failure = N'The TEMPLATE application has no live ROOT tenant.  115_seed_reference_data.sql creates it (BL-051).';
    ;THROW 50000, @Failure, 1;
END;

-- The authentication policy is not optional scenery.  auth.udfResolveAuthPolicy walks UP the closure for the nearest
-- row and 110_auth_authn_procedures.sql COALESCEs RequireMfaForLocal to 1 when it finds none, so a deployment with no
-- policy row anywhere above a tenant cannot sign anybody in locally -- E-50109, fail closed.  Sections 2 and 10 also
-- FLIP three of this row's columns and put them back, so its absence would not merely stop the sign-in, it would make
-- those probes silently no-ops.
IF NOT EXISTS (SELECT 1
                 FROM auth.TenantAuthenticationPolicy AS p
                WHERE p.TenantId = @Root AND p.IsDeleted = 0)
BEGIN
    SET @Failure = CONCAT (N'TEMPLATE/ROOT (TenantId ', @Root, N') has no auth.TenantAuthenticationPolicy row.  This '
                         , N'file signs two users in and temporarily flips AllowLocalPassword, RequireMfaForLocal and '
                         , N'RequireStepUpForPrivileged on that row; with no row there is nothing to flip and local '
                         , N'sign-in fails closed with E-50109.  900_bootstrap_first_admin.sql section 2a writes it -- '
                         , N'conditionally, and it is the only conditional write in that file -- so a database that '
                         , N'reaches this message is one where the bootstrap has never run against THIS root, which is '
                         , N'the state testTemplateS1 is in: its estate was loaded under a root of its own and '
                         , N'TEMPLATE/ROOT was left bare.  Deliberately NOT created here: this file writes its own '
                         , N'fixture but it does not provision somebody else''s root policy, because that row governs '
                         , N'every tenant that has none of its own (auth.udfResolveAuthPolicy returns the NEAREST '
                         , N'ancestor) and inventing one would change how unrelated tenants authenticate.  Run the '
                         , N'bootstrap, or run this file against the database it names in its header.');
    ;THROW 50000, @Failure, 1;
END;

SELECT @Perms = COUNT (*) FROM auth.Permission AS p WHERE p.ApplicationId = @App AND p.IsDeleted = 0;
SELECT @Roles = COUNT (*) FROM auth.Role       AS r WHERE r.ApplicationId = @App AND r.IsDeleted = 0;

IF @Perms < 35 OR @Roles < 14
BEGIN
    SET @Failure = CONCAT (N'TEMPLATE holds ', @Perms, N' permissions and ', @Roles, N' roles; Appendix A ships 35 and '
                         , N'16.2 ships 14.  The role and permission probes name codes from those two lists.');
    ;THROW 50000, @Failure, 1;
END;

-- Every module this file calls, in one list, so a missing one is named once rather than discovered nine sections later.
SELECT @Missing = STRING_AGG (CAST (v.ObjName AS NVARCHAR (200)), N', ') WITHIN GROUP (ORDER BY v.ObjName)
  FROM (VALUES (N'auth.uspSetSessionContext'), (N'auth.uspSwitchProfile'), (N'auth.uspGetLoginVerifier')
             , (N'auth.uspCompleteLogin'), (N'auth.uspVerifyMfa'), (N'auth.uspCreateTenant'), (N'auth.uspUpdateTenant')
             , (N'auth.uspDeactivateTenant'), (N'auth.uspGetTenantTree'), (N'auth.uspCreateUser')
             , (N'auth.uspUpdateUser'), (N'auth.uspDeactivateUser'), (N'auth.uspGetUser'), (N'auth.uspSearchUsers')
             , (N'auth.uspCreateProfile'), (N'auth.uspUpdateProfile'), (N'auth.uspDeactivateProfile')
             , (N'auth.uspDefineRole'), (N'auth.uspUpdateRole'), (N'auth.uspSetRolePermissions')
             , (N'auth.uspAssignRoleToProfile'), (N'auth.uspRevokeRoleFromProfile'), (N'auth.uspListAssignableRoles')
             , (N'auth.uspRebuildTenantAccessPolicy'), (N'auth.uspRebuildProfilePermissionScope')
             , (N'auth.uspRegisterOrganization'), (N'auth.uspApproveOrganization'), (N'auth.uspRegisterExternalUser')
             , (N'logs.uspRecordAuthorizationChange'), (N'logs.uspRecordAuthorizationDenial')
             , (N'logs.uspRecordDataChange'), (N'logs.uspRecordPermissionProbe'), (N'logs.uspPurgePermissionProbe')
             , (N'logs.uspReportPermissionProbe'), (N'util.uspSetObjectDescription'), (N'dbo.uspCreateCaseFile')
             , (N'dbo.uspUpdateCaseFile')) AS v (ObjName)
 WHERE OBJECT_ID (v.ObjName, N'P') IS NULL;

IF @Missing IS NOT NULL
BEGIN
    SET @Failure = CONCAT (N'These procedures are missing, so the probes that call them could not tell a refusal from '
                         , N'an absence: ', @Missing, N'.  Run the install manifest to completion first.');
    ;THROW 50000, @Failure, 1;
END;

PRINT CONCAT ('0.  Preflight passed.  TEMPLATE = ', @App, ', ROOT = ', @Root, ', ', @Perms, ' permissions, '
            , @Roles, ' roles, a policy row on ROOT, and all 37 called procedures present.');
GO

-- ----------------------------------------------------------------------------------------------------------------------
-- 1. The fixture for connection 1: errcat.admin, its three profiles, and ten role grants.
--
-- WHY THIS IS A DIRECT WRITE AND CANNOT BE ANYTHING ELSE
--
-- The same three reasons 070_variants_end_to_end.sql gives, in miniature.  There is no session to demand a permission
-- from before the first user exists; auth.uspCreateUser would need one.  A shipped procedure DOES write
-- auth.UserCredential now -- auth.uspSetPassword, since T-112 closed G-42 -- and it does not help here for the same
-- reason: it demands a live session and User.ResetCredential at the acting tenant, and this file is standing where
-- neither exists yet.  Section 6c uses it, at the one moment in the run when a session does exist, which is also how
-- E-50223 is reached.  Section 14 no longer reports the permission as demanded by nothing.
--
-- 900_bootstrap_first_admin.sql is the supported way to do this for a real deployment.  It is not used here because it
-- refuses when profiles already exist (E-50080) and this database has 20-odd of them.
-- ----------------------------------------------------------------------------------------------------------------------
DECLARE @App          INT = (SELECT a.ApplicationId FROM auth.Application AS a
                              WHERE a.ApplicationCode = N'TEMPLATE' AND a.IsDeleted = 0)
      , @Root         INT
      , @AdminUserId  INT
      , @AdminProfile INT
      , @Inactive     INT
      , @StepUp       INT
      , @Grants       INT
      , @Scopes       INT;

SELECT @Root = t.TenantId FROM auth.Tenant AS t
 WHERE t.ApplicationId = @App AND t.TenantCode = N'ROOT' AND t.IsDeleted = 0;

-- 1a.  The user.  IsPlatformAdmin = 1 because sections 5 to 9 call procedures that demand Platform permissions, and
-- because INV-09 requires BOTH the flag and a scope row -- there is no platform-admin bypass inside
-- auth.uspDemandPermission, so the flag alone would not be enough either.
IF NOT EXISTS (SELECT 1 FROM auth.[User] AS u WHERE u.UserName = N'errcat.admin' AND u.IsDeleted = 0)
    INSERT auth.[User] (UserName, DisplayName, Email, IsActive, IsPlatformAdmin, auditCreatedBy, auditModifiedBy)
    VALUES (N'errcat.admin', N'Error Catalogue Administrator', N'errcat.admin@template.example', 1, 1
          , N'080_error_catalogue', N'080_error_catalogue');

SELECT @AdminUserId = u.UserId FROM auth.[User] AS u WHERE u.UserName = N'errcat.admin' AND u.IsDeleted = 0;

-- Re-running this file after a section has lockeed the account out, or after section 6's E-50154 probe has left the
-- platform-admin flags mid-flip, must not leave the administrator unable to sign in.  Only touched when it is wrong.
UPDATE auth.[User]
   SET IsActive        = 1
     , IsPlatformAdmin = 1
     , IsLockedOut     = 0
     , LockoutEndUtc   = NULL
     , auditModifiedBy = N'080_error_catalogue'
 WHERE UserId = @AdminUserId
   AND (IsActive = 0 OR IsPlatformAdmin = 0 OR IsLockedOut = 1 OR LockoutEndUtc IS NOT NULL);

-- 1b.  The credential.  A syntactically valid Argon2id PHC string that verifies against nothing: the sign-in in
-- section 4 passes @PasswordVerified = 1 because verification is the application layer's job (D-04), so the database
-- never reads this value.  CK_auth_UserCredential_VerifierPhc wants 16 characters and a $...$ shape and that is all
-- this has to satisfy.  It must never be mistaken for a real hash, so it says so in the salt.
IF NOT EXISTS (SELECT 1 FROM auth.UserCredential AS c
                WHERE c.UserId = @AdminUserId AND c.CredentialType = 'Password' AND c.IsDeleted = 0)
    INSERT auth.UserCredential (UserId, CredentialType, VerifierPhc, LastChangedUtc, auditCreatedBy, auditModifiedBy)
    VALUES (@AdminUserId, 'Password'
          , N'$argon2id$v=19$m=65536,t=3,p=4$MDgwLWVycm9yLWNhdGFsb2d1ZQ$bm90LWEtcmVhbC12ZXJpZmllci1ldmVyLWFueXdoZXJl'
          , SYSUTCDATETIME (), N'080_error_catalogue', N'080_error_catalogue');

-- 1c.  Three profiles, and each one is a probe waiting to happen.
--
--   Error Catalogue Admin   the default hat, worn by connections 3 and 4
--   Errcat Inactive         IsActive = 0, so section 10 can prove E-50051 is about STATE
--   Errcat Step-Up          active and privileged, so section 10 can prove E-50052 with the policy flipped
--
-- INV-03 is "exactly one default", so the two extras carry IsDefault = 0 and the first carries 1.
IF NOT EXISTS (SELECT 1 FROM auth.UserProfile AS p
                WHERE p.UserId = @AdminUserId AND p.TenantId = @Root
                  AND p.ProfileName = N'Error Catalogue Admin' AND p.IsDeleted = 0)
    INSERT auth.UserProfile (UserId, TenantId, ProfileName, IsDefault, IsActive, auditCreatedBy, auditModifiedBy)
    VALUES (@AdminUserId, @Root, N'Error Catalogue Admin', 1, 1, N'080_error_catalogue', N'080_error_catalogue');

IF NOT EXISTS (SELECT 1 FROM auth.UserProfile AS p
                WHERE p.UserId = @AdminUserId AND p.TenantId = @Root
                  AND p.ProfileName = N'Errcat Inactive' AND p.IsDeleted = 0)
    INSERT auth.UserProfile (UserId, TenantId, ProfileName, IsDefault, IsActive, auditCreatedBy, auditModifiedBy)
    VALUES (@AdminUserId, @Root, N'Errcat Inactive', 0, 0, N'080_error_catalogue', N'080_error_catalogue');

IF NOT EXISTS (SELECT 1 FROM auth.UserProfile AS p
                WHERE p.UserId = @AdminUserId AND p.TenantId = @Root
                  AND p.ProfileName = N'Errcat Step-Up' AND p.IsDeleted = 0)
    INSERT auth.UserProfile (UserId, TenantId, ProfileName, IsDefault, IsActive, auditCreatedBy, auditModifiedBy)
    VALUES (@AdminUserId, @Root, N'Errcat Step-Up', 0, 1, N'080_error_catalogue', N'080_error_catalogue');

SELECT @AdminProfile = p.UserProfileId FROM auth.UserProfile AS p
 WHERE p.UserId = @AdminUserId AND p.ProfileName = N'Error Catalogue Admin' AND p.IsDeleted = 0;
SELECT @Inactive     = p.UserProfileId FROM auth.UserProfile AS p
 WHERE p.UserId = @AdminUserId AND p.ProfileName = N'Errcat Inactive'       AND p.IsDeleted = 0;
SELECT @StepUp       = p.UserProfileId FROM auth.UserProfile AS p
 WHERE p.UserId = @AdminUserId AND p.ProfileName = N'Errcat Step-Up'        AND p.IsDeleted = 0;

-- 1d.  Eleven role grants at ROOT, on the default hat.  Each one is here because a named section cannot run without it.
--
--   TENANT_ADMIN     section 5   Tenant.Create, Tenant.Update, Tenant.Deactivate
--   USER_ADMIN       section 6   User.Create, User.Update, User.Deactivate, User.Read
--   ROLE_ADMIN       section 7   Authz.Profile*, Authz.RoleAssign, Authz.RoleRevoke, Authz.RoleRead
--   ROLE_ARCHITECT   section 8   Authz.RoleDefine
--   PLATFORM_ADMIN   sections 5-13 Platform.RebuildSecurityCache, and Platform.BypassRowSecurity for section 13
--   CONTRIBUTOR      section 13  Data.Insert and Data.Read, to make the case files sections 13 needs
--   EDITOR           section 13  Data.Update, which G-38 makes mandatory for any profile that writes dbo rows at all
--   APPROVER         section 13  Data.Approve
--   DATA_STEWARD     section 13  Data.Restore, which no other seeded role carries -- E-50205 is otherwise E-50030
--   AUDITOR          section 9   the Audit.Read* verbs, so a denial is never mistaken for an empty log
--   OPERATOR         section 13  Data.Execute, which no other role above carries and which dbo.uspCloseApprovedCaseFiles
--                                demands before it validates its arguments -- so without this grant E-50208 would be
--                                E-50030, and the probe would be asserting the wrong number for the right reason
--
-- EDITOR is NOT optional and the reason is G-38: auth.tvfTenantUpdatePredicate is built from Data.Update alone, and a
-- BLOCK predicate is handed a row rather than a statement, so a profile holding Data.Approve without Data.Update meets
-- an uncatchable Msg 33504 instead of a number this file could assert.
INSERT auth.UserProfileRole (UserProfileId, RoleId, ScopeTenantId, ApplicationId, GrantedUtc
                           , auditCreatedBy, auditModifiedBy)
SELECT @AdminProfile, r.RoleId, @Root, @App, SYSUTCDATETIME (), N'080_error_catalogue', N'080_error_catalogue'
  FROM auth.Role AS r
 WHERE r.ApplicationId = @App
   AND r.IsDeleted     = 0
   AND r.RoleCode IN (N'TENANT_ADMIN', N'USER_ADMIN', N'ROLE_ADMIN', N'ROLE_ARCHITECT', N'PLATFORM_ADMIN'
                    , N'CONTRIBUTOR', N'EDITOR', N'APPROVER', N'DATA_STEWARD', N'AUDITOR', N'OPERATOR')
   AND NOT EXISTS (SELECT 1
                     FROM auth.UserProfileRole AS upr
                    WHERE upr.UserProfileId = @AdminProfile
                      AND upr.RoleId        = r.RoleId
                      AND upr.ScopeTenantId = @Root
                      AND upr.IsDeleted     = 0);

-- USER_ADMIN on the step-up hat, and nothing else.  Section 10's E-50052 fires only for a target profile the procedure
-- calls privileged -- one holding at least one Authz, User, Tenant or Platform permission -- so this grant is the whole
-- point of that profile and one role is enough to earn the adjective.
INSERT auth.UserProfileRole (UserProfileId, RoleId, ScopeTenantId, ApplicationId, GrantedUtc
                           , auditCreatedBy, auditModifiedBy)
SELECT @StepUp, r.RoleId, @Root, @App, SYSUTCDATETIME (), N'080_error_catalogue', N'080_error_catalogue'
  FROM auth.Role AS r
 WHERE r.ApplicationId = @App AND r.IsDeleted = 0 AND r.RoleCode = N'USER_ADMIN'
   AND NOT EXISTS (SELECT 1 FROM auth.UserProfileRole AS upr
                    WHERE upr.UserProfileId = @StepUp AND upr.RoleId = r.RoleId AND upr.IsDeleted = 0);

EXEC auth.uspRebuildProfilePermissionScope @UserProfileId = @AdminProfile;
EXEC auth.uspRebuildProfilePermissionScope @UserProfileId = @StepUp;

SELECT @Grants = COUNT (*) FROM auth.UserProfileRole AS upr
 WHERE upr.UserProfileId = @AdminProfile AND upr.IsDeleted = 0;
SELECT @Scopes = COUNT (*) FROM auth.ProfilePermissionScope AS pps
 WHERE pps.UserProfileId = @AdminProfile AND pps.IsDeleted = 0;

IF @Grants < 11 OR @Scopes = 0
BEGIN
    DECLARE @FixtureFailure NVARCHAR (2000) =
        CONCAT (N'The fixture did not take: errcat.admin''s default profile holds ', @Grants, N' role grants and '
              , @Scopes, N' expanded scope rows, and the sections below need eleven grants and a non-empty expansion.  '
              , N'auth.uspRebuildProfilePermissionScope is the procedure that fills the second number from the first.');
    ;THROW 50000, @FixtureFailure, 1;
END;

PRINT CONCAT ('1.  Fixture ready.  errcat.admin = UserId ', @AdminUserId, ', default profile ', @AdminProfile
            , ', inactive profile ', @Inactive, ', step-up profile ', @StepUp, ', ', @Grants, ' role grants, '
            , @Scopes, ' expanded scope rows.');
GO

-- ----------------------------------------------------------------------------------------------------------------------
-- 2. The probes that need no session at all: the unauthenticated entry points, the logging writers, and the two
--    deploy-time procedures.
--
-- WHY A FLIP-AND-PUT-BACK IS USED THREE TIMES HERE, AND WHY IT IS NOT CHEATING
--
-- E-50103 means "the resolved policy does not permit local password sign-in" and E-50110 means "no confirmed second
-- factor is enrolled".  Neither is reachable against a deployment configured the way this one is: TEMPLATE/ROOT permits
-- local passwords and demands no second factor, which is what makes every other sign-in in this directory work.  So the
-- probe changes the policy column the number is about, calls the procedure, and changes it back -- and the put-back sits
-- AFTER the CATCH rather than inside the TRY, so a probe that fails for an unexpected reason still leaves the policy the
-- way it found it.  The alternative is a second tenant with a second policy row, which measures the second tenant.
-- ----------------------------------------------------------------------------------------------------------------------
DECLARE @R TABLE (RowNo  INT IDENTITY (1,1) PRIMARY KEY
                , Want   INT            NOT NULL
                , Case_  NVARCHAR (130) NOT NULL
                , Got    INT            NULL
                , Msg    NVARCHAR (300) NULL);

DECLARE @App      INT = (SELECT a.ApplicationId FROM auth.Application AS a
                          WHERE a.ApplicationCode = N'TEMPLATE' AND a.IsDeleted = 0)
      , @Root     INT
      , @AdminId  INT = (SELECT u.UserId FROM auth.[User] AS u
                          WHERE u.UserName = N'errcat.admin' AND u.IsDeleted = 0)
      , @Attempt  BIGINT
      , @Phc      NVARCHAR (400)
      , @Mfa      BIT
      , @Session  BIGINT
      , @OutUser  INT
      , @Must     BIT
      , @AbsExp   DATETIME2 (7)
      , @IdleExp  DATETIME2 (7)
      , @Satisfy  BIT
      , @RegId    INT
      , @NewUser  INT
      , @NewProf  INT
      , @ChangeId BIGINT
      , @DenialId BIGINT
      , @ChgLogId BIGINT
      , @ProbeId  BIGINT
      , @Expired  INT
      , @Remain   INT
      , @Bound    INT
      , @Skipped  INT
      , @Fail     NVARCHAR (2000)
      -- EXEC will not take an expression for a parameter: written inline, HASHBYTES () raises Msg 102 and the message
      -- names the function rather than the call it belongs to.  Two sessions are opened here that nothing ever uses --
      -- the tokens exist so the refusals of E-50106 and E-50107 are refusals of a real exchange.
      , @Tok106   VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)-never-used-106')
      , @Tok107   VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)-never-used-107')
      -- G-18's probe needs a token that names no session at all: E-50230 is raised BEFORE the session is resolved, and a
      -- real token would leave that order unproved.
      , @TokNone  VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)-no-such-session')
      -- The three put-back holders the G-21 and G-24 probes need.  Each one is read before the flip rather than assumed,
      -- because this file has to leave a deployment configured the way it found it and neither value is the same in every
      -- deployment -- TEMPLATE/ROOT ships with AllowFederated = 1, and the threshold is an operator's number.
      , @FedWas   BIT
      , @Threshold NVARCHAR (100)
      , @Arrivals  INT;

SELECT @Root = t.TenantId FROM auth.Tenant AS t
 WHERE t.ApplicationId = @App AND t.TenantCode = N'ROOT' AND t.IsDeleted = 0;

-- 2a.  E-50000, the unregistered number.  Appendix B does not list it and should not: it is the house number for "this
-- argument is nonsense and no registered number describes it", and every _tests file in this directory raises it too.
BEGIN TRY
    EXEC util.uspSetObjectDescription @SchemaName = N'auth', @ObjectType = N'FROBNICATE', @ObjectName = N'Tenant'
                                    , @Description = N'This call must not succeed.';
    INSERT @R (Want, Case_, Got, Msg) VALUES (50000, N'uspSetObjectDescription, @ObjectType is not one of the five', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50000, N'uspSetObjectDescription, @ObjectType is not one of the five', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- 2b.  The sign-in round trip 1 refusals.  E-50100 before any lookup, so it cannot be an enumeration signal.
BEGIN TRY
    EXEC auth.uspGetLoginVerifier @ApplicationCode = N'TEMPLATE', @UserName = N'   '
                                , @ClientAddress = N'203.0.113.80', @TenantCode = N'ROOT', @UserAgent = N'080'
                                , @LoginAttemptId = @Attempt OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50100, N'uspGetLoginVerifier, @UserName is whitespace', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50100, N'uspGetLoginVerifier, @UserName is whitespace', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

BEGIN TRY
    EXEC auth.uspGetLoginVerifier @ApplicationCode = N'NO_SUCH_APP_080', @UserName = N'errcat.admin'
                                , @ClientAddress = N'203.0.113.80', @TenantCode = N'ROOT', @UserAgent = N'080'
                                , @LoginAttemptId = @Attempt OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50101, N'uspGetLoginVerifier, unknown application code', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50101, N'uspGetLoginVerifier, unknown application code', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

BEGIN TRY
    EXEC auth.uspGetLoginVerifier @ApplicationCode = N'TEMPLATE', @UserName = N'errcat.admin'
                                , @ClientAddress = N'203.0.113.80', @TenantCode = N'NO_SUCH_TENANT_080', @UserAgent = N'080'
                                , @LoginAttemptId = @Attempt OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50102, N'uspGetLoginVerifier, @TenantCode not in this application', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50102, N'uspGetLoginVerifier, @TenantCode not in this application', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- 2c.  E-50103: the flip.  AllowLocalPassword = 0 is a tenant saying "federated only".
--
-- PreferredMethod moves with it, and not as a courtesy: CK_auth_TenantAuthenticationPolicy_PreferredIsAllowed refuses a
-- row that prefers a method it does not allow, so withdrawing local passwords from a tenant that prefers them is a
-- two-column change or it is Msg 547.  That constraint is the table making a design point -- a policy cannot recommend a
-- door it has locked -- and a probe that tried to flip one column would have learned it the hard way, as this one did.
UPDATE auth.TenantAuthenticationPolicy
   SET AllowLocalPassword = 0
     , AllowFederated     = 1
     , PreferredMethod    = 'Federated'
     , auditModifiedBy    = N'080_error_catalogue probe 50103'
 WHERE TenantId = @Root AND IsDeleted = 0;

BEGIN TRY
    EXEC auth.uspGetLoginVerifier @ApplicationCode = N'TEMPLATE', @UserName = N'errcat.admin'
                                , @ClientAddress = N'203.0.113.80', @TenantCode = N'ROOT', @UserAgent = N'080'
                                , @LoginAttemptId = @Attempt OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50103, N'uspGetLoginVerifier, policy forbids local password', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50103, N'uspGetLoginVerifier, policy forbids local password', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

UPDATE auth.TenantAuthenticationPolicy
   SET AllowLocalPassword = 1
     , PreferredMethod    = 'LocalPassword'
     , auditModifiedBy    = N'080_error_catalogue restore 50103'
 WHERE TenantId = @Root AND IsDeleted = 0;

-- 2d.  Round trip 2.  E-50105 is the number a replayed or expired exchange gets; a bigint nobody issued is the cheapest
-- version of "no such exchange".
BEGIN TRY
    EXEC auth.uspCompleteLogin @LoginAttemptId = 9999999999, @PasswordVerified = 1
                             , @SessionTokenHash = 0x00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
                             , @IsBypassRoute = 0, @UserSessionId = @Session OUTPUT, @UserId = @OutUser OUTPUT
                             , @MustChangePassword = @Must OUTPUT, @AbsoluteExpiryUtc = @AbsExp OUTPUT
                             , @IdleExpiryUtc = @IdleExp OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50105, N'uspCompleteLogin, no such sign-in exchange', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50105, N'uspCompleteLogin, no such sign-in exchange', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- E-50106.  The application layer says "the password did not verify" by passing 0, and the database refuses to open a
-- session on an exchange whose credential was never proved.  A real exchange is needed, so one is opened first.
EXEC auth.uspGetLoginVerifier @ApplicationCode = N'TEMPLATE', @UserName = N'errcat.admin'
                            , @ClientAddress = N'203.0.113.81', @TenantCode = N'ROOT', @UserAgent = N'080'
                            , @LoginAttemptId = @Attempt OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;

BEGIN TRY
    EXEC auth.uspCompleteLogin @LoginAttemptId = @Attempt, @PasswordVerified = 0
                             , @SessionTokenHash = @Tok106
                             , @IsBypassRoute = 0, @UserSessionId = @Session OUTPUT, @UserId = @OutUser OUTPUT
                             , @MustChangePassword = @Must OUTPUT, @AbsoluteExpiryUtc = @AbsExp OUTPUT
                             , @IdleExpiryUtc = @IdleExp OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50106, N'uspCompleteLogin, @PasswordVerified = 0', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50106, N'uspCompleteLogin, @PasswordVerified = 0', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- The probe above recorded a failed sign-in, and Authn.LockoutThreshold is 5 inside Authn.LockoutWindowMinutes of 15.
-- Two failures per run and a handful of runs inside a quarter of an hour is all it takes, and the next probe would then
-- catch E-50115 ("the account cannot sign in") instead of the number it is asking about.  That is not a bug in either
-- procedure: E-50115 is raised AFTER the credential is verified and outranks everything about the route.  It is a bug in
-- a test that probes failures without expecting to be locked out by them, which is what this file did first.
UPDATE auth.[User]
   SET IsLockedOut     = 0
     , LockoutEndUtc   = NULL
     , auditModifiedBy = N'080_error_catalogue clearing the lockout probe 50106 earned'
 WHERE UserId = @AdminId
   AND (IsLockedOut = 1 OR LockoutEndUtc IS NOT NULL);

-- E-50107, INV-08.  The bypass route is the maintenance door and it is barred to anybody who has not satisfied a second
-- factor in this exchange, platform administrator or not -- which is why this probe is ordered before any thought of
-- E-50108: with no factor satisfied, 50107 is the number, and 50108 is only reachable once one has been.
EXEC auth.uspGetLoginVerifier @ApplicationCode = N'TEMPLATE', @UserName = N'errcat.admin'
                            , @ClientAddress = N'203.0.113.82', @TenantCode = N'ROOT', @UserAgent = N'080'
                            , @LoginAttemptId = @Attempt OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;

BEGIN TRY
    EXEC auth.uspCompleteLogin @LoginAttemptId = @Attempt, @PasswordVerified = 1
                             , @SessionTokenHash = @Tok107
                             , @IsBypassRoute = 1, @UserSessionId = @Session OUTPUT, @UserId = @OutUser OUTPUT
                             , @MustChangePassword = @Must OUTPUT, @AbsoluteExpiryUtc = @AbsExp OUTPUT
                             , @IdleExpiryUtc = @IdleExp OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50107, N'uspCompleteLogin, bypass route with no second factor', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50107, N'uspCompleteLogin, bypass route with no second factor', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- 2e.  E-50110: the second flip.  With RequireMfaForLocal = 1 the verifier call returns @RequiresMfa = 1 and leaves the
-- exchange open for auth.uspVerifyMfa, which then finds that errcat.admin has enrolled nothing.
UPDATE auth.TenantAuthenticationPolicy
   SET RequireMfaForLocal = 1, auditModifiedBy = N'080_error_catalogue probe 50110'
 WHERE TenantId = @Root AND IsDeleted = 0;

BEGIN TRY
    EXEC auth.uspGetLoginVerifier @ApplicationCode = N'TEMPLATE', @UserName = N'errcat.admin'
                                , @ClientAddress = N'203.0.113.83', @TenantCode = N'ROOT', @UserAgent = N'080'
                                , @LoginAttemptId = @Attempt OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;

    EXEC auth.uspVerifyMfa @LoginAttemptId = @Attempt, @TimeStep = 1, @FactorType = 'Totp'
                         , @MfaSatisfied = @Satisfy OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50110, N'uspVerifyMfa, no confirmed factor enrolled', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50110, N'uspVerifyMfa, no confirmed factor enrolled', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

UPDATE auth.TenantAuthenticationPolicy
   SET RequireMfaForLocal = 0, auditModifiedBy = N'080_error_catalogue restore 50110'
 WHERE TenantId = @Root AND IsDeleted = 0;

-- Still 2e's idiom, on the other policy column, and one flip buys two numbers: E-50104 needs federation OFF and E-50124
-- needs it on.  TEMPLATE/ROOT ships permitting both methods, so the value is saved into @FedWas first and put back after
-- the second probe -- and it is SAVED rather than assumed, because a deployment that had already switched federation off
-- would otherwise be switched on by this file and left that way.
SELECT @FedWas = p.AllowFederated FROM auth.TenantAuthenticationPolicy AS p
 WHERE p.TenantId = @Root AND p.IsDeleted = 0;

UPDATE auth.TenantAuthenticationPolicy
   SET AllowFederated = 0, auditModifiedBy = N'080_error_catalogue probe 50104'
 WHERE TenantId = @Root AND IsDeleted = 0;

BEGIN TRY
    EXEC auth.uspBeginSsoLogin @ApplicationCode = N'TEMPLATE', @ClientAddress = N'203.0.113.85', @TenantCode = N'ROOT'
                             , @Issuer = N'https://issuer.errcat.example/v2.0', @UserAgent = N'080'
                             , @LoginAttemptId = @Attempt OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50104, N'uspBeginSsoLogin, the resolved policy forbids federation', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50104, N'uspBeginSsoLogin, the resolved policy forbids federation', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- E-50124, G-21.  Federation on, and a trusted-issuer list of exactly one row at ROOT -- the NEAREST ancestor holding a
-- list owns it whole, and a tenant is its own ancestor at depth 0, so a row at ROOT is the list every tenant in this
-- application inherits.  The exchange then offers a DIFFERENT issuer and is refused before the redirect rather than
-- after it, which is the whole of the gap: AllowFederated = 1 says federation is permitted and says nothing about WITH
-- WHOM.  Both probes use one dedicated address because a refused exchange writes no auth.LoginAttempt row and therefore
-- spends nothing from the per-address sign-in throttle -- and an address of their own keeps it that way if that changes.
UPDATE auth.TenantAuthenticationPolicy
   SET AllowFederated = 1, auditModifiedBy = N'080_error_catalogue probe 50124'
 WHERE TenantId = @Root AND IsDeleted = 0;

INSERT auth.TenantTrustedIssuer (TenantId, Issuer, IssuerNote, auditCreatedBy, auditModifiedBy)
SELECT @Root, N'https://issuer.errcat.example/v2.0'
     , N'Written by _tests/080_error_catalogue.sql for the E-50124 probe and soft-deleted again four statements later. '
     + N'If this row is live, that file did not finish.'
     , N'080_error_catalogue probe 50124', N'080_error_catalogue probe 50124'
 WHERE NOT EXISTS (SELECT 1 FROM auth.TenantTrustedIssuer AS ti
                    WHERE ti.TenantId  = @Root
                      AND ti.Issuer    = N'https://issuer.errcat.example/v2.0'
                      AND ti.IsDeleted = 0);

BEGIN TRY
    EXEC auth.uspBeginSsoLogin @ApplicationCode = N'TEMPLATE', @ClientAddress = N'203.0.113.85', @TenantCode = N'ROOT'
                             , @Issuer = N'https://issuer.somebody-elses.example/v2.0', @UserAgent = N'080'
                             , @LoginAttemptId = @Attempt OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50124, N'uspBeginSsoLogin, the issuer is not on the tenant''s list', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50124, N'uspBeginSsoLogin, the issuer is not on the tenant''s list', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- The list goes before the flag goes back, and both are outside the TRY: a file that left the row behind would leave
-- every federated sign-in in this deployment checking a list nobody configured.
UPDATE auth.TenantTrustedIssuer
   SET IsDeleted           = 1
     , auditDeletedBy      = N'080_error_catalogue restore 50124'
     , auditDeletedDateUtc = SYSUTCDATETIME ()
     , auditModifiedBy     = N'080_error_catalogue restore 50124'
 WHERE TenantId  = @Root
   AND Issuer    = N'https://issuer.errcat.example/v2.0'
   AND IsDeleted = 0;

UPDATE auth.TenantAuthenticationPolicy
   SET AllowFederated = @FedWas, auditModifiedBy = N'080_error_catalogue restore 50104 and 50124'
 WHERE TenantId = @Root AND IsDeleted = 0;

-- 2f.  Self-service registration, which takes no session by design -- §16.4's front door.
--
-- G-24 PUT A RE-RUN BUDGET ON THIS SECTION, AND THIS IS WHERE IT IS PAID
--
-- Every arrival at either registration door is now recorded in auth.RegistrationAttempt and counted per address over
-- Registration.ThrottleWindowMinutes -- accepted or refused, because a refusal that cost nothing is a free retry.  This
-- file spends four arrivals from 203.0.113.84 below, three from 203.0.113.86 in the E-50068 probe and one from
-- 203.0.113.91 in section 9: eight, against a shipped threshold of ten over sixty minutes.  So a second run inside the
-- hour would meet E-50068 in probes that are not testing for it, and the three below would report the wrong number for a
-- reason that has nothing to do with them.  The file therefore returns its own allowance first, and section 9's address
-- is returned here rather than there because a cleanup has to precede the first arrival.
--
-- The rows are soft-deleted rather than removed: the table is audited like every other, and the count behind E-50068
-- filters IsDeleted = 0, which is what makes returning the allowance possible at all.
UPDATE auth.RegistrationAttempt
   SET IsDeleted           = 1
     , auditDeletedBy      = N'080_error_catalogue returning its own G-24 allowance'
     , auditDeletedDateUtc = SYSUTCDATETIME ()
     , auditModifiedBy     = N'080_error_catalogue'
 WHERE ClientAddress IN (N'203.0.113.84', N'203.0.113.86', N'203.0.113.91')
   AND IsDeleted = 0;
BEGIN TRY
    EXEC auth.uspRegisterOrganization @ApplicationCode = N'TEMPLATE', @ProposedTenantCode = N'ERRCAT_ORG'
                                    , @OrganizationName = N'   ', @ContactEmail = N'contact@errcat.example'
                                    , @ContactName = N'A Contact', @ClientAddress = N'203.0.113.84'
                                    , @OrganizationRegistrationId = @RegId OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50062, N'uspRegisterOrganization, @OrganizationName is whitespace', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50062, N'uspRegisterOrganization, @OrganizationName is whitespace', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- E-50063 needs a Pending registration for the proposed code to already exist.  On a first run this call creates it and
-- the probe below is the second call; on a re-run the row is already there and this call is itself the duplicate, which
-- is why its outcome is deliberately not recorded.  Either way the state the probe needs is the state that follows.
BEGIN TRY
    EXEC auth.uspRegisterOrganization @ApplicationCode = N'TEMPLATE', @ProposedTenantCode = N'ERRCAT_ORG'
                                    , @OrganizationName = N'Errcat Organization', @ContactEmail = N'contact@errcat.example'
                                    , @ContactName = N'A Contact', @ClientAddress = N'203.0.113.84'
                                    , @OrganizationRegistrationId = @RegId OUTPUT;
END TRY
BEGIN CATCH
    SET @RegId = NULL;
END CATCH

BEGIN TRY
    EXEC auth.uspRegisterOrganization @ApplicationCode = N'TEMPLATE', @ProposedTenantCode = N'ERRCAT_ORG'
                                    , @OrganizationName = N'Errcat Organization Again'
                                    , @ContactEmail = N'other@errcat.example', @ContactName = N'Another Contact'
                                    , @ClientAddress = N'203.0.113.84', @OrganizationRegistrationId = @RegId OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50063, N'uspRegisterOrganization, a Pending row already holds that code', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50063, N'uspRegisterOrganization, a Pending row already holds that code', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

BEGIN TRY
    EXEC auth.uspRegisterExternalUser @OrganizationRegistrationId = 999999, @UserName = N'errcat.nobody'
                                    , @DisplayName = N'Nobody', @Email = N'nobody@errcat.example'
                                    , @ClientAddress = N'203.0.113.84', @NewUserId = @NewUser OUTPUT
                                    , @NewUserProfileId = @NewProf OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50064, N'uspRegisterExternalUser, no such registration', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50064, N'uspRegisterExternalUser, no such registration', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- G-24's own refusal, E-50068, and it is the only probe in this file that flips a SETTING rather than a policy column.
-- Three arrivals measure the same rule as eleven: the threshold is what the count is compared with, so lowering it to two
-- and spending two arrivals leaves the third call over the line.  Both arrivals spent below are deliberately REFUSALS --
-- the whitespace organization name of the E-50062 probe again -- because a refused arrival counts, which is the property
-- G-24 exists for and the one an implementation is most likely to get wrong.  An accepted arrival would also leave a
-- registration row to clean up, and the count is the thing being tested, not the queue.
SELECT @Threshold = s.SettingValue FROM config.ApplicationSetting AS s
 WHERE s.SettingKey = N'Registration.ThrottleThreshold' AND s.IsDeleted = 0;

UPDATE config.ApplicationSetting
   SET SettingValue = N'2', auditModifiedBy = N'080_error_catalogue probe 50068'
 WHERE SettingKey = N'Registration.ThrottleThreshold' AND IsDeleted = 0;

DECLARE @Spend INT = 1;

WHILE @Spend <= 2
BEGIN
    BEGIN TRY
        EXEC auth.uspRegisterOrganization @ApplicationCode = N'TEMPLATE', @ProposedTenantCode = N'ERRCAT_THROTTLE'
                                        , @OrganizationName = N'   ', @ContactEmail = N'throttle@errcat.example'
                                        , @ContactName = N'A Contact', @ClientAddress = N'203.0.113.86'
                                        , @OrganizationRegistrationId = @RegId OUTPUT;
    END TRY
    BEGIN CATCH
        -- The outcome of an arrival being spent on purpose is not recorded: E-50062 is already probed above, and
        -- recording it twice would count one refusal as two kinds of evidence.
        SET @RegId = NULL;
    END CATCH;

    SET @Spend += 1;
END;

BEGIN TRY
    EXEC auth.uspRegisterOrganization @ApplicationCode = N'TEMPLATE', @ProposedTenantCode = N'ERRCAT_THROTTLE'
                                    , @OrganizationName = N'Errcat Throttle Organization'
                                    , @ContactEmail = N'throttle@errcat.example', @ContactName = N'A Contact'
                                    , @ClientAddress = N'203.0.113.86'
                                    , @OrganizationRegistrationId = @RegId OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50068, N'uspRegisterOrganization, the address is over the threshold', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50068, N'uspRegisterOrganization, the address is over the threshold', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- The count is read BEFORE the rows go, and it is asserted rather than printed: three arrivals from one address is the
-- evidence that a refusal was recorded, and a probe that passed while recording nothing would be a throttle that only
-- counts successful requests -- which is the one thing G-24 says it must not be.  The setting and the rows are put back
-- first, outside the TRY, so the assertion cannot leave a deployment throttled at two.
SELECT @Arrivals = COUNT (*) FROM auth.RegistrationAttempt AS ra
 WHERE ra.ClientAddress = N'203.0.113.86' AND ra.IsDeleted = 0;

UPDATE config.ApplicationSetting
   SET SettingValue = @Threshold, auditModifiedBy = N'080_error_catalogue restore 50068'
 WHERE SettingKey = N'Registration.ThrottleThreshold' AND IsDeleted = 0;

UPDATE auth.RegistrationAttempt
   SET IsDeleted           = 1
     , auditDeletedBy      = N'080_error_catalogue restore 50068'
     , auditDeletedDateUtc = SYSUTCDATETIME ()
     , auditModifiedBy     = N'080_error_catalogue restore 50068'
 WHERE ClientAddress = N'203.0.113.86' AND IsDeleted = 0;

-- Belt and braces: if the throttle did NOT refuse, the third call created a registration, and leaving it would make the
-- next run's probe meet E-50063 instead of E-50068.
UPDATE auth.OrganizationRegistration
   SET IsDeleted           = 1
     , auditDeletedBy      = N'080_error_catalogue restore 50068'
     , auditDeletedDateUtc = SYSUTCDATETIME ()
     , auditModifiedBy     = N'080_error_catalogue restore 50068'
 WHERE ProposedTenantCode = N'ERRCAT_THROTTLE' AND IsDeleted = 0;

IF @Arrivals <> 3
BEGIN
    SET @Fail = CONCAT (N'The E-50068 probe spent three arrivals from 203.0.113.86 and auth.RegistrationAttempt holds '
                      , @Arrivals, N' of them. Either a refused arrival is no longer being recorded -- which is the '
                      , N'failure G-24 is most exposed to, because the throttle would then count only the requests that '
                      , N'succeeded -- or a previous run left rows behind and the count above is not this run''s. The '
                      , N'threshold, the attempt rows and any registration have been put back either way.');
    ;THROW 50000, @Fail, 1;
END;

-- 2g.  The logging writers.  Every number here means "the calling procedure has a defect", which is exactly why they
-- are worth probing: nothing else in the system will ever raise them on purpose, so a regression here is silent.
BEGIN TRY
    EXEC logs.uspRecordAuthorizationChange @ChangeType = 'Frobnicated', @TargetUserId = @AdminId
                                         , @AuthorizationChangeId = @ChangeId OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50130, N'uspRecordAuthorizationChange, @ChangeType outside the vocabulary', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50130, N'uspRecordAuthorizationChange, @ChangeType outside the vocabulary', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

BEGIN TRY
    EXEC logs.uspRecordAuthorizationChange @ChangeType = 'RoleGranted', @AuthorizationChangeId = @ChangeId OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50131, N'uspRecordAuthorizationChange, names no user, profile or role', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50131, N'uspRecordAuthorizationChange, names no user, profile or role', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

BEGIN TRY
    EXEC logs.uspRecordAuthorizationChange @ChangeType = 'RoleGranted', @TargetUserId = @AdminId
                                         , @DetailJson = N'{"this":is not json'
                                         , @AuthorizationChangeId = @ChangeId OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50132, N'uspRecordAuthorizationChange, @DetailJson is a fragment', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50132, N'uspRecordAuthorizationChange, @DetailJson is a fragment', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

BEGIN TRY
    EXEC logs.uspRecordAuthorizationDenial @PermissionCode = N'  ', @TenantId = @Root
                                         , @AuthorizationDenialId = @DenialId OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50133, N'uspRecordAuthorizationDenial, @PermissionCode is whitespace', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50133, N'uspRecordAuthorizationDenial, @PermissionCode is whitespace', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

BEGIN TRY
    EXEC logs.uspRecordDataChange @SchemaName = N'dbo', @TableName = N'', @Operation = 'Update'
                                , @KeyJson = N'{"CaseFileId":1}', @DataChangeLogId = @ChgLogId OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50134, N'uspRecordDataChange, @TableName is empty', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50134, N'uspRecordDataChange, @TableName is empty', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

BEGIN TRY
    EXEC logs.uspRecordDataChange @SchemaName = N'dbo', @TableName = N'CaseFile', @Operation = 'Frobnicate'
                                , @KeyJson = N'{"CaseFileId":1}', @DataChangeLogId = @ChgLogId OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50135, N'uspRecordDataChange, @Operation outside the four', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50135, N'uspRecordDataChange, @Operation outside the four', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- 2h.  The permission-probe instrumentation of 175_perf_instrumentation.sql.  Its four validations are the ones that
-- keep a performance table from being poisoned by a measurement that did not happen.
BEGIN TRY
    EXEC logs.uspRecordPermissionProbe @PermissionCode = N'', @BurstCount = 100, @TotalMicroseconds = 1000
                                     , @Allowed = 1, @PermissionProbeId = @ProbeId OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50190, N'uspRecordPermissionProbe, @PermissionCode is empty', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50190, N'uspRecordPermissionProbe, @PermissionCode is empty', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

BEGIN TRY
    EXEC logs.uspRecordPermissionProbe @PermissionCode = N'Data.Read', @BurstCount = 1, @TotalMicroseconds = 1000
                                     , @Allowed = 1, @PermissionProbeId = @ProbeId OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50191, N'uspRecordPermissionProbe, @BurstCount below the clock resolution', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50191, N'uspRecordPermissionProbe, @BurstCount below the clock resolution', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

BEGIN TRY
    EXEC logs.uspRecordPermissionProbe @PermissionCode = N'Data.Read', @BurstCount = 100, @TotalMicroseconds = -5
                                     , @Allowed = 1, @PermissionProbeId = @ProbeId OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50192, N'uspRecordPermissionProbe, the clock ran backwards', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50192, N'uspRecordPermissionProbe, the clock ran backwards', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

BEGIN TRY
    EXEC logs.uspRecordPermissionProbe @PermissionCode = N'Data.Read', @BurstCount = 100, @TotalMicroseconds = 1000
                                     , @Allowed = 1, @DetailJson = N'not json at all'
                                     , @PermissionProbeId = @ProbeId OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50193, N'uspRecordPermissionProbe, @DetailJson is not JSON', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50193, N'uspRecordPermissionProbe, @DetailJson is not JSON', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- E-50194 is the number that refuses to interpret a zero.  Nobody types -1 by accident, so -1 is the deliberate
-- "expire everything" and 0 is an unset variable.
BEGIN TRY
    EXEC logs.uspPurgePermissionProbe @RetentionDays = 0, @BatchSize = 1000
                                    , @RowsExpired = @Expired OUTPUT, @RowsRemaining = @Remain OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50194, N'uspPurgePermissionProbe, @RetentionDays = 0', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50194, N'uspPurgePermissionProbe, @RetentionDays = 0', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

BEGIN TRY
    EXEC logs.uspPurgePermissionProbe @RetentionDays = 30, @BatchSize = 0
                                    , @RowsExpired = @Expired OUTPUT, @RowsRemaining = @Remain OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50195, N'uspPurgePermissionProbe, @BatchSize outside 1..1000000', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50195, N'uspPurgePermissionProbe, @BatchSize outside 1..1000000', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- E-50196.  Appendix B registers this against logs.uspSummarizePermissionProbe, and no such procedure exists -- the
-- number is raised by logs.uspReportPermissionProbe.  The probe calls the procedure that actually raises it and section
-- 14 reports the appendix's stale name, because a registry that names the wrong procedure sends the next reader looking
-- for an object that was renamed before it shipped.
BEGIN TRY
    EXEC logs.uspReportPermissionProbe @BucketMinutes = 0;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50196, N'uspReportPermissionProbe, @BucketMinutes outside 1..1440', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50196, N'uspReportPermissionProbe, @BucketMinutes outside 1..1440', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- 2i.  E-50140, the deploy-time verb check.  @Action is not a free-text field: 'Rebuild' and 'Drop' are the two things
-- 21.3 says a deployment may do to the policy, and anything else is a typo in a release script.
BEGIN TRY
    EXEC auth.uspRebuildTenantAccessPolicy @Action = N'Frobnicate', @TablesBound = @Bound OUTPUT
                                         , @TablesSkipped = @Skipped OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50140, N'uspRebuildTenantAccessPolicy, @Action is neither Rebuild nor Drop', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50140, N'uspRebuildTenantAccessPolicy, @Action is neither Rebuild nor Drop', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- 2j.  E-50230, G-18's catalogue contract, and it belongs in this section for a reason worth stating: it is raised BEFORE
-- the session is resolved.  A caller whose build disagrees with the element catalogue is broken for every session it will
-- ever open, so validating its token first would put a token error at the top of the log in front of a deployment fault.
-- @TokNone names no session anywhere, and the probe reaches the number anyway -- which is the assertion.  150's own
-- closing report raises E-50230 at install time as well, so the ledger in section 14 holds it on a clean database; what
-- that report cannot show is WHEN it is raised, and this can.
BEGIN TRY
    EXEC auth.uspGetNavigationForProfile @SessionTokenHash = @TokNone
                                       , @ExpectedCatalogueVersion = N'0.0-a-catalogue-never-published';
    INSERT @R (Want, Case_, Got, Msg) VALUES (50230, N'uspGetNavigationForProfile, the build''s catalogue is not this one', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50230, N'uspGetNavigationForProfile, the build''s catalogue is not this one', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- ----------------------------------------------------------------------------------------------------------------------
-- 3. The session-context family, which needs a connection that has no context yet -- this one, and only until the last
--    probe sets one.
--
-- WHY THESE FOUR SESSIONS ARE WRITTEN BY HAND
--
-- E-50021, E-50023 and E-50024 are about a session row that is live and a subject that is not: a profile that has been
-- deactivated, an expiry that has passed, an account that has been locked.  auth.uspCompleteLogin cannot produce any of
-- them, because it refuses to open a session in those states in the first place -- that is what E-50115 is for.  The
-- only way to a session row in a state the shipped procedures will not create is to write the row, which is also the
-- honest description of what this probe is testing: auth.uspSetSessionContext is the last line of defence for a session
-- that WAS valid when it was opened and has stopped being valid since, and time is the thing no procedure can fake.
-- ----------------------------------------------------------------------------------------------------------------------
DECLARE @Inactive  INT    = (SELECT p.UserProfileId FROM auth.UserProfile AS p
                              WHERE p.UserId = @AdminId AND p.ProfileName = N'Errcat Inactive' AND p.IsDeleted = 0)
      , @Default   INT    = (SELECT p.UserProfileId FROM auth.UserProfile AS p
                              WHERE p.UserId = @AdminId AND p.ProfileName = N'Error Catalogue Admin' AND p.IsDeleted = 0)
      , @AnyAttempt BIGINT = (SELECT MAX (la.LoginAttemptId) FROM auth.LoginAttempt AS la)
      , @Tok21     VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)-ctx21')
      , @Tok23     VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)-ctx23')
      , @Tok24     VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)-ctx24')
      , @Tok22     VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)-ctx22')
      , @StepUp    INT    = (SELECT p.UserProfileId FROM auth.UserProfile AS p
                             WHERE p.UserId = @AdminId AND p.ProfileName = N'Errcat Step-Up' AND p.IsDeleted = 0)
      , @CtxUser   INT
      , @CtxProf   INT
      , @CtxTenant INT
      , @Now       DATETIME2 (7) = SYSUTCDATETIME ();

-- FIRST, PUT THE ACCOUNT BACK, BECAUSE SECTION 2 LOCKED IT OUT AND THAT WAS THE LOCKOUT WORKING
--
-- Probes 50106 and 50107 are recorded authentication FAILURES -- a password that did not verify and a bypass attempt
-- with no second factor -- and 110_auth_authn_procedures.sql counts them.  Cross the per-account threshold inside the
-- window and the account is locked, which is exactly what §11.5 promises.  The first run of this file that got this far
-- died here instead, on an uncaught E-50024 from the set-up call for probe 50022, and the error was right: by then
-- errcat.admin genuinely could not act.
--
-- So the lockout is cleared here rather than only in the fixture, because the fixture runs BEFORE the failures.  A test
-- that probes the failure paths of a sign-in has to expect to be locked out by them; a test that does not clear it
-- measures the lockout for the rest of its run and calls it something else.
UPDATE auth.[User]
   SET IsLockedOut     = 0
     , LockoutEndUtc   = NULL
     , IsActive        = 1
     , auditModifiedBy = N'080_error_catalogue clearing the lockout section 2 earned'
 WHERE UserId = @AdminId
   AND (IsLockedOut = 1 OR LockoutEndUtc IS NOT NULL OR IsActive = 0);

IF @AnyAttempt IS NULL
BEGIN
    SET @Fail = N'auth.LoginAttempt is empty, so there is no attempt id to hang a hand-written session on.  Run '
              + N'database/_tests/010_authentication_paths.sql first, or any sign-in at all.';
    ;THROW 50000, @Fail, 1;
END;

-- A live session pointing at the deactivated profile.
IF NOT EXISTS (SELECT 1 FROM auth.UserSession AS s WHERE s.SessionTokenHash = @Tok21)
    INSERT auth.UserSession (UserId, ActiveUserProfileId, LoginAttemptId, ApplicationId, SessionTokenHash, ClientAddress
                           , AuthenticationMethod, IsBypassRoute, MfaSatisfied, StartedUtc, LastSeenUtc
                           , AbsoluteExpiryUtc, IdleExpiryUtc, auditCreatedBy, auditModifiedBy)
    VALUES (@AdminId, @Inactive, @AnyAttempt, @App, @Tok21, N'203.0.113.85', 'LocalPassword', 0, 0
          , @Now, @Now, DATEADD (HOUR, 4, @Now), DATEADD (MINUTE, 30, @Now)
          , N'080_error_catalogue probe 50021', N'080_error_catalogue probe 50021');

-- A session that expired yesterday.  The CHECK constraint insists both expiries are after StartedUtc, which is why the
-- row is backdated two days rather than given an expiry in the past with a start in the present: the constraint is
-- describing a session that was once coherent, and so is this row.
IF NOT EXISTS (SELECT 1 FROM auth.UserSession AS s WHERE s.SessionTokenHash = @Tok23)
    INSERT auth.UserSession (UserId, ActiveUserProfileId, LoginAttemptId, ApplicationId, SessionTokenHash, ClientAddress
                           , AuthenticationMethod, IsBypassRoute, MfaSatisfied, StartedUtc, LastSeenUtc
                           , AbsoluteExpiryUtc, IdleExpiryUtc, auditCreatedBy, auditModifiedBy)
    VALUES (@AdminId, @Default, @AnyAttempt, @App, @Tok23, N'203.0.113.86', 'LocalPassword', 0, 0
          , DATEADD (DAY, -2, @Now), DATEADD (DAY, -2, @Now)
          , DATEADD (DAY, -1, @Now), DATEADD (DAY, -1, @Now)
          , N'080_error_catalogue probe 50023', N'080_error_catalogue probe 50023');

-- A live session on a usable profile, for the account-state probe and then for E-50022.
IF NOT EXISTS (SELECT 1 FROM auth.UserSession AS s WHERE s.SessionTokenHash = @Tok24)
    INSERT auth.UserSession (UserId, ActiveUserProfileId, LoginAttemptId, ApplicationId, SessionTokenHash, ClientAddress
                           , AuthenticationMethod, IsBypassRoute, MfaSatisfied, StartedUtc, LastSeenUtc
                           , AbsoluteExpiryUtc, IdleExpiryUtc, auditCreatedBy, auditModifiedBy)
    VALUES (@AdminId, @Default, @AnyAttempt, @App, @Tok24, N'203.0.113.87', 'LocalPassword', 0, 0
          , @Now, @Now, DATEADD (HOUR, 4, @Now), DATEADD (MINUTE, 30, @Now)
          , N'080_error_catalogue probe 50024', N'080_error_catalogue probe 50024');

-- A second live session on a DIFFERENT but perfectly usable profile of the same user, for E-50022.
--
-- The first attempt at that probe re-used the inactive-profile session above and got E-50021 instead, which is the
-- procedure checking in the right order: the hat has to be wearable before "you are already wearing another one" is the
-- interesting thing about it.  So E-50022 needs two hats that are both fine, and the step-up profile is the second.
IF NOT EXISTS (SELECT 1 FROM auth.UserSession AS s WHERE s.SessionTokenHash = @Tok22)
    INSERT auth.UserSession (UserId, ActiveUserProfileId, LoginAttemptId, ApplicationId, SessionTokenHash, ClientAddress
                           , AuthenticationMethod, IsBypassRoute, MfaSatisfied, StartedUtc, LastSeenUtc
                           , AbsoluteExpiryUtc, IdleExpiryUtc, auditCreatedBy, auditModifiedBy)
    VALUES (@AdminId, @StepUp, @AnyAttempt, @App, @Tok22, N'203.0.113.88', 'LocalPassword', 0, 0
          , @Now, @Now, DATEADD (HOUR, 4, @Now), DATEADD (MINUTE, 30, @Now)
          , N'080_error_catalogue probe 50022', N'080_error_catalogue probe 50022');

-- 3a.  E-50020: a token nobody was ever issued.  The number says nothing about whether the token was wrong or the
-- session has ended, which is the point.
BEGIN TRY
    EXEC auth.uspSetSessionContext @SessionTokenHash = 0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF
                                , @UserId = @CtxUser OUTPUT, @UserProfileId = @CtxProf OUTPUT
                                , @ActingTenantId = @CtxTenant OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50020, N'uspSetSessionContext, no such session', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50020, N'uspSetSessionContext, no such session', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- 3b.  E-50021: the session is fine and the hat is not.
BEGIN TRY
    EXEC auth.uspSetSessionContext @SessionTokenHash = @Tok21, @UserId = @CtxUser OUTPUT
                                , @UserProfileId = @CtxProf OUTPUT, @ActingTenantId = @CtxTenant OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50021, N'uspSetSessionContext, the session''s profile is inactive', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50021, N'uspSetSessionContext, the session''s profile is inactive', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- 3c.  E-50023: absolute expiry passed.
BEGIN TRY
    EXEC auth.uspSetSessionContext @SessionTokenHash = @Tok23, @UserId = @CtxUser OUTPUT
                                , @UserProfileId = @CtxProf OUTPUT, @ActingTenantId = @CtxTenant OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50023, N'uspSetSessionContext, the session expired yesterday', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50023, N'uspSetSessionContext, the session expired yesterday', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- 3d.  E-50024: the account, not the session.  The flip is on auth.User and is put back immediately afterwards, outside
-- the TRY, for the reason section 2 gives.  It must be put back: every connection after this one signs in as this user.
UPDATE auth.[User]
   SET IsActive = 0, auditModifiedBy = N'080_error_catalogue probe 50024'
 WHERE UserId = @AdminId;

BEGIN TRY
    EXEC auth.uspSetSessionContext @SessionTokenHash = @Tok24, @UserId = @CtxUser OUTPUT
                                , @UserProfileId = @CtxProf OUTPUT, @ActingTenantId = @CtxTenant OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50024, N'uspSetSessionContext, the account is inactive', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50024, N'uspSetSessionContext, the account is inactive', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

UPDATE auth.[User]
   SET IsActive = 1, auditModifiedBy = N'080_error_catalogue restore 50024'
 WHERE UserId = @AdminId;

-- 3e.  E-50022, and it has to be last.  The first call succeeds and leaves this connection carrying a context; the
-- second names a different profile and is refused.  §14.3: the connection is the unit, one hat per connection, and the
-- refusal is what stops a pooled connection from inheriting somebody else's authority.
EXEC auth.uspSetSessionContext @SessionTokenHash = @Tok24, @UserId = @CtxUser OUTPUT
                            , @UserProfileId = @CtxProf OUTPUT, @ActingTenantId = @CtxTenant OUTPUT;

BEGIN TRY
    EXEC auth.uspSetSessionContext @SessionTokenHash = @Tok22, @UserId = @CtxUser OUTPUT
                                , @UserProfileId = @CtxProf OUTPUT, @ActingTenantId = @CtxTenant OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50022, N'uspSetSessionContext, a second profile on one connection', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50022, N'uspSetSessionContext, a second profile on one connection', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- ---- Connection 1's verdict. ------------------------------------------------------------------------------------------
SELECT Probe   = r.RowNo
     , Want    = r.Want
     , Got     = COALESCE (CAST (r.Got AS NVARCHAR (10)), N'(none)')
     , Verdict = CASE WHEN r.Got = r.Want THEN N'PASS' ELSE N'FAIL' END
     , Case_   = r.Case_
  FROM @R AS r
 ORDER BY r.RowNo;

IF EXISTS (SELECT 1 FROM @R WHERE Got IS NULL OR Got <> Want)
BEGIN
    SELECT Probe = RowNo, Want, Got = COALESCE (CAST (Got AS NVARCHAR (10)), N'(none)'), Case_, Msg
      FROM @R WHERE Got IS NULL OR Got <> Want ORDER BY RowNo;

    SET @Fail = CONCAT (N'080_error_catalogue.sql connection 1: ', (SELECT COUNT (*) FROM @R WHERE Got IS NULL OR Got <> Want)
                      , N' of ', (SELECT COUNT (*) FROM @R), N' probes did not raise the number Appendix B registers.  '
                      , N'The detail rows above name each one.  Nothing after this point ran, so the coverage report in '
                      , N'section 14 has not made any claim about these numbers.');
    ;THROW 50000, @Fail, 1;
END;

-- PRINT rejects a subquery (Msg 1046), so the two figures are assigned first.  Every closing line in this file does the
-- same, and that is the reason.
DECLARE @Count INT = (SELECT COUNT (*) FROM @R)
      , @Proved NVARCHAR (1000) = (SELECT STRING_AGG (CAST (x.Want AS NVARCHAR (10)), N' ') WITHIN GROUP (ORDER BY x.Want)
                                     FROM (SELECT DISTINCT Want FROM @R) AS x);

PRINT CONCAT ('2-3.  ', @Count, ' probes, all raising the registered number.  Numbers proved: ', @Proved);
GO

-- ======================================================================================================================
-- Connection 2.  The sign-in, which costs a whole connection and produces nothing but a session.
--
-- `:connect $(SQLCMDSERVER)` reconnects to the server -S named on the command line.  What survives is the -v variables,
-- which is why the token is derived from $(Seed) on both sides of the boundary; what does not survive is every local
-- variable, every table variable and the SET options, which is why they are re-issued below.
-- ======================================================================================================================
:connect $(SQLCMDSERVER)

USE [$(DbName)];
SET NOCOUNT ON;
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
GO

PRINT '4.  Connection 2: errcat.admin signs in.  This connection is spent by the switch and does nothing else.';
GO

DECLARE @AdminId  INT = (SELECT u.UserId FROM auth.[User] AS u
                          WHERE u.UserName = N'errcat.admin' AND u.IsDeleted = 0)
      , @Default  INT
      , @Tok      VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)-admin')
      , @Attempt  BIGINT
      , @Phc      NVARCHAR (400)
      , @Mfa      BIT
      , @Session  BIGINT
      , @OutUser  INT
      , @Must     BIT
      , @AbsExp   DATETIME2 (7)
      , @IdleExp  DATETIME2 (7);

SELECT @Default = p.UserProfileId FROM auth.UserProfile AS p
 WHERE p.UserId = @AdminId AND p.ProfileName = N'Error Catalogue Admin' AND p.IsDeleted = 0;

-- Section 2 left failures behind and section 3 cleared them, but section 2's E-50110 probe ran after that clearing and
-- an abandoned MFA exchange counts too.  Cleared once more, for the same reason and with the same honesty about it.
UPDATE auth.[User]
   SET IsLockedOut     = 0
     , LockoutEndUtc   = NULL
     , IsActive        = 1
     , auditModifiedBy = N'080_error_catalogue clearing the lockout before the sign-in'
 WHERE UserId = @AdminId
   AND (IsLockedOut = 1 OR LockoutEndUtc IS NOT NULL OR IsActive = 0);

EXEC auth.uspGetLoginVerifier @ApplicationCode = N'TEMPLATE', @UserName = N'errcat.admin'
                            , @ClientAddress = N'203.0.113.90', @TenantCode = N'ROOT', @UserAgent = N'080_error_catalogue'
                            , @LoginAttemptId = @Attempt OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;

-- @PasswordVerified = 1 without verifying anything, because verification is the application layer's job (D-04) and the
-- database is being handed the answer.  That is the whole contract of round trip 2.
EXEC auth.uspCompleteLogin @LoginAttemptId = @Attempt, @PasswordVerified = 1, @SessionTokenHash = @Tok
                         , @IsBypassRoute = 0, @UserSessionId = @Session OUTPUT, @UserId = @OutUser OUTPUT
                         , @MustChangePassword = @Must OUTPUT, @AbsoluteExpiryUtc = @AbsExp OUTPUT
                         , @IdleExpiryUtc = @IdleExp OUTPUT;

EXEC auth.uspSwitchProfile @SessionTokenHash = @Tok, @TargetUserProfileId = @Default;

PRINT CONCAT ('4.  Signed in.  UserSessionId ', @Session, ', profile ', @Default
            , '.  This connection now holds a context that disagrees with the session row, by design, and is finished.');
GO

-- ======================================================================================================================
-- Connection 3.  errcat.admin, wearing the hat, with the authority of ten roles at ROOT.
-- ======================================================================================================================
:connect $(SQLCMDSERVER)

USE [$(DbName)];
SET NOCOUNT ON;
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
GO

PRINT '========================================================================================================';
PRINT '080_error_catalogue.sql -- connection 3: tenancy, users, profiles, roles, triggers, registration';
PRINT '========================================================================================================';
GO

-- ----------------------------------------------------------------------------------------------------------------------
-- 5. Tenancy: E-50090 through E-50096, and the three tenants the later sections stand on.
--
-- Every procedure here establishes the connection's session context itself from @SessionTokenHash on its first
-- statement, which is why nothing calls auth.uspSetSessionContext: the token IS the credential for a request, and a
-- caller that sets context by hand and then calls a procedure has done the procedure's work twice.
-- ----------------------------------------------------------------------------------------------------------------------
DECLARE @R TABLE (RowNo  INT IDENTITY (1,1) PRIMARY KEY
                , Want   INT            NOT NULL
                , Case_  NVARCHAR (130) NOT NULL
                , Got    INT            NULL
                , Msg    NVARCHAR (300) NULL);

DECLARE @Tok      VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)-admin')
      , @App      INT = (SELECT a.ApplicationId FROM auth.Application AS a
                          WHERE a.ApplicationCode = N'TEMPLATE' AND a.IsDeleted = 0)
      , @Root     INT
      , @OtherApp INT = (SELECT MIN (a.ApplicationId) FROM auth.Application AS a
                          WHERE a.ApplicationCode <> N'TEMPLATE' AND a.IsDeleted = 0)
      , @OtherRoot INT
      , @A        INT
      , @B        INT
      , @C        INT
      , @NewId    INT
      , @Fail     NVARCHAR (2000);

SELECT @Root = t.TenantId FROM auth.Tenant AS t
 WHERE t.ApplicationId = @App AND t.TenantCode = N'ROOT' AND t.IsDeleted = 0;

-- Any live tenant in any other application will do, and it is chosen by MIN (TenantId) rather than by code: tenant codes
-- are unique per application, so there is no code this file can name that is guaranteed to exist somewhere else.
SELECT @OtherRoot = MIN (t.TenantId) FROM auth.Tenant AS t
 WHERE t.ApplicationId = @OtherApp AND t.IsDeleted = 0;

-- 5a.  E-50092 first, and on a code that already exists for a reason that has nothing to do with tidiness: probing it by
-- creating ERRCAT_A twice would pass on the first run of this file and raise it on the second from the WRONG call, which
-- is how an idempotent fixture and a duplicate-detection probe quietly swap places.  EXTORG is seeded and is never mine.
BEGIN TRY
    EXEC auth.uspCreateTenant @SessionTokenHash = @Tok, @ParentTenantId = @Root, @TenantCode = N'EXTORG'
                            , @TenantName = N'A Second External Organizations Branch', @TenantTypeCode = N'Division'
                            , @NewTenantId = @NewId OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50092, N'uspCreateTenant, @TenantCode already live in this application', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50092, N'uspCreateTenant, @TenantCode already live in this application', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

BEGIN TRY
    EXEC auth.uspCreateTenant @SessionTokenHash = @Tok, @ParentTenantId = @Root, @TenantCode = N'ERRCAT_TYPELESS'
                            , @TenantName = N'A Tenant Of No Known Type', @TenantTypeCode = N'Frobnicate'
                            , @NewTenantId = @NewId OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50091, N'uspCreateTenant, unknown tenant type code', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50091, N'uspCreateTenant, unknown tenant type code', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- 5b.  E-50094, INV-02.  A root is created by 115_seed_reference_data.sql and by nothing else, and it cannot be
-- deactivated at all: the whole tree hangs off it and auth.udfIsTenantUsable walks upwards, so deactivating a root
-- makes every tenant in the application unusable in one statement.
BEGIN TRY
    EXEC auth.uspDeactivateTenant @SessionTokenHash = @Tok, @TenantId = @Root, @IsActive = 0;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50094, N'uspDeactivateTenant, the root tenant', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50094, N'uspDeactivateTenant, the root tenant', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- 5c.  The three tenants the rest of the file stands on, created through the procedure and re-resolved on a second run.
--
--   ERRCAT_A   Division under ROOT      the subtree everything else lives in
--   ERRCAT_B   Program under ERRCAT_A   errcat.limited's authority, and the deep end of E-50042
--   ERRCAT_C   Program under ERRCAT_A   deactivated immediately, because an UNUSABLE tenant is the only way to reach
--                                       E-50173 and E-50178 -- a non-existent one is caught earlier by other numbers
IF NOT EXISTS (SELECT 1 FROM auth.Tenant AS t
                WHERE t.ApplicationId = @App AND t.TenantCode = N'ERRCAT_A' AND t.IsDeleted = 0)
    EXEC auth.uspCreateTenant @SessionTokenHash = @Tok, @ParentTenantId = @Root, @TenantCode = N'ERRCAT_A'
                            , @TenantName = N'Error Catalogue Division', @TenantTypeCode = N'Division'
                            , @NewTenantId = @NewId OUTPUT;

SELECT @A = t.TenantId FROM auth.Tenant AS t
 WHERE t.ApplicationId = @App AND t.TenantCode = N'ERRCAT_A' AND t.IsDeleted = 0;

IF NOT EXISTS (SELECT 1 FROM auth.Tenant AS t
                WHERE t.ApplicationId = @App AND t.TenantCode = N'ERRCAT_B' AND t.IsDeleted = 0)
    EXEC auth.uspCreateTenant @SessionTokenHash = @Tok, @ParentTenantId = @A, @TenantCode = N'ERRCAT_B'
                            , @TenantName = N'Error Catalogue Programme B', @TenantTypeCode = N'Program'
                            , @NewTenantId = @NewId OUTPUT;

SELECT @B = t.TenantId FROM auth.Tenant AS t
 WHERE t.ApplicationId = @App AND t.TenantCode = N'ERRCAT_B' AND t.IsDeleted = 0;

IF NOT EXISTS (SELECT 1 FROM auth.Tenant AS t
                WHERE t.ApplicationId = @App AND t.TenantCode = N'ERRCAT_C' AND t.IsDeleted = 0)
    EXEC auth.uspCreateTenant @SessionTokenHash = @Tok, @ParentTenantId = @A, @TenantCode = N'ERRCAT_C'
                            , @TenantName = N'Error Catalogue Programme C', @TenantTypeCode = N'Program'
                            , @NewTenantId = @NewId OUTPUT;

SELECT @C = t.TenantId FROM auth.Tenant AS t
 WHERE t.ApplicationId = @App AND t.TenantCode = N'ERRCAT_C' AND t.IsDeleted = 0;

IF EXISTS (SELECT 1 FROM auth.Tenant AS t WHERE t.TenantId = @C AND t.IsActive = 1)
    EXEC auth.uspDeactivateTenant @SessionTokenHash = @Tok, @TenantId = @C, @IsActive = 0;

-- 5d.  E-50090, and the route to it is a finding this file paid for.
--
-- The obvious probe -- @ParentTenantId = 999999 -- raises E-50030, not E-50090, and uspCreateTenant's header says why on
-- purpose: the permission is demanded BEFORE the parent is validated, so that a caller with no authority cannot map the
-- tenant ids by reading which ones answer "no such parent".  The consequence is that E-50090 is reachable ONLY through a
-- parent the caller genuinely administers, which is why this probe had to wait for ERRCAT_C to exist and be deactivated:
-- an inactive tenant inside ROOT's closure is authorized, undeleted, and still fails auth.udfIsTenantUsable.
--
-- The same trade makes E-50096 UNREACHABLE, and section 14 reports it as such rather than pretending otherwise.  Authority
-- 2 of 2 is demanded at the PROPOSED PARENT, and a proposed parent in another application can never be in the closure of
-- the profile making the request -- so a cross-application move dies at E-50030 before E-50096's test is reached.  The
-- number is not wrong; it is unreachable by any caller, and a comment in the procedure would be worth more than a probe.
BEGIN TRY
    EXEC auth.uspCreateTenant @SessionTokenHash = @Tok, @ParentTenantId = @C, @TenantCode = N'ERRCAT_UNDER_DEAD'
                            , @TenantName = N'A Tenant Under A Deactivated Parent', @TenantTypeCode = N'Division'
                            , @NewTenantId = @NewId OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50090, N'uspCreateTenant, the parent is inactive so it is unusable', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50090, N'uspCreateTenant, the parent is inactive so it is unusable', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- E-50095: re-parenting ERRCAT_A beneath its own child.  The closure would have to contain a cycle, and a closure with a
-- cycle is a scope test that never terminates -- so this is refused in the procedure rather than discovered in a loop.
BEGIN TRY
    EXEC auth.uspUpdateTenant @SessionTokenHash = @Tok, @TenantId = @A, @NewParentTenantId = @B;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50095, N'uspUpdateTenant, re-parent beneath its own descendant', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50095, N'uspUpdateTenant, re-parent beneath its own descendant', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- E-50030 is proved here rather than E-50096, and it is proved on purpose: the cross-application move is the shortest
-- demonstration in this database that the second authority test is doing its job.  @OtherRoot belongs to another
-- application, and no profile in TEMPLATE can hold Tenant.Update there.
BEGIN TRY
    EXEC auth.uspUpdateTenant @SessionTokenHash = @Tok, @TenantId = @A, @NewParentTenantId = @OtherRoot;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50030, N'uspUpdateTenant, proposed parent is in another application', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50030, N'uspUpdateTenant, proposed parent is in another application', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- 5e.  E-50093 and E-50000 from auth.uspGetTenantTree.  The read path demands nothing at the subtree root before it
-- resolves it, which is why E-50093 is reachable here and not from uspUpdateTenant -- there, a mistyped tenant id is
-- E-50030 for exactly the reason given in 5d.  The argument pair is exclusive on purpose: one argument means "the whole
-- application from its root down" and the other means "this subtree", and supplying both is a caller who has not decided
-- which question they are asking.
BEGIN TRY
    EXEC auth.uspGetTenantTree @SessionTokenHash = @Tok, @ApplicationId = @App, @RootTenantId = @A;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50000, N'uspGetTenantTree, both @ApplicationId and @RootTenantId', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50000, N'uspGetTenantTree, both @ApplicationId and @RootTenantId', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

BEGIN TRY
    EXEC auth.uspGetTenantTree @SessionTokenHash = @Tok, @RootTenantId = 999999;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50093, N'uspGetTenantTree, no such subtree root', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50093, N'uspGetTenantTree, no such subtree root', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- 5f.  G-43's two procedures and their three refusals, and every one of them writes NOTHING -- which is what makes them
-- safe to probe against a tenant the later sections stand on.  All three are raised before BEGIN TRANSACTION, so ERRCAT_A
-- comes out of this section with no auth.TenantAuthenticationPolicy row and no auth.TenantDefaultRole rows, exactly as it
-- went in.  That is worth more than it sounds: nothing shipped can remove a policy row once it exists (gap G-44), so a
-- probe that created one would quietly change what every later run of this file measures.
BEGIN TRY
    EXEC auth.uspSetTenantAuthenticationPolicy @SessionTokenHash = @Tok, @TenantId = @A
                                             , @AllowFederated = 0, @AllowLocalPassword = 0;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50097, N'uspSetTenantAuthenticationPolicy, neither method is allowed', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50097, N'uspSetTenantAuthenticationPolicy, neither method is allowed', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- E-50180, G-32's element check, on the list G-21 reads.  The bad element is a string and it is even a URL; what is wrong
-- with it is a leading space, and that case is chosen over a number or a null on purpose.  A stored issuer carrying
-- whitespace can never equal the issuer in a token, so trimming it for the caller would turn one typo into a federation
-- that silently refuses everybody it was configured to admit -- which is why the procedure refuses the call instead.
BEGIN TRY
    EXEC auth.uspSetTenantAuthenticationPolicy @SessionTokenHash = @Tok, @TenantId = @A
                                             , @TrustedIssuersJson = N'[" https://issuer.errcat.example/v2.0"]';
    INSERT @R (Want, Case_, Got, Msg) VALUES (50180, N'uspSetTenantAuthenticationPolicy, an issuer with leading space', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50180, N'uspSetTenantAuthenticationPolicy, an issuer with leading space', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- E-50098: a default-role code that resolves to no live assignable role at or above the tenant.  ERRCAT_FROZEN would
-- reach it too -- IsAssignable = 0 is the other half of the same refusal -- and a code that exists nowhere is used
-- instead, because a probe that depends on a role STAYING frozen starts passing for the wrong reason the day somebody
-- unfreezes it.
BEGIN TRY
    EXEC auth.uspSetTenantDefaultRoles @SessionTokenHash = @Tok, @TenantId = @A
                                     , @RoleCodesJson = N'["ERRCAT_NO_SUCH_ROLE"]';
    INSERT @R (Want, Case_, Got, Msg) VALUES (50098, N'uspSetTenantDefaultRoles, a code that resolves to nothing', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50098, N'uspSetTenantDefaultRoles, a code that resolves to nothing', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- 5g.  G-30, and it is an ASSERTION rather than a probe because nothing refuses: the gap was a default nobody could set,
-- not an argument nobody checked.  A policy row created by auth.uspSetTenantAuthenticationPolicy takes
-- RequireStepUpForPrivileged from config.ApplicationSetting's Authn.RequireStepUpForPrivilegedDefault and NOT from the
-- column default of 0, so a deployment that wants step-up for privileged hats gets it on every policy row created from
-- then on instead of on the rows somebody remembered.  The call below passes only a note: every other argument is NULL,
-- which the procedure reads as "I did not say" and fills from the shipped defaults, and that is exactly the path a first
-- policy row takes in practice.
--
-- THE ROW IS THEN REMOVED BY HAND, AND THAT IS THE ONE DIRECT WRITE IN THIS FILE THAT HAS NO ALTERNATIVE.  G-44 records
-- that nothing shipped DELETES a policy row -- auth.uspSetTenantAuthenticationPolicy updates the row it finds and there
-- is no companion that clears it -- so a test that left one behind would change what section 5f measures on the next run:
-- the E-50097 probe reaches its check through the no-policy-row defaults, and a row at ERRCAT_A would answer a different
-- question with the same call.  Soft-deleted with the audit pair in one statement, because
-- CK_auth_TenantAuthenticationPolicy_DeletedPair is evaluated before the AFTER trigger that would otherwise fill it.
DECLARE @StepUpWant INT = COALESCE (TRY_CAST ((SELECT s.SettingValue
                                                 FROM config.ApplicationSetting AS s
                                                WHERE s.SettingKey = N'Authn.RequireStepUpForPrivilegedDefault'
                                                  AND s.IsDeleted  = 0) AS INT), 1)
      , @StepUpGot  INT = NULL
      , @PolicyRows INT = NULL;

EXEC auth.uspSetTenantAuthenticationPolicy
      @SessionTokenHash = @Tok
    , @TenantId         = @A
    , @PolicyNote       = N'Created by _tests/080 section 5g to prove G-30''s seeded default, and soft-deleted again two statements later.';

SELECT @StepUpGot = CAST (p.RequireStepUpForPrivileged AS INT)
  FROM auth.TenantAuthenticationPolicy AS p
 WHERE p.TenantId = @A AND p.IsDeleted = 0;

UPDATE auth.TenantAuthenticationPolicy
   SET IsDeleted           = 1
     , auditDeletedBy      = N'080_error_catalogue restore 5g'
     , auditDeletedDateUtc = SYSUTCDATETIME ()
     , auditModifiedBy     = N'080_error_catalogue restore 5g'
 WHERE TenantId  = @A
   AND IsDeleted = 0;

SELECT @PolicyRows = COUNT (*) FROM auth.TenantAuthenticationPolicy AS p
 WHERE p.TenantId = @A AND p.IsDeleted = 0;

IF @StepUpGot IS NULL OR @StepUpGot <> @StepUpWant OR @PolicyRows <> 0
BEGIN
    SET @Fail = CONCAT (N'G-30: a policy row created at ERRCAT_A came out with RequireStepUpForPrivileged = '
                      , COALESCE (CAST (@StepUpGot AS NVARCHAR (11)), N'(no row was created at all)')
                      , N' and Authn.RequireStepUpForPrivilegedDefault holds ', @StepUpWant, N'. '
                      , CASE WHEN @PolicyRows <> 0
                             THEN CONCAT (N'The row was also not removed: ', @PolicyRows, N' live policy row(s) remain '
                                        , N'at that tenant, which will change what section 5f measures on the next run. ')
                             ELSE N'' END
                      , N'The seeded default is the whole of G-30: the column default is 0 and a project that wants '
                      , N'step-up for privileged hats cannot be asked to remember it on every tenant it creates.');
    ;THROW 50000, @Fail, 1;
END;

PRINT CONCAT ('5.  Tenancy probes done.  ERRCAT_A = ', @A, ', ERRCAT_B = ', @B, ', ERRCAT_C = ', @C
            , ' (deactivated on purpose).  G-30''s seeded step-up default came out as ', @StepUpGot, '.');

-- ----------------------------------------------------------------------------------------------------------------------
-- 6. Identity: E-50150 through E-50155, and errcat.limited, who exists to be small.
-- ----------------------------------------------------------------------------------------------------------------------
-- A table variable cannot share a DECLARE with a scalar -- `DECLARE @x INT, @t TABLE (...)` is a syntax error, not a
-- shorthand -- so the restore list gets a statement of its own.
DECLARE @Restore TABLE (UserId INT PRIMARY KEY);

DECLARE @LimitedId INT
      , @AdminId   INT = (SELECT u.UserId FROM auth.[User] AS u
                           WHERE u.UserName = N'errcat.admin' AND u.IsDeleted = 0)
      , @NewUser   INT;

BEGIN TRY
    EXEC auth.uspCreateUser @SessionTokenHash = @Tok, @UserName = N'   ', @DisplayName = N'Whitespace'
                          , @NewUserId = @NewUser OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50150, N'uspCreateUser, @UserName is whitespace', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50150, N'uspCreateUser, @UserName is whitespace', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

BEGIN TRY
    EXEC auth.uspCreateUser @SessionTokenHash = @Tok, @UserName = N'errcat.admin', @DisplayName = N'A Second Admin'
                          , @NewUserId = @NewUser OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50151, N'uspCreateUser, @UserName already in use', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50151, N'uspCreateUser, @UserName already in use', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

BEGIN TRY
    EXEC auth.uspCreateUser @SessionTokenHash = @Tok, @UserName = N'errcat.badjson', @DisplayName = N'Bad JSON'
                          , @AuthPolicyOverrideJson = N'{"RequireMfaForLocal":', @NewUserId = @NewUser OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50153, N'uspCreateUser, @AuthPolicyOverrideJson is a fragment', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50153, N'uspCreateUser, @AuthPolicyOverrideJson is a fragment', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- E-50155.  The capability is conferred by auth.uspGrantPlatformAdmin and nowhere else, so that the trail has exactly
-- one kind of row to read.  Creating the account with the flag already set would route around E-50084's "only a platform
-- administrator may confer it" by never conferring it.
BEGIN TRY
    EXEC auth.uspCreateUser @SessionTokenHash = @Tok, @UserName = N'errcat.wouldbeplatform'
                          , @DisplayName = N'Would-Be Platform Admin', @IsPlatformAdmin = 1
                          , @NewUserId = @NewUser OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50155, N'uspCreateUser, @IsPlatformAdmin = 1 at creation', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50155, N'uspCreateUser, @IsPlatformAdmin = 1 at creation', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

BEGIN TRY
    EXEC auth.uspGetUser @SessionTokenHash = @Tok, @UserId = 999999;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50152, N'uspGetUser, no such user', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50152, N'uspGetUser, no such user', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- 6a.  errcat.limited, through the procedure this time, because there is a session to demand User.Create from.
IF NOT EXISTS (SELECT 1 FROM auth.[User] AS u WHERE u.UserName = N'errcat.limited' AND u.IsDeleted = 0)
    EXEC auth.uspCreateUser @SessionTokenHash = @Tok, @UserName = N'errcat.limited'
                          , @DisplayName = N'Error Catalogue Limited Actor', @Email = N'errcat.limited@template.example'
                          , @NewUserId = @NewUser OUTPUT;

SELECT @LimitedId = u.UserId FROM auth.[User] AS u WHERE u.UserName = N'errcat.limited' AND u.IsDeleted = 0;

-- The credential, and this is the direct write the header names: no shipped procedure writes auth.UserCredential, so a
-- user created by auth.uspCreateUser cannot sign in until somebody writes this row by hand.  Section 14 reports it.
IF NOT EXISTS (SELECT 1 FROM auth.UserCredential AS c
                WHERE c.UserId = @LimitedId AND c.CredentialType = 'Password' AND c.IsDeleted = 0)
    INSERT auth.UserCredential (UserId, CredentialType, VerifierPhc, LastChangedUtc, auditCreatedBy, auditModifiedBy)
    VALUES (@LimitedId, 'Password'
          , N'$argon2id$v=19$m=65536,t=3,p=4$MDgwLWxpbWl0ZWQtYWN0b3ItZml4$bm90LWEtcmVhbC12ZXJpZmllci1ldmVyLWFueXdoZXJl'
          , SYSUTCDATETIME (), N'080_error_catalogue', N'080_error_catalogue');

-- 6b.  E-50154, the pair of E-50082.  It fires only when the account being deactivated is the LAST live platform
-- administrator, and this database has several -- so the others are set aside, the probe is taken, and they are put back
-- from a list captured first.  Flipping them back from a captured list rather than "set them all to 1" matters: two of
-- the users in this database are deliberately NOT platform administrators and a blanket restore would promote them.
INSERT INTO @Restore (UserId)
SELECT u.UserId FROM auth.[User] AS u
 WHERE u.IsPlatformAdmin = 1 AND u.IsDeleted = 0 AND u.UserId <> @AdminId;

UPDATE u
   SET u.IsPlatformAdmin = 0
     , u.auditModifiedBy = N'080_error_catalogue probe 50154'
  FROM auth.[User] AS u
 INNER JOIN @Restore AS r ON r.UserId = u.UserId;

BEGIN TRY
    -- @AdminId rather than the subquery that reads it, because EXEC takes values and variables and nothing else.
    EXEC auth.uspDeactivateUser @SessionTokenHash = @Tok, @UserId = @AdminId, @IsActive = 0;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50154, N'uspDeactivateUser, the last live platform administrator', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50154, N'uspDeactivateUser, the last live platform administrator', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

UPDATE u
   SET u.IsPlatformAdmin = 1
     , u.auditModifiedBy = N'080_error_catalogue restore 50154'
  FROM auth.[User] AS u
 INNER JOIN @Restore AS r ON r.UserId = u.UserId;

-- 6c.  E-50223 and G-42's administrative reset, which are one probe because the reset is what puts the fixture back.
--
-- E-50223 is "this account has no password to change", and reaching it needs two things that are awkward to have at
-- once: an account with no live credential, and a LIVE SESSION belonging to that account.  A user with no verifier
-- cannot sign in, and a session belonging to somebody else would be a second identity on this connection, which is
-- E-50022 by design (§14.3).  So the credential of the account that IS signed in here is soft-deleted for the length of
-- one call.  auth.uspChangePassword then finds no row for a user it has already authenticated -- exactly the state a
-- revoked credential leaves behind -- and the put-back is auth.uspSetPassword, the administrative route, which demands
-- User.ResetCredential at the acting tenant.  USER_ADMIN carries that permission and section 1 granted it, so one probe
-- proves both halves of the pair and the second half is proved by the fixture still working rather than by an assertion
-- about it.
--
-- auth.uspSetPassword forces MustChangePassword = 1 on purpose: an administrator who installed a password knows it, so
-- the user must replace it.  The flag is cleared below because every other section expects errcat.admin the way section 1
-- left it, and the clearing is a direct write for the same reason the fixture is.
DECLARE @AdminPhc  NVARCHAR (512) = N'$argon2id$v=19$m=65536,t=3,p=4$MDgwLWVycm9yLWNhdGFsb2d1ZQ$bm90LWEtcmVhbC12ZXJpZmllci1ldmVyLWFueXdoZXJl'
      , @LiveCreds INT;

UPDATE auth.UserCredential
   SET IsDeleted           = 1
     , auditDeletedBy      = N'080_error_catalogue probe 50223'
     , auditDeletedDateUtc = SYSUTCDATETIME ()
     , auditModifiedBy     = N'080_error_catalogue probe 50223'
 WHERE UserId         = @AdminId
   AND CredentialType = 'Password'
   AND IsDeleted      = 0;

BEGIN TRY
    EXEC auth.uspChangePassword @SessionTokenHash = @Tok, @CurrentPasswordVerified = 1, @NewVerifierPhc = @AdminPhc;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50223, N'uspChangePassword, the account has no live password', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50223, N'uspChangePassword, the account has no live password', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- Outside the TRY, and not in one of its own: if the administrative reset fails, this file must stop at the error the
-- procedure raised rather than report a tidy verdict about a deployment whose administrator can no longer sign in.
EXEC auth.uspSetPassword @SessionTokenHash = @Tok, @UserId = @AdminId, @NewVerifierPhc = @AdminPhc
                       , @Reason = N'Putting back the credential the E-50223 probe removed. _tests/080 section 6c.';

UPDATE auth.[User]
   SET MustChangePassword = 0
     , auditModifiedBy    = N'080_error_catalogue restore 50223'
 WHERE UserId = @AdminId AND MustChangePassword = 1;

SELECT @LiveCreds = COUNT (*) FROM auth.UserCredential AS c
 WHERE c.UserId = @AdminId AND c.CredentialType = 'Password' AND c.IsDeleted = 0;

IF @LiveCreds <> 1
BEGIN
    SET @Fail = CONCAT (N'The E-50223 probe left errcat.admin holding ', @LiveCreds, N' live password credential(s) and '
                      , N'section 1 needs exactly one. The put-back is auth.uspSetPassword, so this is a failure of '
                      , N'G-42''s administrative route rather than of the probe: the account it was asked to install a '
                      , N'password for is the account this connection is signed in as, and UX_auth_UserCredential_UserType '
                      , N'is filtered on IsDeleted = 0, so a second live row is not possible either.');
    ;THROW 50000, @Fail, 1;
END;

PRINT CONCAT ('6.  Identity probes done.  errcat.limited = UserId ', @LimitedId, '.');

-- ----------------------------------------------------------------------------------------------------------------------
-- 7. Profiles: E-50160 through E-50165, and the two hats errcat.limited will need in connection 6.
--
-- auth.uspUpdateProfile and auth.uspDeactivateProfile resolve the profile BEFORE demanding the permission, and the
-- comment at 140_auth_profile_procedures.sql:755 explains why that is not the tenancy trade-off backwards: the demand
-- needs a tenant to be made at, so a profile id that names nothing falls back to the ACTOR'S OWN acting tenant.  A caller
-- who holds the permission nowhere still gets E-50030; a caller who holds it, as this one does, gets E-50163.
-- ----------------------------------------------------------------------------------------------------------------------
DECLARE @AdminProfile INT = (SELECT p.UserProfileId FROM auth.UserProfile AS p
                              WHERE p.UserId = @AdminId AND p.ProfileName = N'Error Catalogue Admin' AND p.IsDeleted = 0)
      , @LimRoot      INT
      , @LimB         INT
      , @NewProfile   INT;

BEGIN TRY
    EXEC auth.uspCreateProfile @SessionTokenHash = @Tok, @UserId = @LimitedId, @TenantId = @Root
                             , @ProfileName = N'   ', @NewUserProfileId = @NewProfile OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50162, N'uspCreateProfile, @ProfileName is whitespace', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50162, N'uspCreateProfile, @ProfileName is whitespace', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

BEGIN TRY
    EXEC auth.uspCreateProfile @SessionTokenHash = @Tok, @UserId = 999999, @TenantId = @Root
                             , @ProfileName = N'A Hat For Nobody', @NewUserProfileId = @NewProfile OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50160, N'uspCreateProfile, no such user', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50160, N'uspCreateProfile, no such user', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- E-50161 takes the same route E-50090 did, for the same reason: ERRCAT_C exists and is administered by this caller, and
-- it is INACTIVE, which is what auth.udfIsTenantUsable is measuring.  A non-existent tenant id would answer E-50030.
BEGIN TRY
    EXEC auth.uspCreateProfile @SessionTokenHash = @Tok, @UserId = @LimitedId, @TenantId = @C
                             , @ProfileName = N'A Hat In A Suspended Branch', @NewUserProfileId = @NewProfile OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50161, N'uspCreateProfile, the tenant is inactive so it is unusable', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50161, N'uspCreateProfile, the tenant is inactive so it is unusable', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- 7a.  The two hats.  The first one is the default because INV-03 requires a user's first profile to be one, and the
-- second is at ERRCAT_B, which is the authority errcat.limited will be holding when connection 6 asks it to overreach.
IF NOT EXISTS (SELECT 1 FROM auth.UserProfile AS p
                WHERE p.UserId = @LimitedId AND p.TenantId = @Root
                  AND p.ProfileName = N'Errcat Limited At Root' AND p.IsDeleted = 0)
    EXEC auth.uspCreateProfile @SessionTokenHash = @Tok, @UserId = @LimitedId, @TenantId = @Root
                             , @ProfileName = N'Errcat Limited At Root', @IsDefault = 1
                             , @NewUserProfileId = @NewProfile OUTPUT;

SELECT @LimRoot = p.UserProfileId FROM auth.UserProfile AS p
 WHERE p.UserId = @LimitedId AND p.TenantId = @Root AND p.ProfileName = N'Errcat Limited At Root' AND p.IsDeleted = 0;

IF NOT EXISTS (SELECT 1 FROM auth.UserProfile AS p
                WHERE p.UserId = @LimitedId AND p.TenantId = @B
                  AND p.ProfileName = N'Errcat Limited At B' AND p.IsDeleted = 0)
    EXEC auth.uspCreateProfile @SessionTokenHash = @Tok, @UserId = @LimitedId, @TenantId = @B
                             , @ProfileName = N'Errcat Limited At B', @IsDefault = 0
                             , @NewUserProfileId = @NewProfile OUTPUT;

SELECT @LimB = p.UserProfileId FROM auth.UserProfile AS p
 WHERE p.UserId = @LimitedId AND p.TenantId = @B AND p.ProfileName = N'Errcat Limited At B' AND p.IsDeleted = 0;

BEGIN TRY
    EXEC auth.uspCreateProfile @SessionTokenHash = @Tok, @UserId = @LimitedId, @TenantId = @Root
                             , @ProfileName = N'Errcat Limited At Root', @NewUserProfileId = @NewProfile OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50162, N'uspCreateProfile, same name for the same user at the same tenant', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50162, N'uspCreateProfile, same name for the same user at the same tenant', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

BEGIN TRY
    EXEC auth.uspUpdateProfile @SessionTokenHash = @Tok, @UserProfileId = 999999, @ProfileName = N'Nothing';
    INSERT @R (Want, Case_, Got, Msg) VALUES (50163, N'uspUpdateProfile, no such profile', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50163, N'uspUpdateProfile, no such profile', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- E-50164.  "Stop being the default" is not an instruction the database can carry out, because INV-03 says a user has
-- EXACTLY one -- so clearing the flag would leave the user with no hat to land in at sign-in.  The way to move a default
-- is to name the profile that should become one, which sets this one to 0 as a consequence.
BEGIN TRY
    EXEC auth.uspUpdateProfile @SessionTokenHash = @Tok, @UserProfileId = @LimRoot, @IsDefault = 0;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50164, N'uspUpdateProfile, clear IsDefault on the only default', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50164, N'uspUpdateProfile, clear IsDefault on the only default', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- E-50165 is the only probe in this file that depends on WHICH profile this connection is wearing.  Deactivating the hat
-- you are standing in would leave the session holding a UserProfileId that auth.uspSetSessionContext now refuses
-- (E-50021) -- an administrator who locks themselves out with one call, which is what this number prevents.
BEGIN TRY
    EXEC auth.uspDeactivateProfile @SessionTokenHash = @Tok, @UserProfileId = @AdminProfile, @IsActive = 0;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50165, N'uspDeactivateProfile, the profile this session is wearing', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50165, N'uspDeactivateProfile, the profile this session is wearing', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

PRINT CONCAT ('7.  Profile probes done.  errcat.limited holds profile ', @LimRoot, ' at ROOT and ', @LimB, ' at ERRCAT_B.');

-- ----------------------------------------------------------------------------------------------------------------------
-- 8. Roles and grants: E-50170 through E-50179, plus E-50042, E-50044, E-50046 and E-50047.
--
-- INV-05 is three clauses and auth.uspAssignRoleToProfile tests them in a fixed order -- 50177 profile, 50040 authority
-- over the profile's tenant, 50041 authority over the scope, 50042 owner at or above scope, 50043, 50047 assignable,
-- 50044 self-grant, 50178 scope usable, 50179 duplicate.  The order is why several probes below look over-specified:
-- reaching a later clause means satisfying every earlier one, and a probe that satisfies them by accident is a probe that
-- silently moves to a different number when the procedure changes.
-- ----------------------------------------------------------------------------------------------------------------------
DECLARE @SysRoleId  INT
      , @SysOwner   INT
      , @SysCode    NVARCHAR (100)
      , @RoleFree   INT
      , @RoleFrozen INT
      , @RoleAtB    INT
      , @NewRoleId  INT
      , @NewGrantId INT;

SELECT TOP (1) @SysRoleId = r.RoleId, @SysOwner = r.OwnerTenantId, @SysCode = r.RoleCode
  FROM auth.Role AS r
 WHERE r.ApplicationId = @App AND r.IsSystemRole = 1 AND r.IsDeleted = 0
 ORDER BY r.RoleId;

-- E-50176 rather than E-50030, and the difference is the point: auth.uspDefineRole tests authority with
-- auth.udfHasPermission and raises its own number, so the caller is told WHICH tenant was out of reach instead of being
-- told only that something was refused.  @OtherRoot is in another application, which no profile here can ever reach.
BEGIN TRY
    EXEC auth.uspDefineRole @SessionTokenHash = @Tok, @OwnerTenantId = @OtherRoot, @RoleCode = N'ERRCAT_ELSEWHERE'
                          , @RoleName = N'A Role In Somebody Else''s Application', @NewRoleId = @NewRoleId OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50176, N'uspDefineRole, owner tenant outside this caller''s authority', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50176, N'uspDefineRole, owner tenant outside this caller''s authority', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

BEGIN TRY
    EXEC auth.uspDefineRole @SessionTokenHash = @Tok, @OwnerTenantId = @C, @RoleCode = N'ERRCAT_IN_A_DEAD_BRANCH'
                          , @RoleName = N'A Role Owned By A Suspended Tenant', @NewRoleId = @NewRoleId OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50173, N'uspDefineRole, owner tenant is inactive so it is unusable', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50173, N'uspDefineRole, owner tenant is inactive so it is unusable', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

BEGIN TRY
    EXEC auth.uspDefineRole @SessionTokenHash = @Tok, @OwnerTenantId = @SysOwner, @RoleCode = @SysCode
                          , @RoleName = N'A Second Role With A Taken Code', @NewRoleId = @NewRoleId OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50170, N'uspDefineRole, @RoleCode already used by that owner', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50170, N'uspDefineRole, @RoleCode already used by that owner', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- 8a.  Three custom roles, because a system role cannot be used for most of what follows: INV-10 refuses to freeze one
-- (E-50172) and refuses to have its permission set edited (E-50172 again), which are the two things E-50046, E-50047 and
-- E-50174 need a role to tolerate.
IF NOT EXISTS (SELECT 1 FROM auth.Role AS r
                WHERE r.ApplicationId = @App AND r.OwnerTenantId = @Root AND r.RoleCode = N'ERRCAT_FREE' AND r.IsDeleted = 0)
    EXEC auth.uspDefineRole @SessionTokenHash = @Tok, @OwnerTenantId = @Root, @RoleCode = N'ERRCAT_FREE'
                          , @RoleName = N'Error Catalogue Assignable Role'
                          , @RoleDescription = N'Created by _tests/080_error_catalogue.sql. Holds no permissions.'
                          , @IsAssignable = 1, @NewRoleId = @NewRoleId OUTPUT;

SELECT @RoleFree = r.RoleId FROM auth.Role AS r
 WHERE r.ApplicationId = @App AND r.OwnerTenantId = @Root AND r.RoleCode = N'ERRCAT_FREE' AND r.IsDeleted = 0;

IF NOT EXISTS (SELECT 1 FROM auth.Role AS r
                WHERE r.ApplicationId = @App AND r.OwnerTenantId = @Root AND r.RoleCode = N'ERRCAT_FROZEN' AND r.IsDeleted = 0)
    EXEC auth.uspDefineRole @SessionTokenHash = @Tok, @OwnerTenantId = @Root, @RoleCode = N'ERRCAT_FROZEN'
                          , @RoleName = N'Error Catalogue Frozen Role'
                          , @RoleDescription = N'Created by _tests/080_error_catalogue.sql, unassignable on purpose.'
                          , @IsAssignable = 0, @NewRoleId = @NewRoleId OUTPUT;

SELECT @RoleFrozen = r.RoleId FROM auth.Role AS r
 WHERE r.ApplicationId = @App AND r.OwnerTenantId = @Root AND r.RoleCode = N'ERRCAT_FROZEN' AND r.IsDeleted = 0;

IF NOT EXISTS (SELECT 1 FROM auth.Role AS r
                WHERE r.ApplicationId = @App AND r.OwnerTenantId = @B AND r.RoleCode = N'ERRCAT_OWNED_BY_B' AND r.IsDeleted = 0)
    EXEC auth.uspDefineRole @SessionTokenHash = @Tok, @OwnerTenantId = @B, @RoleCode = N'ERRCAT_OWNED_BY_B'
                          , @RoleName = N'Error Catalogue Role Owned Deep'
                          , @RoleDescription = N'Created by _tests/080_error_catalogue.sql to prove INV-05 clause 3.'
                          , @IsAssignable = 1, @NewRoleId = @NewRoleId OUTPUT;

SELECT @RoleAtB = r.RoleId FROM auth.Role AS r
 WHERE r.ApplicationId = @App AND r.OwnerTenantId = @B AND r.RoleCode = N'ERRCAT_OWNED_BY_B' AND r.IsDeleted = 0;

BEGIN TRY
    EXEC auth.uspUpdateRole @SessionTokenHash = @Tok, @RoleId = 999999, @RoleName = N'Nothing';
    INSERT @R (Want, Case_, Got, Msg) VALUES (50171, N'uspUpdateRole, no such role', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50171, N'uspUpdateRole, no such role', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

BEGIN TRY
    EXEC auth.uspUpdateRole @SessionTokenHash = @Tok, @RoleId = @SysRoleId, @IsAssignable = 0;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50172, N'uspUpdateRole, freezing a system role', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50172, N'uspUpdateRole, freezing a system role', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

BEGIN TRY
    EXEC auth.uspSetRolePermissions @SessionTokenHash = @Tok, @RoleId = @SysRoleId
                                  , @PermissionCodesJson = N'["Tenant.Read"]';
    INSERT @R (Want, Case_, Got, Msg) VALUES (50172, N'uspSetRolePermissions, editing a system role''s permissions', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50172, N'uspSetRolePermissions, editing a system role''s permissions', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- E-50046 wants a JSON OBJECT, not a malformed string: ISJSON (@x, ARRAY) is the test, so '{"a":1}' is valid JSON and
-- still wrong, which is the mistake a caller actually makes.
BEGIN TRY
    EXEC auth.uspSetRolePermissions @SessionTokenHash = @Tok, @RoleId = @RoleFree
                                  , @PermissionCodesJson = N'{"PermissionCodes":["Tenant.Read"]}';
    INSERT @R (Want, Case_, Got, Msg) VALUES (50046, N'uspSetRolePermissions, JSON object where an array is required', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50046, N'uspSetRolePermissions, JSON object where an array is required', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

BEGIN TRY
    EXEC auth.uspSetRolePermissions @SessionTokenHash = @Tok, @RoleId = @RoleFree
                                  , @PermissionCodesJson = N'["Tenant.Read","Frobnicate.Everything"]';
    INSERT @R (Want, Case_, Got, Msg) VALUES (50174, N'uspSetRolePermissions, a code that is not registered', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50174, N'uspSetRolePermissions, a code that is not registered', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

BEGIN TRY
    EXEC auth.uspAssignRoleToProfile @SessionTokenHash = @Tok, @UserProfileId = 999999, @RoleId = @RoleFree
                                   , @ScopeTenantId = @Root, @NewUserProfileRoleId = @NewGrantId OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50177, N'uspAssignRoleToProfile, no such profile', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50177, N'uspAssignRoleToProfile, no such profile', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- E-50042, INV-05 clause 3.  ERRCAT_OWNED_BY_B is owned three levels down and is being granted at ROOT, which would make
-- a role defined for one programme effective across the whole application.  This is also the probe that showed E-50043 to
-- be unreachable: clause 4 asks the same closure the same question, so nothing survives clause 3 to reach it.
BEGIN TRY
    EXEC auth.uspAssignRoleToProfile @SessionTokenHash = @Tok, @UserProfileId = @LimRoot, @RoleId = @RoleAtB
                                   , @ScopeTenantId = @Root, @NewUserProfileRoleId = @NewGrantId OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50042, N'uspAssignRoleToProfile, owner tenant below the requested scope', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50042, N'uspAssignRoleToProfile, owner tenant below the requested scope', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

BEGIN TRY
    EXEC auth.uspAssignRoleToProfile @SessionTokenHash = @Tok, @UserProfileId = @LimRoot, @RoleId = @RoleFrozen
                                   , @ScopeTenantId = @Root, @NewUserProfileRoleId = @NewGrantId OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50047, N'uspAssignRoleToProfile, the role is frozen', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50047, N'uspAssignRoleToProfile, the role is frozen', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- E-50044, INV-06.  Granting yourself a role is the one authorization change with no second person in it, and the trail
-- would read as though somebody had approved it.
BEGIN TRY
    EXEC auth.uspAssignRoleToProfile @SessionTokenHash = @Tok, @UserProfileId = @AdminProfile, @RoleId = @RoleFree
                                   , @ScopeTenantId = @Root, @NewUserProfileRoleId = @NewGrantId OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50044, N'uspAssignRoleToProfile, granting to the profile being worn', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50044, N'uspAssignRoleToProfile, granting to the profile being worn', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- E-50178 needs an INACTIVE scope rather than a missing one, and the reason is the check order above: a scope tenant that
-- does not exist is refused by clause 2 as E-50041 long before usability is considered.
BEGIN TRY
    EXEC auth.uspAssignRoleToProfile @SessionTokenHash = @Tok, @UserProfileId = @LimRoot, @RoleId = @RoleFree
                                   , @ScopeTenantId = @C, @NewUserProfileRoleId = @NewGrantId OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50178, N'uspAssignRoleToProfile, the scope tenant is inactive', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50178, N'uspAssignRoleToProfile, the scope tenant is inactive', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- 8b.  E-50179 needs a grant that already exists, so one is made first.  The IF makes the second run of this file behave
-- like the first: without it the make-it-first call would itself raise E-50179 and the probe would prove nothing.
IF NOT EXISTS (SELECT 1 FROM auth.UserProfileRole AS upr
                WHERE upr.UserProfileId = @LimRoot AND upr.RoleId = @RoleFree
                  AND upr.ScopeTenantId = @Root AND upr.IsDeleted = 0)
    EXEC auth.uspAssignRoleToProfile @SessionTokenHash = @Tok, @UserProfileId = @LimRoot, @RoleId = @RoleFree
                                   , @ScopeTenantId = @Root, @NewUserProfileRoleId = @NewGrantId OUTPUT;

BEGIN TRY
    EXEC auth.uspAssignRoleToProfile @SessionTokenHash = @Tok, @UserProfileId = @LimRoot, @RoleId = @RoleFree
                                   , @ScopeTenantId = @Root, @NewUserProfileRoleId = @NewGrantId OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50179, N'uspAssignRoleToProfile, that grant already exists', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50179, N'uspAssignRoleToProfile, that grant already exists', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- E-50175 is the revoke's counterpart: nothing to revoke.  ERRCAT_FROZEN was never granted to anybody, by construction.
BEGIN TRY
    EXEC auth.uspRevokeRoleFromProfile @SessionTokenHash = @Tok, @UserProfileId = @LimRoot, @RoleId = @RoleFrozen
                                     , @ScopeTenantId = @Root;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50175, N'uspRevokeRoleFromProfile, no such live grant', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50175, N'uspRevokeRoleFromProfile, no such live grant', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- 8b''. Not an error probe: the RE-GRANT after a revoke, through the procedures.  auth.uspAssignRoleToProfile brings a
-- revoked grant back to life in place, re-stamping GrantedUtc and GrantedByProfileId, and until 2026-09-25
-- trg_au_updt_UserProfileRole refused exactly that with E-50010: every procedural re-grant after a revoke failed.
-- _tests/050 resurrects by a direct UPDATE that leaves both columns alone, which is why it never showed.  This asserts
-- the round trip, and that the row that comes back is the one that was revoked.  8b made the grant live.
DECLARE @RegrantBefore INT = (SELECT upr.UserProfileRoleId FROM auth.UserProfileRole AS upr
                               WHERE upr.UserProfileId = @LimRoot AND upr.RoleId = @RoleFree
                                 AND upr.ScopeTenantId = @Root AND upr.IsDeleted = 0)
      , @RegrantFail   NVARCHAR (2000) = NULL;

BEGIN TRY
    EXEC auth.uspRevokeRoleFromProfile @SessionTokenHash = @Tok, @UserProfileId = @LimRoot, @RoleId = @RoleFree
                                     , @ScopeTenantId = @Root;
    EXEC auth.uspAssignRoleToProfile @SessionTokenHash = @Tok, @UserProfileId = @LimRoot, @RoleId = @RoleFree
                                   , @ScopeTenantId = @Root, @NewUserProfileRoleId = @NewGrantId OUTPUT;
    IF @RegrantBefore IS NULL OR @NewGrantId IS NULL OR @NewGrantId <> @RegrantBefore
        SET @RegrantFail = CONCAT (N'the re-grant came back as row ', @NewGrantId, N', not the revoked row ', @RegrantBefore, N'.');
END TRY
BEGIN CATCH
    SET @RegrantFail = CONCAT (N'E-', ERROR_NUMBER (), N': ', LEFT (ERROR_MESSAGE (), 300));
END CATCH

IF @RegrantFail IS NOT NULL
BEGIN
    SET @RegrantFail = N'080_error_catalogue.sql 8b'''': revoke then re-grant through the procedures failed -- ' + @RegrantFail;
    THROW 50000, @RegrantFail, 1;
END;
PRINT CONCAT ('8b''''.  Revoke and re-grant through the procedures: row ', @NewGrantId, ' resurrected in place.');

-- 8c.  The authority errcat.limited will hold in connection 6, and it is deliberately ONE role at ONE tenant.  E-50040 and
-- E-50041 are the two halves of INV-05 clauses 1 and 2, and telling them apart needs an actor who holds Authz.RoleAssign
-- SOMEWHERE but not everywhere: at ERRCAT_B and not at ROOT.  An actor with no authority at all can only ever prove
-- E-50040, and an actor with authority everywhere can prove neither.
DECLARE @RoleAdminId INT = (SELECT r.RoleId FROM auth.Role AS r
                             WHERE r.ApplicationId = @App AND r.RoleCode = N'ROLE_ADMIN' AND r.IsDeleted = 0);

IF NOT EXISTS (SELECT 1 FROM auth.UserProfileRole AS upr
                WHERE upr.UserProfileId = @LimB AND upr.RoleId = @RoleAdminId
                  AND upr.ScopeTenantId = @B AND upr.IsDeleted = 0)
    EXEC auth.uspAssignRoleToProfile @SessionTokenHash = @Tok, @UserProfileId = @LimB, @RoleId = @RoleAdminId
                                   , @ScopeTenantId = @B, @NewUserProfileRoleId = @NewGrantId OUTPUT;

EXEC auth.uspRebuildProfilePermissionScope @UserProfileId = @LimB;

PRINT CONCAT ('8.  Role probes done.  ERRCAT_FREE = ', @RoleFree, ', ERRCAT_FROZEN = ', @RoleFrozen
            , ', ERRCAT_OWNED_BY_B = ', @RoleAtB, ', ROLE_ADMIN = ', @RoleAdminId, ' granted to profile ', @LimB, '.');

-- ----------------------------------------------------------------------------------------------------------------------
-- 9. The immutability triggers, and the registration queue.
--
-- E-50010 and E-50012 are raised by AFTER UPDATE triggers, not by procedures, which is the only reason this section
-- writes to a table directly.  There is no procedure to route through: the whole point of an immutable column is that
-- nothing offers to change it.
-- ----------------------------------------------------------------------------------------------------------------------
DECLARE @RegId       INT
      , @RegTenantId INT
      , @BranchSaved NVARCHAR (400);

-- auth.[User].UserName is the cheapest E-50010 in the schema: it is immutable because auth.LoginAttempt records the name
-- as a STRING, so a rename silently rewrites what every historical attempt was about -- and unlike most immutable columns
-- it carries no foreign key, so the probe needs no other row to exist.
BEGIN TRY
    UPDATE auth.[User] SET UserName = N'errcat.limited.renamed' WHERE UserId = @LimitedId;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50010, N'trg_au_updt_User, UserName is immutable', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50010, N'trg_au_updt_User, UserName is immutable', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- E-50012 is INV-10 in the trigger rather than in a procedure, and it has to be: 900_bootstrap_first_admin.sql grants
-- system roles BY CODE and 115_seed_reference_data.sql re-seeds them on every deployment, so a renamed system role turns
-- both scripts into silent no-ops rather than errors.
BEGIN TRY
    UPDATE auth.Role SET RoleCode = N'ERRCAT_RENAMED_SYSTEM_ROLE' WHERE RoleId = @SysRoleId;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50012, N'trg_au_updt_Role, a system role''s code cannot change', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50012, N'trg_au_updt_Role, a system role''s code cannot change', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- 9a.  The registration queue.  One Pending row is needed, and the IF is what makes a second run behave like the first:
-- the row is rejected at the end of this section, so the next run finds nothing pending and registers again.
IF NOT EXISTS (SELECT 1 FROM auth.OrganizationRegistration AS orr
                WHERE orr.ApplicationId = @App AND orr.ProposedTenantCode = N'ERRCAT_COLLIDE'
                  AND orr.Status = N'Pending' AND orr.IsDeleted = 0)
    EXEC auth.uspRegisterOrganization @ApplicationCode = N'TEMPLATE', @ProposedTenantCode = N'ERRCAT_COLLIDE'
                                    , @OrganizationName = N'Error Catalogue Collision Ltd'
                                    , @ContactEmail = N'registrations@errcat.example'
                                    , @ContactName = N'E. Catalogue', @ClientAddress = N'203.0.113.91'
                                    , @OrganizationRegistrationId = @RegId OUTPUT;

SELECT @RegId = orr.OrganizationRegistrationId FROM auth.OrganizationRegistration AS orr
 WHERE orr.ApplicationId = @App AND orr.ProposedTenantCode = N'ERRCAT_COLLIDE'
   AND orr.Status = N'Pending' AND orr.IsDeleted = 0;

-- E-50067 is a CONFIGURATION fault, and the only honest way to provoke one is to break the configuration.  The setting is
-- global (G-34: every registration-accepting application must code its external branch with this value), so it is saved,
-- pointed at a code no tenant has, probed, and put back -- and the restore sits after the CATCH so that a probe failing
-- for an unexpected reason still leaves the deployment able to approve registrations.
SELECT @BranchSaved = s.SettingValue FROM config.ApplicationSetting AS s
 WHERE s.SettingKey = N'Registration.ExternalBranchTenantCode' AND s.IsDeleted = 0;

UPDATE config.ApplicationSetting
   SET SettingValue    = N'ERRCAT_NO_SUCH_BRANCH'
     , auditModifiedBy = N'080_error_catalogue probe 50067'
 WHERE SettingKey = N'Registration.ExternalBranchTenantCode' AND IsDeleted = 0;

BEGIN TRY
    EXEC auth.uspApproveOrganization @SessionTokenHash = @Tok, @OrganizationRegistrationId = @RegId, @Approve = 1
                                   , @ReviewNote = N'Probing the unresolvable branch.', @TenantId = @RegTenantId OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50067, N'uspApproveOrganization, the external branch cannot be resolved', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50067, N'uspApproveOrganization, the external branch cannot be resolved', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

UPDATE config.ApplicationSetting
   SET SettingValue    = @BranchSaved
     , auditModifiedBy = N'080_error_catalogue restoring after probe 50067'
 WHERE SettingKey = N'Registration.ExternalBranchTenantCode' AND IsDeleted = 0;

-- E-50065.  auth.uspRegisterOrganization deliberately does NOT test the proposed code against live tenants -- its own
-- header says that collision is the reviewer's to find -- so a tenant with the proposed code is created here to make the
-- registration unapprovable, which is exactly the situation a real reviewer meets.
IF NOT EXISTS (SELECT 1 FROM auth.Tenant AS t
                WHERE t.ApplicationId = @App AND t.TenantCode = N'ERRCAT_COLLIDE' AND t.IsDeleted = 0)
    EXEC auth.uspCreateTenant @SessionTokenHash = @Tok, @ParentTenantId = @A, @TenantCode = N'ERRCAT_COLLIDE'
                            , @TenantName = N'The Tenant The Registration Wanted To Be'
                            , @TenantTypeCode = N'Program', @NewTenantId = @NewId OUTPUT;

BEGIN TRY
    EXEC auth.uspApproveOrganization @SessionTokenHash = @Tok, @OrganizationRegistrationId = @RegId, @Approve = 1
                                   , @ReviewNote = N'Probing the code collision.', @TenantId = @RegTenantId OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50065, N'uspApproveOrganization, the proposed code is already a tenant', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50065, N'uspApproveOrganization, the proposed code is already a tenant', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- The rejection is not a probe: it is the cleanup that makes E-50060 reachable on the very next statement and makes this
-- whole section repeatable.  A rejection creates no tenant, which is why it succeeds where both approvals failed.
EXEC auth.uspApproveOrganization @SessionTokenHash = @Tok, @OrganizationRegistrationId = @RegId, @Approve = 0
                               , @ReviewNote = N'Rejected by _tests/080_error_catalogue.sql, which only wanted the queue.'
                               , @TenantId = @RegTenantId OUTPUT;

BEGIN TRY
    EXEC auth.uspApproveOrganization @SessionTokenHash = @Tok, @OrganizationRegistrationId = @RegId, @Approve = 1
                                   , @ReviewNote = N'Probing the second conclusion.', @TenantId = @RegTenantId OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50060, N'uspApproveOrganization, concluding an already concluded registration', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50060, N'uspApproveOrganization, concluding an already concluded registration', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

PRINT CONCAT ('9.  Trigger and registration probes done.  Registration ', @RegId, ' was rejected and left in the queue.');

-- ----------------------------------------------------------------------------------------------------------------------
-- 9b. The platform administrator flag: E-50081, E-50082 and E-50083, the three numbers 160_auth_admin_procedures.sql
--     raises that a caller holding the flag can reach.  E-50084 is the fourth and needs an actor WITHOUT the flag, so it
--     is probed in connection 6.
--
--     These four were originally proved by a throwaway pair of smoke scripts, and the coverage report in section 14 was
--     passing on their residue: logs.ExecutionLog remembered the numbers from a run whose script no longer existed.  That
--     is exactly the failure mode the report is supposed to catch, and it caught it here -- a fresh install would have
--     reported E-50081 to E-50084 as unaccounted for.  The lesson is worth the four probes below: a coverage ledger
--     measures the SUITE, so every number the suite is credited with has to be raised by a file the suite still ships.
-- ----------------------------------------------------------------------------------------------------------------------
DECLARE @Flagged TABLE (UserId INT PRIMARY KEY);

-- E-50081.  The flag test comes first (that is E-50084's whole point), then the permission, then existence -- so this
-- reaches the third gate only because errcat.admin passes the first two.
BEGIN TRY
    EXEC auth.uspGrantPlatformAdmin @SessionTokenHash = @Tok, @UserId = 999999
                                  , @Reason = N'Probing the non-existent grantee.';
    INSERT @R (Want, Case_, Got, Msg) VALUES (50081, N'uspGrantPlatformAdmin, no such user', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50081, N'uspGrantPlatformAdmin, no such user', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- E-50083 is about EXISTENCE and not about state: @UserProfileId = NULL means "every live profile" and is not an error,
-- and an INACTIVE profile is rebuilt rather than refused (section 8.6).  Only an id matching no live row gets the number.
BEGIN TRY
    EXEC auth.uspRebuildEffectivePermissions @SessionTokenHash = @Tok, @UserProfileId = 999999;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50083, N'uspRebuildEffectivePermissions, no such profile', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50083, N'uspRebuildEffectivePermissions, no such profile', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- E-50082, the number that stops a deployment locking itself out, and the twin of section 6b's E-50154: one guards the
-- flag, the other guards the account that carries it.  Reaching it needs errcat.admin to be the ONLY platform
-- administrator, so every other one is captured, cleared, and put back four statements later -- the same capture-flip-
-- probe-restore shape 6b uses, and for the same reason: the condition is a property of the whole table, not of a row.
INSERT INTO @Flagged (UserId)
SELECT u.UserId FROM auth.[User] AS u
 WHERE u.IsPlatformAdmin = 1 AND u.IsDeleted = 0 AND u.UserId <> @AdminId;

UPDATE u
   SET u.IsPlatformAdmin = 0
     , u.auditModifiedBy = N'080_error_catalogue probe 50082'
  FROM auth.[User] AS u
 INNER JOIN @Flagged AS f ON f.UserId = u.UserId;

-- The revoke is aimed at errcat.admin itself, which is legal -- the header of uspRevokePlatformAdmin says an
-- administrator may resign -- and is the cleanest way to ask the question, because the count E-50082 makes is of the OTHER
-- live active administrators and there are now none.
BEGIN TRY
    EXEC auth.uspRevokePlatformAdmin @SessionTokenHash = @Tok, @UserId = @AdminId
                                   , @Reason = N'Probing the resignation of the last administrator.';
    INSERT @R (Want, Case_, Got, Msg) VALUES (50082, N'uspRevokePlatformAdmin, the last platform administrator', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50082, N'uspRevokePlatformAdmin, the last platform administrator', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

UPDATE u
   SET u.IsPlatformAdmin = 1
     , u.auditModifiedBy = N'080_error_catalogue restore 50082'
  FROM auth.[User] AS u
 INNER JOIN @Flagged AS f ON f.UserId = u.UserId;

PRINT '9b. Platform administrator probes done.  Every flag cleared for E-50082 has been put back.';

-- ----------------------------------------------------------------------------------------------------------------------
-- Connection 3's verdict.  Same shape and same logic as connection 1's: any mismatch ends the run, so section 14 can
-- only ever be reached on a connection whose every probe matched Appendix B.
-- ----------------------------------------------------------------------------------------------------------------------
SELECT r.RowNo
     , r.Want
     , CASE WHEN r.Got = r.Want THEN 'PASS' ELSE 'FAIL' END AS Verdict
     , r.Got
     , r.Case_
  FROM @R AS r
 ORDER BY r.RowNo;

IF EXISTS (SELECT 1 FROM @R AS r WHERE r.Got IS NULL OR r.Got <> r.Want)
BEGIN
    SELECT r.RowNo, r.Want, r.Got, r.Case_, r.Msg FROM @R AS r
     WHERE r.Got IS NULL OR r.Got <> r.Want
     ORDER BY r.RowNo;

    SELECT @Fail = CONCAT (N'Connection 3 probes did not raise their registered numbers: '
                         , STRING_AGG (CAST (x.Want AS NVARCHAR (10)), N' ') WITHIN GROUP (ORDER BY x.Want)
                         , N'.  Nothing after this point ran, so the coverage report in section 14 has not made any '
                         , N'claim about these numbers.')
      FROM (SELECT DISTINCT r.Want FROM @R AS r WHERE r.Got IS NULL OR r.Got <> r.Want) AS x;

    ;THROW 50000, @Fail, 1;
END

DECLARE @Count  INT = (SELECT COUNT (*) FROM @R)
      , @Proved NVARCHAR (1000) = (SELECT STRING_AGG (CAST (x.Want AS NVARCHAR (10)), N' ') WITHIN GROUP (ORDER BY x.Want)
                                     FROM (SELECT DISTINCT Want FROM @R) AS x);

PRINT CONCAT ('5-9.  ', @Count, ' probes, all raising the registered number.  Numbers proved: ', @Proved);
GO

-- ======================================================================================================================
-- Connection 4.  No session of its own, and that is the whole reason it exists.
--
-- auth.uspSwitchProfile takes a token and establishes the context itself, so a caller does not need to have set one -- but
-- a caller that HAS set one cannot call it, because auth.uspSetSessionContext refuses the second establishment on a
-- connection with E-50022.  Connection 2 is therefore unusable for this and a fresh connection is the cheapest fix.
-- ======================================================================================================================
:connect $(SQLCMDSERVER)

USE [$(DbName)];
SET NOCOUNT ON;
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
GO

PRINT '========================================================================================================';
PRINT '080_error_catalogue.sql -- connection 4: the three refusals auth.uspSwitchProfile owns';
PRINT '========================================================================================================';
GO

DECLARE @R TABLE (RowNo  INT IDENTITY (1,1) PRIMARY KEY
                , Want   INT            NOT NULL
                , Case_  NVARCHAR (130) NOT NULL
                , Got    INT            NULL
                , Msg    NVARCHAR (300) NULL);

DECLARE @Tok      VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)-admin')
      , @App      INT = (SELECT a.ApplicationId FROM auth.Application AS a
                          WHERE a.ApplicationCode = N'TEMPLATE' AND a.IsDeleted = 0)
      , @AdminId  INT = (SELECT u.UserId FROM auth.[User] AS u
                          WHERE u.UserName = N'errcat.admin' AND u.IsDeleted = 0)
      , @LimitedId INT = (SELECT u.UserId FROM auth.[User] AS u
                           WHERE u.UserName = N'errcat.limited' AND u.IsDeleted = 0)
      , @Root      INT
      , @Inactive  INT
      , @StepUp    INT
      , @LimRoot   INT
      , @WasStepUp BIT
      , @Fail      NVARCHAR (2000);

SELECT @Root = t.TenantId FROM auth.Tenant AS t
 WHERE t.ApplicationId = @App AND t.TenantCode = N'ROOT' AND t.IsDeleted = 0;

SELECT @Inactive = p.UserProfileId FROM auth.UserProfile AS p
 WHERE p.UserId = @AdminId AND p.ProfileName = N'Errcat Inactive' AND p.IsDeleted = 0;

SELECT @StepUp = p.UserProfileId FROM auth.UserProfile AS p
 WHERE p.UserId = @AdminId AND p.ProfileName = N'Errcat Step-Up' AND p.IsDeleted = 0;

SELECT @LimRoot = p.UserProfileId FROM auth.UserProfile AS p
 WHERE p.UserId = @LimitedId AND p.ProfileName = N'Errcat Limited At Root' AND p.IsDeleted = 0;

-- E-50050.  D-10: a switch is never impersonation, so "that is not your profile" and "that profile does not exist" are
-- the same number on purpose -- a caller who could tell them apart could enumerate other people's profile ids by trying.
-- This probe uses errcat.limited's profile, which exists and belongs to somebody else, because the interesting half of
-- that decision is the one where the id is real.
BEGIN TRY
    EXEC auth.uspSwitchProfile @SessionTokenHash = @Tok, @TargetUserProfileId = @LimRoot;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50050, N'uspSwitchProfile, a profile belonging to another user', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50050, N'uspSwitchProfile, a profile belonging to another user', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

BEGIN TRY
    EXEC auth.uspSwitchProfile @SessionTokenHash = @Tok, @TargetUserProfileId = @Inactive;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50051, N'uspSwitchProfile, the target profile is deactivated', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50051, N'uspSwitchProfile, the target profile is deactivated', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- E-50052 needs two things at once, which is why 'Errcat Step-Up' was given USER_ADMIN and nothing else in section 1: the
-- target profile must be PRIVILEGED -- holding at least one Authz, User, Tenant or Platform permission -- and the target
-- tenant's resolved policy must require step-up.  TEMPLATE ships RequireStepUpForPrivileged = 0, so the policy is flipped
-- and put back, and the restore sits after the CATCH for the same reason section 2's did.
SELECT @WasStepUp = pol.RequireStepUpForPrivileged FROM auth.TenantAuthenticationPolicy AS pol
 WHERE pol.TenantId = @Root AND pol.IsDeleted = 0;

UPDATE auth.TenantAuthenticationPolicy
   SET RequireStepUpForPrivileged = 1
     , auditModifiedBy            = N'080_error_catalogue probe 50052'
 WHERE TenantId = @Root AND IsDeleted = 0;

BEGIN TRY
    EXEC auth.uspSwitchProfile @SessionTokenHash = @Tok, @TargetUserProfileId = @StepUp;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50052, N'uspSwitchProfile, a privileged hat with no elevation window', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50052, N'uspSwitchProfile, a privileged hat with no elevation window', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

UPDATE auth.TenantAuthenticationPolicy
   SET RequireStepUpForPrivileged = @WasStepUp
     , auditModifiedBy            = N'080_error_catalogue restoring after probe 50052'
 WHERE TenantId = @Root AND IsDeleted = 0;

SELECT r.RowNo
     , r.Want
     , CASE WHEN r.Got = r.Want THEN 'PASS' ELSE 'FAIL' END AS Verdict
     , r.Got
     , r.Case_
  FROM @R AS r
 ORDER BY r.RowNo;

IF EXISTS (SELECT 1 FROM @R AS r WHERE r.Got IS NULL OR r.Got <> r.Want)
BEGIN
    SELECT r.RowNo, r.Want, r.Got, r.Case_, r.Msg FROM @R AS r
     WHERE r.Got IS NULL OR r.Got <> r.Want
     ORDER BY r.RowNo;

    SELECT @Fail = CONCAT (N'Connection 4 probes did not raise their registered numbers: '
                         , STRING_AGG (CAST (x.Want AS NVARCHAR (10)), N' ') WITHIN GROUP (ORDER BY x.Want)
                         , N'.  Nothing after this point ran, so the coverage report in section 14 has not made any '
                         , N'claim about these numbers.')
      FROM (SELECT DISTINCT r.Want FROM @R AS r WHERE r.Got IS NULL OR r.Got <> r.Want) AS x;

    ;THROW 50000, @Fail, 1;
END

DECLARE @Count  INT = (SELECT COUNT (*) FROM @R)
      , @Proved NVARCHAR (1000) = (SELECT STRING_AGG (CAST (x.Want AS NVARCHAR (10)), N' ') WITHIN GROUP (ORDER BY x.Want)
                                     FROM (SELECT DISTINCT Want FROM @R) AS x);

PRINT CONCAT ('10.  ', @Count, ' probes, all raising the registered number.  Numbers proved: ', @Proved);
GO

-- ======================================================================================================================
-- Connection 5.  errcat.limited signs in, and is spent doing it, exactly as connection 2 was.
-- ======================================================================================================================
:connect $(SQLCMDSERVER)

USE [$(DbName)];
SET NOCOUNT ON;
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
GO

PRINT '11.  Connection 5: errcat.limited signs in and puts on the ERRCAT_B hat.';
GO

DECLARE @LimitedId INT = (SELECT u.UserId FROM auth.[User] AS u
                           WHERE u.UserName = N'errcat.limited' AND u.IsDeleted = 0)
      , @Target   INT
      , @Tok2     VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)-limited')
      , @Attempt  BIGINT
      , @Phc      NVARCHAR (400)
      , @Mfa      BIT
      , @Session  BIGINT
      , @OutUser  INT
      , @Must     BIT
      , @AbsExp   DATETIME2 (7)
      , @IdleExp  DATETIME2 (7);

SELECT @Target = p.UserProfileId FROM auth.UserProfile AS p
 WHERE p.UserId = @LimitedId AND p.ProfileName = N'Errcat Limited At B' AND p.IsDeleted = 0;

UPDATE auth.[User]
   SET IsLockedOut     = 0
     , LockoutEndUtc   = NULL
     , auditModifiedBy = N'080_error_catalogue clearing the lockout before the second sign-in'
 WHERE UserId = @LimitedId
   AND (IsLockedOut = 1 OR LockoutEndUtc IS NOT NULL);

EXEC auth.uspGetLoginVerifier @ApplicationCode = N'TEMPLATE', @UserName = N'errcat.limited'
                            , @ClientAddress = N'203.0.113.92', @TenantCode = N'ROOT', @UserAgent = N'080_error_catalogue'
                            , @LoginAttemptId = @Attempt OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;

EXEC auth.uspCompleteLogin @LoginAttemptId = @Attempt, @PasswordVerified = 1, @SessionTokenHash = @Tok2
                         , @IsBypassRoute = 0, @UserSessionId = @Session OUTPUT, @UserId = @OutUser OUTPUT
                         , @MustChangePassword = @Must OUTPUT, @AbsoluteExpiryUtc = @AbsExp OUTPUT
                         , @IdleExpiryUtc = @IdleExp OUTPUT;

-- The switch is to the ERRCAT_B hat rather than the default one at ROOT, and that is the point of having two: the whole
-- authority of connection 6 is "Authz.RoleAssign at ERRCAT_B and nowhere else", which is what tells E-50041 from E-50040.
EXEC auth.uspSwitchProfile @SessionTokenHash = @Tok2, @TargetUserProfileId = @Target;

PRINT CONCAT ('11.  Signed in.  UserSessionId ', @Session, ', wearing profile ', @Target, ' at ERRCAT_B.');
GO

-- ======================================================================================================================
-- Connection 6.  errcat.limited, who can do exactly one thing, in exactly one place.
-- ======================================================================================================================
:connect $(SQLCMDSERVER)

USE [$(DbName)];
SET NOCOUNT ON;
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
GO

PRINT '========================================================================================================';
PRINT '080_error_catalogue.sql -- connection 6: the refusals that need a SMALL actor';
PRINT '========================================================================================================';
GO

DECLARE @R TABLE (RowNo  INT IDENTITY (1,1) PRIMARY KEY
                , Want   INT            NOT NULL
                , Case_  NVARCHAR (130) NOT NULL
                , Got    INT            NULL
                , Msg    NVARCHAR (300) NULL);

DECLARE @Tok2     VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)-limited')
      , @App      INT = (SELECT a.ApplicationId FROM auth.Application AS a
                          WHERE a.ApplicationCode = N'TEMPLATE' AND a.IsDeleted = 0)
      , @LimitedId INT = (SELECT u.UserId FROM auth.[User] AS u
                           WHERE u.UserName = N'errcat.limited' AND u.IsDeleted = 0)
      , @Root      INT
      , @LimRoot   INT
      , @LimB      INT
      , @RoleFree  INT
      , @NewGrantId INT
      , @NewProfile INT
      , @Fail      NVARCHAR (2000);

SELECT @Root = t.TenantId FROM auth.Tenant AS t
 WHERE t.ApplicationId = @App AND t.TenantCode = N'ROOT' AND t.IsDeleted = 0;

SELECT @LimRoot = p.UserProfileId FROM auth.UserProfile AS p
 WHERE p.UserId = @LimitedId AND p.ProfileName = N'Errcat Limited At Root' AND p.IsDeleted = 0;

SELECT @LimB = p.UserProfileId FROM auth.UserProfile AS p
 WHERE p.UserId = @LimitedId AND p.ProfileName = N'Errcat Limited At B' AND p.IsDeleted = 0;

SELECT @RoleFree = r.RoleId FROM auth.Role AS r
 WHERE r.ApplicationId = @App AND r.RoleCode = N'ERRCAT_FREE' AND r.IsDeleted = 0;

-- E-50040, INV-05 clause 1.  The target profile lives at ROOT and this actor holds Authz.RoleAssign only at ERRCAT_B, so
-- the grant is refused before the role, the scope or the duplicate check is considered.  Note the number: this is NOT
-- E-50030, because auth.uspAssignRoleToProfile tests each clause of INV-05 with its own message rather than deferring to
-- auth.uspDemandPermission -- a reviewer reading the trail can see WHICH clause stopped it.
BEGIN TRY
    EXEC auth.uspAssignRoleToProfile @SessionTokenHash = @Tok2, @UserProfileId = @LimRoot, @RoleId = @RoleFree
                                   , @ScopeTenantId = @Root, @NewUserProfileRoleId = @NewGrantId OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50040, N'uspAssignRoleToProfile, the profile''s tenant is out of reach', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50040, N'uspAssignRoleToProfile, the profile''s tenant is out of reach', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- E-50041, INV-05 clause 2.  Same actor, same role, but now the target profile is the one at ERRCAT_B -- which this actor
-- DOES administer -- and the requested scope is ROOT, which it does not.  Clause 1 passes and clause 2 refuses, which is
-- the pair of probes that proves the two clauses are separately enforced rather than collapsed into one test.
BEGIN TRY
    EXEC auth.uspAssignRoleToProfile @SessionTokenHash = @Tok2, @UserProfileId = @LimB, @RoleId = @RoleFree
                                   , @ScopeTenantId = @Root, @NewUserProfileRoleId = @NewGrantId OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50041, N'uspAssignRoleToProfile, the requested scope is out of reach', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50041, N'uspAssignRoleToProfile, the requested scope is out of reach', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- E-50045 exists because auth.uspCreateProfile tests authority with auth.udfHasPermission instead of calling
-- auth.uspDemandPermission, which could only ever throw E-50030 (BL-042, and the file header of
-- 140_auth_profile_procedures.sql).  The denial row in logs.AuthorizationDenial is written by hand and is identical to the
-- one uspDemandPermission would have written, so choosing the sharper number costs the trail nothing.
BEGIN TRY
    EXEC auth.uspCreateProfile @SessionTokenHash = @Tok2, @UserId = @LimitedId, @TenantId = @Root
                             , @ProfileName = N'A Hat This Actor May Not Make', @NewUserProfileId = @NewProfile OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50045, N'uspCreateProfile, no Authz.ProfileCreate at that tenant', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50045, N'uspCreateProfile, no Authz.ProfileCreate at that tenant', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- E-50084, and this is the connection it needs: the flag is an AUTHENTICATION capability (D-05, INV-09), so no role can
-- confer it and errcat.limited cannot have it.  The number is raised BEFORE auth.uspDemandPermission is called, which is
-- why it arrives here rather than E-50030 -- a caller who holds Platform.ManageApplications but not the flag would get
-- this same number and be told the truth about what it is missing.  @UserId is the actor's own id because the test never
-- gets as far as looking at it.
BEGIN TRY
    EXEC auth.uspGrantPlatformAdmin @SessionTokenHash = @Tok2, @UserId = @LimitedId
                                  , @Reason = N'Probing the flag gate from outside the flag.';
    INSERT @R (Want, Case_, Got, Msg) VALUES (50084, N'uspGrantPlatformAdmin, the actor is not a platform administrator', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50084, N'uspGrantPlatformAdmin, the actor is not a platform administrator', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

SELECT r.RowNo
     , r.Want
     , CASE WHEN r.Got = r.Want THEN 'PASS' ELSE 'FAIL' END AS Verdict
     , r.Got
     , r.Case_
  FROM @R AS r
 ORDER BY r.RowNo;

IF EXISTS (SELECT 1 FROM @R AS r WHERE r.Got IS NULL OR r.Got <> r.Want)
BEGIN
    SELECT r.RowNo, r.Want, r.Got, r.Case_, r.Msg FROM @R AS r
     WHERE r.Got IS NULL OR r.Got <> r.Want
     ORDER BY r.RowNo;

    SELECT @Fail = CONCAT (N'Connection 6 probes did not raise their registered numbers: '
                         , STRING_AGG (CAST (x.Want AS NVARCHAR (10)), N' ') WITHIN GROUP (ORDER BY x.Want)
                         , N'.  Nothing after this point ran, so the coverage report in section 14 has not made any '
                         , N'claim about these numbers.')
      FROM (SELECT DISTINCT r.Want FROM @R AS r WHERE r.Got IS NULL OR r.Got <> r.Want) AS x;

    ;THROW 50000, @Fail, 1;
END

DECLARE @Count  INT = (SELECT COUNT (*) FROM @R)
      , @Proved NVARCHAR (1000) = (SELECT STRING_AGG (CAST (x.Want AS NVARCHAR (10)), N' ') WITHIN GROUP (ORDER BY x.Want)
                                     FROM (SELECT DISTINCT Want FROM @R) AS x);

PRINT CONCAT ('12.  ', @Count, ' probes, all raising the registered number.  Numbers proved: ', @Proved);
GO

-- ======================================================================================================================
-- Connection 7.  The step-up family, on a session that exists and is wearing no hat.
--
-- WHY IT IS LABELLED 12A AND NOT 13.  Inserting a section number here would renumber the demo-domain section and the
-- coverage report, and both are referred to BY NUMBER in this file's own prose, in the other files under _tests, and in
-- docs/10-database-authn-authz-design.md.  A letter costs one sentence of explanation; a renumbering costs a search
-- through three directories and misses one.
--
-- WHY THE SESSION HAS NO PROFILE, AND WHY THAT IS THE POINT RATHER THAN A SHORTCUT.  auth.uspCompleteLogin returns a
-- session and deliberately does not give it a hat: choosing one is auth.uspSwitchProfile's job, on a fresh connection
-- (UI-06).  A step-up re-proves the second factor for a session that already exists, so it has no business requiring a
-- profile -- and a profileless session is also the only way to reach E-50032, the refusal a UI meets when a user with no
-- live profile calls something that demands a permission.  One sign-in therefore buys six numbers.
--
-- WHAT IT WRITES AND PUTS BACK.  One confirmed Totp factor for errcat.admin, soft-deleted at the end of the section.
-- E-50128 and E-50129 cannot be reached without a confirmed factor, and section 2e's E-50110 probe cannot be reached
-- WITH one, so the two coexist only because this section hands the database back the way it found it.  What it writes
-- into SecretCiphertext is not a secret and does not have to be: the database never verifies a TOTP code and never
-- decrypts that column -- the application does, and passes in the step it verified.  Which is exactly why E-50128 can be
-- provoked by naming step 1: a step outside Authn.TotpWindowSteps of the server's own step is refused by arithmetic,
-- with nothing decrypted and nothing to decrypt it with.
-- ======================================================================================================================
:connect $(SQLCMDSERVER)

USE [$(DbName)];
SET NOCOUNT ON;
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
GO

PRINT '========================================================================================================';
PRINT '080_error_catalogue.sql -- connection 7: the step-up family, on a profileless session';
PRINT '========================================================================================================';
GO

DECLARE @R TABLE (RowNo  INT IDENTITY (1,1) PRIMARY KEY
                , Want   INT            NOT NULL
                , Case_  NVARCHAR (130) NOT NULL
                , Got    INT            NULL
                , Msg    NVARCHAR (300) NULL);

DECLARE @App     INT = (SELECT a.ApplicationId FROM auth.Application AS a
                         WHERE a.ApplicationCode = N'TEMPLATE' AND a.IsDeleted = 0)
      , @Root    INT             = NULL
      , @AdminId INT             = NULL
      , @Attempt BIGINT          = NULL
      , @Phc     NVARCHAR (512)  = NULL
      , @Mfa     BIT             = NULL
      , @Sess    BIGINT          = NULL
      , @Uid     INT             = NULL
      , @Must    BIT             = NULL
      , @Abs     DATETIME2 (3)   = NULL
      , @Idle    DATETIME2 (3)   = NULL
      , @Until   DATETIME2 (3)   = NULL
      , @Fail    NVARCHAR (2000) = NULL
      , @Left    INT             = 0
      , @Loops   INT             = 0
      , @Tok     VARBINARY (32)  = HASHBYTES ('SHA2_256', N'$(Seed)-stepup')
        -- The step an application would have just verified a code against: seconds since the Unix epoch divided by the
        -- configured step length, which is the arithmetic auth.uspVerifyMfa and auth.uspElevateSession both do.
      , @Step    BIGINT = DATEDIFF_BIG (SECOND, CAST (N'1970-01-01' AS DATETIME2 (3)), SYSUTCDATETIME ()) / 30;

SELECT @Root = t.TenantId FROM auth.Tenant AS t
 WHERE t.ApplicationId = @App AND t.TenantCode = N'ROOT' AND t.IsDeleted = 0;

-- No ApplicationId predicate here, and the line above has one: auth.Tenant is scoped to an application and auth.[User]
-- is NOT.  A user name is unique across the whole database -- which is what lets one person hold hats in tenants
-- belonging to different applications -- so adding the column the tenant lookup uses would not narrow this, it would
-- fail to compile.  Every other errcat.admin lookup in this file resolves it by name alone for the same reason.
SELECT @AdminId = u.UserId FROM auth.[User] AS u
 WHERE u.UserName = N'errcat.admin' AND u.IsDeleted = 0;

-- 12A a.  E-50125, the argument refusal, raised BEFORE any session is read -- so this probe needs no session at all and
-- is deliberately the first thing in the section.  Sixteen bytes is a plausible mistake (an MD5, or half a hash), and it
-- is refused for the reason D-08 gives: the token itself is never a parameter, only its SHA-256, and a value that is not
-- 32 bytes long cannot be one.
BEGIN TRY
    EXEC auth.uspElevateSession @SessionTokenHash = 0x00112233445566778899AABBCCDDEEFF
                              , @TimeStep = @Step, @ElevatedUntilUtc = @Until OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50125, N'uspElevateSession, @SessionTokenHash is 16 bytes', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50125, N'uspElevateSession, @SessionTokenHash is 16 bytes', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- 12A b.  E-50126, and it makes the same conflation E-50020 makes, for the same reason: absent, ended, idle-expired,
-- absolutely expired and belonging to a deactivated user are one answer, because they are five facts about an account
-- the caller has not proved anything about.
BEGIN TRY
    EXEC auth.uspElevateSession @SessionTokenHash = 0xFEEDFACEFEEDFACEFEEDFACEFEEDFACEFEEDFACEFEEDFACEFEEDFACEFEEDFACE
                              , @TimeStep = @Step, @ElevatedUntilUtc = @Until OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50126, N'uspElevateSession, no live session for that token hash', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50126, N'uspElevateSession, no live session for that token hash', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- 12A c.  The session the rest of the section needs: a sign-in of its own, from an address of its own.  ROOT permits
-- local passwords and does not require MFA at this point in the file (section 2e set RequireMfaForLocal back to 0), so
-- the exchange completes in two calls and leaves a live session with no hat on it.
EXEC auth.uspGetLoginVerifier @ApplicationCode = N'TEMPLATE', @UserName = N'errcat.admin'
                            , @ClientAddress = N'203.0.113.93', @TenantCode = N'ROOT', @UserAgent = N'080-stepup'
                            , @LoginAttemptId = @Attempt OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;

EXEC auth.uspCompleteLogin @LoginAttemptId = @Attempt, @PasswordVerified = 1, @SessionTokenHash = @Tok
                         , @IsBypassRoute = 0, @UserSessionId = @Sess OUTPUT, @UserId = @Uid OUTPUT
                         , @MustChangePassword = @Must OUTPUT, @AbsoluteExpiryUtc = @Abs OUTPUT
                         , @IdleExpiryUtc = @Idle OUTPUT;

-- 12A d.  E-50032, and G-51 is the reason it exists.  The session is real, the connection's context is real, and there
-- is no profile in it -- so a permission has nothing to be held BY.  Before T-126 this was E-50030, "permission
-- denied", which sent a UI hunting for a missing grant when the answer was "this user is wearing no hat yet, show the
-- chooser".  The context is established explicitly here because auth.uspDemandPermission reads SESSION_CONTEXT and
-- takes no token: its callers are procedures, which have set the context already.
EXEC auth.uspSetSessionContext @SessionTokenHash = @Tok;

BEGIN TRY
    EXEC auth.uspDemandPermission @PermissionCode = N'Data.Read', @TenantId = @Root
                                , @ObjectName = N'080_error_catalogue section 12A';
    INSERT @R (Want, Case_, Got, Msg) VALUES (50032, N'uspDemandPermission, the session is wearing no profile', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50032, N'uspDemandPermission, the session is wearing no profile', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- 12A e.  E-50127, and it has to be probed BEFORE the factor is enrolled: nothing confirmed means nothing the reported
-- step could have been verified against.  It is also the one refusal in this family that is NOT counted as a failed
-- step-up, which matters for the two probes after it -- no factor was presented, so there is nothing to throttle.
BEGIN TRY
    EXEC auth.uspElevateSession @SessionTokenHash = @Tok, @TimeStep = @Step, @ElevatedUntilUtc = @Until OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50127, N'uspElevateSession, no confirmed factor of that type', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50127, N'uspElevateSession, no confirmed factor of that type', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- 12A f.  The factor, written directly rather than through auth.uspEnrolMfaFactor and auth.uspConfirmMfaFactor.  The
-- reason is the same one that makes section 1 write a credential directly: confirming a factor means presenting a code
-- computed from the secret, and computing that code is the application's job and cannot be done in T-SQL.
INSERT auth.UserMfaFactor (UserId, FactorType, SecretCiphertext, KeyReference, IsConfirmed, ConfirmedUtc
                         , auditCreatedBy, auditModifiedBy)
SELECT @AdminId, 'Totp', 0x303830206572726361742070726F6265, N'dev:local/authn-mfa-kek#v1', 1, SYSUTCDATETIME ()
     , N'080_error_catalogue probe 50128', N'080_error_catalogue probe 50128'
 WHERE NOT EXISTS (SELECT 1 FROM auth.UserMfaFactor AS f
                    WHERE f.UserId = @AdminId AND f.FactorType = 'Totp' AND f.IsDeleted = 0);

-- 12A g.  E-50128, ONE FEWER TIMES THAN THE THRESHOLD, and the arithmetic is the whole point of this comment.  Step 1 is
-- the first thirty seconds of 1970 and is therefore outside Authn.TotpWindowSteps of anything, which is a refusal the
-- database can reach on its own arithmetic and with no secret.
--
-- THE THRESHOLD-th REFUSAL IS THE ONE THAT REVOKES, NOT THE ONE AFTER IT.  auth.uspElevateSession writes the MfaFailed
-- row for the refusal it is currently making and THEN counts the rows, so the count it compares to the threshold
-- INCLUDES the attempt in hand.  A loop of five followed by a sixth attempt therefore does not probe E-50129 at all:
-- the fifth iteration raises it, unasserted and unseen because only the first iteration is recorded, and the sixth
-- attempt then meets E-50126 because the session it names has already been revoked.  That is exactly what this probe
-- did on its first run -- it reported 50126 where it wanted 50129 -- and the fix is to leave the counter one short.
--
-- Read from config rather than written as a literal, because a deployment that tightens the threshold must not turn this
-- probe into a false failure, and one that disables it must say so rather than time out on a refusal that never comes.
SET @Left = COALESCE (TRY_CAST ((SELECT SettingValue FROM config.ApplicationSetting
                                  WHERE SettingKey = N'Authn.LockoutThreshold'
                                    AND IsDeleted  = 0) AS INT), 5) - 1;

IF @Left < 1
BEGIN
    SET @Fail = CONCAT (N'Authn.LockoutThreshold resolves to ', @Left + 1, N', so there is no way to reach E-50129 with '
                      , N'a session still alive to be revoked: at 0 the step-up throttle is disabled by design, and at '
                      , N'1 the first refusal revokes the session before E-50128 can be probed at all. Set it to 2 or '
                      , N'more, or move E-50129 to the @Accounted list in section 14 with this as the reason.');

    ;THROW 50000, @Fail, 1;
END;

SET @Loops = @Left;

WHILE @Left > 0
BEGIN
    BEGIN TRY
        EXEC auth.uspElevateSession @SessionTokenHash = @Tok, @TimeStep = 1, @ElevatedUntilUtc = @Until OUTPUT;

        IF @Left = @Loops
            INSERT @R (Want, Case_, Got, Msg)
            VALUES (50128, N'uspElevateSession, the step is outside the window', NULL, N'NO ERROR');
    END TRY
    BEGIN CATCH
        IF @Left = @Loops
            INSERT @R (Want, Case_, Got, Msg)
            VALUES (50128, N'uspElevateSession, the step is outside the window', ERROR_NUMBER ()
                  , LEFT (ERROR_MESSAGE (), 300));

        -- Any iteration after the first that does NOT raise 50128 has moved the state the next probe depends on, and
        -- silence here is what made the first run of this section report the wrong number with no clue why.
        IF @Left < @Loops AND ERROR_NUMBER () <> 50128
            INSERT @R (Want, Case_, Got, Msg)
            VALUES (50128, N'uspElevateSession, a counter-filling refusal changed number', ERROR_NUMBER ()
                  , LEFT (ERROR_MESSAGE (), 300));
    END CATCH

    SET @Left = @Left - 1;
END;

-- 12A h.  E-50129.  This is the Authn.LockoutThreshold-th refusal: it finds its own MfaFailed row plus the ones 12A g
-- left, reaches the threshold, and revokes THE SESSION rather than locking the account -- deliberately, because a
-- step-up brute force is evidence about one stolen token, and locking the account would let whoever holds that token
-- deny service to its owner.  Nothing after this point may use @Tok: it names a session that no longer exists.
BEGIN TRY
    EXEC auth.uspElevateSession @SessionTokenHash = @Tok, @TimeStep = 1, @ElevatedUntilUtc = @Until OUTPUT;
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50129, N'uspElevateSession, past Authn.LockoutThreshold on this session', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50129, N'uspElevateSession, past Authn.LockoutThreshold on this session', ERROR_NUMBER ()
          , LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- The factor goes back, OUTSIDE any TRY and BEFORE the assertion below, for the same reason section 2e puts
-- RequireMfaForLocal back: a run that left it behind would make section 2e's E-50110 probe unreachable on every later
-- run, and E-50110 is the number that proves an account with nothing enrolled cannot sign in where MFA is required.
-- Putting it before the THROW means a FAILING run restores it too.
UPDATE auth.UserMfaFactor
   SET IsDeleted            = 1
     , auditDeletedBy       = N'080_error_catalogue restore 50128'
     , auditDeletedDateUtc  = SYSUTCDATETIME ()
     , auditModifiedBy      = N'080_error_catalogue restore 50128'
     , auditModifiedDateUtc = SYSUTCDATETIME ()
 WHERE UserId         = @AdminId
   AND auditCreatedBy = N'080_error_catalogue probe 50128'
   AND IsDeleted      = 0;

SELECT Probe = r.RowNo, Expected = r.Want, Actual = r.Got, Probed = r.Case_, Message = r.Msg
  FROM @R AS r ORDER BY r.RowNo;

IF EXISTS (SELECT 1 FROM @R AS r WHERE r.Got IS NULL OR r.Got <> r.Want)
BEGIN
    SELECT @Fail = CONCAT (N'Connection 7 probes did not raise their registered numbers: '
                         , STRING_AGG (CAST (x.Want AS NVARCHAR (10)), N' ') WITHIN GROUP (ORDER BY x.Want)
                         , N'.  Nothing after this point ran, so the coverage report in section 14 has not made any '
                         , N'claim about these numbers.')
      FROM (SELECT DISTINCT r.Want FROM @R AS r WHERE r.Got IS NULL OR r.Got <> r.Want) AS x;

    ;THROW 50000, @Fail, 1;
END

PRINT '12A. The step-up family: E-50125, E-50126, E-50032, E-50127, E-50128 and E-50129, all raising the registered number.';
GO

-- ======================================================================================================================
-- Connection 8.  The demo domain, and then the coverage report.
--
-- This connection sets BypassRowSecurity BEFORE it does anything else, and the reason is narrow: section 13 has to read
-- dbo.CaseFile by key and UPDATE it by key from OUTSIDE any procedure, and config.TenantScopedTable registers dbo.CaseFile
-- and dbo.CaseNote as the only two tables the policy binds -- so without the bypass those statements see no rows at all
-- and the immutability trigger never fires.  The bypass suppresses the RLS PREDICATE and nothing else: every procedure
-- called below still establishes its own context and still demands its own permissions, which is why the numbers it
-- raises are the numbers a real caller would get.
-- ======================================================================================================================
:connect $(SQLCMDSERVER)

USE [$(DbName)];
SET NOCOUNT ON;
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
GO

PRINT '========================================================================================================';
PRINT '080_error_catalogue.sql -- connection 8: the demo domain, and the coverage report';
PRINT '========================================================================================================';
GO

EXEC sys.sp_set_session_context @key = N'BypassRowSecurity', @value = 1;
GO

DECLARE @R TABLE (RowNo  INT IDENTITY (1,1) PRIMARY KEY
                , Want   INT            NOT NULL
                , Case_  NVARCHAR (130) NOT NULL
                , Got    INT            NULL
                , Msg    NVARCHAR (300) NULL);

DECLARE @Tok      VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)-admin')
      , @App      INT = (SELECT a.ApplicationId FROM auth.Application AS a
                          WHERE a.ApplicationCode = N'TEMPLATE' AND a.IsDeleted = 0)
      , @Root     INT
      , @A        INT
      , @Case     INT
      , @Case2    INT
      , @NewCase  INT
      , @Note     BIGINT
      , @Closed   INT
      , @Reassigned BIT
      , @Fail     NVARCHAR (2000);

SELECT @Root = t.TenantId FROM auth.Tenant AS t
 WHERE t.ApplicationId = @App AND t.TenantCode = N'ROOT' AND t.IsDeleted = 0;

SELECT @A = t.TenantId FROM auth.Tenant AS t
 WHERE t.ApplicationId = @App AND t.TenantCode = N'ERRCAT_A' AND t.IsDeleted = 0;

-- 13a.  E-50206 covers "a case file needs a number and a title", and both parameters are tested together because either
-- one missing is the same mistake.  CK_dbo_CaseFile_CaseNumber would refuse it anyway; this names the parameter.
BEGIN TRY
    EXEC dbo.uspCreateCaseFile @SessionTokenHash = @Tok, @CaseNumber = N'   ', @Title = N'   '
                             , @CaseFileId = @NewCase OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50206, N'uspCreateCaseFile, blank case number and title', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50206, N'uspCreateCaseFile, blank case number and title', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- 13b.  One case file, at ROOT, created through the procedure.  It ends this section approved and closed, which is
-- exactly the state the next run of this file needs to find -- see the comments on E-50202 and E-50204.
IF NOT EXISTS (SELECT 1 FROM dbo.CaseFile AS cf
                WHERE cf.TenantId = @Root AND cf.CaseNumber = N'ERRCAT-CASE-1' AND cf.IsDeleted = 0)
    EXEC dbo.uspCreateCaseFile @SessionTokenHash = @Tok, @CaseNumber = N'ERRCAT-CASE-1'
                             , @Title = N'Error Catalogue Case One', @CaseFileId = @NewCase OUTPUT;

SELECT @Case = cf.CaseFileId FROM dbo.CaseFile AS cf
 WHERE cf.TenantId = @Root AND cf.CaseNumber = N'ERRCAT-CASE-1' AND cf.IsDeleted = 0;

BEGIN TRY
    EXEC dbo.uspCreateCaseFile @SessionTokenHash = @Tok, @CaseNumber = N'ERRCAT-CASE-1'
                             , @Title = N'A Second Case With The Same Number', @CaseFileId = @NewCase OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50200, N'uspCreateCaseFile, case number already used at this tenant', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50200, N'uspCreateCaseFile, case number already used at this tenant', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- E-50207 is the status vocabulary, and it is checked in the PROCEDURE as well as by CK_dbo_CaseFile_CaseStatus because a
-- constraint violation tells the caller a constraint name and this tells them the six values.
BEGIN TRY
    EXEC dbo.uspUpdateCaseFile @SessionTokenHash = @Tok, @CaseFileId = @Case
                             , @Title = N'Error Catalogue Case One', @CaseStatus = 'frobnicated';
    INSERT @R (Want, Case_, Got, Msg) VALUES (50207, N'uspUpdateCaseFile, a status outside the six', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50207, N'uspUpdateCaseFile, a status outside the six', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- E-50208 is an OPERATION's bounds rather than a row's, and it is the only number in this section raised by a
-- procedure that is not CRUD: dbo.uspCloseApprovedCaseFiles sweeps one tenant's approved case files closed, and T-129
-- added it because Data.Execute was a permission nothing granted and nothing demanded (G-45).  The probe asks for 4,000
-- days, past the ten-year ceiling the procedure sets, because a units mistake -- months or hours where days were meant
-- -- is the failure that bound is really there to catch.  It reaches the bound at all only because the fixture holds
-- OPERATOR: both permission demands come first, and an actor without Data.Execute meets E-50030 and never gets as far as
-- the validation.
BEGIN TRY
    EXEC dbo.uspCloseApprovedCaseFiles @SessionTokenHash = @Tok, @OlderThanDays = 4000, @MaxCaseFiles = 10
                                     , @CaseFilesClosed = @Closed OUTPUT;
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50208, N'uspCloseApprovedCaseFiles, @OlderThanDays past the ceiling', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50208, N'uspCloseApprovedCaseFiles, @OlderThanDays past the ceiling', ERROR_NUMBER ()
          , LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- E-50201 deliberately conflates "no such case", "not yours" and "deleted", and the procedures say why: row-level
-- security removed the other tenants' rows before the procedure looked, so it CANNOT tell them apart and inventing three
-- numbers would be inventing information.  A caller who could tell them apart could count another tenant's cases.
BEGIN TRY
    EXEC dbo.uspGetCaseFile @SessionTokenHash = @Tok, @CaseFileId = 999999;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50201, N'uspGetCaseFile, no such case file', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50201, N'uspGetCaseFile, no such case file', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

BEGIN TRY
    EXEC dbo.uspReassignCaseFile @SessionTokenHash = @Tok, @CaseFileId = @Case, @AssignedToProfileId = 999999
                               , @Reassigned = @Reassigned OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50203, N'uspReassignCaseFile, the target profile cannot take it', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50203, N'uspReassignCaseFile, the target profile cannot take it', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- 13c.  E-50202 needs the case approved already, so it is approved if it is not.  ApprovedByProfileId is write-once
-- (E-50010), which is the reason a second approval is refused rather than overwritten: an approval that can be
-- reattributed is not an approval.
IF EXISTS (SELECT 1 FROM dbo.CaseFile AS cf WHERE cf.CaseFileId = @Case AND cf.ApprovedUtc IS NULL)
    EXEC dbo.uspApproveCaseFile @SessionTokenHash = @Tok, @CaseFileId = @Case
                              , @ApprovalNote = N'Approved by _tests/080_error_catalogue.sql to make E-50202 reachable.';

BEGIN TRY
    EXEC dbo.uspApproveCaseFile @SessionTokenHash = @Tok, @CaseFileId = @Case
                              , @ApprovalNote = N'Probing the second approval.';
    INSERT @R (Want, Case_, Got, Msg) VALUES (50202, N'uspApproveCaseFile, it is already approved', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50202, N'uspApproveCaseFile, it is already approved', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- 13d.  E-50204, and closing the case is what makes it reachable.  A closed case takes no more notes because the note
-- would be a change to a record the organization has finished with, and there is no trail entry that would explain it.
IF EXISTS (SELECT 1 FROM dbo.CaseFile AS cf WHERE cf.CaseFileId = @Case AND cf.CaseStatus <> 'closed')
    EXEC dbo.uspUpdateCaseFile @SessionTokenHash = @Tok, @CaseFileId = @Case
                             , @Title = N'Error Catalogue Case One', @CaseStatus = 'closed';

BEGIN TRY
    EXEC dbo.uspAddCaseNote @SessionTokenHash = @Tok, @CaseFileId = @Case
                          , @NoteText = N'A note on a closed case.', @CaseNoteId = @Note OUTPUT;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50204, N'uspAddCaseNote, the case file is closed', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50204, N'uspAddCaseNote, the case file is closed', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

BEGIN TRY
    EXEC dbo.uspRestoreCaseFile @SessionTokenHash = @Tok, @CaseFileId = @Case;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50205, N'uspRestoreCaseFile, it was never deleted', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50205, N'uspRestoreCaseFile, it was never deleted', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

-- 13e.  E-50011, and this is the one statement in the file that needs the bypass set above.  dbo.CaseFile.TenantId is
-- immutable because the RLS predicate reads it: moving a case between tenants would move it out of one organization's
-- sight and into another's with no trail row that says so, and the audit trail references the row by key either way.
--
-- IT IS PROBED ON A SECOND, UNTOUCHED CASE FILE, AND THAT IS A FINDING RATHER THAN TIDINESS.  Run on ERRCAT-CASE-1 the
-- statement raises Msg 547 on FK_dbo_CaseFile_ApprovedBy_Tenant instead of E-50011: the approval wrote a
-- (TenantId, ApprovedByProfileId) pair, the composite foreign key is checked BEFORE any AFTER trigger fires, and the
-- trigger that owns the sharper message never runs.  So the trigger's number is reachable only while the row holds no
-- composite reference -- which for a case file means unapproved and unassigned.  A DECLARATIVE constraint will always
-- win this race, and any table whose immutability message lives in a trigger has the same hole in it.
IF NOT EXISTS (SELECT 1 FROM dbo.CaseFile AS cf
                WHERE cf.TenantId = @Root AND cf.CaseNumber = N'ERRCAT-CASE-2' AND cf.IsDeleted = 0)
    EXEC dbo.uspCreateCaseFile @SessionTokenHash = @Tok, @CaseNumber = N'ERRCAT-CASE-2'
                             , @Title = N'Error Catalogue Case Two, Never Approved And Never Assigned'
                             , @CaseFileId = @NewCase OUTPUT;

SELECT @Case2 = cf.CaseFileId FROM dbo.CaseFile AS cf
 WHERE cf.TenantId = @Root AND cf.CaseNumber = N'ERRCAT-CASE-2' AND cf.IsDeleted = 0;

BEGIN TRY
    UPDATE dbo.CaseFile SET TenantId = @A WHERE CaseFileId = @Case2;
    INSERT @R (Want, Case_, Got, Msg) VALUES (50011, N'trg_au_updt_CaseFile, TenantId is immutable', NULL, N'NO ERROR');
END TRY
BEGIN CATCH
    INSERT @R (Want, Case_, Got, Msg)
    VALUES (50011, N'trg_au_updt_CaseFile, TenantId is immutable', ERROR_NUMBER (), LEFT (ERROR_MESSAGE (), 300));
END CATCH

SELECT r.RowNo
     , r.Want
     , CASE WHEN r.Got = r.Want THEN 'PASS' ELSE 'FAIL' END AS Verdict
     , r.Got
     , r.Case_
  FROM @R AS r
 ORDER BY r.RowNo;

IF EXISTS (SELECT 1 FROM @R AS r WHERE r.Got IS NULL OR r.Got <> r.Want)
BEGIN
    SELECT r.RowNo, r.Want, r.Got, r.Case_, r.Msg FROM @R AS r
     WHERE r.Got IS NULL OR r.Got <> r.Want
     ORDER BY r.RowNo;

    SELECT @Fail = CONCAT (N'Connection 8 probes did not raise their registered numbers: '
                         , STRING_AGG (CAST (x.Want AS NVARCHAR (10)), N' ') WITHIN GROUP (ORDER BY x.Want)
                         , N'.  The coverage report below did not run, so it has not made any claim about these numbers.')
      FROM (SELECT DISTINCT r.Want FROM @R AS r WHERE r.Got IS NULL OR r.Got <> r.Want) AS x;

    ;THROW 50000, @Fail, 1;
END

DECLARE @Count  INT = (SELECT COUNT (*) FROM @R)
      , @Proved NVARCHAR (1000) = (SELECT STRING_AGG (CAST (x.Want AS NVARCHAR (10)), N' ') WITHIN GROUP (ORDER BY x.Want)
                                     FROM (SELECT DISTINCT Want FROM @R) AS x);

PRINT CONCAT ('13.  ', @Count, ' probes, all raising the registered number.  Numbers proved: ', @Proved);
GO

-- ----------------------------------------------------------------------------------------------------------------------
-- 14. The coverage report, and the only part of this file that makes a claim about numbers it did not raise itself.
--
-- Three sets are compared.
--
--   THROWABLE   every distinct 5xxxx number that appears in sys.sql_modules in the house ';THROW <n>, @Var, 1;' form.
--               The leading semicolon is what makes the harvest trustworthy: procedure headers in this database quote
--               their own error numbers in prose, and searching for 'THROW 5' matches those sentences as well as the
--               statements.  The semicolon only ever appears where a statement does.
--
--   OBSERVED    every distinct 5xxxx number logs.ExecutionLog has EVER recorded, across every run of every test and
--               every hand call since the database was built.  Rule 8 instrumentation writes that column in the CATCH
--               block of every procedure, which makes the log an accidental coverage ledger and a very good one: it
--               cannot be fooled by a test that asserts a number without provoking it.
--
--   PROBED      the numbers THIS RUN raised on purpose, listed literally below.  The list needs no cross-connection
--               plumbing to be sound, and the header explains why: every connection THROWs on the first mismatch and
--               sqlcmd -b ends the run, so this section can only be executing if all 103 probes matched.
--
-- What the report then asserts is one thing, and it is the thing worth asserting: every throwable number is either in the
-- ledger or on the list of numbers that CANNOT be in the ledger, with a reason.  A new unaccounted number is either a new
-- error path nothing tests or a number a procedure can no longer raise, and both are worth a failed test run.
-- ----------------------------------------------------------------------------------------------------------------------
DECLARE @Throwable TABLE (ErrorNumber INT PRIMARY KEY);
DECLARE @Probed    TABLE (ErrorNumber INT PRIMARY KEY);
-- 1000 and not 400, because the reasons added for E-50166 and E-50209 are longer than that and truncation here is the
-- one failure mode this table must not have: a reason that is cut off mid-sentence is a reason nobody can evaluate, and
-- the whole point of this list is that an unprobed number is accounted for in words a reader can disagree with.
DECLARE @Accounted TABLE (ErrorNumber INT PRIMARY KEY, Reason NVARCHAR (1000) NOT NULL);

-- STRING_SPLIT takes a SINGLE character, so the seven-character marker is swapped for NCHAR (1) -- a character no SQL
-- source file contains -- and the split then yields one fragment per throw site, each beginning with its number.
INSERT @Throwable (ErrorNumber)
SELECT DISTINCT TRY_CAST (LEFT (s.value, 5) AS INT)
  FROM sys.sql_modules AS m
 CROSS APPLY STRING_SPLIT (REPLACE (m.definition, N';THROW ', NCHAR (1)), NCHAR (1)) AS s
 WHERE TRY_CAST (LEFT (s.value, 5) AS INT) BETWEEN 50000 AND 59999;

INSERT @Probed (ErrorNumber)
VALUES (50000), (50010), (50011), (50012), (50020), (50021), (50022), (50023), (50024), (50030), (50040), (50041)
     , (50042), (50044), (50045), (50046), (50047), (50050), (50051), (50052), (50060), (50062), (50063), (50064)
     , (50065), (50067), (50081), (50082), (50083), (50084), (50090), (50091), (50092), (50093), (50094), (50095)
     , (50068), (50097), (50098), (50100), (50101), (50102), (50103), (50104)
     , (50105), (50106), (50107), (50110), (50124), (50130), (50131), (50132), (50133), (50134), (50135), (50140), (50150)
     , (50151), (50152), (50153), (50154), (50155), (50160), (50161), (50162), (50163), (50164), (50165), (50170)
     , (50171), (50172), (50173), (50174), (50175), (50176), (50177), (50178), (50179), (50180), (50190), (50191), (50192)
     , (50193), (50194), (50195), (50196), (50200), (50201), (50202), (50203), (50204), (50205), (50206), (50207)
     , (50223), (50230)
     -- T-125, T-126 and T-129 arrivals. The step-up family and E-50032 are section 12A; E-50208 is section 13, and it
     -- is the reason the fixture holds OPERATOR.
     , (50032), (50125), (50126), (50127), (50128), (50129), (50208);

INSERT @Accounted (ErrorNumber, Reason)
VALUES (50010, N'Raised by the immutability triggers, which carry no rule 8 instrumentation: a trigger has no CATCH '
             + N'block to write logs.ExecutionLog from, so this number can never enter the ledger. Proved by probe in '
             + N'section 9 instead.')
     , (50011, N'Raised by auth.trg_au_updt_CaseFile and trg_au_updt_CaseNote. Same reason as E-50010, and proved by '
             + N'probe in section 13 -- on an unapproved case file, because the composite foreign key otherwise wins the '
             + N'race with Msg 547.')
     , (50012, N'Raised by auth.trg_au_updt_Role for INV-10. Same reason as E-50010, proved by probe in section 9.')
     , (50043, N'UNREACHABLE. INV-05 clause 4 in auth.uspAssignRoleToProfile, and clause 3 (E-50042) asks '
             + N'auth.TenantClosure the same question one test earlier: the closure never holds a cross-application '
             + N'pair, so a role whose owner is in another application dies at E-50042 and nothing reaches clause 4. '
             + N'A finding of this file, not a gap in it.')
     , (50096, N'UNREACHABLE. auth.uspUpdateTenant demands Tenant.Update at the PROPOSED PARENT before it compares '
             + N'applications, and no profile can hold a permission at a tenant outside its own application''s closure, '
             + N'so a cross-application move is always E-50030 first. Section 5 proves the E-50030 instead.')
     , (50141, N'auth.uspRebuildTenantAccessPolicy''s check on its own work: it fires only when the rebuild it has just '
             + N'performed did not take effect. No caller can ask for that, and a test that could provoke it would have '
             + N'to break the security policy it is testing.')
     , (50166, N'A RACE, and a narrow one: auth.uspListMyProfiles read the session through auth.uspSetSessionContext one '
             + N'statement earlier and cannot read the row back. Reaching it means ending that session from another '
             + N'connection inside that window, which no test can time reliably, and which is exactly the situation the '
             + N'number exists to describe. T-126 added it so a caller in that race is told "sign in again" rather than '
             + N'handed an empty list, which reads as "you have no profiles".')
     , (50209, N'dbo.uspCloseApprovedCaseFiles checking its own work: it fires when the sweep closed N case files but '
             + N'wrote a number of audit rows that is not N, and it rolls the batch back. Reaching it means breaking the '
             + N'UPDATE''s OUTPUT clause first, which is the statement being asserted -- a test that edited it would be '
             + N'measuring the edit. It is here because a set-based writer that silently under-logs is the exact failure '
             + N'logs.uspRecordDataChange''s notes warn about, and an assertion is cheaper than a code review.');

DECLARE @CountThrowable INT = (SELECT COUNT (*) FROM @Throwable)
      , @CountObserved  INT = (SELECT COUNT (DISTINCT el.ErrorNumber) FROM logs.ExecutionLog AS el
                                WHERE el.ErrorNumber BETWEEN 50000 AND 59999)
      , @CountProbed    INT = (SELECT COUNT (*) FROM @Probed)
      , @CountAccounted INT = (SELECT COUNT (*) FROM @Accounted)
      , @Unaccounted    NVARCHAR (1000)
      , @NotThrowable   NVARCHAR (1000)
      , @ReportFailure  NVARCHAR (2000);

SELECT t.ErrorNumber
     , CASE WHEN EXISTS (SELECT 1 FROM logs.ExecutionLog AS el WHERE el.ErrorNumber = t.ErrorNumber)
            THEN 'in the ledger'
            WHEN EXISTS (SELECT 1 FROM @Accounted AS a WHERE a.ErrorNumber = t.ErrorNumber)
            THEN 'accounted for'
            ELSE 'UNACCOUNTED' END                                                            AS LedgerStatus
     , CASE WHEN EXISTS (SELECT 1 FROM @Probed AS p WHERE p.ErrorNumber = t.ErrorNumber)
            THEN 'probed here' ELSE '' END                                                    AS ThisFile
     , COALESCE ((SELECT a.Reason FROM @Accounted AS a WHERE a.ErrorNumber = t.ErrorNumber), N'') AS Reason
  FROM @Throwable AS t
 ORDER BY t.ErrorNumber;

SELECT @Unaccounted = STRING_AGG (CAST (x.ErrorNumber AS NVARCHAR (10)), N' ') WITHIN GROUP (ORDER BY x.ErrorNumber)
  FROM (SELECT t.ErrorNumber FROM @Throwable AS t
         WHERE NOT EXISTS (SELECT 1 FROM logs.ExecutionLog AS el WHERE el.ErrorNumber = t.ErrorNumber)
           AND NOT EXISTS (SELECT 1 FROM @Accounted AS a WHERE a.ErrorNumber = t.ErrorNumber)) AS x;

-- The other direction, reported rather than asserted: a number in the ledger that the harvest did not find.  At the time
-- of writing there is exactly one, E-50099, and it is honest about the harvest's limits -- util.uspPhase0Probe is created
-- by _tests/010_phase0_instrumentation.sql rather than by a shipped script, and it writes THROW without the leading
-- semicolon, so the pattern that makes the harvest trustworthy is also the pattern that misses it.
SELECT @NotThrowable = STRING_AGG (CAST (x.ErrorNumber AS NVARCHAR (10)), N' ') WITHIN GROUP (ORDER BY x.ErrorNumber)
  FROM (SELECT DISTINCT el.ErrorNumber FROM logs.ExecutionLog AS el
         WHERE el.ErrorNumber BETWEEN 50000 AND 59999
           AND NOT EXISTS (SELECT 1 FROM @Throwable AS t WHERE t.ErrorNumber = el.ErrorNumber)) AS x;

PRINT '';
PRINT '14.  Coverage of Appendix B, measured rather than asserted';
PRINT '     ---------------------------------------------------------------------------------------------------';
PRINT CONCAT ('     Throwable from sys.sql_modules in the house idiom ....... ', @CountThrowable);
PRINT CONCAT ('     Ever recorded in logs.ExecutionLog ..................... ', @CountObserved);
PRINT CONCAT ('     Raised on purpose by this file ......................... ', @CountProbed);
PRINT CONCAT ('     Throwable but unobservable, with a reason .............. ', @CountAccounted);
PRINT CONCAT ('     Throwable, unobserved and unaccounted for .............. ', COALESCE (@Unaccounted, N'none'));
PRINT CONCAT ('     In the ledger but outside the harvest .................. ', COALESCE (@NotThrowable, N'none'));
PRINT '';
PRINT '     Numbers raised by SCRIPTS rather than modules are outside the harvest by construction, because a script';
PRINT '     leaves nothing in sys.sql_modules: E-50080, E-50085, E-50086 and E-50087 in 900_bootstrap_first_admin.sql,';
PRINT '     and E-50210 and E-50211 in 135_audit_triggers.sql. No file under _tests raises any of the six, and none of';
PRINT '     them is a refusal a CALLER can meet -- the four bootstrap numbers are what a second bootstrap or an';
PRINT '     out-of-order install is told, and the two audit numbers are 135 asserting its own triggers at install time.';
PRINT '     A database this file can run against at all is one where 135 did not throw, and a database with profiles in';
PRINT '     it is one where a second bootstrap would raise E-50080. They are proved by the install, not by a test.';
PRINT '';
PRINT '     Three more numbers are in the ledger without being raised here, and each has one place that does raise it:';
PRINT '     E-50220, E-50221 and E-50222 are the password-change refusals, and _tests/040_identity_and_authn.sql';
PRINT '     section 13 provokes all three on an account whose whole fixture exists for them. E-50224 is 110''s own';
PRINT '     closing report, which probes it on every deployment. E-50230 is probed BOTH here and by 150''s closing';
PRINT '     report, and the duplication is deliberate: the report proves the number exists, and section 2j proves it is';
PRINT '     raised before the session is resolved. A number observed on every install is not a number this file has to';
PRINT '     raise -- but it is a number somebody has to, and the sentence above says who.';
PRINT '';

IF @Unaccounted IS NOT NULL
BEGIN
    SET @ReportFailure = CONCAT (N'Coverage gap: ', @Unaccounted, N' can be thrown by a shipped module, has never been '
                               , N'recorded in logs.ExecutionLog, and is not on this file''s list of numbers that '
                               , N'cannot be. Either a new error path arrived without a probe, or a number that used to '
                               , N'be reachable no longer is. Both are worth reading the procedure over.');
    ;THROW 50000, @ReportFailure, 1;
END;

PRINT 'PASS  080_error_catalogue: every number a shipped module can throw is either in the ledger or accounted for.';
GO
