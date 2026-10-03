/***********************************************************************************************************************
Script:         S1_load_agency.sql
Purpose:        Build ONE state agency and its counties at the population test_scenario_1.txt describes -- an agency of
                170 users over 67 jurisdictions carrying 12,660 more, ~12,830 people and ~30,490 profiles in a single
                run -- so that the four scenario runs measure the shipped objects against a real government shape
                rather than against a fixture.
Task:           T-122.
Run with:       sqlcmd -S MDE-55TT2J4 -E -d <db> -I -C -b
                       -v DbName=<db> -v Seed=<unique-text-no-spaces>
                       -v AgencyCode=DEP -v AgencyName=Department_of_Environmental_Protection
                       -v CountyCount=67 -v Wave=w1
                       -i database/_scenarios/S1_load_agency.sql
Author:         Template project
CreateDate:     2026-09-21

NOT PART OF THE INSTALL MANIFEST.  Install-TemplateDatabase.ps1 does not know this file exists and must not: it writes
tens of thousands of rows into auth.[User] and auth.UserProfile, and a template that shipped a state agency's staff list
as seed data would be a template nobody could deploy.

WHY THIS IS DIRECT DML, AND WHAT THAT COSTS
-------------------------------------------
Same division of labour database/_perf/T069_load_volumes.sql sets out and for the same reason, restated here because a
reader who finds this file first must not mistake it for a test of the procedure surface.  This script is a SET
GENERATOR.  It bypasses auth.uspCreateTenant, auth.uspCreateUser, auth.uspCreateProfile and auth.uspAssignRoleToProfile
entirely, and it therefore proves NOTHING about any of them.

The reason is arithmetic, not taste.  30,490 profiles through auth.uspCreateProfile is 30,490 round trips, each one
opening a transaction, resolving a permission, writing a logs.ExecutionLog pair and rebuilding a permission scope; T069
measured that shape at four to six hours for 5,000 profiles.  Four scenario runs would be a fortnight.

What proves the procedures is the OTHER half: database/_scenarios/S1_prove_duties.sql takes a sample out of every cohort
this file creates and makes it sign in, switch hats repeatedly and do the demo domain's work THROUGH THE PROCEDURES
ONLY.  A cohort that this file can generate but that file cannot exercise is a finding, and the two files together are
the test.  Neither alone is.

WHAT "RANDOMLY SELECTED" MEANS HERE
-----------------------------------
The scenario asks for randomly picked counties three times -- ten for the agency's CRUD switchers, twenty for the
dual-county cohort, ten for the eleven-county cohort.  A test whose population changes on every run cannot be argued
about after it fails, so the selection is SEEDED rather than random: counties are ordered by
CHECKSUM (HASHBYTES ('SHA2_256', @Seed + county code)), which is arbitrary with respect to county number and identical
on every run with the same -v Seed.  Change the seed and the picks change; keep it and the failure reproduces.

The three selections are made DISJOINT by taking successive bands of that one order -- ranks 1-20, 21-30, and partner
bands above rank 30.  The scenario does not require disjointness and reality would not have it.  It is done because the
profile arithmetic is the assertion this file is checked against: overlapping bands would leave "20 users with 4
profiles" and "20 users with 22 profiles" resident in one county, and a count that came out wrong could then be either a
bug or the overlap, with nothing to say which.  CountyCount must therefore be at least 60, and the script refuses below
that rather than silently building a smaller shape.

THE COHORTS, AND THE ARITHMETIC THEY HAVE TO ADD UP TO
-----------------------------------------------------
Agency-resident, nine cohorts, from the scenario's lines in order.  "Profiles" is per user:

  D1  10 users   1 profile    READ_ONLY at the agency.  No switching -- one profile is what makes that true.
  D2  20 users   1+N          READ_ONLY at the agency and at every county.
  D3  20 users   1            CRUD_ACCESS at the agency.
  D4  50 users   1+N          CRUD_ACCESS at the agency and at every county.
  D5  10 users   1            PROFILE_ASSIGNER + USER_ADMIN + PLATFORM_ADMIN, and IsPlatformAdmin = 1.
  D6  10 users   1            PROFILE_ASSIGNER + READ_ONLY.
  D7  20 users   1            PROFILE_ASSIGNER + CRUD_ACCESS.
  D8  10 users   1+N          PROFILE_ASSIGNER at the agency and at every county.
  D9  20 users   1+10         CRUD_ACCESS at the agency and at ten seeded counties.

County-resident, six cohorts, per county:

  C1  20 users   1            READ_ONLY at home.
  C2  50 users   1            CRUD_ACCESS at home.
  C3  10 users   1            PROFILE_ASSIGNER + USER_ADMIN at home.  NOT IsPlatformAdmin -- see below.
  C4 100 users   2            READ_ONLY and CRUD_ACCESS at home, which is what "can switch between" means.
  C5  20 users   4            in the 20 seeded counties only: READ_ONLY and CRUD_ACCESS at home and at one partner.
  C6  20 users   22           in the 10 seeded counties only: the same pair at home and at ten partners.

At CountyCount = 67 that is 170 + 12,660 = 12,830 users and 5,730 + 24,760 = 30,490 profiles, and the script's closing
report asserts both numbers rather than printing them.  "Nearly 13,000" in the scenario is 12,830.

C3 IS NOT A PLATFORM ADMIN AND D5 IS, WHICH IS A READING OF THE SCENARIO AND NOT A TYPO.  The two lines describe the
same four abilities in the same words, and only the agency's line ends "These are platform admins."  So D5 gets
auth.[User].IsPlatformAdmin = 1 and the PLATFORM_ADMIN role; C3 gets the same profile-administration reach inside its own
county and no platform flag at all.  If that reading is wrong the fix is one INSERT, but the distinction is the whole
difference between an agency that can bypass row security and a county that cannot, so it is made explicitly.

TWO ROLES THIS FILE USED TO CREATE AND NOW REQUIRES
--------------------------------------------------
The scenario's two load-bearing nouns are "CRUD access profile" -- read, update, insert, soft delete and execute -- and
"can assign profiles".  On 2026-09-21 database/115_seed_reference_data.sql shipped neither, this file created both by
hand to place a single profile, and that failure to express the scenario in seeded roles WAS gaps G-46 and G-47 -- found
before one row was inserted.

  CRUD_ACCESS       Data.Read, Data.Insert, Data.Update, Data.SoftDelete, Data.Execute.  The seeded pool got close and
                    missed: CONTRIBUTOR is read and insert, EDITOR is read and update, DATA_STEWARD is read, update,
                    soft delete AND RESTORE, OPERATOR is read and execute.  Assembling CRUD out of those takes three
                    roles and brings Data.Restore along uninvited -- so every "CRUD" user in the estate would also be
                    able to undelete, which is not what the scenario says and not what an agency means.
  PROFILE_ASSIGNER  Authz.ProfileRead, Authz.ProfileCreate, Authz.ProfileUpdate, Authz.RoleRead, Authz.RoleAssign,
                    Authz.RoleRevoke.  ROLE_ADMIN is the near miss and carries Authz.ProfileDeactivate as well, which
                    hands the people who provision access the one operation that takes it away.

T-128 seeded both, with those exact permission lists, as IsSystemRole = 1 baseline roles.  So section 1 no longer
CREATES them -- it ASSERTS them, and refuses the run when either is absent or when either has drifted from the
permission list above.

WHY ASSERTING IS NOT THE TIMID VERSION OF CREATING.  Leaving the create-if-absent block in place would have been
harmless on every database that matters and would have destroyed the finding: a loader that quietly supplies what the
seed forgot can never again discover that the seed forgot it, which is exactly how this gap survived eight phases of
fixtures that each built their own roles.  The refusal below is what keeps G-46 and G-47 reproducible -- run this file
against a database seeded by the fourteen-role version of 115 and it stops, with the reason, before writing anything.

WHAT AUTHENTICATION SHAPE EACH COHORT GETS
------------------------------------------
The scenario is specific and the specificity is the point: agency staff arrive through Microsoft Entra, except the ten
platform admins, who must not.  So

  D1-D4, D6-D9   auth.UserFederatedIdentity against the Entra issuer.  No password row at all -- a federated user who
                 also has a password has two ways in, and the weaker one is the one that gets attacked.
  D5             auth.UserCredential (Password) plus a CONFIRMED auth.UserMfaFactor.  Local credentials with 2FA.
  C1-C6          the same local shape as D5.  Every county user, all 12,660 of them.

and the tenant policies match: the agency allows federated and local, prefers federated; every county allows local only.
Both set RequireStepUpForPrivileged = 1, which is what the shipped default Authn.RequireStepUpForPrivilegedDefault says
and what every policy row in the repository's own tests sets to 0.  S1_prove_duties.sql section 6 is about what happens
next.

VERIFIER STRINGS HERE HASH NOTHING, DELIBERATELY
------------------------------------------------
Every VerifierPhc written below is a syntactically valid Argon2id PHC string over the text "not a real verifier".  The
password comparison belongs to the application layer by design -- auth.uspCompleteLogin is TOLD the answer through
@PasswordVerified -- so a verifier the database could check would be a verifier the database could be made to leak.  The
same is true of SecretCiphertext on the MFA factors: it is sixteen bytes of nothing, and KeyReference says dev: so that
no reader mistakes it for a wrapped secret.

RUNNING IT TWICE, AND WHY THAT IS A RESUME RATHER THAN A REFUSAL
---------------------------------------------------------------
Every insert in this file is NOT EXISTS against the row it would write, so a second run with the same -v Wave adds
nothing and re-asserts section 9's fifteen checks.  To load a SECOND population -- which is exactly what the scenario's
third run is, "double the number of users but not the number of agencies or counties" -- pass a different -v Wave.  Wave
is part of every user name, so two waves cannot collide.

An earlier revision refused instead, on the reasoning that a population whose size depends on how many times it was
loaded cannot be counted.  That reasoning is right and the refusal was still wrong, and the run that proved it is worth
recording: section 7e failed on CK_auth_UserMfaFactor_KeyReferenceFormat after sections 2 to 7d had already COMMITTED --
XACT_ABORT with no explicit transaction ends the batch, not the work.  12,830 users and 30,490 profiles were on disk with
no second factor and no permission scope, and the refusal then made the only way forward dropping the database.  A guard
that turns a one-line constraint violation into a reinstall is not protecting anything.  Idempotent inserts give the same
guarantee -- run it ten times, get one population -- and leave a half-finished load recoverable.  BL-076.

There is no unload script and that is a property of the design, not an omission: nothing here may hard delete, soft
deleting 12,830 users would leave 30,490 tombstoned profiles that auth.uspRebuildProfilePermissionScope still walks, and
the honest way back is to drop the database and reinstall it.

    sqlcmd -S MDE-55TT2J4 -E -d master -C -Q "ALTER DATABASE <db> SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE <db>;"

Depends on:     a database installed by Install-TemplateDatabase.ps1 through all 39 steps, with database/115's TEMPLATE
                application and ROOT tenant present and live.
Implements:     test_scenario_1.txt.  See docs/60-scenario-test-1.md.
***********************************************************************************************************************/

SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;
GO

PRINT N'--- S1_load_agency.sql: $(AgencyCode) with $(CountyCount) counties, wave $(Wave), in [$(DbName)] ---';
GO


-- *** 0. Guards ***
-- Four refusals, and each one is a failure mode that has actually been hit while building this file.
DECLARE @App    INT = (SELECT ApplicationId FROM auth.Application WHERE ApplicationCode = N'TEMPLATE' AND IsDeleted = 0)
      , @Root   INT
      , @Actor  NVARCHAR (510) = ORIGINAL_LOGIN ()
      , @N      INT = $(CountyCount);

IF @App IS NULL
BEGIN
    PRINT N'E-59100: there is no live TEMPLATE application. Install the database before loading a scenario.';
    THROW 59100, N'No live TEMPLATE application.', 1;
END;

SELECT @Root = TenantId
  FROM auth.Tenant
 WHERE ApplicationId = @App AND TenantCode = N'ROOT' AND IsDeleted = 0 AND IsActive = 1;

IF @Root IS NULL
BEGIN
    PRINT N'E-59100: there is no live ROOT tenant under TEMPLATE.';
    THROW 59100, N'No live ROOT tenant.', 1;
END;

IF @N < 60
BEGIN
    PRINT N'E-59101: CountyCount must be at least 60 -- the three seeded selections take disjoint bands up to rank 60.';
    THROW 59101, N'CountyCount below 60.', 1;
END;

DECLARE @Already INT = (SELECT COUNT (*) FROM auth.[User]
                         WHERE UserName LIKE LOWER (N'$(AgencyCode)') + N'.$(Wave).%' AND IsDeleted = 0);

PRINT CONCAT (N'Section 0: guards passed. ApplicationId ', @App, N', ROOT tenant ', @Root, N', ', @N, N' counties. '
            , CASE WHEN @Already = 0 THEN N'Wave $(Wave) is new.'
                   ELSE CONCAT (N'Wave $(Wave) already holds ', @Already
                              , N' user(s) -- this run RESUMES it and adds only what is missing.') END);
GO


-- *** 1. The two roles this file requires and no longer creates ***
-- 115_seed_reference_data.sql seeds CRUD_ACCESS and PROFILE_ASSIGNER as baseline roles owned by ROOT -- T-128, which
-- closed G-46 and G-47.  This section used to create them when they were missing; now it checks them, and the check is
-- deliberately the STRICTER of the two things it could be.  It is not enough that a role with the right code exists:
-- the scenario's cohorts mean something by these roles, the prover asserts the consequences verb by verb, and a role
-- that had been narrowed by an operator would turn 34 asserted observations into a fog of permission denials pointing
-- at nothing.  So the permission list is compared too, and a difference stops the run here rather than 30,490 profiles
-- later.
--
-- Owned by ROOT and not by the agency, which is why this file can rely on the seed at all: the scenario gives both roles
-- the same meaning in the agency and in every county, and INV-04 makes a role owned by the agency ungrantable at a
-- county that is not beneath it.
DECLARE @App   INT = (SELECT ApplicationId FROM auth.Application WHERE ApplicationCode = N'TEMPLATE' AND IsDeleted = 0);
DECLARE @Root  INT = (SELECT TenantId FROM auth.Tenant
                       WHERE ApplicationId = @App AND TenantCode = N'ROOT' AND IsDeleted = 0);

CREATE TABLE #RoleWanted
    (
        RoleCode        NVARCHAR (200) NOT NULL PRIMARY KEY
      , PermissionCodes NVARCHAR (1000) NOT NULL
    );

INSERT #RoleWanted (RoleCode, PermissionCodes)
VALUES (N'CRUD_ACCESS'
      , N'Data.Read,Data.Insert,Data.Update,Data.SoftDelete,Data.Execute')
     , (N'PROFILE_ASSIGNER'
      , N'Authz.ProfileRead,Authz.ProfileCreate,Authz.ProfileUpdate,Authz.RoleRead,Authz.RoleAssign,Authz.RoleRevoke');

-- Two findings, reported together.  A run that is missing both roles should say so once, not twice in a row with a
-- re-run in between: the operator's next action is the same either way, and it is naming the file to run.
DECLARE @RoleFault NVARCHAR (2000) = N'';

SELECT @RoleFault = @RoleFault
     + CASE WHEN r.RoleId IS NULL
            THEN w.RoleCode + N' is absent. '
            WHEN EXISTS (SELECT 1
                           FROM STRING_SPLIT (w.PermissionCodes, ',') AS want
                          WHERE NOT EXISTS (SELECT 1
                                              FROM auth.RolePermission AS rp
                                             INNER JOIN auth.Permission AS p ON p.PermissionId = rp.PermissionId
                                                                           AND p.IsDeleted     = 0
                                             WHERE rp.RoleId    = r.RoleId
                                               AND rp.IsDeleted = 0
                                               AND p.PermissionCode = TRIM (want.value)))
            THEN w.RoleCode + N' exists but does not hold every permission the scenario means by it ('
               + w.PermissionCodes + N'). '
            ELSE N'' END
  FROM #RoleWanted AS w
  LEFT JOIN auth.Role AS r ON r.ApplicationId = @App AND r.OwnerTenantId = @Root
                          AND r.RoleCode = w.RoleCode AND r.IsDeleted = 0;

IF LEN (@RoleFault) > 0
BEGIN
    DECLARE @MsgRoles NVARCHAR (2000) =
        N'S1_load_agency.sql cannot build the scenario: ' + @RoleFault
      + N'Both roles are seeded by database/115_seed_reference_data.sql (T-128, gaps G-46 and G-47) and owned by the '
      + N'ROOT tenant. Run that file -- it is idempotent -- and run this one again. This file used to create the two '
      + N'roles itself; it stopped on purpose, because a loader that supplies what the seed forgot can never again '
      + N'report that the seed forgot it, and that is how G-46 and G-47 survived eight phases. Nothing has been '
      + N'changed.';

    THROW 50000, @MsgRoles, 1;
END;

PRINT CONCAT (N'Section 1: CRUD_ACCESS and PROFILE_ASSIGNER are present as seeded baseline roles owned by ROOT, with '
            , N'the permission lists the scenario means. Asserted, not created -- T-128 closed G-46 and G-47.');
GO


-- *** 2. The tenants: one agency, N counties ***
-- Merging rather than refusing, because the scenario's third run loads a second wave of PEOPLE into the SAME tree --
-- "double the number of users but not the number of agencies or counties" -- and a tenant section that refused would
-- make that run impossible.
DECLARE @App    INT = (SELECT ApplicationId FROM auth.Application WHERE ApplicationCode = N'TEMPLATE' AND IsDeleted = 0)
      , @Root   INT
      , @Agency INT
      , @Actor  NVARCHAR (510) = ORIGINAL_LOGIN ()
      , @Made   INT = 0
      , @T0     DATETIME2 (3)
      , @Ms     INT;

SELECT @Root = TenantId FROM auth.Tenant
 WHERE ApplicationId = @App AND TenantCode = N'ROOT' AND IsDeleted = 0;

INSERT auth.Tenant (ApplicationId, TenantCode, TenantName, TenantTypeId, TenantTypeCode, ParentTenantId, IsActive
                  , auditCreatedBy, auditModifiedBy)
SELECT @App, N'$(AgencyCode)', REPLACE (N'$(AgencyName)', N'_', N' '), tt.TenantTypeId, tt.TenantTypeCode, @Root, 1
     , @Actor, @Actor
  FROM auth.TenantType AS tt
 WHERE tt.TenantTypeCode = N'Agency' AND tt.IsDeleted = 0
   AND NOT EXISTS (SELECT 1 FROM auth.Tenant AS x
                    WHERE x.ApplicationId = @App AND x.TenantCode = N'$(AgencyCode)' AND x.IsDeleted = 0);

SET @Made = @@ROWCOUNT;

SELECT @Agency = TenantId FROM auth.Tenant
 WHERE ApplicationId = @App AND TenantCode = N'$(AgencyCode)' AND IsDeleted = 0;

INSERT auth.Tenant (ApplicationId, TenantCode, TenantName, TenantTypeId, TenantTypeCode, ParentTenantId, IsActive
                  , auditCreatedBy, auditModifiedBy)
SELECT @App
     , N'$(AgencyCode)-C' + RIGHT (N'000' + CAST (s.value AS NVARCHAR (10)), 3)
     , N'$(AgencyCode) County ' + CAST (s.value AS NVARCHAR (10))
     , tt.TenantTypeId, tt.TenantTypeCode, @Agency, 1, @Actor, @Actor
  FROM GENERATE_SERIES (1, $(CountyCount)) AS s
 CROSS JOIN auth.TenantType AS tt
 WHERE tt.TenantTypeCode = N'Jurisdiction' AND tt.IsDeleted = 0
   AND NOT EXISTS (SELECT 1 FROM auth.Tenant AS x
                    WHERE x.ApplicationId = @App
                      AND x.TenantCode = N'$(AgencyCode)-C' + RIGHT (N'000' + CAST (s.value AS NVARCHAR (10)), 3)
                      AND x.IsDeleted = 0);

DECLARE @Counties INT = @@ROWCOUNT;

SET @T0 = SYSUTCDATETIME ();
EXEC auth.uspRebuildTenantClosure;
SET @Ms = DATEDIFF (MILLISECOND, @T0, SYSUTCDATETIME ());

PRINT CONCAT (N'Section 2: agency tenant ', @Agency, N' (', @Made, N' created this run), ', @Counties
            , N' county tenant(s) created this run. Closure rebuilt in ', @Ms, N' ms.');
GO


-- *** 3. The seeded county order, and the three selections taken out of it ***
-- One ORDER, three disjoint bands. Ranks 1-20 are the dual-county cohort's home counties, 21-30 the eleven-county
-- cohort's, 31-50 the partners for the first, 51 upward the partner pool for the second. The agency's ten CRUD-switch
-- counties come from a SECOND order seeded differently, because they are a separate draw in the scenario and using the
-- same order would silently make them the same counties as the dual-county band.
CREATE TABLE #County
    (
        CountyNo   INT            NOT NULL PRIMARY KEY
      , TenantId   INT            NOT NULL
      , TenantCode NVARCHAR (100) NOT NULL
      , Rnk        INT            NOT NULL
      , DepRnk     INT            NOT NULL
    );

DECLARE @App INT = (SELECT ApplicationId FROM auth.Application WHERE ApplicationCode = N'TEMPLATE' AND IsDeleted = 0);

INSERT #County (CountyNo, TenantId, TenantCode, Rnk, DepRnk)
SELECT s.value
     , t.TenantId
     , t.TenantCode
     , ROW_NUMBER () OVER (ORDER BY CHECKSUM (HASHBYTES ('SHA2_256', N'$(Seed)|' + t.TenantCode)), t.TenantCode)
     , ROW_NUMBER () OVER (ORDER BY CHECKSUM (HASHBYTES ('SHA2_256', N'$(Seed)|dep|' + t.TenantCode)), t.TenantCode)
  FROM GENERATE_SERIES (1, $(CountyCount)) AS s
 INNER JOIN auth.Tenant AS t
    ON t.ApplicationId = @App
   AND t.TenantCode    = N'$(AgencyCode)-C' + RIGHT (N'000' + CAST (s.value AS NVARCHAR (10)), 3)
   AND t.IsDeleted     = 0;

-- Each dual-county home county (rank 1-20) gets exactly one partner, at rank + 30.
CREATE TABLE #Pair
    (
        HomeNo    INT NOT NULL
      , PartnerNo INT NOT NULL
      , Slot      INT NOT NULL
      , PRIMARY KEY (HomeNo, PartnerNo)
    );

INSERT #Pair (HomeNo, PartnerNo, Slot)
SELECT h.CountyNo, p.CountyNo, 1
  FROM #County AS h
 INNER JOIN #County AS p ON p.Rnk = h.Rnk + 30
 WHERE h.Rnk BETWEEN 1 AND 20;

-- Each eleven-county home county (rank 21-30) gets ten partners, rotating through the band above rank 50 so that no two
-- home counties draw the same ten.
CREATE TABLE #Multi
    (
        HomeNo    INT NOT NULL
      , PartnerNo INT NOT NULL
      , Slot      INT NOT NULL
      , PRIMARY KEY (HomeNo, PartnerNo)
    );

DECLARE @PoolSize INT = (SELECT COUNT (*) FROM #County WHERE Rnk > 50);

INSERT #Multi (HomeNo, PartnerNo, Slot)
SELECT h.CountyNo, p.CountyNo, k.value
  FROM #County AS h
 CROSS JOIN GENERATE_SERIES (1, 10) AS k
 INNER JOIN #County AS p ON p.Rnk = 51 + ((h.Rnk - 21 + k.value - 1) % @PoolSize)
 WHERE h.Rnk BETWEEN 21 AND 30;

DECLARE @Pairs INT = (SELECT COUNT (*) FROM #Pair)
      , @Multi INT = (SELECT COUNT (*) FROM #Multi);

PRINT CONCAT (N'Section 3: county order seeded from "$(Seed)". Partner pool above rank 50 holds ', @PoolSize
            , N' counties. ', @Pairs, N' dual-county pairing(s), ', @Multi, N' eleven-county pairing(s).');
GO


-- *** 4. The people ***
-- #Person is the whole plan, written once and then read three times -- by the user insert, the profile insert and the
-- grant insert. Building it first is what keeps the three in agreement: a cohort added to #Person and forgotten
-- downstream shows up as a user with no profile, which section 8 counts and refuses.
CREATE TABLE #Person
    (
        UserName        NVARCHAR (200) NOT NULL PRIMARY KEY
      , DisplayName     NVARCHAR (400) NOT NULL
      , Cohort          CHAR (2)       NOT NULL
      , HomeCountyNo    INT            NULL
      , IsPlatformAdmin BIT            NOT NULL
      , IsFederated     BIT            NOT NULL
      , UserId          INT            NULL
      , INDEX IX_Person_Cohort NONCLUSTERED (Cohort, HomeCountyNo)
    );

DECLARE @Pfx NVARCHAR (100) = LOWER (N'$(AgencyCode)') + N'.$(Wave).';

-- 4a. Agency-resident cohorts. Everything federated except D5.
INSERT #Person (UserName, DisplayName, Cohort, HomeCountyNo, IsPlatformAdmin, IsFederated)
SELECT @Pfx + LOWER (c.Cohort) + N'.' + RIGHT (N'0000' + CAST (s.value AS NVARCHAR (10)), 4)
     , N'$(AgencyCode) ' + c.Label + N' ' + CAST (s.value AS NVARCHAR (10))
     , c.Cohort
     , NULL
     , c.PlatformAdmin
     , c.Federated
  FROM (VALUES (CAST (N'D1' AS CHAR (2)), 10, N'read-only',             CAST (0 AS BIT), CAST (1 AS BIT))
             , (N'D2', 20, N'read-only switcher',    0, 1)
             , (N'D3', 20, N'CRUD',                  0, 1)
             , (N'D4', 50, N'CRUD switcher',         0, 1)
             , (N'D5', 10, N'platform admin',        1, 0)
             , (N'D6', 10, N'assigner read-only',    0, 1)
             , (N'D7', 20, N'assigner CRUD',         0, 1)
             , (N'D8', 10, N'assigner switcher',     0, 1)
             , (N'D9', 20, N'CRUD ten-county',       0, 1)
       ) AS c (Cohort, Qty, Label, PlatformAdmin, Federated)
 CROSS APPLY GENERATE_SERIES (1, c.Qty) AS s;

-- 4b. County-resident cohorts C1-C4, in every county. All local.
INSERT #Person (UserName, DisplayName, Cohort, HomeCountyNo, IsPlatformAdmin, IsFederated)
SELECT @Pfx + LOWER (c.Cohort) + N'.' + RIGHT (N'000' + CAST (t.CountyNo AS NVARCHAR (10)), 3)
       + N'.' + RIGHT (N'0000' + CAST (s.value AS NVARCHAR (10)), 4)
     , t.TenantCode + N' ' + c.Label + N' ' + CAST (s.value AS NVARCHAR (10))
     , c.Cohort
     , t.CountyNo
     , 0
     , 0
  FROM #County AS t
 CROSS JOIN (VALUES (CAST (N'C1' AS CHAR (2)),  20, N'read-only')
                  , (N'C2',  50, N'CRUD')
                  , (N'C3',  10, N'profile admin')
                  , (N'C4', 100, N'dual-profile')
            ) AS c (Cohort, Qty, Label)
 CROSS APPLY GENERATE_SERIES (1, c.Qty) AS s;

-- 4c. C5 in the twenty seeded counties, C6 in the ten.
INSERT #Person (UserName, DisplayName, Cohort, HomeCountyNo, IsPlatformAdmin, IsFederated)
SELECT @Pfx + N'c5.' + RIGHT (N'000' + CAST (t.CountyNo AS NVARCHAR (10)), 3)
       + N'.' + RIGHT (N'0000' + CAST (s.value AS NVARCHAR (10)), 4)
     , t.TenantCode + N' two-county ' + CAST (s.value AS NVARCHAR (10)), N'C5', t.CountyNo, 0, 0
  FROM #County AS t CROSS APPLY GENERATE_SERIES (1, 20) AS s
 WHERE t.Rnk BETWEEN 1 AND 20;

INSERT #Person (UserName, DisplayName, Cohort, HomeCountyNo, IsPlatformAdmin, IsFederated)
SELECT @Pfx + N'c6.' + RIGHT (N'000' + CAST (t.CountyNo AS NVARCHAR (10)), 3)
       + N'.' + RIGHT (N'0000' + CAST (s.value AS NVARCHAR (10)), 4)
     , t.TenantCode + N' eleven-county ' + CAST (s.value AS NVARCHAR (10)), N'C6', t.CountyNo, 0, 0
  FROM #County AS t CROSS APPLY GENERATE_SERIES (1, 20) AS s
 WHERE t.Rnk BETWEEN 21 AND 30;

DECLARE @Planned INT = (SELECT COUNT (*) FROM #Person);

INSERT auth.[User] (UserName, DisplayName, Email, IsActive, IsPlatformAdmin, MustChangePassword
                  , auditCreatedBy, auditModifiedBy)
SELECT p.UserName, p.DisplayName, p.UserName + N'@example.gov', 1, p.IsPlatformAdmin, 0
     , ORIGINAL_LOGIN (), ORIGINAL_LOGIN ()
  FROM #Person AS p
 WHERE NOT EXISTS (SELECT 1 FROM auth.[User] AS u WHERE u.UserName = p.UserName AND u.IsDeleted = 0);

DECLARE @Users INT = @@ROWCOUNT;

UPDATE p
   SET p.UserId = u.UserId
  FROM #Person AS p
 INNER JOIN auth.[User] AS u ON u.UserName = p.UserName AND u.IsDeleted = 0;

PRINT CONCAT (N'Section 4: ', @Planned, N' people planned, ', @Users, N' inserted into auth.[User].');
GO


-- *** 5. Profiles ***
-- #Plan is (person, tenant, profile name, roles) and it is built cohort by cohort so that each row of the scenario is
-- visibly one INSERT. ProfileName carries the ACCESS SHAPE rather than the person, because C4, C5 and C6 hold two
-- profiles at one tenant and UX_auth_UserProfile_UserTenantName is what distinguishes them.
CREATE TABLE #Plan
    (
        UserName      NVARCHAR (200) NOT NULL
      , TenantId      INT            NOT NULL
      , ProfileName   NVARCHAR (100) NOT NULL
      , IsDefault     BIT            NOT NULL
      , RoleCodes     NVARCHAR (400) NOT NULL
      , UserProfileId INT            NULL
      , PRIMARY KEY (UserName, TenantId, ProfileName)
    );

DECLARE @App    INT = (SELECT ApplicationId FROM auth.Application WHERE ApplicationCode = N'TEMPLATE' AND IsDeleted = 0)
      , @Agency INT;

SELECT @Agency = TenantId FROM auth.Tenant
 WHERE ApplicationId = @App AND TenantCode = N'$(AgencyCode)' AND IsDeleted = 0;

-- 5a. The agency profile every agency cohort has, and for the non-switchers it is the only one. Default here.
INSERT #Plan (UserName, TenantId, ProfileName, IsDefault, RoleCodes)
SELECT p.UserName, @Agency
     , CASE p.Cohort WHEN N'D1' THEN N'Read-only'
                     WHEN N'D2' THEN N'Read-only'
                     WHEN N'D3' THEN N'CRUD'
                     WHEN N'D4' THEN N'CRUD'
                     WHEN N'D5' THEN N'Platform administrator'
                     WHEN N'D6' THEN N'Assigner read-only'
                     WHEN N'D7' THEN N'Assigner CRUD'
                     WHEN N'D8' THEN N'Assigner'
                     ELSE            N'CRUD' END
     , 1
     , CASE p.Cohort WHEN N'D1' THEN N'READ_ONLY'
                     WHEN N'D2' THEN N'READ_ONLY'
                     WHEN N'D3' THEN N'CRUD_ACCESS'
                     WHEN N'D4' THEN N'CRUD_ACCESS'
                     WHEN N'D5' THEN N'PROFILE_ASSIGNER,USER_ADMIN,PLATFORM_ADMIN'
                     WHEN N'D6' THEN N'PROFILE_ASSIGNER,READ_ONLY'
                     WHEN N'D7' THEN N'PROFILE_ASSIGNER,CRUD_ACCESS'
                     WHEN N'D8' THEN N'PROFILE_ASSIGNER'
                     ELSE            N'CRUD_ACCESS' END
  FROM #Person AS p
 WHERE p.Cohort LIKE N'D%';

-- 5b. D2, D4 and D8 get a profile in EVERY county; D9 in the ten counties its own seeded order picked.
INSERT #Plan (UserName, TenantId, ProfileName, IsDefault, RoleCodes)
SELECT p.UserName, c.TenantId
     , CASE p.Cohort WHEN N'D2' THEN N'Read-only' WHEN N'D8' THEN N'Assigner' ELSE N'CRUD' END
     , 0
     , CASE p.Cohort WHEN N'D2' THEN N'READ_ONLY' WHEN N'D8' THEN N'PROFILE_ASSIGNER' ELSE N'CRUD_ACCESS' END
  FROM #Person AS p
 CROSS JOIN #County AS c
 WHERE p.Cohort IN (N'D2', N'D4', N'D8')
    OR (p.Cohort = N'D9' AND c.DepRnk BETWEEN 1 AND 10);

-- 5c. C1, C2 and C3 -- one profile at home.
INSERT #Plan (UserName, TenantId, ProfileName, IsDefault, RoleCodes)
SELECT p.UserName, c.TenantId
     , CASE p.Cohort WHEN N'C1' THEN N'Read-only' WHEN N'C2' THEN N'CRUD' ELSE N'Profile administrator' END
     , 1
     , CASE p.Cohort WHEN N'C1' THEN N'READ_ONLY' WHEN N'C2' THEN N'CRUD_ACCESS'
                     ELSE N'PROFILE_ASSIGNER,USER_ADMIN' END
  FROM #Person AS p
 INNER JOIN #County AS c ON c.CountyNo = p.HomeCountyNo
 WHERE p.Cohort IN (N'C1', N'C2', N'C3');

-- 5d. C4, C5 and C6 -- the read-only/CRUD pair, at home for all three and at the partners for C5 and C6. The read-only
--     profile at HOME is the default one, which is UX_auth_UserProfile_Default's one-per-user rule and also the safe
--     landing place: a session that has not switched yet can read and cannot write.
INSERT #Plan (UserName, TenantId, ProfileName, IsDefault, RoleCodes)
SELECT p.UserName, c.TenantId, s.ProfileName, CASE WHEN s.ProfileName = N'Read-only' THEN 1 ELSE 0 END, s.RoleCodes
  FROM #Person AS p
 INNER JOIN #County AS c ON c.CountyNo = p.HomeCountyNo
 CROSS JOIN (VALUES (N'Read-only', N'READ_ONLY'), (N'CRUD', N'CRUD_ACCESS')) AS s (ProfileName, RoleCodes)
 WHERE p.Cohort IN (N'C4', N'C5', N'C6');

INSERT #Plan (UserName, TenantId, ProfileName, IsDefault, RoleCodes)
SELECT p.UserName, c.TenantId, s.ProfileName, 0, s.RoleCodes
  FROM #Person AS p
 INNER JOIN #Pair  AS x ON x.HomeNo   = p.HomeCountyNo
 INNER JOIN #County AS c ON c.CountyNo = x.PartnerNo
 CROSS JOIN (VALUES (N'Read-only', N'READ_ONLY'), (N'CRUD', N'CRUD_ACCESS')) AS s (ProfileName, RoleCodes)
 WHERE p.Cohort = N'C5';

INSERT #Plan (UserName, TenantId, ProfileName, IsDefault, RoleCodes)
SELECT p.UserName, c.TenantId, s.ProfileName, 0, s.RoleCodes
  FROM #Person AS p
 INNER JOIN #Multi AS x ON x.HomeNo   = p.HomeCountyNo
 INNER JOIN #County AS c ON c.CountyNo = x.PartnerNo
 CROSS JOIN (VALUES (N'Read-only', N'READ_ONLY'), (N'CRUD', N'CRUD_ACCESS')) AS s (ProfileName, RoleCodes)
 WHERE p.Cohort = N'C6';

DECLARE @PlanRows INT = (SELECT COUNT (*) FROM #Plan);

INSERT auth.UserProfile (UserId, TenantId, ProfileName, IsDefault, IsActive, auditCreatedBy, auditModifiedBy)
SELECT p.UserId, n.TenantId, n.ProfileName, n.IsDefault, 1, ORIGINAL_LOGIN (), ORIGINAL_LOGIN ()
  FROM #Plan   AS n
 INNER JOIN #Person AS p ON p.UserName = n.UserName
 WHERE NOT EXISTS (SELECT 1 FROM auth.UserProfile AS up
                    WHERE up.UserId = p.UserId AND up.TenantId = n.TenantId
                      AND up.ProfileName = n.ProfileName AND up.IsDeleted = 0);

DECLARE @Profiles INT = @@ROWCOUNT;

UPDATE n
   SET n.UserProfileId = up.UserProfileId
  FROM #Plan   AS n
 INNER JOIN #Person      AS p  ON p.UserName    = n.UserName
 INNER JOIN auth.UserProfile AS up ON up.UserId = p.UserId AND up.TenantId = n.TenantId
                                  AND up.ProfileName = n.ProfileName AND up.IsDeleted = 0;

PRINT CONCAT (N'Section 5: ', @PlanRows, N' profiles planned, ', @Profiles, N' inserted into auth.UserProfile.');
GO


-- *** 6. Role grants, scoped at the profile's own tenant ***
-- ScopeTenantId = the profile's tenant, never an ancestor. That is the scenario's shape read literally: a county user
-- administers that county, and an agency user who needs a county's data holds a PROFILE there rather than a wider scope
-- from the agency. It also keeps auth.ProfilePermissionScope honest -- a grant scoped at the agency would fan out over
-- the whole closure and silently give every agency reader every county.
INSERT auth.UserProfileRole (UserProfileId, RoleId, ScopeTenantId, ApplicationId, GrantedUtc
                           , auditCreatedBy, auditModifiedBy)
SELECT n.UserProfileId, r.RoleId, n.TenantId, r.ApplicationId, SYSUTCDATETIME (), ORIGINAL_LOGIN (), ORIGINAL_LOGIN ()
  FROM #Plan AS n
 CROSS APPLY STRING_SPLIT (n.RoleCodes, ',') AS s
 INNER JOIN auth.Role AS r
    ON r.RoleCode      = TRIM (s.value)
   AND r.IsDeleted     = 0
   AND r.ApplicationId = (SELECT ApplicationId FROM auth.Application
                           WHERE ApplicationCode = N'TEMPLATE' AND IsDeleted = 0)
   AND r.OwnerTenantId = (SELECT TenantId FROM auth.Tenant
                           WHERE ApplicationId = r.ApplicationId AND TenantCode = N'ROOT' AND IsDeleted = 0)
 WHERE n.UserProfileId IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM auth.UserProfileRole AS g
                    WHERE g.UserProfileId = n.UserProfileId AND g.RoleId = r.RoleId
                      AND g.ScopeTenantId = n.TenantId AND g.IsDeleted = 0);

DECLARE @Grants INT = @@ROWCOUNT;

PRINT CONCAT (N'Section 6: ', @Grants, N' role grant(s) written to auth.UserProfileRole.');
GO


-- *** 7. Authentication: federated for the agency, local with 2FA for everyone else ***
DECLARE @App    INT = (SELECT ApplicationId FROM auth.Application WHERE ApplicationCode = N'TEMPLATE' AND IsDeleted = 0)
      , @Agency INT
      , @Actor  NVARCHAR (510) = ORIGINAL_LOGIN ()
      , @Issuer NVARCHAR (1024) = N'https://login.microsoftonline.com/$(AgencyCode)-tenant/v2.0'
      , @Phc    NVARCHAR (1024) = N'$argon2id$v=19$m=65536,t=3,p=4$c2NlbmFyaW8xLXNhbHQtbm90LXJlYWw$bm90LWEtcmVhbC12ZXJpZmllci1ldmVyLWFueXdoZXJl'
      , @Now    DATETIME2 (3) = SYSUTCDATETIME ();

SELECT @Agency = TenantId FROM auth.Tenant
 WHERE ApplicationId = @App AND TenantCode = N'$(AgencyCode)' AND IsDeleted = 0;

-- 7a. The agency policy: both routes open, federated preferred, step-up demanded of privileged hats. That last value is
--     what Authn.RequireStepUpForPrivilegedDefault ships as, and no policy row anywhere else in this repository sets it.
IF NOT EXISTS (SELECT 1 FROM auth.TenantAuthenticationPolicy WHERE TenantId = @Agency AND IsDeleted = 0)
    INSERT auth.TenantAuthenticationPolicy (TenantId, AllowFederated, AllowLocalPassword, RequireMfaForLocal
                                          , PreferredMethod, SessionLifetimeMinutes, IdleTimeoutMinutes
                                          , RequireStepUpForPrivileged, PolicyNote, auditCreatedBy, auditModifiedBy)
    VALUES (@Agency, 1, 1, 1, 'Federated', 480, 60, 1
          , N'test_scenario_1.txt: agency staff arrive through Microsoft Entra; the platform admins use local credentials with 2FA, which is why AllowLocalPassword stays 1.'
          , @Actor, @Actor);

IF NOT EXISTS (SELECT 1 FROM auth.TenantTrustedIssuer WHERE TenantId = @Agency AND Issuer = @Issuer AND IsDeleted = 0)
    INSERT auth.TenantTrustedIssuer (TenantId, Issuer, IssuerNote, auditCreatedBy, auditModifiedBy)
    VALUES (@Agency, @Issuer, N'Microsoft Entra ID for $(AgencyCode). test_scenario_1.txt.', @Actor, @Actor);

-- 7b. Every county: local only, MFA compulsory, step-up demanded.
INSERT auth.TenantAuthenticationPolicy (TenantId, AllowFederated, AllowLocalPassword, RequireMfaForLocal
                                      , PreferredMethod, SessionLifetimeMinutes, IdleTimeoutMinutes
                                      , RequireStepUpForPrivileged, PolicyNote, auditCreatedBy, auditModifiedBy)
SELECT c.TenantId, 0, 1, 1, 'LocalPassword', 480, 60, 1
     , N'test_scenario_1.txt: county users log in with local credentials and 2FA. Federated is refused HERE rather than left to inherit, because the agency above allows it.'
     , @Actor, @Actor
  FROM #County AS c
 WHERE NOT EXISTS (SELECT 1 FROM auth.TenantAuthenticationPolicy AS x
                    WHERE x.TenantId = c.TenantId AND x.IsDeleted = 0);

DECLARE @Pol INT = @@ROWCOUNT;

-- 7c. Federated identities for the agency's Entra cohorts.
INSERT auth.UserFederatedIdentity (UserId, Issuer, SubjectId, LinkedUtc, auditCreatedBy, auditModifiedBy)
SELECT p.UserId, @Issuer, N'sub-' + CONVERT (NVARCHAR (64), HASHBYTES ('SHA2_256', p.UserName), 2), @Now, @Actor, @Actor
  FROM #Person AS p
 WHERE p.IsFederated = 1
   AND NOT EXISTS (SELECT 1 FROM auth.UserFederatedIdentity AS f
                    WHERE f.UserId = p.UserId AND f.Issuer = @Issuer AND f.IsDeleted = 0);

DECLARE @Fed INT = @@ROWCOUNT;

-- 7d. Local credentials for everyone else. LastChangedUtc is back-dated ninety days so that a later test can set
--     ExpiresUtc without tripping CK_auth_UserCredential_ExpiresUtc, which insists the expiry be after the change.
INSERT auth.UserCredential (UserId, CredentialType, VerifierPhc, LastChangedUtc, auditCreatedBy, auditModifiedBy)
SELECT p.UserId, 'Password', @Phc, DATEADD (DAY, -90, @Now), @Actor, @Actor
  FROM #Person AS p
 WHERE p.IsFederated = 0
   AND NOT EXISTS (SELECT 1 FROM auth.UserCredential AS c WHERE c.UserId = p.UserId AND c.IsDeleted = 0);

DECLARE @Cred INT = @@ROWCOUNT;

-- 7e. A confirmed TOTP factor for each of them. That is the "with 2FA" in the scenario, and it is what makes
--     auth.uspGetLoginVerifier return @RequiresMfa = 1 for these users.
INSERT auth.UserMfaFactor (UserId, FactorType, SecretCiphertext, KeyReference, IsConfirmed, ConfirmedUtc
                         , auditCreatedBy, auditModifiedBy)
SELECT p.UserId, 'Totp', HASHBYTES ('SHA2_256', N'$(Seed)|totp|' + p.UserName), N'dev:scenario#v1', 1, @Now
     , @Actor, @Actor
  FROM #Person AS p
 WHERE p.IsFederated = 0
   AND NOT EXISTS (SELECT 1 FROM auth.UserMfaFactor AS m
                    WHERE m.UserId = p.UserId AND m.FactorType = 'Totp' AND m.IsDeleted = 0);

DECLARE @Mfa INT = @@ROWCOUNT;

PRINT CONCAT (N'Section 7: ', @Pol, N' county policy row(s), ', @Fed, N' federated identity(ies), ', @Cred
            , N' local credential(s), ', @Mfa, N' confirmed TOTP factor(s).');
GO


-- *** 8. Answers, then statistics ***
-- auth.ProfilePermissionScope is what every predicate reads, and nothing above wrote a row of it. Rebuilding for ALL
-- profiles rather than one at a time is the only affordable option at this volume and is also the honest one: the
-- scenario's question is whether ~13,000 people can work, and a scope table rebuilt profile by profile would be
-- measuring 30,490 calls instead.
DECLARE @T0 DATETIME2 (3) = SYSUTCDATETIME (), @Ms INT;

EXEC auth.uspRebuildProfilePermissionScope;

SET @Ms = DATEDIFF (MILLISECOND, @T0, SYSUTCDATETIME ());
PRINT CONCAT (N'Section 8: auth.uspRebuildProfilePermissionScope over every profile in ', @Ms, N' ms.');

UPDATE STATISTICS auth.ProfilePermissionScope WITH FULLSCAN;
UPDATE STATISTICS auth.TenantClosure          WITH FULLSCAN;
UPDATE STATISTICS auth.UserProfileRole        WITH FULLSCAN;
UPDATE STATISTICS auth.UserProfile            WITH FULLSCAN;
UPDATE STATISTICS auth.Tenant                 WITH FULLSCAN;
UPDATE STATISTICS auth.[User]                 WITH FULLSCAN;
PRINT N'Section 8: statistics updated WITH FULLSCAN on the six tables the predicates read.';
GO


-- *** 9. The closing report, which ASSERTS the arithmetic instead of printing it ***
-- Every line is OK or VIOLATED and the script exits non-zero on the first violation, because a population that is the
-- wrong shape produces a scenario result that means nothing and looks fine.
DECLARE @App      INT = (SELECT ApplicationId FROM auth.Application WHERE ApplicationCode = N'TEMPLATE' AND IsDeleted = 0)
      , @Agency   INT
      , @N        INT = $(CountyCount)
      , @Bad      INT = 0;

SELECT @Agency = TenantId FROM auth.Tenant
 WHERE ApplicationId = @App AND TenantCode = N'$(AgencyCode)' AND IsDeleted = 0;

CREATE TABLE #Check
    (
        Seq      INT            NOT NULL PRIMARY KEY
      , Subject  NVARCHAR (200) NOT NULL
      , Expected INT            NOT NULL
      , Actual   INT            NOT NULL
      , Detail   NVARCHAR (400) NOT NULL
    );

INSERT #Check (Seq, Subject, Expected, Actual, Detail)
SELECT 1, N'Counties created', @N
     , (SELECT COUNT (*) FROM auth.Tenant
         WHERE ParentTenantId = @Agency AND TenantTypeCode = N'Jurisdiction' AND IsDeleted = 0)
     , N'One Jurisdiction per county, all directly under the agency.'
UNION ALL SELECT 2, N'Users in this wave', 170 + @N * 180 + 400 + 200
     , (SELECT COUNT (*) FROM #Person)
     , N'170 agency + 180 per county + 400 dual-county + 200 eleven-county. The scenario''s "nearly 13,000".'
UNION ALL SELECT 3, N'Profiles in this wave'
     , (10 + 20 * (@N + 1) + 20 + 50 * (@N + 1) + 10 + 10 + 20 + 10 * (@N + 1) + 20 * 11)
       + (@N * 280 + 400 * 4 + 200 * 22)
     , (SELECT COUNT (*) FROM #Plan)
     , N'Agency cohorts D1-D9 plus county cohorts C1-C6, per the header table.'
UNION ALL SELECT 4, N'Profiles actually inserted', (SELECT COUNT (*) FROM #Plan)
     , (SELECT COUNT (*) FROM #Plan WHERE UserProfileId IS NOT NULL)
     , N'Every planned profile found its auth.UserProfile row. A shortfall is a name collision.'
UNION ALL SELECT 5, N'People with no profile', 0
     , (SELECT COUNT (*) FROM #Person AS p
         WHERE NOT EXISTS (SELECT 1 FROM #Plan AS n WHERE n.UserName = p.UserName))
     , N'A cohort added to section 4 and forgotten in section 5 shows up here and nowhere else.'
UNION ALL SELECT 6, N'People with no way to authenticate', 0
     , (SELECT COUNT (*) FROM #Person AS p
         WHERE NOT EXISTS (SELECT 1 FROM auth.UserFederatedIdentity AS f WHERE f.UserId = p.UserId AND f.IsDeleted = 0)
           AND NOT EXISTS (SELECT 1 FROM auth.UserCredential      AS c WHERE c.UserId = p.UserId AND c.IsDeleted = 0))
     , N'Federated or local, never neither and never both.'
UNION ALL SELECT 7, N'Local users without a confirmed factor', 0
     , (SELECT COUNT (*) FROM #Person AS p
         WHERE p.IsFederated = 0
           AND NOT EXISTS (SELECT 1 FROM auth.UserMfaFactor AS m
                            WHERE m.UserId = p.UserId AND m.IsConfirmed = 1 AND m.IsDeleted = 0))
     , N'"Local user credentials with 2FA" is a confirmed auth.UserMfaFactor, not an intention.'
UNION ALL SELECT 8, N'Federated users holding a password', 0
     , (SELECT COUNT (*) FROM #Person AS p
         INNER JOIN auth.UserCredential AS c ON c.UserId = p.UserId AND c.IsDeleted = 0
         WHERE p.IsFederated = 1)
     , N'Two ways in means the weaker one is the attack surface. The agency''s Entra cohorts have no password row.'
UNION ALL SELECT 9, N'Platform admins', 10
     , (SELECT COUNT (*) FROM #Person WHERE Cohort = N'D5' AND IsPlatformAdmin = 1)
     , N'Ten, at the agency, and nowhere else in this wave. C3 has the same reach inside one county and no flag.'
UNION ALL SELECT 10, N'Counties whose users hold 4 profiles', 20
     , (SELECT COUNT (DISTINCT HomeCountyNo) FROM #Person WHERE Cohort = N'C5')
     , N'Twenty seeded counties, twenty users each, a read-only and a CRUD profile in two counties.'
UNION ALL SELECT 11, N'Counties whose users hold 22 profiles', 10
     , (SELECT COUNT (DISTINCT HomeCountyNo) FROM #Person WHERE Cohort = N'C6')
     , N'Ten seeded counties, twenty users each, the same pair across eleven counties.'
UNION ALL SELECT 12, N'C6 users whose profile count is not 22', 0
     , (SELECT COUNT (*) FROM (SELECT n.UserName FROM #Plan AS n
                                INNER JOIN #Person AS p ON p.UserName = n.UserName AND p.Cohort = N'C6'
                                GROUP BY n.UserName HAVING COUNT (*) <> 22) AS q)
     , N'Eleven counties times two profiles. Any other number means the partner rotation collided.'
UNION ALL SELECT 13, N'D9 users whose profile count is not 11', 0
     , (SELECT COUNT (*) FROM (SELECT n.UserName FROM #Plan AS n
                                INNER JOIN #Person AS p ON p.UserName = n.UserName AND p.Cohort = N'D9'
                                GROUP BY n.UserName HAVING COUNT (*) <> 11) AS q)
     , N'The agency profile plus the ten seeded counties.'
UNION ALL SELECT 14, N'Users with more than one default profile', 0
     , (SELECT COUNT (*) FROM (SELECT n.UserName FROM #Plan AS n
                                WHERE n.IsDefault = 1 GROUP BY n.UserName HAVING COUNT (*) <> 1) AS q)
     , N'UX_auth_UserProfile_Default allows exactly one, and a user with none cannot land anywhere.'
UNION ALL SELECT 15, N'Profiles with no permission scope', 0
     , (SELECT COUNT (*) FROM #Plan AS n
         WHERE n.UserProfileId IS NOT NULL
           AND NOT EXISTS (SELECT 1 FROM auth.ProfilePermissionScope AS s
                            WHERE s.UserProfileId = n.UserProfileId))
     , N'A profile with no scope row is a profile that can do nothing, whatever its grants say.';

SELECT @Bad = COUNT (*) FROM #Check WHERE Expected <> Actual;

SELECT Seq
     , Result   = CASE WHEN Expected = Actual THEN N'OK' ELSE N'VIOLATED' END
     , Subject
     , Expected
     , Actual
     , Detail
  FROM #Check
 ORDER BY Seq;

DECLARE @Scope   BIGINT = (SELECT COUNT_BIG (*) FROM auth.ProfilePermissionScope)
      , @Closure BIGINT = (SELECT COUNT_BIG (*) FROM auth.TenantClosure)
      , @AllU    INT    = (SELECT COUNT (*) FROM auth.[User] WHERE IsDeleted = 0)
      , @AllP    INT    = (SELECT COUNT (*) FROM auth.UserProfile WHERE IsDeleted = 0)
      , @AllT    INT    = (SELECT COUNT (*) FROM auth.Tenant WHERE IsDeleted = 0);

PRINT CONCAT (N'Section 9: database now holds ', @AllT, N' tenants, ', @AllU, N' users, ', @AllP, N' profiles, '
            , @Closure, N' closure rows and ', @Scope, N' permission-scope rows.');

IF @Bad > 0
BEGIN
    PRINT CONCAT (N'E-59103: ', @Bad, N' population check(s) VIOLATED. The scenario must not be run on this shape.');
    THROW 59103, N'Scenario population is the wrong shape.', 1;
END;

PRINT N'--- S1_load_agency.sql: 15 checks, 0 violations. Population ready. ---';
GO
