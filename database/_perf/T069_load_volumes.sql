/***********************************************************************************************************************
Script:         T069_load_volumes.sql
Purpose:        Generate the realistic volumes section 10.6 names, so that Phase 5 measures a shape rather than an
                opinion. NOT part of the install manifest and never run against a real database.
Task:           T-069.
Run with:       sqlcmd -S MDE-55TT2J4 -E -d testTemplateBoot -I -C -b -i database/_perf/T069_load_volumes.sql
Author:         Template project
CreateDate:     2026-09-20

WHY THIS IS DIRECT DML AND NOT THE PROCEDURE SURFACE
----------------------------------------------------
T-093 builds the three section 17 variants THROUGH THE PROCEDURES ONLY, and that is the test of the procedure surface.
This script is the opposite exercise and needs to be honest about it: it is a set generator, it bypasses
auth.uspCreateTenant and auth.uspCreateUserProfile entirely, and it therefore proves nothing whatever about them.  What
it produces is a row population of the right ORDER OF MAGNITUDE and, more importantly, the right SHAPE -- a closure
table whose depth distribution is realistic, and a scope table whose rows per profile are realistic -- because those two
distributions are the only inputs the predicate's cost actually depends on.

Building 5,000 profiles through the procedure surface would take a documented 4 to 6 hours of round trips and would
measure the procedures, not the predicates.  The measurement wants the predicates.

WHAT SHAPE, EXACTLY
-------------------
Tenants: a five-level tree under the existing ROOT.  8 agencies, 5 divisions each, 5 programs each, 4 jurisdictions
each -- 1,048 new tenants, and a closure table of roughly 4,900 rows.  The tree is deliberately WIDE AND SHALLOW rather
than deep, because that is what an agency hierarchy looks like and because a deep narrow tree would flatter the
predicate: closure rows per tenant grow with DEPTH, and depth 5 is the realistic worst case section 17 describes.

Profiles: 5,000, one per user, distributed five to a tenant across the 1,000 LEAF-ish tenants (programs and
jurisdictions).  Nobody is given a profile at the root, because a root profile sees the whole closure and would be the
best case, not the expected one.

Roles: FIVE per profile at the profile's own tenant -- READ_ONLY, three drawn deterministically from the operational
pool, and USER_ADMIN -- plus a sixth, DATA_STEWARD at the PARENT tenant, for every fourth profile.

That shape was arrived at by measurement and not by design, and the first attempt is worth recording because the reason
it was wrong is the interesting part.  Four operational roles per profile looks like ten permissions and resolves to
six: the pool roles OVERLAP heavily -- CONTRIBUTOR, EDITOR, OPERATOR and APPROVER share Data.Read and Data.Update
between them -- so distinct permissions per profile grows far more slowly than roles per profile.  auth.RolePermission
holds 42 rows across 14 roles, and auth.ProfilePermissionScope is keyed on (UserProfileId, PermissionId, ScopeTenantId),
so a second role granting a permission the profile already holds at the same scope adds no row at all.  USER_ADMIN was
added because its five permissions are administrative and therefore disjoint from the operational pool, which is the
only kind of role that actually moves the count.

The parent-tenant grant on every fourth profile is there for a different reason.  All three RLS predicates join
auth.ProfilePermissionScope to auth.TenantClosure on pps.ScopeTenantId = tc.AncestorTenantId, so DISTINCT SCOPE TENANTS
PER PROFILE is the multiplier on the closure side of that join, and a population where every profile has exactly one
scope tenant would never exercise it.  One in four is the "supervises the division as well as the program" case, and it
is the population the P95 numbers in the report below are drawn from.

THERE IS NO UNLOAD SCRIPT, AND THAT IS A PROPERTY OF THE DESIGN RATHER THAN AN OMISSION
--------------------------------------------------------------------------------------
Nothing in this database hard-deletes: every table carries the audit block, every audited table carries an update
trigger that forbids anything but setting IsDeleted, and the convention validator refuses a hard delete outright.  So an
unload script could only ever soft-delete tens of thousands of rows, which would leave the pages, the statistics, the
identity values and the closure table exactly as loaded -- a population invisible to every query and still on every
page, which is the worst possible starting point for a second measurement.

The way back is therefore to DROP AND REBUILD the database:

    sqlcmd -S MDE-55TT2J4 -E -d master -Q "ALTER DATABASE testTemplateBoot SET SINGLE_USER
        WITH ROLLBACK IMMEDIATE; DROP DATABASE testTemplateBoot;"
    powershell -NoProfile -ExecutionPolicy Bypass -File database/Install-TemplateDatabase.ps1
        -DatabaseName testTemplateBoot -BootstrapAdminVerifierPhc <phc>

which takes about a minute and is the only way to get a population comparable with a previous one.  It is also why this
script refuses rather than merges: run it twice and the second run stops on E-59001, because a load script that silently
appends is a load script whose numbers cannot be compared with yesterday's.
***********************************************************************************************************************/
SET NOCOUNT ON;
SET XACT_ABORT ON;

DECLARE @Agencies       INT = 8
      , @DivPerAgency   INT = 5
      , @ProgPerDiv     INT = 5
      , @JurPerProg     INT = 4
      , @Profiles       INT = 5000
      , @RolesPerProf   INT = 4
      , @ApplicationId  INT = (SELECT ApplicationId FROM auth.Application WHERE ApplicationCode = N'TEMPLATE' AND IsDeleted = 0)
      , @RootTenantId   INT = (SELECT TenantId FROM auth.Tenant WHERE TenantCode = N'ROOT' AND IsDeleted = 0)
      , @Actor          NVARCHAR (128) = N'T069_load'
      , @Failure        NVARCHAR (2000) = NULL
      , @T0             DATETIME2 (7)
      , @T1             DATETIME2 (7)
      , @N              INT = NULL
      , @N2             INT = NULL;

IF @ApplicationId IS NULL OR @RootTenantId IS NULL
BEGIN
    SET @Failure = N'This database has no live TEMPLATE application or no live ROOT tenant, so 115_seed_reference_data.sql '
                 + N'has not run. Deploy the database before loading it.';
    THROW 59000, @Failure, 1;
END;

IF EXISTS (SELECT 1 FROM auth.Tenant WHERE TenantCode LIKE N'PERF-%')
   OR EXISTS (SELECT 1 FROM auth.[User] WHERE UserName LIKE N'perf.u%')
BEGIN
    SET @Failure = N'This database already holds a T-069 load (tenants coded PERF-% or users named perf.u%). There is no '
                 + N'unload script and there cannot be one -- see the file header -- so drop the database and rebuild '
                 + N'it. Appending a second load silently would make today''s numbers incomparable with yesterday''s, '
                 + N'which is the one thing a measurement must not do.';
    THROW 59001, @Failure, 1;
END;

-- ---------------------------------------------------------------------------------------------------------------------
-- 1.  The tenant tree, one level per statement.  Each level reads the level above out of the table it just wrote, so
--     the identities are real and nothing here guesses at an id.
-- ---------------------------------------------------------------------------------------------------------------------
PRINT 'Building the tenant tree...';
SET @T0 = SYSUTCDATETIME ();

DECLARE @Types TABLE (Code NVARCHAR (50) PRIMARY KEY, Id INT NOT NULL);

INSERT @Types (Code, Id)
SELECT tt.TenantTypeCode, tt.TenantTypeId
  FROM auth.TenantType AS tt
 WHERE tt.IsDeleted = 0;

-- Level 1: agencies under the root.
INSERT auth.Tenant (ApplicationId, TenantCode, TenantName, TenantTypeId, TenantTypeCode, ParentTenantId, IsActive
                  , auditCreatedBy, auditModifiedBy)
SELECT @ApplicationId
     , CONCAT (N'PERF-AGY-', FORMAT (g.value, N'000'))
     , CONCAT (N'Perf Agency ', g.value)
     , t.Id
     , N'Agency'
     , @RootTenantId
     , 1
     , @Actor
     , @Actor
  FROM GENERATE_SERIES (1, @Agencies) AS g
 CROSS JOIN (SELECT Id FROM @Types WHERE Code = N'Agency') AS t;

-- Level 2: divisions under each agency.
INSERT auth.Tenant (ApplicationId, TenantCode, TenantName, TenantTypeId, TenantTypeCode, ParentTenantId, IsActive
                  , auditCreatedBy, auditModifiedBy)
SELECT @ApplicationId
     , CONCAT (N'PERF-DIV-', RIGHT (a.TenantCode, 3), N'-', FORMAT (g.value, N'000'))
     , CONCAT (a.TenantName, N' Division ', g.value)
     , t.Id
     , N'Division'
     , a.TenantId
     , 1
     , @Actor
     , @Actor
  FROM auth.Tenant AS a
 CROSS JOIN GENERATE_SERIES (1, @DivPerAgency) AS g
 CROSS JOIN (SELECT Id FROM @Types WHERE Code = N'Division') AS t
 WHERE a.TenantCode LIKE N'PERF-AGY-%';

-- Level 3: programs under each division.
INSERT auth.Tenant (ApplicationId, TenantCode, TenantName, TenantTypeId, TenantTypeCode, ParentTenantId, IsActive
                  , auditCreatedBy, auditModifiedBy)
SELECT @ApplicationId
     , CONCAT (N'PERF-PRG-', RIGHT (d.TenantCode, 7), N'-', FORMAT (g.value, N'000'))
     , CONCAT (d.TenantName, N' Program ', g.value)
     , t.Id
     , N'Program'
     , d.TenantId
     , 1
     , @Actor
     , @Actor
  FROM auth.Tenant AS d
 CROSS JOIN GENERATE_SERIES (1, @ProgPerDiv) AS g
 CROSS JOIN (SELECT Id FROM @Types WHERE Code = N'Program') AS t
 WHERE d.TenantCode LIKE N'PERF-DIV-%';

-- Level 4: jurisdictions under each program.
INSERT auth.Tenant (ApplicationId, TenantCode, TenantName, TenantTypeId, TenantTypeCode, ParentTenantId, IsActive
                  , auditCreatedBy, auditModifiedBy)
SELECT @ApplicationId
     , CONCAT (N'PERF-JUR-', RIGHT (p.TenantCode, 11), N'-', FORMAT (g.value, N'000'))
     , CONCAT (p.TenantName, N' Jurisdiction ', g.value)
     , t.Id
     , N'Jurisdiction'
     , p.TenantId
     , 1
     , @Actor
     , @Actor
  FROM auth.Tenant AS p
 CROSS JOIN GENERATE_SERIES (1, @JurPerProg) AS g
 CROSS JOIN (SELECT Id FROM @Types WHERE Code = N'Jurisdiction') AS t
 WHERE p.TenantCode LIKE N'PERF-PRG-%';

SET @T1 = SYSUTCDATETIME ();
-- PRINT will not accept a subquery (Msg 1046), so every count below lands in a variable first.
SELECT @N = COUNT (*) FROM auth.Tenant WHERE TenantCode LIKE N'PERF-%';
PRINT CONCAT ('  ', @N, ' tenants in ', DATEDIFF (MILLISECOND, @T0, @T1), ' ms.');

-- ---------------------------------------------------------------------------------------------------------------------
-- 2.  The closure, rebuilt through its own procedure.  This is one of the two T-072 measurements and the number is
--     printed rather than discarded.
-- ---------------------------------------------------------------------------------------------------------------------
PRINT 'Rebuilding auth.TenantClosure...';
SET @T0 = SYSUTCDATETIME ();
EXEC auth.uspRebuildTenantClosure;
SET @T1 = SYSUTCDATETIME ();

SELECT @N = COUNT (*), @N2 = MAX (Depth) FROM auth.TenantClosure WHERE IsDeleted = 0;
PRINT CONCAT ('  ', @N, ' live closure rows in ', DATEDIFF (MILLISECOND, @T0, @T1), ' ms. Max depth ', @N2, '.');

-- ---------------------------------------------------------------------------------------------------------------------
-- 3.  Users and profiles.  One profile per user, five profiles per leaf-ish tenant, nobody at the root.
-- ---------------------------------------------------------------------------------------------------------------------
PRINT 'Building users and profiles...';
SET @T0 = SYSUTCDATETIME ();

-- The tenants a profile may sit at: programs and jurisdictions only, numbered 0..N-1 so a profile number can be
-- distributed over them by modulus and the distribution is reproducible rather than random.
DECLARE @Leaf TABLE (Seq INT PRIMARY KEY, TenantId INT NOT NULL UNIQUE);

INSERT @Leaf (Seq, TenantId)
SELECT ROW_NUMBER () OVER (ORDER BY t.TenantId) - 1, t.TenantId
  FROM auth.Tenant AS t
 WHERE t.TenantCode LIKE N'PERF-PRG-%'
    OR t.TenantCode LIKE N'PERF-JUR-%';

DECLARE @LeafCount INT = (SELECT COUNT (*) FROM @Leaf);

INSERT auth.[User] (UserName, DisplayName, Email, IsActive, IsPlatformAdmin, MustChangePassword
                  , auditCreatedBy, auditModifiedBy)
SELECT CONCAT (N'perf.u', FORMAT (g.value, N'00000'))
     , CONCAT (N'Perf User ', g.value)
     , CONCAT (N'perf.u', FORMAT (g.value, N'00000'), N'@example.gov')
     , 1
     , 0
     , 0
     , @Actor
     , @Actor
  FROM GENERATE_SERIES (1, @Profiles) AS g;

INSERT auth.UserProfile (UserId, TenantId, ProfileName, IsDefault, IsActive, auditCreatedBy, auditModifiedBy)
SELECT u.UserId
     , l.TenantId
     , CONCAT (u.DisplayName, N' at ', t.TenantCode)
     , 1
     , 1
     , @Actor
     , @Actor
  FROM auth.[User] AS u
  CROSS APPLY (SELECT Seq = CAST (RIGHT (u.UserName, 5) AS INT) % @LeafCount) AS m
  JOIN @Leaf      AS l ON l.Seq = m.Seq
  JOIN auth.Tenant AS t ON t.TenantId = l.TenantId
 WHERE u.UserName LIKE N'perf.u%';

SET @T1 = SYSUTCDATETIME ();
SELECT @N = COUNT (*)
  FROM auth.UserProfile AS p
  JOIN auth.[User]      AS u ON u.UserId = p.UserId
 WHERE u.UserName LIKE N'perf.u%';
PRINT CONCAT ('  ', @N, ' profiles in ', DATEDIFF (MILLISECOND, @T0, @T1), ' ms across ', @LeafCount, ' tenants.');

-- ---------------------------------------------------------------------------------------------------------------------
-- 4.  Role grants.  READ_ONLY for everybody, plus three from the non-administrative pool picked by modulus on the
--     profile number so the assignment is deterministic and a re-load produces the same population.
-- ---------------------------------------------------------------------------------------------------------------------
PRINT 'Granting roles...';
SET @T0 = SYSUTCDATETIME ();

DECLARE @Pool TABLE (Seq INT PRIMARY KEY, RoleId INT NOT NULL);

INSERT @Pool (Seq, RoleId)
SELECT ROW_NUMBER () OVER (ORDER BY r.RoleId) - 1, r.RoleId
  FROM auth.Role AS r
 WHERE r.IsDeleted = 0
   AND r.RoleCode IN (N'CONTRIBUTOR', N'EDITOR', N'DATA_STEWARD', N'OPERATOR', N'APPROVER', N'EXPORTER', N'AUDITOR');

DECLARE @PoolCount INT = (SELECT COUNT (*) FROM @Pool);

INSERT auth.UserProfileRole (UserProfileId, RoleId, ScopeTenantId, ApplicationId, GrantedByProfileId
                           , auditCreatedBy, auditModifiedBy)
SELECT DISTINCT
       p.UserProfileId
     , x.RoleId
     , p.TenantId
     , @ApplicationId
     , NULL
     , @Actor
     , @Actor
  FROM auth.UserProfile AS p
  JOIN auth.[User]      AS u ON u.UserId = p.UserId
 CROSS APPLY (SELECT N = CAST (RIGHT (u.UserName, 5) AS INT)) AS n
 CROSS APPLY (SELECT RoleId = (SELECT RoleId FROM auth.Role WHERE RoleCode = N'READ_ONLY' AND IsDeleted = 0)
              UNION ALL
              SELECT RoleId FROM @Pool WHERE Seq = (n.N + 0) % @PoolCount
              UNION ALL
              SELECT RoleId FROM @Pool WHERE Seq = (n.N + 2) % @PoolCount
              UNION ALL
              SELECT RoleId FROM @Pool WHERE Seq = (n.N + 4) % @PoolCount) AS x
 WHERE u.UserName LIKE N'perf.u%';

-- @@ROWCOUNT is captured on the very next statement or not at all; SET @T1 would already have reset it to 1.
SET @N  = @@ROWCOUNT;
SET @T1 = SYSUTCDATETIME ();
PRINT CONCAT ('  ', @N, ' role grants in ', DATEDIFF (MILLISECOND, @T0, @T1), ' ms from a pool of '
            , @PoolCount, ' plus READ_ONLY.');

-- ---------------------------------------------------------------------------------------------------------------------
-- 4b. The two grants that make the population the right SIZE as well as the right shape: USER_ADMIN at the profile's own
--     tenant for everybody, because its permissions are administrative and therefore do not collide with the
--     operational pool, and DATA_STEWARD at the PARENT tenant for every fourth profile, because a profile with two
--     scope tenants is the only kind that exercises the closure side of the predicate's join. See the header.
-- ---------------------------------------------------------------------------------------------------------------------
PRINT 'Granting the administrative role and the parent-tenant role...';
SET @T0 = SYSUTCDATETIME ();

INSERT auth.UserProfileRole (UserProfileId, RoleId, ScopeTenantId, ApplicationId, GrantedByProfileId
                           , auditCreatedBy, auditModifiedBy)
SELECT p.UserProfileId
     , r.RoleId
     , p.TenantId
     , @ApplicationId
     , NULL
     , @Actor
     , @Actor
  FROM auth.UserProfile AS p
  JOIN auth.[User]      AS u ON u.UserId = p.UserId
 CROSS JOIN (SELECT RoleId FROM auth.Role WHERE RoleCode = N'USER_ADMIN' AND IsDeleted = 0) AS r
 WHERE u.UserName LIKE N'perf.u%';

SET @N = @@ROWCOUNT;

INSERT auth.UserProfileRole (UserProfileId, RoleId, ScopeTenantId, ApplicationId, GrantedByProfileId
                           , auditCreatedBy, auditModifiedBy)
SELECT p.UserProfileId
     , r.RoleId
     , t.ParentTenantId
     , @ApplicationId
     , NULL
     , @Actor
     , @Actor
  FROM auth.UserProfile AS p
  JOIN auth.[User]      AS u ON u.UserId = p.UserId
  JOIN auth.Tenant      AS t ON t.TenantId = p.TenantId
 CROSS JOIN (SELECT RoleId FROM auth.Role WHERE RoleCode = N'DATA_STEWARD' AND IsDeleted = 0) AS r
 WHERE u.UserName LIKE N'perf.u%'
   AND t.ParentTenantId IS NOT NULL
   AND CAST (RIGHT (u.UserName, 5) AS INT) % 4 = 0;

SET @N2 = @@ROWCOUNT;
SET @T1 = SYSUTCDATETIME ();
PRINT CONCAT ('  ', @N, ' USER_ADMIN grants at the own tenant and ', @N2
            , ' DATA_STEWARD grants at the parent tenant, in ', DATEDIFF (MILLISECOND, @T0, @T1), ' ms.');

-- ---------------------------------------------------------------------------------------------------------------------
-- 5.  The scope cache, rebuilt through its own procedure.  This is the T-071 bulk measurement.
-- ---------------------------------------------------------------------------------------------------------------------
PRINT 'Rebuilding auth.ProfilePermissionScope for every profile...';
SET @T0 = SYSUTCDATETIME ();
EXEC auth.uspRebuildProfilePermissionScope;
SET @T1 = SYSUTCDATETIME ();

SELECT @N = COUNT (*) FROM auth.ProfilePermissionScope WHERE IsDeleted = 0;
PRINT CONCAT ('  ', @N, ' live scope rows in ', DATEDIFF (MILLISECOND, @T0, @T1), ' ms.');

-- ---------------------------------------------------------------------------------------------------------------------
-- 6.  Statistics.  Measuring a predicate against stale statistics measures the optimiser's ignorance, not the design.
-- ---------------------------------------------------------------------------------------------------------------------
PRINT 'Updating statistics on the three tables the predicate reads...';
UPDATE STATISTICS auth.ProfilePermissionScope WITH FULLSCAN;
UPDATE STATISTICS auth.TenantClosure          WITH FULLSCAN;
UPDATE STATISTICS auth.UserProfileRole        WITH FULLSCAN;
UPDATE STATISTICS auth.Tenant                 WITH FULLSCAN;
UPDATE STATISTICS auth.UserProfile            WITH FULLSCAN;

-- ---------------------------------------------------------------------------------------------------------------------
-- 7.  What was built.
-- ---------------------------------------------------------------------------------------------------------------------
SELECT Item      = N'Live tenants'
     , Rows_     = (SELECT COUNT (*) FROM auth.Tenant WHERE IsDeleted = 0)
     , Target    = N'about 1050 -- section 17 describes five levels, and depth is what closure size follows'
UNION ALL
SELECT N'Live closure rows'
     , (SELECT COUNT (*) FROM auth.TenantClosure WHERE IsDeleted = 0)
     , N'a few thousand (section 10.6)'
UNION ALL
SELECT N'Live profiles'
     , (SELECT COUNT (*) FROM auth.UserProfile WHERE IsDeleted = 0)
     , N'about 5000 (section 10.6)'
UNION ALL
SELECT N'Live role grants'
     , (SELECT COUNT (*) FROM auth.UserProfileRole WHERE IsDeleted = 0)
     , N'five per profile, plus a sixth for every fourth profile'
UNION ALL
SELECT N'Live scope rows'
     , (SELECT COUNT (*) FROM auth.ProfilePermissionScope WHERE IsDeleted = 0)
     , N'about 50000 -- 5000 profiles x about 10 permissions (section 10.6)';

-- The two distributions that are the whole point of loading anything at all.
SELECT Distribution = N'Closure rows per tenant'
     , Minimum      = MIN (c.Rows_)
     , Median       = APPROX_PERCENTILE_CONT (0.50) WITHIN GROUP (ORDER BY c.Rows_)
     , P95          = APPROX_PERCENTILE_CONT (0.95) WITHIN GROUP (ORDER BY c.Rows_)
     , Maximum      = MAX (c.Rows_)
  FROM (SELECT tc.DescendantTenantId, Rows_ = COUNT (*)
          FROM auth.TenantClosure AS tc
         WHERE tc.IsDeleted = 0
         GROUP BY tc.DescendantTenantId) AS c
UNION ALL
SELECT N'Scope rows per profile'
     , MIN (s.Rows_)
     , APPROX_PERCENTILE_CONT (0.50) WITHIN GROUP (ORDER BY s.Rows_)
     , APPROX_PERCENTILE_CONT (0.95) WITHIN GROUP (ORDER BY s.Rows_)
     , MAX (s.Rows_)
  FROM (SELECT pps.UserProfileId, Rows_ = COUNT (*)
          FROM auth.ProfilePermissionScope AS pps
         WHERE pps.IsDeleted = 0
         GROUP BY pps.UserProfileId) AS s
UNION ALL
SELECT N'Distinct scope tenants per profile'
     , MIN (d.Rows_)
     , APPROX_PERCENTILE_CONT (0.50) WITHIN GROUP (ORDER BY d.Rows_)
     , APPROX_PERCENTILE_CONT (0.95) WITHIN GROUP (ORDER BY d.Rows_)
     , MAX (d.Rows_)
  FROM (SELECT pps.UserProfileId, Rows_ = COUNT (DISTINCT pps.ScopeTenantId)
          FROM auth.ProfilePermissionScope AS pps
         WHERE pps.IsDeleted = 0
         GROUP BY pps.UserProfileId) AS d;

PRINT 'T069_load_volumes.sql: done.';
GO
