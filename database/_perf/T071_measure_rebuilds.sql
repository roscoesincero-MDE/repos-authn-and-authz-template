/***********************************************************************************************************************
Script:         T071_measure_rebuilds.sql
Purpose:        Measure the two cache-rebuild procedures -- auth.uspRebuildProfilePermissionScope (T-071) and
                auth.uspRebuildTenantClosure (T-072) -- against the T-069 population, and then against a tenant tree ten
                times larger.  NOT part of the install manifest and never run against a real database.
Tasks:          T-071, T-072.
Run with:       sqlcmd -S MDE-55TT2J4 -E -d testTemplateBoot -I -C -b -i database/_perf/T071_measure_rebuilds.sql
Depends on:     database/_perf/T069_load_volumes.sql must have run first.
Author:         Template project
CreateDate:     2026-09-20

WHY THESE TWO PROCEDURES ARE THE ONES WORTH TIMING
--------------------------------------------------
auth.ProfilePermissionScope and auth.TenantClosure are the only two DERIVED tables in the authorization model: every
other table is written by a user action and read as it stands.  These two are recomputed from the tables above them, and
the recomputation is on the write path of ordinary administration -- granting a role, moving a tenant, approving an
external organization.  So their cost is not a background-job cost that can be hidden overnight; it is the cost an
administrator waits for, and section 10.6's claim that the model "trades read cost for write cost" is only defensible if
somebody has measured the write cost.

THE HONEST COMPARISON FOR THE SCOPE REBUILD IS 1,000 CALLS AGAINST ONE CALL
---------------------------------------------------------------------------
auth.uspRebuildProfilePermissionScope takes a single optional @UserProfileId, and NULL means every profile.  There is no
batch overload and no list parameter, so an administrative operation that touches a thousand profiles -- retiring a
role, re-parenting a division -- has exactly two ways to put the cache right: call the procedure a thousand times, once
per profile, or call it once with NULL and rebuild all 5,000.  Those are the two numbers this script produces, and the
interesting result is the RATIO, because if one all-profiles call costs less than a thousand single-profile calls then
the procedure surface is quietly telling callers to prefer the blunt instrument, and that is a thing the design document
should say out loud rather than leave for somebody to discover in production.

The per-profile number is measured across twenty DIFFERENT profiles rather than twenty calls for the same one.  Calling
it twenty times for one profile measures a warm cache and nothing else; the population was built with a deliberate
spread of scope shapes (see T069_load_volumes.sql) and the measurement should sample that spread.

EVERY CALL WRITES TO logs.ExecutionLog, AND THAT IS PART OF THE COST, NOT NOISE
------------------------------------------------------------------------------
Both procedures carry the Rule 8 instrumentation block, so each invocation writes a logs.ExecutionLog row on entry and
updates it on exit.  The thousand-call run therefore also writes a thousand log rows, and that write is counted in the
thousand-call number.  It is not subtracted out, because a caller cannot subtract it out either: the instrumentation is
not optional and a procedure call that did not log would not be this procedure.  What the numbers below separate instead
is the FIXED per-call cost from the per-row cost, by measuring one call and a thousand calls of the same work.

SECTION 4 PERMANENTLY CHANGES THE POPULATION, WHICH IS WHY IT IS LAST
--------------------------------------------------------------------
T-072 asks for the closure rebuild at the expected size and at ten times the expected size.  Getting to ten times means
adding roughly 9,600 tenants, and nothing in this database hard-deletes, so that addition cannot be taken back -- the
same argument the T-069 header makes at length about unload scripts.  Every measurement that wants the expected-size
population therefore runs BEFORE section 4, and section 4 runs once, at the end, and re-measures what the larger tree
changed.  The way back is to drop the database and rebuild it:

    sqlcmd -S MDE-55TT2J4 -E -d master -Q "ALTER DATABASE testTemplateBoot SET SINGLE_USER
        WITH ROLLBACK IMMEDIATE; DROP DATABASE testTemplateBoot;"
    powershell -NoProfile -ExecutionPolicy Bypass -File database/Install-TemplateDatabase.ps1
        -DatabaseName testTemplateBoot -BootstrapAdminVerifierPhc <phc>

Section 4 also re-measures the ALL-PROFILES SCOPE REBUILD on the larger tree, and that is not padding.  It is a test of a
specific prediction: auth.ProfilePermissionScope stores the GRANT's scope tenant and not its expansion over descendants,
so a ten-times-larger tree should leave the scope rebuild almost unchanged, while the closure rebuild should grow with
it.  If the scope number moves with the tree, the prediction is wrong and section 10.6 is wrong with it.

THIS SCRIPT IS RE-RUNNABLE UP TO SECTION 4, AND REFUSES SECTION 4 TWICE
----------------------------------------------------------------------
Sections 1 to 3 only rebuild caches and can be run as often as you like; the rebuild is idempotent by construction and
that is the whole point of it.  Section 4 refuses on E-59021 if the expansion is already present, for the same reason
T-069 refuses a second load: a population that has been expanded twice is not comparable with one that was expanded
once.
***********************************************************************************************************************/
SET NOCOUNT ON;
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;

-- =====================================================================================================================
-- 0.  Refuse to measure an unloaded database.
-- =====================================================================================================================
IF NOT EXISTS (SELECT 1 FROM auth.Tenant WHERE TenantCode LIKE N'PERF-JUR-%')
BEGIN
    DECLARE @Failure0 NVARCHAR (2000)
          = N'This database holds no T-069 load, so there is nothing here to measure and a rebuild of an empty cache '
          + N'would report a number that means nothing. Run database/_perf/T069_load_volumes.sql first.';
    THROW 59020, @Failure0, 1;
END;
GO

-- =====================================================================================================================
-- 1 to 3.  The measurements at the EXPECTED population size.  One batch, so that one @Result table can hold all of it.
-- =====================================================================================================================
SET NOCOUNT ON;
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;

DECLARE @Result TABLE
(
    RowNo        INT IDENTITY (1, 1) PRIMARY KEY
  , Operation    NVARCHAR (70)  NOT NULL
  , TreeSize     NVARCHAR (30)  NOT NULL
  , Calls        INT            NOT NULL
  , TotalMs      BIGINT             NULL
  , MsPerCall    DECIMAL (18, 2)    NULL
  , CpuMs        BIGINT             NULL
  , LogicalReads BIGINT             NULL
  , ReadsPerCall BIGINT             NULL
  , RowsAfter    BIGINT             NULL
  , Notes        NVARCHAR (300)     NULL
);

-- The burst harness, identical to T070's: sys.dm_exec_requests carries cpu_time and logical_reads for the request that
-- is RUNNING, which is this batch, and is the only DMV that moves between two samples taken inside one batch.
DECLARE @T0 DATETIME2 (7), @T1 DATETIME2 (7)
      , @Cpu0 BIGINT, @Cpu1 BIGINT, @Rd0 BIGINT, @Rd1 BIGINT
      , @Iter INT, @Calls INT, @Prof INT, @N BIGINT, @Tree NVARCHAR (30), @Note NVARCHAR (300);

SELECT @N = COUNT (*) FROM auth.Tenant WHERE IsDeleted = 0;
SET @Tree = CONCAT (N'expected (', @N, N' tenants)');

-- ---------------------------------------------------------------------------------------------------------------------
-- 1.  T-071a. ONE PROFILE AT A TIME, twenty different profiles. This is the cost an administrator pays for a single
--     grant, and it is the number that matters most often because a single grant is the commonest administrative act.
-- ---------------------------------------------------------------------------------------------------------------------
PRINT 'Measuring auth.uspRebuildProfilePermissionScope, one profile at a time...';

DECLARE @Sample TABLE (Seq INT IDENTITY (1, 1) PRIMARY KEY, UserProfileId INT NOT NULL);

INSERT @Sample (UserProfileId)
SELECT TOP (20) p.UserProfileId
  FROM auth.UserProfile AS p
  JOIN auth.[User]      AS u ON u.UserId = p.UserId
 WHERE u.UserName LIKE N'perf.u%'
   AND p.IsDeleted = 0
 ORDER BY p.UserProfileId;

SET @Calls = (SELECT COUNT (*) FROM @Sample);
SET @Iter  = 0;

SELECT @Cpu0 = cpu_time, @Rd0 = logical_reads FROM sys.dm_exec_requests WHERE session_id = @@SPID;
SET @T0 = SYSUTCDATETIME ();

WHILE @Iter < @Calls
BEGIN
    SET @Iter = @Iter + 1;
    SELECT @Prof = UserProfileId FROM @Sample WHERE Seq = @Iter;
    EXEC auth.uspRebuildProfilePermissionScope @UserProfileId = @Prof;
END;

SET @T1 = SYSUTCDATETIME ();
SELECT @Cpu1 = cpu_time, @Rd1 = logical_reads FROM sys.dm_exec_requests WHERE session_id = @@SPID;

SELECT @N = COUNT (*) FROM auth.ProfilePermissionScope WHERE IsDeleted = 0;

INSERT @Result (Operation, TreeSize, Calls, TotalMs, MsPerCall, CpuMs, LogicalReads, ReadsPerCall, RowsAfter, Notes)
VALUES (N'uspRebuildProfilePermissionScope, one profile', @Tree, @Calls
      , DATEDIFF_BIG (MILLISECOND, @T0, @T1)
      , CAST (DATEDIFF_BIG (MICROSECOND, @T0, @T1) AS DECIMAL (18, 2)) / (@Calls * 1000.0)
      , @Cpu1 - @Cpu0, @Rd1 - @Rd0, (@Rd1 - @Rd0) / @Calls, @N
      , N'Twenty DIFFERENT profiles, not one profile twenty times, so the scope-shape spread is sampled.');

-- ---------------------------------------------------------------------------------------------------------------------
-- 2.  T-071b. A THOUSAND PROFILES, the two ways the procedure surface allows. First one call per profile, then one call
--     with @UserProfileId = NULL, which rebuilds all 5,000. The ratio is the finding.
-- ---------------------------------------------------------------------------------------------------------------------
PRINT 'Measuring a thousand sequential single-profile rebuilds...';

DECLARE @Bulk TABLE (Seq INT IDENTITY (1, 1) PRIMARY KEY, UserProfileId INT NOT NULL);

INSERT @Bulk (UserProfileId)
SELECT TOP (1000) p.UserProfileId
  FROM auth.UserProfile AS p
  JOIN auth.[User]      AS u ON u.UserId = p.UserId
 WHERE u.UserName LIKE N'perf.u%'
   AND p.IsDeleted = 0
 ORDER BY p.UserProfileId;

SET @Calls = (SELECT COUNT (*) FROM @Bulk);
SET @Iter  = 0;

SELECT @Cpu0 = cpu_time, @Rd0 = logical_reads FROM sys.dm_exec_requests WHERE session_id = @@SPID;
SET @T0 = SYSUTCDATETIME ();

WHILE @Iter < @Calls
BEGIN
    SET @Iter = @Iter + 1;
    SELECT @Prof = UserProfileId FROM @Bulk WHERE Seq = @Iter;
    EXEC auth.uspRebuildProfilePermissionScope @UserProfileId = @Prof;
END;

SET @T1 = SYSUTCDATETIME ();
SELECT @Cpu1 = cpu_time, @Rd1 = logical_reads FROM sys.dm_exec_requests WHERE session_id = @@SPID;

SELECT @N = COUNT (*) FROM auth.ProfilePermissionScope WHERE IsDeleted = 0;

INSERT @Result (Operation, TreeSize, Calls, TotalMs, MsPerCall, CpuMs, LogicalReads, ReadsPerCall, RowsAfter, Notes)
VALUES (N'uspRebuildProfilePermissionScope, 1000 x one profile', @Tree, @Calls
      , DATEDIFF_BIG (MILLISECOND, @T0, @T1)
      , CAST (DATEDIFF_BIG (MICROSECOND, @T0, @T1) AS DECIMAL (18, 2)) / (@Calls * 1000.0)
      , @Cpu1 - @Cpu0, @Rd1 - @Rd0, (@Rd1 - @Rd0) / @Calls, @N
      , N'1000 calls, 1000 transactions and 1000 logs.ExecutionLog rows. The log write is part of the cost.');

PRINT 'Measuring one all-profiles rebuild...';

SELECT @Cpu0 = cpu_time, @Rd0 = logical_reads FROM sys.dm_exec_requests WHERE session_id = @@SPID;
SET @T0 = SYSUTCDATETIME ();

EXEC auth.uspRebuildProfilePermissionScope @UserProfileId = NULL;

SET @T1 = SYSUTCDATETIME ();
SELECT @Cpu1 = cpu_time, @Rd1 = logical_reads FROM sys.dm_exec_requests WHERE session_id = @@SPID;

SELECT @N = COUNT (*) FROM auth.ProfilePermissionScope WHERE IsDeleted = 0;

INSERT @Result (Operation, TreeSize, Calls, TotalMs, MsPerCall, CpuMs, LogicalReads, ReadsPerCall, RowsAfter, Notes)
VALUES (N'uspRebuildProfilePermissionScope, all profiles', @Tree, 1
      , DATEDIFF_BIG (MILLISECOND, @T0, @T1)
      , CAST (DATEDIFF_BIG (MICROSECOND, @T0, @T1) AS DECIMAL (18, 2)) / 1000.0
      , @Cpu1 - @Cpu0, @Rd1 - @Rd0, @Rd1 - @Rd0, @N
      , N'One call, one transaction, one log row -- and FIVE times the profiles the row above touched.');

-- ---------------------------------------------------------------------------------------------------------------------
-- 3.  T-072a. THE CLOSURE REBUILD at the expected tree size. Five calls, because this procedure takes no arguments and
--     always rebuilds the whole closure: there is no single-tenant variant to compare against.
-- ---------------------------------------------------------------------------------------------------------------------
PRINT 'Measuring auth.uspRebuildTenantClosure at the expected tree size...';

SET @Calls = 5;
SET @Iter  = 0;

SELECT @Cpu0 = cpu_time, @Rd0 = logical_reads FROM sys.dm_exec_requests WHERE session_id = @@SPID;
SET @T0 = SYSUTCDATETIME ();

WHILE @Iter < @Calls
BEGIN
    EXEC auth.uspRebuildTenantClosure;
    SET @Iter = @Iter + 1;
END;

SET @T1 = SYSUTCDATETIME ();
SELECT @Cpu1 = cpu_time, @Rd1 = logical_reads FROM sys.dm_exec_requests WHERE session_id = @@SPID;

SELECT @N = COUNT (*) FROM auth.TenantClosure WHERE IsDeleted = 0;
SELECT @Note = CONCAT (N'Max depth ', MAX (Depth), N'. No single-tenant variant exists, so this is the cost of ANY '
                     , N'tenant move, however small.')
  FROM auth.TenantClosure WHERE IsDeleted = 0;

INSERT @Result (Operation, TreeSize, Calls, TotalMs, MsPerCall, CpuMs, LogicalReads, ReadsPerCall, RowsAfter, Notes)
VALUES (N'uspRebuildTenantClosure', @Tree, @Calls
      , DATEDIFF_BIG (MILLISECOND, @T0, @T1)
      , CAST (DATEDIFF_BIG (MICROSECOND, @T0, @T1) AS DECIMAL (18, 2)) / (@Calls * 1000.0)
      , @Cpu1 - @Cpu0, @Rd1 - @Rd0, (@Rd1 - @Rd0) / @Calls, @N, @Note);

SELECT Operation, TreeSize, Calls, TotalMs, MsPerCall, CpuMs, LogicalReads, ReadsPerCall, RowsAfter, Notes
  FROM @Result
 ORDER BY RowNo;
GO

-- =====================================================================================================================
-- 4.  T-072b. TEN TIMES THE TREE. This section is destructive of the population -- see the file header -- so it is last
--     and it refuses to run twice.
--
--     The expansion adds a SIXTH level: twelve sub-divisions under each of the 800 jurisdictions, 9,600 new tenants, for
--     roughly 10,650 live tenants in total. Going deeper rather than wider is deliberate. Closure rows per tenant are a
--     function of DEPTH, so a wider tree at the same depth would multiply the tenant count without multiplying the work
--     per tenant, and the rebuild would look artificially cheap. Depth 6 is past anything section 17 describes and that
--     is the point: this is the pessimistic case, not the expected one.
--
--     No profiles, users, case files or grants are added. The new tenants are empty, which isolates what is being
--     measured -- the closure rebuild's sensitivity to tree size, and the scope rebuild's insensitivity to it.
-- =====================================================================================================================
SET NOCOUNT ON;
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;

IF EXISTS (SELECT 1 FROM auth.Tenant WHERE TenantCode LIKE N'PERF-SUB-%')
BEGIN
    DECLARE @Failure4 NVARCHAR (2000)
          = N'This database has already been expanded once (tenants coded PERF-SUB-% exist), and nothing here '
          + N'hard-deletes, so it cannot be expanded again to a comparable size. Drop the database and rebuild it, then '
          + N'run T069_load_volumes.sql and this script in order. See the file header.';
    THROW 59021, @Failure4, 1;
END;
GO

SET NOCOUNT ON;
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;

DECLARE @Result4 TABLE
(
    RowNo        INT IDENTITY (1, 1) PRIMARY KEY
  , Operation    NVARCHAR (70)  NOT NULL
  , TreeSize     NVARCHAR (30)  NOT NULL
  , Calls        INT            NOT NULL
  , TotalMs      BIGINT             NULL
  , MsPerCall    DECIMAL (18, 2)    NULL
  , CpuMs        BIGINT             NULL
  , LogicalReads BIGINT             NULL
  , RowsAfter    BIGINT             NULL
  , Notes        NVARCHAR (300)     NULL
);

DECLARE @T0 DATETIME2 (7), @T1 DATETIME2 (7)
      , @Cpu0 BIGINT, @Cpu1 BIGINT, @Rd0 BIGINT, @Rd1 BIGINT
      , @Iter INT, @Calls INT, @N BIGINT, @Tree NVARCHAR (30), @Note NVARCHAR (300)
      , @ApplicationId INT = (SELECT ApplicationId FROM auth.Application WHERE ApplicationCode = N'TEMPLATE' AND IsDeleted = 0)
      , @DivisionTypeId INT = (SELECT TenantTypeId FROM auth.TenantType WHERE TenantTypeCode = N'Division' AND IsDeleted = 0)
      , @Actor NVARCHAR (128) = N'T071_measure';

PRINT 'Expanding the tenant tree to roughly ten times its loaded size...';
SET @T0 = SYSUTCDATETIME ();

INSERT auth.Tenant (ApplicationId, TenantCode, TenantName, TenantTypeId, TenantTypeCode, ParentTenantId, IsActive
                  , auditCreatedBy, auditModifiedBy)
SELECT @ApplicationId
     , CONCAT (N'PERF-SUB-', j.TenantId, N'-', FORMAT (g.value, N'00'))
     , CONCAT (j.TenantName, N' Unit ', g.value)
     , @DivisionTypeId
     , N'Division'
     , j.TenantId
     , 1
     , @Actor
     , @Actor
  FROM auth.Tenant AS j
 CROSS JOIN GENERATE_SERIES (1, 12) AS g
 WHERE j.TenantCode LIKE N'PERF-JUR-%'
   AND j.IsDeleted  = 0;

SET @T1 = SYSUTCDATETIME ();
SELECT @N = COUNT (*) FROM auth.Tenant WHERE IsDeleted = 0;
PRINT CONCAT ('  ', @N, ' live tenants after the expansion, built in ', DATEDIFF_BIG (MILLISECOND, @T0, @T1), ' ms.');

SET @Tree = CONCAT (N'ten times (', @N, N' tenants)');

-- ---------------------------------------------------------------------------------------------------------------------
-- 4a. The closure rebuild on the larger tree. Three calls rather than five: if this is as expensive as it is expected to
--     be, five is a minute of waiting for a third significant figure nobody needs.
-- ---------------------------------------------------------------------------------------------------------------------
PRINT 'Measuring auth.uspRebuildTenantClosure on the expanded tree...';

SET @Calls = 3;
SET @Iter  = 0;

SELECT @Cpu0 = cpu_time, @Rd0 = logical_reads FROM sys.dm_exec_requests WHERE session_id = @@SPID;
SET @T0 = SYSUTCDATETIME ();

WHILE @Iter < @Calls
BEGIN
    EXEC auth.uspRebuildTenantClosure;
    SET @Iter = @Iter + 1;
END;

SET @T1 = SYSUTCDATETIME ();
SELECT @Cpu1 = cpu_time, @Rd1 = logical_reads FROM sys.dm_exec_requests WHERE session_id = @@SPID;

SELECT @N = COUNT (*) FROM auth.TenantClosure WHERE IsDeleted = 0;
SELECT @Note = CONCAT (N'Max depth ', MAX (Depth), N'. Compare this against the expected-size row in the first result '
                     , N'set: the growth factor is the answer T-072 wants.')
  FROM auth.TenantClosure WHERE IsDeleted = 0;

INSERT @Result4 (Operation, TreeSize, Calls, TotalMs, MsPerCall, CpuMs, LogicalReads, RowsAfter, Notes)
VALUES (N'uspRebuildTenantClosure', @Tree, @Calls
      , DATEDIFF_BIG (MILLISECOND, @T0, @T1)
      , CAST (DATEDIFF_BIG (MICROSECOND, @T0, @T1) AS DECIMAL (18, 2)) / (@Calls * 1000.0)
      , @Cpu1 - @Cpu0, @Rd1 - @Rd0, @N, @Note);

-- ---------------------------------------------------------------------------------------------------------------------
-- 4b. The all-profiles scope rebuild on the larger tree. THE PREDICTION UNDER TEST: auth.ProfilePermissionScope records
--     the grant's own scope tenant, not its expansion over descendants, so this number should be within noise of the
--     expected-size number even though the tree is ten times larger. If it is not, section 10.6 is wrong about what the
--     scope table holds.
-- ---------------------------------------------------------------------------------------------------------------------
PRINT 'Re-measuring the all-profiles scope rebuild on the expanded tree...';

SELECT @Cpu0 = cpu_time, @Rd0 = logical_reads FROM sys.dm_exec_requests WHERE session_id = @@SPID;
SET @T0 = SYSUTCDATETIME ();

EXEC auth.uspRebuildProfilePermissionScope @UserProfileId = NULL;

SET @T1 = SYSUTCDATETIME ();
SELECT @Cpu1 = cpu_time, @Rd1 = logical_reads FROM sys.dm_exec_requests WHERE session_id = @@SPID;

SELECT @N = COUNT (*) FROM auth.ProfilePermissionScope WHERE IsDeleted = 0;

INSERT @Result4 (Operation, TreeSize, Calls, TotalMs, MsPerCall, CpuMs, LogicalReads, RowsAfter, Notes)
VALUES (N'uspRebuildProfilePermissionScope, all profiles', @Tree, 1
      , DATEDIFF_BIG (MILLISECOND, @T0, @T1)
      , CAST (DATEDIFF_BIG (MICROSECOND, @T0, @T1) AS DECIMAL (18, 2)) / 1000.0
      , @Cpu1 - @Cpu0, @Rd1 - @Rd0, @N
      , N'Should be within noise of the expected-size figure. Same profiles, same grants, ten times the tenants.');

SELECT Operation, TreeSize, Calls, TotalMs, MsPerCall, CpuMs, LogicalReads, RowsAfter, Notes
  FROM @Result4
 ORDER BY RowNo;

PRINT 'T071_measure_rebuilds.sql: done. This database is now EXPANDED and its predicate numbers are no longer';
PRINT '  comparable with T070''s. Drop and rebuild before measuring predicates again.';
GO


