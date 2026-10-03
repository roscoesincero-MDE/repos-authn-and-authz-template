/***********************************************************************************************************************
Script:         T070_measure_predicates.sql
Purpose:        Measure what the row-level security predicate actually costs, on the three access patterns section 10.6
                names -- a point read, a range scan and a large aggregate -- against an unprotected copy of the same
                rows; measure the per-call config read the sampled probe adds to auth.uspDemandPermission; and confirm
                the plan shape is a semi-join with the seek on the inner side.
Tasks:          T-070 (the predicate and the config read), T-073 (the plan shape).
Depends on:     database/_perf/T069_load_volumes.sql, which must have run against this database.
Run with:       sqlcmd -S MDE-55TT2J4 -E -d testTemplateBoot -I -C -b -i database/_perf/T070_measure_predicates.sql
Author:         Template project
CreateDate:     2026-09-20

THE ONLY HONEST BASELINE IS AN UNPROTECTED COPY OF THE SAME ROWS
----------------------------------------------------------------
"How expensive is the predicate" has three plausible baselines and two of them are wrong.

It is NOT the same query with BypassRowSecurity = 1.  That flag is the right-hand side of an OR inside the predicate, so
the predicate function still runs, is still inlined into the plan, and still forces the optimiser to reason about a join
it may then short-circuit.  Measuring that measures the escape hatch, not the absence of the policy.

It is NOT the same query with the policy disabled by ALTER SECURITY POLICY.  That is closer, but disabling the policy on
a database anybody else is reading is an unsafe thing for a measurement script to do, and the plan would be invalidated
for reasons other than the one being measured.

So this script makes dbo.PerfCaseFileNoRls: the same columns, the same indexes, the same rows, not registered in
config.TenantScopedTable and therefore not bound by TenantAccessPolicy.  Two tables, one query shape, one difference.
That difference is the number.

WHY LOGICAL READS MATTER MORE THAN MILLISECONDS HERE
----------------------------------------------------
Elapsed time on a development instance with a warm cache and one connection is the least transferable number this script
can produce.  Logical reads are not: they are what the predicate makes the engine touch, they do not depend on the disk,
and they are what will still be true on the production box.  Both are reported; the reads are the ones to argue from.

Both come from sys.dm_exec_REQUESTS and not from sys.dm_exec_sessions, and that distinction cost a run to discover.
sys.dm_exec_sessions does carry cpu_time and logical_reads for the session, but it is updated when a REQUEST COMPLETES,
so a batch that samples it before and after a loop inside itself reads the same stale value twice and every delta comes
out as exactly zero.  sys.dm_exec_requests carries the live counters for the request that is currently executing --
which, inside this batch, is this batch -- so sampling it before and after each burst gives the burst's own consumption.

That is also why every measurement here is a burst and not a single execution, and why the script holds one connection
throughout.

THE SESSION CONTEXT IS SET BY HAND, DELIBERATELY, AND THAT IS NOT HOW AN APPLICATION DOES IT
--------------------------------------------------------------------------------------------
auth.uspSetSessionContext sets its five identity keys with @read_only = 1, which is correct for an application: a
connection that has been told who it is cannot be told otherwise, and a profile switch therefore spends the connection
(G-36, BL-057).  It is also fatal to a measurement script, which needs to compare a one-scope-tenant profile against a
two-scope-tenant profile and cannot open a second connection from inside a batch.

So this script calls sp_set_session_context directly, with @read_only omitted, and switches profiles freely.  Nothing
here is a model of how to write an application.  The predicates read exactly the same keys either way, which is the only
property the measurement depends on.
***********************************************************************************************************************/
SET NOCOUNT ON;
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;

DECLARE @CaseFiles     INT = 200000
      , @NotesPerCase  INT = 1
      , @Failure       NVARCHAR (2000) = NULL
      , @Msg           NVARCHAR (1000) = NULL
      , @N             INT = NULL
      , @LeafCount     INT = NULL
      , @Actor         NVARCHAR (128) = N'T070_measure';

-- =====================================================================================================================
-- 0.  Refuse to measure an unloaded database. A measurement against 0 rows is not a small number, it is a wrong one.
-- =====================================================================================================================
IF NOT EXISTS (SELECT 1 FROM auth.Tenant WHERE TenantCode LIKE N'PERF-JUR-%')
   OR (SELECT COUNT (*) FROM auth.ProfilePermissionScope WHERE IsDeleted = 0) < 10000
BEGIN
    SET @Failure = N'This database has not been loaded. Run database/_perf/T069_load_volumes.sql first: the predicate '
                 + N'cost is a function of closure rows per tenant and scope rows per profile, and on an empty database '
                 + N'both are 1, which measures nothing that will ever be true in production.';
    THROW 59010, @Failure, 1;
END;

-- The measurement runs as a real profile, but the SETUP has to write rows into a thousand different tenants, which the
-- insert block predicate correctly forbids: P-06 requires TenantId = ActingTenantId on every insert, one tenant at a
-- time. BypassRowSecurity is the documented maintenance escape and this is exactly what it is for.
EXEC sys.sp_set_session_context @key = N'BypassRowSecurity', @value = 1;

-- =====================================================================================================================
-- 1.  The protected table, populated. 200 case files per leaf-ish tenant.
-- =====================================================================================================================
IF NOT EXISTS (SELECT 1 FROM dbo.CaseFile WHERE CaseNumber LIKE N'PERF-%')
BEGIN
    PRINT 'Populating dbo.CaseFile...';

    DECLARE @Leaf TABLE (Seq INT PRIMARY KEY, TenantId INT NOT NULL UNIQUE);

    INSERT @Leaf (Seq, TenantId)
    SELECT ROW_NUMBER () OVER (ORDER BY t.TenantId) - 1, t.TenantId
      FROM auth.Tenant AS t
     WHERE t.TenantCode LIKE N'PERF-PRG-%'
        OR t.TenantCode LIKE N'PERF-JUR-%';

    SET @LeafCount = (SELECT COUNT (*) FROM @Leaf);

    INSERT dbo.CaseFile (TenantId, CaseNumber, Title, CaseStatus, AssignedToProfileId, OpenedUtc
                       , auditCreatedBy, auditModifiedBy)
    SELECT l.TenantId
         , CONCAT (N'PERF-', FORMAT (g.value, N'0000000'))
         , CONCAT (N'Perf case file ', g.value)
         , CASE g.value % 4 WHEN 0 THEN 'draft' WHEN 1 THEN 'open' WHEN 2 THEN 'closed' ELSE 'open' END
         , NULL
         , DATEADD (MINUTE, -g.value, SYSUTCDATETIME ())
         , @Actor
         , @Actor
      FROM GENERATE_SERIES (1, @CaseFiles) AS g
      JOIN @Leaf AS l ON l.Seq = g.value % (SELECT COUNT (*) FROM @Leaf);

    PRINT CONCAT ('  ', @@ROWCOUNT, ' case files.');

    INSERT dbo.CaseNote (TenantId, CaseFileId, NoteText, IsInternal, AuthoredByProfileId, AuthoredUtc
                       , auditCreatedBy, auditModifiedBy)
    SELECT cf.TenantId
         , cf.CaseFileId
         , CONCAT (N'Perf note on ', cf.CaseNumber)
         , 0
         , p.UserProfileId
         , cf.OpenedUtc
         , @Actor
         , @Actor
      FROM dbo.CaseFile AS cf
     CROSS APPLY (SELECT TOP (1) up.UserProfileId
                    FROM auth.UserProfile AS up
                   WHERE up.TenantId = cf.TenantId
                     AND up.IsDeleted = 0
                   ORDER BY up.UserProfileId) AS p
     WHERE cf.CaseNumber LIKE N'PERF-%';

    PRINT CONCAT ('  ', @@ROWCOUNT, ' case notes.');
END;
ELSE
BEGIN
    PRINT 'dbo.CaseFile already holds PERF- rows; leaving them alone.';
END;
GO

-- =====================================================================================================================
-- 2.  The unprotected twin. Same columns, same indexes, same rows, NOT registered in config.TenantScopedTable and
--     therefore not bound by TenantAccessPolicy. This is the baseline and there is no other honest one.
-- =====================================================================================================================
IF OBJECT_ID (N'dbo.PerfCaseFileNoRls', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.PerfCaseFileNoRls
    (
        CaseFileId            INT            NOT NULL
      , TenantId              INT            NOT NULL
      , CaseNumber            NVARCHAR (50)  NOT NULL
      , Title                 NVARCHAR (400) NOT NULL
      , CaseStatus            VARCHAR (20)   NOT NULL
      , AssignedToProfileId   INT                NULL
      , OpenedUtc             DATETIME2 (3)  NOT NULL
      , ClosedUtc             DATETIME2 (3)      NULL
        -- The full audit block, carried for a reason that is not compliance: the comparison is only fair if the two
        -- tables have the SAME ROW WIDTH. Rows per page follows width, logical reads follows rows per page, and a
        -- baseline with six fewer columns would read fewer pages for reasons that have nothing to do with the policy.
      , IsDeleted             BIT            NOT NULL
            CONSTRAINT DF_dbo_PerfCaseFileNoRls_IsDeleted DEFAULT (0)
      , auditDeletedBy        NVARCHAR (128)     NULL
      , auditDeletedDateUtc   DATETIME2 (3)      NULL
      , auditCreatedBy        NVARCHAR (128) NOT NULL
            CONSTRAINT DF_dbo_PerfCaseFileNoRls_auditCreatedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditCreatedDateUtc   DATETIME2 (3)  NOT NULL
            CONSTRAINT DF_dbo_PerfCaseFileNoRls_auditCreatedDateUtc DEFAULT (SYSUTCDATETIME ())
      , auditModifiedBy       NVARCHAR (128) NOT NULL
            CONSTRAINT DF_dbo_PerfCaseFileNoRls_auditModifiedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditModifiedDateUtc  DATETIME2 (3)  NOT NULL
            CONSTRAINT DF_dbo_PerfCaseFileNoRls_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ())
      , CONSTRAINT PK_dbo_PerfCaseFileNoRls PRIMARY KEY CLUSTERED (CaseFileId)
      , CONSTRAINT CK_dbo_PerfCaseFileNoRls_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS NULL     AND auditDeletedDateUtc IS NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL))
    );
END;

-- The same two access paths the protected table has, so a plan difference is a POLICY difference and not an indexing
-- difference. Both are filtered exactly as dbo.CaseFile's are, and both are guarded so the script runs twice.
IF OBJECT_ID (N'dbo.PerfCaseFileNoRls', N'U') IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM sys.indexes
                    WHERE name = N'UX_dbo_PerfCaseFileNoRls_Tenant_CaseNumber'
                      AND object_id = OBJECT_ID (N'dbo.PerfCaseFileNoRls'))
BEGIN
    CREATE UNIQUE NONCLUSTERED INDEX UX_dbo_PerfCaseFileNoRls_Tenant_CaseNumber
        ON dbo.PerfCaseFileNoRls (TenantId, CaseNumber) WHERE IsDeleted = 0;
END;

IF OBJECT_ID (N'dbo.PerfCaseFileNoRls', N'U') IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM sys.indexes
                    WHERE name = N'IX_dbo_PerfCaseFileNoRls_Tenant_Status'
                      AND object_id = OBJECT_ID (N'dbo.PerfCaseFileNoRls'))
BEGIN
    CREATE NONCLUSTERED INDEX IX_dbo_PerfCaseFileNoRls_Tenant_Status
        ON dbo.PerfCaseFileNoRls (TenantId, CaseStatus) INCLUDE (Title, OpenedUtc) WHERE IsDeleted = 0;
END;

IF OBJECT_ID (N'dbo.PerfCaseFileNoRls', N'U') IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM sys.extended_properties
                    WHERE major_id = OBJECT_ID (N'dbo.PerfCaseFileNoRls') AND minor_id = 0 AND name = N'MS_Description')
BEGIN
    -- EXEC will not take an expression for a parameter (Msg 102 on the first '+'), so the text is built first and the
    -- variable is passed. Every EXEC in this project that carries prose does the same.
    DECLARE @Desc NVARCHAR (MAX) =
              N'THROWAWAY. The unprotected twin of dbo.CaseFile, created by database/_perf/'
            + N'T070_measure_predicates.sql (T-070) to serve as the baseline for what TenantAccessPolicy '
            + N'costs. Same columns, same indexes, same row width, same rows, deliberately NOT registered in '
            + N'config.TenantScopedTable so that no security predicate binds to it. It holds a copy of real '
            + N'tenant data with no row-level security whatsoever and MUST NOT EXIST in any database anybody '
            + N'relies on. Drop it when the Phase 5 numbers are recorded.';

    EXEC util.uspSetObjectDescription
          @SchemaName  = N'dbo'
        , @ObjectType  = N'TABLE'
        , @ObjectName  = N'PerfCaseFileNoRls'
        , @Description = @Desc;
END;

IF NOT EXISTS (SELECT 1 FROM dbo.PerfCaseFileNoRls)
BEGIN
    PRINT 'Copying dbo.CaseFile into the unprotected twin...';

    EXEC sys.sp_set_session_context @key = N'BypassRowSecurity', @value = 1;

    INSERT dbo.PerfCaseFileNoRls (CaseFileId, TenantId, CaseNumber, Title, CaseStatus, AssignedToProfileId
                                , OpenedUtc, ClosedUtc, IsDeleted, auditDeletedBy, auditDeletedDateUtc
                                , auditCreatedBy, auditCreatedDateUtc, auditModifiedBy, auditModifiedDateUtc)
    SELECT cf.CaseFileId, cf.TenantId, cf.CaseNumber, cf.Title, cf.CaseStatus, cf.AssignedToProfileId
         , cf.OpenedUtc, cf.ClosedUtc, cf.IsDeleted, cf.auditDeletedBy, cf.auditDeletedDateUtc
         , cf.auditCreatedBy, cf.auditCreatedDateUtc
         , COALESCE (cf.auditModifiedBy, cf.auditCreatedBy)
         , COALESCE (cf.auditModifiedDateUtc, cf.auditCreatedDateUtc)
      FROM dbo.CaseFile AS cf;

    PRINT CONCAT ('  ', @@ROWCOUNT, ' rows copied.');
END;

UPDATE STATISTICS dbo.CaseFile          WITH FULLSCAN;
UPDATE STATISTICS dbo.CaseNote          WITH FULLSCAN;
UPDATE STATISTICS dbo.PerfCaseFileNoRls WITH FULLSCAN;
GO

-- =====================================================================================================================
-- 3.  The measurements.
-- =====================================================================================================================
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;

DECLARE @Result TABLE
(
    RowNo        INT IDENTITY (1, 1) PRIMARY KEY
  , Pattern      NVARCHAR (60)  NOT NULL
  , Protection   NVARCHAR (30)  NOT NULL
  , Profile_     NVARCHAR (40)      NULL
  , Iterations   INT            NOT NULL
  , TotalMs      INT                NULL
  , UsPerCall    DECIMAL (18, 1)    NULL
  , CpuMs        BIGINT             NULL
  , LogicalReads BIGINT             NULL
  , ReadsPerCall DECIMAL (18, 1)    NULL
  , RowsSeen     BIGINT             NULL
);

-- Two profiles: the median case (one scope tenant) and the P95 case (two). The load script put a DATA_STEWARD grant at
-- the parent tenant on every fourth profile, so a profile number divisible by four is the two-scope-tenant case.
DECLARE @Prof1 INT = (SELECT MIN (p.UserProfileId)
                        FROM auth.UserProfile AS p
                        JOIN auth.[User]      AS u ON u.UserId = p.UserId
                       WHERE u.UserName LIKE N'perf.u%'
                         AND CAST (RIGHT (u.UserName, 5) AS INT) % 4 = 1)
      , @Prof2 INT = (SELECT MIN (p.UserProfileId)
                        FROM auth.UserProfile AS p
                        JOIN auth.[User]      AS u ON u.UserId = p.UserId
                       WHERE u.UserName LIKE N'perf.u%'
                         AND CAST (RIGHT (u.UserName, 5) AS INT) % 4 = 0)
      , @Tenant1 INT
      , @Tenant2 INT
      , @Scope1  INT
      , @Scope2  INT
      , @Clos1   INT
      , @Clos2   INT;

SELECT @Tenant1 = TenantId FROM auth.UserProfile WHERE UserProfileId = @Prof1;
SELECT @Tenant2 = TenantId FROM auth.UserProfile WHERE UserProfileId = @Prof2;
SELECT @Scope1 = COUNT (*) FROM auth.ProfilePermissionScope WHERE UserProfileId = @Prof1 AND IsDeleted = 0;
SELECT @Scope2 = COUNT (*) FROM auth.ProfilePermissionScope WHERE UserProfileId = @Prof2 AND IsDeleted = 0;
SELECT @Clos1 = COUNT (*) FROM auth.TenantClosure WHERE DescendantTenantId = @Tenant1 AND IsDeleted = 0;
SELECT @Clos2 = COUNT (*) FROM auth.TenantClosure WHERE DescendantTenantId = @Tenant2 AND IsDeleted = 0;

PRINT CONCAT ('Profile A = ', @Prof1, ' at tenant ', @Tenant1, ': ', @Scope1, ' scope rows, ', @Clos1
            , ' closure rows above its tenant.');
PRINT CONCAT ('Profile B = ', @Prof2, ' at tenant ', @Tenant2, ': ', @Scope2, ' scope rows, ', @Clos2
            , ' closure rows above its tenant.');

-- The burst harness. sys.dm_exec_requests carries cpu_time and logical_reads for the request that is RUNNING, which is
-- this batch, and is therefore the only DMV that moves between two samples taken inside one batch -- see the header.
DECLARE @T0 DATETIME2 (7), @T1 DATETIME2 (7)
      , @Cpu0 BIGINT, @Cpu1 BIGINT, @Rd0 BIGINT, @Rd1 BIGINT
      , @Iter INT, @Reps INT, @Sink INT, @RowsSeen BIGINT, @Id INT;

-- ---------------------------------------------------------------------------------------------------------------------
-- 3a. POINT READ. One row by primary key -- the cheapest possible query and therefore the one where a predicate costs
--     the largest PROPORTION of the total. This is the pattern that decides D-07.
-- ---------------------------------------------------------------------------------------------------------------------
SET @Reps = 2000;
SET @Id   = (SELECT MIN (CaseFileId) FROM dbo.PerfCaseFileNoRls WHERE TenantId = @Tenant1);

EXEC sys.sp_set_session_context @key = N'BypassRowSecurity', @value = NULL;
EXEC sys.sp_set_session_context @key = N'UserProfileId',     @value = @Prof1;
EXEC sys.sp_set_session_context @key = N'ActingTenantId',    @value = @Tenant1;

SET @Iter = 0;
SET @RowsSeen = 0;
SELECT @Cpu0 = cpu_time, @Rd0 = logical_reads FROM sys.dm_exec_requests WHERE session_id = @@SPID;
SET @T0 = SYSUTCDATETIME ();

WHILE @Iter < @Reps
BEGIN
    SELECT @Sink = cf.TenantId /*T073-POINT*/ FROM dbo.CaseFile AS cf WHERE cf.CaseFileId = @Id AND cf.IsDeleted = 0;
    SET @RowsSeen = @RowsSeen + @@ROWCOUNT;
    SET @Iter = @Iter + 1;
END;

SET @T1 = SYSUTCDATETIME ();
SELECT @Cpu1 = cpu_time, @Rd1 = logical_reads FROM sys.dm_exec_requests WHERE session_id = @@SPID;

INSERT @Result (Pattern, Protection, Profile_, Iterations, TotalMs, UsPerCall, CpuMs, LogicalReads, ReadsPerCall, RowsSeen)
VALUES (N'Point read by primary key', N'RLS bound', N'A (1 scope tenant)', @Reps
      , DATEDIFF (MILLISECOND, @T0, @T1)
      , CAST (DATEDIFF_BIG (MICROSECOND, @T0, @T1) AS DECIMAL (18, 1)) / @Reps
      , @Cpu1 - @Cpu0, @Rd1 - @Rd0, CAST (@Rd1 - @Rd0 AS DECIMAL (18, 1)) / @Reps, @RowsSeen);

SET @Iter = 0;
SET @RowsSeen = 0;
SELECT @Cpu0 = cpu_time, @Rd0 = logical_reads FROM sys.dm_exec_requests WHERE session_id = @@SPID;
SET @T0 = SYSUTCDATETIME ();

WHILE @Iter < @Reps
BEGIN
    SELECT @Sink = cf.TenantId FROM dbo.PerfCaseFileNoRls AS cf WHERE cf.CaseFileId = @Id AND cf.IsDeleted = 0;
    SET @RowsSeen = @RowsSeen + @@ROWCOUNT;
    SET @Iter = @Iter + 1;
END;

SET @T1 = SYSUTCDATETIME ();
SELECT @Cpu1 = cpu_time, @Rd1 = logical_reads FROM sys.dm_exec_requests WHERE session_id = @@SPID;

INSERT @Result (Pattern, Protection, Profile_, Iterations, TotalMs, UsPerCall, CpuMs, LogicalReads, ReadsPerCall, RowsSeen)
VALUES (N'Point read by primary key', N'no RLS (baseline)', NULL, @Reps
      , DATEDIFF (MILLISECOND, @T0, @T1)
      , CAST (DATEDIFF_BIG (MICROSECOND, @T0, @T1) AS DECIMAL (18, 1)) / @Reps
      , @Cpu1 - @Cpu0, @Rd1 - @Rd0, CAST (@Rd1 - @Rd0 AS DECIMAL (18, 1)) / @Reps, @RowsSeen);

-- ---------------------------------------------------------------------------------------------------------------------
-- 3b. RANGE SCAN. One tenant's case files by status -- the pattern a list screen issues, and the one where the
--     predicate's semi-join has to be evaluated against a range rather than a single row.
-- ---------------------------------------------------------------------------------------------------------------------
SET @Reps = 500;

SET @Iter = 0;
SET @RowsSeen = 0;
SELECT @Cpu0 = cpu_time, @Rd0 = logical_reads FROM sys.dm_exec_requests WHERE session_id = @@SPID;
SET @T0 = SYSUTCDATETIME ();

WHILE @Iter < @Reps
BEGIN
    SELECT @Sink = COUNT (*) /*T073-RANGE*/
      FROM dbo.CaseFile AS cf
     WHERE cf.TenantId   = @Tenant1
       AND cf.CaseStatus = 'open'
       AND cf.IsDeleted  = 0;
    SET @RowsSeen = @RowsSeen + @Sink;
    SET @Iter = @Iter + 1;
END;

SET @T1 = SYSUTCDATETIME ();
SELECT @Cpu1 = cpu_time, @Rd1 = logical_reads FROM sys.dm_exec_requests WHERE session_id = @@SPID;

INSERT @Result (Pattern, Protection, Profile_, Iterations, TotalMs, UsPerCall, CpuMs, LogicalReads, ReadsPerCall, RowsSeen)
VALUES (N'Range scan, one tenant by status', N'RLS bound', N'A (1 scope tenant)', @Reps
      , DATEDIFF (MILLISECOND, @T0, @T1)
      , CAST (DATEDIFF_BIG (MICROSECOND, @T0, @T1) AS DECIMAL (18, 1)) / @Reps
      , @Cpu1 - @Cpu0, @Rd1 - @Rd0, CAST (@Rd1 - @Rd0 AS DECIMAL (18, 1)) / @Reps, @RowsSeen);

SET @Iter = 0;
SET @RowsSeen = 0;
SELECT @Cpu0 = cpu_time, @Rd0 = logical_reads FROM sys.dm_exec_requests WHERE session_id = @@SPID;
SET @T0 = SYSUTCDATETIME ();

WHILE @Iter < @Reps
BEGIN
    SELECT @Sink = COUNT (*)
      FROM dbo.PerfCaseFileNoRls AS cf
     WHERE cf.TenantId   = @Tenant1
       AND cf.CaseStatus = 'open'
       AND cf.IsDeleted  = 0;
    SET @RowsSeen = @RowsSeen + @Sink;
    SET @Iter = @Iter + 1;
END;

SET @T1 = SYSUTCDATETIME ();
SELECT @Cpu1 = cpu_time, @Rd1 = logical_reads FROM sys.dm_exec_requests WHERE session_id = @@SPID;

INSERT @Result (Pattern, Protection, Profile_, Iterations, TotalMs, UsPerCall, CpuMs, LogicalReads, ReadsPerCall, RowsSeen)
VALUES (N'Range scan, one tenant by status', N'no RLS (baseline)', NULL, @Reps
      , DATEDIFF (MILLISECOND, @T0, @T1)
      , CAST (DATEDIFF_BIG (MICROSECOND, @T0, @T1) AS DECIMAL (18, 1)) / @Reps
      , @Cpu1 - @Cpu0, @Rd1 - @Rd0, CAST (@Rd1 - @Rd0 AS DECIMAL (18, 1)) / @Reps, @RowsSeen);

-- ---------------------------------------------------------------------------------------------------------------------
-- 3c. LARGE AGGREGATE. Every row the profile may see, counted. The predicate is evaluated per row here, so this is the
--     pattern where a per-row predicate either scales or does not, and it is the one a nightly report issues.
-- ---------------------------------------------------------------------------------------------------------------------
SET @Reps = 20;

SET @Iter = 0;
SET @RowsSeen = 0;
SELECT @Cpu0 = cpu_time, @Rd0 = logical_reads FROM sys.dm_exec_requests WHERE session_id = @@SPID;
SET @T0 = SYSUTCDATETIME ();

WHILE @Iter < @Reps
BEGIN
    SELECT @Sink = COUNT (*) /*T073-AGG*/ FROM dbo.CaseFile AS cf WHERE cf.IsDeleted = 0;
    SET @RowsSeen = @Sink;
    SET @Iter = @Iter + 1;
END;

SET @T1 = SYSUTCDATETIME ();
SELECT @Cpu1 = cpu_time, @Rd1 = logical_reads FROM sys.dm_exec_requests WHERE session_id = @@SPID;

INSERT @Result (Pattern, Protection, Profile_, Iterations, TotalMs, UsPerCall, CpuMs, LogicalReads, ReadsPerCall, RowsSeen)
VALUES (N'Aggregate over everything visible', N'RLS bound', N'A (1 scope tenant)', @Reps
      , DATEDIFF (MILLISECOND, @T0, @T1)
      , CAST (DATEDIFF_BIG (MICROSECOND, @T0, @T1) AS DECIMAL (18, 1)) / @Reps
      , @Cpu1 - @Cpu0, @Rd1 - @Rd0, CAST (@Rd1 - @Rd0 AS DECIMAL (18, 1)) / @Reps, @RowsSeen);

-- The same aggregate as profile B, whose two scope tenants make the closure side of the semi-join do more work and
-- whose visible set is larger. Two rows, one difference, and the difference is the thing being measured.
EXEC sys.sp_set_session_context @key = N'UserProfileId',  @value = @Prof2;
EXEC sys.sp_set_session_context @key = N'ActingTenantId', @value = @Tenant2;

SET @Iter = 0;
SET @RowsSeen = 0;
SELECT @Cpu0 = cpu_time, @Rd0 = logical_reads FROM sys.dm_exec_requests WHERE session_id = @@SPID;
SET @T0 = SYSUTCDATETIME ();

WHILE @Iter < @Reps
BEGIN
    SELECT @Sink = COUNT (*) FROM dbo.CaseFile AS cf WHERE cf.IsDeleted = 0;
    SET @RowsSeen = @Sink;
    SET @Iter = @Iter + 1;
END;

SET @T1 = SYSUTCDATETIME ();
SELECT @Cpu1 = cpu_time, @Rd1 = logical_reads FROM sys.dm_exec_requests WHERE session_id = @@SPID;

INSERT @Result (Pattern, Protection, Profile_, Iterations, TotalMs, UsPerCall, CpuMs, LogicalReads, ReadsPerCall, RowsSeen)
VALUES (N'Aggregate over everything visible', N'RLS bound', N'B (2 scope tenants)', @Reps
      , DATEDIFF (MILLISECOND, @T0, @T1)
      , CAST (DATEDIFF_BIG (MICROSECOND, @T0, @T1) AS DECIMAL (18, 1)) / @Reps
      , @Cpu1 - @Cpu0, @Rd1 - @Rd0, CAST (@Rd1 - @Rd0 AS DECIMAL (18, 1)) / @Reps, @RowsSeen);

SET @Iter = 0;
SET @RowsSeen = 0;
SELECT @Cpu0 = cpu_time, @Rd0 = logical_reads FROM sys.dm_exec_requests WHERE session_id = @@SPID;
SET @T0 = SYSUTCDATETIME ();

WHILE @Iter < @Reps
BEGIN
    SELECT @Sink = COUNT (*) FROM dbo.PerfCaseFileNoRls AS cf WHERE cf.IsDeleted = 0;
    SET @RowsSeen = @Sink;
    SET @Iter = @Iter + 1;
END;

SET @T1 = SYSUTCDATETIME ();
SELECT @Cpu1 = cpu_time, @Rd1 = logical_reads FROM sys.dm_exec_requests WHERE session_id = @@SPID;

INSERT @Result (Pattern, Protection, Profile_, Iterations, TotalMs, UsPerCall, CpuMs, LogicalReads, ReadsPerCall, RowsSeen)
VALUES (N'Aggregate over everything visible', N'no RLS (baseline)', NULL, @Reps
      , DATEDIFF (MILLISECOND, @T0, @T1)
      , CAST (DATEDIFF_BIG (MICROSECOND, @T0, @T1) AS DECIMAL (18, 1)) / @Reps
      , @Cpu1 - @Cpu0, @Rd1 - @Rd0, CAST (@Rd1 - @Rd0 AS DECIMAL (18, 1)) / @Reps, @RowsSeen);

-- ---------------------------------------------------------------------------------------------------------------------
-- 3d. THE PERMISSION DECISION ITSELF, and then the config read the sampled probe adds to it. 175's file header claims
--     the probe's cost when off is one config read per demand and says it is measured rather than assumed. This is the
--     measurement. Three bursts: the scalar function alone, the procedure that wraps it with the probe block present
--     and the sample rate at 0, and the config SELECT on its own.
-- ---------------------------------------------------------------------------------------------------------------------
EXEC sys.sp_set_session_context @key = N'UserProfileId',  @value = @Prof1;
EXEC sys.sp_set_session_context @key = N'ActingTenantId', @value = @Tenant1;

DECLARE @Bit BIT, @Str NVARCHAR (400);

SET @Reps = 5000;

SET @Iter = 0;
SELECT @Cpu0 = cpu_time, @Rd0 = logical_reads FROM sys.dm_exec_requests WHERE session_id = @@SPID;
SET @T0 = SYSUTCDATETIME ();

WHILE @Iter < @Reps
BEGIN
    SET @Bit = auth.udfHasPermission (N'Data.Read', @Tenant1);
    SET @Iter = @Iter + 1;
END;

SET @T1 = SYSUTCDATETIME ();
SELECT @Cpu1 = cpu_time, @Rd1 = logical_reads FROM sys.dm_exec_requests WHERE session_id = @@SPID;

INSERT @Result (Pattern, Protection, Profile_, Iterations, TotalMs, UsPerCall, CpuMs, LogicalReads, ReadsPerCall, RowsSeen)
VALUES (N'auth.udfHasPermission (the decision)', N'n/a', N'A (1 scope tenant)', @Reps
      , DATEDIFF (MILLISECOND, @T0, @T1)
      , CAST (DATEDIFF_BIG (MICROSECOND, @T0, @T1) AS DECIMAL (18, 1)) / @Reps
      , @Cpu1 - @Cpu0, @Rd1 - @Rd0, CAST (@Rd1 - @Rd0 AS DECIMAL (18, 1)) / @Reps, NULL);

SET @Iter = 0;
SELECT @Cpu0 = cpu_time, @Rd0 = logical_reads FROM sys.dm_exec_requests WHERE session_id = @@SPID;
SET @T0 = SYSUTCDATETIME ();

WHILE @Iter < @Reps
BEGIN
    EXEC auth.uspDemandPermission @PermissionCode = N'Data.Read', @TenantId = @Tenant1;
    SET @Iter = @Iter + 1;
END;

SET @T1 = SYSUTCDATETIME ();
SELECT @Cpu1 = cpu_time, @Rd1 = logical_reads FROM sys.dm_exec_requests WHERE session_id = @@SPID;

INSERT @Result (Pattern, Protection, Profile_, Iterations, TotalMs, UsPerCall, CpuMs, LogicalReads, ReadsPerCall, RowsSeen)
VALUES (N'auth.uspDemandPermission, probe OFF', N'n/a', N'A (1 scope tenant)', @Reps
      , DATEDIFF (MILLISECOND, @T0, @T1)
      , CAST (DATEDIFF_BIG (MICROSECOND, @T0, @T1) AS DECIMAL (18, 1)) / @Reps
      , @Cpu1 - @Cpu0, @Rd1 - @Rd0, CAST (@Rd1 - @Rd0 AS DECIMAL (18, 1)) / @Reps, NULL);

SET @Iter = 0;
SELECT @Cpu0 = cpu_time, @Rd0 = logical_reads FROM sys.dm_exec_requests WHERE session_id = @@SPID;
SET @T0 = SYSUTCDATETIME ();

WHILE @Iter < @Reps
BEGIN
    SELECT @Str = s.SettingValue
      FROM config.ApplicationSetting AS s
     WHERE s.SettingKey = N'Perf.PermissionProbeSampleRate'
       AND s.IsDeleted  = 0;
    SET @Iter = @Iter + 1;
END;

SET @T1 = SYSUTCDATETIME ();
SELECT @Cpu1 = cpu_time, @Rd1 = logical_reads FROM sys.dm_exec_requests WHERE session_id = @@SPID;

INSERT @Result (Pattern, Protection, Profile_, Iterations, TotalMs, UsPerCall, CpuMs, LogicalReads, ReadsPerCall, RowsSeen)
VALUES (N'The probe''s config read, on its own', N'n/a', NULL, @Reps
      , DATEDIFF (MILLISECOND, @T0, @T1)
      , CAST (DATEDIFF_BIG (MICROSECOND, @T0, @T1) AS DECIMAL (18, 1)) / @Reps
      , @Cpu1 - @Cpu0, @Rd1 - @Rd0, CAST (@Rd1 - @Rd0 AS DECIMAL (18, 1)) / @Reps, NULL);

SELECT Pattern, Protection, Profile_, Iterations, TotalMs, UsPerCall, CpuMs, LogicalReads, ReadsPerCall, RowsSeen
  FROM @Result
 ORDER BY RowNo;
GO
-- =====================================================================================================================
-- 4.  T-073. THE PLAN SHAPE, read out of the plan cache rather than eyeballed in an editor.
--
--     What section 10.6 asserts and this section either confirms or refutes: the predicate is folded in as a SEMI-JOIN
--     (the engine stops at the first matching scope row rather than counting them) and the access to
--     auth.ProfilePermissionScope and auth.TenantClosure is a SEEK on the inner side (the profile id and the tenant id
--     are known constants at run time, so an index seek is available and a scan would mean a missing index).
--
--     EACH QUERY IS RE-EXECUTED THROUGH sp_executesql HERE, AND THAT IS NOT LAZINESS. The first version of this section
--     read the plans of the queries section 3 had already run, by looking for a marker comment in
--     sys.dm_exec_sql_text. It returned nothing every time. The reason is that section 3's statements live inside a
--     large ad-hoc BATCH whose text sys.dm_exec_query_stats could not be made to yield on this instance, while the
--     CREATE TABLE batch beside it cached perfectly -- so the lookup silently found nothing and reported an empty
--     result set, which is the worst way for a measurement to fail. sp_executesql text is cached as its own entry and
--     is reliably findable by its text, so the queries are simply run again, one statement per cache entry, and the
--     plan that comes back is unambiguously the plan for that statement.
--
--     The re-execution costs three query executions and is not timed. Section 3 owns the timings; this section owns
--     only the shape.
-- =====================================================================================================================
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;

DECLARE @Prof1  INT = (SELECT MIN (p.UserProfileId)
                         FROM auth.UserProfile AS p
                         JOIN auth.[User]      AS u ON u.UserId = p.UserId
                        WHERE u.UserName LIKE N'perf.u%'
                          AND CAST (RIGHT (u.UserName, 5) AS INT) % 4 = 1)
      , @Ten1   INT
      , @FileId INT
      , @Sql    NVARCHAR (MAX);

SELECT @Ten1 = TenantId FROM auth.UserProfile WHERE UserProfileId = @Prof1;
SELECT @FileId = MIN (CaseFileId) FROM dbo.PerfCaseFileNoRls WHERE TenantId = @Ten1;

-- SESSION_CONTEXT survives GO because GO is a client-side batch separator and not a new connection, so the profile set
-- in section 3 is still in force. Setting it again costs nothing and makes this section runnable on its own.
EXEC sys.sp_set_session_context @key = N'BypassRowSecurity', @value = NULL;
EXEC sys.sp_set_session_context @key = N'UserProfileId',     @value = @Prof1;
EXEC sys.sp_set_session_context @key = N'ActingTenantId',    @value = @Ten1;

-- Each shape assigns into a local sink declared inside the dynamic text rather than returning a result set. That keeps
-- four one-row result sets out of the output -- they would be mistaken for measurements -- and does not change the plan:
-- an assignment SELECT is optimized exactly as the SELECT it wraps.
SET @Sql = N'DECLARE @Sink INT;'
         + N' SELECT /*T073-POINT*/ @Sink = cf.TenantId FROM dbo.CaseFile AS cf WHERE cf.CaseFileId = @Id AND cf.IsDeleted = 0;';
EXEC sys.sp_executesql @Sql, N'@Id INT', @Id = @FileId;

SET @Sql = N'DECLARE @Sink INT;'
         + N' SELECT /*T073-RANGE*/ @Sink = COUNT (*) FROM dbo.CaseFile AS cf'
         + N' WHERE cf.TenantId = @T AND cf.CaseStatus = ''open'' AND cf.IsDeleted = 0;';
EXEC sys.sp_executesql @Sql, N'@T INT', @T = @Ten1;

SET @Sql = N'DECLARE @Sink INT;'
         + N' SELECT /*T073-AGG*/ @Sink = COUNT (*) FROM dbo.CaseFile AS cf WHERE cf.IsDeleted = 0;';
EXEC sys.sp_executesql @Sql;

SET @Sql = N'DECLARE @Sink INT;'
         + N' SELECT /*T073-BASE*/ @Sink = COUNT (*) FROM dbo.PerfCaseFileNoRls AS cf WHERE cf.IsDeleted = 0;';
EXEC sys.sp_executesql @Sql;
GO

SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;

;WITH XMLNAMESPACES (DEFAULT 'http://schemas.microsoft.com/sqlserver/2004/07/showplan')
SELECT Pattern      = m.Pattern
     , SemiJoins    = p.query_plan.value ('count(//RelOp[contains(@LogicalOp, "Semi Join")])', 'INT')
     , ScopeSeeks   = p.query_plan.value ('count(//RelOp[contains(@PhysicalOp, "Seek")][.//Object[@Table = "[ProfilePermissionScope]"]])', 'INT')
     , ScopeScans   = p.query_plan.value ('count(//RelOp[contains(@PhysicalOp, "Scan")][.//Object[@Table = "[ProfilePermissionScope]"]])', 'INT')
     , ClosureSeeks = p.query_plan.value ('count(//RelOp[contains(@PhysicalOp, "Seek")][.//Object[@Table = "[TenantClosure]"]])', 'INT')
     , ClosureScans = p.query_plan.value ('count(//RelOp[contains(@PhysicalOp, "Scan")][.//Object[@Table = "[TenantClosure]"]])', 'INT')
     , OuterTableOp = p.query_plan.value ('(//RelOp[.//Object[@Table = "[CaseFile]" or @Table = "[PerfCaseFileNoRls]"]]/@PhysicalOp)[1]', 'NVARCHAR (60)')
       -- fn:string-join is NOT in the XQuery subset SQL Server implements (Msg 2395), so the join shape is reported as
       -- the physical operator of the first semi-join plus a count of nested loops rather than as a joined-up list.
     , SemiJoinOp   = p.query_plan.value ('(//RelOp[contains(@LogicalOp, "Semi Join")]/@PhysicalOp)[1]', 'NVARCHAR (60)')
     , NestedLoops  = p.query_plan.value ('count(//RelOp[@PhysicalOp = "Nested Loops"])', 'INT')
     , Executions   = qs.execution_count
     , AvgReads     = qs.total_logical_reads  / NULLIF (qs.execution_count, 0)
     , AvgUs        = qs.total_elapsed_time   / NULLIF (qs.execution_count, 0)
  FROM (VALUES (1, N'T073-POINT', N'Point read by primary key, RLS bound')
             , (2, N'T073-RANGE', N'Range scan, one tenant by status, RLS bound')
             , (3, N'T073-AGG',   N'Aggregate over everything visible, RLS bound')
             , (4, N'T073-BASE',  N'Aggregate, the unprotected baseline')) AS m (Seq, Marker, Pattern)
  OUTER APPLY (SELECT TOP (1) qs2.plan_handle, qs2.execution_count, qs2.total_logical_reads, qs2.total_elapsed_time
                 FROM sys.dm_exec_query_stats AS qs2
                CROSS APPLY sys.dm_exec_sql_text (qs2.sql_handle) AS st
                WHERE st.text LIKE N'%/*' + m.Marker + N'*/%'
                ORDER BY qs2.last_execution_time DESC) AS qs
  OUTER APPLY sys.dm_exec_query_plan (qs.plan_handle) AS p
 ORDER BY m.Seq;

PRINT 'T070_measure_predicates.sql: done. Read the plan-shape result set as follows:';
PRINT '  SemiJoins > 0, ScopeScans = 0, ClosureScans = 0  -- the design holds. The predicate folded in as a semi-join';
PRINT '                                                      and both of its tables are seeked, which is what section';
PRINT '                                                      10.6 asserts and T-073 exists to confirm.';
PRINT '  ScopeScans > 0 or ClosureScans > 0               -- a SCAN on the inner side. On this population that is';
PRINT '                                                      57,000 or 4,900 rows read to decide one row, and it is the';
PRINT '                                                      failure mode decision D-07 exists to catch.';
PRINT '  SemiJoins = 0 with seeks present                 -- folded in as an ordinary join or an apply. Not';
PRINT '                                                      necessarily wrong, but the engine is then counting';
PRINT '                                                      matches it does not need.';
PRINT '  A row of NULLs                                   -- the plan was not found in the cache, NOT a passing result.';
GO

