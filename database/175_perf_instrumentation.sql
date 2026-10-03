/***********************************************************************************************************************
Script:         175_perf_instrumentation.sql
Purpose:        The measurement apparatus for the row-level security predicate and the permission decision:
                logs.PermissionProbe, its recorder, its purge, its report, logs.vwPredicateFunctionStats, and the
                extended-events session that watches the predicate functions from outside.
Target:         SQL Server 2022.
Run as:         db_owner in the target database.  The extended-events session in section 8 additionally needs the
                server-level ALTER ANY EVENT SESSION, and is skipped with a notice when the runner does not hold it.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/175_perf_instrumentation.sql
Idempotent:     Yes.  CREATE OR ALTER throughout, IF OBJECT_ID guards on the table, trigger and indexes, a MERGE for
                the one setting this file owns, and the event session is created only when absent.
Depends on:     database/025_config_tables.sql, database/040_auth_userprofile.sql, database/030_auth_tenant.sql,
                database/050_auth_permission.sql, scripts/logExecutionLogging.sql, templates/extended-properties.sql.
                NOT on 150_auth_query_procedures.sql: the dependency runs the other way and it is guarded.  See below.
Implements:     T-069 to T-074.  DES-AUTH-001 sections 10.6 and 19.4, gap G-22, decision D-07.
                See docs/10-database-authn-authz-design.md.
To retarget:    Pass it per run:  sqlcmd -d <database> -v DbName=<database>.  There is no in-file default.

WHY THIS FILE EXISTS AT ALL, WHICH IS GAP G-22 IN ONE SENTENCE
--------------------------------------------------------------
The single code path that runs on every query against every protected table in this database is the one path that can
report nothing about itself.  auth.tvfTenantReadPredicate and its three siblings are functions: a function cannot write
to a table, and a SCHEMABINDING function must not try, so while every procedure in the database opens a
logs.ExecutionLog row and closes it, the predicates run billions of times and leave no trace.  Section 10.6 records that
as G-22 and commits Phase 5 to shipping the measurement as a DESIGN rather than performing it as an investigation and
throwing the scaffolding away.  This file is that design.  It has three parts and they answer different questions:

  1. logs.PermissionProbe, written by auth.uspDemandPermission's CALLER SIDE under a sample rate.  Answers "what does
     the permission decision cost, in this deployment, at this data volume, for real profiles" -- the question a
     synthetic benchmark cannot answer because it cannot know the shape of the customer's tenant tree.
  2. logs.vwPredicateFunctionStats over sys.dm_exec_function_stats.  Answers "how often is the predicate being called
     and what is the server's own running total for it" -- free, always on, and it survives nothing: the DMV is reset by
     a restart, a recompile or a DBCC FREEPROCCACHE, which the view states in its own output.
  3. The extended-events session in section 8.  Answers "what did ONE statement against a protected table actually do"
     -- the only one of the three that can attribute cost to a specific plan shape, and the only one that is off by
     default because it is the only one that costs something whether or not anybody reads it.

THE PREDICATE FUNCTIONS THEMSELVES ARE NOT TOUCHED BY THIS FILE, AND THAT IS THE POINT
--------------------------------------------------------------------------------------
Nothing here alters auth.tvfTenantReadPredicate, auth.tvfTenantInsertPredicate, auth.tvfTenantUpdatePredicate,
auth.tvfPermissionScope, auth.udfHasPermission or auth.udfResolveAuthPolicy.  They stay silent, schema-bound and
inlineable.  Every number this file produces is produced from OUTSIDE them: by the procedure that calls them, by the
server's own statistics, or by an event session.  A future maintainer who "improves" the instrumentation by adding a
logging call inside a predicate will get error 443 for the attempt and, if they work around it by dropping
SCHEMABINDING, will silently un-bind the security policy from its own tables.  Do not.

THE PROBE COSTS ONE CONFIG READ PER DEMAND EVEN WHEN IT IS OFF, AND THAT IS MEASURED RATHER THAN ASSUMED
--------------------------------------------------------------------------------------------------------
config.ApplicationSetting documents Perf.PermissionProbeSampleRate as "one call in N", 0 meaning off.  Implementing
that literally means auth.uspDemandPermission reads the setting on EVERY call, including the overwhelming majority of
calls on which the answer is "do nothing" -- one seek on a single-page table that is never out of cache, but a seek.

Three cheaper designs were considered and all three were rejected:

  *  A fixed pre-gate -- CHECKSUM (NEWID ()) masked to one call in 64, read the setting only when it fires -- costs no
     I/O at all, but it puts a hard ceiling on the sample rate and makes the configured N mean something other than
     what config.ApplicationSetting says it means.  A tunable whose documented semantics are wrong at some values is
     worse than a seek.
  *  Publishing the rate in SESSION_CONTEXT so the read happens once per session instead of once per demand.  This is
     the cheapest correct design and it was rejected on a different ground: the five identity keys are read-only for the
     life of the connection and are the entire session contract that sections 8 and 10 reason about.  A sixth key that
     no predicate reads still widens that contract, and widening it for a performance counter is the wrong trade.  If
     the measurement below ever says the seek matters, THIS is the change to make, and it is a design change.
  *  Reading the setting once at install time into a literal baked into the procedure body.  Rejected: the point of a
     sample rate in a config table is that an operator can turn it up during an incident without a deployment.

So the seek stays and it is measured, not asserted.  The figure is recorded in workbooks/build-and-traceability.xlsx
against T-070 and in section 11 of this file.  The remedy of last resort is named there too: delete the block in
auth.uspDemandPermission marked "-- 1b. The sampled probe", which is written as one self-contained block flanked by
comments precisely so it can be removed in one edit without disturbing the decision above it.

THE PROBE MEASURES A BURST, NOT A SINGLE CALL, BECAUSE THE CLOCK CANNOT SEE A SINGLE CALL
-----------------------------------------------------------------------------------------
This is the part everybody gets wrong, including the first draft of this file.  SYSUTCDATETIME () reads the Windows
system time, whose granularity on this instance is about one millisecond -- not the hundred nanoseconds its DATETIME2 (7)
return type suggests.  A permission decision costs single-digit microseconds.  So timing one call yields 0 or 1000
microseconds, and a table full of those two values is not a measurement, it is a coin flip with extra steps.

The probe therefore re-runs the decision @BurstCount times in a tight loop and divides.  Perf.PermissionProbeBurstCount
defaults to 25, which puts a typical burst comfortably above the clock's resolution while keeping the cost of a sampled
call bounded: at the default sample rate the burst never runs at all, and at 1-in-1000 it adds 25 decisions per thousand
-- 2.5% of the permission-checking work of the database, which is itself a small fraction of its total work.

The re-run is safe because the thing being re-run is a read.  auth.udfHasPermission is a scalar function over
auth.ProfilePermissionScope and auth.TenantClosure with no side effects; running it 25 more times cannot change an
authorization outcome, and the value it returns is DISCARDED -- the decision the caller acts on is the one taken before
the probe, never one taken inside it.  If that ever stops being true the probe must be deleted, not fixed.

A CONSEQUENCE WORTH STATING: THE FIRST CALL OF A BURST IS NOT LIKE THE OTHER TWENTY-FOUR.  It is the one that may have
to fetch a page; the rest are warm.  So MicrosecondsPerCall is a WARM-CACHE figure and systematically optimistic about a
cold one.  That is the right figure for the question section 10.6 asks -- "both fit in cache and stay there" is the
design's claim and this measures the claim's own regime -- but it is not the figure for "what does the first query after
a failover cost".  Nothing in this database measures that; the extended-events session in section 8 is how you would.

WHY THE DEPENDENCY RUNS FROM 150 TO HERE AND NOT THE OTHER WAY
--------------------------------------------------------------
auth.uspDemandPermission calls logs.uspRecordPermissionProbe, so 150_auth_query_procedures.sql depends on this file --
and yet this file installs AFTER 150 in the manifest and 150 does not assert it.  That is deliberate and it is the one
place in this deployment where a runtime OBJECT_ID guard is preferred to an install-time assertion:

  *  Deferred name resolution lets 150 install with the EXEC unresolved, exactly as 140_auth_profile_procedures.sql
     installs with its call to 150 unresolved.
  *  The guard sits INSIDE the sample gate, so it is evaluated on the sampled calls only and costs nothing on the
     other N-1.  An install-time assertion would cost nothing either, but it would make a performance counter into a
     hard prerequisite of the authorization gate, and the authorization gate must install on a database that has
     decided it does not want to be measured.
  *  A deployment that omits this file therefore gets a fully working permission system with no probe, which is a
     supported configuration and the reason Perf.PermissionProbeSampleRate ships as 0.

THE PROBE NEVER WRITES INSIDE SOMEBODY ELSE'S TRANSACTION
---------------------------------------------------------
The gate tests @@TRANCOUNT = 0 before anything else.  Two reasons, and the second is the one that matters:

  *  A probe row written inside a caller's transaction is rolled back with it, so half the measurements would silently
     vanish and the surviving half would be biased towards the procedures that do not use transactions.  A biased
     sample is worse than a smaller one.
  *  auth.uspDemandPermission is called at step 5 of section 9, BEFORE the work opens a transaction -- so a demand with
     @@TRANCOUNT > 0 is a caller that got the order wrong, which is BL-042.  Those are exactly the calls whose denial
     rows are already being lost to the rollback.  The probe declining to add a second casualty to that list keeps the
     two problems separate: BL-042 is one defect with one fix, not a performance mystery as well.

WHAT THE PROBE RECORDS, AND THE TWO THINGS IT DELIBERATELY DOES NOT
-------------------------------------------------------------------
It records the permission code, the tenant, the profile, the outcome, the burst size, the elapsed microseconds, and
ScopeRowsForProfile -- the number of live auth.ProfilePermissionScope rows the profile holds, which is the cost driver
the design's own estimate in section 10.6 is stated in terms of ("profiles x permissions granted").  A measurement
without its independent variable is a number nobody can extrapolate from.

It does NOT record a plan handle or a sql_handle.  Both are stable enough to be tempting and neither survives a
recompile, so a probe row pointing at a plan that no longer exists reads as a lost plan rather than a plan that aged
out.  Section 8's event session is where plan-level attribution belongs.

It does NOT record anything about the CALLER beyond a short context string the caller may pass.  No statement text, no
parameters, no object name from the business schema.  UI-16 applies here as everywhere: this table's read audience is
whoever is chasing a performance problem, which is a wider audience than the one entitled to see what the application
was doing at the time.

THE PURGE IS A SOFT DELETE, WHICH FOR THIS ONE TABLE IS AN HONEST PROBLEM RATHER THAN A DESIGN
----------------------------------------------------------------------------------------------
Nothing in this database hard-deletes a row; the convention is absolute and the SQL validator enforces it.  So
logs.uspPurgePermissionProbe sets IsDeleted = 1 and the pages stay where they are.  For every other table in the
database that is exactly right, because every other table holds something somebody may have to account for.

This table holds performance samples.  At 1-in-1000 on a busy application it is the fastest-growing table here, and a
retention policy that reclaims no space is not a retention policy.  The position is therefore stated plainly rather than
dressed up: the procedure marks rows expired so that every read and every report ignores them and the row count in
section 11's report tells the truth about how much dead weight is present, and RECLAIMING the space is a DBA operation
outside the procedure layer -- a DELETE in batches, or a partition switch if the deployment has partitioned this table.
It is the one table in the database where running a hard DELETE by hand against expired rows is a supported thing to
do, and Perf.PermissionProbeRetentionDays is what tells the DBA which rows those are.

sys.dm_exec_function_stats DOES NOT SEE AN INLINED SCALAR FUNCTION, AND THAT IS NOT A BUG IN THE VIEW
-----------------------------------------------------------------------------------------------------
Measured on this instance rather than read in a blog: a scalar UDF that Scalar UDF Inlining folds into the calling
query stops appearing in sys.dm_exec_function_stats entirely, because there is no longer a function execution to count.
auth.udfHasPermission is a candidate for inlining and auth.udfResolveAuthPolicy is not, so the view routinely shows
some of the six and not others, and an empty row set for a function is ambiguous between "never called" and "called
constantly and inlined every time".

logs.vwPredicateFunctionStats therefore lists all six functions by name from a VALUES constructor and LEFT JOINs the
DMV, so a function with no statistics appears with NULLs and a StatsNote saying which of the two it is -- decided from
sys.sql_modules for the INLINE hint and from the function's own type, not guessed.  A view that simply selected from the
DMV would have silently omitted the most important function in the database.

INLINE TABLE-VALUED FUNCTIONS NEVER APPEAR IN IT AT ALL.  sys.dm_exec_function_stats covers scalar and CLR functions.
The three predicates are inline TVFs by necessity -- section 10.2 requires it, a multi-statement TVF would defeat the
semi-join the whole design rests on -- so the four rows for them in the view are permanent, informative NULLs whose
StatsNote says so.  They are listed anyway, because the first question anybody asks this view is about them and an
absent row would be read as an omission.
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

-- The table this file creates carries three foreign keys and the report reads a fourth table, so all four must exist.
-- Asserted rather than warned about: unlike a procedure, section 1 creates a TABLE and a missing referenced table is
-- error 1767 with no indication of which script was skipped.
IF OBJECT_ID (N'auth.UserProfile', N'U') IS NULL
   OR OBJECT_ID (N'auth.Tenant', N'U') IS NULL
   OR OBJECT_ID (N'auth.Permission', N'U') IS NULL
   OR OBJECT_ID (N'auth.ProfilePermissionScope', N'U') IS NULL
   OR OBJECT_ID (N'config.ApplicationSetting', N'U') IS NULL
BEGIN
    DECLARE @MsgParents NVARCHAR (2000) =
        N'One of auth.UserProfile, auth.Tenant, auth.Permission, auth.ProfilePermissionScope or '
      + N'config.ApplicationSetting is missing. Run 025_config_tables.sql, 030_auth_tenant.sql, '
      + N'040_auth_userprofile.sql, 050_auth_permission.sql and 065_auth_effective_permission.sql first. This file '
      + N'creates a table with foreign keys to three of them, so deferred name resolution does not save it the way it '
      + N'saves a procedure script.';

    THROW 50000, @MsgParents, 1;
END
GO

-- The instrumentation chain.  A warning and not a THROW, for the reason 125_auth_tenant_procedures.sql gives: a
-- procedure gets deferred name resolution and installs without it.  The difference from 165_logs_procedures.sql is that
-- nothing in this file EXECs its own recorder, so a database missing the chain installs cleanly here and fails on the
-- first sampled call instead -- which, at the shipped sample rate of 0, is never.
IF OBJECT_ID (N'logs.uspStartExecutionLogging', N'P') IS NULL OR OBJECT_ID (N'logs.uspRecordExecutionError', N'P') IS NULL
BEGIN
    PRINT N'WARNING: logs.uspStartExecutionLogging or logs.uspRecordExecutionError is missing. The three procedures in '
        + N'this file will install and will fail with error 2812 when first called. Run '
        + N'.claude/skills/ponytail-sql-objects/scripts/logExecutionLogging.sql against this database.';
END
GO


-- *** 1. logs.PermissionProbe ***
-- One row per SAMPLED call to auth.uspDemandPermission.  Not one row per call: at one row per call this table would be
-- larger than every other table in the database put together within a week, and the measurement would be dominated by
-- the cost of recording it.
IF OBJECT_ID (N'logs.PermissionProbe', N'U') IS NULL
BEGIN
    CREATE TABLE logs.PermissionProbe
    (
        PermissionProbeId     BIGINT        IDENTITY (1, 1) NOT NULL
      , OccurredUtc           DATETIME2 (3)                 NOT NULL
            CONSTRAINT DF_logs_PermissionProbe_OccurredUtc DEFAULT (SYSUTCDATETIME ())
        -- The measurement.  BurstCount decisions took TotalMicroseconds; the per-call figure is derived rather than
        -- stored twice, because two columns that must agree are two columns that eventually do not.
      , BurstCount            INT                           NOT NULL
      , TotalMicroseconds     BIGINT                        NOT NULL
      , MicrosecondsPerCall   AS (CAST (TotalMicroseconds AS DECIMAL (18, 3)) / NULLIF (BurstCount, 0))
        -- What was being decided.  PermissionCode is a string and not a foreign key, for the same reason
        -- logs.AuthorizationDenial gives: a probe of a code that does not exist is a probe worth keeping.
      , PermissionCode        NVARCHAR (100)                NOT NULL
      , TenantId              INT                               NULL
      , UserProfileId         INT                               NULL
      , Allowed               BIT                           NOT NULL
        -- The independent variable.  Section 10.6 states the design's cost estimate in terms of "profiles x permissions
        -- granted", so a row without this number is a number nobody can extrapolate from.
      , ScopeRowsForProfile   INT                               NULL
      , ClosureRowsForTenant  INT                               NULL
        -- A short caller-supplied label -- 'nav', 'caseRead', 'benchmark T-070' -- and nothing else about the caller.
        -- UI-16: this table's readers are whoever is chasing a slow query, a wider audience than the one entitled to
        -- know what the application was doing.
      , ProbeContext          NVARCHAR (100)                    NULL
      , DetailJson            NVARCHAR (MAX)                    NULL
      , IsDeleted             BIT                           NOT NULL
            CONSTRAINT DF_logs_PermissionProbe_IsDeleted DEFAULT (0)
      , auditDeletedBy        NVARCHAR (255)                    NULL
      , auditDeletedDateUtc   DATETIME2 (3)                     NULL
      , auditCreatedBy        NVARCHAR (255)                NOT NULL
            CONSTRAINT DF_logs_PermissionProbe_auditCreatedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditCreatedDateUtc   DATETIME2 (3)                 NOT NULL
            CONSTRAINT DF_logs_PermissionProbe_auditCreatedDateUtc DEFAULT (SYSUTCDATETIME ())
      , auditModifiedBy       NVARCHAR (255)                NOT NULL
            CONSTRAINT DF_logs_PermissionProbe_auditModifiedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditModifiedDateUtc  DATETIME2 (3)                 NOT NULL
            CONSTRAINT DF_logs_PermissionProbe_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ())
      , CONSTRAINT PK_logs_PermissionProbe PRIMARY KEY CLUSTERED (PermissionProbeId)
        -- Both nullable and both NO ACTION.  A probe outlives the profile it measured, and a profile that is retired
        -- must not take the evidence of what it cost with it.
      , CONSTRAINT FK_logs_PermissionProbe_UserProfile
            FOREIGN KEY (UserProfileId) REFERENCES auth.UserProfile (UserProfileId)
      , CONSTRAINT FK_logs_PermissionProbe_Tenant
            FOREIGN KEY (TenantId) REFERENCES auth.Tenant (TenantId)
        -- A burst of zero would make MicrosecondsPerCall NULL and a burst of one is below the clock's resolution, which
        -- is the whole reason the burst exists.  Refused at the constraint as well as in the recorder (E-50191).
      , CONSTRAINT CK_logs_PermissionProbe_BurstCount
            CHECK (BurstCount >= 2 AND BurstCount <= 10000)
        -- A negative elapsed time means the system clock moved backwards during the burst, which happens, and a row
        -- recording it would poison every average computed from this table.
      , CONSTRAINT CK_logs_PermissionProbe_TotalMicroseconds
            CHECK (TotalMicroseconds >= 0)
      , CONSTRAINT CK_logs_PermissionProbe_PermissionCode
            CHECK (LEN (PermissionCode) > 0 AND PermissionCode = LTRIM (RTRIM (PermissionCode)))
      , CONSTRAINT CK_logs_PermissionProbe_ProbeContext
            CHECK (ProbeContext IS NULL OR LEN (ProbeContext) > 0)
      , CONSTRAINT CK_logs_PermissionProbe_Counts
            CHECK ((ScopeRowsForProfile  IS NULL OR ScopeRowsForProfile  >= 0)
               AND (ClosureRowsForTenant IS NULL OR ClosureRowsForTenant >= 0))
      , CONSTRAINT CK_logs_PermissionProbe_DetailJson
            CHECK (DetailJson IS NULL OR ISJSON (DetailJson) = 1)
      , CONSTRAINT CK_logs_PermissionProbe_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS     NULL AND auditDeletedDateUtc IS     NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL))
    );
END
GO

-- The report's own read: a window, then everything in it.  Leading on time because a performance question is always
-- "since when", and the purge in section 6 seeks on exactly this index too.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_logs_PermissionProbe_When'
                  AND object_id = OBJECT_ID (N'logs.PermissionProbe'))
BEGIN
    CREATE INDEX IX_logs_PermissionProbe_When
        ON logs.PermissionProbe (OccurredUtc DESC)
        INCLUDE (PermissionCode, BurstCount, TotalMicroseconds, Allowed, ScopeRowsForProfile)
        WHERE IsDeleted = 0;
END
GO

-- "Which permission is expensive" -- the read that finds a permission whose scope rows have grown out of proportion,
-- which is the failure mode section 10.6 predicts and D-07 has to be decided against.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_logs_PermissionProbe_Permission'
                  AND object_id = OBJECT_ID (N'logs.PermissionProbe'))
BEGIN
    CREATE INDEX IX_logs_PermissionProbe_Permission
        ON logs.PermissionProbe (PermissionCode, OccurredUtc DESC)
        INCLUDE (BurstCount, TotalMicroseconds, ScopeRowsForProfile, Allowed)
        WHERE IsDeleted = 0;
END
GO

-- "Is the cost a function of how much the profile holds" -- the correlation the design's estimate asserts and this table
-- exists to test.  Leading on the driver rather than on time, because this read is not windowed: it wants every sample.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_logs_PermissionProbe_ScopeRows'
                  AND object_id = OBJECT_ID (N'logs.PermissionProbe'))
BEGIN
    CREATE INDEX IX_logs_PermissionProbe_ScopeRows
        ON logs.PermissionProbe (ScopeRowsForProfile)
        INCLUDE (BurstCount, TotalMicroseconds, PermissionCode)
        WHERE IsDeleted = 0 AND ScopeRowsForProfile IS NOT NULL;
END
GO


-- *** 2. Audit trigger ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   logs.trg_au_updt_PermissionProbe
Author:       rsincero
CreateDate:   2026-09-20
Description:
AFTER UPDATE audit stamp for logs.PermissionProbe, and the guard that makes the measurement itself immutable -- E-50010.

A MEASUREMENT THAT CAN BE EDITED IS NOT A MEASUREMENT.  Every column except IsDeleted describes an event that has
already been timed, and there is no correction anybody could legitimately apply: a probe that recorded an implausible
number recorded what the clock said, and the response is another probe, not a rewrite.  The reason this matters here and
not just as consistency with logs.AuthenticationEvent is decision D-07 -- a go/no-go on the row-level security design
taken at milestone M3 on the numbers in this table.  A table that feeds a design decision must be one nobody can tidy.

IsDeleted is the single exception, and section 6's purge is the only thing expected to set it.

Modification History:
2026-09-20  rsincero  Created.  PLAN-AUTH-001 T-074.
***********************************************************************************************************************/
CREATE OR ALTER TRIGGER logs.trg_au_updt_PermissionProbe
    ON logs.PermissionProbe
    AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    IF EXISTS (SELECT 1
                 FROM inserted AS i
                 JOIN deleted  AS d ON d.PermissionProbeId = i.PermissionProbeId
                WHERE i.OccurredUtc <> d.OccurredUtc
                   OR i.BurstCount <> d.BurstCount
                   OR i.TotalMicroseconds <> d.TotalMicroseconds
                   OR i.PermissionCode <> d.PermissionCode
                   OR i.Allowed <> d.Allowed
                   OR ISNULL (i.TenantId, -1) <> ISNULL (d.TenantId, -1)
                   OR ISNULL (i.UserProfileId, -1) <> ISNULL (d.UserProfileId, -1)
                   OR ISNULL (i.ScopeRowsForProfile, -1) <> ISNULL (d.ScopeRowsForProfile, -1)
                   OR ISNULL (i.ClosureRowsForTenant, -1) <> ISNULL (d.ClosureRowsForTenant, -1)
                   OR ISNULL (i.ProbeContext, N'~') <> ISNULL (d.ProbeContext, N'~')
                   OR ISNULL (i.DetailJson, N'~') <> ISNULL (d.DetailJson, N'~'))
    BEGIN
        ;THROW 50010, N'logs.PermissionProbe is append-only: every column on it records a measurement that has already been taken, and the response to an implausible number is another probe rather than an edit. Decision D-07 is taken on the contents of this table, so a table anybody can tidy is a decision nobody can audit. Only IsDeleted may change, and logs.uspPurgePermissionProbe is what changes it.', 1;
    END;

    DECLARE @Now   DATETIME2 (3)  = SYSUTCDATETIME ()
          , @Actor NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                            , ORIGINAL_LOGIN ());

    UPDATE t
       SET t.auditModifiedDateUtc = @Now
         , t.auditModifiedBy      = CASE WHEN UPDATE (auditModifiedBy)
                                         THEN COALESCE (NULLIF (i.auditModifiedBy, N''), @Actor)
                                         ELSE @Actor END
         , t.auditDeletedBy       = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Actor ELSE t.auditDeletedBy      END
         , t.auditDeletedDateUtc  = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Now   ELSE t.auditDeletedDateUtc END
      FROM logs.PermissionProbe AS t
      JOIN inserted AS i ON i.PermissionProbeId = t.PermissionProbeId
      JOIN deleted  AS d ON d.PermissionProbeId = t.PermissionProbeId;
END;
GO


-- *** 3. The one setting this file owns ***
-- BL-050 says a setting is seeded in exactly one place, because a setting with two defaults has two defaults and the
-- second script to run wins silently.  025_config_tables.sql owns the twenty-three authentication, authorization and
-- registration tunables, 115_seed_reference_data.sql owns four -- Perf.PermissionProbeSampleRate,
-- Perf.PermissionProbeRetentionDays, Registration.ExternalBranchTenantCode and the Ui.CatalogueVersion digest -- and
-- this file owns the burst count, the only one of the twenty-eight that is meaningless without the code in this file to
-- read it.
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

MERGE config.ApplicationSetting AS tgt
USING (VALUES
       (N'Perf.PermissionProbeBurstCount', N'25', 'Int', 0
      , N'How many times a sampled call to auth.uspDemandPermission re-runs the permission decision before dividing. It exists because SYSUTCDATETIME () has about one millisecond of real resolution on Windows while a permission decision costs single-digit microseconds, so timing ONE call yields 0 or 1000 and a table of those two values is a coin flip rather than a measurement. 25 puts a typical burst above the clock floor; below 2 is refused by both CK_logs_PermissionProbe_BurstCount and E-50191. The re-runs are discarded reads with no side effects -- the decision the caller acts on is always the one taken before the probe.')
      ) AS src (SettingKey, SettingValue, ValueKind, IsSensitive, SettingDescription)
   ON tgt.SettingKey = src.SettingKey
 WHEN MATCHED THEN
      -- SettingValue deliberately NOT updated on a match, exactly as in 115: an operator who raised the burst count for
      -- a benchmark run should not have it reset by the next deployment, and ShippedDefault is what records intent.
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


-- *** 4. logs.uspRecordPermissionProbe ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   logs.uspRecordPermissionProbe
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Records one row in logs.PermissionProbe: what was decided, how long a burst of that decision took, and how much the
profile held while it was being decided.  Section 10.6, gap G-22, decision D-07.

Called by auth.uspDemandPermission from inside its sample gate, and by the Phase 5 benchmark scripts with
@ProbeContext = 'benchmark T-070' so that a deliberate measurement can be told apart from the ambient sampling.  Not
granted to applicationRole; reached by ownership chaining, for the reason 165_logs_procedures.sql gives about trails --
a table the application can write arbitrary rows into cannot support a design decision.

THE CALLER DOES THE TIMING, NOT THIS PROCEDURE.  It has to: the burst has to happen around the decision the caller is
already making, and moving the loop in here would mean this procedure calling auth.udfHasPermission, which puts a
measurement procedure in the authorization call graph.  So the caller passes the numbers and this procedure validates
and stores them.  The division is the computed column MicrosecondsPerCall and happens nowhere else.

========================================================================================================================
Requirements and Key Dependencies:

logs.PermissionProbe, and through its two foreign keys auth.UserProfile and auth.Tenant.

logs.uspStartExecutionLogging and logs.uspRecordExecutionError, for the rule 8 instrumentation block, plus
logs.ExecutionLog itself, which the completion UPDATE writes directly.  All three are installed by
scripts/logExecutionLogging.sql.

========================================================================================================================
Notes:

FULLY INSTRUMENTED, LIKE EVERY PROCEDURE THAT IS NOT ONE OF THE FIVE.  Rule 8's exemptions are the logs.ExecutionLog
chain itself and nothing else, whatever schema it lives in.  The cost -- two logs.ExecutionLog writes per probe row -- is
real and is the reason the probe is sampled rather than continuous.  It is also, less obviously, a second measurement:
the elapsed time of THIS procedure as recorded in logs.ExecutionLog is what a probe row costs, and comparing it to the
MicrosecondsPerCall it recorded is how you tell whether the observer is bigger than the thing observed.  At the shipped
burst of 25 it is, by roughly two orders of magnitude, and that is exactly why the sample rate exists.

NOT IDEMPOTENT, AND IT MUST NOT BE.  Two probes of the same permission by the same profile a second apart are two
measurements, and averaging them at write time would throw away the variance -- which, for a question about whether a
predicate occasionally defeats a good plan, is the interesting half of the data.

@ScopeRowsForProfile AND @ClosureRowsForTenant ARE TAKEN AS PARAMETERS AND NOT COUNTED HERE.  The caller is already
holding the profile id and can count its scope rows with a seek on an index it has just used; counting them in here means
a second lookup, and counting them for a profile the caller did not resolve means counting them for the wrong profile.
NULL is legitimate and means "not measured", not "zero" -- CK_logs_PermissionProbe_Counts allows 0 and section 6's report
excludes NULLs from the correlation rather than treating them as zeroes.

NO PERMISSION IS DEMANDED, and the reason is stronger here than for the trail recorders: this procedure is called BY
auth.uspDemandPermission, so demanding a permission would be an unbounded recursion rather than merely an awkward one.
The protection is the absent grant.

ERRORS ARE E-50190 TO E-50193, A NEW RANGE.  Every one of them is a defect in the calling procedure, and every one would
be refused by a CHECK constraint a few microseconds later -- so the choice is between a number naming the problem and a
547 naming a constraint.  Appendix B registers the range.

========================================================================================================================
Example Usage and Performance:

declare @id bigint;
exec logs.uspRecordPermissionProbe @PermissionCode = N'Data.Read', @TenantId = 7, @UserProfileId = 12, @Allowed = 1
                                 , @BurstCount = 25, @TotalMicroseconds = 3100, @ScopeRowsForProfile = 14
                                 , @ClosureRowsForTenant = 4, @ProbeContext = N'benchmark T-070'
                                 , @PermissionProbeId = @id output;

One singleton insert on a table with three filtered nonclustered indexes, plus the two instrumentation writes.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-074
Description: Created.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE logs.uspRecordPermissionProbe
      @PermissionCode       NVARCHAR (100)
    , @BurstCount           INT
    , @TotalMicroseconds    BIGINT
    , @Allowed              BIT            = 0
    , @TenantId             INT            = NULL
    , @UserProfileId        INT            = NULL
    , @ScopeRowsForProfile  INT            = NULL
    , @ClosureRowsForTenant INT            = NULL
    , @ProbeContext         NVARCHAR (100) = NULL
    , @DetailJson           NVARCHAR (MAX) = NULL
    , @PermissionProbeId    BIGINT         = NULL OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    -- The literal is not a fallback for odd cases; it is what the application logins actually log,
    -- because metadata visibility is denied to them. Keep it in step with the name above.
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[logs].[uspRecordPermissionProbe]')
          , @StartTimeUtc   DATETIME2 (3)  = SYSUTCDATETIME ()
          , @EndTimeUtc     DATETIME2 (3)  = NULL
          , @ExecutionId    BIGINT         = NULL
          , @KeyParameters  NVARCHAR (MAX) = NULL
          , @Comments       NVARCHAR (MAX) = NULL
          , @ContextMessage NVARCHAR (MAX) = NULL
          , @DynamicSql     NVARCHAR (MAX) = NULL
          , @ErrorMsg       NVARCHAR (MAX) = NULL
          , @ErrorProc      NVARCHAR (300) = NULL
          , @ErrorNumber    INT            = NULL
          , @ErrorLine      INT            = NULL;

    -- One timestamp for OccurredUtc and both audit dates, so a row cannot appear to have been audited
    -- before it occurred, and the Actor string that carries the human rather than the pooled login.
    DECLARE @Now     DATETIME2 (3)   = SYSUTCDATETIME ()
          , @Actor   NVARCHAR (255)  = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                               , ORIGINAL_LOGIN ())
          , @Failure NVARCHAR (2000) = NULL;

    -- Identifiers and counts ONLY. Every parameter here is one or the other, which is unusual and is a
    -- property of the table rather than a coincidence: see the file header on what it does not record.
    SET @KeyParameters = CONCAT (N'PermissionCode=',       @PermissionCode
                               , N', BurstCount=',         @BurstCount
                               , N', TotalMicroseconds=',  @TotalMicroseconds
                               , N', Allowed=',            @Allowed
                               , N', TenantId=',           @TenantId
                               , N', UserProfileId=',      @UserProfileId
                               , N', ProbeContext=',       @ProbeContext);

    BEGIN TRY

        EXEC logs.uspStartExecutionLogging
              @ProcedureName          = @ProcName
            , @KeyParameters          = @KeyParameters
            , @StartDateUtc           = @StartTimeUtc
            , @ReCreatedAfterRollback = 0
            , @ExecutionLogId         = @ExecutionId OUTPUT;

        -- =========================================================================================
        -- ===== The procedure's own work starts here. Everything above and below is boilerplate. ==
        -- =========================================================================================

        -- Validation BEFORE BEGIN TRANSACTION. A malformed call has nothing to roll back, and doing it
        -- here means the failure is recorded against a logs.ExecutionLog row no rollback can reach.
        SET @PermissionCode = LTRIM (RTRIM (@PermissionCode));

        IF @PermissionCode IS NULL OR LEN (@PermissionCode) = 0
        BEGIN
            ;THROW 50190, N'@PermissionCode is required and was empty -- CK_logs_PermissionProbe_PermissionCode. A probe of a code that does not exist in auth.Permission is perfectly legitimate and is deliberately not validated against it, but a probe of NO code measures nothing and could not be grouped with anything. This is a defect in the calling procedure.', 1;
        END;

        IF @BurstCount IS NULL OR @BurstCount < 2 OR @BurstCount > 10000
        BEGIN
            ;THROW 50191, N'@BurstCount must be between 2 and 10000 -- CK_logs_PermissionProbe_BurstCount. Below 2 the measurement is below the resolution of the system clock, which is about one millisecond on Windows and is the entire reason the burst exists; a burst of 1 records 0 or 1000 microseconds and nothing in between. Above 10000 the probe has stopped being a sample and become the workload. Perf.PermissionProbeBurstCount is the setting the caller should be reading.', 1;
        END;

        IF @TotalMicroseconds IS NULL OR @TotalMicroseconds < 0
        BEGIN
            ;THROW 50192, N'@TotalMicroseconds must be present and not negative -- CK_logs_PermissionProbe_TotalMicroseconds. A negative elapsed time means the system clock moved backwards during the burst, which does happen on a virtual machine whose host adjusts time, and a row recording it would poison every average taken from this table. Discard the burst and take another one.', 1;
        END;

        IF @DetailJson IS NOT NULL AND ISJSON (@DetailJson) = 0
        BEGIN
            ;THROW 50193, N'@DetailJson was supplied and is not valid JSON -- CK_logs_PermissionProbe_DetailJson. It carries the SHAPE of the measurement and never the material: a plan warning, a bucket label, a count. NULL is the correct value when there is nothing to add.', 1;
        END;

        -- The acting profile is the same value on every ambient call, so a caller that omits it gets
        -- the session's. TRY_CAST, never CAST: an unset key is NULL and a malformed one must not raise
        -- inside a recorder. The benchmark scripts pass it explicitly and are unaffected.
        SET @UserProfileId = COALESCE (@UserProfileId, TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT));

        -- Sanitize the two ids about to meet a foreign key. A probe of a tenant that no longer exists is
        -- still a valid measurement of what the decision cost, so the id becomes NULL on the row and
        -- survives verbatim in @DetailJson where no constraint can object to it.
        IF @TenantId IS NOT NULL AND NOT EXISTS (SELECT 1 FROM auth.Tenant AS t WHERE t.TenantId = @TenantId)
        BEGIN
            SET @DetailJson = COALESCE (@DetailJson, N'{}');
            SET @DetailJson = JSON_MODIFY (@DetailJson, N'$.unresolvedTenantId', @TenantId);
            SET @TenantId   = NULL;
        END;

        IF @UserProfileId IS NOT NULL
           AND NOT EXISTS (SELECT 1 FROM auth.UserProfile AS up WHERE up.UserProfileId = @UserProfileId)
        BEGIN
            SET @DetailJson    = COALESCE (@DetailJson, N'{}');
            SET @DetailJson    = JSON_MODIFY (@DetailJson, N'$.unresolvedUserProfileId', @UserProfileId);
            SET @UserProfileId = NULL;
        END;

        BEGIN TRANSACTION;

        INSERT logs.PermissionProbe
            (OccurredUtc, BurstCount, TotalMicroseconds, PermissionCode, TenantId, UserProfileId, Allowed
           , ScopeRowsForProfile, ClosureRowsForTenant, ProbeContext, DetailJson
           , auditCreatedBy, auditCreatedDateUtc, auditModifiedBy, auditModifiedDateUtc)
        VALUES (@Now, @BurstCount, @TotalMicroseconds, @PermissionCode, @TenantId, @UserProfileId, @Allowed
              , @ScopeRowsForProfile, @ClosureRowsForTenant, @ProbeContext, @DetailJson
              , @Actor, @Now, @Actor, @Now);

        -- SCOPE_IDENTITY and not @@IDENTITY: the table carries an AFTER UPDATE trigger today and may
        -- gain more, and @@IDENTITY would return whatever a trigger inserted last. Cast because
        -- SCOPE_IDENTITY is NUMERIC (38, 0) and the column is BIGINT.
        SET @PermissionProbeId = CAST (SCOPE_IDENTITY () AS BIGINT);

        SET @Comments = CONCAT (N'PermissionProbe ', @PermissionProbeId, N' recorded: ', @BurstCount
                              , N' decision(s) of ', @PermissionCode, N' in ', @TotalMicroseconds
                              , N' microseconds = '
                              , CAST (CAST (@TotalMicroseconds AS DECIMAL (18, 3))
                                      / NULLIF (@BurstCount, 0) AS NVARCHAR (30))
                              , N' per call, Allowed=', @Allowed
                              , COALESCE (N', ScopeRowsForProfile=' + CAST (@ScopeRowsForProfile AS NVARCHAR (11))
                                        , N', ScopeRowsForProfile not measured'), N'.');

        -- =========================================================================================
        -- ===== End of the procedure's own work. ==================================================
        -- =========================================================================================

        IF @@TRANCOUNT > 0
        BEGIN
            COMMIT TRANSACTION;
        END;

        -- Completion. Deliberately after the COMMIT; see the procedure template for what that costs.
        SET @EndTimeUtc = SYSUTCDATETIME ();

        IF @ExecutionId IS NOT NULL
        BEGIN
            UPDATE logs.ExecutionLog
               SET EndDateUtc           = @EndTimeUtc
                 , ElapsedMilliseconds  = CAST (LEAST (DATEDIFF_BIG (MILLISECOND, @StartTimeUtc, @EndTimeUtc)
                                                     , CAST (2147483647 AS BIGINT)) AS INT)
                 , Successful           = 1
                 , Comments             = @Comments
                 , auditModifiedBy      = ORIGINAL_LOGIN ()
                 , auditModifiedDateUtc = @EndTimeUtc
             WHERE ExecutionLogId = @ExecutionId;
        END;

    END TRY
    BEGIN CATCH

        -- The ERROR_* functions are valid only in this scope and any statement can reset them, so
        -- capture them before doing anything else -- including before the rollback.
        SELECT @ErrorNumber = ERROR_NUMBER ()
             , @ErrorProc   = ERROR_PROCEDURE ()
             , @ErrorLine   = ERROR_LINE ()
             , @ErrorMsg    = ERROR_MESSAGE ()
                            + N' (error '  + CAST (ERROR_NUMBER () AS NVARCHAR (11))
                            + N', line '   + CAST (ERROR_LINE ()   AS NVARCHAR (11)) + N')';

        -- One test, not two: XACT_ABORT ON makes XACT_STATE () = -1 the common case, and -1 and 1
        -- both need the same unqualified rollback.
        IF XACT_STATE () <> 0
        BEGIN
            ROLLBACK TRANSACTION;
        END;

        -- The rollback destroyed the row logs.uspStartExecutionLogging wrote. Put it back, with the
        -- ORIGINAL @StartTimeUtc, or the only unrecorded executions would be the failures.
        BEGIN TRY
            IF @ExecutionId IS NULL
               OR NOT EXISTS (SELECT 1
                                FROM logs.ExecutionLog
                               WHERE ExecutionLogId = @ExecutionId)
            BEGIN
                EXEC logs.uspStartExecutionLogging
                      @ProcedureName          = @ProcName
                    , @KeyParameters          = @KeyParameters
                    , @StartDateUtc           = @StartTimeUtc
                    , @ReCreatedAfterRollback = 1
                    , @ExecutionLogId         = @ExecutionId OUTPUT;
            END;
        END TRY
        BEGIN CATCH
            SET @ExecutionId = NULL;
        END CATCH;

        -- Swallows everything by design, so this call cannot mask the error below it.
        EXEC logs.uspRecordExecutionError
              @ProcedureName   = @ProcName
            , @KeyParameters   = @KeyParameters
            , @ExecutionLogId  = @ExecutionId
            , @ErrorMessage    = @ErrorMsg
            , @ErrorProcedure  = @ErrorProc
            , @ErrorNumber     = @ErrorNumber
            , @ErrorLine       = @ErrorLine
            , @DynamicSql      = @DynamicSql
            , @ContextMessage  = @ContextMessage;

        -- Bare, so the ORIGINAL error number reaches the caller: 50190 to 50193 are branchable and
        -- RAISERROR would flatten every one of them to 50000. The leading semicolon is required.
        ;THROW;

    END CATCH;

    RETURN 0;
END;
GO


-- *** 5. logs.uspPurgePermissionProbe ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   logs.uspPurgePermissionProbe
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Expires logs.PermissionProbe rows older than Perf.PermissionProbeRetentionDays by setting IsDeleted = 1, in bounded
batches, and reports how many it expired and how many remain.  Section 10.6.

Meant to be called by a scheduled job -- an Agent job, an application timer, anything -- with no parameters.  The
retention comes from config.ApplicationSetting so that turning the sample rate up for an incident and the retention down
afterwards are both operator actions and neither is a deployment.

IT IS A SOFT DELETE AND THE FILE HEADER SAYS WHY THAT IS AN HONEST PROBLEM.  Nothing in this database hard-deletes and
the convention is not relaxed here, so this procedure reclaims no space: it makes the rows invisible to every read, every
index (all three are filtered on IsDeleted = 0) and every report, and the closing report of this file counts what has
accumulated.  Reclaiming the space is a DBA operation and this is the one table where running a hard DELETE against
already-expired rows by hand is a supported thing to do.

========================================================================================================================
Requirements and Key Dependencies:

logs.PermissionProbe and config.ApplicationSetting.

logs.uspStartExecutionLogging and logs.uspRecordExecutionError, for the rule 8 instrumentation block, plus
logs.ExecutionLog itself, which the completion UPDATE writes directly.

========================================================================================================================
Notes:

BATCHED, AND THE BATCH SIZE IS A PARAMETER RATHER THAN A CONSTANT.  A single UPDATE over a month of samples at
1-in-1000 on a busy application is a multi-million-row transaction that escalates to a table lock and blocks the very
procedure that writes the samples.  Each batch is its own transaction -- so a purge that is killed half way through has
expired the rows it reported and left the rest, which is a correct and resumable state.  This is the one place in the
deployment where a loop of committed transactions is preferred to one atomic statement, because there is nothing atomic
about "rows older than fourteen days": the set is different by the time the statement finishes.

IDEMPOTENT.  Running it twice expires nothing the second time and reports 0, because the predicate excludes rows that
are already IsDeleted = 1.

@RetentionDays = 0 IS REFUSED (E-50194) AND NOT TREATED AS "EXPIRE EVERYTHING".  A zero in a retention parameter is
almost always an unset variable rather than an instruction, and the cost of guessing wrong is the whole table. An
operator who genuinely wants everything gone passes @RetentionDays = -1, which is accepted and documented, because
nobody types -1 by accident.

NO PERMISSION IS DEMANDED, for the same reason as the recorder: this is infrastructure below the authorization layer and
it is protected by having no grant. A scheduled job runs it as a principal that holds EXECUTE because a DBA said so.

========================================================================================================================
Example Usage and Performance:

declare @expired int, @remaining int;
exec logs.uspPurgePermissionProbe @RowsExpired = @expired output, @RowsRemaining = @remaining output;

exec logs.uspPurgePermissionProbe @RetentionDays = 2, @BatchSize = 20000;   -- after a benchmark run

One seek per batch on IX_logs_PermissionProbe_When, plus the trigger's own UPDATE over the same batch.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-074
Description: Created.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE logs.uspPurgePermissionProbe
      @RetentionDays  INT = NULL
    , @BatchSize      INT = 5000
    , @RowsExpired    INT = NULL OUTPUT
    , @RowsRemaining  INT = NULL OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[logs].[uspPurgePermissionProbe]')
          , @StartTimeUtc   DATETIME2 (3)  = SYSUTCDATETIME ()
          , @EndTimeUtc     DATETIME2 (3)  = NULL
          , @ExecutionId    BIGINT         = NULL
          , @KeyParameters  NVARCHAR (MAX) = NULL
          , @Comments       NVARCHAR (MAX) = NULL
          , @ContextMessage NVARCHAR (MAX) = NULL
          , @DynamicSql     NVARCHAR (MAX) = NULL
          , @ErrorMsg       NVARCHAR (MAX) = NULL
          , @ErrorProc      NVARCHAR (300) = NULL
          , @ErrorNumber    INT            = NULL
          , @ErrorLine      INT            = NULL;

    DECLARE @Now      DATETIME2 (3)   = SYSUTCDATETIME ()
          , @Actor    NVARCHAR (255)  = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                                , ORIGINAL_LOGIN ())
          , @Cutoff   DATETIME2 (3)   = NULL
          , @Batch    INT             = 0
          , @Batches  INT             = 0
          , @Failure  NVARCHAR (2000) = NULL
          , @Source   NVARCHAR (30)   = N'parameter';

    SET @RowsExpired = 0;

    SET @KeyParameters = CONCAT (N'RetentionDays=', @RetentionDays, N', BatchSize=', @BatchSize);

    BEGIN TRY

        EXEC logs.uspStartExecutionLogging
              @ProcedureName          = @ProcName
            , @KeyParameters          = @KeyParameters
            , @StartDateUtc           = @StartTimeUtc
            , @ReCreatedAfterRollback = 0
            , @ExecutionLogId         = @ExecutionId OUTPUT;

        -- =========================================================================================
        -- ===== The procedure's own work starts here. Everything above and below is boilerplate. ==
        -- =========================================================================================

        -- 1.  The retention. TRY_CAST because a setting is a string and an operator can type anything
        --     into it; a malformed value falls through to E-50194 rather than silently becoming NULL
        --     and then, by way of DATEADD, expiring nothing forever.
        IF @RetentionDays IS NULL
        BEGIN
            SET @Source        = N'config.ApplicationSetting';
            SET @RetentionDays = TRY_CAST ((SELECT s.SettingValue
                                              FROM config.ApplicationSetting AS s
                                             WHERE s.SettingKey = N'Perf.PermissionProbeRetentionDays'
                                               AND s.IsDeleted  = 0) AS INT);
        END;

        IF @RetentionDays IS NULL OR @RetentionDays = 0
        BEGIN
            SET @Failure = N'The retention could not be resolved to a usable number of days (source: ' + @Source
                         + N'). A NULL or a 0 here is refused rather than interpreted: 0 would mean "expire every '
                         + N'sample ever taken", which is almost always an unset variable and never what anybody typed '
                         + N'on purpose. Set Perf.PermissionProbeRetentionDays to a positive integer, or pass '
                         + N'@RetentionDays explicitly. Pass -1 if you really do want the whole table expired; nobody '
                         + N'types -1 by accident. Nothing has been changed.';

            ;THROW 50194, @Failure, 1;
        END;

        IF @BatchSize IS NULL OR @BatchSize < 1 OR @BatchSize > 1000000
        BEGIN
            ;THROW 50195, N'@BatchSize must be between 1 and 1000000. The batching is not a tuning nicety: a single UPDATE over a month of samples escalates to a table lock and blocks auth.uspDemandPermission, which is the procedure that writes the samples -- so an unbatched purge of this table degrades the thing it is measuring. 5000 is the default and is deliberately modest.', 1;
        END;

        -- DATEADD on a negative retention gives a cutoff in the future, which expires everything. That
        -- is the documented meaning of -1 and it needs no special case.
        SET @Cutoff = DATEADD (DAY, -@RetentionDays, @Now);

        -- 2.  The loop. Each batch is its own transaction, so a purge that is killed part way through
        --     has committed what it reported. TOP inside an UPDATE needs no ORDER BY here: any 5000 of
        --     the qualifying rows will do, and the predicate is what bounds the set.
        SET @Batch = 1;

        WHILE @Batch > 0
        BEGIN
            BEGIN TRANSACTION;

            UPDATE TOP (@BatchSize) p
               SET p.IsDeleted            = 1
                 , p.auditDeletedBy       = @Actor
                 , p.auditDeletedDateUtc  = @Now
                 , p.auditModifiedBy      = @Actor
              FROM logs.PermissionProbe AS p
             WHERE p.IsDeleted   = 0
               AND p.OccurredUtc < @Cutoff;

            SET @Batch = @@ROWCOUNT;

            IF @@TRANCOUNT > 0
            BEGIN
                COMMIT TRANSACTION;
            END;

            SET @RowsExpired += @Batch;
            SET @Batches     += CASE WHEN @Batch > 0 THEN 1 ELSE 0 END;
        END;

        SET @RowsRemaining = (SELECT COUNT (*) FROM logs.PermissionProbe WHERE IsDeleted = 0);

        SET @Comments = CONCAT (N'Expired ', @RowsExpired, N' probe row(s) older than ', @Cutoff, N' in ', @Batches
                              , N' batch(es) of up to ', @BatchSize, N'; retention ', @RetentionDays
                              , N' day(s) from ', @Source, N'. ', @RowsRemaining
                              , N' live row(s) remain. SOFT delete: no space was reclaimed and none will be until a '
                              + N'DBA removes the expired rows by hand.');

        -- =========================================================================================
        -- ===== End of the procedure's own work. ==================================================
        -- =========================================================================================

        SET @EndTimeUtc = SYSUTCDATETIME ();

        IF @ExecutionId IS NOT NULL
        BEGIN
            UPDATE logs.ExecutionLog
               SET EndDateUtc           = @EndTimeUtc
                 , ElapsedMilliseconds  = CAST (LEAST (DATEDIFF_BIG (MILLISECOND, @StartTimeUtc, @EndTimeUtc)
                                                     , CAST (2147483647 AS BIGINT)) AS INT)
                 , Successful           = 1
                 , Comments             = @Comments
                 , auditModifiedBy      = ORIGINAL_LOGIN ()
                 , auditModifiedDateUtc = @EndTimeUtc
             WHERE ExecutionLogId = @ExecutionId;
        END;

    END TRY
    BEGIN CATCH

        SELECT @ErrorNumber = ERROR_NUMBER ()
             , @ErrorProc   = ERROR_PROCEDURE ()
             , @ErrorLine   = ERROR_LINE ()
             , @ErrorMsg    = ERROR_MESSAGE ()
                            + N' (error '  + CAST (ERROR_NUMBER () AS NVARCHAR (11))
                            + N', line '   + CAST (ERROR_LINE ()   AS NVARCHAR (11)) + N')';

        IF XACT_STATE () <> 0
        BEGIN
            ROLLBACK TRANSACTION;
        END;

        -- The batches already committed are NOT undone by that rollback, and that is correct: they are
        -- expired rows, the operation is resumable, and @RowsExpired in the context message says how far
        -- it got. A purge is the one operation here where partial progress is a feature.
        SET @ContextMessage = CONCAT (N'Failed after expiring ', @RowsExpired, N' row(s) in ', @Batches
                                    , N' committed batch(es). Those batches stand; re-run to continue.');

        BEGIN TRY
            IF @ExecutionId IS NULL
               OR NOT EXISTS (SELECT 1
                                FROM logs.ExecutionLog
                               WHERE ExecutionLogId = @ExecutionId)
            BEGIN
                EXEC logs.uspStartExecutionLogging
                      @ProcedureName          = @ProcName
                    , @KeyParameters          = @KeyParameters
                    , @StartDateUtc           = @StartTimeUtc
                    , @ReCreatedAfterRollback = 1
                    , @ExecutionLogId         = @ExecutionId OUTPUT;
            END;
        END TRY
        BEGIN CATCH
            SET @ExecutionId = NULL;
        END CATCH;

        EXEC logs.uspRecordExecutionError
              @ProcedureName   = @ProcName
            , @KeyParameters   = @KeyParameters
            , @ExecutionLogId  = @ExecutionId
            , @ErrorMessage    = @ErrorMsg
            , @ErrorProcedure  = @ErrorProc
            , @ErrorNumber     = @ErrorNumber
            , @ErrorLine       = @ErrorLine
            , @DynamicSql      = @DynamicSql
            , @ContextMessage  = @ContextMessage;

        ;THROW;

    END CATCH;

    RETURN 0;
END;
GO


-- *** 6. logs.uspReportPermissionProbe ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   logs.uspReportPermissionProbe
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Reads logs.PermissionProbe back as the three answers Phase 5 was set up to produce.  Section 10.6, tasks T-070 and
T-074, decision D-07.

  Result set 1 -- THE HEADLINE.  One row: how many samples, over what window, and the distribution of microseconds per
                  call as a median, a 95th and a 99th percentile rather than as a mean.  A mean is the wrong statistic
                  for this question: the design's claim is that the predicate is cheap, and the way a predicate fails is
                  by being cheap almost always and catastrophic occasionally, which a mean hides and a 99th shows.
  Result set 2 -- BY PERMISSION.  The same distribution per permission code, with the average scope-row count beside it.
                  This is the result set D-07 is actually decided on: a permission whose 99th percentile is an order of
                  magnitude above the others is a permission whose scope has grown a shape the design did not predict.
  Result set 3 -- BY HOUR.  DATE_BUCKET over the window, so a regression can be dated. Answers "did this get worse on
                  Tuesday", which is the question nobody can answer from an aggregate over all time.

========================================================================================================================
Requirements and Key Dependencies:

logs.PermissionProbe.  Nothing else -- deliberately: a report that joined auth.Permission to prettify the output would
stop working for exactly the probes most worth reading, the ones whose permission code does not exist.

logs.uspStartExecutionLogging and logs.uspRecordExecutionError, for the rule 8 instrumentation block.

========================================================================================================================
Notes:

APPROX_PERCENTILE_CONT IS A SQL SERVER 2022 AGGREGATE AND IS USED DELIBERATELY.  The exact PERCENTILE_CONT is a window
function: it returns a value per row and needs a DISTINCT or a second pass to be read as one number per group, and it
sorts the whole partition to do it.  The approximate form is an aggregate, composes with GROUP BY, and its error bound
(about 1.33% at rank) is an order of magnitude smaller than the thing being measured is noisy.  This file's floor and
ceiling are both SQL Server 2022, so the function is in range -- see the skill's compatibility notes.

THE WINDOW DEFAULTS TO THE WHOLE TABLE AND NOT TO THE LAST DAY.  A performance report that silently windows is a report
that shows nothing after a quiet weekend and sends somebody looking for a broken probe. @FromUtc and @ToUtc are NULL by
default and the header row states the window it actually used.

ROWS WITH A NULL ScopeRowsForProfile ARE COUNTED IN THE TIMINGS AND EXCLUDED FROM THE CORRELATION.  AVG ignores NULLs, so
the average scope count is over the rows that measured it -- and the report says how many did, because "average scope
rows 12" over four samples out of nine thousand is a number that should not be read as anything.

IT READS SOFT-DELETED ROWS BACK ONLY WHEN ASKED.  @IncludeExpired defaults to 0. The reason to have the switch at all is
the purge's own limitation: expired rows are still there, and after an incident somebody usually wants the samples that
were expired the morning the incident was reported.

NO PERMISSION IS DEMANDED and there is no grant, same as the rest of this file. Reading it is a DBA activity.

========================================================================================================================
Example Usage and Performance:

exec logs.uspReportPermissionProbe;
exec logs.uspReportPermissionProbe @FromUtc = '2026-09-01', @BucketMinutes = 15;

Three scans of IX_logs_PermissionProbe_When, or a seek plus a range when the window is bounded.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-074
Description: Created.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE logs.uspReportPermissionProbe
      @FromUtc        DATETIME2 (3) = NULL
    , @ToUtc          DATETIME2 (3) = NULL
    , @BucketMinutes  INT           = 60
    , @IncludeExpired BIT           = 0
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[logs].[uspReportPermissionProbe]')
          , @StartTimeUtc   DATETIME2 (3)  = SYSUTCDATETIME ()
          , @EndTimeUtc     DATETIME2 (3)  = NULL
          , @ExecutionId    BIGINT         = NULL
          , @KeyParameters  NVARCHAR (MAX) = NULL
          , @Comments       NVARCHAR (MAX) = NULL
          , @ContextMessage NVARCHAR (MAX) = NULL
          , @DynamicSql     NVARCHAR (MAX) = NULL
          , @ErrorMsg       NVARCHAR (MAX) = NULL
          , @ErrorProc      NVARCHAR (300) = NULL
          , @ErrorNumber    INT            = NULL
          , @ErrorLine      INT            = NULL;

    DECLARE @Anchor DATETIME2 (3) = CAST (N'2020-01-01T00:00:00' AS DATETIME2 (3))
          , @Rows   INT           = 0;

    SET @KeyParameters = CONCAT (N'FromUtc=', @FromUtc, N', ToUtc=', @ToUtc, N', BucketMinutes=', @BucketMinutes
                               , N', IncludeExpired=', @IncludeExpired);

    BEGIN TRY

        EXEC logs.uspStartExecutionLogging
              @ProcedureName          = @ProcName
            , @KeyParameters          = @KeyParameters
            , @StartDateUtc           = @StartTimeUtc
            , @ReCreatedAfterRollback = 0
            , @ExecutionLogId         = @ExecutionId OUTPUT;

        -- =========================================================================================
        -- ===== The procedure's own work starts here. Everything above and below is boilerplate. ==
        -- =========================================================================================

        IF @BucketMinutes IS NULL OR @BucketMinutes < 1 OR @BucketMinutes > 1440
        BEGIN
            ;THROW 50196, N'@BucketMinutes must be between 1 and 1440. Below 1 DATE_BUCKET has no width to bucket by; above a day the third result set has fewer rows than the first and stops being a time series. 60 is the default and 15 is the useful one during an incident.', 1;
        END;

        -- Bound the window once, into a table variable the three result sets share. Three reads of the
        -- base table with three copies of the same predicate would be three chances for them to drift,
        -- and a report whose three sections describe different row sets is worse than no report.
        DECLARE @Sample TABLE
        (
            RowNo               INT IDENTITY (1, 1) PRIMARY KEY,
            OccurredUtc         DATETIME2 (3)   NOT NULL,
            PermissionCode      NVARCHAR (100)  NOT NULL,
            MicrosecondsPerCall DECIMAL (18, 3) NOT NULL,
            BurstCount          INT             NOT NULL,
            Allowed             BIT             NOT NULL,
            ScopeRowsForProfile INT                 NULL,
            UserProfileId       INT                 NULL
        );

        INSERT @Sample (OccurredUtc, PermissionCode, MicrosecondsPerCall, BurstCount, Allowed
                      , ScopeRowsForProfile, UserProfileId)
        SELECT p.OccurredUtc
             , p.PermissionCode
             , p.MicrosecondsPerCall
             , p.BurstCount
             , p.Allowed
             , p.ScopeRowsForProfile
             , p.UserProfileId
          FROM logs.PermissionProbe AS p
         WHERE (@IncludeExpired = 1 OR p.IsDeleted = 0)
           AND (@FromUtc IS NULL OR p.OccurredUtc >= @FromUtc)
           AND (@ToUtc   IS NULL OR p.OccurredUtc <  @ToUtc);

        SET @Rows = @@ROWCOUNT;

        -- 1.  The headline. Percentiles and not a mean; the header essay says why.
        SELECT Samples            = COUNT (*)
             , WindowFromUtc      = MIN (s.OccurredUtc)
             , WindowToUtc        = MAX (s.OccurredUtc)
             , DistinctPermissions = COUNT (DISTINCT s.PermissionCode)
             , DecisionsTimed     = SUM (CAST (s.BurstCount AS BIGINT))
             , AllowedPct         = CAST (100.0 * SUM (CAST (s.Allowed AS INT)) / NULLIF (COUNT (*), 0) AS DECIMAL (5, 1))
             , MinMicroseconds    = MIN (s.MicrosecondsPerCall)
             , MedianMicroseconds = APPROX_PERCENTILE_CONT (0.50) WITHIN GROUP (ORDER BY s.MicrosecondsPerCall)
             , P95Microseconds    = APPROX_PERCENTILE_CONT (0.95) WITHIN GROUP (ORDER BY s.MicrosecondsPerCall)
             , P99Microseconds    = APPROX_PERCENTILE_CONT (0.99) WITHIN GROUP (ORDER BY s.MicrosecondsPerCall)
             , MaxMicroseconds    = MAX (s.MicrosecondsPerCall)
             , ScopeRowsMeasured  = COUNT (s.ScopeRowsForProfile)
             , AvgScopeRows       = AVG (CAST (s.ScopeRowsForProfile AS DECIMAL (18, 2)))
             , MaxScopeRows       = MAX (s.ScopeRowsForProfile)
             , ReadNote           = N'Microseconds per DECISION, warm cache, derived from bursts. The median is what '
                                  + N'the design claims; the 99th is how the claim fails. Section 10.6, D-07.'
          FROM @Sample AS s;

        -- 2.  By permission. The set decision D-07 is taken on.
        SELECT s.PermissionCode
             , Samples            = COUNT (*)
             , DecisionsTimed     = SUM (CAST (s.BurstCount AS BIGINT))
             , AllowedPct         = CAST (100.0 * SUM (CAST (s.Allowed AS INT)) / NULLIF (COUNT (*), 0) AS DECIMAL (5, 1))
             , MedianMicroseconds = APPROX_PERCENTILE_CONT (0.50) WITHIN GROUP (ORDER BY s.MicrosecondsPerCall)
             , P95Microseconds    = APPROX_PERCENTILE_CONT (0.95) WITHIN GROUP (ORDER BY s.MicrosecondsPerCall)
             , P99Microseconds    = APPROX_PERCENTILE_CONT (0.99) WITHIN GROUP (ORDER BY s.MicrosecondsPerCall)
             , MaxMicroseconds    = MAX (s.MicrosecondsPerCall)
             , ScopeRowsMeasured  = COUNT (s.ScopeRowsForProfile)
             , AvgScopeRows       = AVG (CAST (s.ScopeRowsForProfile AS DECIMAL (18, 2)))
             , DistinctProfiles   = COUNT (DISTINCT s.UserProfileId)
          FROM @Sample AS s
         GROUP BY s.PermissionCode
         ORDER BY P99Microseconds DESC, s.PermissionCode;

        -- 3.  By bucket. DATE_BUCKET is a 2022 aggregate-friendly date function and is used here rather
        --     than the older DATEADD (MINUTE, DATEDIFF (MINUTE, 0, x) / n * n, 0) idiom, which is off by
        --     the epoch when n does not divide an hour.
        SELECT BucketStartUtc     = DATE_BUCKET (MINUTE, @BucketMinutes, s.OccurredUtc, @Anchor)
             , Samples            = COUNT (*)
             , MedianMicroseconds = APPROX_PERCENTILE_CONT (0.50) WITHIN GROUP (ORDER BY s.MicrosecondsPerCall)
             , P99Microseconds    = APPROX_PERCENTILE_CONT (0.99) WITHIN GROUP (ORDER BY s.MicrosecondsPerCall)
             , MaxMicroseconds    = MAX (s.MicrosecondsPerCall)
             , AvgScopeRows       = AVG (CAST (s.ScopeRowsForProfile AS DECIMAL (18, 2)))
          FROM @Sample AS s
         GROUP BY DATE_BUCKET (MINUTE, @BucketMinutes, s.OccurredUtc, @Anchor)
         ORDER BY BucketStartUtc;

        SET @Comments = CONCAT (N'Reported on ', @Rows, N' probe row(s), bucket ', @BucketMinutes
                              , N' minute(s), IncludeExpired=', @IncludeExpired
                              , CASE WHEN @Rows = 0
                                     THEN N'. NO SAMPLES: either Perf.PermissionProbeSampleRate is 0, which is the '
                                        + N'shipped default, or nothing has called auth.uspDemandPermission since it '
                                        + N'was raised.'
                                     ELSE N'.' END);

        -- =========================================================================================
        -- ===== End of the procedure's own work. ==================================================
        -- =========================================================================================

        SET @EndTimeUtc = SYSUTCDATETIME ();

        IF @ExecutionId IS NOT NULL
        BEGIN
            UPDATE logs.ExecutionLog
               SET EndDateUtc           = @EndTimeUtc
                 , ElapsedMilliseconds  = CAST (LEAST (DATEDIFF_BIG (MILLISECOND, @StartTimeUtc, @EndTimeUtc)
                                                     , CAST (2147483647 AS BIGINT)) AS INT)
                 , Successful           = 1
                 , Comments             = @Comments
                 , auditModifiedBy      = ORIGINAL_LOGIN ()
                 , auditModifiedDateUtc = @EndTimeUtc
             WHERE ExecutionLogId = @ExecutionId;
        END;

    END TRY
    BEGIN CATCH

        SELECT @ErrorNumber = ERROR_NUMBER ()
             , @ErrorProc   = ERROR_PROCEDURE ()
             , @ErrorLine   = ERROR_LINE ()
             , @ErrorMsg    = ERROR_MESSAGE ()
                            + N' (error '  + CAST (ERROR_NUMBER () AS NVARCHAR (11))
                            + N', line '   + CAST (ERROR_LINE ()   AS NVARCHAR (11)) + N')';

        -- No rollback: this procedure opens no transaction, and a caller's transaction is not its to end.

        BEGIN TRY
            IF @ExecutionId IS NULL
               OR NOT EXISTS (SELECT 1
                                FROM logs.ExecutionLog
                               WHERE ExecutionLogId = @ExecutionId)
            BEGIN
                EXEC logs.uspStartExecutionLogging
                      @ProcedureName          = @ProcName
                    , @KeyParameters          = @KeyParameters
                    , @StartDateUtc           = @StartTimeUtc
                    , @ReCreatedAfterRollback = 1
                    , @ExecutionLogId         = @ExecutionId OUTPUT;
            END;
        END TRY
        BEGIN CATCH
            SET @ExecutionId = NULL;
        END CATCH;

        EXEC logs.uspRecordExecutionError
              @ProcedureName   = @ProcName
            , @KeyParameters   = @KeyParameters
            , @ExecutionLogId  = @ExecutionId
            , @ErrorMessage    = @ErrorMsg
            , @ErrorProcedure  = @ErrorProc
            , @ErrorNumber     = @ErrorNumber
            , @ErrorLine       = @ErrorLine
            , @DynamicSql      = @DynamicSql
            , @ContextMessage  = @ContextMessage;

        ;THROW;

    END CATCH;

    RETURN 0;
END;
GO


-- *** 7. logs.vwPredicateFunctionStats ***
-- The free half of the measurement: the server's own running totals for the six functions the security design depends
-- on.  Always available, costs nothing, and survives nothing -- the DMV is cleared by a restart, an ALTER, a recompile
-- or a DBCC FREEPROCCACHE, which is why every row carries the cache-entry age that says how far back it can see.
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   logs.vwPredicateFunctionStats
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

The server's own running totals for the six functions the security design depends on, one row per function whether or not
the server has a number for it.  Section 10.6, gap G-22.

Not SCHEMABINDING, and it cannot be: it reads a dynamic management view.  That is also why it is a view rather than a
function -- a DMV read inside a SCHEMABINDING predicate is impossible, which is the whole shape of G-22.

Requirements and Key Dependencies:

sys.dm_exec_function_stats, and VIEW SERVER PERFORMANCE STATE (or VIEW SERVER STATE on earlier builds) for the reader.
A principal without it gets an empty right-hand side and therefore six rows of NULLs whose StatsNote reads as "not
called" -- which is the one misreading this view can produce and the reason the permission is named here.

Notes:

EVERY ROW IS LISTED FROM A VALUES CONSTRUCTOR AND LEFT JOINED.  Selecting from the DMV directly would omit an inlined
scalar function and every inline table-valued function, which between them are five of the six.  See the file header.

THE NUMBERS ARE CUMULATIVE SINCE CachedSinceUtc AND SURVIVE NOTHING.  A restart, an ALTER, a recompile or a DBCC
FREEPROCCACHE resets them.  Read the age, not just the count.

Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-073
Description: Created.

***********************************************************************************************************************/
CREATE OR ALTER VIEW logs.vwPredicateFunctionStats
AS
-- The six are listed by name from a VALUES constructor and LEFT JOINed, never selected from the DMV directly.  The
-- header essay gives the measured reason: an inlined scalar function disappears from sys.dm_exec_function_stats
-- altogether, and an inline table-valued function was never in it, so a view built on the DMV alone would silently omit
-- the most important functions in the database and read as "never called".
SELECT FunctionName      = f.FunctionName
     , FunctionKind      = f.FunctionKind
     , RoleInTheDesign   = f.RoleInTheDesign
     , ObjectExists      = CASE WHEN OBJECT_ID (f.FunctionName) IS NULL THEN CAST (0 AS BIT) ELSE CAST (1 AS BIT) END
     , ExecutionCount    = s.execution_count
     , TotalWorkerMs     = CAST (s.total_worker_time / 1000.0 AS DECIMAL (18, 3))
     , AvgWorkerMicrosec = CAST (s.total_worker_time * 1.0 / NULLIF (s.execution_count, 0) AS DECIMAL (18, 3))
     , TotalElapsedMs    = CAST (s.total_elapsed_time / 1000.0 AS DECIMAL (18, 3))
     , TotalLogicalReads = s.total_logical_reads
     , CachedSinceUtc    = s.cached_time
     , LastExecutedUtc   = s.last_execution_time
       -- Why the numbers are absent, decided rather than guessed: an inline TVF is structurally invisible to this DMV,
       -- an inlineable scalar function is invisible whenever the optimizer inlined it, and anything else with no row
       -- really has not been called since the cache entry was created.
     , StatsNote         = CASE
                             WHEN OBJECT_ID (f.FunctionName) IS NULL
                                  THEN N'The function does not exist in this database. Run 100_auth_functions.sql.'
                             WHEN f.FunctionKind = N'inline TVF'
                                  THEN N'NO STATISTICS ARE POSSIBLE. sys.dm_exec_function_stats covers scalar and CLR '
                                     + N'functions only; an inline table-valued function is expanded into the calling '
                                     + N'plan and has no separate execution to count. This is permanent, not a gap in '
                                     + N'the data, and section 10.2 requires the function to be an inline TVF -- a '
                                     + N'multi-statement one would defeat the semi-join the whole design rests on. Use '
                                     + N'the extended-events session in section 8 of 175_perf_instrumentation.sql, or '
                                     + N'logs.PermissionProbe.'
                             WHEN s.object_id IS NULL AND f.MayBeInlined = 1
                                  THEN N'NO ROW IN THE DMV, AND THE REASON IS AMBIGUOUS. This scalar function is a '
                                     + N'candidate for Scalar UDF Inlining, and an inlined call is not counted at all. '
                                     + N'So this means EITHER never called OR called constantly and inlined every '
                                     + N'time. logs.PermissionProbe is how you tell the two apart.'
                             WHEN s.object_id IS NULL
                                  THEN N'No row in the DMV: not called since the plan cache entry was created. This '
                                     + N'function is not a candidate for inlining, so the absence is unambiguous.'
                             ELSE N'Live statistics. They start at CachedSinceUtc and are lost on a restart, an ALTER '
                                + N'to the function, a recompile or a DBCC FREEPROCCACHE -- so a small '
                                + N'ExecutionCount on a busy server means a recent recompile at least as often as it '
                                + N'means a quiet function.'
                           END
  FROM (VALUES
         (N'auth.tvfTenantReadPredicate',    N'inline TVF',   CAST (1 AS BIT)
        , N'The RLS FILTER and the READ block predicate. Section 10.2. Runs on every SELECT against every registered table.')
       , (N'auth.tvfTenantInsertPredicate',  N'inline TVF',   CAST (1 AS BIT)
        , N'The RLS BLOCK predicate for INSERT, AFTER INSERT. Section 10.3 -- separate from the read predicate because inserting into a tenant you can read is not the same right as reading it, and the only one of the three that tests ActingTenantId for equality (P-06).')
       , (N'auth.tvfTenantUpdatePredicate',  N'inline TVF',   CAST (1 AS BIT)
        , N'The RLS BLOCK predicate for UPDATE, both AFTER and BEFORE. Governs the soft delete, so it is the predicate behind "which rows may I retire".')
       , (N'auth.tvfPermissionScope',        N'inline TVF',   CAST (1 AS BIT)
        , N'The scope expansion the three predicates and auth.udfHasPermission all fold in. If anything in this design is the hot path, it is this.')
       , (N'auth.udfHasPermission',          N'scalar',       CAST (1 AS BIT)
        , N'The permission decision auth.uspDemandPermission calls, and the one logs.PermissionProbe times. Inlineable, so its absence from the DMV proves nothing.')
       , (N'auth.udfResolveAuthPolicy',      N'scalar',       CAST (0 AS BIT)
        , N'Resolves the nearest ancestor authentication policy. Called once per sign-in rather than once per row, and not a candidate for inlining, so its statistics here are trustworthy and are a sign-in counter in all but name.')
       ) AS f (FunctionName, FunctionKind, MayBeInlined, RoleInTheDesign)
  LEFT JOIN sys.dm_exec_function_stats AS s
         ON s.database_id = DB_ID ()
        AND s.object_id   = OBJECT_ID (f.FunctionName);
GO


-- *** 8. The extended-events session ***
-- The third measurement, and the only one that can attribute cost to a plan.  Section 10.6 asks for "a documented
-- extended-events session"; this creates it, stopped, and leaves starting it to whoever is doing the measuring.
--
-- IT IS CREATED STOPPED AND WITH STARTUP_STATE = OFF, AND BOTH MATTER.  An event session that starts itself is an
-- event session somebody will find running on a production server eighteen months from now with nobody able to say who
-- turned it on.  module_end fires once per function or procedure call: on the hot path measured here that is millions of
-- events an hour, and the ring buffer will drop most of them -- which is fine for sampling a distribution and fatal for
-- anybody who believes the buffer holds everything.
--
-- WHY module_end AND NOT sp_statement_completed.  The question is "what did the predicate cost", and the predicate is a
-- function: sp_statement_completed sees the statement that CONTAINS it, with the predicate's cost folded in and
-- inseparable.  module_end has an object_id and object_name, so the events can be attributed to a named function -- for
-- the scalar functions at least.  For the inline TVFs even this does not work, because an inlined TVF produces no module
-- to end: the session watches auth.uspDemandPermission and auth.udfHasPermission, and the predicates are measured by
-- the difference between a statement against a protected table and the same statement with the policy disabled. That
-- comparison is a manual procedure and it is written out in workbooks/build-and-traceability.xlsx against T-073, not
-- automated here, because disabling a security policy is not something a script in this deployment should ever do.
--
-- DB_ID () CANNOT APPEAR IN AN EVENT-SESSION PREDICATE, so the session is built with dynamic SQL to substitute the
-- literal.  That is the only reason there is dynamic SQL in this file.
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

DECLARE @XeName     SYSNAME        = N'authPermissionProbe'
      , @XeSql      NVARCHAR (MAX) = NULL
      , @CanCreate  BIT            = 0
      , @Exists     BIT            = 0;

-- HAS_PERMS_BY_NAME with three NULLs asks about a server-level permission.  Checked rather than attempted: a failed
-- CREATE EVENT SESSION inside a deployment that is otherwise fine reads as a broken deployment.
SET @CanCreate = CASE WHEN HAS_PERMS_BY_NAME (NULL, NULL, 'ALTER ANY EVENT SESSION') = 1 THEN 1 ELSE 0 END;
SET @Exists    = CASE WHEN EXISTS (SELECT 1 FROM sys.server_event_sessions WHERE name = @XeName) THEN 1 ELSE 0 END;

IF @Exists = 1
BEGIN
    PRINT N'Extended-events session [authPermissionProbe] already exists and was left exactly as it is -- including '
        + N'whether it is running. A deployment does not get to decide that. To see its definition: SELECT * FROM '
        + N'sys.server_event_sessions WHERE name = N''authPermissionProbe'';';
END
ELSE IF @CanCreate = 0
BEGIN
    PRINT N'SKIPPED the extended-events session: this login does not hold the server-level ALTER ANY EVENT SESSION, '
        + N'which a deployment that is only db_owner in one database normally should not. Everything else in this file '
        + N'installed. Section 8 of database/175_perf_instrumentation.sql carries the CREATE EVENT SESSION statement '
        + N'for a DBA to run by hand; the deployment is complete and supported without it, and logs.PermissionProbe '
        + N'plus logs.vwPredicateFunctionStats are unaffected.';
END
ELSE
BEGIN
    SET @XeSql =
        N'CREATE EVENT SESSION [' + @XeName + N'] ON SERVER' + NCHAR (13) + NCHAR (10)
      + N'ADD EVENT sqlserver.module_end ('                  + NCHAR (13) + NCHAR (10)
      + N'    SET collect_statement = (0)'                   + NCHAR (13) + NCHAR (10)
      + N'    ACTION (sqlserver.database_name, sqlserver.session_id, sqlserver.username'
      + N', sqlserver.plan_handle, sqlserver.sql_text)'      + NCHAR (13) + NCHAR (10)
      + N'    WHERE (sqlserver.database_id = ' + CAST (DB_ID () AS NVARCHAR (11))
      + N'           AND (object_name = N''uspDemandPermission''' + NCHAR (13) + NCHAR (10)
      + N'                OR object_name = N''udfHasPermission'''  + NCHAR (13) + NCHAR (10)
      + N'                OR object_name = N''udfResolveAuthPolicy''))'     + NCHAR (13) + NCHAR (10)
      + N')'                                                + NCHAR (13) + NCHAR (10)
      + N'ADD TARGET package0.ring_buffer (SET max_memory = (8192), max_events_limit = (10000))' + NCHAR (13) + NCHAR (10)
      + N'WITH (MAX_MEMORY = 8192 KB'                        + NCHAR (13) + NCHAR (10)
      + N'    , EVENT_RETENTION_MODE = ALLOW_SINGLE_EVENT_LOSS'  + NCHAR (13) + NCHAR (10)
      + N'    , MAX_DISPATCH_LATENCY = 5 SECONDS'            + NCHAR (13) + NCHAR (10)
      + N'    , TRACK_CAUSALITY = ON'                        + NCHAR (13) + NCHAR (10)
      + N'    , STARTUP_STATE = OFF);';

    EXEC sys.sp_executesql @XeSql;

    PRINT N'Created extended-events session [authPermissionProbe], STOPPED, STARTUP_STATE = OFF, ring buffer, 10000 '
        + N'events, single-event loss allowed. It watches auth.uspDemandPermission, auth.udfHasPermission and '
        + N'auth.udfResolveAuthPolicy in this database only, and collects no statement text on the event itself. To '
        + N'use it:   ALTER EVENT SESSION [authPermissionProbe] ON SERVER STATE = START;   run the workload;   read '
        + N'sys.dm_xe_session_targets;   then STATE = STOP. Leave it stopped. module_end on this path fires millions '
        + N'of times an hour and the buffer WILL drop events -- that is correct for sampling a distribution and wrong '
        + N'for anybody who believes the buffer holds everything.';
END
GO


-- *** 9. Descriptions ***
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

    -- Rows rather than EXEC calls with concatenated arguments, because an EXEC argument takes a constant or a variable
    -- and never an expression -- a '+' in the parameter position is a parse error (102).
    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    VALUES
      (N'logs', N'TABLE', N'PermissionProbe', NULL
     , N'One row per SAMPLED call to auth.uspDemandPermission: what was decided, how long a BURST of that decision took, '
     + N'and how many auth.ProfilePermissionScope rows the profile held while it was being decided. Section 10.6, gap '
     + N'G-22, decision D-07. The predicate FUNCTIONS cannot write to a table and a schema-bound one must not try, so '
     + N'this is a caller-side measurement and the only kind available. A BURST and not a single call because '
     + N'SYSUTCDATETIME () has about a millisecond of real resolution while a decision costs microseconds -- timing one '
     + N'call yields 0 or 1000 and nothing between. Append-only (E-50010); the sample rate is '
     + N'Perf.PermissionProbeSampleRate and ships as 0, so an untuned deployment has an empty table here and that is '
     + N'correct.')
    , (N'logs', N'TABLE', N'PermissionProbe', N'MicrosecondsPerCall'
     , N'TotalMicroseconds / BurstCount, computed and not stored, because two columns that must agree are two columns '
     + N'that eventually do not. A WARM-CACHE figure: the first decision of a burst may fetch a page and the other '
     + N'twenty-four do not, so this is systematically optimistic about a cold cache. That is the right figure for '
     + N'section 10.6''s claim that both tables stay in cache, and the wrong one for "what does the first query after a '
     + N'failover cost".')
    , (N'logs', N'TABLE', N'PermissionProbe', N'ScopeRowsForProfile'
     , N'How many live auth.ProfilePermissionScope rows the measured profile held. The independent variable: section '
     + N'10.6 states the design''s cost estimate as "profiles x permissions granted", so a timing without this number '
     + N'is a number nobody can extrapolate from. NULL means NOT MEASURED and not zero -- logs.uspReportPermissionProbe '
     + N'excludes NULLs from the correlation and reports how many rows measured it.')
    , (N'logs', N'TABLE', N'PermissionProbe', N'ProbeContext'
     , N'A short caller-supplied label -- ''nav'', ''caseRead'', ''benchmark T-070'' -- and the only thing on the row '
     + N'about the caller. UI-16: the readers of this table are whoever is chasing a slow query, a wider audience than '
     + N'the one entitled to know what the application was doing at the time. No statement text, no parameters, no '
     + N'business object name.')
    , (N'logs', N'PROCEDURE', N'uspRecordPermissionProbe', NULL
     , N'Records one row in logs.PermissionProbe. Section 10.6, G-22, D-07. THE CALLER DOES THE TIMING: the burst has to '
     + N'happen around the decision the caller is already making, and moving the loop in here would put a measurement '
     + N'procedure in the authorization call graph. Fully instrumented (rule 8) -- whose secondary use is that comparing '
     + N'this procedure''s own ElapsedMilliseconds to the MicrosecondsPerCall it recorded tells you whether the observer '
     + N'is bigger than the thing observed. It is, by about two orders of magnitude, which is why the probe is sampled. '
     + N'Raises 50190 empty code, 50191 burst outside 2-10000, 50192 negative elapsed, 50193 malformed DetailJson. Not '
     + N'granted to applicationRole: a table the application can write arbitrary rows into cannot support a design '
     + N'decision.')
    , (N'logs', N'PROCEDURE', N'uspPurgePermissionProbe', NULL
     , N'Expires logs.PermissionProbe rows older than Perf.PermissionProbeRetentionDays in bounded batches. A SOFT '
     + N'delete: nothing in this database hard-deletes, so it reclaims no space and says so in its own Comments. This is '
     + N'the one table where a DBA removing already-expired rows by hand is supported. Each batch is its own '
     + N'transaction, so a killed purge has committed what it reported and is resumable -- the one place here where a '
     + N'loop of commits beats one atomic statement, because "older than fourteen days" is not an atomic set. '
     + N'@RetentionDays = 0 is REFUSED (E-50194) rather than read as "expire everything", because a zero in a retention '
     + N'parameter is an unset variable far more often than an instruction; -1 means everything and nobody types it by '
     + N'accident. Raises 50194, 50195.')
    , (N'logs', N'PROCEDURE', N'uspReportPermissionProbe', NULL
     , N'Three result sets from logs.PermissionProbe: the headline distribution, the same per permission code, and a '
     + N'DATE_BUCKET time series. Tasks T-070 and T-074; the second set is what decision D-07 is taken on. Reports '
     + N'PERCENTILES and not a mean, because the way a predicate fails is by being cheap almost always and catastrophic '
     + N'occasionally, which a mean hides and a 99th shows. Uses APPROX_PERCENTILE_CONT, a SQL Server 2022 aggregate '
     + N'whose 1.33% rank error is far smaller than the measurement is noisy. Joins nothing: a report that joined '
     + N'auth.Permission to prettify the output would break for exactly the probes most worth reading. Raises 50196.')
    , (N'logs', N'VIEW', N'vwPredicateFunctionStats', NULL
     , N'sys.dm_exec_function_stats for the six functions the security design depends on, one row each whether or not the '
     + N'server has a number. Every row comes from a VALUES constructor and is LEFT JOINed, never selected from the DMV: '
     + N'MEASURED on this instance, an inlined scalar function vanishes from that DMV entirely and an inline '
     + N'table-valued function was never in it, so a view built on the DMV alone would omit five of the six and read as '
     + N'"never called". StatsNote says which of the three reasons a row has no numbers. The totals are cumulative since '
     + N'CachedSinceUtc and are lost on a restart, an ALTER, a recompile or a DBCC FREEPROCCACHE -- read the age, not '
     + N'just the count. Needs VIEW SERVER PERFORMANCE STATE; without it every row reads as "not called".');

    -- Assertion 11: the key and audit columns the list above left undescribed, found by 950_verify_deployment.sql,
    -- which fails a column without an MS_Description.
    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    VALUES
      (N'logs', N'TABLE', N'PermissionProbe', N'PermissionProbeId', N'Surrogate key.')
    , (N'logs', N'TABLE', N'PermissionProbe', N'OccurredUtc', N'When the burst was measured, UTC.')
    , (N'logs', N'TABLE', N'PermissionProbe', N'BurstCount', N'How many permission decisions the burst made. MicrosecondsPerCall divides by it.')
    , (N'logs', N'TABLE', N'PermissionProbe', N'TotalMicroseconds', N'Wall-clock time the whole burst took, measured by the caller.')
    , (N'logs', N'TABLE', N'PermissionProbe', N'PermissionCode', N'The permission code decided. A string, not a foreign key: a probe of a code that does not exist is worth keeping.')
    , (N'logs', N'TABLE', N'PermissionProbe', N'TenantId', N'The tenant the decision was made at. NULL when the caller did not say.')
    , (N'logs', N'TABLE', N'PermissionProbe', N'UserProfileId', N'The profile the decision was made for. NULL when the caller did not say.')
    , (N'logs', N'TABLE', N'PermissionProbe', N'Allowed', N'The answer the burst returned: 1 allowed, 0 refused.')
    , (N'logs', N'TABLE', N'PermissionProbe', N'ClosureRowsForTenant', N'auth.TenantClosure rows for the tenant: the second independent variable. NULL means not measured, not zero.')
    , (N'logs', N'TABLE', N'PermissionProbe', N'DetailJson', N'Optional flat JSON of further measurement facts. Never an identifier of the caller beyond the columns above.');

    -- The audit block carries the same description on every table, so it is generated rather than typed out.
    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    SELECT t.SchemaName, N'TABLE', t.TableName, c.ColumnName, c.Description
      FROM (VALUES (N'logs', N'PermissionProbe')) AS t (SchemaName, TableName)
     CROSS JOIN (VALUES
          (N'IsDeleted',            N'Soft-delete flag. 1 means the row is gone as far as the application is concerned; nothing in this database hard-deletes.')
        , (N'auditDeletedBy',       N'Who soft-deleted the row. NULL unless IsDeleted = 1 -- the pair is enforced by CK_<table>_DeletedPair.')
        , (N'auditDeletedDateUtc',  N'When the row was soft-deleted, UTC. NULL unless IsDeleted = 1.')
        , (N'auditCreatedBy',       N'Who inserted the row. Defaults to ORIGINAL_LOGIN (); a procedure sets it to the acting profile instead.')
        , (N'auditCreatedDateUtc',  N'When the row was inserted, UTC.')
        , (N'auditModifiedBy',      N'Who last updated the row, set by the AFTER UPDATE trigger from SESSION_CONTEXT (''AppUser'') or ORIGINAL_LOGIN ().')
        , (N'auditModifiedDateUtc', N'When the row was last updated, UTC, set by the AFTER UPDATE trigger.')
       ) AS c (ColumnName, Description)
     WHERE NOT EXISTS (SELECT 1 FROM @Descriptions AS d
                        WHERE d.SchemaName = t.SchemaName AND d.ObjectName = t.TableName AND d.ColumnName = c.ColumnName);

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


-- *** 10. Grants ***
-- The three procedures get NOTHING, for the reason 165_logs_procedures.sql sets out in full: ownership chaining covers a
-- nested EXEC across schemas when the schemas share an owner, and auth, config, dbo, logs and util are all owned by dbo
-- here -- measured on this instance.  So auth.uspDemandPermission reaches the recorder with no grant, and nothing else
-- can reach it at all.  The specific harm the withheld grant prevents is narrower than for the audit trails and still
-- real: decision D-07 is taken on the contents of logs.PermissionProbe, and an application login that could write rows
-- there could make the predicate look however it wanted it to look.
--
-- THE VIEW IS A DIFFERENT CASE AND IT GETS A GRANT.  logsAuditReader is the role for principals whose job is reading
-- what the database recorded about itself, and a DBA chasing a slow query is exactly that reader.  The view exposes no
-- business data and no identity: six function names and the server's own counters.  It still needs VIEW SERVER
-- PERFORMANCE STATE at the server level, which this script cannot grant and does not pretend to -- a member of
-- logsAuditReader without it sees six rows of NULLs, which is the one misreading this view can produce.
IF DATABASE_PRINCIPAL_ID (N'logsAuditReader') IS NOT NULL
BEGIN
    GRANT SELECT ON logs.vwPredicateFunctionStats TO logsAuditReader;
    PRINT N'Granted SELECT on logs.vwPredicateFunctionStats to logsAuditReader. The server-level VIEW SERVER '
        + N'PERFORMANCE STATE is a separate grant this script cannot make; without it the view returns six rows of '
        + N'NULLs that read as "never called".';
END
ELSE
BEGIN
    PRINT N'Role logsAuditReader does not exist, so no grant was made on logs.vwPredicateFunctionStats. Run '
        + N'005_schemas_and_roles.sql. The three procedures in this file are granted to nobody by design.';
END
GO

-- Also granted to logsAuditReader: reading the probe table itself is already covered by the schema-level SELECT on logs
-- that scripts/permissions.sql gives that role, so there is deliberately no object-level grant here -- an object grant
-- alongside a schema grant is a second place to look when somebody cannot read a table.
PRINT N'No grants on logs.PermissionProbe: logsAuditReader already holds SELECT on the logs schema (permissions.sql), '
    + N'and an object-level grant beside a schema-level one is just a second place to look when a read is refused.';
GO


-- *** 11. Closing report ***
DECLARE @Report TABLE
(
    RowNo    INT IDENTITY (1, 1) PRIMARY KEY,
    Severity INT             NOT NULL,
    Status   VARCHAR (10)    NOT NULL,
    Item     NVARCHAR (200)  NOT NULL,
    Detail   NVARCHAR (1000)     NULL
);

-- The table, its computed column and its three indexes.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (N'logs.PermissionProbe', N'U') IS NULL THEN 1 ELSE 4 END
     , CASE WHEN OBJECT_ID (N'logs.PermissionProbe', N'U') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Table logs.PermissionProbe'
     , CONCAT (N'Columns: ', (SELECT COUNT (*) FROM sys.columns WHERE object_id = OBJECT_ID (N'logs.PermissionProbe'))
             , N'. Computed columns: '
             , (SELECT COUNT (*) FROM sys.computed_columns WHERE object_id = OBJECT_ID (N'logs.PermissionProbe'))
             , N' (MicrosecondsPerCall, which must be exactly 1 -- storing the division as well as its operands is how '
             + N'the two stop agreeing). CHECK constraints: '
             , (SELECT COUNT (*) FROM sys.check_constraints WHERE parent_object_id = OBJECT_ID (N'logs.PermissionProbe'))
             , N'. Filtered indexes: '
             , (SELECT COUNT (*) FROM sys.indexes
                 WHERE object_id = OBJECT_ID (N'logs.PermissionProbe') AND has_filter = 1)
             , N' of 3 expected, all on IsDeleted = 0 so the purge hides rows from every read at once.');

-- The append-only trigger.  sys.triggers keys on parent_id, NOT parent_object_id -- the column name differs from
-- sys.objects and getting it wrong yields an empty result that reads as a missing trigger.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN EXISTS (SELECT 1 FROM sys.triggers
                          WHERE parent_id = OBJECT_ID (N'logs.PermissionProbe')
                            AND name = N'trg_au_updt_PermissionProbe'
                            AND is_disabled = 0) THEN 4 ELSE 1 END
     , CASE WHEN EXISTS (SELECT 1 FROM sys.triggers
                          WHERE parent_id = OBJECT_ID (N'logs.PermissionProbe')
                            AND name = N'trg_au_updt_PermissionProbe'
                            AND is_disabled = 0) THEN 'OK' ELSE 'MISSING' END
     , N'Trigger logs.trg_au_updt_PermissionProbe, enabled'
     , N'The append-only guard, E-50010. Decision D-07 is taken on the contents of this table, so a table anybody can '
     + N'tidy is a decision nobody can audit. Only IsDeleted may change, and logs.uspPurgePermissionProbe is what '
     + N'changes it. A DISABLED trigger here is reported as MISSING on purpose -- it is the same thing.';

-- The three procedures and the view.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (x.ObjName) IS NULL THEN 1 ELSE 4 END
     , CASE WHEN OBJECT_ID (x.ObjName) IS NULL THEN 'MISSING' ELSE 'OK' END
     , x.Label + N' ' + x.ObjName
     , x.Detail
  FROM (VALUES (N'Procedure', N'logs.uspRecordPermissionProbe'
              , N'Section 10.6, G-22. The caller times the burst; this validates and stores it. Raises 50190 to 50193.')
             , (N'Procedure', N'logs.uspPurgePermissionProbe'
              , N'Batched SOFT expiry against Perf.PermissionProbeRetentionDays. Reclaims no space and says so. Raises 50194, 50195.')
             , (N'Procedure', N'logs.uspReportPermissionProbe'
              , N'Three result sets: headline, by permission, by DATE_BUCKET. Percentiles, never a mean. D-07 is decided on set 2. Raises 50196.')
             , (N'View',      N'logs.vwPredicateFunctionStats'
              , N'Six functions, LEFT JOINed to sys.dm_exec_function_stats, with a StatsNote for each of the three reasons a row can be empty.')) AS x (Label, ObjName, Detail);

-- The three settings, which live in three different files on purpose (BL-050).
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 3 THEN 4 ELSE 2 END
     , CASE WHEN COUNT (*) = 3 THEN 'OK' ELSE 'INCOMPLETE' END
     , N'The three Perf.* settings the probe reads'
     , CONCAT (COUNT (*), N' of 3 present: '
             , STRING_AGG (CONCAT (REPLACE (s.SettingKey, N'Perf.', N''), N'=', s.SettingValue), N', ')
             , N'. SampleRate and RetentionDays are seeded by 115_seed_reference_data.sql and BurstCount by this file -- '
             + N'three files, no overlap, because a setting seeded twice has two defaults and the second script to run '
             + N'wins silently (BL-050).')
  FROM config.ApplicationSetting AS s
 WHERE s.SettingKey IN (N'Perf.PermissionProbeSampleRate', N'Perf.PermissionProbeRetentionDays'
                      , N'Perf.PermissionProbeBurstCount')
   AND s.IsDeleted = 0;

-- Is the probe actually on?  Severity 3 either way: off is the shipped state and correct, on is a decision somebody made.
INSERT @Report (Severity, Status, Item, Detail)
SELECT 3
     , CASE WHEN COALESCE (r.Rate, 0) = 0 THEN 'OFF' ELSE 'SAMPLING' END
     , N'Perf.PermissionProbeSampleRate'
     , CASE WHEN COALESCE (r.Rate, 0) = 0
            THEN N'0 -- the probe is OFF and this is the shipped default. auth.uspDemandPermission reads this setting on '
               + N'every call and does nothing else, which is the probe''s entire cost when off and is measured rather '
               + N'than assumed (see the file header, and T-070 in the build log). Set it to 1000 to sample one call in '
               + N'a thousand; that is the production value. 1 is for a benchmark and will distort its own numbers.'
            ELSE CONCAT (N'One call in ', r.Rate, N' is being timed, with a burst of '
                       , COALESCE (r.Burst, N'25 (default)')
                       , N'. That is roughly ', CAST (r.Burst AS INT), N' extra decisions per ', r.Rate
                       , N' calls. Somebody turned this on deliberately; logs.uspReportPermissionProbe is how to read '
                       + N'the result, and setting it back to 0 is how to stop paying for it.') END
  FROM (SELECT Rate  = TRY_CAST (MAX (CASE WHEN s.SettingKey = N'Perf.PermissionProbeSampleRate'
                                           THEN s.SettingValue END) AS INT)
             , Burst = MAX (CASE WHEN s.SettingKey = N'Perf.PermissionProbeBurstCount' THEN s.SettingValue END)
          FROM config.ApplicationSetting AS s
         WHERE s.IsDeleted = 0) AS r;

-- Whether the caller side is wired up at all.  This is the row that catches "175 ran, 150 did not" and the reverse.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (N'auth.uspDemandPermission', N'P') IS NULL THEN 3
            WHEN EXISTS (SELECT 1 FROM sys.sql_modules
                          WHERE object_id = OBJECT_ID (N'auth.uspDemandPermission')
                            AND definition LIKE N'%uspRecordPermissionProbe%') THEN 4
            ELSE 2 END
     , CASE WHEN OBJECT_ID (N'auth.uspDemandPermission', N'P') IS NULL THEN 'ABSENT'
            WHEN EXISTS (SELECT 1 FROM sys.sql_modules
                          WHERE object_id = OBJECT_ID (N'auth.uspDemandPermission')
                            AND definition LIKE N'%uspRecordPermissionProbe%') THEN 'OK'
            ELSE 'NOT WIRED' END
     , N'auth.uspDemandPermission calls the recorder'
     , CASE WHEN OBJECT_ID (N'auth.uspDemandPermission', N'P') IS NULL
            THEN N'auth.uspDemandPermission does not exist yet, so there is nothing to wire. Run '
               + N'150_auth_query_procedures.sql. Everything in this file installed and is inert until then, which is '
               + N'a supported state: the dependency runs from 150 to here and is a runtime OBJECT_ID guard, not an '
               + N'install-time assertion. See the file header.'
            WHEN EXISTS (SELECT 1 FROM sys.sql_modules
                          WHERE object_id = OBJECT_ID (N'auth.uspDemandPermission')
                            AND definition LIKE N'%uspRecordPermissionProbe%')
            THEN N'The sampled probe block is present in the stored definition of auth.uspDemandPermission. Checked '
               + N'against sys.sql_modules rather than asserted in a comment, because the one way this stops working '
               + N'silently is somebody editing 150 and dropping the block.'
            ELSE N'auth.uspDemandPermission EXISTS BUT DOES NOT CALL logs.uspRecordPermissionProbe, so nothing will '
               + N'ever be sampled whatever the sample rate says. Either 150_auth_query_procedures.sql predates the '
               + N'probe and needs re-running, or somebody removed the block marked "-- 1b. The sampled probe" -- '
               + N'which is a documented and supported thing to do, but it should be done knowing that the Phase 5 '
               + N'measurement and decision D-07 lose their only source of production numbers.' END;

-- What has accumulated.  Both halves matter: the live count is what the report reads, and the expired count is the dead
-- weight the soft delete leaves behind and nothing in the procedure layer will ever reclaim.
--
-- Two things here are deliberately not written the obvious way.  COUNT over an empty table returns 0 but SUM returns
-- NULL, and CONCAT renders NULL as an empty string rather than propagating it -- so the naive version of this row reads
-- "  live,   expired" on a freshly deployed database, which is how a count of zero disguises itself as a broken query.
-- Hence COALESCE around each total.  And the oldest-sample sentence is a CASE on the aggregate, not a COALESCE around
-- CONCAT: CONCAT never returns NULL, so a COALESCE wrapped round it can never fire and the "No live samples." branch
-- would be dead code that looks like it works.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COALESCE (SUM (CASE WHEN p.IsDeleted = 1 THEN 1 ELSE 0 END), 0) > 1000000 THEN 3 ELSE 4 END
     , 'INFO'
     , N'Rows in logs.PermissionProbe'
     , CONCAT (COALESCE (SUM (CASE WHEN p.IsDeleted = 0 THEN 1 ELSE 0 END), 0), N' live, '
             , COALESCE (SUM (CASE WHEN p.IsDeleted = 1 THEN 1 ELSE 0 END), 0)
             , N' expired. Expired rows still occupy their pages: the purge is a soft delete because nothing in this '
             + N'database hard-deletes, and this is the one table where a DBA removing expired rows by hand is '
             + N'supported. '
             , CASE WHEN MIN (CASE WHEN p.IsDeleted = 0 THEN p.OccurredUtc END) IS NULL
                    THEN N'No live samples, which is the shipped state: nothing writes here until '
                       + N'Perf.PermissionProbeSampleRate is non-zero.'
                    ELSE CONCAT (N'Oldest live sample: '
                               , MIN (CASE WHEN p.IsDeleted = 0 THEN p.OccurredUtc END), N'.') END)
  FROM logs.PermissionProbe AS p;

-- The view, exercised rather than merely counted: a LEFT JOIN to a DMV either returns its six rows or it does not, and
-- a view that parses and fails on execution is the failure mode a catalog check cannot see.
BEGIN TRY
    DECLARE @ViewRows INT
          , @WithStats INT;

    SELECT @ViewRows  = COUNT (*)
         , @WithStats = COUNT (v.ExecutionCount)
      FROM logs.vwPredicateFunctionStats AS v;

    INSERT @Report (Severity, Status, Item, Detail)
    VALUES (CASE WHEN @ViewRows = 6 THEN 4 ELSE 2 END
          , CASE WHEN @ViewRows = 6 THEN 'OK' ELSE 'WRONG' END
          , N'logs.vwPredicateFunctionStats returns its six rows'
          , CONCAT (@ViewRows, N' row(s), of which ', @WithStats, N' carry statistics. Six is correct and is a literal '
                  + N'list, not a count of what the DMV happened to hold. '
                  , CASE WHEN @WithStats = 0
                         THEN N'NONE carry statistics, which on a freshly deployed database is expected -- four of the '
                            + N'six are inline table-valued functions the DMV structurally cannot see, and the other '
                            + N'two have not been called. Read each row''s StatsNote.'
                         ELSE N'Read each row''s StatsNote before drawing a conclusion from a small number: an '
                            + N'inlined scalar function is not counted at all.' END));
END TRY
BEGIN CATCH
    INSERT @Report (Severity, Status, Item, Detail)
    VALUES (2, 'FAILED', N'logs.vwPredicateFunctionStats returns its six rows'
          , CONCAT (N'Selecting from the view raised: ', LEFT (ERROR_MESSAGE (), 700)
                  , N' -- if this is error 297 or 300 the runner lacks VIEW SERVER PERFORMANCE STATE, which is a '
                  + N'server-level grant this script cannot make and the view documents.'));
END CATCH;

-- The event session, and the honest three-way answer.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN es.name IS NULL THEN 3 ELSE 4 END
     , CASE WHEN es.name IS NULL THEN 'ABSENT'
            WHEN rs.name IS NOT NULL THEN 'RUNNING'
            ELSE 'STOPPED' END
     , N'Extended-events session [authPermissionProbe]'
     , CASE WHEN es.name IS NULL
            THEN N'Not created. Either this login lacks the server-level ALTER ANY EVENT SESSION -- normal for a '
               + N'deployment that is only db_owner in one database -- or section 8 was skipped. The deployment is '
               + N'complete and supported without it; logs.PermissionProbe and logs.vwPredicateFunctionStats are the '
               + N'other two thirds of the measurement and neither needs it. The CREATE statement is in section 8 for '
               + N'a DBA to run by hand.'
            WHEN rs.name IS NOT NULL
            THEN N'IT IS RUNNING RIGHT NOW. module_end on this path fires millions of times an hour. If you did not '
               + N'start it deliberately in the last few minutes, stop it: ALTER EVENT SESSION [authPermissionProbe] '
               + N'ON SERVER STATE = STOP;'
            ELSE N'Created, stopped, STARTUP_STATE = OFF, which is the intended resting state. Start it, run the '
               + N'workload, read sys.dm_xe_session_targets, stop it again. It watches auth.uspDemandPermission, '
               + N'auth.udfHasPermission and auth.udfResolveAuthPolicy in this database only. The inline TVF '
               + N'predicates produce no module to end and are therefore invisible to it -- T-073 in the build log '
               + N'records the manual comparison that measures those.' END
  FROM (SELECT 1 AS One) AS anchor
  LEFT JOIN sys.server_event_sessions AS es ON es.name = N'authPermissionProbe'
  LEFT JOIN sys.dm_xe_sessions        AS rs ON rs.name = N'authPermissionProbe';

IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
    PRINT '175_perf_instrumentation.sql: PROBLEMS found. See the report below.';
ELSE
    PRINT '175_perf_instrumentation.sql: no problems found.';

SELECT Severity, Status, Item, Detail FROM @Report ORDER BY Severity, RowNo;
GO

