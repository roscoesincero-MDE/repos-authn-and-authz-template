/***********************************************************************************************************************
Script:         _tests/010_phase0_instrumentation.sql
Purpose:        The Phase 0 exit criterion that no installer can satisfy on its own: "logs.ExecutionLog exists and an
                instrumented test procedure writes to it".  Builds one plain table and one fully instrumented procedure
                exactly as the conventions require, exercises all three instrumentation paths, and reports on what
                actually landed in logs.ExecutionLog.
Target:         SQL Server 2022 or newer.
Run as:         db_owner in the target database.
Run in:         The target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/_tests/010_phase0_instrumentation.sql
Idempotent:     Yes.  The table is guarded, the trigger and procedure are CREATE OR ALTER, the probe's own work is a
                MERGE, and the report reads rather than asserts by row count.  A second run changes the probe counters
                and nothing else.
Depends on:     The whole Phase 0 install, in order: 000_prerequisites.sql, 005_schemas_and_roles.sql,
                templates/extended-properties.sql, scripts/logdBChanges.sql, scripts/logExecutionLogging.sql,
                scripts/permissions.sql.  database/Install-TemplateDatabase.ps1 runs them.
Implements:     PLAN-AUTH-001 Phase 0 exit criteria.  Tasks T-005 and T-007.
To retarget:    Pass it per run:  -d <database> -v DbName=<database>.  There is no in-file default.

WHY THIS FILE IS NOT IN THE INSTALL MANIFEST
--------------------------------------------
It is a test, and its objects are test fixtures.  Install-TemplateDatabase.ps1 deploys a template that a project team
clones; util.Phase0ProbeTarget has no business meaning and no place in a database that team then puts data in.  So it
lives under database/_tests/, is run by hand against a development database, and is named in the runner's closing notes
rather than in its manifest.

WHAT IT PROVES, AND WHY EACH PART IS NEEDED
-------------------------------------------
The four installers each end with a report on their own objects, which is how Phase 0 knows they deployed.  None of
them proves the thing the conventions actually promise: that a procedure written to rule 8 records what happened to it.
Three paths have to be walked separately, because they are three different mechanisms and only the first is obvious:

  1.  SUCCESS.  A start row is opened before the transaction and completed after the commit, with Successful = 1,
      EndDateUtc and ElapsedMilliseconds set.  If the completion UPDATE is wrong, the monitoring grid reads every call
      in the database as still running.

  2.  FAILURE WITH NO AMBIENT TRANSACTION.  The start row was written in autocommit, so the procedure's own ROLLBACK
      cannot reach it.  The CATCH finds it present and logs.uspRecordExecutionErrorUpdate takes its MATCHED branch,
      updating the existing row.  ReCreatedAfterRollback stays 0.

  3.  FAILURE INSIDE A CALLER'S TRANSACTION.  ROLLBACK unwinds the OUTERMOST transaction, so it destroys the start row
      this procedure wrote.  The CATCH's existence check misses, the row is re-created with the ORIGINAL @StartTimeUtc,
      and ReCreatedAfterRollback = 1 records the fact.  This is the path that exists only because somebody measured
      it; it is invisible from reading the template, and it is the one an untested instrumentation block gets wrong.

      It also leaves a PERMANENT GAP in ExecutionLogId, because IDENTITY allocation is not transactional and the
      destroyed row's number is never returned.  The report states the arithmetic, since a gap reads like a lost
      execution and is not one -- the execution is the next row, flagged ReCreatedAfterRollback = 1.

Path 3 is also the reason the probe takes @ForceFailure rather than being made to fail by bad input: the failure has to
happen AFTER the start row is written and INSIDE the transaction, which is not where a validation refusal happens.

WHAT IT DELIBERATELY DOES NOT DO
--------------------------------
It does not drop anything, including itself.  Soft delete only is not a rule about business data (conventions
non-negotiable 3), and a test that cleans up after itself by dropping its fixtures is a script that has DROP TABLE in
it.  Re-running this file is the supported way to re-run the test; util.Phase0ProbeTarget staying behind on a
development database is the intended outcome, and the probe rows say so in their own description.
***********************************************************************************************************************/

:on error exit

SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;
GO


-- *** 0. Assert the target ***
IF DB_NAME () <> N'$(DbName)'
BEGIN
    DECLARE @Mismatch NVARCHAR (2000) =
        N'Target mismatch. Connected to [' + DB_NAME () + N'] but this file is configured for [$(DbName)]. '
      + N'Either connect with  -d $(DbName)  or override the file with  -v DbName=' + DB_NAME ()
      + N'. Nothing has been changed.';

    THROW 50000, @Mismatch, 1;
END
GO


-- *** 1. Assert the machinery this test is testing ***
-- Without this block the failure arrives as "invalid object name" three hundred lines down, which reads as a defect in
-- the test rather than as an installer that was never run.
DECLARE @Absent NVARCHAR (2000) = NULL;

SELECT @Absent = STRING_AGG (x.ObjectName, N', ')
  FROM (VALUES (N'util.uspSetObjectDescription')
             , (N'logs.ExecutionLog')
             , (N'logs.uspStartExecutionLogging')
             , (N'logs.uspRecordExecutionError')) AS x (ObjectName)
 WHERE OBJECT_ID (x.ObjectName) IS NULL;

IF @Absent IS NOT NULL
BEGIN
    DECLARE @NotInstalled NVARCHAR (2000) =
        N'The conventions machinery this test exercises is not installed. Absent: ' + @Absent
      + N'. Run database/Install-TemplateDatabase.ps1 first. Nothing has been changed.';

    THROW 50000, @NotInstalled, 1;
END
GO


-- *** 2. The probe target ***
-- A plain table, built to the conventions the same way any table in this database is: seven audit columns, DF_ names
-- carrying this schema and this table, a natural key filtered on IsDeleted = 0, and an AFTER UPDATE trigger.  It is a
-- fixture, but a fixture built to a weaker standard would not exercise the machinery the real tables use.
IF OBJECT_ID (N'util.Phase0ProbeTarget', N'U') IS NULL
BEGIN
    CREATE TABLE util.Phase0ProbeTarget
    (
        Phase0ProbeTargetId  INT             IDENTITY (1, 1) NOT NULL,
        ProbeName            NVARCHAR (100)  NOT NULL,
        ProbeCount           INT             NOT NULL,
        LastProbedDateUtc    DATETIME2 (3)   NOT NULL,

        IsDeleted            BIT             NOT NULL CONSTRAINT DF_util_Phase0ProbeTarget_IsDeleted            DEFAULT (0),
        auditDeletedBy       NVARCHAR (255)  NOT NULL CONSTRAINT DF_util_Phase0ProbeTarget_auditDeletedBy       DEFAULT (ORIGINAL_LOGIN ()),
        auditDeletedDateUtc  DATETIME2 (3)   NOT NULL CONSTRAINT DF_util_Phase0ProbeTarget_auditDeletedDateUtc  DEFAULT (SYSUTCDATETIME ()),
        auditCreatedBy       NVARCHAR (255)  NOT NULL CONSTRAINT DF_util_Phase0ProbeTarget_auditCreatedBy       DEFAULT (ORIGINAL_LOGIN ()),
        auditCreatedDateUtc  DATETIME2 (3)   NOT NULL CONSTRAINT DF_util_Phase0ProbeTarget_auditCreatedDateUtc  DEFAULT (SYSUTCDATETIME ()),
        auditModifiedBy      NVARCHAR (255)  NOT NULL CONSTRAINT DF_util_Phase0ProbeTarget_auditModifiedBy      DEFAULT (ORIGINAL_LOGIN ()),
        auditModifiedDateUtc DATETIME2 (3)   NOT NULL CONSTRAINT DF_util_Phase0ProbeTarget_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ()),

        CONSTRAINT PK_util_Phase0ProbeTarget            PRIMARY KEY CLUSTERED (Phase0ProbeTargetId),
        CONSTRAINT CK_util_Phase0ProbeTarget_ProbeCount CHECK (ProbeCount >= 0)
    );
END;
GO

IF NOT EXISTS (SELECT 1
                 FROM sys.indexes
                WHERE name      = N'UX_util_Phase0ProbeTarget_ProbeName'
                  AND object_id = OBJECT_ID (N'util.Phase0ProbeTarget'))
BEGIN
    CREATE UNIQUE INDEX UX_util_Phase0ProbeTarget_ProbeName
        ON util.Phase0ProbeTarget (ProbeName)
        WHERE IsDeleted = 0;
END;
GO


-- *** 3. The audit trigger ***
-- Not optional on a plain table, and the finding this test is downstream of: F-01 in PLAN-AUTH-001 section 7 is exactly
-- this trigger missing from dbo.CaseFile and dbo.CaseNote.  A fixture table without one would be the same defect in the
-- file that exists to catch it.
/***********************************************************************************************************************
ObjectName:   util.trg_au_updt_Phase0ProbeTarget
Author:       Opus 5
CreateDate:   2026-09-19
========================================================================================================================
Description:

Owns the modification and soft-delete audit columns on util.Phase0ProbeTarget.  Recomputes auditModifiedDateUtc on every
update and stamps auditDeletedBy / auditDeletedDateUtc when IsDeleted transitions 0 -> 1.

========================================================================================================================
Requirements and Key Dependencies:

util.Phase0ProbeTarget and its PRIMARY KEY.  No grant of its own -- a trigger runs in the caller's security context.

========================================================================================================================
Notes:

Copied from templates/table.sql section 4 with only the schema, table and key column changed, which is the point: if the
template's trigger does not work, it does not work here either, and this file runs.

The 0 -> 1 test is on both images because there is no view filtering IsDeleted = 0 in front of a plain table, so an
already-deleted row can be updated again and testing the after-image alone would move the delete forward in time.

TRIGGER_NESTLEVEL rather than trusting RECURSIVE_TRIGGERS to stay OFF: it is a database option somebody else can turn
on, and the failure if they do is an infinite loop rather than a wrong value.

========================================================================================================================
Example Usage and Performance:

update util.Phase0ProbeTarget set ProbeCount = ProbeCount + 1 where ProbeName = N'Phase0.Success';

Set-based; one extra UPDATE per statement regardless of row count.

========================================================================================================================
Modification History:

Date:		2026-09-19
Author:		Opus 5
Ticket:		T-005
Description:

Created with the file.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER TRIGGER util.trg_au_updt_Phase0ProbeTarget
ON util.Phase0ProbeTarget
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;

    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    DECLARE @Now   DATETIME2 (3)  = SYSUTCDATETIME (),
            @Actor NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N''), ORIGINAL_LOGIN ());

    UPDATE t
       SET t.auditModifiedDateUtc = @Now,

           t.auditModifiedBy = CASE WHEN UPDATE (auditModifiedBy)
                                    THEN COALESCE (NULLIF (i.auditModifiedBy, N''), @Actor)
                                    ELSE @Actor
                               END,

           t.auditDeletedBy      = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Actor ELSE t.auditDeletedBy      END,
           t.auditDeletedDateUtc = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Now   ELSE t.auditDeletedDateUtc END
      FROM util.Phase0ProbeTarget AS t
      JOIN inserted               AS i ON i.Phase0ProbeTargetId = t.Phase0ProbeTargetId
      JOIN deleted                AS d ON d.Phase0ProbeTargetId = t.Phase0ProbeTargetId;
END;
GO


-- *** 4. The instrumented probe ***
/***********************************************************************************************************************
ObjectName:   util.uspPhase0Probe
Author:       Opus 5
CreateDate:   2026-09-19
========================================================================================================================
Description:

A fully instrumented write procedure whose only purpose is to be instrumented.  Increments a counter on
util.Phase0ProbeTarget, and fails on purpose when @ForceFailure = 1 so the CATCH path can be exercised.

========================================================================================================================
Requirements and Key Dependencies:

util.Phase0ProbeTarget.

logs.uspStartExecutionLogging and logs.uspRecordExecutionError, plus logs.ExecutionLog itself, which the completion
UPDATE below writes directly.  All three are installed by scripts/logExecutionLogging.sql.

========================================================================================================================
Notes:

THE INSTRUMENTATION BLOCK IS COPIED VERBATIM FROM templates/procedure.sql, and that is the whole point of this
procedure.  Only the parameter list, @KeyParameters, the work between the two ===== banners, and @Comments differ from
the template.  If the template's block is wrong, this file is where it shows.

@ForceFailure THROWS INSIDE THE TRANSACTION, AFTER THE MERGE, and that placement is deliberate.  A validation refusal
would throw before BEGIN TRANSACTION, where the procedure owns nothing and the start row is not at risk -- which is
precisely the path that does NOT exercise the re-creation block.  Error 50099 is used so the bare ;THROW; can be checked
to have preserved the original number rather than replacing it with 50000, which is what RAISERROR would have done.

auditCreatedBy IS SET EXPLICITLY ON INSERT, not left to its DEFAULT.  This is finding F-02 of PLAN-AUTH-001 section 7:
DEFAULT (ORIGINAL_LOGIN ()) records the pooled application login on every row, and the AFTER UPDATE trigger resolves
SESSION_CONTEXT ('AppUser') on update but there is no equivalent on insert -- so the procedure has to do it.  Every
write procedure in this design carries this line; the probe carries it too so the pattern is demonstrated somewhere
that runs.

THE PROBE IS IDEMPOTENT IN THE SENSE THAT MATTERS: a second run merges rather than inserting, so it converges on shape
even though ProbeCount deliberately does not converge on value.  A counter that did not move would not show that the
write happened.

========================================================================================================================
Example Usage and Performance:

exec util.uspPhase0Probe @ProbeName = N'Phase0.Success';
exec util.uspPhase0Probe @ProbeName = N'Phase0.Failure', @ForceFailure = 1;   -- raises 50099

Singleton MERGE seeking UX_util_Phase0ProbeTarget_ProbeName.  Instrumentation adds one singleton insert on every call
and one singleton update on the successful path.

========================================================================================================================
Modification History:

Date:		2026-09-19
Author:		Opus 5
Ticket:		T-005
Description:

Created with the file.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE util.uspPhase0Probe
      @ProbeName    NVARCHAR (100)
    , @ForceFailure BIT = 0
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
                                                    , N'[util].[uspPhase0Probe]')
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

    -- Identifiers and counts ONLY.
    SET @KeyParameters = CONCAT (N'ProbeName=',       @ProbeName
                               , N', ForceFailure=', @ForceFailure);

    BEGIN TRY

        EXEC logs.uspStartExecutionLogging
              @ProcedureName          = @ProcName
            , @KeyParameters          = @KeyParameters
            , @StartDateUtc           = @StartTimeUtc
            , @ReCreatedAfterRollback = 0
            , @ExecutionLogId         = @ExecutionId OUTPUT;

        BEGIN TRANSACTION;

        -- =========================================================================================
        -- ===== The procedure's own work starts here. Everything above and below is boilerplate. ==
        -- =========================================================================================

        DECLARE @Now   DATETIME2 (3)  = SYSUTCDATETIME ()
              , @Actor NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                                , ORIGINAL_LOGIN ());

        MERGE util.Phase0ProbeTarget AS tgt
        USING (SELECT @ProbeName AS ProbeName) AS src
           ON src.ProbeName = tgt.ProbeName
          AND tgt.IsDeleted = 0
        WHEN MATCHED
        THEN UPDATE SET tgt.ProbeCount        = tgt.ProbeCount + 1
                      , tgt.LastProbedDateUtc = @Now
                      , tgt.auditModifiedBy   = @Actor
        WHEN NOT MATCHED BY TARGET
        -- auditCreatedBy named explicitly: see F-02 in the notes. The DEFAULT would record the
        -- pooled application login instead of the acting user.
        THEN INSERT (ProbeName, ProbeCount, LastProbedDateUtc, auditCreatedBy, auditModifiedBy)
             VALUES (src.ProbeName, 1, @Now, @Actor, @Actor);

        -- @@ROWCOUNT is reset by the next statement, so read it immediately.
        SET @Comments = CONCAT (@@ROWCOUNT, N' probe row(s) merged.');

        -- The failure is here: inside the transaction and after the start row exists, which is the
        -- only placement that exercises the re-creation block. See the header.
        IF @ForceFailure = 1
        BEGIN
            THROW 50099, N'Phase 0 instrumentation probe: deliberate failure, requested by @ForceFailure = 1.', 1;
        END;

        -- =========================================================================================
        -- ===== End of the procedure's own work. ==================================================
        -- =========================================================================================

        IF @@TRANCOUNT > 0
        BEGIN
            COMMIT TRANSACTION;
        END;

        -- Completion. Deliberately after the COMMIT.
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

        -- ERROR_* are valid only in this scope and any statement can reset them, so capture first.
        SELECT @ErrorNumber = ERROR_NUMBER ()
             , @ErrorProc   = ERROR_PROCEDURE ()
             , @ErrorLine   = ERROR_LINE ()
             , @ErrorMsg    = ERROR_MESSAGE ()
                            + N' (error '  + CAST (ERROR_NUMBER () AS NVARCHAR (11))
                            + N', line '   + CAST (ERROR_LINE ()   AS NVARCHAR (11)) + N')';

        -- One test, not two: XACT_ABORT ON makes -1 the common case and both states need the same
        -- unqualified rollback.
        IF XACT_STATE () <> 0
        BEGIN
            ROLLBACK TRANSACTION;
        END;

        -- The rollback may have destroyed the row uspStartExecutionLogging wrote -- it does when the
        -- procedure was called inside a transaction that was ALREADY open, because ROLLBACK unwinds
        -- the outermost one. Put it back with the ORIGINAL @StartTimeUtc.
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

        -- Bare, so the ORIGINAL error number reaches the caller.
        ;THROW;

    END CATCH;

    RETURN 0;
END;
GO


-- *** 5. Descriptions ***
-- Rule 4 applies to a fixture as much as to a business table, and this file is the first thing in the deployment that
-- calls util.uspSetObjectDescription for real on objects it created itself, which is T-003's verification.
EXEC util.uspSetObjectDescription
      @SchemaName  = N'util'
    , @ObjectType  = N'TABLE'
    , @ObjectName  = N'Phase0ProbeTarget'
    , @Description = N'Phase 0 test fixture, not part of the template a project team clones. One row per named probe run by util.uspPhase0Probe, so the probe has something real to write. Created by database/_tests/010_phase0_instrumentation.sql; safe to leave on a development database and safe to soft-delete every row in.';
GO

EXEC util.uspSetObjectDescription
      @SchemaName  = N'util'
    , @ObjectType  = N'TABLE'
    , @ObjectName  = N'Phase0ProbeTarget'
    , @ColumnName  = N'Phase0ProbeTargetId'
    , @Description = N'Surrogate key. No business meaning; the natural key is ProbeName.';
GO

EXEC util.uspSetObjectDescription
      @SchemaName  = N'util'
    , @ObjectType  = N'TABLE'
    , @ObjectName  = N'Phase0ProbeTarget'
    , @ColumnName  = N'ProbeName'
    , @Description = N'Name of the probe path being exercised, e.g. ''Phase0.Success''. Natural key, unique among live rows.';
GO

EXEC util.uspSetObjectDescription
      @SchemaName  = N'util'
    , @ObjectType  = N'TABLE'
    , @ObjectName  = N'Phase0ProbeTarget'
    , @ColumnName  = N'ProbeCount'
    , @Description = N'How many times this probe path has completed its write. Increments on every successful run and deliberately does not converge -- a counter that did not move would not show that the write happened.';
GO

EXEC util.uspSetObjectDescription
      @SchemaName  = N'util'
    , @ObjectType  = N'TABLE'
    , @ObjectName  = N'Phase0ProbeTarget'
    , @ColumnName  = N'LastProbedDateUtc'
    , @Description = N'UTC timestamp of the most recent successful run of this probe path. Set by util.uspPhase0Probe, not by a default, because a rolled-back run must not move it.';
GO

EXEC util.uspSetObjectDescription
      @SchemaName  = N'util'
    , @ObjectType  = N'TABLE'
    , @ObjectName  = N'Phase0ProbeTarget'
    , @ColumnName  = N'IsDeleted'
    , @Description = N'Soft-delete flag. 1 = deleted, 0 = active. This database performs no hard deletes; all reads must filter IsDeleted = 0.';
GO

EXEC util.uspSetObjectDescription
      @SchemaName  = N'util'
    , @ObjectType  = N'TABLE'
    , @ObjectName  = N'Phase0ProbeTarget'
    , @ColumnName  = N'auditDeletedBy'
    , @Description = N'Login that soft-deleted the row. Stamped by trg_au_updt_Phase0ProbeTarget when IsDeleted transitions 0 -> 1. Meaningful only when IsDeleted = 1.';
GO

EXEC util.uspSetObjectDescription
      @SchemaName  = N'util'
    , @ObjectType  = N'TABLE'
    , @ObjectName  = N'Phase0ProbeTarget'
    , @ColumnName  = N'auditDeletedDateUtc'
    , @Description = N'UTC timestamp of the soft delete, stamped with the same instant as auditModifiedDateUtc. Meaningful only when IsDeleted = 1.';
GO

EXEC util.uspSetObjectDescription
      @SchemaName  = N'util'
    , @ObjectType  = N'TABLE'
    , @ObjectName  = N'Phase0ProbeTarget'
    , @ColumnName  = N'auditCreatedBy'
    , @Description = N'Acting user that inserted the row. Set explicitly by util.uspPhase0Probe from SESSION_CONTEXT (''AppUser''), falling back to ORIGINAL_LOGIN () -- the DEFAULT alone would record the pooled application login. See F-02.';
GO

EXEC util.uspSetObjectDescription
      @SchemaName  = N'util'
    , @ObjectType  = N'TABLE'
    , @ObjectName  = N'Phase0ProbeTarget'
    , @ColumnName  = N'auditCreatedDateUtc'
    , @Description = N'UTC timestamp of row insert.';
GO

EXEC util.uspSetObjectDescription
      @SchemaName  = N'util'
    , @ObjectType  = N'TABLE'
    , @ObjectName  = N'Phase0ProbeTarget'
    , @ColumnName  = N'auditModifiedBy'
    , @Description = N'Acting user that last modified the row. Maintained by trg_au_updt_Phase0ProbeTarget, but caller-overridable: a statement naming this column keeps the value it supplied.';
GO

EXEC util.uspSetObjectDescription
      @SchemaName  = N'util'
    , @ObjectType  = N'TABLE'
    , @ObjectName  = N'Phase0ProbeTarget'
    , @ColumnName  = N'auditModifiedDateUtc'
    , @Description = N'UTC timestamp of last modification. The DEFAULT fires on INSERT only, so trg_au_updt_Phase0ProbeTarget recomputes this on every UPDATE; a caller-supplied value is overwritten.';
GO

EXEC util.uspSetObjectDescription
      @SchemaName  = N'util'
    , @ObjectType  = N'TRIGGER'
    , @ObjectName  = N'trg_au_updt_Phase0ProbeTarget'
    , @Description = N'Owns the modification and soft-delete audit columns on util.Phase0ProbeTarget. Copied from templates/table.sql section 4 with only the names changed, so that the template''s trigger is exercised by a script that actually runs.';
GO

EXEC util.uspSetObjectDescription
      @SchemaName  = N'util'
    , @ObjectType  = N'PROCEDURE'
    , @ObjectName  = N'uspPhase0Probe'
    , @Description = N'Phase 0 instrumentation probe. A fully instrumented write procedure whose purpose is to be instrumented: it increments a counter on util.Phase0ProbeTarget and, with @ForceFailure = 1, throws 50099 inside its transaction so the CATCH, the re-creation block and the bare ;THROW; are all exercised.';
GO


-- *** 6. Grant ***
-- Per procedure, to the roles that call it, in the procedure's own script -- which is what makes the permission report
-- at the end of scripts/permissions.sql the authoritative answer to what the applications can do.
--
-- NOTE WHAT THIS GRANT DOES NOT BUY. scripts/permissions.sql issues no grant and no deny on SCHEMA::util, so
-- applicationRole can EXECUTE this procedure and still cannot read util.Phase0ProbeTarget directly -- which is the
-- intended posture for every table in this design and is worth seeing once here.
IF DATABASE_PRINCIPAL_ID (N'applicationRole') IS NOT NULL
BEGIN
    GRANT EXECUTE ON util.uspPhase0Probe TO applicationRole;
END;
GO


/***********************************************************************************************************************
    7. Exercise all three instrumentation paths.

    Each is run in its own batch with its own error handling, because a THROW that escapes would stop the script before
    the report and the failure paths are SUPPOSED to throw.
***********************************************************************************************************************/

PRINT N'Path 1 of 3: success.';
GO

EXEC util.uspPhase0Probe @ProbeName = N'Phase0.Success';
GO

PRINT N'Path 2 of 3: failure with no ambient transaction. The start row survives the procedure''s own rollback.';
GO

BEGIN TRY
    EXEC util.uspPhase0Probe @ProbeName = N'Phase0.FlatFailure', @ForceFailure = 1;
    PRINT N'  UNEXPECTED: the probe did not throw.';
END TRY
BEGIN CATCH
    PRINT N'  Caught error ' + CAST (ERROR_NUMBER () AS NVARCHAR (11))
        + N' as expected (50099 means the bare THROW preserved the original number).';
END CATCH;
GO

PRINT N'Path 3 of 3: failure inside a caller''s transaction. ROLLBACK unwinds the outermost transaction, so the start';
PRINT N'             row is destroyed and the CATCH must re-create it with ReCreatedAfterRollback = 1.';
GO

BEGIN TRY
    BEGIN TRANSACTION;
    EXEC util.uspPhase0Probe @ProbeName = N'Phase0.NestedFailure', @ForceFailure = 1;
    COMMIT TRANSACTION;
    PRINT N'  UNEXPECTED: the probe did not throw.';
END TRY
BEGIN CATCH
    IF XACT_STATE () <> 0
    BEGIN
        ROLLBACK TRANSACTION;
    END;

    PRINT N'  Caught error ' + CAST (ERROR_NUMBER () AS NVARCHAR (11)) + N' as expected.';
END CATCH;
GO


/***********************************************************************************************************************
    8. Report.

    Reads logs.ExecutionLog back and states, per path, whether the row that should be there is there.  The severities
    match the other scripts in this deployment: 1 and 2 need attention, 3 is information, 4 is fine.
***********************************************************************************************************************/

DECLARE @Report TABLE
(
    RowNo    INT IDENTITY (1, 1) PRIMARY KEY,
    Severity INT             NOT NULL,
    Status   VARCHAR (10)    NOT NULL,
    Item     NVARCHAR (200)  NOT NULL,
    Detail   NVARCHAR (1000)     NULL
);

DECLARE @Proc NVARCHAR (300) = N'[util].[uspPhase0Probe]';

-- Path 1. Completed successfully, with an end time and an elapsed measurement.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 0 THEN 1 ELSE 4 END
     , CASE WHEN COUNT (*) = 0 THEN 'MISSING' ELSE 'OK' END
     , N'Path 1 -- success row'
     , CASE WHEN COUNT (*) = 0
            THEN N'No row with Successful = 1, EndDateUtc and ElapsedMilliseconds set. The completion UPDATE after the '
               + N'COMMIT is not working, which would make every call in the database read as still running.'
            ELSE CAST (COUNT (*) AS NVARCHAR (10)) + N' row(s). Latest elapsed: '
               + CAST (MAX (e.ElapsedMilliseconds) AS NVARCHAR (11)) + N' ms.'
       END
  FROM logs.ExecutionLog AS e
 WHERE e.ProcedureName = @Proc
   AND e.Successful    = 1
   AND e.EndDateUtc          IS NOT NULL
   AND e.ElapsedMilliseconds IS NOT NULL;

-- Path 2. Failure whose start row survived: the MATCHED branch of the error MERGE.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 0 THEN 1 ELSE 4 END
     , CASE WHEN COUNT (*) = 0 THEN 'MISSING' ELSE 'OK' END
     , N'Path 2 -- flat failure row'
     , CASE WHEN COUNT (*) = 0
            THEN N'No row with Successful = 0, ErrorNumber 50099 and ReCreatedAfterRollback = 0. A failure with no '
               + N'ambient transaction should UPDATE the start row it already has.'
            ELSE CAST (COUNT (*) AS NVARCHAR (10)) + N' row(s), ErrorNumber 50099, ReCreatedAfterRollback = 0.'
       END
  FROM logs.ExecutionLog AS e
 WHERE e.ProcedureName          = @Proc
   AND e.Successful             = 0
   AND e.ErrorNumber            = 50099
   AND e.ReCreatedAfterRollback = 0;

-- Path 3. The one that only a measurement finds.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 0 THEN 1 ELSE 4 END
     , CASE WHEN COUNT (*) = 0 THEN 'MISSING' ELSE 'OK' END
     , N'Path 3 -- re-created after rollback'
     , CASE WHEN COUNT (*) = 0
            THEN N'No row with ReCreatedAfterRollback = 1. A failure inside a caller''s transaction loses its start '
               + N'row to the outermost ROLLBACK, and without the re-creation block the only executions never '
               + N'recorded in this database would be the failures.'
            ELSE CAST (COUNT (*) AS NVARCHAR (10)) + N' row(s) re-created with the original StartDateUtc preserved.'
       END
  FROM logs.ExecutionLog AS e
 WHERE e.ProcedureName          = @Proc
   AND e.ReCreatedAfterRollback = 1;

-- The rolled-back work really was rolled back. A failure that left its counter incremented would mean the transaction
-- was not doing its job, and the log row would be recording a lie.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 0 THEN 4 ELSE 1 END
     , CASE WHEN COUNT (*) = 0 THEN 'OK' ELSE 'FAILED' END
     , N'Rollback actually rolled back'
     , CASE WHEN COUNT (*) = 0
            THEN N'Neither failure path left a probe row behind, so the transaction covered the work while the log '
               + N'row survived outside it. That separation is the point of the instrumentation block.'
            ELSE N'A failure path committed its work: ' + STRING_AGG (t.ProbeName, N', ')
               + N'. The BEGIN TRANSACTION / ROLLBACK pairing is wrong.'
       END
  FROM util.Phase0ProbeTarget AS t
 WHERE t.ProbeName IN (N'Phase0.FlatFailure', N'Phase0.NestedFailure');

-- The success path did commit.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 0 THEN 1 ELSE 4 END
     , CASE WHEN COUNT (*) = 0 THEN 'MISSING' ELSE 'OK' END
     , N'Probe target written'
     , CASE WHEN COUNT (*) = 0
            THEN N'util.Phase0ProbeTarget holds no Phase0.Success row, so the successful path did not commit.'
            ELSE N'Phase0.Success ProbeCount = ' + CAST (MAX (t.ProbeCount) AS NVARCHAR (11))
               + N' (one per run of this file), auditCreatedBy = ' + MAX (t.auditCreatedBy) + N'.'
       END
  FROM util.Phase0ProbeTarget AS t
 WHERE t.ProbeName = N'Phase0.Success'
   AND t.IsDeleted = 0;

-- Descriptions, which is T-003's own verification: the helper was called fourteen times above.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) >= 12 THEN 4 ELSE 2 END
     , CASE WHEN COUNT (*) >= 12 THEN 'OK' ELSE 'PARTIAL' END
     , N'MS_Description via util.uspSetObjectDescription'
     , CAST (COUNT (*) AS NVARCHAR (10)) + N' extended propert(ies) on the probe objects. The helper adds or updates, '
     + N'which is why this file re-runs -- a bare sp_addextendedproperty fails the second time with "Property already '
     + N'exists".'
  FROM sys.extended_properties AS ep
 WHERE ep.name = N'MS_Description'
   AND ep.major_id IN (OBJECT_ID (N'util.Phase0ProbeTarget')
                     , OBJECT_ID (N'util.trg_au_updt_Phase0ProbeTarget')
                     , OBJECT_ID (N'util.uspPhase0Probe'));

-- The DDL change trail saw this file arrive. Informational, because it depends on when the file was first run.
INSERT @Report (Severity, Status, Item, Detail)
SELECT 3, 'INFO', N'DDL change logging saw these objects'
     , CAST (COUNT (*) AS NVARCHAR (10)) + N' event(s) recorded against the probe objects by record_db_changes. '
     + N'Zero on a re-run that changed nothing would be wrong -- CREATE OR ALTER fires a DDL event whether or not the '
     + N'definition differs.'
  FROM logsData.DdlChange AS d
 WHERE d.SchemaName = N'util'
   AND d.ObjectName IN (N'Phase0ProbeTarget', N'trg_au_updt_Phase0ProbeTarget', N'uspPhase0Probe');

-- The identity gap the re-creation leaves behind, stated in the output rather than left to be noticed.  IDENTITY
-- allocation is not transactional, so the value the destroyed start row consumed is never returned: path 3 costs one
-- ExecutionLogId per run, for ever.  Anything that reads this table has to know that, because the arithmetic looks like
-- missing rows and is not.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN Burned >= ReCreated THEN 3 ELSE 2 END
     , CASE WHEN Burned >= ReCreated THEN 'INFO' ELSE 'CHECK' END
     , N'Identity gaps in ExecutionLogId'
     , CASE WHEN Burned >= ReCreated
            THEN CAST (Burned AS NVARCHAR (11)) + N' identity value(s) consumed by rows that no longer exist, against '
               + CAST (ReCreated AS NVARCHAR (11)) + N' row(s) with ReCreatedAfterRollback = 1. EXPECTED, and not a '
               + N'lost execution: a rollback does not return an identity value, so every failure inside a caller''s '
               + N'transaction burns one number and the execution is recorded under the next one. Nothing may treat '
               + N'ExecutionLogId as gapless -- order and join on it, never count with it.'
            ELSE CAST (Burned AS NVARCHAR (11)) + N' value(s) consumed by absent rows but '
               + CAST (ReCreated AS NVARCHAR (11)) + N' row(s) flagged ReCreatedAfterRollback = 1. Fewer gaps than '
               + N're-creations is arithmetically impossible unless the table has been reseeded or rows have been '
               + N'deleted. Check before trusting anything else in this report.'
       END
  FROM (SELECT CAST (IDENT_CURRENT (N'logs.ExecutionLog') AS BIGINT)
             - (SELECT COUNT_BIG (*) FROM logs.ExecutionLog)                                            AS Burned
             , (SELECT COUNT_BIG (*) FROM logs.ExecutionLog WHERE ReCreatedAfterRollback = 1)            AS ReCreated) AS x;

IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
    PRINT N'Phase 0 instrumentation probe: PROBLEMS found. Read the report below -- rule 8 is not working as documented.';
ELSE
    PRINT N'Phase 0 instrumentation probe: all three instrumentation paths recorded correctly.';

PRINT N'';

SELECT Severity, Status, Item, Detail
  FROM @Report
 ORDER BY Severity, RowNo;

-- And the rows themselves, because the point of the exercise is that somebody has seen them.
SELECT e.ExecutionLogId
     , e.KeyParameters
     , e.Successful
     , e.ReCreatedAfterRollback
     , e.ElapsedMilliseconds
     , e.ErrorNumber
     , e.Comments
     , e.ContextMessage
  FROM logs.ExecutionLog AS e
 WHERE e.ProcedureName = N'[util].[uspPhase0Probe]'
 ORDER BY e.ExecutionLogId;
GO
