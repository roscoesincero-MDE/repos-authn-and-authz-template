/***********************************************************************************************************************
FileName:     120_rls_policy.sql
Author:       rsincero
CreateDate:   2026-09-20
Implements:   T-064, T-065.  DES-AUTH-001 sections 10.1, 10.2, 10.3, 10.5 and 21.3.
Depends on:   005_schemas_and_roles.sql, 025_config_tables.sql (config.TenantScopedTable), 030_auth_tenant.sql
              (auth.TenantClosure), 050_auth_permission.sql (auth.Permission), 065_auth_effective_permission.sql
              (auth.ProfilePermissionScope), 090_dbo_application.sql (the demo domain tables), 100_auth_functions.sql
              (the three predicates in their reference form), scripts/logExecutionLogging.sql,
              templates/extended-properties.sql.
========================================================================================================================
Description:

The row-level security policy.  One FILTER predicate and three BLOCK predicates on every table registered in
config.TenantScopedTable, built at deploy time by auth.uspRebuildTenantAccessPolicy, which also re-creates the three
predicate functions of 100_auth_functions.sql with the permission ids resolved to literals.

After this file has run, a connection that has not called auth.uspSetSessionContext SEES NOTHING in the registered
tables.  That includes db_owner.  That includes the person deploying.  Read section 5's demonstration before you decide
it is a bug.

========================================================================================================================
Notes:

WHY THE PREDICATES ARE RE-CREATED HERE AT ALL, when 100_auth_functions.sql already contains them.

100 holds the REFERENCE form: it joins auth.Permission and compares PermissionCode = N'Data.Read'.  That form is
readable, it is what section 10.2 publishes, and it is what a reviewer should read to understand the rule.  It is also
one join per row per query, on the hot path of every SELECT against every tenant-scoped table in the database, forever.

This file holds the DEPLOYED form: the same predicate with the join replaced by `pps.PermissionId IN (17, 84, 152)`.
Two seeks become one, and the literal list is fixed at deploy time.

THE LIST IS A LIST, AND THAT IS BL-039.  'Data.Read' is not one permission: auth.Permission is keyed on
(ApplicationId, PermissionCode), so there is one Data.Read row PER APPLICATION.  A predicate written with a single
scalar id -- the obvious first draft -- silently protects one application and silently denies every other.  The plural
is the whole point of the assertion in section 5.

THE PRICE IS STALENESS, AND IT IS PAID IN THE OPEN.  A literal cannot notice a new application.  So:

    1.  auth.uspRebuildTenantAccessPolicy re-resolves the lists and re-creates everything, every time it runs.
    2.  115_seed_reference_data.sql (T-089) and anything else that adds an application MUST run it afterwards.
    3.  The closing report of this file compares the literals embedded in the DEPLOYED function definitions against the
        catalogue as it stands right now, and fails the file if they differ.  A stale predicate is a silent denial, and
        a silent denial reads to a user exactly like missing data.

WHAT HAPPENS WHEN THE CATALOGUE IS EMPTY, WHICH IS THE STATE OF A FRESH TEMPLATE.  Section 16.1 item 3 puts the 35
permission rows in 115_seed_reference_data.sql, and that is task T-089 in Phase 6 -- later than this file.  With no rows
to resolve, the id list is the sentinel `-1`, which no PermissionId can equal, and the predicates therefore deny every
non-bypass session.  FAIL CLOSED, LOUDLY: the report says so at severity 3, the numbers are in the transcript, and the
fix is to re-run this file after the seed.  The alternative -- omitting the IN clause when the list is empty -- would
turn an unseeded database into one where every profile can read every tenant, which is the failure this file exists to
prevent.

THE ORDER DEPENDENCY NOBODY EXPECTS: THIS FILE MAKES 100_auth_functions.sql UNRUNNABLE UNTIL THE POLICY IS DROPPED.
A security policy binds its predicate functions, and a bound function cannot be altered -- `ALTER FUNCTION ... failed
because object ... is being referenced by object 'TenantAccessPolicy'` (error 3729).  So re-running 100 against a
protected database fails.  That is not a defect to work around, it is section 21.3's change procedure, and the supported
sequence is:

    exec auth.uspRebuildTenantAccessPolicy @Action = N'Drop';     -- the policy goes away
    :r 100_auth_functions.sql                                     -- or 065, or 030: anything the predicates bind
    exec auth.uspRebuildTenantAccessPolicy @Action = N'Rebuild';  -- or simply re-run this whole file

Install-TemplateDatabase.ps1 does exactly that, in that order, on every run.  Doing it by hand and forgetting the third
line leaves a database with no row-level security and no error to say so, which is why the runner owns it.

DYNAMIC SQL, AND WHY THIS IS THE FILE THAT USES IT.  Everything about this policy is data: which tables are registered,
which column carries the tenant, which permission ids exist.  A hand-written CREATE SECURITY POLICY would have to be
edited by every project that adds a table -- and the one thing a template must not require is editing the security layer
to add a table.  The generated statements are captured in @DynamicSql, so a failure records the exact text that failed
in logs.ExecutionLog.  That parameter has been on logs.uspRecordExecutionError since Phase 0 for this file.

REGISTERED BUT ABSENT TABLES ARE SKIPPED, NOT FATAL.  A registry row naming a table a project has not created yet is
ordinary during development.  The row is skipped, counted, and reported at severity 2 -- visible, not blocking -- and
the same is true of a registry row naming a column the table does not have.  A skipped table is an UNPROTECTED table,
so the report says that in those words.

WHAT THE POLICY DOES NOT DO.
    -   It does not protect auth, logs, config or util.  Those are reached only through procedures (P-11), and a
        predicate on auth.UserProfile would be evaluated while resolving the predicate on dbo.CaseFile.
    -   It does not cover soft delete, export, approval or reassignment: an UPDATE is an UPDATE to a predicate.  G-05,
        and section 10.4's answer is auth.uspDemandPermission inside procedures.
    -   It does not stop db_owner.  A db_owner can DROP this policy, and can set SESSION_CONTEXT ('BypassRowSecurity')
        directly without going near auth.uspBeginMaintenanceSession -- the role gate on that procedure is there to make
        the ordinary path recorded and reviewable, not to restrain an account that can drop the policy outright.  Row
        security is a boundary between TENANTS, never a boundary between an administrator and the data.  Anybody who
        needs the second thing needs a different database.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-064, T-065
Description:
Created.  Phase 4.  auth.uspRebuildTenantAccessPolicy, the registry-driven policy, the resolved permission id lists and
the assertion that keeps them honest.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
SET NOCOUNT ON;
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

-- *** 0. Assert the target and the parents ***
-- The guard that makes -v DbName the only way to choose a database.  There is no :setvar in this file on purpose: an
-- in-file :setvar OVERRIDES -v and would silently deploy row security to whatever database the author last tested on.
IF DB_NAME () <> N'$(DbName)'
BEGIN
    ;THROW 50000, N'This script must run against the database named by -v DbName. Start sqlcmd with -v DbName=<database> and do not add a :setvar line to this file: an in-file :setvar overrides -v, and a security policy deployed to the wrong database is not a mistake anybody notices quickly.', 1;
END;
GO

USE [$(DbName)];
GO

DECLARE @Missing NVARCHAR (MAX) = NULL;

SELECT @Missing = STRING_AGG (x.ObjectName, N', ') WITHIN GROUP (ORDER BY x.ObjectName)
  FROM (VALUES (N'auth.ProfilePermissionScope', N'U')
             , (N'auth.TenantClosure',          N'U')
             , (N'auth.Permission',             N'U')
             , (N'config.TenantScopedTable',    N'U')
             , (N'auth.tvfTenantReadPredicate',   N'IF')
             , (N'auth.tvfTenantInsertPredicate', N'IF')
             , (N'auth.tvfTenantUpdatePredicate', N'IF')) AS x (ObjectName, ObjectType)
 WHERE OBJECT_ID (x.ObjectName, x.ObjectType) IS NULL;

IF @Missing IS NOT NULL
BEGIN
    DECLARE @Failure NVARCHAR (2048) = N'Row security cannot be deployed: ' + @Missing
        + N' is missing. Run 025_config_tables.sql, 030_auth_tenant.sql, 050_auth_permission.sql, '
        + N'065_auth_effective_permission.sql and 100_auth_functions.sql first. This is a hard stop rather than a '
        + N'warning because a policy built on half a dependency graph is a policy that denies everything.';
    ;THROW 50000, @Failure, 1;
END;
GO

IF OBJECT_ID (N'logs.uspRecordExecutionError', N'P') IS NULL
BEGIN
    PRINT N'WARNING: logs.uspRecordExecutionError is absent, so auth.uspRebuildTenantAccessPolicy will fail in its own '
        + N'CATCH block and report the wrong error. Run scripts/logExecutionLogging.sql.';
END;
GO

IF NOT EXISTS (SELECT 1 FROM config.TenantScopedTable WHERE IsActive = 1 AND IsDeleted = 0)
BEGIN
    PRINT N'WARNING: config.TenantScopedTable has no active rows, so there is nothing to protect and no policy will be '
        + N'created. Register the tenant-scoped tables in 025_config_tables.sql (section 10.1) and re-run this file.';
END;
GO

IF NOT EXISTS (SELECT 1 FROM auth.Permission WHERE IsDeleted = 0 AND PermissionCode = N'Data.Read')
BEGIN
    PRINT N'WARNING: the permission catalogue holds no live Data.Read row, so the predicates will be built with the '
        + N'sentinel id -1 and will DENY every session that is not a maintenance session. Expected before '
        + N'115_seed_reference_data.sql (T-089, Phase 6) has run. Re-run this file after the seed.';
END;
GO


-- *** 1. auth.uspRebuildTenantAccessPolicy ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspRebuildTenantAccessPolicy
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Drops auth.TenantAccessPolicy, re-creates the three predicate functions with the current permission ids resolved to
literals, and re-creates the policy over every active row of config.TenantScopedTable -- one FILTER predicate and three
BLOCK predicates per table.  Sections 10.2 and 10.3.

@Action = N'Rebuild' (the default) does all of it.  @Action = N'Drop' stops after the drop, which is how section 21.3's
change procedure gets a database into a state where 100_auth_functions.sql, 065_auth_effective_permission.sql or
030_auth_tenant.sql can be re-run at all.

@TablesBound returns how many tables the policy protects.  @TablesSkipped returns how many registry rows named a table
or a column that does not exist -- every one of those is an UNPROTECTED table.

========================================================================================================================
Notes:

IT IS ONE PROCEDURE AND NOT FOUR SCRIPTS BECAUSE THE FOUR STEPS ARE NOT INDEPENDENT.  Re-creating a predicate requires
the policy to be gone; leaving the policy gone is a database with no row security; and the id lists have to be resolved
between the two.  A procedure makes the whole sequence one transaction and one audited call, and gives 120_rls_policy.sql,
Install-TemplateDatabase.ps1, database/_tests/060_*.sql and any future seed the same entry point.

WHY IT TAKES NO SESSION TOKEN AND DEMANDS NO PERMISSION.  It is DDL over the security layer itself: the only principal
who can run it is one who could already drop the policy by hand.  So EXECUTE is granted to nobody -- see section 4 --
exactly as auth.uspRebuildTenantClosure is, and for the same reason: a procedure that rewrites the rules must not be
reachable by the application that the rules constrain.

THE TRANSACTION IS REAL AND IT MATTERS.  DDL participates: if the policy re-creation fails after the predicates have
been altered, the rollback restores the previous predicates AND the previous policy.  The failure mode this avoids is
the worst one available -- a rolled-back deployment that leaves the tables unprotected.

THE SENTINEL IS -1 AND NOT AN OMITTED CLAUSE.  When no permission of a given code exists, the generated predicate says
`pps.PermissionId IN (-1)`, which no row satisfies.  Dropping the clause instead would produce a predicate that grants
every scoped profile every right, and an unseeded database would silently be an open one.

THE MARKER COMMENT IN EACH GENERATED FUNCTION IS LOAD-BEARING.  It records which permission code the list came from and
when, and 120_rls_policy.sql's closing report reads sys.sql_modules to check that the literals still match the
catalogue.  A reviewer who sees a bare list of integers in a security predicate should be able to find out where they
came from without running anything.

========================================================================================================================
Example Usage and Performance:

declare @bound int, @skipped int;
exec auth.uspRebuildTenantAccessPolicy @TablesBound = @bound output, @TablesSkipped = @skipped output;

-- to re-run 100_auth_functions.sql against a protected database
exec auth.uspRebuildTenantAccessPolicy @Action = N'Drop';

Four DDL statements plus one per registered table.  Measured in milliseconds; it is deploy-time work, and every call
invalidates the plans of every query against every registered table, so it is not something to run on a schedule.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-064, T-065
Description:
Created.  Phase 4.  The registry-driven policy and the resolved permission id lists.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspRebuildTenantAccessPolicy
      @Action        NVARCHAR (20) = N'Rebuild'
    , @TablesBound   INT           = NULL OUTPUT
    , @TablesSkipped INT           = NULL OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspRebuildTenantAccessPolicy]')
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

    -- A separator for STRING_AGG must be a literal or a VARIABLE -- an expression is error 8733, which is why @Separator
    -- exists beside @Crlf rather than being written as N',' + @Crlf at the point of use.
    DECLARE @Crlf      NCHAR (2)      = NCHAR (13) + NCHAR (10)
          , @Separator NVARCHAR (10)  = N',' + NCHAR (13) + NCHAR (10)
          , @ReadIds   NVARCHAR (MAX) = NULL
          , @InsertIds NVARCHAR (MAX) = NULL
          , @UpdateIds NVARCHAR (MAX) = NULL
          , @Bindings  NVARCHAR (MAX) = NULL
          , @Stamp     NVARCHAR (30)  = CONVERT (NVARCHAR (30), SYSUTCDATETIME (), 126)
          , @Predicates INT           = NULL;

    DECLARE @Bindable TABLE
    (
        Ord         INT IDENTITY (1, 1) PRIMARY KEY,
        SchemaName  SYSNAME NOT NULL,
        TableName   SYSNAME NOT NULL,
        ColumnName  SYSNAME NOT NULL
    );

    SET @Action = LTRIM (RTRIM (COALESCE (@Action, N'Rebuild')));
    SET @KeyParameters = CONCAT (N'@Action=', @Action);
    SET @ContextMessage = N'Section 10.3. Drops auth.TenantAccessPolicy, re-creates the three predicates with the '
                        + N'current permission ids as literals, and re-binds the policy from config.TenantScopedTable. '
                        + N'A bound predicate cannot be altered (error 3729), which is why the drop comes first.';
    SET @TablesBound   = 0;
    SET @TablesSkipped = 0;

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

        -- 1.  Two actions and no third. A typo must not quietly mean 'Rebuild', because the caller
        --     who typed 'drop ' is in the middle of section 21.3's change procedure and would get a
        --     rebuilt policy over stale functions.
        IF @Action NOT IN (N'Rebuild', N'Drop')
        BEGIN
            ;THROW 50140, N'@Action must be N''Rebuild'' or N''Drop''. Rebuild drops the policy, re-creates the three predicate functions with the current permission ids resolved to literals, and re-binds the policy from config.TenantScopedTable. Drop stops after the drop, which is how section 21.3 gets a database into a state where the objects the predicates bind -- auth.ProfilePermissionScope, auth.TenantClosure, auth.Permission -- can be altered at all. There is no third action, and an unrecognised one is refused rather than defaulted.', 1;
        END;

        -- 2.  The drop, and it is first for a reason the error message will not tell you: a function
        --     bound by a security policy cannot be altered (3729), so every re-creation below is
        --     impossible until this has run.
        IF EXISTS (SELECT 1
                     FROM sys.security_policies
                    WHERE name = N'TenantAccessPolicy'
                      AND schema_id = SCHEMA_ID (N'auth'))
        BEGIN
            SET @DynamicSql = N'DROP SECURITY POLICY auth.TenantAccessPolicy;';
            EXEC sys.sp_executesql @DynamicSql;
        END;

        IF @Action = N'Drop'
        BEGIN
            SET @Comments = N'Policy dropped and NOT rebuilt, as asked. The registered tables are unprotected until '
                          + N'auth.uspRebuildTenantAccessPolicy runs again with @Action = N''Rebuild''.';
        END
        ELSE
        BEGIN
            -- 3.  The id lists. BL-039: one row per application per code, so this is a LIST. The
            --     sentinel -1 is what makes an unseeded catalogue deny rather than permit.
            SELECT @ReadIds = STRING_AGG (CAST (p.PermissionId AS NVARCHAR (11)), N', ')
                                  WITHIN GROUP (ORDER BY p.PermissionId)
              FROM auth.Permission AS p
             WHERE p.IsDeleted = 0
               AND p.PermissionCode = N'Data.Read';

            SELECT @InsertIds = STRING_AGG (CAST (p.PermissionId AS NVARCHAR (11)), N', ')
                                    WITHIN GROUP (ORDER BY p.PermissionId)
              FROM auth.Permission AS p
             WHERE p.IsDeleted = 0
               AND p.PermissionCode = N'Data.Insert';

            SELECT @UpdateIds = STRING_AGG (CAST (p.PermissionId AS NVARCHAR (11)), N', ')
                                    WITHIN GROUP (ORDER BY p.PermissionId)
              FROM auth.Permission AS p
             WHERE p.IsDeleted = 0
               AND p.PermissionCode = N'Data.Update';

            SET @ReadIds   = COALESCE (NULLIF (@ReadIds,   N''), N'-1');
            SET @InsertIds = COALESCE (NULLIF (@InsertIds, N''), N'-1');
            SET @UpdateIds = COALESCE (NULLIF (@UpdateIds, N''), N'-1');

            -- 4.  The FILTER predicate. Same rule as 100_auth_functions.sql section 8; the join on
            --     auth.Permission is gone and its answer is in the IN list.
            SET @DynamicSql = N'CREATE OR ALTER FUNCTION auth.tvfTenantReadPredicate (@TenantId INT)' + @Crlf
                + N'RETURNS TABLE' + @Crlf
                + N'WITH SCHEMABINDING' + @Crlf
                + N'AS' + @Crlf
                + N'RETURN' + @Crlf
                + N'    -- GENERATED by auth.uspRebuildTenantAccessPolicy at ' + @Stamp + N'Z from the live Data.Read' + @Crlf
                + N'    -- rows of auth.Permission. The reference form, with the join and the code, is in' + @Crlf
                + N'    -- 100_auth_functions.sql section 8. Re-run 120_rls_policy.sql after ANY change to the' + @Crlf
                + N'    -- permission catalogue or this list goes stale, and a stale list is a silent denial.' + @Crlf
                + N'    SELECT 1 AS Allowed' + @Crlf
                + N'     WHERE EXISTS (SELECT 1' + @Crlf
                + N'                     FROM auth.ProfilePermissionScope AS pps' + @Crlf
                + N'                     JOIN auth.TenantClosure          AS tc' + @Crlf
                + N'                       ON tc.AncestorTenantId = pps.ScopeTenantId' + @Crlf
                + N'                    WHERE pps.UserProfileId     = TRY_CAST (SESSION_CONTEXT (N''UserProfileId'') AS INT)' + @Crlf
                + N'                      AND pps.IsDeleted         = 0' + @Crlf
                + N'                      AND pps.PermissionId IN (' + @ReadIds + N')' + @Crlf
                + N'                      AND tc.DescendantTenantId = @TenantId' + @Crlf
                + N'                      AND tc.IsDeleted          = 0)' + @Crlf
                + N'        OR TRY_CAST (SESSION_CONTEXT (N''BypassRowSecurity'') AS BIT) = 1;';
            EXEC sys.sp_executesql @DynamicSql;

            -- 5.  The BLOCK AFTER INSERT predicate. The equality against ActingTenantId stays: P-06
            --     is the one asymmetry in the whole scheme and it is not an optimisation.
            SET @DynamicSql = N'CREATE OR ALTER FUNCTION auth.tvfTenantInsertPredicate (@TenantId INT)' + @Crlf
                + N'RETURNS TABLE' + @Crlf
                + N'WITH SCHEMABINDING' + @Crlf
                + N'AS' + @Crlf
                + N'RETURN' + @Crlf
                + N'    -- GENERATED by auth.uspRebuildTenantAccessPolicy at ' + @Stamp + N'Z from the live Data.Insert' + @Crlf
                + N'    -- rows of auth.Permission. Reference form: 100_auth_functions.sql section 9.' + @Crlf
                + N'    SELECT 1 AS Allowed' + @Crlf
                + N'     WHERE (@TenantId = TRY_CAST (SESSION_CONTEXT (N''ActingTenantId'') AS INT)' + @Crlf
                + N'            AND EXISTS (SELECT 1' + @Crlf
                + N'                          FROM auth.ProfilePermissionScope AS pps' + @Crlf
                + N'                          JOIN auth.TenantClosure          AS tc' + @Crlf
                + N'                            ON tc.AncestorTenantId = pps.ScopeTenantId' + @Crlf
                + N'                         WHERE pps.UserProfileId     = TRY_CAST (SESSION_CONTEXT (N''UserProfileId'') AS INT)' + @Crlf
                + N'                           AND pps.IsDeleted         = 0' + @Crlf
                + N'                           AND pps.PermissionId IN (' + @InsertIds + N')' + @Crlf
                + N'                           AND tc.DescendantTenantId = @TenantId' + @Crlf
                + N'                           AND tc.IsDeleted          = 0))' + @Crlf
                + N'        OR TRY_CAST (SESSION_CONTEXT (N''BypassRowSecurity'') AS BIT) = 1;';
            EXEC sys.sp_executesql @DynamicSql;

            -- 6.  The BLOCK BEFORE/AFTER UPDATE predicate. One function, two bindings, two tenants.
            SET @DynamicSql = N'CREATE OR ALTER FUNCTION auth.tvfTenantUpdatePredicate (@TenantId INT)' + @Crlf
                + N'RETURNS TABLE' + @Crlf
                + N'WITH SCHEMABINDING' + @Crlf
                + N'AS' + @Crlf
                + N'RETURN' + @Crlf
                + N'    -- GENERATED by auth.uspRebuildTenantAccessPolicy at ' + @Stamp + N'Z from the live Data.Update' + @Crlf
                + N'    -- rows of auth.Permission. Reference form: 100_auth_functions.sql section 10. Bound TWICE per' + @Crlf
                + N'    -- table -- before and after update -- so a row can be neither edited nor moved out of reach.' + @Crlf
                + N'    SELECT 1 AS Allowed' + @Crlf
                + N'     WHERE EXISTS (SELECT 1' + @Crlf
                + N'                     FROM auth.ProfilePermissionScope AS pps' + @Crlf
                + N'                     JOIN auth.TenantClosure          AS tc' + @Crlf
                + N'                       ON tc.AncestorTenantId = pps.ScopeTenantId' + @Crlf
                + N'                    WHERE pps.UserProfileId     = TRY_CAST (SESSION_CONTEXT (N''UserProfileId'') AS INT)' + @Crlf
                + N'                      AND pps.IsDeleted         = 0' + @Crlf
                + N'                      AND pps.PermissionId IN (' + @UpdateIds + N')' + @Crlf
                + N'                      AND tc.DescendantTenantId = @TenantId' + @Crlf
                + N'                      AND tc.IsDeleted          = 0)' + @Crlf
                + N'        OR TRY_CAST (SESSION_CONTEXT (N''BypassRowSecurity'') AS BIT) = 1;';
            EXEC sys.sp_executesql @DynamicSql;

            -- 7.  Which registry rows can actually be bound. A row naming a table or a column that
            --     does not exist is skipped and counted -- and a skipped row is an UNPROTECTED table,
            --     which is why the count is an OUTPUT parameter and not a PRINT.
            INSERT @Bindable (SchemaName, TableName, ColumnName)
            SELECT r.SchemaName, r.TableName, r.TenantColumnName
              FROM config.TenantScopedTable AS r
             WHERE r.IsActive  = 1
               AND r.IsDeleted = 0
               AND EXISTS (SELECT 1
                             FROM sys.columns AS c
                            WHERE c.object_id = OBJECT_ID (QUOTENAME (r.SchemaName) + N'.' + QUOTENAME (r.TableName), N'U')
                              AND c.name      = r.TenantColumnName)
             ORDER BY r.SchemaName, r.TableName;

            SET @TablesBound = (SELECT COUNT (*) FROM @Bindable);

            SET @TablesSkipped = (SELECT COUNT (*)
                                    FROM config.TenantScopedTable AS r
                                   WHERE r.IsActive  = 1
                                     AND r.IsDeleted = 0
                                     AND NOT EXISTS (SELECT 1
                                                       FROM @Bindable AS b
                                                      WHERE b.SchemaName = r.SchemaName
                                                        AND b.TableName  = r.TableName));

            IF @TablesBound = 0
            BEGIN
                -- 8.  Nothing to bind. A security policy with no predicates is not a thing SQL Server
                --     will create, and a policy that protects nothing would be worse than its absence
                --     anyway: it would read as protection in every catalogue query.
                SET @Comments = CONCAT (N'No policy created: none of the ', @TablesSkipped
                                      , N' active registry row(s) names a table and column that exist. '
                                      , N'THE REGISTERED TABLES ARE UNPROTECTED.');
            END
            ELSE
            BEGIN
                -- 9.  Four bindings per table, in the order section 10.3 lists them. STRING_AGG with
                --     WITHIN GROUP because the order of the clauses is the order a reviewer reads.
                SELECT @Bindings = STRING_AGG (CAST (x.Clause AS NVARCHAR (MAX)), @Separator)
                                       WITHIN GROUP (ORDER BY x.Ord, x.Slot)
                  FROM (SELECT b.Ord, Slot = 1
                             , Clause = N'    ADD FILTER PREDICATE auth.tvfTenantReadPredicate (' + QUOTENAME (b.ColumnName)
                                      + N') ON ' + QUOTENAME (b.SchemaName) + N'.' + QUOTENAME (b.TableName)
                          FROM @Bindable AS b
                        UNION ALL
                        SELECT b.Ord, Slot = 2
                             , Clause = N'    ADD BLOCK PREDICATE auth.tvfTenantInsertPredicate (' + QUOTENAME (b.ColumnName)
                                      + N') ON ' + QUOTENAME (b.SchemaName) + N'.' + QUOTENAME (b.TableName) + N' AFTER INSERT'
                          FROM @Bindable AS b
                        UNION ALL
                        SELECT b.Ord, Slot = 3
                             , Clause = N'    ADD BLOCK PREDICATE auth.tvfTenantUpdatePredicate (' + QUOTENAME (b.ColumnName)
                                      + N') ON ' + QUOTENAME (b.SchemaName) + N'.' + QUOTENAME (b.TableName) + N' BEFORE UPDATE'
                          FROM @Bindable AS b
                        UNION ALL
                        SELECT b.Ord, Slot = 4
                             , Clause = N'    ADD BLOCK PREDICATE auth.tvfTenantUpdatePredicate (' + QUOTENAME (b.ColumnName)
                                      + N') ON ' + QUOTENAME (b.SchemaName) + N'.' + QUOTENAME (b.TableName) + N' AFTER UPDATE'
                          FROM @Bindable AS b) AS x;

                SET @DynamicSql = N'CREATE SECURITY POLICY auth.TenantAccessPolicy' + @Crlf
                                + @Bindings + @Crlf
                                + N'    WITH (STATE = ON);';
                EXEC sys.sp_executesql @DynamicSql;

                -- 10. Assert what was built, inside the transaction, so a policy that came out wrong
                --     never survives the call. Four predicates per table and enabled, or nothing.
                SELECT @Predicates = COUNT (*)
                  FROM sys.security_predicates AS sp
                  JOIN sys.security_policies   AS pol ON pol.object_id = sp.object_id
                 WHERE pol.name = N'TenantAccessPolicy'
                   AND pol.schema_id = SCHEMA_ID (N'auth')
                   AND pol.is_enabled = 1;

                IF COALESCE (@Predicates, 0) <> @TablesBound * 4
                BEGIN
                    DECLARE @Failure NVARCHAR (2048) = CONCAT (
                          N'auth.TenantAccessPolicy was created with ', COALESCE (@Predicates, 0)
                        , N' enabled predicate(s) over ', @TablesBound, N' table(s); section 10.3 requires exactly four '
                        , N'per table -- one FILTER, one BLOCK AFTER INSERT, one BLOCK BEFORE UPDATE and one BLOCK '
                        , N'AFTER UPDATE. The transaction has been rolled back, which restores the previous policy: a '
                        , N'half-built policy is worse than the one it replaced, because every catalogue query reads it '
                        , N'as protection.');
                    ;THROW 50141, @Failure, 1;
                END;

                SET @Comments = CONCAT (N'auth.TenantAccessPolicy rebuilt: ', @TablesBound, N' table(s), '
                                      , @Predicates, N' predicate(s), ', @TablesSkipped, N' registry row(s) skipped. '
                                      , N'Data.Read ids (', @ReadIds, N'), Data.Insert ids (', @InsertIds
                                      , N'), Data.Update ids (', @UpdateIds, N').');
            END;
        END;

        -- =========================================================================================
        -- ===== End of the procedure's own work. ==================================================
        -- =========================================================================================
        IF @@TRANCOUNT > 0
        BEGIN
            COMMIT TRANSACTION;
        END;

        SET @EndTimeUtc = SYSUTCDATETIME ();

        IF @ExecutionId IS NOT NULL
        BEGIN
            UPDATE logs.ExecutionLog
               SET EndDateUtc           = @EndTimeUtc
                 , ElapsedMilliseconds  = CAST (LEAST (DATEDIFF_BIG (MILLISECOND, @StartTimeUtc, @EndTimeUtc)
                                                     , CAST (2147483647 AS BIGINT)) AS INT)
                 , Successful           = 1
                 , Comments             = @Comments
                 , DynamicSql           = @DynamicSql
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

        BEGIN TRY
            IF @ExecutionId IS NULL
               OR NOT EXISTS (SELECT 1 FROM logs.ExecutionLog WHERE ExecutionLogId = @ExecutionId)
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


-- *** 2. Build it ***
-- The deploy-time act.  Everything above is a definition; this is the line that turns row security on, and running this
-- file is how a project turns it on again after registering a table or seeding the catalogue.
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

DECLARE @Bound INT, @Skipped INT;

EXEC auth.uspRebuildTenantAccessPolicy
      @Action        = N'Rebuild'
    , @TablesBound   = @Bound   OUTPUT
    , @TablesSkipped = @Skipped OUTPUT;

PRINT CONCAT (N'auth.TenantAccessPolicy: ', @Bound, N' table(s) protected, ', @Skipped, N' registry row(s) skipped.');
GO


-- *** 3. Descriptions ***
IF OBJECT_ID (N'util.uspSetObjectDescription', N'P') IS NOT NULL
BEGIN
    DECLARE @Description NVARCHAR (3750) =
            N'Drops auth.TenantAccessPolicy, re-creates the three tenant predicates with the current permission ids '
          + N'resolved to literals, and re-binds the policy over every active row of config.TenantScopedTable -- one '
          + N'FILTER and three BLOCK predicates per table. Sections 10.2 and 10.3. @Action = N''Drop'' stops after the '
          + N'drop, which is section 21.3''s change procedure: a function bound by a security policy cannot be altered '
          + N'(error 3729), so re-running 100_auth_functions.sql, 065_auth_effective_permission.sql or '
          + N'030_auth_tenant.sql against a protected database requires the policy to be gone first. '
          + N'Install-TemplateDatabase.ps1 drops, deploys and rebuilds on every run so that nobody has to remember. '
          + N'THE ID LISTS ARE LISTS (BL-039): auth.Permission is keyed on (ApplicationId, PermissionCode), so there is '
          + N'one Data.Read row per application, and a predicate written with a single id would silently protect one '
          + N'application and deny every other. An empty catalogue resolves to the sentinel -1, which denies every '
          + N'non-bypass session -- fail closed, because the alternative is an unseeded database where every profile '
          + N'reads every tenant. @TablesSkipped counts registry rows naming a table or column that does not exist, and '
          + N'every one of those is an UNPROTECTED table. Granted to nobody: it is DDL over the security layer, so the '
          + N'only principal who can run it is one who could drop the policy by hand. Raises 50140 on an unrecognised '
          + N'@Action and 50141 when the rebuilt policy does not carry exactly four enabled predicates per table, in '
          + N'which case the transaction rolls the previous policy back into place.';

    EXEC util.uspSetObjectDescription @SchemaName  = N'auth'
                                    , @ObjectType  = N'PROCEDURE'
                                    , @ObjectName  = N'uspRebuildTenantAccessPolicy'
                                    , @Description = @Description;
END
ELSE
BEGIN
    PRINT N'util.uspSetObjectDescription is absent, so no description was set. Run templates/extended-properties.sql '
        + N'and then re-run this file to add it.';
END
GO


-- *** 4. Grants ***
-- NOTHING IS GRANTED, AND THAT IS THE ENTRY.  auth.uspRebuildTenantAccessPolicy is DDL over the security layer: the
-- only principal who can run it is one who could already drop the policy by hand, which is db_owner.  Granting EXECUTE
-- to applicationRole would hand the application a supported way to rewrite the rules that constrain it -- the same
-- reasoning that leaves auth.uspRebuildTenantClosure ungranted in 125_auth_tenant_procedures.sql.
--
-- The predicate functions are not granted either, and do not need to be.  A security policy evaluates its predicates in
-- the context of the policy, not the caller, so a user with no permission at all on auth.ProfilePermissionScope,
-- auth.TenantClosure or the functions themselves still has the policy applied correctly.  That is what makes P-11
-- workable: the application holds EXECUTE on procedures and nothing else, and row security still reaches it.
PRINT N'No grants: auth.uspRebuildTenantAccessPolicy is DDL over the security layer and stays with db_owner. The '
    + N'predicate functions need no grant either -- a policy evaluates its predicates in its own context.';
GO


-- *** 5. Closing report ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

DECLARE @Report TABLE
(
    RowNo    INT IDENTITY (1, 1) PRIMARY KEY,
    Severity INT             NOT NULL,
    Status   VARCHAR (10)    NOT NULL,
    Item     NVARCHAR (200)  NOT NULL,
    Detail   NVARCHAR (1000)     NULL
);

DECLARE @Bound     INT            = (SELECT COUNT (*) FROM config.TenantScopedTable WHERE IsActive = 1 AND IsDeleted = 0)
      , @Predicates INT           = NULL
      , @Enabled   BIT            = NULL
      , @ReadIds   NVARCHAR (MAX) = NULL
      , @InsertIds NVARCHAR (MAX) = NULL
      , @UpdateIds NVARCHAR (MAX) = NULL
      , @VisibleRows INT          = NULL
      , @AllRows    INT           = NULL;

SELECT @Predicates = COUNT (*)
     , @Enabled    = MAX (CAST (pol.is_enabled AS TINYINT))
  FROM sys.security_policies   AS pol
  LEFT JOIN sys.security_predicates AS sp ON sp.object_id = pol.object_id
 WHERE pol.name = N'TenantAccessPolicy'
   AND pol.schema_id = SCHEMA_ID (N'auth');

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN @Enabled = 1 THEN 4
            WHEN @Enabled = 0 THEN 1
            ELSE 2 END
     , CASE WHEN @Enabled = 1 THEN 'OK'
            WHEN @Enabled = 0 THEN 'DISABLED'
            ELSE 'MISSING' END
     , N'auth.TenantAccessPolicy exists and is ON'
     , CONCAT (N'State ', CASE WHEN @Enabled IS NULL THEN N'(no policy)'
                               WHEN @Enabled = 1 THEN N'ON' ELSE N'OFF' END
             , N', ', COALESCE (@Predicates, 0), N' predicate(s). A policy that exists but is OFF is the worst of the '
             , N'three states: every catalogue query reads it as protection and none of it is enforced.');

-- Four per table, or somebody has bound predicates by hand.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Wrong = 0 AND x.Tables > 0 THEN 4
            WHEN x.Tables = 0 THEN 3
            ELSE 2 END
     , CASE WHEN x.Wrong = 0 AND x.Tables > 0 THEN 'OK'
            WHEN x.Tables = 0 THEN 'PENDING'
            ELSE 'INCOMPLETE' END
     , N'Every protected table carries four predicates'
     , CONCAT (x.Tables, N' table(s) bound, ', x.Wrong, N' with a count other than four. Section 10.3: one FILTER, one '
             , N'BLOCK AFTER INSERT, one BLOCK BEFORE UPDATE, one BLOCK AFTER UPDATE. Three of the four would still '
             , N'look like row security in a demonstration.')
  FROM (SELECT Tables = COUNT (*)
             , Wrong  = SUM (CASE WHEN y.Predicates = 4 THEN 0 ELSE 1 END)
          FROM (SELECT sp.target_object_id, Predicates = COUNT (*)
                  FROM sys.security_predicates AS sp
                  JOIN sys.security_policies   AS pol ON pol.object_id = sp.object_id
                 WHERE pol.name = N'TenantAccessPolicy'
                   AND pol.schema_id = SCHEMA_ID (N'auth')
                 GROUP BY sp.target_object_id) AS y) AS x;

-- Registered and NOT protected.  The words matter: this is not a missing feature, it is a table anybody can read.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Unprotected = 0 THEN 4 ELSE 2 END
     , CASE WHEN x.Unprotected = 0 THEN 'OK' ELSE 'UNPROTECT' END
     , N'Every active registry row is actually protected'
     , CONCAT (x.Unprotected, N' of ', @Bound, N' active row(s) in config.TenantScopedTable carry no predicate. Each '
             , N'one is a table the registry claims is tenant-scoped and that any session can read in full. Usually it '
             , N'names a table or a tenant column that does not exist yet -- create it and re-run this file.')
  FROM (SELECT Unprotected = COUNT (*)
          FROM config.TenantScopedTable AS r
         WHERE r.IsActive  = 1
           AND r.IsDeleted = 0
           AND NOT EXISTS (SELECT 1
                             FROM sys.security_predicates AS sp
                             JOIN sys.security_policies   AS pol ON pol.object_id = sp.object_id
                            WHERE pol.name = N'TenantAccessPolicy'
                              AND pol.schema_id = SCHEMA_ID (N'auth')
                              AND sp.target_object_id = OBJECT_ID (QUOTENAME (r.SchemaName) + N'.'
                                                                 + QUOTENAME (r.TableName), N'U'))) AS x;

-- =====================================================================================================================
-- T-065's assertion.  The literals in the DEPLOYED predicates against the catalogue as it stands right now.  This is
-- the row that catches the failure this design chooses to risk: an id list that no longer matches the permissions.
-- =====================================================================================================================
SELECT @ReadIds = STRING_AGG (CAST (p.PermissionId AS NVARCHAR (11)), N', ') WITHIN GROUP (ORDER BY p.PermissionId)
  FROM auth.Permission AS p WHERE p.IsDeleted = 0 AND p.PermissionCode = N'Data.Read';
SELECT @InsertIds = STRING_AGG (CAST (p.PermissionId AS NVARCHAR (11)), N', ') WITHIN GROUP (ORDER BY p.PermissionId)
  FROM auth.Permission AS p WHERE p.IsDeleted = 0 AND p.PermissionCode = N'Data.Insert';
SELECT @UpdateIds = STRING_AGG (CAST (p.PermissionId AS NVARCHAR (11)), N', ') WITHIN GROUP (ORDER BY p.PermissionId)
  FROM auth.Permission AS p WHERE p.IsDeleted = 0 AND p.PermissionCode = N'Data.Update';

SET @ReadIds   = COALESCE (NULLIF (@ReadIds,   N''), N'-1');
SET @InsertIds = COALESCE (NULLIF (@InsertIds, N''), N'-1');
SET @UpdateIds = COALESCE (NULLIF (@UpdateIds, N''), N'-1');

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Stale = 0 THEN 4 ELSE 1 END
     , CASE WHEN x.Stale = 0 THEN 'OK' ELSE 'STALE' END
     , N'The embedded permission ids match the catalogue'
     , CONCAT (x.Stale, N' of 3 predicates carry a list that is no longer current. Data.Read (', @ReadIds
             , N'), Data.Insert (', @InsertIds, N'), Data.Update (', @UpdateIds
             , N'). A stale list is a SILENT DENIAL, and to a user a silent denial is indistinguishable from data that '
             , N'has gone missing. Re-run this file; it is idempotent.')
  FROM (SELECT Stale = SUM (CASE WHEN CHARINDEX (N'PermissionId IN (' + y.Expected + N')', m.definition) > 0
                                 THEN 0 ELSE 1 END)
          FROM (VALUES (N'auth.tvfTenantReadPredicate',   @ReadIds)
                     , (N'auth.tvfTenantInsertPredicate', @InsertIds)
                     , (N'auth.tvfTenantUpdatePredicate', @UpdateIds)) AS y (FuncName, Expected)
          JOIN sys.sql_modules AS m ON m.object_id = OBJECT_ID (y.FuncName, N'IF')) AS x;

-- The catalogue itself, reported separately, because 'the ids match' is a true and useless statement when the ids are
-- the sentinel.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN @ReadIds <> N'-1' THEN 4 ELSE 3 END
     , CASE WHEN @ReadIds <> N'-1' THEN 'OK' ELSE 'PENDING' END
     , N'The permission catalogue is seeded'
     , CASE WHEN @ReadIds <> N'-1'
            THEN CONCAT (N'Data.Read resolves to (', @ReadIds, N'), one id per application, which is BL-039 working.')
            ELSE N'Empty, so the predicates were built with the sentinel id -1 and DENY every session that is not a '
               + N'maintenance session. Expected until 115_seed_reference_data.sql (T-089, section 16.1 item 3) has '
               + N'run. Re-run this file afterwards -- the predicates do not notice a seed on their own.' END;

-- =====================================================================================================================
-- T-068, at deploy time and in the transcript.  The whole point is that nobody should meet this cold: the account that
-- just built the policy is db_owner, and it can see nothing.  Row security applies to the owner of the database.
-- The bypass here is set DIRECTLY rather than through auth.uspBeginMaintenanceSession, because dbo is deliberately not
-- a member of rlsBypassRole -- and because a db_owner who wants the bypass has always been able to do exactly this,
-- which is the honest reason section 10.5's role gate is a record-keeping measure and not a wall.
-- =====================================================================================================================
IF OBJECT_ID (N'dbo.CaseFile', N'U') IS NOT NULL
BEGIN
    SELECT @VisibleRows = COUNT (*) FROM dbo.CaseFile;

    EXEC sp_set_session_context @key = N'BypassRowSecurity', @value = 1;
    SELECT @AllRows = COUNT (*) FROM dbo.CaseFile;
    EXEC sp_set_session_context @key = N'BypassRowSecurity', @value = NULL;

    INSERT @Report (Severity, Status, Item, Detail)
    SELECT CASE WHEN @Enabled IS NULL THEN 3
                WHEN @VisibleRows = 0 THEN 4
                ELSE 1 END
         , CASE WHEN @Enabled IS NULL THEN 'PENDING'
                WHEN @VisibleRows = 0 THEN 'OK'
                ELSE 'VIOLATED' END
         , N'db_owner with no session context sees nothing (T-068, UI-18)'
         , CONCAT (N'dbo.CaseFile: ', @VisibleRows, N' row(s) visible to this connection, ', @AllRows
                 , N' row(s) with the bypass key set. The first number must be 0 whatever the second one is. This is '
                 , N'the demonstration section 10.5 asks for -- a DBA who queries a protected table and gets an empty '
                 , N'grid has NOT lost the data, and the person who concludes otherwise at 3 a.m. is the reason this '
                 , N'row is printed at deploy time.');
END;

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (N'auth.uspRebuildTenantAccessPolicy', N'P') IS NULL THEN 1 ELSE 4 END
     , CASE WHEN OBJECT_ID (N'auth.uspRebuildTenantAccessPolicy', N'P') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Procedure auth.uspRebuildTenantAccessPolicy'
     , N'Sections 10.2, 10.3, 21.3. T-064 and T-065. @Action = N''Drop'' is the half of section 21.3''s change '
     + N'procedure that makes 100_auth_functions.sql runnable again against a protected database.';

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 1 THEN 4 ELSE 2 END
     , CASE WHEN COUNT (*) = 1 THEN 'OK' ELSE 'INCOMPLETE' END
     , N'MS_Description on auth.uspRebuildTenantAccessPolicy'
     , CONCAT (COUNT (*), N' of 1. Conventions rule 4.')
  FROM sys.extended_properties AS ep
  JOIN sys.objects             AS o ON o.object_id = ep.major_id
 WHERE ep.class = 1
   AND ep.minor_id = 0
   AND ep.name = N'MS_Description'
   AND o.schema_id = SCHEMA_ID (N'auth')
   AND o.name = N'uspRebuildTenantAccessPolicy';

-- What this file changes about every script that comes after it, stated once, here, where somebody reading a deployment
-- transcript will see it.
INSERT @Report (Severity, Status, Item, Detail)
SELECT 3, 'PENDING', x.Item, x.Detail
  FROM (VALUES (N'Re-running 100, 065 or 030 now fails with error 3729'
              , N'A function bound by a security policy cannot be altered, and these predicates bind '
              + N'auth.ProfilePermissionScope, auth.TenantClosure and auth.Permission. Section 21.3: EXEC '
              + N'auth.uspRebuildTenantAccessPolicy @Action = N''Drop'', re-run the file, then re-run this one. '
              + N'Install-TemplateDatabase.ps1 does it in that order automatically.')
             , (N'Seeding or loading the demo tables now needs a bypass'
              , N'dbo.CaseFile and dbo.CaseNote are protected from this point on, including from the deploying account. '
              + N'A fixture or seed must either set SESSION_CONTEXT (''BypassRowSecurity'') or act as a profile that '
              + N'holds Data.Insert at the acting tenant. database/_tests/060_row_security.sql does both, deliberately.')
             , (N'115_seed_reference_data.sql must re-run this file'
              , N'T-089, Phase 6. The permission ids are literals in the deployed predicates, so a seed that adds an '
              + N'application without rebuilding leaves that application unable to read its own rows.')) AS x (Item, Detail);

IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
    PRINT N'Row-level security policy: PROBLEMS found. Read the report below before running the next script.';
ELSE
    PRINT N'Row-level security policy: no problems found. Items listed as PENDING are consequences, not defects.';

PRINT N'';

SELECT Severity, Status, Item, Detail
  FROM @Report
 ORDER BY Severity, RowNo;
GO
