/***********************************************************************************************************************
Script:         180_dbo_application_procedures.sql
Purpose:        The demonstration domain's calling surface, and the reference implementation of section 14's contract:
                dbo.uspCreateCaseFile, dbo.uspUpdateCaseFile, dbo.uspApproveCaseFile, dbo.uspReassignCaseFile,
                dbo.uspAddCaseNote, dbo.uspSoftDeleteCaseFile, dbo.uspRestoreCaseFile, the three reads
                dbo.uspGetCaseFile, dbo.uspListCaseFiles and dbo.uspListCaseNotes, and the one registered OPERATION
                dbo.uspCloseApprovedCaseFiles.
Target:         SQL Server 2022.
Run as:         db_owner in the target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/180_dbo_application_procedures.sql
Idempotent:     Yes.  CREATE OR ALTER throughout, and every grant guarded on DATABASE_PRINCIPAL_ID.
Depends on:     090_dbo_application.sql (dbo.CaseFile, dbo.CaseNote), 120_rls_policy.sql (the three predicates and the
                policy binding), 105_auth_session_procedures.sql (auth.uspSetSessionContext),
                150_auth_query_procedures.sql (auth.uspDemandPermission), 165_logs_procedures.sql
                (logs.uspRecordDataChange), 085_logs_auth_tables.sql (logs.DataChangeLog, which section 11 writes
                directly rather than through the recorder -- see its notes), scripts/logExecutionLogging.sql,
                templates/extended-properties.sql.
Implements:     T-102 and T-129.  DES-AUTH-001 sections 10.6, 14.1, 14.2, 14.3, 14.4, 14.6, 15.5, 17.
                Appendix B E-50200 to E-50209.  Gap G-45, closed by section 11.
                See docs/10-database-authn-authz-design.md.
To retarget:    Pass it per run:  sqlcmd -d <database> -v DbName=<database>.  There is no in-file default.

WHAT THIS FILE IS FOR, WHICH IS NOT THE CASE FILES
--------------------------------------------------
Nothing in this database needs a case file.  dbo.CaseFile and dbo.CaseNote exist so that the security model has something
ordinary to protect, and these eleven procedures exist so that a project starting from this template has a worked
example of
every rule section 14 states, in the smallest domain that can carry all of them.  A project deletes both tables and both
of these files and writes its own; what it copies is the SHAPE.

So the procedures are deliberately dull.  No paging DSL, no dynamic ORDER BY, no MERGE, no table-valued parameters, no
optional-parameter-catch-all WHERE clause.  Every one of those is a legitimate technique and every one of them would
obscure the thing this file is here to demonstrate.  What is worth copying is in the order of the statements, not in
their cleverness:

    1.  EXEC auth.uspSetSessionContext @SessionTokenHash   -- always first, never assumed (section 14.1, UI-05)
    2.  read the session's own values out of SESSION_CONTEXT
    3.  EXEC auth.uspDemandPermission                      -- once per distinct authority, BEFORE any transaction
    4.  validate the arguments and the target row, and THROW a branchable number
    5.  EXEC logs.uspStartExecutionLogging
    6.  BEGIN TRANSACTION
    7.  the one or two statements that are the actual work, with auditCreatedBy / auditModifiedBy set explicitly
    8.  EXEC logs.uspRecordDataChange                      -- the domain trail, inside the transaction
    9.  COMMIT, close the execution log row, and in the CATCH: rollback, re-open the log row, record, rethrow

Steps 3 and 4 are in that order on purpose and it is the one ordering decision here that is easy to get backwards.  See
"WHY THE PERMISSION IS DEMANDED BEFORE THE ROW IS LOOKED UP" below.

THERE IS NO @TenantId PARAMETER ON ANY OF THE WRITES, AND THAT IS P-06 RATHER THAN AN OMISSION
---------------------------------------------------------------------------------------------
A reader who has written multi-tenant procedures before will look for @TenantId on dbo.uspCreateCaseFile and not find it.
The tenant a row is created at is the session's ActingTenantId, read out of SESSION_CONTEXT, and it cannot be anything
else -- not because these procedures decline to offer the choice, but because auth.tvfTenantInsertPredicate refuses it:

    WHERE (@TenantId = TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT) AND EXISTS (... Data.Insert scope ...))

That equality is P-06, the one asymmetry in the whole scheme: a profile READS across its scope subtree and WRITES only at
the tenant it is acting for.  A parameter would therefore be a lie -- it could only ever be passed the value the session
already holds, and passing anything else would earn Msg 33504 from the block predicate rather than a useful error.  So
the procedures take the value from where it is true, and the update-shaped procedures take @CaseFileId alone and let the
filter predicate decide which one that is.

EVERY WRITE DEMANDS Data.Update AS WELL AS ITS OWN VERB, AND THIS IS THE FILE'S MOST IMPORTANT FINDING
----------------------------------------------------------------------------------------------------
Appendix A reads as though Data.Approve, Data.Reassign, Data.SoftDelete and Data.Restore are four independent
authorities.  On a table bound by 120_rls_policy.sql they are not, and the reason is structural rather than a matter of
taste.  The BLOCK BEFORE/AFTER UPDATE predicate is generated from the Data.Update rows of auth.Permission and from
nothing else.  Approving a case file is an UPDATE statement.  So a profile holding Data.Approve at a tenant, and NOT
holding Data.Update there, cannot approve anything: the statement is refused by the predicate, with

    Msg 33504 -- The attempted operation failed because the target object '...' has a block predicate that conflicts
                with this operation.

which is unbranchable, names an object rather than a permission, and tells the person at the screen nothing they can act
on.  Leaving that as the failure mode would have been the defect: an authorization decision surfacing as a plumbing
error.

So each of the four verb procedures demands TWO permissions, its own verb and Data.Update, in that order:

    EXEC auth.uspDemandPermission @PermissionCode = N'Data.Approve', @TenantId = @TenantId;
    EXEC auth.uspDemandPermission @PermissionCode = N'Data.Update',  @TenantId = @TenantId;

The caller who is missing either gets E-50030 naming the one they are missing, a logs.AuthorizationDenial row that says
which, and a sentence they can take to an administrator.  Section 14.2's "once per distinct authority it needs" is
satisfied literally -- this procedure genuinely needs both -- and the order puts the more specific verb first so that the
more informative refusal is the one raised.

The alternative, adding the four verbs to the UPDATE predicate's id list, was rejected: it would let a profile holding
only Data.Restore edit a title, because a block predicate cannot tell which columns a statement touched.  The asymmetry
is recorded as a gap against Appendix A rather than fixed here, because it is a documentation defect in the design and
not a defect in the model.

THE ELEVENTH PROCEDURE IS AN OPERATION, AND IT IS THE ONLY DEMANDER OF Data.Execute IN THE DATABASE
--------------------------------------------------------------------------------------------------
Ten of these procedures are the CRUD surface.  The eleventh, dbo.uspCloseApprovedCaseFiles, is not: it is a batch
close-out sweep, and it exists because Data.Execute had been seeded, granted to OPERATOR and to CRUD_ACCESS, and
demanded by nothing.  A permission no module demands is indistinguishable at run time from a permission that does not
exist -- it shows up in the role matrix, an administrator grants it believing it gates something, and it gates nothing.
That was gap G-45, and a caller is the only thing that closes it.  Documentation would not have.

It also demonstrates two things the other ten cannot, both of which bite the first time a project writes a batch job:

    A SET-BASED WRITE HAS A FAILURE MODE A SINGLETON WRITE DOES NOT.  The read predicate is built from the Data.Read
    rows and the update predicate from the Data.Update rows, over the same closure but not necessarily the same scope
    tenants.  A profile that may READ a child tenant's case files and may only EDIT its own therefore sees rows in a
    sweep's range that the BLOCK BEFORE UPDATE predicate refuses -- and a block predicate refuses the STATEMENT, so one
    unwritable row in five hundred rolls the whole batch back with Msg 33504.  Section 11 confines itself to
    SESSION_CONTEXT's ActingTenantId for that reason, which makes the demand it has already passed a proof that the
    predicate will permit every row it can touch.

    THE TRAIL FOR A SET IS ONE INSERT, NOT N CALLS.  logs.uspRecordDataChange says so in its own notes -- 'a set-based
    writer must not loop over it ... should INSERT into logs.DataChangeLog directly from its OUTPUT clause, which
    ownership chaining permits'.  Section 11 is the first caller in this template to take that route, and it is worth
    reading beside section 3 to see the two shapes side by side.

WHY THE PERMISSION IS DEMANDED BEFORE THE ROW IS LOOKED UP
---------------------------------------------------------
It would read more naturally to find the case file first, discover it does not exist, and say so without troubling the
authorization model.  That is the wrong order and it leaks.

A caller with no Data.Read scope at a tenant sees none of its rows -- the filter predicate has already removed them -- so
"not found" and "not yours" are the same answer to them, which is the point of E-50201.  But a caller with READ scope and
no UPDATE authority is a different case: look the row up first and the two failure modes become distinguishable, and the
procedure becomes an oracle that answers "does case 4471 exist at this tenant?" for anybody who may read.  Demanding
first means the answer to every unauthorized call is the same refusal regardless of what exists.

It also puts both refusals ahead of BEGIN TRANSACTION, which they must be for a second reason: auth.uspDemandPermission
writes a logs.AuthorizationDenial row and THEN throws.  Inside a transaction that row is rolled back with the statement
and the denial vanishes from the trail.  BL-042 and G-31.

E-50201 IS ONE NUMBER FOR TWO SITUATIONS, DELIBERATELY
-----------------------------------------------------
Every procedure here that takes @CaseFileId raises E-50201 when the id resolves to nothing, and the message says "no such
case file, or it is not yours to act on".  That is not laziness about error taxonomy; it is the only honest message the
procedure can produce.  Row-level security has already filtered dbo.CaseFile before the SELECT runs, so a row belonging
to another tenant is genuinely invisible to the lookup -- the procedure cannot tell the two apart, and a version that
could would be one that read around its own predicate.  Appendix B says this in terms and it is repeated in every
procedure's notes, because a maintainer's first instinct on seeing it will be to split it in two.

A SOFT DELETE IS ONE STATEMENT, AND THE TRIGGER DOES NOT HELP
-----------------------------------------------------------
CK_dbo_CaseFile_DeletedPair requires auditDeletedBy and auditDeletedDateUtc to be non-NULL whenever IsDeleted = 1, and
SQL Server evaluates CHECK constraints BEFORE an AFTER trigger fires.  So the obvious

    UPDATE dbo.CaseFile SET IsDeleted = 1 WHERE CaseFileId = @CaseFileId;

does not soft-delete anything and does not reach dbo.trg_au_updt_CaseFile.  It fails with Msg 547, measured rather than
assumed.  dbo.uspSoftDeleteCaseFile therefore sets all three columns in one statement, and dbo.uspRestoreCaseFile clears
all three in one statement, and the auditDeletedBy branch inside the audit triggers is unreachable backstop code that
nobody should rely on.  135_audit_triggers.sql knows about the split and reports it rather than demanding the branch;
090_dbo_application.sql says so beside both triggers.  This is the single easiest mistake to make in a project built from
this template, which is why it appears in four places.

THE THREE READS DEMAND NOTHING, AND RETURN AN EMPTY SET RATHER THAN AN ERROR
--------------------------------------------------------------------------
Section 14.2: for a read that returns a filtered set there is nothing to demand, because row-level security returns
exactly what the profile may see and an empty result is the correct answer for a profile with no read scope.  So
dbo.uspListCaseFiles and dbo.uspListCaseNotes call auth.uspSetSessionContext and then simply SELECT.  A profile with no
scope gets no rows and no exception, which is what a list screen wants.

dbo.uspGetCaseFile is the exception that proves the rule: it addresses ONE row by id, the caller has asserted that row
exists, and silence would be indistinguishable from a bug in the caller.  So it raises E-50201 on an empty lookup -- the
same conflated number, for the same reason.

All three are instrumented in the ERROR-ONLY shape of rule 8: logs.uspRecordExecutionError in the CATCH, no start row and
no completion update.  Reads are the most frequent calls in any application and a start row per read would make
logs.ExecutionLog a table about reading rather than a table about work.  auth.uspDemandPermission in
150_auth_query_procedures.sql documents the same reading of rule 8 at greater length.

WHAT PHASE 5 MEASURED HERE, AND THE ONE RULE IT PRODUCED
-------------------------------------------------------
The predicate costs in section 10.6 were measured on these two tables.  The number that matters to anybody writing more
of these procedures: a range scan of 1,000 rows with the predicate bound reads 1,007 pages against 6 unprotected, and an
aggregate over 200,000 rows reads 1,002,655 pages against 1,405 -- 714 times as many, for the same answer.  The plan is
already optimal (T-073 confirmed seeks on both inner tables and no scans), so no index fixes it.

The rule, which is why dbo.uspListCaseFiles takes a @TopN and why there is no dbo.uspGetCaseFileStatistics in this file:
PROTECTED TABLES ARE FOR FILTERED ACCESS, NOT FOR AGGREGATION.  A counts-by-status tile belongs in a summary table
maintained by a job that runs with BypassRowSecurity, or in a report reading a replica.  It does not belong in a
procedure that a user's request waits on.
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

IF OBJECT_ID (N'dbo.CaseFile', N'U') IS NULL OR OBJECT_ID (N'dbo.CaseNote', N'U') IS NULL
BEGIN
    DECLARE @MsgTables NVARCHAR (2000) =
        N'dbo.CaseFile or dbo.CaseNote is missing. Run database/090_dbo_application.sql first. If this project has '
      + N'deleted the demonstration domain -- which it is meant to be able to do -- delete this file too: it is the '
      + N'worked example of the section 14 contract against those two tables and has no other subject.';

    THROW 50000, @MsgTables, 1;
END
GO

IF OBJECT_ID (N'logs.uspStartExecutionLogging', N'P') IS NULL
   OR OBJECT_ID (N'logs.uspRecordExecutionError', N'P') IS NULL
BEGIN
    DECLARE @MsgLog NVARCHAR (2000) =
        N'The rule 8 instrumentation procedures are missing. Run scripts/logExecutionLogging.sql first: every procedure '
      + N'in this file is instrumented and cannot be created usefully without them.';

    THROW 50000, @MsgLog, 1;
END
GO

-- The security objects are a WARNING and not a refusal, for two different reasons.  Name resolution inside a procedure
-- body is deferred to first execution, so the file installs cleanly without them; and 120_rls_policy.sql runs AFTER this
-- file in the manifest, so on a first build the policy legitimately does not exist yet when these procedures are created.
IF OBJECT_ID (N'auth.uspSetSessionContext', N'P') IS NULL
   OR OBJECT_ID (N'auth.uspDemandPermission', N'P') IS NULL
   OR OBJECT_ID (N'logs.uspRecordDataChange', N'P') IS NULL
BEGIN
    PRINT N'WARNING: one or more of auth.uspSetSessionContext, auth.uspDemandPermission and logs.uspRecordDataChange is '
        + N'absent. The procedures in this file will be created -- name resolution is deferred -- but every call will '
        + N'fail until database/105, database/150 and database/165 have run.';
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.security_predicates AS sp
                WHERE sp.target_object_id = OBJECT_ID (N'dbo.CaseFile'))
BEGIN
    PRINT N'WARNING: dbo.CaseFile carries no security predicate. These procedures are written on the assumption that '
        + N'row-level security has already filtered the table before they look -- it is why E-50201 does not distinguish '
        + N'"not found" from "not yours", and why none of the writes takes a @TenantId. Until database/120_rls_policy.sql '
        + N'has run, every one of them is a cross-tenant read and write. This is expected on a first build, because 120 '
        + N'runs after this file; it is a defect at any other time.';
END
GO

-- *** 1. dbo.uspCreateCaseFile ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   dbo.uspCreateCaseFile
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Creates one case file at the session's ACTING tenant, in status 'draft', and returns its id.  Demands Data.Insert.
E-50206 on an empty @CaseNumber or @Title; E-50200 when @CaseNumber is already live at this tenant.

========================================================================================================================
Requirements and Key Dependencies:

dbo.CaseFile, auth.uspSetSessionContext, auth.uspDemandPermission, logs.uspRecordDataChange.
Granted to applicationRole.  DES-AUTH-001 sections 14.1, 14.2, 14.4, P-06.  Appendix B E-50200, E-50206.

========================================================================================================================
Notes:

NO @TenantId PARAMETER.  The tenant is SESSION_CONTEXT (N'ActingTenantId') and can be nothing else: P-06 puts an equality
against that value inside auth.tvfTenantInsertPredicate, so a parameter could only ever carry the value the session
already holds.  See the file header.

auditCreatedBy IS SET EXPLICITLY, not left to the DEFAULT.  Section 14.4 and UI-17.  The DEFAULT on the column reads the
session context too -- T-097 changed it so that a direct maintenance INSERT is attributed as well as this one -- but the
procedure naming the column is what the contract requires, and it keeps the attribution true if the DEFAULT is ever
simplified back.

E-50200 IS A PRE-CHECK OVER A UNIQUE INDEX, AND BOTH ARE NEEDED.  UX_dbo_CaseFile_Tenant_CaseNumber is the thing that
actually guarantees uniqueness; the SELECT here exists to turn its 2601 into a branchable number with a sentence the UI
can show.  The index is filtered on IsDeleted = 0, so a case number freed by a soft delete becomes available again --
which is why the pre-check filters the same way.  Between the check and the insert there is a window; the index closes it,
and a 2601 escaping this procedure means two users typed the same number in the same instant rather than that the check
is wrong.

WHY 'draft' IS NOT A PARAMETER.  CaseStatus has a DEFAULT of 'draft' and this procedure does not offer to override it. A
case file that can be created already approved would make CK_dbo_CaseFile_ApprovalPair and dbo.uspApproveCaseFile's
E-50202 both decorative: the status machine is owned by the procedures that advance it, and creation is its first state.

========================================================================================================================
Example Usage and Performance:

declare @id int;
exec dbo.uspCreateCaseFile @SessionTokenHash = 0x9F86..., @CaseNumber = N'2026-0184'
                         , @Title = N'Renewal review, R. Okonkwo', @AssignedToProfileId = 41, @CaseFileId = @id output;

One seek on the filtered unique index, one insert, one trail row.  Measured at 8 logical reads with the predicate bound
against 3 without it -- section 10.6.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-102
Description:
Created.  Phase 7.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE dbo.uspCreateCaseFile
      @SessionTokenHash    VARBINARY (32)
    , @CaseNumber          NVARCHAR (50)
    , @Title               NVARCHAR (400)
    , @AssignedToProfileId INT = NULL
    , @CaseFileId          INT = NULL OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[dbo].[uspCreateCaseFile]')
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

    DECLARE @Actor          NVARCHAR (255)  = NULL
          , @ActorProfileId INT             = NULL
          , @TenantId       INT             = NULL
          , @ChangeId       BIGINT          = NULL
          , @KeyJson        NVARCHAR (400)  = NULL
          , @Failure        NVARCHAR (2000) = NULL;

    SET @CaseNumber = TRIM (COALESCE (@CaseNumber, N''));
    SET @Title      = TRIM (COALESCE (@Title,      N''));

    SET @KeyParameters = CONCAT (N'CaseNumber=', @CaseNumber, N', TitleLength=', LEN (@Title)
                               , N', AssignedToProfileId='
                               , COALESCE (CAST (@AssignedToProfileId AS NVARCHAR (11)), N'(null)'));

    BEGIN TRY

        -- Session first, always, and never assumed from a previous call on this connection: Dapper's pool decides which
        -- physical connection this is and the application does not control the ordering.  Section 14.1, UI-05.
        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        SET @ActorProfileId = TRY_CAST (SESSION_CONTEXT (N'UserProfileId')  AS INT);
        SET @TenantId       = TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT);
        SET @Actor          = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                      , ORIGINAL_LOGIN ());

        -- Authority before arguments, and both before BEGIN TRANSACTION so the denial row survives its own refusal.
        EXEC auth.uspDemandPermission @PermissionCode = N'Data.Insert'
                                    , @TenantId       = @TenantId
                                    , @ObjectName     = N'dbo.uspCreateCaseFile';

        IF @CaseNumber = N'' OR @Title = N''
        BEGIN
            SET @Failure = N'A case file needs a case number and a title, and both must contain something other than '
                         + N'whitespace. CK_dbo_CaseFile_CaseNumber and CK_dbo_CaseFile_Title enforce it; this is the '
                         + N'number that says so in a sentence. Nothing was created.';
            ;THROW 50206, @Failure, 1;
        END;

        -- Filtered the same way as UX_dbo_CaseFile_Tenant_CaseNumber, so a number freed by a soft delete is available.
        -- The TenantId term is redundant under the filter predicate and is written anyway: it makes the index seek
        -- explicit and it keeps the statement correct if it is ever run with BypassRowSecurity set.
        IF EXISTS (SELECT 1
                     FROM dbo.CaseFile AS cf
                    WHERE cf.TenantId   = @TenantId
                      AND cf.CaseNumber = @CaseNumber
                      AND cf.IsDeleted  = 0)
        BEGIN
            SET @Failure = CONCAT (N'Case number ''', @CaseNumber, N''' is already in use at this tenant. Case numbers '
                                 , N'are unique per tenant and not per database -- two organizations number their own '
                                 , N'cases from 1 and both are right. Nothing was created.');
            ;THROW 50200, @Failure, 1;
        END;

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

        INSERT dbo.CaseFile (TenantId, CaseNumber, Title, CaseStatus, AssignedToProfileId, auditCreatedBy)
        VALUES (@TenantId, @CaseNumber, @Title, 'draft', @AssignedToProfileId, @Actor);

        -- SCOPE_IDENTITY () rather than @@IDENTITY, which would return the identity of any row an AFTER INSERT trigger
        -- elsewhere happened to write.  There is no such trigger on this table today; the habit is the point.
        SET @CaseFileId = CAST (SCOPE_IDENTITY () AS INT);

        -- The trail identifies the row by its KEY, not by its ordinal position in a result set, because the audit trail
        -- outlives the request that wrote it.  CK_logs_DataChangeLog_KeyJson requires valid JSON.
        SET @KeyJson = CONCAT (N'{"CaseFileId":', @CaseFileId, N',"TenantId":', @TenantId, N'}');

        EXEC logs.uspRecordDataChange
              @SchemaName         = N'dbo'
            , @TableName          = N'CaseFile'
            , @Operation          = 'Insert'
            , @KeyJson            = @KeyJson
            , @ChangedColumnsJson = NULL
            , @ActorUserProfileId = @ActorProfileId
            , @DataChangeLogId    = @ChangeId OUTPUT;

        SET @Comments = CONCAT (N'CaseFileId=', @CaseFileId, N' TenantId=', @TenantId, N' DataChangeLogId='
                              , COALESCE (CAST (@ChangeId AS NVARCHAR (20)), N'(null)'), N'.');

        -- =========================================================================================
        -- ===== End of the procedure's own work. ===================================================
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


-- *** 2. dbo.uspUpdateCaseFile ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   dbo.uspUpdateCaseFile
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Edits one case file's title and, optionally, moves it along the status machine.  Demands Data.Update.  E-50201 when the
id resolves to nothing, E-50206 on an empty @Title, E-50207 on a status this procedure does not own.  A NULL @CaseStatus
leaves the status alone, which is the common call.

========================================================================================================================
Requirements and Key Dependencies:

dbo.CaseFile, auth.uspSetSessionContext, auth.uspDemandPermission, logs.uspRecordDataChange.
Granted to applicationRole.  DES-AUTH-001 sections 14.1, 14.2, 14.4.  Appendix B E-50201, E-50206, E-50207.

========================================================================================================================
Notes:

'approved' IS NOT AVAILABLE HERE -- E-50207.  Approval writes ApprovedUtc and ApprovedByProfileId together, is immutable
once written (dbo.trg_au_updt_CaseFile raises E-50010), and demands a different authority.  Letting @CaseStatus carry
'approved' would make CK_dbo_CaseFile_ApprovalPair the only thing standing between a Data.Update holder and an approval
with no approver, and would route the one status transition anybody audits around the procedure that records it.
dbo.uspApproveCaseFile owns it.  'rejected' and the other five are ordinary.

THE UPDATE IS GUARDED ON IsDeleted = 0 IN ITS OWN WHERE CLAUSE, not only by the lookup above it.  Between the two there
is no transaction and no lock, so a concurrent soft delete can land in between; without the guard this procedure would
resurrect the row's Title on a deleted case file and leave the trail describing an edit nobody can see.  @@ROWCOUNT is
captured on the very next statement -- anything else resets it -- and a zero means exactly that race.

ONLY auditModifiedBy IS SET.  auditModifiedDateUtc is the AFTER UPDATE trigger's, and naming it here would be the one
place in the database where two statements compete to stamp the same column.  Section 14.4: the trigger already resolves
the actor correctly and the procedure supplies it explicitly so the value survives a trigger that is later simplified.

========================================================================================================================
Example Usage and Performance:

exec dbo.uspUpdateCaseFile @SessionTokenHash = 0x9F86..., @CaseFileId = 4471
                         , @Title = N'Renewal review, R. Okonkwo (consolidated)', @CaseStatus = 'open';

One seek on PK_dbo_CaseFile through the filter predicate, one narrow update, one trail row.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-102
Description:
Created.  Phase 7.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE dbo.uspUpdateCaseFile
      @SessionTokenHash VARBINARY (32)
    , @CaseFileId       INT
    , @Title            NVARCHAR (400)
    , @CaseStatus       VARCHAR (20) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[dbo].[uspUpdateCaseFile]')
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

    DECLARE @Actor          NVARCHAR (255)  = NULL
          , @ActorProfileId INT             = NULL
          , @TenantId       INT             = NULL
          , @OldTitle       NVARCHAR (400)  = NULL
          , @OldStatus      VARCHAR (20)    = NULL
          , @Rows           INT             = 0
          , @ChangeId       BIGINT          = NULL
          , @KeyJson        NVARCHAR (400)  = NULL
          , @ColumnsJson    NVARCHAR (MAX)  = NULL
          , @Failure        NVARCHAR (2000) = NULL;

    SET @Title      = TRIM (COALESCE (@Title, N''));
    SET @CaseStatus = NULLIF (TRIM (COALESCE (@CaseStatus, '')), '');

    SET @KeyParameters = CONCAT (N'CaseFileId=', @CaseFileId, N', TitleLength=', LEN (@Title), N', CaseStatus='
                               , COALESCE (@CaseStatus, N'(unchanged)'));

    BEGIN TRY

        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        SET @ActorProfileId = TRY_CAST (SESSION_CONTEXT (N'UserProfileId')  AS INT);
        SET @TenantId       = TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT);
        SET @Actor          = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                      , ORIGINAL_LOGIN ());

        EXEC auth.uspDemandPermission @PermissionCode = N'Data.Update'
                                    , @TenantId       = @TenantId
                                    , @ObjectName     = N'dbo.uspUpdateCaseFile';

        IF @Title = N''
        BEGIN
            SET @Failure = N'A case file needs a title containing something other than whitespace. '
                         + N'CK_dbo_CaseFile_Title enforces it; this is the number that says so in a sentence. Nothing '
                         + N'was changed.';
            ;THROW 50206, @Failure, 1;
        END;

        IF @CaseStatus IS NOT NULL
           AND @CaseStatus NOT IN ('draft', 'open', 'pending', 'rejected', 'closed', 'withdrawn')
        BEGIN
            SET @Failure = CONCAT (N'''', @CaseStatus, N''' is not a status this procedure can set. The permitted values '
                                 , N'are draft, open, pending, rejected, closed and withdrawn. ''approved'' is '
                                 , N'deliberately absent: an approval is a timestamp AND a person, it is immutable once '
                                 , N'written, and it demands Data.Approve -- so dbo.uspApproveCaseFile owns it. Anything '
                                 , N'else is not a status at all. Nothing was changed.');
            ;THROW 50207, @Failure, 1;
        END;

        -- Row-level security has already filtered the table, so a NULL here means "no such case file, or not yours" and
        -- the procedure genuinely cannot tell which.  See the file header.  E-50201.
        SELECT @OldTitle  = cf.Title
             , @OldStatus = cf.CaseStatus
          FROM dbo.CaseFile AS cf
         WHERE cf.CaseFileId = @CaseFileId
           AND cf.IsDeleted  = 0;

        IF @OldTitle IS NULL
        BEGIN
            SET @Failure = CONCAT (N'No case file ', @CaseFileId, N', or it is not yours to act on, or it has been '
                                 , N'deleted. These are deliberately one error: row-level security removed the other '
                                 , N'tenants'' rows before this procedure looked, so it cannot tell them apart -- and a '
                                 , N'version that could would be one that read around its own predicate. Nothing was '
                                 , N'changed.');
            ;THROW 50201, @Failure, 1;
        END;

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

        UPDATE cf
           SET cf.Title           = @Title
             , cf.CaseStatus      = COALESCE (@CaseStatus, cf.CaseStatus)
             , cf.auditModifiedBy = @Actor
          FROM dbo.CaseFile AS cf
         WHERE cf.CaseFileId = @CaseFileId
           AND cf.IsDeleted  = 0;

        SET @Rows = @@ROWCOUNT;

        IF @Rows = 0
        BEGIN
            SET @Failure = CONCAT (N'Case file ', @CaseFileId, N' was readable a moment ago and is not updatable now: '
                                 , N'somebody soft-deleted it between the lookup and the update. Nothing was changed. '
                                 , N'Re-read the case file and try again.');
            ;THROW 50201, @Failure, 1;
        END;

        SET @KeyJson     = CONCAT (N'{"CaseFileId":', @CaseFileId, N',"TenantId":', @TenantId, N'}');
        SET @ColumnsJson = CONCAT (N'{"Title":{"old":"', STRING_ESCAPE (@OldTitle, 'json')
                                 , N'","new":"', STRING_ESCAPE (@Title, 'json'), N'"}'
                                 , CASE WHEN @CaseStatus IS NOT NULL AND @CaseStatus <> @OldStatus
                                        THEN CONCAT (N',"CaseStatus":{"old":"', @OldStatus, N'","new":"', @CaseStatus
                                                   , N'"}')
                                        ELSE N''
                                   END
                                 , N'}');

        EXEC logs.uspRecordDataChange
              @SchemaName         = N'dbo'
            , @TableName          = N'CaseFile'
            , @Operation          = 'Update'
            , @KeyJson            = @KeyJson
            , @ChangedColumnsJson = @ColumnsJson
            , @ActorUserProfileId = @ActorProfileId
            , @DataChangeLogId    = @ChangeId OUTPUT;

        SET @Comments = CONCAT (N'CaseFileId=', @CaseFileId, N' StatusChanged='
                              , CASE WHEN @CaseStatus IS NOT NULL AND @CaseStatus <> @OldStatus THEN N'1' ELSE N'0' END
                              , N' DataChangeLogId=', COALESCE (CAST (@ChangeId AS NVARCHAR (20)), N'(null)'), N'.');

        -- =========================================================================================
        -- ===== End of the procedure's own work. ===================================================
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


-- *** 3. dbo.uspApproveCaseFile ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   dbo.uspApproveCaseFile
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Approves one case file: writes ApprovedUtc and ApprovedByProfileId together, sets CaseStatus to 'approved', and records
the decision in logs.DataChangeLog.  Demands Data.Approve AND Data.Update.  E-50201 when the id resolves to nothing,
E-50202 when it is already approved, E-50203 when the acting profile is not at the case file's own tenant.

========================================================================================================================
Requirements and Key Dependencies:

dbo.CaseFile, auth.uspSetSessionContext, auth.uspDemandPermission, logs.uspRecordDataChange.
Granted to applicationRole.  DES-AUTH-001 sections 14.1, 14.2, 14.4.  Appendix B E-50201, E-50202, E-50203.

========================================================================================================================
Notes:

TWO PERMISSIONS, IN THIS ORDER, AND THE SECOND ONE IS NOT DECORATION.  An approval is an UPDATE statement, and
auth.tvfTenantUpdatePredicate is generated from the Data.Update rows of auth.Permission alone.  A profile holding
Data.Approve and not Data.Update therefore cannot approve anything, and without the second demand it would find that out
as Msg 33504 from the block predicate -- a plumbing error naming an object instead of an authorization error naming a
permission.  Data.Approve is demanded first so that the more specific refusal is the one the caller sees.  The file header
argues this at length; it is the most easily missed consequence of binding a policy to a table.

E-50203 IS A DOCUMENTED WIDENING OF APPENDIX B.  Appendix B registers it against dbo.uspReassignCaseFile, for a target
profile that is not at the case file's tenant.  The identical structural fact applies to the approver:
FK_dbo_CaseFile_ApprovedBy_Tenant is on the composite pair (ApprovedByProfileId, TenantId), so a profile acting at a
PARENT tenant may legitimately read and edit a child tenant's case file -- read scope spans the subtree -- and still
cannot be recorded as its approver.  The fault class is the same, the sentence is the same with 'approver' in place of
'assignee', and the alternative is Msg 547 naming a foreign key.  Recorded as a gap rather than left silent, on the same
grounds as E-50062 in 155 and E-50084 in 160.

THE APPROVER IS THE SESSION, NOT A PARAMETER.  There is no @ApprovedByProfileId.  An approval that can name somebody
else is not an approval, dbo.trg_au_updt_CaseFile makes the column immutable once set (E-50010), and the whole reason the
column exists is to answer "who decided this".  @ApprovalNote is free prose for the trail and is escaped, not stored on
the row.

ALREADY-APPROVED IS E-50202 AND NOT AN IDEMPOTENT SUCCESS.  Everywhere else in this template a repeated call that changes
nothing succeeds quietly.  Not here: a second approval means two people believe they made this decision, and the second
one needs to be told that the first already did, with the first one's identity available to show them.

========================================================================================================================
Example Usage and Performance:

exec dbo.uspApproveCaseFile @SessionTokenHash = 0x9F86..., @CaseFileId = 4471
                          , @ApprovalNote = N'Documents verified against the register, 2026-09-20.';

One seek on PK_dbo_CaseFile through the filter predicate, one narrow update, one trail row.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-102
Description:
Created.  Phase 7.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE dbo.uspApproveCaseFile
      @SessionTokenHash VARBINARY (32)
    , @CaseFileId       INT
    , @ApprovalNote     NVARCHAR (500) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[dbo].[uspApproveCaseFile]')
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

    DECLARE @Actor          NVARCHAR (255)  = NULL
          , @ActorProfileId INT             = NULL
          , @ActingTenantId INT             = NULL
          , @RowTenantId    INT             = NULL
          , @ApprovedUtc    DATETIME2 (3)   = NULL
          , @ApprovedBy     INT             = NULL
          , @OldStatus      VARCHAR (20)    = NULL
          , @Now            DATETIME2 (3)   = NULL
          , @Rows           INT             = 0
          , @ChangeId       BIGINT          = NULL
          , @KeyJson        NVARCHAR (400)  = NULL
          , @ColumnsJson    NVARCHAR (MAX)  = NULL
          , @Failure        NVARCHAR (2000) = NULL;

    SET @KeyParameters = CONCAT (N'CaseFileId=', @CaseFileId, N', NoteLength='
                               , COALESCE (CAST (LEN (@ApprovalNote) AS NVARCHAR (11)), N'(null)'));

    BEGIN TRY

        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        SET @ActorProfileId = TRY_CAST (SESSION_CONTEXT (N'UserProfileId')  AS INT);
        SET @ActingTenantId = TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT);
        SET @Actor          = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                      , ORIGINAL_LOGIN ());

        -- The verb first, then the one the block predicate is actually built from.  See the notes.
        EXEC auth.uspDemandPermission @PermissionCode = N'Data.Approve'
                                    , @TenantId       = @ActingTenantId
                                    , @ObjectName     = N'dbo.uspApproveCaseFile';

        EXEC auth.uspDemandPermission @PermissionCode = N'Data.Update'
                                    , @TenantId       = @ActingTenantId
                                    , @ObjectName     = N'dbo.uspApproveCaseFile';

        SELECT @RowTenantId = cf.TenantId
             , @ApprovedUtc = cf.ApprovedUtc
             , @ApprovedBy  = cf.ApprovedByProfileId
             , @OldStatus   = cf.CaseStatus
          FROM dbo.CaseFile AS cf
         WHERE cf.CaseFileId = @CaseFileId
           AND cf.IsDeleted  = 0;

        IF @RowTenantId IS NULL
        BEGIN
            SET @Failure = CONCAT (N'No case file ', @CaseFileId, N', or it is not yours to act on, or it has been '
                                 , N'deleted. These are deliberately one error: row-level security removed the other '
                                 , N'tenants'' rows before this procedure looked, so it cannot tell them apart. Nothing '
                                 , N'was changed.');
            ;THROW 50201, @Failure, 1;
        END;

        IF @ApprovedUtc IS NOT NULL
        BEGIN
            SET @Failure = CONCAT (N'Case file ', @CaseFileId, N' was already approved on '
                                 , CONVERT (NVARCHAR (30), @ApprovedUtc, 126), N'Z by profile '
                                 , @ApprovedBy, N'. ApprovedByProfileId is written once and is immutable thereafter '
                                 , N'(E-50010): an approval that can be reattributed is not an approval. If the earlier '
                                 , N'decision was wrong, the case file has to be reopened deliberately and re-approved '
                                 , N'as a new decision. Nothing was changed.');
            ;THROW 50202, @Failure, 1;
        END;

        -- FK_dbo_CaseFile_ApprovedBy_Tenant is on the composite pair, so the approver's profile must be at the case
        -- file's OWN tenant -- which is not necessarily the tenant being acted for.  See the notes on E-50203.
        IF @RowTenantId <> @ActingTenantId
        BEGIN
            SET @Failure = CONCAT (N'Case file ', @CaseFileId, N' belongs to tenant ', @RowTenantId, N' and you are '
                                 , N'acting for tenant ', @ActingTenantId, N'. You may read and edit it -- read scope '
                                 , N'spans the subtree -- but the approver must be a profile AT the case file''s own '
                                 , N'tenant, because FK_dbo_CaseFile_ApprovedBy_Tenant is on the composite pair and an '
                                 , N'approval names a person in the organization that owns the case. Switch to a profile '
                                 , N'at that tenant and approve it there. Nothing was changed.');
            ;THROW 50203, @Failure, 1;
        END;

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

        SET @Now = SYSUTCDATETIME ();

        -- The ApprovedUtc IS NULL term is what makes this safe under concurrency: two callers who both passed the
        -- E-50202 check race here, and the loser updates nothing rather than overwriting the winner's attribution.
        UPDATE cf
           SET cf.ApprovedUtc         = @Now
             , cf.ApprovedByProfileId = @ActorProfileId
             , cf.CaseStatus          = 'approved'
             , cf.auditModifiedBy     = @Actor
          FROM dbo.CaseFile AS cf
         WHERE cf.CaseFileId  = @CaseFileId
           AND cf.IsDeleted   = 0
           AND cf.ApprovedUtc IS NULL;

        SET @Rows = @@ROWCOUNT;

        IF @Rows = 0
        BEGIN
            SET @Failure = CONCAT (N'Case file ', @CaseFileId, N' was unapproved a moment ago and is not now: another '
                                 , N'request approved or deleted it between the check and the update. Nothing was '
                                 , N'changed by this call. Re-read the case file.');
            ;THROW 50202, @Failure, 1;
        END;

        SET @KeyJson     = CONCAT (N'{"CaseFileId":', @CaseFileId, N',"TenantId":', @RowTenantId, N'}');
        SET @ColumnsJson = CONCAT (N'{"CaseStatus":{"old":"', @OldStatus, N'","new":"approved"}'
                                 , N',"ApprovedByProfileId":{"old":null,"new":', @ActorProfileId, N'}'
                                 , N',"ApprovedUtc":{"old":null,"new":"', CONVERT (NVARCHAR (30), @Now, 126), N'"}'
                                 , N',"note":'
                                 , COALESCE (N'"' + STRING_ESCAPE (@ApprovalNote, 'json') + N'"', N'null')
                                 , N'}');

        EXEC logs.uspRecordDataChange
              @SchemaName         = N'dbo'
            , @TableName          = N'CaseFile'
            , @Operation          = 'Update'
            , @KeyJson            = @KeyJson
            , @ChangedColumnsJson = @ColumnsJson
            , @ActorUserProfileId = @ActorProfileId
            , @DataChangeLogId    = @ChangeId OUTPUT;

        SET @Comments = CONCAT (N'CaseFileId=', @CaseFileId, N' ApprovedByProfileId=', @ActorProfileId
                              , N' DataChangeLogId=', COALESCE (CAST (@ChangeId AS NVARCHAR (20)), N'(null)'), N'.');

        -- =========================================================================================
        -- ===== End of the procedure's own work. ===================================================
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


-- *** 4. dbo.uspReassignCaseFile ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   dbo.uspReassignCaseFile
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Points one case file at a different profile, or at nobody when @AssignedToProfileId is NULL.  Demands Data.Reassign AND
Data.Update.  E-50201 when the id resolves to nothing, E-50203 when the target profile is not at the case file's tenant
or is not usable.

========================================================================================================================
Requirements and Key Dependencies:

dbo.CaseFile, auth.UserProfile, auth.uspSetSessionContext, auth.uspDemandPermission, logs.uspRecordDataChange.
Granted to applicationRole.  DES-AUTH-001 sections 14.1, 14.2, 14.4.  Appendix B E-50201, E-50203.

========================================================================================================================
Notes:

E-50203 EXISTS BECAUSE THE FOREIGN KEY CANNOT EXPLAIN ITSELF.  FK_dbo_CaseFile_AssignedTo_Tenant is on the composite pair
(AssignedToProfileId, TenantId), so a profile at another tenant is already structurally impossible -- the insert or update
would fail with Msg 547.  This procedure checks first so the caller gets a sentence about organizations instead of a
sentence about a constraint name.  The check is on the case file's TenantId, NOT on the acting tenant: reassigning a child
tenant's case file to one of that child's people is legitimate, and the assignment follows the case, not the actor.

UNASSIGNMENT IS A NULL, AND IT IS NOT AN ERROR.  A case file with no assignee is a queue item, which is the normal state
for a newly created one.  Passing NULL skips the profile lookup entirely, because there is nothing to look up and a
nullable foreign key permits it.

THE PROFILE MUST BE USABLE, NOT MERELY PRESENT.  A soft-deleted or inactive profile passes the foreign key and fails the
person: work assigned to somebody who cannot sign in is work nobody is doing.  auth.UserProfile.IsActive and IsDeleted are
both tested, and so is the owning auth.[User] -- a live profile belonging to a deactivated account is the same failure
wearing a different hat.  E-50203's Appendix B text says "or is unusable" and this is what that means.

REASSIGNING TO THE SAME PROFILE SUCCEEDS AND WRITES NO TRAIL ROW.  logs.DataChangeLog counts changes, not button presses.
@Reassigned reports 0 so the caller can tell the difference.

========================================================================================================================
Example Usage and Performance:

declare @changed bit;
exec dbo.uspReassignCaseFile @SessionTokenHash = 0x9F86..., @CaseFileId = 4471, @AssignedToProfileId = 58
                           , @Reassigned = @changed output;

One seek on PK_dbo_CaseFile through the filter predicate, one seek on auth.UserProfile, one narrow update.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-102
Description:
Created.  Phase 7.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE dbo.uspReassignCaseFile
      @SessionTokenHash    VARBINARY (32)
    , @CaseFileId          INT
    , @AssignedToProfileId INT = NULL
    , @Reassigned          BIT = NULL OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[dbo].[uspReassignCaseFile]')
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

    DECLARE @Actor          NVARCHAR (255)  = NULL
          , @ActorProfileId INT             = NULL
          , @ActingTenantId INT             = NULL
          , @RowTenantId    INT             = NULL
          , @OldAssignee    INT             = NULL
          , @TargetOk       BIT             = NULL
          , @Rows           INT             = 0
          , @ChangeId       BIGINT          = NULL
          , @KeyJson        NVARCHAR (400)  = NULL
          , @ColumnsJson    NVARCHAR (MAX)  = NULL
          , @Failure        NVARCHAR (2000) = NULL;

    SET @Reassigned    = 0;
    SET @KeyParameters = CONCAT (N'CaseFileId=', @CaseFileId, N', AssignedToProfileId='
                               , COALESCE (CAST (@AssignedToProfileId AS NVARCHAR (11)), N'(null, unassign)'));

    BEGIN TRY

        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        SET @ActorProfileId = TRY_CAST (SESSION_CONTEXT (N'UserProfileId')  AS INT);
        SET @ActingTenantId = TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT);
        SET @Actor          = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                      , ORIGINAL_LOGIN ());

        EXEC auth.uspDemandPermission @PermissionCode = N'Data.Reassign'
                                    , @TenantId       = @ActingTenantId
                                    , @ObjectName     = N'dbo.uspReassignCaseFile';

        EXEC auth.uspDemandPermission @PermissionCode = N'Data.Update'
                                    , @TenantId       = @ActingTenantId
                                    , @ObjectName     = N'dbo.uspReassignCaseFile';

        SELECT @RowTenantId = cf.TenantId
             , @OldAssignee = cf.AssignedToProfileId
          FROM dbo.CaseFile AS cf
         WHERE cf.CaseFileId = @CaseFileId
           AND cf.IsDeleted  = 0;

        IF @RowTenantId IS NULL
        BEGIN
            SET @Failure = CONCAT (N'No case file ', @CaseFileId, N', or it is not yours to act on, or it has been '
                                 , N'deleted. These are deliberately one error: row-level security removed the other '
                                 , N'tenants'' rows before this procedure looked, so it cannot tell them apart. Nothing '
                                 , N'was changed.');
            ;THROW 50201, @Failure, 1;
        END;

        -- Usable, not merely present: at the case file's own tenant, live, active, and owned by a live active account.
        IF @AssignedToProfileId IS NOT NULL
        BEGIN
            SELECT @TargetOk = 1
              FROM auth.UserProfile AS up
              JOIN auth.[User]      AS u ON u.UserId = up.UserId
             WHERE up.UserProfileId = @AssignedToProfileId
               AND up.TenantId      = @RowTenantId
               AND up.IsActive      = 1
               AND up.IsDeleted     = 0
               AND u.IsActive       = 1
               AND u.IsDeleted      = 0;

            IF @TargetOk IS NULL
            BEGIN
                SET @Failure = CONCAT (N'Profile ', @AssignedToProfileId, N' cannot take case file ', @CaseFileId
                                     , N'. Either it is not at tenant ', @RowTenantId, N' -- the case file''s own '
                                     , N'tenant, which FK_dbo_CaseFile_AssignedTo_Tenant enforces structurally through '
                                     , N'the composite pair -- or the profile or its account is inactive or deleted. '
                                     , N'Work assigned to somebody who cannot sign in is work nobody is doing. Nothing '
                                     , N'was changed.');
                ;THROW 50203, @Failure, 1;
            END;
        END;

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

        -- IS DISTINCT FROM rather than <>, because either side can be NULL and an unassignment of an already
        -- unassigned case file must compare equal rather than unknown.  SQL Server 2022.
        IF @AssignedToProfileId IS DISTINCT FROM @OldAssignee
        BEGIN
            UPDATE cf
               SET cf.AssignedToProfileId = @AssignedToProfileId
                 , cf.auditModifiedBy     = @Actor
              FROM dbo.CaseFile AS cf
             WHERE cf.CaseFileId = @CaseFileId
               AND cf.IsDeleted  = 0;

            SET @Rows = @@ROWCOUNT;

            IF @Rows = 0
            BEGIN
                SET @Failure = CONCAT (N'Case file ', @CaseFileId, N' was readable a moment ago and is not updatable '
                                     , N'now: somebody soft-deleted it between the lookup and the update. Nothing was '
                                     , N'changed. Re-read the case file and try again.');
                ;THROW 50201, @Failure, 1;
            END;

            SET @Reassigned  = 1;
            SET @KeyJson     = CONCAT (N'{"CaseFileId":', @CaseFileId, N',"TenantId":', @RowTenantId, N'}');
            SET @ColumnsJson = CONCAT (N'{"AssignedToProfileId":{"old":'
                                     , COALESCE (CAST (@OldAssignee AS NVARCHAR (11)), N'null')
                                     , N',"new":'
                                     , COALESCE (CAST (@AssignedToProfileId AS NVARCHAR (11)), N'null')
                                     , N'}}');

            EXEC logs.uspRecordDataChange
                  @SchemaName         = N'dbo'
                , @TableName          = N'CaseFile'
                , @Operation          = 'Update'
                , @KeyJson            = @KeyJson
                , @ChangedColumnsJson = @ColumnsJson
                , @ActorUserProfileId = @ActorProfileId
                , @DataChangeLogId    = @ChangeId OUTPUT;
        END;

        SET @Comments = CONCAT (N'CaseFileId=', @CaseFileId, N' Reassigned=', @Reassigned
                              , CASE WHEN @Reassigned = 1
                                     THEN CONCAT (N'. DataChangeLogId='
                                                , COALESCE (CAST (@ChangeId AS NVARCHAR (20)), N'(null)'), N'.')
                                     ELSE N'. Already assigned to that profile, so no row was written to '
                                        + N'logs.DataChangeLog: the trail counts changes, not button presses.'
                                END);

        -- =========================================================================================
        -- ===== End of the procedure's own work. ===================================================
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


-- *** 5. dbo.uspAddCaseNote ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   dbo.uspAddCaseNote
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Adds one note to a case file, authored by the session's own profile.  Demands Data.Insert.  E-50201 when the case file id
resolves to nothing, E-50204 when the case file is closed, E-50206 on empty @NoteText.

========================================================================================================================
Requirements and Key Dependencies:

dbo.CaseNote, dbo.CaseFile, auth.uspSetSessionContext, auth.uspDemandPermission, logs.uspRecordDataChange.
Granted to applicationRole.  DES-AUTH-001 sections 14.1, 14.2, 14.4, P-06.  Appendix B E-50201, E-50204, E-50206.

========================================================================================================================
Notes:

THE NOTE'S TenantId IS THE CASE FILE'S, AND IT IS ALSO THE SESSION'S, AND BOTH FACTS ARE LOAD-BEARING.
FK_dbo_CaseNote_CaseFile_Tenant is on the composite pair, so the note must carry the case file's tenant;
auth.tvfTenantInsertPredicate requires it to equal SESSION_CONTEXT (N'ActingTenantId') (P-06).  Together those mean a
note can only be added by somebody acting AT the case file's own tenant -- reading a child tenant's case file from the
parent is allowed, annotating it is not.  The refusal for that case is E-50201's cousin and is raised as E-50201 with a
message that says which of the two it was, because the row was found and the insert is the part that cannot proceed.

E-50204 IS ABOUT 'closed', NOT ABOUT IsDeleted.  A deleted case file is invisible to the lookup and produces E-50201; a
CLOSED one is perfectly visible and is a deliberate refusal.  Appendix B's note is the whole design: the common request is
to annotate a closed case, and the answer is to reopen it deliberately -- which is a Data.Update through
dbo.uspUpdateCaseFile and therefore leaves a trail -- rather than to let notes accumulate on a case nobody is reviewing.
'withdrawn' is treated the same way, for the same reason.

AuthoredByProfileId IS THE SESSION'S PROFILE AND NOT A PARAMETER, for the same reason ApprovedByProfileId is not one.  A
note whose author can be nominated by the caller is a note that proves nothing.

========================================================================================================================
Example Usage and Performance:

declare @noteId bigint;
exec dbo.uspAddCaseNote @SessionTokenHash = 0x9F86..., @CaseFileId = 4471
                      , @NoteText = N'Applicant telephoned; asked for an extension to 2026-10-15.', @IsInternal = 0
                      , @CaseNoteId = @noteId output;

One seek on PK_dbo_CaseFile through the filter predicate, one insert, one trail row.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-102
Description:
Created.  Phase 7.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE dbo.uspAddCaseNote
      @SessionTokenHash VARBINARY (32)
    , @CaseFileId       INT
    , @NoteText         NVARCHAR (MAX)
    , @IsInternal       BIT    = 0
    , @CaseNoteId       BIGINT = NULL OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[dbo].[uspAddCaseNote]')
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

    DECLARE @Actor          NVARCHAR (255)  = NULL
          , @ActorProfileId INT             = NULL
          , @ActingTenantId INT             = NULL
          , @RowTenantId    INT             = NULL
          , @CaseStatus     VARCHAR (20)    = NULL
          , @ChangeId       BIGINT          = NULL
          , @KeyJson        NVARCHAR (400)  = NULL
          , @Failure        NVARCHAR (2000) = NULL;

    SET @IsInternal = COALESCE (@IsInternal, 0);
    SET @KeyParameters = CONCAT (N'CaseFileId=', @CaseFileId, N', NoteLength='
                               , COALESCE (CAST (LEN (@NoteText) AS NVARCHAR (11)), N'(null)')
                               , N', IsInternal=', @IsInternal);

    BEGIN TRY

        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        SET @ActorProfileId = TRY_CAST (SESSION_CONTEXT (N'UserProfileId')  AS INT);
        SET @ActingTenantId = TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT);
        SET @Actor          = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                      , ORIGINAL_LOGIN ());

        EXEC auth.uspDemandPermission @PermissionCode = N'Data.Insert'
                                    , @TenantId       = @ActingTenantId
                                    , @ObjectName     = N'dbo.uspAddCaseNote';

        -- TRIM would not do here: NoteText is NVARCHAR (MAX) and CK_dbo_CaseNote_NoteText tests DATALENGTH, so the test
        -- has to be about whether anything other than whitespace was typed rather than about the stored length.
        IF @NoteText IS NULL OR LEN (TRIM (@NoteText)) = 0
        BEGIN
            SET @Failure = N'A note needs text containing something other than whitespace. CK_dbo_CaseNote_NoteText '
                         + N'enforces it; this is the number that says so in a sentence. Nothing was created.';
            ;THROW 50206, @Failure, 1;
        END;

        SELECT @RowTenantId = cf.TenantId
             , @CaseStatus  = cf.CaseStatus
          FROM dbo.CaseFile AS cf
         WHERE cf.CaseFileId = @CaseFileId
           AND cf.IsDeleted  = 0;

        IF @RowTenantId IS NULL
        BEGIN
            SET @Failure = CONCAT (N'No case file ', @CaseFileId, N', or it is not yours to act on, or it has been '
                                 , N'deleted. These are deliberately one error: row-level security removed the other '
                                 , N'tenants'' rows before this procedure looked, so it cannot tell them apart. Nothing '
                                 , N'was created.');
            ;THROW 50201, @Failure, 1;
        END;

        -- P-06: reading a descendant tenant's case file is allowed, writing at that tenant is not.  Caught here so the
        -- caller gets an explanation instead of Msg 33504 from auth.tvfTenantInsertPredicate.
        IF @RowTenantId <> @ActingTenantId
        BEGIN
            SET @Failure = CONCAT (N'Case file ', @CaseFileId, N' belongs to tenant ', @RowTenantId, N' and you are '
                                 , N'acting for tenant ', @ActingTenantId, N'. You may read it -- read scope spans the '
                                 , N'subtree -- but a note is written AT a tenant and P-06 permits writing only at the '
                                 , N'tenant you are acting for. Switch to a profile at that tenant. Nothing was created.');
            ;THROW 50201, @Failure, 1;
        END;

        IF @CaseStatus IN ('closed', 'withdrawn')
        BEGIN
            SET @Failure = CONCAT (N'Case file ', @CaseFileId, N' is ', @CaseStatus, N', so it takes no more notes. This '
                                 , N'is the common request and the answer is deliberate rather than obstructive: reopen '
                                 , N'the case with dbo.uspUpdateCaseFile -- which demands Data.Update and leaves a trail '
                                 , N'row saying who reopened it -- and then add the note. Letting notes accumulate on a '
                                 , N'case nobody is reviewing is how a file stops being a record of a decision. Nothing '
                                 , N'was created.');
            ;THROW 50204, @Failure, 1;
        END;

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

        INSERT dbo.CaseNote (TenantId, CaseFileId, NoteText, IsInternal, AuthoredByProfileId, auditCreatedBy)
        VALUES (@RowTenantId, @CaseFileId, @NoteText, @IsInternal, @ActorProfileId, @Actor);

        SET @CaseNoteId = CAST (SCOPE_IDENTITY () AS BIGINT);

        SET @KeyJson = CONCAT (N'{"CaseNoteId":', @CaseNoteId, N',"CaseFileId":', @CaseFileId, N',"TenantId":'
                             , @RowTenantId, N'}');

        EXEC logs.uspRecordDataChange
              @SchemaName         = N'dbo'
            , @TableName          = N'CaseNote'
            , @Operation          = 'Insert'
            , @KeyJson            = @KeyJson
            , @ChangedColumnsJson = NULL
            , @ActorUserProfileId = @ActorProfileId
            , @DataChangeLogId    = @ChangeId OUTPUT;

        SET @Comments = CONCAT (N'CaseNoteId=', @CaseNoteId, N' CaseFileId=', @CaseFileId, N' IsInternal=', @IsInternal
                              , N' DataChangeLogId=', COALESCE (CAST (@ChangeId AS NVARCHAR (20)), N'(null)'), N'.');

        -- =========================================================================================
        -- ===== End of the procedure's own work. ===================================================
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


-- *** 6. dbo.uspSoftDeleteCaseFile ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   dbo.uspSoftDeleteCaseFile
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Soft-deletes one case file: sets IsDeleted, auditDeletedBy and auditDeletedDateUtc in ONE statement, because a CHECK
constraint requires all three together.  Demands Data.SoftDelete AND Data.Update.  E-50201 when the id resolves to
nothing or has already been deleted.

========================================================================================================================
Requirements and Key Dependencies:

dbo.CaseFile, auth.uspSetSessionContext, auth.uspDemandPermission, logs.uspRecordDataChange.
Granted to applicationRole.  DES-AUTH-001 sections 14.1, 14.2, 14.4.  Appendix B E-50201.

========================================================================================================================
Notes:

THIS PROCEDURE IS THE REASON THE TEMPLATE SAYS "ONE STATEMENT" FOUR TIMES.  CK_dbo_CaseFile_DeletedPair requires
auditDeletedBy and auditDeletedDateUtc to be non-NULL whenever IsDeleted = 1, and SQL Server evaluates CHECK constraints
BEFORE an AFTER trigger fires.  So the obvious  UPDATE dbo.CaseFile SET IsDeleted = 1  fails with Msg 547 and never
reaches dbo.trg_au_updt_CaseFile, whose soft-delete branch looks exactly like the thing that would have handled it.  The
UPDATE below sets all three columns at once.  That is not a workaround; it is the only shape that works, and it is why
135_audit_triggers.sql reports the trigger as CALLER rather than demanding a branch it can never execute.

NO DELETE STATEMENT EXISTS ANYWHERE, AND applicationRole HAS NO DELETE ON SCHEMA::dbo.  170_permissions.sql grants SELECT,
INSERT and UPDATE there and deliberately not DELETE; the absence of that verb is what makes deletion in this design a soft
delete rather than a convention people mean to follow.

THE NOTES ARE NOT CASCADED, AND THAT IS A DECISION RATHER THAN AN OVERSIGHT.  Cascading would make restore lossy: after
soft-deleting five notes along with the case file there is no way to tell them from the two notes somebody had already
deleted individually, so dbo.uspRestoreCaseFile would either resurrect those two or leave the five deleted.  Instead the
case file's own IsDeleted is the gate -- dbo.uspListCaseNotes joins through it, so a deleted case file's notes disappear
from every read and come back intact on restore.  A project that genuinely wants a cascade needs a second column
recording WHY each note was deleted, and that is a domain decision this template should not make for it.

TWO PERMISSIONS, FOR THE REASON IN THE FILE HEADER: the deletion is an UPDATE and the BLOCK predicate is generated from
Data.Update alone, so Data.SoftDelete on its own would earn Msg 33504 rather than a refusal anybody can read.

========================================================================================================================
Example Usage and Performance:

exec dbo.uspSoftDeleteCaseFile @SessionTokenHash = 0x9F86..., @CaseFileId = 4471
                             , @Reason = N'Duplicate of 2026-0179, confirmed with the applicant.';

One seek on PK_dbo_CaseFile through the filter predicate, one narrow update, one trail row.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-102
Description:
Created.  Phase 7.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE dbo.uspSoftDeleteCaseFile
      @SessionTokenHash VARBINARY (32)
    , @CaseFileId       INT
    , @Reason           NVARCHAR (500) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[dbo].[uspSoftDeleteCaseFile]')
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

    DECLARE @Actor          NVARCHAR (255)  = NULL
          , @ActorProfileId INT             = NULL
          , @ActingTenantId INT             = NULL
          , @RowTenantId    INT             = NULL
          , @CaseNumber     NVARCHAR (50)   = NULL
          , @Now            DATETIME2 (3)   = NULL
          , @Rows           INT             = 0
          , @ChangeId       BIGINT          = NULL
          , @KeyJson        NVARCHAR (400)  = NULL
          , @ColumnsJson    NVARCHAR (MAX)  = NULL
          , @Failure        NVARCHAR (2000) = NULL;

    SET @KeyParameters = CONCAT (N'CaseFileId=', @CaseFileId, N', ReasonLength='
                               , COALESCE (CAST (LEN (@Reason) AS NVARCHAR (11)), N'(null)'));

    BEGIN TRY

        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        SET @ActorProfileId = TRY_CAST (SESSION_CONTEXT (N'UserProfileId')  AS INT);
        SET @ActingTenantId = TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT);
        SET @Actor          = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                      , ORIGINAL_LOGIN ());

        EXEC auth.uspDemandPermission @PermissionCode = N'Data.SoftDelete'
                                    , @TenantId       = @ActingTenantId
                                    , @ObjectName     = N'dbo.uspSoftDeleteCaseFile';

        EXEC auth.uspDemandPermission @PermissionCode = N'Data.Update'
                                    , @TenantId       = @ActingTenantId
                                    , @ObjectName     = N'dbo.uspSoftDeleteCaseFile';

        SELECT @RowTenantId = cf.TenantId
             , @CaseNumber  = cf.CaseNumber
          FROM dbo.CaseFile AS cf
         WHERE cf.CaseFileId = @CaseFileId
           AND cf.IsDeleted  = 0;

        IF @RowTenantId IS NULL
        BEGIN
            SET @Failure = CONCAT (N'No case file ', @CaseFileId, N', or it is not yours to act on, or it has already '
                                 , N'been deleted. These are deliberately one error: row-level security removed the '
                                 , N'other tenants'' rows before this procedure looked, so it cannot tell them apart. '
                                 , N'Nothing was changed.');
            ;THROW 50201, @Failure, 1;
        END;

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

        SET @Now = SYSUTCDATETIME ();

        -- ALL THREE COLUMNS IN ONE STATEMENT.  See the notes: CK_dbo_CaseFile_DeletedPair is evaluated before the AFTER
        -- UPDATE trigger, so setting IsDeleted alone and leaving the stamp to the trigger fails with Msg 547.
        UPDATE cf
           SET cf.IsDeleted           = 1
             , cf.auditDeletedBy      = @Actor
             , cf.auditDeletedDateUtc = @Now
             , cf.auditModifiedBy     = @Actor
          FROM dbo.CaseFile AS cf
         WHERE cf.CaseFileId = @CaseFileId
           AND cf.IsDeleted  = 0;

        SET @Rows = @@ROWCOUNT;

        IF @Rows = 0
        BEGIN
            SET @Failure = CONCAT (N'Case file ', @CaseFileId, N' was live a moment ago and is not now: another request '
                                 , N'deleted it between the lookup and the update. Nothing was changed by this call.');
            ;THROW 50201, @Failure, 1;
        END;

        SET @KeyJson     = CONCAT (N'{"CaseFileId":', @CaseFileId, N',"TenantId":', @RowTenantId, N'}');
        SET @ColumnsJson = CONCAT (N'{"IsDeleted":{"old":0,"new":1}'
                                 , N',"CaseNumber":"', STRING_ESCAPE (@CaseNumber, 'json'), N'"'
                                 , N',"reason":', COALESCE (N'"' + STRING_ESCAPE (@Reason, 'json') + N'"', N'null')
                                 , N'}');

        EXEC logs.uspRecordDataChange
              @SchemaName         = N'dbo'
            , @TableName          = N'CaseFile'
            , @Operation          = 'SoftDelete'
            , @KeyJson            = @KeyJson
            , @ChangedColumnsJson = @ColumnsJson
            , @ActorUserProfileId = @ActorProfileId
            , @DataChangeLogId    = @ChangeId OUTPUT;

        SET @Comments = CONCAT (N'CaseFileId=', @CaseFileId, N' CaseNumber=', @CaseNumber, N' DataChangeLogId='
                              , COALESCE (CAST (@ChangeId AS NVARCHAR (20)), N'(null)')
                              , N'. The case number is now free for re-use at this tenant: '
                              , N'UX_dbo_CaseFile_Tenant_CaseNumber is filtered on IsDeleted = 0.');

        -- =========================================================================================
        -- ===== End of the procedure's own work. ===================================================
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


-- *** 7. dbo.uspRestoreCaseFile ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   dbo.uspRestoreCaseFile
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Undoes a soft delete: clears IsDeleted, auditDeletedBy and auditDeletedDateUtc in ONE statement.  Demands Data.Restore AND
Data.Update.  E-50205 when the row is not deleted, so there is nothing to restore; E-50200 when the case number has been
re-used at this tenant while the row was away.

========================================================================================================================
Requirements and Key Dependencies:

dbo.CaseFile, auth.uspSetSessionContext, auth.uspDemandPermission, logs.uspRecordDataChange.
Granted to applicationRole.  DES-AUTH-001 sections 14.1, 14.2, 14.4.  Appendix B E-50200, E-50205.

========================================================================================================================
Notes:

IT HAS TO READ AROUND THE FILTER PREDICATE TO SEE ITS OWN TARGET, AND IT DOES NOT.  A soft-deleted row is still visible to
auth.tvfTenantReadPredicate -- the predicate is about TENANCY, not about deletion, and nothing in it mentions IsDeleted.
So this procedure's lookup finds the row for the same reason every other procedure's lookup does, and no bypass is needed
anywhere.  That is worth stating because it is the first thing a reader suspects.

E-50205 RATHER THAN A SILENT SUCCESS, and the reason is in Appendix B: Data.Restore is a separate permission from
Data.SoftDelete, so a caller exercising it on a row that was never deleted has misunderstood the state of the record.  A
quiet success would let a UI show "restored" for a case file nobody had deleted.

E-50200 IS RAISED ON THE WAY BACK IN, AND IT IS NOT A THEORETICAL CASE.  UX_dbo_CaseFile_Tenant_CaseNumber is filtered on
IsDeleted = 0, which is what frees a case number when a case file is deleted.  If somebody has since created a new case
file with that number, restoring this one would violate the index -- and the caller needs to be told that the number is
taken rather than shown a 2601.  The remedy is a domain decision (renumber one of them), so the procedure refuses and says
which number is in the way.

ALL THREE COLUMNS AGAIN, IN ONE STATEMENT.  CK_dbo_CaseFile_DeletedPair forbids the intermediate state in BOTH directions:
clearing IsDeleted while leaving auditDeletedBy set fails exactly as setting it while leaving auditDeletedBy NULL does.

WHAT IS DELIBERATELY LOST.  The restore clears the deletion stamp, so who deleted the case file and when survives only in
logs.DataChangeLog -- which is precisely what that table is for.  A project wanting the previous deletion visible on the
row needs a history table, not two more columns.

========================================================================================================================
Example Usage and Performance:

exec dbo.uspRestoreCaseFile @SessionTokenHash = 0x9F86..., @CaseFileId = 4471;

Two seeks on dbo.CaseFile -- the row, then the case-number collision -- one narrow update, one trail row.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-102
Description:
Created.  Phase 7.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE dbo.uspRestoreCaseFile
      @SessionTokenHash VARBINARY (32)
    , @CaseFileId       INT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[dbo].[uspRestoreCaseFile]')
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

    DECLARE @Actor          NVARCHAR (255)  = NULL
          , @ActorProfileId INT             = NULL
          , @ActingTenantId INT             = NULL
          , @RowTenantId    INT             = NULL
          , @IsDeleted      BIT             = NULL
          , @CaseNumber     NVARCHAR (50)   = NULL
          , @DeletedBy      NVARCHAR (255)  = NULL
          , @Rows           INT             = 0
          , @ChangeId       BIGINT          = NULL
          , @KeyJson        NVARCHAR (400)  = NULL
          , @ColumnsJson    NVARCHAR (MAX)  = NULL
          , @Failure        NVARCHAR (2000) = NULL;

    SET @KeyParameters = CONCAT (N'CaseFileId=', @CaseFileId);

    BEGIN TRY

        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        SET @ActorProfileId = TRY_CAST (SESSION_CONTEXT (N'UserProfileId')  AS INT);
        SET @ActingTenantId = TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT);
        SET @Actor          = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                      , ORIGINAL_LOGIN ());

        EXEC auth.uspDemandPermission @PermissionCode = N'Data.Restore'
                                    , @TenantId       = @ActingTenantId
                                    , @ObjectName     = N'dbo.uspRestoreCaseFile';

        EXEC auth.uspDemandPermission @PermissionCode = N'Data.Update'
                                    , @TenantId       = @ActingTenantId
                                    , @ObjectName     = N'dbo.uspRestoreCaseFile';

        -- No IsDeleted filter: a deleted row is still inside the tenancy predicate, which is about tenancy alone.
        SELECT @RowTenantId = cf.TenantId
             , @IsDeleted   = cf.IsDeleted
             , @CaseNumber  = cf.CaseNumber
             , @DeletedBy   = cf.auditDeletedBy
          FROM dbo.CaseFile AS cf
         WHERE cf.CaseFileId = @CaseFileId;

        IF @RowTenantId IS NULL
        BEGIN
            SET @Failure = CONCAT (N'No case file ', @CaseFileId, N', or it is not yours to act on. These are '
                                 , N'deliberately one error: row-level security removed the other tenants'' rows before '
                                 , N'this procedure looked, so it cannot tell them apart. Nothing was changed.');
            ;THROW 50201, @Failure, 1;
        END;

        IF @IsDeleted = 0
        BEGIN
            SET @Failure = CONCAT (N'Case file ', @CaseFileId, N' is not deleted, so there is nothing to restore. '
                                 , N'Data.Restore is a separate permission from Data.SoftDelete and this refusal is '
                                 , N'what keeps the trail honest about which one was exercised. Nothing was changed.');
            ;THROW 50205, @Failure, 1;
        END;

        -- The number was freed by the deletion, because the unique index is filtered on IsDeleted = 0.  Somebody may
        -- have taken it since.
        IF EXISTS (SELECT 1
                     FROM dbo.CaseFile AS cf
                    WHERE cf.TenantId   = @RowTenantId
                      AND cf.CaseNumber = @CaseNumber
                      AND cf.IsDeleted  = 0)
        BEGIN
            SET @Failure = CONCAT (N'Case file ', @CaseFileId, N' cannot be restored because its case number '''
                                 , @CaseNumber, N''' has been re-used at this tenant since it was deleted. Deleting a '
                                 , N'case file frees its number -- UX_dbo_CaseFile_Tenant_CaseNumber is filtered on '
                                 , N'IsDeleted = 0 -- and one of the two now has to be renumbered, which is a decision '
                                 , N'for a person and not for this procedure. Nothing was changed.');
            ;THROW 50200, @Failure, 1;
        END;

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

        -- All three, again, and for the same reason: the CHECK constraint forbids the half-way state in both directions.
        UPDATE cf
           SET cf.IsDeleted           = 0
             , cf.auditDeletedBy      = NULL
             , cf.auditDeletedDateUtc = NULL
             , cf.auditModifiedBy     = @Actor
          FROM dbo.CaseFile AS cf
         WHERE cf.CaseFileId = @CaseFileId
           AND cf.IsDeleted  = 1;

        SET @Rows = @@ROWCOUNT;

        IF @Rows = 0
        BEGIN
            SET @Failure = CONCAT (N'Case file ', @CaseFileId, N' was deleted a moment ago and is not now: another '
                                 , N'request restored it between the check and the update. Nothing was changed by this '
                                 , N'call.');
            ;THROW 50205, @Failure, 1;
        END;

        SET @KeyJson     = CONCAT (N'{"CaseFileId":', @CaseFileId, N',"TenantId":', @RowTenantId, N'}');
        SET @ColumnsJson = CONCAT (N'{"IsDeleted":{"old":1,"new":0}'
                                 , N',"clearedDeletedBy":'
                                 , COALESCE (N'"' + STRING_ESCAPE (@DeletedBy, 'json') + N'"', N'null')
                                 , N'}');

        EXEC logs.uspRecordDataChange
              @SchemaName         = N'dbo'
            , @TableName          = N'CaseFile'
            , @Operation          = 'Restore'
            , @KeyJson            = @KeyJson
            , @ChangedColumnsJson = @ColumnsJson
            , @ActorUserProfileId = @ActorProfileId
            , @DataChangeLogId    = @ChangeId OUTPUT;

        SET @Comments = CONCAT (N'CaseFileId=', @CaseFileId, N' CaseNumber=', @CaseNumber, N' DataChangeLogId='
                              , COALESCE (CAST (@ChangeId AS NVARCHAR (20)), N'(null)')
                              , N'. The previous deletion stamp is cleared from the row and survives only in '
                              , N'logs.DataChangeLog, which is what that table is for.');

        -- =========================================================================================
        -- ===== End of the procedure's own work. ===================================================
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


-- *** 8. dbo.uspGetCaseFile ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   dbo.uspGetCaseFile
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Returns one case file by id, with the assignee's and approver's profile names resolved.  Demands nothing: row-level
security decides whether the row is visible.  E-50201 when it is not.

========================================================================================================================
Requirements and Key Dependencies:

dbo.CaseFile, auth.UserProfile, auth.uspSetSessionContext.  Error-only instrumented -- logs.uspRecordExecutionError, NOT
logs.uspStartExecutionLogging.  Granted to applicationRole.  DES-AUTH-001 sections 14.1, 14.2, 14.6.  Appendix B E-50201.

========================================================================================================================
Notes:

IT DEMANDS NOTHING AND IT IS STILL NOT AN OPEN DOOR.  Section 14.2: a read whose result is filtered by the predicate has
nothing to demand, because the predicate has already answered the question.  A profile with no Data.Read scope at this
case file's tenant does not see the row and therefore gets E-50201 -- which is the same answer it gets for a case file that
does not exist, and the reason those are one number.

THE ONE READ THAT RAISES RATHER THAN RETURNING NOTHING.  A list returning zero rows is a correct answer; a point read by
id returning zero rows is indistinguishable from a bug in the caller, which is why this one throws and the two list
procedures below do not.

THE TWO JOINS ARE LEFT JOINS TO auth.UserProfile, WHICH IS NOT POLICY-BOUND.  Only dbo.CaseFile and dbo.CaseNote carry
predicates, so the profile names resolve without a second predicate evaluation -- and there is no leak in that, because the
profile ids reached here came out of a row the predicate already released.  INV-11 keeps applicationRole away from
auth.UserProfile directly; this procedure reaches it by ownership chaining.

NO SELECT *.  Dapper maps by column name and a widened table would silently start returning columns the DTO does not
have -- or, worse, would start returning one it does.  Section 14.6.

========================================================================================================================
Example Usage and Performance:

exec dbo.uspGetCaseFile @SessionTokenHash = 0x9F86..., @CaseFileId = 4471;

Measured at 8 logical reads with the predicate bound against 3 without it: 2.5 times the cost of an unprotected point
read, which is the price of the model and is cheap at this shape.  Section 10.6.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-102
Description:
Created.  Phase 7.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE dbo.uspGetCaseFile
      @SessionTokenHash VARBINARY (32)
    , @CaseFileId       INT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation, READ variant: error-only. No start row is opened.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[dbo].[uspGetCaseFile]')
          , @KeyParameters  NVARCHAR (MAX) = NULL
          , @ContextMessage NVARCHAR (MAX) = NULL
          , @DynamicSql     NVARCHAR (MAX) = NULL
          , @ErrorMsg       NVARCHAR (MAX) = NULL
          , @ErrorProc      NVARCHAR (300) = NULL
          , @ErrorNumber    INT            = NULL
          , @ErrorLine      INT            = NULL;

    DECLARE @Failure NVARCHAR (2000) = NULL;

    SET @KeyParameters  = CONCAT (N'CaseFileId=', @CaseFileId, N', SessionTokenHash=(32 bytes, not logged)');
    SET @ContextMessage = N'Error-only instrumented read: no start row is opened, so @ExecutionLogId is NULL by design.';

    BEGIN TRY

        -- =========================================================================================
        -- ===== The procedure's own work starts here. Everything above and below is boilerplate. ==
        -- =========================================================================================

        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        IF NOT EXISTS (SELECT 1
                         FROM dbo.CaseFile AS cf
                        WHERE cf.CaseFileId = @CaseFileId
                          AND cf.IsDeleted  = 0)
        BEGIN
            SET @Failure = CONCAT (N'No case file ', @CaseFileId, N', or it is not yours to read, or it has been '
                                 , N'deleted. These are deliberately one error: row-level security removed the other '
                                 , N'tenants'' rows before this procedure looked, so it cannot tell them apart.');
            ;THROW 50201, @Failure, 1;
        END;

        SELECT CaseFileId          = cf.CaseFileId
             , TenantId            = cf.TenantId
             , CaseNumber          = cf.CaseNumber
             , Title               = cf.Title
             , CaseStatus          = cf.CaseStatus
             , AssignedToProfileId = cf.AssignedToProfileId
             , AssignedToName      = asg.ProfileName
             , OpenedUtc           = cf.OpenedUtc
             , ClosedUtc           = cf.ClosedUtc
             , ApprovedUtc         = cf.ApprovedUtc
             , ApprovedByProfileId = cf.ApprovedByProfileId
             , ApprovedByName      = apr.ProfileName
             , NoteCount           = (SELECT COUNT (*)
                                        FROM dbo.CaseNote AS cn
                                       WHERE cn.CaseFileId = cf.CaseFileId
                                         AND cn.IsDeleted  = 0)
             , auditCreatedBy       = cf.auditCreatedBy
             , auditCreatedDateUtc  = cf.auditCreatedDateUtc
             , auditModifiedBy      = cf.auditModifiedBy
             , auditModifiedDateUtc = cf.auditModifiedDateUtc
          FROM dbo.CaseFile         AS cf
          LEFT JOIN auth.UserProfile AS asg ON asg.UserProfileId = cf.AssignedToProfileId
          LEFT JOIN auth.UserProfile AS apr ON apr.UserProfileId = cf.ApprovedByProfileId
         WHERE cf.CaseFileId = @CaseFileId
           AND cf.IsDeleted  = 0;

        -- =========================================================================================
        -- ===== End of the procedure's own work. ===================================================
        -- =========================================================================================

    END TRY
    BEGIN CATCH

        SELECT @ErrorNumber = ERROR_NUMBER ()
             , @ErrorProc   = ERROR_PROCEDURE ()
             , @ErrorLine   = ERROR_LINE ()
             , @ErrorMsg    = ERROR_MESSAGE ()
                            + N' (error '  + CAST (ERROR_NUMBER () AS NVARCHAR (11))
                            + N', line '   + CAST (ERROR_LINE ()   AS NVARCHAR (11)) + N')';

        EXEC logs.uspRecordExecutionError
              @ProcedureName   = @ProcName
            , @KeyParameters   = @KeyParameters
            , @ExecutionLogId  = NULL
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


-- *** 9. dbo.uspListCaseFiles ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   dbo.uspListCaseFiles
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Returns the case files the session's profile may see, newest first, optionally narrowed to one status or one assignee, and
capped at @TopN rows.  Demands nothing and raises nothing: an empty set is the correct answer for a profile with no read
scope.

========================================================================================================================
Requirements and Key Dependencies:

dbo.CaseFile, auth.UserProfile, auth.uspSetSessionContext.  Error-only instrumented.  Granted to applicationRole.
DES-AUTH-001 sections 10.6, 14.1, 14.2, 14.6.

========================================================================================================================
Notes:

@TopN IS MANDATORY IN SPIRIT AND DEFAULTED TO 200, AND IT IS THE PHASE 5 MEASUREMENT WEARING A PARAMETER.  Section 10.6:
with the predicate bound, a 1,000-row range scan reads 1,007 pages against 6 unprotected, and an unbounded aggregate over
200,000 rows reads 1,002,655.  The plan is already optimal -- T-073 confirmed index seeks on both inner tables and no
scans -- so the only lever left is the number of rows the caller asks for.  A screen that needs page 40 of 8,000 case files
needs a different design, not a bigger @TopN.

THE ROWS RETURNED SPAN THE PROFILE'S WHOLE SCOPE SUBTREE, NOT JUST THE ACTING TENANT.  That asymmetry is P-06 and it is the
point of the closure table: a regional manager reads every office beneath them and writes only at their own.  TenantId is
returned so the UI can show which organization each row belongs to; a list that silently mixes tenants without saying so
is how a user comes to believe a case is theirs.

NO DYNAMIC SQL AND NO DYNAMIC ORDER BY.  The two optional filters are ordinary  (@x IS NULL OR col = @x)  terms.  That
shape can produce a plan tuned for one parameter and reused for the other; at the row counts a bounded list returns it does
not matter, and the alternative -- building the statement as text -- would put a caller-supplied string into a procedure
whose whole purpose is to demonstrate that callers cannot reach the tables.  If a project's list screen outgrows this, the
answer is OPTION (RECOMPILE) on a measured statement, stated deliberately.

========================================================================================================================
Example Usage and Performance:

exec dbo.uspListCaseFiles @SessionTokenHash = 0x9F86..., @CaseStatus = 'open', @TopN = 50;

One seek per tenant in scope on IX_dbo_CaseFile_Tenant_Status, then a sort.  Measured cost is linear in the rows returned
and in the size of auth.ProfilePermissionScope -- section 10.6.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-102
Description:
Created.  Phase 7.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE dbo.uspListCaseFiles
      @SessionTokenHash    VARBINARY (32)
    , @CaseStatus          VARCHAR (20) = NULL
    , @AssignedToProfileId INT          = NULL
    , @TopN                INT          = 200
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation, READ variant: error-only. No start row is opened.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[dbo].[uspListCaseFiles]')
          , @KeyParameters  NVARCHAR (MAX) = NULL
          , @ContextMessage NVARCHAR (MAX) = NULL
          , @DynamicSql     NVARCHAR (MAX) = NULL
          , @ErrorMsg       NVARCHAR (MAX) = NULL
          , @ErrorProc      NVARCHAR (300) = NULL
          , @ErrorNumber    INT            = NULL
          , @ErrorLine      INT            = NULL;

    -- GREATEST and LEAST rather than a THROW: a list procedure that refuses a silly page size is a list procedure that
    -- breaks a screen over a typo.  The ceiling is the interesting half and it is section 10.6's rule in one expression.
    SET @TopN = LEAST (GREATEST (COALESCE (@TopN, 200), 1), 1000);
    SET @CaseStatus = NULLIF (TRIM (COALESCE (@CaseStatus, '')), '');

    SET @KeyParameters  = CONCAT (N'CaseStatus=', COALESCE (@CaseStatus, N'(any)'), N', AssignedToProfileId='
                                , COALESCE (CAST (@AssignedToProfileId AS NVARCHAR (11)), N'(any)')
                                , N', TopN=', @TopN);
    SET @ContextMessage = N'Error-only instrumented read: no start row is opened, so @ExecutionLogId is NULL by design.';

    BEGIN TRY

        -- =========================================================================================
        -- ===== The procedure's own work starts here. Everything above and below is boilerplate. ==
        -- =========================================================================================

        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        SELECT TOP (@TopN)
               CaseFileId          = cf.CaseFileId
             , TenantId            = cf.TenantId
             , CaseNumber          = cf.CaseNumber
             , Title               = cf.Title
             , CaseStatus          = cf.CaseStatus
             , AssignedToProfileId = cf.AssignedToProfileId
             , AssignedToName      = asg.ProfileName
             , OpenedUtc           = cf.OpenedUtc
             , ApprovedUtc         = cf.ApprovedUtc
          FROM dbo.CaseFile          AS cf
          LEFT JOIN auth.UserProfile AS asg ON asg.UserProfileId = cf.AssignedToProfileId
         WHERE cf.IsDeleted = 0
           AND (@CaseStatus          IS NULL OR cf.CaseStatus          = @CaseStatus)
           AND (@AssignedToProfileId IS NULL OR cf.AssignedToProfileId = @AssignedToProfileId)
         ORDER BY cf.OpenedUtc DESC, cf.CaseFileId DESC;

        -- =========================================================================================
        -- ===== End of the procedure's own work. ===================================================
        -- =========================================================================================

    END TRY
    BEGIN CATCH

        SELECT @ErrorNumber = ERROR_NUMBER ()
             , @ErrorProc   = ERROR_PROCEDURE ()
             , @ErrorLine   = ERROR_LINE ()
             , @ErrorMsg    = ERROR_MESSAGE ()
                            + N' (error '  + CAST (ERROR_NUMBER () AS NVARCHAR (11))
                            + N', line '   + CAST (ERROR_LINE ()   AS NVARCHAR (11)) + N')';

        EXEC logs.uspRecordExecutionError
              @ProcedureName   = @ProcName
            , @KeyParameters   = @KeyParameters
            , @ExecutionLogId  = NULL
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


-- *** 10. dbo.uspListCaseNotes ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   dbo.uspListCaseNotes
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Returns one case file's notes, oldest first, optionally excluding the internal ones.  Demands nothing and raises nothing:
an empty set is the answer both for a case file with no notes and for one the profile may not see.

========================================================================================================================
Requirements and Key Dependencies:

dbo.CaseNote, dbo.CaseFile, auth.UserProfile, auth.uspSetSessionContext.  Error-only instrumented.  Granted to
applicationRole.  DES-AUTH-001 sections 14.1, 14.2, 14.6.

========================================================================================================================
Notes:

THE JOIN TO dbo.CaseFile IS THE ONLY REASON A DELETED CASE FILE'S NOTES DISAPPEAR.  dbo.uspSoftDeleteCaseFile deliberately
does not cascade -- see its notes for why cascading would make restore lossy -- so the parent's IsDeleted is enforced here,
in the read, on every call.  A project that adds a second reader of dbo.CaseNote has to repeat this join, and that is the
cost of the decision: it is stated in both places rather than hidden in one.

@IncludeInternal DEFAULTS TO 1 AND IS THE CALLER'S DECISION, NOT A PERMISSION.  IsInternal separates a note written for
colleagues from one written for the applicant; which of those a screen shows depends on the screen, and the template does
not have enough domain to make it an authority.  A project that needs it to be one adds a permission and demands it here --
that is the extension point, and it is deliberately not pre-empted.

NO E-50201 ON AN UNKNOWN CASE FILE.  This procedure returns rows rather than a row, so silence is a valid answer and
distinguishing "no such case file" from "no notes yet" would tell an unauthorized caller which case file ids exist.  The
point read next door raises; this one does not.

========================================================================================================================
Example Usage and Performance:

exec dbo.uspListCaseNotes @SessionTokenHash = 0x9F86..., @CaseFileId = 4471, @IncludeInternal = 0;

One seek on IX_dbo_CaseNote_Tenant_CaseFile per tenant in scope, with the predicate evaluated once per candidate row.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-102
Description:
Created.  Phase 7.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE dbo.uspListCaseNotes
      @SessionTokenHash VARBINARY (32)
    , @CaseFileId       INT
    , @IncludeInternal  BIT = 1
    , @TopN             INT = 500
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation, READ variant: error-only. No start row is opened.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[dbo].[uspListCaseNotes]')
          , @KeyParameters  NVARCHAR (MAX) = NULL
          , @ContextMessage NVARCHAR (MAX) = NULL
          , @DynamicSql     NVARCHAR (MAX) = NULL
          , @ErrorMsg       NVARCHAR (MAX) = NULL
          , @ErrorProc      NVARCHAR (300) = NULL
          , @ErrorNumber    INT            = NULL
          , @ErrorLine      INT            = NULL;

    SET @IncludeInternal = COALESCE (@IncludeInternal, 1);
    SET @TopN            = LEAST (GREATEST (COALESCE (@TopN, 500), 1), 2000);

    SET @KeyParameters  = CONCAT (N'CaseFileId=', @CaseFileId, N', IncludeInternal=', @IncludeInternal, N', TopN=', @TopN);
    SET @ContextMessage = N'Error-only instrumented read: no start row is opened, so @ExecutionLogId is NULL by design.';

    BEGIN TRY

        -- =========================================================================================
        -- ===== The procedure's own work starts here. Everything above and below is boilerplate. ==
        -- =========================================================================================

        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        SELECT TOP (@TopN)
               CaseNoteId          = cn.CaseNoteId
             , CaseFileId          = cn.CaseFileId
             , TenantId            = cn.TenantId
             , NoteText            = cn.NoteText
             , IsInternal          = cn.IsInternal
             , AuthoredByProfileId = cn.AuthoredByProfileId
             , AuthoredByName      = aut.ProfileName
             , AuthoredUtc         = cn.AuthoredUtc
          FROM dbo.CaseNote          AS cn
          JOIN dbo.CaseFile          AS cf  ON cf.CaseFileId    = cn.CaseFileId
                                           AND cf.TenantId      = cn.TenantId
          LEFT JOIN auth.UserProfile AS aut ON aut.UserProfileId = cn.AuthoredByProfileId
         WHERE cn.CaseFileId = @CaseFileId
           AND cn.IsDeleted  = 0
           AND cf.IsDeleted  = 0
           AND (@IncludeInternal = 1 OR cn.IsInternal = 0)
         ORDER BY cn.AuthoredUtc, cn.CaseNoteId;

        -- =========================================================================================
        -- ===== End of the procedure's own work. ===================================================
        -- =========================================================================================

    END TRY
    BEGIN CATCH

        SELECT @ErrorNumber = ERROR_NUMBER ()
             , @ErrorProc   = ERROR_PROCEDURE ()
             , @ErrorLine   = ERROR_LINE ()
             , @ErrorMsg    = ERROR_MESSAGE ()
                            + N' (error '  + CAST (ERROR_NUMBER () AS NVARCHAR (11))
                            + N', line '   + CAST (ERROR_LINE ()   AS NVARCHAR (11)) + N')';

        EXEC logs.uspRecordExecutionError
              @ProcedureName   = @ProcName
            , @KeyParameters   = @KeyParameters
            , @ExecutionLogId  = NULL
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


-- *** 11. dbo.uspCloseApprovedCaseFiles ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   dbo.uspCloseApprovedCaseFiles
Author:       rsincero
CreateDate:   2026-09-21
========================================================================================================================
Description:

The one registered OPERATION in the demonstration domain, and the only module in this database that demands
Data.Execute.  Closes every case file at the session's acting tenant that was approved more than @OlderThanDays ago and
has not been closed yet: sets CaseStatus to 'closed', writes ClosedUtc, and records one logs.DataChangeLog row per case
file from the UPDATE's own OUTPUT clause.  Returns the count in @CaseFilesClosed.  Demands Data.Execute AND Data.Update.
E-50208 for an out-of-range bound, E-50209 if the trail and the batch ever disagree.

========================================================================================================================
Requirements and Key Dependencies:

dbo.CaseFile, auth.uspSetSessionContext, auth.uspDemandPermission, logs.DataChangeLog (written directly -- see the
notes).  Granted to applicationRole.  DES-AUTH-001 sections 10.6, 14.1, 14.2, 14.4, 15.5.  Appendix B E-50208
and E-50209.
PLAN-AUTH-001 task T-129, gap G-45.

========================================================================================================================
Notes:

WHY THIS PROCEDURE EXISTS AT ALL, WHICH IS NOT BECAUSE ANYBODY NEEDS A SWEEP.  115_seed_reference_data.sql has seeded
Data.Execute since Phase 3 and grants it to OPERATOR and, since T-128, to CRUD_ACCESS.  Until this procedure was written,
nothing in the database demanded it.  A permission no module demands is indistinguishable at run time from a permission
that does not exist: it appears in the role matrix, it appears in every administrator's mental model of what the
application can do, and it gates nothing at all.  Worse, a team building on this template grants it believing it means
something.  That was gap G-45, and this is its closure -- not documentation, a caller.

WHAT Data.Execute MEANS, TAKEN FROM ITS OWN SEED ROW AND NOT INVENTED HERE.  115 defines it as "run a registered
operation -- a batch job, a recalculation, a nightly reconciliation triggered from a screen", and then says what it is
NOT: 'NOT "may call stored procedures": every user calls stored procedures, because that is the only access path there
is'.  So the permission cannot be satisfied by decorating an existing procedure with a third demand.  It needs a module
that is an OPERATION -- something a person starts, that runs over a set they did not enumerate, and that they could not
have achieved by filling in a form.  A close-out sweep is the smallest honest example this domain can carry.  It was
chosen over an escalation sweep because dbo.CaseFile has no due date and no priority, and inventing one would have
changed 090_dbo_application.sql to make a permission demonstrable, which is the tail wagging the dog.

Data.Execute AND THEN Data.Update, FOR THE REASON SECTION 3 GIVES AT LENGTH.  The sweep is an UPDATE statement, and
auth.tvfTenantUpdatePredicate is generated from the Data.Update rows of auth.Permission alone.  A profile holding
Data.Execute and not Data.Update would reach the UPDATE and be refused by the block predicate with Msg 33504, which
names an object instead of a permission.  So the operation verb is demanded first -- it is the more specific refusal and
the one worth showing the person who pressed the button -- and Data.Update second.

  This has a consequence in the seeded role matrix that is easy to mistake for a defect: OPERATOR holds Data.Read and
  Data.Execute and NOT Data.Update, so an OPERATOR profile cannot run this sweep.  That is the seed telling the truth.
  OPERATOR is for operations that READ -- a reconciliation that reports a discrepancy, an export, a recount into a
  summary table.  An operation that edits business rows needs the edit authority as well, exactly as approving does.
  CRUD_ACCESS, seeded by T-128, holds both, and it is the role the scenario's own caseworker cohort carries.

THE TENANT TERM IS NOT A PARAMETER, AND IT IS NOT OPTIONAL EITHER.  The file header explains why no write here takes a
@TenantId; this procedure still does not take one, but unlike the singleton writes it must put SESSION_CONTEXT's
ActingTenantId in the WHERE clause explicitly:

    AND cf.TenantId = @ActingTenantId

Leave it out and the sweep is not wrong, it is UNRELIABLE, and in a way that only appears for some callers.
auth.tvfTenantReadPredicate is built from the Data.Read rows and auth.tvfTenantUpdatePredicate from the Data.Update
rows, over the same closure but not necessarily over the same scope tenants.  A profile whose read scope is wider than
its update scope -- an auditor at a county who may edit only their own department's cases, which is an ordinary
arrangement -- would see rows in this set that the BEFORE UPDATE block predicate then refuses.  A block predicate
refuses the STATEMENT, not the row: one unwritable case file in five hundred aborts the whole batch with Msg 33504 and
rolls back the other four hundred and ninety-nine.  That is the failure mode a set-based writer has and a singleton
writer does not, and it is the reason batch jobs in multi-tenant systems get a reputation for working in test and
failing in production.

  Confining the sweep to the acting tenant makes the guarantee exact rather than probable: auth.uspDemandPermission has
  just proved Data.Update at @ActingTenantId, and tvfTenantUpdatePredicate (@ActingTenantId) asks the same question of
  the same two tables.  The demand succeeding is therefore a proof that the predicate will permit every row this
  statement can touch.  A sweep that spanned the read subtree could not make that promise to itself.

THE CAP IS THE DESIGN, NOT A CONVENIENCE PARAMETER.  @MaxCaseFiles defaults to 500 and is bounded at 5,000, and the
number was not chosen for tidiness.  SQL Server escalates row locks to a TABLE lock at about 5,000 locks on one object,
and dbo.CaseFile is one object shared by every tenant in the database.  An uncapped sweep on a large tenant therefore
takes out a table lock that blocks every OTHER tenant's ordinary work -- an operation for one county stopping the whole
platform -- and holds it for the length of the transaction, including the trail write.  The file header's Phase 5 rule
says protected tables are for filtered access and not for aggregation; this is the same rule for writes.  A caller with
more than @MaxCaseFiles in scope calls again, which is why @CaseFilesClosed is an OUTPUT parameter and not a PRINT: a
scheduler loops until it comes back 0.

  A sweep returning exactly @MaxCaseFiles is therefore NOT a success report, it is "there is probably more".  That is
  stated in @Comments so the ExecutionLog row says it too.

THE TRAIL IS WRITTEN DIRECTLY, AND logs.uspRecordDataChange TOLD IT TO.  Every other write in this file calls
logs.uspRecordDataChange.  This one does not, and the recorder's own notes are the authority: 'ONE ROW PER CALL, AND A
SET-BASED WRITER MUST NOT LOOP OVER IT ... Such a caller should INSERT into logs.DataChangeLog directly from its OUTPUT
clause, which ownership chaining permits'.  That sentence was written in Phase 5 for a caller that did not exist yet.
It does now, and the arithmetic it was defending against is real: five hundred calls to the recorder would add a
thousand logs.ExecutionLog writes inside this transaction, turning a table about work into a table about one sweep.
So the UPDATE captures its own rows with OUTPUT ... INTO a table variable, and one set-based INSERT writes the trail --
one row per case file, keyed exactly as the singleton writes key theirs, so a search for "what happened to case 4471"
finds the batch that closed it.  The batch itself is identified by executionLogId inside ChangedColumnsJson, which is
what makes five hundred trail rows attributable to one decision by one person.

  Ownership chaining is what permits it: logs.DataChangeLog is not granted to applicationRole, the INSERT here is
  reached through dbo owning the procedure, and a project that copies this shape gets the same permission for free.

NOTHING IN SCOPE IS A SUCCESS.  @CaseFilesClosed comes back 0, no trail rows are written, and no error is raised.  A
scheduled operation that throws when there is nothing to do is an operation that pages somebody every night.  This is
the opposite of dbo.uspApproveCaseFile's E-50202, and the difference is that a sweep names no row: there is no caller
assertion to contradict.  E-50208 is reserved for a bound the caller could not have meant -- a negative number of days,
or a cap of zero -- because those are calling bugs and not empty sets.  E-50209 is an invariant on this procedure's
own work and should never be seen: it fires only if the UPDATE and the trail INSERT disagree about how many rows there
were, and it rolls the batch back rather than leaving business rows changed with nobody recorded as changing them.

AN APPROVED CASE FILE IS THE ONLY THING THIS TOUCHES.  The WHERE clause requires CaseStatus = 'approved' AND ClosedUtc
IS NULL, so a case file that is draft, open, pending, rejected, withdrawn or already closed is not in scope at any age.
It deliberately does not close 'rejected' cases as well, although the argument for doing so is good: a rejection is also
a finished decision.  Widening it would make the procedure two operations behind one permission, and the moment a
project wants both it wants them auditable separately.  Copy the procedure; do not add a flag.

========================================================================================================================
Example Usage and Performance:

declare @closed int;
exec dbo.uspCloseApprovedCaseFiles @SessionTokenHash = 0x9F86..., @OlderThanDays = 30, @MaxCaseFiles = 500
                                 , @CaseFilesClosed = @closed output;

One range scan of at most @MaxCaseFiles rows on dbo.CaseFile through the filter predicate, one narrow update of the same
rows, and one set-based insert of the same count into logs.DataChangeLog.  Two instrumentation writes for the whole
call, not two per row.  The predicate's cost is section 10.6's: a bounded set is what it is priced for.

========================================================================================================================
Modification History:

Date:		2026-09-21
Author:		rsincero
Ticket:		T-129
Description:
Created.  The first and only demander of Data.Execute, closing gap G-45.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE dbo.uspCloseApprovedCaseFiles
      @SessionTokenHash VARBINARY (32)
    , @OlderThanDays    INT = 30
    , @MaxCaseFiles     INT = 500
    , @CaseFilesClosed  INT = NULL OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[dbo].[uspCloseApprovedCaseFiles]')
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

    DECLARE @Actor          NVARCHAR (255)  = NULL
          , @ActorProfileId INT             = NULL
          , @ActingTenantId INT             = NULL
          , @CutoffUtc      DATETIME2 (3)   = NULL
          , @Now            DATETIME2 (3)   = NULL
          , @Rows           INT             = 0
          , @TrailRows      INT             = 0
          , @Failure        NVARCHAR (2000) = NULL;

    -- The batch the UPDATE actually wrote, captured by the statement itself rather than re-read afterwards: a second
    -- SELECT would see a different set, because the rows it is looking for no longer match the WHERE clause.
    DECLARE @Closed TABLE
    (
        CaseFileId INT          NOT NULL PRIMARY KEY,
        TenantId   INT          NOT NULL,
        OldStatus  VARCHAR (20) NOT NULL
    );

    SET @CaseFilesClosed = 0;

    SET @KeyParameters = CONCAT (N'OlderThanDays=', @OlderThanDays, N', MaxCaseFiles=', @MaxCaseFiles);

    BEGIN TRY

        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        SET @ActorProfileId = TRY_CAST (SESSION_CONTEXT (N'UserProfileId')  AS INT);
        SET @ActingTenantId = TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT);
        SET @Actor          = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                      , ORIGINAL_LOGIN ());

        -- The operation verb first, then the one auth.tvfTenantUpdatePredicate is actually built from.  See the notes.
        EXEC auth.uspDemandPermission @PermissionCode = N'Data.Execute'
                                    , @TenantId       = @ActingTenantId
                                    , @ObjectName     = N'dbo.uspCloseApprovedCaseFiles';

        EXEC auth.uspDemandPermission @PermissionCode = N'Data.Update'
                                    , @TenantId       = @ActingTenantId
                                    , @ObjectName     = N'dbo.uspCloseApprovedCaseFiles';

        IF @OlderThanDays IS NULL OR @OlderThanDays < 0 OR @OlderThanDays > 3650
        BEGIN
            SET @Failure = CONCAT (N'@OlderThanDays was ', COALESCE (CAST (@OlderThanDays AS NVARCHAR (11)), N'NULL')
                                 , N' and has to be between 0 and 3650. 0 means "every approved case file, however '
                                 , N'recently", which is a legitimate thing to ask for and is why the floor is not 1. '
                                 , N'A negative number is a date in the future and would close nothing; anything past '
                                 , N'ten years is almost certainly a units mistake -- months or hours where days were '
                                 , N'meant. Nothing was changed.');
            ;THROW 50208, @Failure, 1;
        END;

        IF @MaxCaseFiles IS NULL OR @MaxCaseFiles < 1 OR @MaxCaseFiles > 5000
        BEGIN
            SET @Failure = CONCAT (N'@MaxCaseFiles was ', COALESCE (CAST (@MaxCaseFiles AS NVARCHAR (11)), N'NULL')
                                 , N' and has to be between 1 and 5000. The ceiling is not arbitrary: SQL Server '
                                 , N'escalates row locks to a lock on the whole of dbo.CaseFile at around 5,000 locks, '
                                 , N'and that table holds every tenant''s rows -- so a bigger batch would stop every '
                                 , N'other tenant''s work for the length of this transaction. Call this procedure '
                                 , N'repeatedly until @CaseFilesClosed comes back 0 instead. Nothing was changed.');
            ;THROW 50208, @Failure, 1;
        END;

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

        SET @Now       = SYSUTCDATETIME ();
        SET @CutoffUtc = DATEADD (DAY, -@OlderThanDays, @Now);

        -- cf.TenantId = @ActingTenantId is the term that makes this statement safe for every caller rather than for
        -- most of them, and the ClosedUtc IS NULL term is what makes two schedulers running at once harmless: the
        -- loser writes nothing instead of re-closing a case file and giving it a second ClosedUtc.
        UPDATE TOP (@MaxCaseFiles) cf
           SET cf.CaseStatus      = 'closed'
             , cf.ClosedUtc       = @Now
             , cf.auditModifiedBy = @Actor
        OUTPUT inserted.CaseFileId, inserted.TenantId, deleted.CaseStatus
          INTO @Closed (CaseFileId, TenantId, OldStatus)
          FROM dbo.CaseFile AS cf
         WHERE cf.TenantId    = @ActingTenantId
           AND cf.IsDeleted   = 0
           AND cf.CaseStatus  = 'approved'
           AND cf.ClosedUtc   IS NULL
           AND cf.ApprovedUtc IS NOT NULL
           AND cf.ApprovedUtc <= @CutoffUtc;

        SET @Rows            = @@ROWCOUNT;
        SET @CaseFilesClosed = @Rows;

        -- One INSERT, not @Rows calls to logs.uspRecordDataChange, on that procedure's own written instruction.  The
        -- keys match the singleton writers' shape exactly, so a search by CaseFileId finds batch closures too.
        IF @Rows > 0
        BEGIN
            INSERT logs.DataChangeLog
                (OccurredUtc, SchemaName, TableName, Operation, KeyJson, ChangedColumnsJson, ActorUserProfileId
               , auditCreatedBy, auditCreatedDateUtc, auditModifiedBy, auditModifiedDateUtc)
            SELECT @Now
                 , N'dbo'
                 , N'CaseFile'
                 , 'Update'
                 , CONCAT (N'{"CaseFileId":', c.CaseFileId, N',"TenantId":', c.TenantId, N'}')
                 , CONCAT (N'{"CaseStatus":{"old":"', c.OldStatus, N'","new":"closed"}'
                         , N',"ClosedUtc":{"old":null,"new":"', CONVERT (NVARCHAR (30), @Now, 126), N'"}'
                         , N',"operation":"dbo.uspCloseApprovedCaseFiles"'
                         , N',"olderThanDays":', @OlderThanDays
                         , N',"executionLogId":', COALESCE (CAST (@ExecutionId AS NVARCHAR (20)), N'null'), N'}')
                 , @ActorProfileId
                 , @Actor
                 , @Now
                 , @Actor
                 , @Now
              FROM @Closed AS c;

            SET @TrailRows = @@ROWCOUNT;

            -- The trail is not best-effort.  If the two counts disagree, some case file has been closed with nobody
            -- recorded as having closed it, and a rollback is the only honest outcome.
            IF @TrailRows <> @Rows
            BEGIN
                SET @Failure = CONCAT (N'The sweep closed ', @Rows, N' case file(s) but wrote ', @TrailRows
                                     , N' trail row(s). Nothing has been closed: the whole batch is rolled back, '
                                     , N'because a business row that changed with no logs.DataChangeLog entry is '
                                     , N'worse than a batch that did not run.');
                ;THROW 50209, @Failure, 1;
            END;
        END;

        SET @Comments = CONCAT (N'ActingTenantId=', COALESCE (CAST (@ActingTenantId AS NVARCHAR (11)), N'(null)')
                              , N' OlderThanDays=', @OlderThanDays
                              , N' CutoffUtc=', CONVERT (NVARCHAR (30), @CutoffUtc, 126)
                              , N' CaseFilesClosed=', @Rows
                              , N' TrailRows=', @TrailRows
                              , CASE WHEN @Rows = 0
                                     THEN N'. Nothing was in scope, which is a success: a scheduled operation that '
                                        + N'throws when there is nothing to do pages somebody every night.'
                                     WHEN @Rows = @MaxCaseFiles
                                     THEN CONCAT (N'. The batch filled its cap of ', @MaxCaseFiles, N', so there is '
                                                , N'PROBABLY MORE in scope -- call again until 0 comes back.')
                                     ELSE N'.' END);

        -- =========================================================================================
        -- ===== End of the procedure's own work. ===================================================
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

        -- Nothing was closed, so the OUTPUT parameter must not claim otherwise: a caller that catches the error and
        -- reads @CaseFilesClosed would otherwise be told the rolled-back count.
        SET @CaseFilesClosed = 0;

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


-- *** 12. Descriptions ***
IF OBJECT_ID (N'util.uspSetObjectDescription', N'P') IS NOT NULL
BEGIN
    DECLARE @Descriptions TABLE
    (
        RowNo       INT IDENTITY (1, 1) PRIMARY KEY,
        ObjectName  SYSNAME         NOT NULL,
        Description NVARCHAR (3750) NOT NULL
    );

    INSERT @Descriptions (ObjectName, Description)
    VALUES
      (N'uspCreateCaseFile'
     , N'Creates one case file at the session''s ACTING tenant. There is no @TenantId parameter: P-06 makes '
     + N'auth.tvfTenantInsertPredicate compare the row''s TenantId with SESSION_CONTEXT(''ActingTenantId''), so a '
     + N'parameter could only agree with the session or be refused by the database with Msg 33504. Demands Data.Insert. '
     + N'E-50206 a blank case number or title, E-50200 a case number already live at this tenant. Opens the case as '
     + N'''draft''. Writes one logs.DataChangeLog row keyed on the new id, which is taken from SCOPE_IDENTITY().')
    , (N'uspUpdateCaseFile'
     , N'Changes one case file''s title and, optionally, its status. Demands Data.Update. E-50206 a blank title; E-50207 '
     + N'a status this procedure does not own -- ''approved'' is reachable only through dbo.uspApproveCaseFile, so that the '
     + N'approver and timestamp can never be absent from an approved case. E-50201 for a case file that does not exist, '
     + N'is not in the session''s read scope, or is deleted; the same number is raised again when the UPDATE itself '
     + N'matches nothing, which is the concurrency loser and is deliberately not a different error.')
    , (N'uspApproveCaseFile'
     , N'Approves one case file: sets CaseStatus = ''approved'', ApprovedUtc and ApprovedByProfileId. Demands Data.Approve '
     + N'AND THEN Data.Update, because auth.tvfTenantUpdatePredicate is built from Data.Update alone -- without it the '
     + N'database refuses with Msg 33504, which cannot be caught. E-50201 not found; E-50202 already approved, naming the '
     + N'earlier approver and time; E-50203 the acting profile is not at the case file''s own tenant, which '
     + N'FK_dbo_CaseFile_ApprovedBy_Tenant would otherwise reject as a foreign key. The UPDATE requires ApprovedUtc IS '
     + N'NULL, so a concurrent second approval writes nothing and no trail row.')
    , (N'uspReassignCaseFile'
     , N'Moves one case file to another profile at the SAME tenant, or unassigns it with @AssignedToProfileId = NULL. '
     + N'Demands Data.Reassign AND THEN Data.Update. E-50201 not found; E-50203 a target profile that is not at the case '
     + N'file''s tenant, or is inactive, deleted, or owned by an unusable auth.User. Reassigning to the current assignee '
     + N'is a no-op that writes no trail row -- the guard is IS DISTINCT FROM, so NULL-to-NULL counts as unchanged. '
     + N'@Reassigned OUTPUT tells the caller which of the two happened.')
    , (N'uspAddCaseNote'
     , N'Adds one note to a case file, authored by the session''s own profile. Demands Data.Insert. E-50206 empty text; '
     + N'E-50201 not found; E-50201 also when the case file is readable but belongs to a tenant OTHER than the acting one '
     + N'-- P-06 again, caught here so the caller gets a message instead of Msg 33504. E-50204 a case file that is closed '
     + N'or withdrawn: a finished case does not grow. IsInternal separates a note for colleagues from one for the '
     + N'applicant and is the caller''s decision, not a permission.')
    , (N'uspSoftDeleteCaseFile'
     , N'Soft-deletes one case file. Demands Data.SoftDelete AND THEN Data.Update. E-50201 not found or already deleted. '
     + N'Sets IsDeleted, auditDeletedBy and auditDeletedDateUtc in ONE statement, because CK_dbo_CaseFile_DeletedPair is '
     + N'evaluated BEFORE the AFTER trigger fires and a bare flag flip is rejected with Msg 547 -- section 14.4. Does NOT '
     + N'cascade to dbo.CaseNote: a cascade cannot be distinguished from individual deletions and would make restore '
     + N'lossy, so dbo.uspListCaseNotes enforces the parent''s IsDeleted on every read instead. Frees the case number, '
     + N'because UX_dbo_CaseFile_Tenant_CaseNumber is filtered on IsDeleted = 0.')
    , (N'uspRestoreCaseFile'
     , N'Reverses a soft delete, clearing IsDeleted, auditDeletedBy and auditDeletedDateUtc in one statement. Demands '
     + N'Data.Restore AND THEN Data.Update. Needs NO row-security bypass, which is the first thing a reader suspects: the '
     + N'tenancy predicates say nothing about IsDeleted, so a deleted row is still visible to a profile with scope. '
     + N'E-50201 not found; E-50205 not deleted, or a concurrent restore won; E-50200 the case number was taken by a new '
     + N'case file while this one was away, which is the cost of freeing it on delete and has to be resolved by hand.')
    , (N'uspGetCaseFile'
     , N'Returns ONE case file by id with the assignee''s and approver''s names resolved. Demands nothing -- section 14.2: '
     + N'auth.tvfTenantReadPredicate has already answered the authorization question, so there is nothing left to ask. '
     + N'E-50201 covers does-not-exist, not-in-scope and deleted as one answer, on purpose: telling them apart would tell '
     + N'an unauthorized caller which case file ids exist. The only read here that raises rather than returning an empty '
     + N'set, because a point read by id returning nothing is indistinguishable from a caller bug.')
    , (N'uspListCaseFiles'
     , N'Returns the case files visible to the session''s profile, newest first, optionally narrowed to one status or one '
     + N'assignee, capped at @TopN (1-1000, default 200). Demands nothing and raises nothing: an empty set is the correct '
     + N'answer for a profile with no read scope. The rows span the profile''s whole scope SUBTREE, not just the acting '
     + N'tenant, so TenantId is returned. @TopN is section 10.6 wearing a parameter -- a bounded list of 1,000 rows costs '
     + N'1,007 logical reads with the predicate bound, and an unbounded aggregate over 200,000 costs 1,002,655.')
    , (N'uspCloseApprovedCaseFiles'
     , N'THE ONE REGISTERED OPERATION, and the only module in this database that demands Data.Execute -- which had been '
     + N'seeded, granted and enforced by nothing until T-129 (gap G-45). Closes every case file at the session''s ACTING '
     + N'tenant that was approved more than @OlderThanDays ago and is not closed yet, at most @MaxCaseFiles of them. '
     + N'Demands Data.Execute AND THEN Data.Update, so a seeded OPERATOR profile -- Data.Read and Data.Execute, no '
     + N'Data.Update -- cannot run it, which is the role matrix being honest rather than a defect: an operation that '
     + N'EDITS needs the edit authority too. Nothing in scope is a success returning 0, not an error. E-50208 a bound '
     + N'outside 0-3650 days or 1-5000 rows; the cap exists because lock escalation at around 5,000 locks would take a '
     + N'table lock on dbo.CaseFile and stop every other tenant. E-50209 the batch and its trail disagreeing, which '
     + N'rolls the batch back. Writes the trail as ONE set-based INSERT into logs.DataChangeLog from the UPDATE''s OUTPUT '
     + N'clause -- logs.uspRecordDataChange''s own notes forbid looping over it -- keyed identically to the singleton '
     + N'writers, so a search by CaseFileId finds batch closures too.')
    , (N'uspListCaseNotes'
     , N'Returns one case file''s notes, oldest first, optionally excluding the internal ones, capped at @TopN. Demands '
     + N'nothing and raises nothing -- not even for an unknown case file, because silence is a valid answer for a set and '
     + N'the point read next door is where E-50201 lives. The JOIN to dbo.CaseFile is the ONLY thing that hides a deleted '
     + N'case file''s notes, since dbo.uspSoftDeleteCaseFile deliberately does not cascade; any second reader of '
     + N'dbo.CaseNote has to repeat that join.');

    DECLARE @RowNo       INT = 1
          , @MaxRowNo    INT = (SELECT MAX (RowNo) FROM @Descriptions)
          , @ObjectName  SYSNAME
          , @Description NVARCHAR (3750);

    WHILE @RowNo <= @MaxRowNo
    BEGIN
        SELECT @ObjectName  = ObjectName
             , @Description = Description
          FROM @Descriptions
         WHERE RowNo = @RowNo;

        EXEC util.uspSetObjectDescription @SchemaName  = N'dbo'
                                       , @ObjectType  = N'PROCEDURE'
                                       , @ObjectName  = @ObjectName
                                       , @Description = @Description
                                       , @ColumnName  = NULL;

        SET @RowNo += 1;
    END;
END
ELSE
BEGIN
    PRINT N'util.uspSetObjectDescription is absent, so no descriptions were set. Run templates/extended-properties.sql '
        + N'and then re-run this file.';
END
GO


-- *** 13. Grants ***
-- All eleven, to applicationRole.  This is the whole point of the file: 170_permissions.sql grants applicationRole
-- SELECT, INSERT and UPDATE on SCHEMA::dbo and deliberately no DELETE, and these eleven procedures are the only
-- sanctioned way in.
-- A project that wants the application to reach dbo.CaseFile directly does not need a grant -- it already has one -- which
-- is why section 14's contract is a CONVENTION enforced by review, not by permissions.  The database's own defence is
-- row-level security: a direct write that ignores P-06 fails with Msg 33504 whatever the caller's GRANTs say.
IF DATABASE_PRINCIPAL_ID (N'applicationRole') IS NOT NULL
BEGIN
    GRANT EXECUTE ON dbo.uspCreateCaseFile     TO applicationRole;
    GRANT EXECUTE ON dbo.uspUpdateCaseFile     TO applicationRole;
    GRANT EXECUTE ON dbo.uspApproveCaseFile    TO applicationRole;
    GRANT EXECUTE ON dbo.uspReassignCaseFile   TO applicationRole;
    GRANT EXECUTE ON dbo.uspAddCaseNote        TO applicationRole;
    GRANT EXECUTE ON dbo.uspSoftDeleteCaseFile TO applicationRole;
    GRANT EXECUTE ON dbo.uspRestoreCaseFile    TO applicationRole;
    GRANT EXECUTE ON dbo.uspGetCaseFile        TO applicationRole;
    GRANT EXECUTE ON dbo.uspListCaseFiles      TO applicationRole;
    GRANT EXECUTE ON dbo.uspListCaseNotes      TO applicationRole;
    GRANT EXECUTE ON dbo.uspCloseApprovedCaseFiles TO applicationRole;

    PRINT N'Granted EXECUTE on the eleven demonstration-domain procedures to applicationRole.';
END
ELSE
BEGIN
    PRINT N'applicationRole does not exist, so no grants were made. Run database/005_schemas_and_roles.sql and then '
        + N're-run this file.';
END
GO


-- *** 14. Closing report ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

DECLARE @Report TABLE
(
    RowNo    INT IDENTITY (1, 1) PRIMARY KEY,
    Severity INT            NOT NULL,
    Status   VARCHAR (10)   NOT NULL,
    Item     NVARCHAR (200) NOT NULL,
    Detail   NVARCHAR (1000) NOT NULL
);

-- ---------------------------------------------------------------------------------------------------------------------
-- 14a.  All eleven procedures exist.
-- ---------------------------------------------------------------------------------------------------------------------
DECLARE @Expected TABLE (ObjectName SYSNAME PRIMARY KEY);

INSERT @Expected (ObjectName)
VALUES (N'uspCreateCaseFile'), (N'uspUpdateCaseFile'), (N'uspApproveCaseFile'), (N'uspReassignCaseFile')
     , (N'uspAddCaseNote'), (N'uspSoftDeleteCaseFile'), (N'uspRestoreCaseFile')
     , (N'uspGetCaseFile'), (N'uspListCaseFiles'), (N'uspListCaseNotes'), (N'uspCloseApprovedCaseFiles');

INSERT @Report (Severity, Status, Item, Detail)
SELECT 1
     , 'MISSING'
     , CONCAT (N'dbo.', e.ObjectName)
     , N'The procedure was not created. Read the errors above this report: SQL Server continued past a failed batch '
     + N'because each CREATE OR ALTER is its own batch, so an earlier syntax error does not stop the file.'
  FROM @Expected AS e
 WHERE OBJECT_ID (N'dbo.' + QUOTENAME (e.ObjectName), N'P') IS NULL;

DECLARE @Present INT = (SELECT COUNT (*)
                          FROM @Expected AS e
                         WHERE OBJECT_ID (N'dbo.' + QUOTENAME (e.ObjectName), N'P') IS NOT NULL);

INSERT @Report (Severity, Status, Item, Detail)
SELECT 4, 'OK', N'Procedures created'
     , CONCAT (N'', @Present, N' of 11 demonstration-domain procedures are present: seven writes, three reads and '
             , N'one operation. DES-AUTH-001 section 14 is the contract they implement.');

-- ---------------------------------------------------------------------------------------------------------------------
-- 14b.  Every one of them is granted to applicationRole.  A procedure nobody can execute is the same as a missing one.
-- ---------------------------------------------------------------------------------------------------------------------
IF DATABASE_PRINCIPAL_ID (N'applicationRole') IS NULL
BEGIN
    INSERT @Report (Severity, Status, Item, Detail)
    VALUES (3, 'NOROLE', N'applicationRole'
          , N'The role does not exist, so nothing was granted and the grant check below was skipped. Run '
          + N'database/005_schemas_and_roles.sql and then re-run this file.');
END
ELSE
BEGIN
    INSERT @Report (Severity, Status, Item, Detail)
    SELECT 2
         , 'NOGRANT'
         , CONCAT (N'dbo.', e.ObjectName)
         , N'The procedure exists but applicationRole has no EXECUTE on it, so the application cannot call it. This '
         + N'should be impossible -- section 13 grants all eleven -- so the grant was probably revoked outside this '
         + N'file.'
      FROM @Expected AS e
     WHERE OBJECT_ID (N'dbo.' + QUOTENAME (e.ObjectName), N'P') IS NOT NULL
       AND NOT EXISTS (SELECT 1
                         FROM sys.database_permissions AS dp
                        WHERE dp.major_id      = OBJECT_ID (N'dbo.' + QUOTENAME (e.ObjectName), N'P')
                          AND dp.grantee_principal_id = DATABASE_PRINCIPAL_ID (N'applicationRole')
                          AND dp.permission_name      = N'EXECUTE'
                          AND dp.state       IN ('G', 'W'));

    DECLARE @Granted INT = (SELECT COUNT (*)
                              FROM @Expected AS e
                             WHERE EXISTS (SELECT 1
                                             FROM sys.database_permissions AS dp
                                            WHERE dp.major_id = OBJECT_ID (N'dbo.' + QUOTENAME (e.ObjectName), N'P')
                                              AND dp.grantee_principal_id = DATABASE_PRINCIPAL_ID (N'applicationRole')
                                              AND dp.permission_name      = N'EXECUTE'
                                              AND dp.state       IN ('G', 'W')));

    INSERT @Report (Severity, Status, Item, Detail)
    SELECT 4, 'OK', N'EXECUTE granted'
         , CONCAT (N'applicationRole holds EXECUTE on ', @Granted, N' of 11. It also holds SELECT, INSERT and UPDATE on '
                 , N'SCHEMA::dbo from 170_permissions.sql and no DELETE at all, so these procedures are a convention '
                 , N'enforced by review rather than a wall -- the wall is row-level security.');
END;

-- ---------------------------------------------------------------------------------------------------------------------
-- 14c.  Are the two tables actually policy-bound?  If they are not, every write in this file will appear to work and
--       will silently ignore P-06, which is the single most misleading state this file can be deployed into.
-- ---------------------------------------------------------------------------------------------------------------------
DECLARE @CaseFilePredicates INT = (SELECT COUNT (*)
                                     FROM sys.security_predicates AS sp
                                    WHERE sp.target_object_id = OBJECT_ID (N'dbo.CaseFile'))
      , @CaseNotePredicates INT = (SELECT COUNT (*)
                                     FROM sys.security_predicates AS sp
                                    WHERE sp.target_object_id = OBJECT_ID (N'dbo.CaseNote'));

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN @CaseFilePredicates >= 4 AND @CaseNotePredicates >= 4 THEN 4 ELSE 3 END
     , CASE WHEN @CaseFilePredicates >= 4 AND @CaseNotePredicates >= 4 THEN 'OK' ELSE 'UNBOUND' END
     , N'Row-level security binding'
     , CASE WHEN @CaseFilePredicates >= 4 AND @CaseNotePredicates >= 4
            THEN CONCAT (N'dbo.CaseFile carries ', @CaseFilePredicates, N' predicates and dbo.CaseNote ', @CaseNotePredicates
                       , N'. The writes in this file are genuinely constrained by P-06 and by the Data.Read / Data.Insert '
                       , N'/ Data.Update id lists, which is what makes their permission demands honest.')
            ELSE CONCAT (N'dbo.CaseFile carries ', @CaseFilePredicates, N' predicates and dbo.CaseNote '
                       , @CaseNotePredicates, N', where 4 each is expected. Until 120_rls_policy.sql runs, these '
                       , N'procedures enforce their own permission demands and NOTHING ELSE: every tenant''s rows are '
                       , N'visible to every profile and P-06 is not in force. A warning rather than a problem because '
                       , N'120 runs after this file in the manifest -- but a deployment that ends here is not secure.')
            END;

-- ---------------------------------------------------------------------------------------------------------------------
-- 14d.  The Data.Update coupling, stated as a report row because it is the file's most surprising fact.
-- ---------------------------------------------------------------------------------------------------------------------
-- auth.Permission.PermissionCode is unique PER APPLICATION, not globally -- 'Data.Update' legitimately exists once for
-- each registered application -- so this counts DISTINCT codes.  Counting rows reports 7 of 5, which is how this check
-- was first written and what it taught.
DECLARE @UpdateVerbs INT = (SELECT COUNT (DISTINCT p.PermissionCode)
                              FROM auth.Permission AS p
                             WHERE p.PermissionCode IN (N'Data.Approve', N'Data.Reassign', N'Data.SoftDelete'
                                                      , N'Data.Restore', N'Data.Update'));

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN @UpdateVerbs = 5 THEN 4 ELSE 3 END
     , CASE WHEN @UpdateVerbs = 5 THEN 'INFO' ELSE 'MISSING' END
     , N'Data.Update is demanded alongside every write verb'
     , CASE WHEN @UpdateVerbs = 5
            THEN N'All five permission codes are in the catalogue. Appendix A reads as though Data.Approve, Data.Reassign, '
               + N'Data.SoftDelete and Data.Restore are independent; on a policy-bound table they are not, because '
               + N'auth.tvfTenantUpdatePredicate is built from Data.Update ALONE. Holding only the verb produces Msg '
               + N'33504 from the database, which no procedure can catch or explain, so each procedure demands its verb '
               + N'FIRST and then Data.Update. Recorded as a gap against Appendix A rather than fixed by widening the '
               + N'predicate: a block predicate cannot see which columns a statement touched, so widening it would let a '
               + N'Data.Restore holder edit a title.'
            ELSE CONCAT (N'Only ', @UpdateVerbs, N' of the 5 Data.* permission codes this file demands are in '
                       , N'auth.Permission. Every write here will refuse. Run 115_seed_reference_data.sql.')
            END;

-- ---------------------------------------------------------------------------------------------------------------------
-- 14e.  WHICH applications can actually run these procedures.  Because the codes are per-application, a session on an
--       application that holds Data.Update but not Data.Approve cannot approve anything, no matter what roles the
--       profile has -- auth.uspDemandPermission resolves the code within the session's own ApplicationId.  That is not a
--       defect in this file, but it is invisible from here and it is exactly the kind of thing that gets diagnosed as
--       "the permission check is broken".
-- ---------------------------------------------------------------------------------------------------------------------
DECLARE @FullApps NVARCHAR (1000)
      , @PartApps NVARCHAR (1000);

SELECT @FullApps = STRING_AGG (CAST (x.ApplicationCode AS NVARCHAR (200)), N', ') WITHIN GROUP (ORDER BY x.ApplicationCode)
  FROM (SELECT a.ApplicationCode
          FROM auth.Application AS a
         WHERE (SELECT COUNT (DISTINCT p.PermissionCode)
                  FROM auth.Permission AS p
                 WHERE p.ApplicationId  = a.ApplicationId
                   AND p.PermissionCode IN (N'Data.Approve', N'Data.Reassign', N'Data.SoftDelete'
                                          , N'Data.Restore', N'Data.Update')) = 5) AS x;

SELECT @PartApps = STRING_AGG (CAST (x.ApplicationCode AS NVARCHAR (200)), N', ') WITHIN GROUP (ORDER BY x.ApplicationCode)
  FROM (SELECT a.ApplicationCode
          FROM auth.Application AS a
         WHERE (SELECT COUNT (DISTINCT p.PermissionCode)
                  FROM auth.Permission AS p
                 WHERE p.ApplicationId  = a.ApplicationId
                   AND p.PermissionCode IN (N'Data.Approve', N'Data.Reassign', N'Data.SoftDelete'
                                          , N'Data.Restore', N'Data.Update')) BETWEEN 1 AND 4) AS x;

INSERT @Report (Severity, Status, Item, Detail)
VALUES (4, 'INFO', N'Applications whose catalogue covers all five write verbs'
      , CONCAT (N'Complete: ', COALESCE (@FullApps, N'(none)')
              , N'. Partial: ', COALESCE (@PartApps, N'(none)')
              , N'. PermissionCode is unique per application, and auth.uspDemandPermission resolves the code inside the '
              , N'SESSION''s ApplicationId -- so a session on a partial application gets a refusal from the demand rather '
              , N'than from row security, and the fix is to register the missing codes for that application, not to '
              , N'change a role. Applications listed as partial can still run the three reads and dbo.uspCreateCaseFile '
              , N'if they hold Data.Insert.'));

-- ---------------------------------------------------------------------------------------------------------------------
-- 14f.  Data.Execute is demanded by something.  This is gap G-45's standing check, and it reads the COMPILED definition
--       rather than this file: a permission is enforced when a module in the database demands it, and a demand in a
--       script that was never deployed is exactly the state G-45 described.
-- ---------------------------------------------------------------------------------------------------------------------
DECLARE @ExecuteCodes   INT = (SELECT COUNT (DISTINCT p.PermissionCode)
                                 FROM auth.Permission AS p
                                WHERE p.PermissionCode = N'Data.Execute'
                                  AND p.IsDeleted      = 0)
      , @ExecuteDemands INT = (SELECT COUNT (*)
                                 FROM sys.sql_modules AS m
                                WHERE m.definition LIKE N'%@PermissionCode = N''Data.Execute''%');

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN @ExecuteCodes >= 1 AND @ExecuteDemands >= 1 THEN 4 ELSE 3 END
     , CASE WHEN @ExecuteCodes >= 1 AND @ExecuteDemands >= 1 THEN 'INFO' ELSE 'UNENFORCED' END
     , N'Data.Execute is demanded by a module'
     , CASE WHEN @ExecuteCodes >= 1 AND @ExecuteDemands >= 1
            THEN CONCAT (N'Data.Execute is in the catalogue and ', @ExecuteDemands, N' module(s) demand it -- '
                       , N'dbo.uspCloseApprovedCaseFiles, section 11. Before T-129 the count was 0, which is gap G-45: '
                       , N'a permission no module demands is indistinguishable at run time from one that does not '
                       , N'exist, and a project granting it to a role would have been granting nothing. If this row '
                       , N'ever reads 0 again, either section 11 failed to deploy or somebody removed the demand -- '
                       , N'retire the permission from 115_seed_reference_data.sql deliberately or put the demand back.')
            ELSE CONCAT (N'Data.Execute is in the catalogue ', @ExecuteCodes, N' time(s) and is demanded by '
                       , @ExecuteDemands, N' module(s). A permission nothing demands is not enforced, however many '
                       , N'roles hold it -- gap G-45. dbo.uspCloseApprovedCaseFiles is the demander; if it is missing '
                       , N'from the report above, that is why.')
            END;

-- ---------------------------------------------------------------------------------------------------------------------
-- 14g.  Verdict.
-- ---------------------------------------------------------------------------------------------------------------------
IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
    PRINT '180_dbo_application_procedures.sql: PROBLEMS found -- see the report below.';
ELSE
    PRINT '180_dbo_application_procedures.sql: no problems found.';

SELECT Severity, Status, Item, Detail FROM @Report ORDER BY Severity, RowNo;
GO

