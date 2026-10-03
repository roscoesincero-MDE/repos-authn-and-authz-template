/***********************************************************************************************************************
Script:         125_auth_tenant_procedures.sql
Purpose:        The tenancy procedure surface: auth.uspRebuildTenantClosure, auth.uspCreateTenant,
                auth.uspUpdateTenant, auth.uspDeactivateTenant, auth.uspGetTenantTree,
                auth.uspSetTenantAuthenticationPolicy and auth.uspSetTenantDefaultRoles.  Every path by which the
                application is permitted to change or read the tenant tree, its per-tenant authentication policy, its
                trusted federation issuers and the roles it seeds into new profiles.
Target:         SQL Server 2022.
Run as:         db_owner in the target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/125_auth_tenant_procedures.sql
Idempotent:     Yes.  CREATE OR ALTER throughout, and every grant guarded on DATABASE_PRINCIPAL_ID.
Depends on:     database/030_auth_tenant.sql, database/035_auth_tenant_policy.sql, database/055_auth_role.sql,
                database/085_logs_auth_tables.sql, database/095_auth_views.sql, database/100_auth_functions.sql,
                scripts/logExecutionLogging.sql, templates/extended-properties.sql.
Implements:     T-018 and T-021, and gap G-43.  DES-AUTH-001 sections 5.3, 5.4, 7.2, 7.3, 8.5, 11.5, 14.1 to 14.5.
                See docs/10-database-authn-authz-design.md.
To retarget:    Pass it per run:  sqlcmd -d <database> -v DbName=<database>.  There is no in-file default.

THE TWO POLICY WRITERS WERE ADDED LAST, AND UNTIL THEY EXISTED TWO SHIPPED TABLES HAD NO WRITER AT ALL
-----------------------------------------------------------------------------------------------------
035_auth_tenant_policy.sql creates auth.TenantAuthenticationPolicy, auth.TenantTrustedIssuer and auth.TenantDefaultRole,
and 115_seed_reference_data.sql MERGEs a starting row or two into them.  Nothing else wrote to any of the three.  So the
per-tenant authentication policy that section 7.2 makes the centre of the sign-in decision, the issuer allow-list that
section 7.3 requires before a federated assertion can be trusted, and the default roles that section 8.5 gives every new
profile were all editable only by hand, by somebody with table rights the application deliberately does not have
(INV-11).  A template that ships a policy table and no way to set the policy has shipped the table and not the feature.

auth.uspSetTenantAuthenticationPolicy (section 6) and auth.uspSetTenantDefaultRoles (section 7) are those writers.  Both
are WHOLE-SET calls for their list halves -- issuers and default roles -- because "add one" and "remove one" cannot
express "these and no others", and an administration screen showing a list needs to be able to save the list.  Their
notes carry the two decisions worth arguing about: what NULL means against what [] means, and why a default role demands
Authz.RoleAssign as well as Tenant.Update.

THESE PROCEDURES INSTALL TODAY AND CANNOT BE CALLED BY AN APPLICATION UNTIL PHASE 3
----------------------------------------------------------------------------------
Six of the seven call auth.uspSetSessionContext and auth.uspDemandPermission, which do not exist yet -- they arrive with
database/105_auth_session_procedures.sql and database/150_auth_authorization_procedures.sql.  That is deliberate and it
is safe: a PROCEDURE gets deferred name resolution, so it compiles against a missing procedure and fails at CALL time
with error 2812, "could not find stored procedure".

They are written to the FINAL section 14 contract rather than to what exists today, and the alternative was considered
and rejected.  Wrapping the two calls in IF OBJECT_ID (...) IS NOT NULL would make them installable AND callable now --
with no session context and no permission check, silently.  That is precisely the shape of finding F-07: a permission
model applied to nobody, with nothing reporting it.  An outright failure at call time is the better outcome, and
auth.uspRebuildTenantClosure -- the one the Phase 1 fixtures actually need -- takes no session token and works now.

A NOTE ON WHICH PERMISSION THE TWO NEW PROCEDURES DEMAND.  G-43's proposed resolution names "Tenant.Manage or
Config.Manage".  Neither is a code this design has: Appendix A and 115_seed_reference_data.sql seed fifteen permissions
and the tenancy four are Tenant.Create, Tenant.Deactivate, Tenant.Read and Tenant.Update.  Inventing a sixteenth would
mean editing Appendix A, the seed, the shipped role bundles and 900_bootstrap_first_admin.sql to add a permission that
nobody could distinguish from Tenant.Update -- both mean "may change this tenant's configuration", and a permission
model is only useful while every code in it answers a question somebody actually asks separately.  So both procedures
demand Tenant.Update, and auth.uspSetTenantDefaultRoles demands Authz.RoleAssign as well, which is a real second
question: may this administrator hand out roles here.  The register's text is a proposal, not a specification.

THE SESSION PARAMETER IS @SessionTokenHash VARBINARY (32), AND IT WAS @SessionToken NVARCHAR (128) UNTIL PHASE 6
--------------------------------------------------------------------------------------------------------------
Four of these five procedures were written in Phase 1 against section 9's sketch, which says
EXEC auth.uspSetSessionContext @SessionToken = @token.  105_auth_session_procedures.sql then built the real procedure
with @SessionTokenHash VARBINARY (32) and recorded the deviation as the DESIGN's rather than the code's (BL-043): a
procedure that hashed would have to fix an encoding, and two callers disagreeing about UTF-8 versus UTF-16 would produce
two hashes of one token with nothing to say which was wrong.

Nothing caught the mismatch, because the deferred-name-resolution note above is exactly why: these procedures compile
against a procedure that does not exist yet, and a parameter-NAME error is raised at call time, not at CREATE time.  The
first Phase 6 call produced

    Procedure or function 'uspSetSessionContext' expects parameter '@SessionTokenHash', which was not supplied.

All four were dead on their first statement.  G-26 and BL-053 record it; the lesson the workbook carries is that "it
installs" is not "it runs", and that a procedure written against a contract its dependency has not published yet needs a
smoke call the moment the dependency lands.  Every procedure file from 130 onwards takes @SessionTokenHash.

WHY THE REBUILD TAKES NO PARAMETERS
-----------------------------------
Section 5.3: "A full rebuild of a few thousand rows takes milliseconds."  Scoping it to one application was tried on
paper and abandoned -- the MERGE would need a target-side predicate restricting auth.TenantClosure to one application,
and the closure has no ApplicationId column to restrict on.  Adding one would denormalise a derived table to make an
optimisation possible that the row counts do not justify.  So it rebuilds everything, every time, and there is exactly
one code path to get wrong.
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

IF OBJECT_ID (N'auth.Tenant', N'U') IS NULL OR OBJECT_ID (N'auth.TenantClosure', N'U') IS NULL
BEGIN
    -- Built into a variable because THROW takes a constant or a variable, never an expression.
    DECLARE @Msg NVARCHAR (2000) =
        N'auth.Tenant or auth.TenantClosure is missing. Run database/030_auth_tenant.sql first.';

    THROW 50000, @Msg, 1;
END
GO

-- The three policy tables the two writers in sections 6 and 7 edit.  A THROW and not a warning, because unlike the
-- instrumentation chain below these are resolved at CREATE time by the INSERT and UPDATE statements inside the
-- procedures, so a missing table is a compile failure with a less helpful message than this one.
IF OBJECT_ID (N'auth.TenantAuthenticationPolicy', N'U') IS NULL
   OR OBJECT_ID (N'auth.TenantTrustedIssuer',     N'U') IS NULL
   OR OBJECT_ID (N'auth.TenantDefaultRole',       N'U') IS NULL
   OR OBJECT_ID (N'auth.Role',                    N'U') IS NULL
BEGIN
    DECLARE @MsgPolicy NVARCHAR (2000) =
        N'One of auth.TenantAuthenticationPolicy, auth.TenantTrustedIssuer, auth.TenantDefaultRole or auth.Role is '
      + N'missing. Run database/035_auth_tenant_policy.sql and database/055_auth_role.sql first: '
      + N'auth.uspSetTenantAuthenticationPolicy and auth.uspSetTenantDefaultRoles write to all four.';

    THROW 50000, @MsgPolicy, 1;
END
GO

-- The instrumentation chain.  A warning rather than a THROW: these procedures COMPILE without it, because a procedure
-- gets deferred name resolution, and refusing to install them would make the order in which the conventions installers
-- and the local scripts run into a hard dependency it does not need to be.  The failure would arrive on the first call.
IF OBJECT_ID (N'logs.uspStartExecutionLogging', N'P') IS NULL OR OBJECT_ID (N'logs.uspRecordExecutionError', N'P') IS NULL
BEGIN
    PRINT N'WARNING: logs.uspStartExecutionLogging or logs.uspRecordExecutionError is missing. The procedures in this '
        + N'file will install and will fail on their FIRST CALL with error 2812. Run '
        + N'.claude/skills/ponytail-sql-objects/scripts/logExecutionLogging.sql against this database.';
END
GO


-- *** 1. auth.uspRebuildTenantClosure ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspRebuildTenantClosure
Author:       rsincero
CreateDate:   2026-09-19
========================================================================================================================
Description:

Rebuilds auth.TenantClosure from auth.Tenant's parent edges, in full, in one transaction.  Idempotent: a second call
against an unchanged tree affects no rows.  Section 5.3.

Called by every procedure in this file that changes the shape of the tree, and by the Phase 1 test fixtures after they
write tenants directly.  Takes no session token and demands no permission, because it is not a request -- it is the
maintenance of a derived table, and every caller that IS a request has already authorized itself.

========================================================================================================================
Requirements and Key Dependencies:

auth.Tenant, auth.TenantClosure.

logs.uspStartExecutionLogging and logs.uspRecordExecutionError, for the rule 8 instrumentation block, plus
logs.ExecutionLog itself, which the completion UPDATE writes directly.  All three are installed by
scripts/logExecutionLogging.sql.

========================================================================================================================
Notes:

WHY IT REBUILDS WHOLE RATHER THAN PATCHING.  This is the decision the Phase 1 exit criterion exists to test.  A
re-parenting does not ADD ancestors to a subtree, it REPLACES them: move an administration from one agency to another and
every program beneath it must lose one set of ancestors and gain another.  An incremental algorithm that inserts the new
pairs and forgets to retire the old ones leaves a stale ancestor row behind -- and a stale ancestor row is a grant of
authority nobody granted, invisible to every test that only checks what the tree looks like after a fresh build.  So
there is no incremental path to get wrong.  Section 5.3 measured the cost as milliseconds for a few thousand rows.

"WHOLE" WITHOUT A DELETE.  Non-negotiable 3 forbids a hard delete anywhere in this database and the convention gate
enforces it, so the rebuild is a MERGE whose NOT MATCHED BY SOURCE branch sets IsDeleted = 1.  Retired pairs stay as
evidence: after a re-parenting, auth.TenantClosure holds the old ancestor rows flagged deleted with the actor and the
instant, which is a better audit trail than a delete would have left.

THE SOURCE IS NOT FILTERED ON IsDeleted, AND THAT IS LOAD-BEARING.  The edge CTE reads every tenant, deleted or not.  A
closure built over live tenants only would drop a soft-deleted mid-tree tenant from its descendants' ancestor set, and
auth.udfIsTenantUsable -- which decides usability by looking for an inactive or deleted ANCESTOR -- would then return 1
for a program under a deleted administration.  Failing open.  The closure records shape; the function decides usability.
BL-020.

THE MERGE SETS auditDeletedBy AND auditDeletedDateUtc ITSELF rather than leaving them to auth.trg_au_updt_TenantClosure.
CHECK constraints are evaluated BEFORE AFTER triggers, so CK_auth_TenantClosure_DeletedPair would reject the soft delete
before the trigger could fill the columns in.  The resurrection branch clears them the same way, for the same reason.

IT NEVER UPDATES AncestorTenantId OR DescendantTenantId.  auth.trg_au_updt_TenantClosure joins inserted to deleted on
that pair, and unlike an IDENTITY column nothing in the engine would stop a statement from changing it and making the
trigger stamp the wrong row.  The MERGE matches on the pair and writes Depth and the soft-delete columns only.

MAXRECURSION 100 IS STATED, NOT LEFT TO THE DEFAULT.  It happens to equal the server default, and writing it down is the
point: a tree deeper than 100 raises 530 and the rebuild fails loudly, instead of a future MAXRECURSION 0 somewhere
turning a cyclic edge into a query that never returns.  CK_auth_Tenant_NotOwnParent and auth.uspUpdateTenant's 50095
prevent cycles; this is the backstop for the case they miss.

THE COMMIT IS ALL OR NOTHING, which for this procedure means the closure is never half rebuilt.  A reader during the
transaction sees the previous closure under READ_COMMITTED_SNAPSHOT (000_prerequisites.sql sets it ON), which is the
correct answer -- the OLD tree is a consistent tree.

========================================================================================================================
Example Usage and Performance:

exec auth.uspRebuildTenantClosure;

One recursive CTE over IX_auth_Tenant_Parent and one MERGE against the clustered primary key.  For the 23 tenants of the
three Phase 1 variant trees it writes 60 pairs.  Instrumentation adds one singleton insert per call and one singleton
update on the successful path.

========================================================================================================================
Modification History:

Date:		2026-09-19
Author:		rsincero
Ticket:		T-018
Description:
Created.  Phase 1.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspRebuildTenantClosure
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspRebuildTenantClosure]')
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

    -- The procedure's own working values.  Hoisted above the transaction so the soft-delete stamp and the modification
    -- stamp on one row are the SAME instant rather than two SYSUTCDATETIME () calls a millisecond boundary can separate.
    DECLARE @Now     DATETIME2 (3)  = SYSUTCDATETIME ()
          , @Actor   NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                              , ORIGINAL_LOGIN ())
          , @Retired INT            = 0
          , @Written INT            = 0;

    -- Counts only.  The procedure has no parameters, so this records the size of the problem instead.
    SET @KeyParameters = CONCAT (N'Tenants=',    (SELECT COUNT (*) FROM auth.Tenant)
                               , N', LivePairsBefore=', (SELECT COUNT (*) FROM auth.TenantClosure WHERE IsDeleted = 0));

    SET @ContextMessage = N'Full rebuild of auth.TenantClosure. Retired pairs are soft-deleted, not removed.';

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

        -- The edge list, DELIBERATELY NOT FILTERED ON IsDeleted. See the header note; filtering here is the change that
        -- would make auth.udfIsTenantUsable fail open.
        WITH edge AS
        (
            SELECT t.TenantId
                 , t.ParentTenantId
              FROM auth.Tenant AS t
        )
        , closure AS
        (
            -- Anchor: the depth-0 self row for every tenant. Without it, "the scope of a grant at tenant X" would need
            -- an OR for X itself, and the OR is where somebody eventually writes AND.
            SELECT AncestorTenantId   = e.TenantId
                 , DescendantTenantId = e.TenantId
                 , Depth              = 0
              FROM edge AS e

            UNION ALL

            -- One level per iteration: every ancestor of a parent is an ancestor of its children.
            SELECT c.AncestorTenantId
                 , e.TenantId
                 , c.Depth + 1
              FROM closure AS c
              JOIN edge    AS e ON e.ParentTenantId = c.DescendantTenantId
        )
        MERGE auth.TenantClosure AS tgt
        USING (SELECT AncestorTenantId, DescendantTenantId, Depth FROM closure) AS src
           ON tgt.AncestorTenantId   = src.AncestorTenantId
          AND tgt.DescendantTenantId = src.DescendantTenantId

        -- The pair is still correct but its depth moved, or it had been retired and the tree brought it back. The
        -- auditDeleted* columns are cleared explicitly because CK_auth_TenantClosure_DeletedPair is checked before the
        -- trigger runs.
        WHEN MATCHED AND (tgt.Depth <> src.Depth OR tgt.IsDeleted = 1)
            THEN UPDATE SET tgt.Depth                = src.Depth
                          , tgt.IsDeleted            = 0
                          , tgt.auditDeletedBy       = NULL
                          , tgt.auditDeletedDateUtc  = NULL
                          , tgt.auditModifiedBy      = @Actor
                          , tgt.auditModifiedDateUtc = @Now

        WHEN NOT MATCHED BY TARGET
            THEN INSERT (AncestorTenantId, DescendantTenantId, Depth, auditCreatedBy)
                 VALUES (src.AncestorTenantId, src.DescendantTenantId, src.Depth, @Actor)

        -- "Rebuilt whole" without a DELETE. A pair the tree no longer implies is retired, with the actor and the
        -- instant, and stays as evidence of the re-parenting that retired it.
        WHEN NOT MATCHED BY SOURCE AND tgt.IsDeleted = 0
            THEN UPDATE SET tgt.IsDeleted            = 1
                          , tgt.auditDeletedBy       = @Actor
                          , tgt.auditDeletedDateUtc  = @Now
                          , tgt.auditModifiedBy      = @Actor
                          , tgt.auditModifiedDateUtc = @Now
        OPTION (MAXRECURSION 100);

        -- @@ROWCOUNT is reset by the next statement, so read it immediately.
        SET @Written = @@ROWCOUNT;

        SET @Retired = (SELECT COUNT (*) FROM auth.TenantClosure WHERE IsDeleted = 1);

        SET @Comments = CONCAT (@Written, N' closure row(s) inserted or updated. '
                              , (SELECT COUNT (*) FROM auth.TenantClosure WHERE IsDeleted = 0), N' live pair(s), '
                              , @Retired, N' retired pair(s) retained.');

        -- =========================================================================================
        -- ===== End of the procedure's own work. ===================================================
        -- =========================================================================================

        IF @@TRANCOUNT > 0
        BEGIN
            COMMIT TRANSACTION;
        END;

        -- Completion. Deliberately after the COMMIT; see templates/procedure.sql for what that costs.
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

        -- The ERROR_* functions are valid only in this scope and any statement can reset them, so capture them before
        -- doing anything else -- including before the rollback.
        SELECT @ErrorNumber = ERROR_NUMBER ()
             , @ErrorProc   = ERROR_PROCEDURE ()
             , @ErrorLine   = ERROR_LINE ()
             , @ErrorMsg    = ERROR_MESSAGE ()
                            + N' (error '  + CAST (ERROR_NUMBER () AS NVARCHAR (11))
                            + N', line '   + CAST (ERROR_LINE ()   AS NVARCHAR (11)) + N')';

        -- One test, not two: XACT_ABORT ON makes XACT_STATE () = -1 the common case, and -1 and 1 both need the same
        -- unqualified rollback.
        IF XACT_STATE () <> 0
        BEGIN
            ROLLBACK TRANSACTION;
        END;

        -- The rollback destroyed the row logs.uspStartExecutionLogging wrote. Put it back, with the ORIGINAL
        -- @StartTimeUtc, or the only unrecorded executions in the database would be the failures.
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


-- *** 2. auth.uspCreateTenant ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspCreateTenant
Author:       rsincero
CreateDate:   2026-09-19
========================================================================================================================
Description:

Adds a tenant beneath an existing one and rebuilds the closure.  Returns the new TenantId as an OUTPUT parameter.

Section 8.1 names the permission this demands: Tenant.Create, "add a tenant beneath one you administer".  The authority
is therefore tested at the PARENT, not at the new tenant -- which could not be tested, because it does not exist yet.

========================================================================================================================
Requirements and Key Dependencies:

auth.Tenant, auth.TenantType, auth.udfIsTenantUsable, auth.uspRebuildTenantClosure.

auth.uspSetSessionContext and auth.uspDemandPermission, which arrive in Phases 2 and 3.  Until then this procedure
installs and fails on call with error 2812; see the file header for why that is the intended state.

logs.uspStartExecutionLogging and logs.uspRecordExecutionError, per rule 8.

========================================================================================================================
Notes:

@ParentTenantId IS NOT NULL, WHICH MEANS THIS PROCEDURE CANNOT CREATE A ROOT.  Deliberate.  A root is the one tenant
whose creation is not an administrative act within an application -- it IS the application's tree coming into existence,
it has no parent at which to test authority, and INV-02 allows exactly one.  Roots are created by
900_bootstrap_first_admin.sql and by the test fixtures, as db_owner, and an attempt to make one here is 50094.

THE PERMISSION IS DEMANDED BEFORE THE PARENT IS VALIDATED, and the trade-off is worth stating because it looks backwards.
Validating first would mean a caller with no authority anywhere could learn which tenant ids exist, by reading 50090
("no such parent") where an unauthorized-but-real parent gives 50030.  Demanding first closes that: an unauthorized
caller gets 50030 whether the parent exists or not.  The cost is that an ADMINISTRATOR who mistypes a parent id also
gets 50030 rather than 50090, which reads as "you lack permission" when the truth is "that tenant does not exist".  The
UI should say so -- 50030 on a create means either, and the administrator can tell the difference by looking at the tree.

TenantTypeCode IS RESOLVED FROM THE CODE, NEVER SUPPLIED AS AN ID.  The caller names a type; this procedure finds the id
and writes BOTH columns, which is what keeps the denormalised pair honest without the caller having to know it exists.

THE CLOSURE REBUILD IS INSIDE THE TRANSACTION.  A committed tenant with no closure rows is a tenant that every scope test
fails closed on -- authority would silently disappear rather than leak, which is the safe direction but still wrong.
Committing them together means there is no window in which the tree and its closure disagree.

The rest of the instrumentation block is rule 8 boilerplate; auth.uspRebuildTenantClosure's header carries the reasoning.

========================================================================================================================
Example Usage and Performance:

declare @NewId int;
exec auth.uspCreateTenant @SessionTokenHash = 0x9F86..., @ParentTenantId = 2, @TenantCode = N'HAZ_WASTE'
                        , @TenantName = N'Hazardous Waste Program', @TenantTypeCode = N'Program'
                        , @NewTenantId = @NewId output;

Four singleton seeks plus the full closure rebuild, which is the dominant cost and is measured in milliseconds.

========================================================================================================================
Modification History:

Date:		2026-09-19
Author:		rsincero
Ticket:		T-021
Description:
Created.  Phase 1.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspCreateTenant
      @SessionTokenHash VARBINARY (32)
    , @ParentTenantId INT
    , @TenantCode     NVARCHAR (50)
    , @TenantName     NVARCHAR (200)
    , @TenantTypeCode NVARCHAR (50)
    , @NewTenantId    INT OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspCreateTenant]')
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

    DECLARE @Actor         NVARCHAR (255) = NULL
          , @ApplicationId INT            = NULL
          , @TenantTypeId  INT            = NULL
          , @Failure       NVARCHAR (2000) = NULL;

    -- Identifiers only. The session token is a CREDENTIAL and never appears here -- UI-16, and rule 8's own list.
    SET @KeyParameters = CONCAT (N'ParentTenantId=', @ParentTenantId
                               , N', TenantCode=',   @TenantCode
                               , N', TenantTypeCode=', @TenantTypeCode);

    SET @NewTenantId = NULL;

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

        -- Section 14.1: every procedure establishes its own context, and never trusts a previous call to have done it.
        -- UI-05 -- relying on a previous call works perfectly in development and fails intermittently under pooling.
        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        -- Section 14.2, and before any validation; see the header for the trade-off that buys.
        EXEC auth.uspDemandPermission @PermissionCode = N'Tenant.Create', @TenantId = @ParentTenantId;

        -- The actor, read AFTER the context is established, because that is what sets it.
        SET @Actor = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N''), ORIGINAL_LOGIN ());

        -- The parent must exist, be undeleted, and be USABLE -- which by section 5.4 means it and every tenant above it
        -- are active. Hanging a new program under a deactivated administration would create a tenant that cannot be
        -- signed in to, and it is kinder to refuse than to create it and let the first sign-in fail.
        SELECT @ApplicationId = t.ApplicationId
          FROM auth.Tenant AS t
         WHERE t.TenantId  = @ParentTenantId
           AND t.IsDeleted = 0;

        IF @ApplicationId IS NULL OR auth.udfIsTenantUsable (@ParentTenantId) = 0
        BEGIN
            SET @Failure = N'The parent tenant does not exist, has been deleted, or is unusable because it or a tenant '
                         + N'above it is inactive. No tenant was created.';
            ;THROW 50090, @Failure, 1;
        END;

        -- A root has no parent, so it cannot be created here. See the header.
        IF @TenantTypeCode = N'Root'
        BEGIN
            SET @Failure = N'A root tenant cannot be created through this procedure: INV-02 allows exactly one per '
                         + N'application and it has no parent at which to test authority. Roots are created by '
                         + N'900_bootstrap_first_admin.sql.';
            ;THROW 50094, @Failure, 1;
        END;

        SELECT @TenantTypeId = tt.TenantTypeId
          FROM auth.TenantType AS tt
         WHERE tt.TenantTypeCode = @TenantTypeCode
           AND tt.IsDeleted      = 0;

        IF @TenantTypeId IS NULL
        BEGIN
            SET @Failure = N'Unknown tenant type code. The seeded types are Root, Agency, Administration, Program, '
                         + N'Jurisdiction, ExternalOrganization and Division; a project may add its own.';
            ;THROW 50091, @Failure, 1;
        END;

        -- Caught here so the caller gets a number it can branch on and a message it can show, rather than 2601 from
        -- UX_auth_Tenant_Application_Code. The index is still the thing that GUARANTEES it under a race.
        IF EXISTS (SELECT 1
                     FROM auth.Tenant AS t
                    WHERE t.ApplicationId = @ApplicationId
                      AND t.TenantCode    = @TenantCode
                      AND t.IsDeleted     = 0)
        BEGIN
            SET @Failure = N'That tenant code is already in use in this application. Tenant codes must be unique within '
                         + N'an application; they may repeat across applications.';
            ;THROW 50092, @Failure, 1;
        END;

        -- auditCreatedBy is set EXPLICITLY, not left to its DEFAULT: under the pooled application login
        -- ORIGINAL_LOGIN () is the application's name, identical on every row. Section 14.4, F-02.
        INSERT auth.Tenant (ApplicationId, TenantCode, TenantName, TenantTypeId, TenantTypeCode, ParentTenantId
                          , auditCreatedBy, auditModifiedBy)
        VALUES (@ApplicationId, @TenantCode, @TenantName, @TenantTypeId, @TenantTypeCode, @ParentTenantId
              , @Actor, @Actor);

        SET @NewTenantId = CAST (SCOPE_IDENTITY () AS INT);

        -- Inside the transaction, so the tree and its closure are never committed out of step.
        EXEC auth.uspRebuildTenantClosure;

        SET @Comments = CONCAT (N'Created TenantId=', @NewTenantId, N' under ', @ParentTenantId
                              , N' in ApplicationId=', @ApplicationId, N'. Closure rebuilt.');

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

        -- A validation failure is rolled back like any other, so its start row is destroyed like any other when the
        -- caller had a transaction open. The resurrection block does not care which kind of error it was.
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


-- *** 3. auth.uspUpdateTenant ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspUpdateTenant
Author:       rsincero
CreateDate:   2026-09-19
========================================================================================================================
Description:

Renames or re-parents a tenant and rebuilds the closure.  Section 8.1 names the permission: Tenant.Update, "rename or
re-parent".

Every parameter except @SessionTokenHash and @TenantId is OPTIONAL: NULL means "leave this alone".  Passing all of them NULL
is a legal no-op that still rebuilds the closure, because a procedure with a conditional rebuild is a procedure with a
path that forgets to rebuild.

========================================================================================================================
Requirements and Key Dependencies:

auth.Tenant, auth.TenantType, auth.TenantClosure, auth.udfIsTenantUsable, auth.uspRebuildTenantClosure.

auth.uspSetSessionContext and auth.uspDemandPermission, which arrive in Phases 2 and 3.

logs.uspStartExecutionLogging and logs.uspRecordExecutionError, per rule 8.

========================================================================================================================
Notes:

RE-PARENTING IS THE CASE THIS WHOLE PHASE EXISTS TO GET RIGHT.  It is the operation an incremental closure algorithm
gets wrong, because it REPLACES a subtree's ancestors rather than adding to them.  This procedure does not attempt to be
clever about it: it writes the new parent and calls the full rebuild.

NULL MEANS "LEAVE ALONE", AND THAT IS UNAMBIGUOUS HERE ONLY BECAUSE OF INV-02.  Ordinarily a nullable parameter cannot
express "set this to NULL", and for @NewParentTenantId that would be re-parenting a tenant to no parent -- making it a
second root.  INV-02 forbids that outright, so the ambiguity has no legal case to represent.

TWO DISTINCT AUTHORITIES, DEMANDED SEPARATELY.  Section 14.2 says once per distinct authority, and a re-parenting has
two: you must be able to update the tenant you are moving AND to update the tenant you are moving it under.  Demanding
only the first would let an administrator of one administration graft their subtree under an agency they have no
authority over -- and every row would be internally consistent afterwards.

THE CYCLE TEST READS THE CLOSURE, NOT THE PARENT CHAIN.  "Is the proposed parent a descendant of the tenant being
moved?" is one seek against auth.TenantClosure including the depth-0 self row, which also catches the self-parent case
for free.  Walking parents instead would need a recursive query that, on an already-cyclic tree, would not terminate.
CK_auth_Tenant_NotOwnParent is the declarative backstop for the one-node case; 50095 is the general one.

THE CROSS-APPLICATION TEST HAS NO DECLARATIVE EQUIVALENT, deliberately.  A composite foreign key onto
(TenantId, ApplicationId) would enforce it, at the price of another unique index on auth.Tenant to point at -- and the
report at the end of 030_auth_tenant.sql counts live violations on every run, which covers the case where something
other than this procedure gets there first.

TenantCode IS CHANGEABLE AND TenantTypeCode IS NOT -- not on the type table, but the tenant's CHOICE of type is.  A code
rename is an ordinary administrative act: the code appears in SESSION_CONTEXT ('AppUser'), but that string is rebuilt
from the profile on every call, so it self-heals on the next one. Changing a tenant's type TO or FROM Root is refused
with 50094 rather than left to CK_auth_Tenant_RootHasNoParent's 547, because a number the UI can branch on is worth more
than a constraint name in a message.

========================================================================================================================
Example Usage and Performance:

exec auth.uspUpdateTenant @SessionTokenHash = 0x9F86..., @TenantId = 7, @NewParentTenantId = 3;   -- re-parent
exec auth.uspUpdateTenant @SessionTokenHash = 0x9F86..., @TenantId = 7, @TenantName = N'Radiological Health';

Singleton seeks plus the full closure rebuild, which dominates.

========================================================================================================================
Modification History:

Date:		2026-09-19
Author:		rsincero
Ticket:		T-021
Description:
Created.  Phase 1.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspUpdateTenant
      @SessionTokenHash  VARBINARY (32)
    , @TenantId          INT
    , @TenantCode        NVARCHAR (50)  = NULL
    , @TenantName        NVARCHAR (200) = NULL
    , @TenantTypeCode    NVARCHAR (50)  = NULL
    , @NewParentTenantId INT            = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspUpdateTenant]')
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

    DECLARE @Actor            NVARCHAR (255)  = NULL
          , @ApplicationId    INT             = NULL
          , @CurrentParentId  INT             = NULL
          , @NewTenantTypeId  INT             = NULL
          , @NewApplicationId INT             = NULL
          , @Failure          NVARCHAR (2000) = NULL;

    SET @KeyParameters = CONCAT (N'TenantId=',            @TenantId
                               , N', NewParentTenantId=', @NewParentTenantId
                               , N', TenantCode=',        @TenantCode
                               , N', TenantTypeCode=',    @TenantTypeCode);

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

        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        -- Authority 1 of 2: over the tenant being changed.
        EXEC auth.uspDemandPermission @PermissionCode = N'Tenant.Update', @TenantId = @TenantId;

        SET @Actor = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N''), ORIGINAL_LOGIN ());

        SELECT @ApplicationId   = t.ApplicationId
             , @CurrentParentId = t.ParentTenantId
          FROM auth.Tenant AS t
         WHERE t.TenantId  = @TenantId
           AND t.IsDeleted = 0;

        IF @ApplicationId IS NULL
        BEGIN
            SET @Failure = N'That tenant does not exist or has been deleted. Nothing was changed.';
            ;THROW 50093, @Failure, 1;
        END;

        -- A root is identified by having no parent, which CK_auth_Tenant_RootHasNoParent makes equivalent to being
        -- typed Root. Moving it would make its former tree parentless and its new tree two-rooted.
        IF @CurrentParentId IS NULL AND @NewParentTenantId IS NOT NULL
        BEGIN
            SET @Failure = N'The root tenant cannot be re-parented. It is the scope that means "everything" in its '
                         + N'application, and INV-02 allows exactly one. Nothing was changed.';
            ;THROW 50094, @Failure, 1;
        END;

        -- The type change, if one was asked for.
        IF @TenantTypeCode IS NOT NULL
        BEGIN
            -- Refused in BOTH directions. Typing a non-root as Root would need it to lose its parent; typing the root as
            -- anything else would need it to gain one. CK_auth_Tenant_RootHasNoParent would raise 547 either way; this
            -- gives the UI a number it can act on instead.
            IF @TenantTypeCode = N'Root' OR @CurrentParentId IS NULL
            BEGIN
                SET @Failure = N'A tenant''s type cannot be changed to or from Root. The root is defined by having no '
                             + N'parent, so changing its type would require changing the shape of the tree. Nothing was '
                             + N'changed.';
                ;THROW 50094, @Failure, 1;
            END;

            SELECT @NewTenantTypeId = tt.TenantTypeId
              FROM auth.TenantType AS tt
             WHERE tt.TenantTypeCode = @TenantTypeCode
               AND tt.IsDeleted      = 0;

            IF @NewTenantTypeId IS NULL
            BEGIN
                SET @Failure = N'Unknown tenant type code. Nothing was changed.';
                ;THROW 50091, @Failure, 1;
            END;
        END;

        -- The rename, if one was asked for. Tested against the application rather than globally, because codes are
        -- unique per application by design.
        IF @TenantCode IS NOT NULL
           AND EXISTS (SELECT 1
                         FROM auth.Tenant AS t
                        WHERE t.ApplicationId = @ApplicationId
                          AND t.TenantCode    = @TenantCode
                          AND t.TenantId     <> @TenantId
                          AND t.IsDeleted     = 0)
        BEGIN
            SET @Failure = N'That tenant code is already in use in this application. Nothing was changed.';
            ;THROW 50092, @Failure, 1;
        END;

        -- The re-parenting, if one was asked for.
        IF @NewParentTenantId IS NOT NULL
        BEGIN
            -- Authority 2 of 2: over the tenant it is being moved UNDER. See the header.
            EXEC auth.uspDemandPermission @PermissionCode = N'Tenant.Update', @TenantId = @NewParentTenantId;

            SELECT @NewApplicationId = p.ApplicationId
              FROM auth.Tenant AS p
             WHERE p.TenantId  = @NewParentTenantId
               AND p.IsDeleted = 0;

            IF @NewApplicationId IS NULL OR auth.udfIsTenantUsable (@NewParentTenantId) = 0
            BEGIN
                SET @Failure = N'The proposed parent does not exist, has been deleted, or is unusable because it or a '
                             + N'tenant above it is inactive. Nothing was changed.';
                ;THROW 50090, @Failure, 1;
            END;

            -- auth.Tenant.ApplicationId is immutable (auth.trg_au_updt_Tenant, 50010), so this move is not merely
            -- disallowed -- it is inexpressible. Refused here with a number that says why.
            IF @NewApplicationId <> @ApplicationId
            BEGIN
                SET @Failure = N'The proposed parent belongs to a different application. A tenant cannot cross '
                             + N'applications: the application scopes the roles and permissions every profile beneath '
                             + N'it holds. Nothing was changed.';
                ;THROW 50096, @Failure, 1;
            END;

            -- The cycle test, one seek. The depth-0 self row makes @NewParentTenantId = @TenantId a hit too, so the
            -- self-parent case needs no separate branch.
            IF EXISTS (SELECT 1
                         FROM auth.TenantClosure AS c
                        WHERE c.AncestorTenantId   = @TenantId
                          AND c.DescendantTenantId = @NewParentTenantId
                          AND c.IsDeleted          = 0)
            BEGIN
                SET @Failure = N'That move would place the tenant beneath one of its own descendants, or beneath itself. '
                             + N'Nothing was changed.';
                ;THROW 50095, @Failure, 1;
            END;
        END;

        -- One UPDATE for every change, with COALESCE doing the "leave alone" semantics. TenantTypeId and TenantTypeCode
        -- move together or not at all, which is what FK_auth_Tenant_TenantType requires of the pair.
        UPDATE auth.Tenant
           SET TenantCode      = COALESCE (@TenantCode,       TenantCode)
             , TenantName      = COALESCE (@TenantName,       TenantName)
             , TenantTypeId    = COALESCE (@NewTenantTypeId,  TenantTypeId)
             , TenantTypeCode  = COALESCE (@TenantTypeCode,   TenantTypeCode)
             , ParentTenantId  = COALESCE (@NewParentTenantId, ParentTenantId)
             , auditModifiedBy = @Actor
         WHERE TenantId  = @TenantId
           AND IsDeleted = 0;

        -- Unconditional, even when nothing moved. A conditional rebuild is a rebuild somebody eventually skips.
        EXEC auth.uspRebuildTenantClosure;

        SET @Comments = CONCAT (N'Updated TenantId=', @TenantId
                              , CASE WHEN @NewParentTenantId IS NULL THEN N'' ELSE CONCAT (N', re-parented from '
                                    , @CurrentParentId, N' to ', @NewParentTenantId) END
                              , N'. Closure rebuilt.');

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


-- *** 4. auth.uspDeactivateTenant ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspDeactivateTenant
Author:       rsincero
CreateDate:   2026-09-19
========================================================================================================================
Description:

Takes a tenant out of service by setting IsActive = 0, which -- through auth.udfIsTenantUsable -- also takes every
tenant beneath it out of service, without writing to any of them.  Section 8.1 names the permission:
Tenant.Deactivate, "take a tenant out of service".

Reactivation is the same procedure with @IsActive = 1.  There is no separate uspActivateTenant, because the two
operations share every validation and one of them would eventually drift.

========================================================================================================================
Requirements and Key Dependencies:

auth.Tenant, auth.udfIsTenantUsable, auth.uspRebuildTenantClosure.

auth.uspSetSessionContext and auth.uspDemandPermission, which arrive in Phases 2 and 3.

logs.uspStartExecutionLogging and logs.uspRecordExecutionError, per rule 8.

========================================================================================================================
Notes:

IT SETS IsActive, NEVER IsDeleted, and the difference is the whole point of the procedure.  Deactivation is reversible
and visible: the tenant still appears in auth.vwTenantHierarchy, its descendants still appear, and every one of them
reads as unusable until it is reactivated.  A soft delete is a different act with a different permission
(Tenant.Delete, section 8.1) and it removes the subtree from the display entirely.  Nothing in this file deletes a
tenant; when that procedure is written it belongs in this file next to this one.

DEACTIVATION IS NOT CASCADED, AND THAT IS WHY IT CAN BE UNDONE.  Writing IsActive = 0 to the whole subtree would make
reactivation ambiguous -- which of those tenants was already inactive before?  Ancestor-aware usability
(auth.udfIsTenantUsable, section 5.4) gives the cascade for free and keeps each tenant's own flag meaning only what
somebody set deliberately.  Section 5.4 is where that division is stated; this procedure is what depends on it.

THE ROOT CANNOT BE DEACTIVATED, 50094.  Its closure covers every tenant in the application, so deactivating it would
make every acting tenant unusable and every sign-in fail with 50021 -- an application-wide outage with no error
message that says what happened.  If an application genuinely has to be switched off, that is a change to
auth.Application, not to its root tenant.

IT STILL REBUILDS THE CLOSURE, AND NOTHING IT DOES CHANGES THE CLOSURE.  A flag change moves no tenant, so the rebuild
is provably a no-op here: auth.uspRebuildTenantClosure will report 0 rows written.  It is called anyway, because the
rule "every procedure that writes auth.Tenant rebuilds the closure" is one an auditor can check by reading, whereas
"every procedure that writes auth.Tenant EXCEPT this one, because flags do not affect shape" is a rule somebody will
extend to a procedure where it is not true.  The cost is one MERGE against a table with a clustered key on the pair.

NO-OP WRITES ARE ALLOWED THROUGH.  Deactivating an already-inactive tenant succeeds and says so in the log comment
rather than raising.  A UI that fires the same request twice, or two administrators clicking at once, should not see an
error for reaching the state they asked for.

========================================================================================================================
Example Usage and Performance:

exec auth.uspDeactivateTenant @SessionTokenHash = 0x9F86..., @TenantId = 7;                 -- take out of service
exec auth.uspDeactivateTenant @SessionTokenHash = 0x9F86..., @TenantId = 7, @IsActive = 1;  -- put back

One seek and one singleton update, plus a closure rebuild that writes nothing.

========================================================================================================================
Modification History:

Date:		2026-09-19
Author:		rsincero
Ticket:		T-021
Description:
Created.  Phase 1.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspDeactivateTenant
      @SessionTokenHash VARBINARY (32)
    , @TenantId         INT
    , @IsActive     BIT = 0
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspDeactivateTenant]')
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
          , @ParentTenantId INT             = NULL
          , @TenantCode     NVARCHAR (50)   = NULL
          , @WasActive      BIT             = NULL
          , @Found          BIT             = 0
          , @Descendants    INT             = 0
          , @Failure        NVARCHAR (2000) = NULL;

    SET @KeyParameters = CONCAT (N'TenantId=', @TenantId, N', IsActive=', @IsActive);

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

        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        EXEC auth.uspDemandPermission @PermissionCode = N'Tenant.Deactivate', @TenantId = @TenantId;

        SET @Actor = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N''), ORIGINAL_LOGIN ());

        SELECT @Found          = 1
             , @ParentTenantId = t.ParentTenantId
             , @TenantCode     = t.TenantCode
             , @WasActive      = t.IsActive
          FROM auth.Tenant AS t
         WHERE t.TenantId  = @TenantId
           AND t.IsDeleted = 0;

        IF @Found = 0
        BEGIN
            SET @Failure = N'That tenant does not exist or has been deleted. Nothing was changed.';
            ;THROW 50093, @Failure, 1;
        END;

        -- Root only, and only for deactivation -- reactivating a root that somehow got switched off must stay possible.
        IF @ParentTenantId IS NULL AND @IsActive = 0
        BEGIN
            SET @Failure = N'The root tenant cannot be deactivated. Its closure covers every tenant in the '
                         + N'application, so every sign-in would fail with 50021 and nothing would say why. Switch the '
                         + N'application off instead. Nothing was changed.';
            ;THROW 50094, @Failure, 1;
        END;

        -- Counted for the log comment, so the transcript records how far the change reaches.  Excludes the depth-0 self
        -- row, and reads the live closure: a soft-deleted pair describes a tenant that has already been moved away.
        SELECT @Descendants = COUNT (*)
          FROM auth.TenantClosure AS c
         WHERE c.AncestorTenantId = @TenantId
           AND c.Depth           > 0
           AND c.IsDeleted        = 0;

        -- No guard on the current value: reaching the state the caller asked for is not an error. See the header.
        UPDATE auth.Tenant
           SET IsActive        = @IsActive
             , auditModifiedBy = @Actor
         WHERE TenantId  = @TenantId
           AND IsDeleted = 0;

        -- A flag change moves nothing, so this writes 0 rows -- called regardless, because the rule has no exceptions.
        EXEC auth.uspRebuildTenantClosure;

        SET @Comments = CONCAT (N'Tenant ', @TenantCode, N' (TenantId=', @TenantId, N') IsActive '
                              , @WasActive, N' -> ', @IsActive, N'. '
                              , @Descendants, N' descendant tenant(s) follow it through auth.udfIsTenantUsable without '
                              , N'being written to.'
                              , CASE WHEN @WasActive = @IsActive THEN N' Already in that state; no change.' ELSE N'' END);

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


-- *** 5. auth.uspGetTenantTree ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspGetTenantTree
Author:       rsincero
CreateDate:   2026-09-19
========================================================================================================================
Description:

The tenant tree for one application, or one subtree of it, with a usability verdict on every node.  What an
administration screen binds to.  Reads only; writes nothing except a log row on failure.

Called with @RootTenantId, it returns that tenant and everything beneath it.  Called with @ApplicationId, it returns
the whole application from its root down.  One of the two is required.

========================================================================================================================
Requirements and Key Dependencies:

auth.vwTenantHierarchy -- for the path, the depth and the type label.
auth.udfIsTenantUsable -- for IsUsable, one call per row, inlined by Froid.
auth.TenantClosure     -- for the subtree restriction, which is a seek rather than a second recursion.

auth.uspSetSessionContext and auth.uspDemandPermission, which arrive in Phases 2 and 3.

logs.uspRecordExecutionError.  NOT logs.uspStartExecutionLogging: this is the error-only shape, per rule 8.

========================================================================================================================
Notes:

THIS IS THE ERROR-ONLY TEMPLATE, because this procedure only reads.  No start row, no completion UPDATE, no
resurrection block, no transaction.  @ExecutionLogId is passed as NULL in the CATCH and @ContextMessage says why, so
the orphan row is not read as a lost start row.  An administration screen that refreshes is exactly the caller that
would fill logs.ExecutionLog with a record of people looking at things.

IT IS THE OBJECT THAT JOINS THE VIEW TO THE FUNCTION, and that is its reason for existing rather than the UI selecting
from auth.vwTenantHierarchy directly.  The view cannot call auth.udfIsTenantUsable -- 095_auth_views.sql installs at
position 20 and 100_auth_functions.sql at 21, and CREATE VIEW resolves names immediately, so the reference would fail
with 208 on a first deployment.  A PROCEDURE gets DEFERRED name resolution, so this one may reference both.  The
alternative -- duplicating the usability rule inside the view -- was rejected: two copies of a security-relevant rule
drift, and the copy that drifts is the one nobody is testing.

THE SUBTREE FILTER READS THE CLOSURE, NOT THE VIEW'S PATH.  auth.TenantClosure answers "is this tenant at or below
@RootTenantId" with one seek on IX_auth_TenantClosure_Descendant.  Filtering on TenantPath LIKE instead would scan, and
would break the moment a tenant code became a prefix of another.

IT DOES NOT FILTER BY WHAT THE CALLER MAY SEE, and in Phase 1 that is a real limitation stated rather than hidden.  It
demands Tenant.Read at the requested scope and then returns that whole scope.  Row-level security (section 21) is what
restricts a caller to its own subtree, and it arrives in Phase 2 -- at which point the RLS predicate applies to
auth.Tenant beneath the view and this procedure narrows automatically, with no change here.  Until then, a caller
holding Tenant.Read at a root sees the root's whole tree, which is what Tenant.Read at a root means anyway.

AnyAncestorInactive AND IsUsable BOTH APPEAR, AND THEY ARE NOT THE SAME COLUMN.  The first comes from the view and
ignores soft-deleted tenants, because the view excludes them and their subtrees.  The second is the single definition
(section 5.4) and reads the closure, where soft-deleted tenants are still present.  A screen should grey out on
IsUsable and may explain itself with AnyAncestorInactive; a security decision uses IsUsable and nothing else.

========================================================================================================================
Example Usage and Performance:

exec auth.uspGetTenantTree @SessionTokenHash = 0x9F86..., @ApplicationId = 2;
exec auth.uspGetTenantTree @SessionTokenHash = 0x9F86..., @RootTenantId  = 4;

The view's recursion over IX_auth_Tenant_Parent, one closure seek per row for the filter, and an inlined function call
per row.  Sized for an administration screen, not for the request path -- an authorization decision reads
auth.TenantClosure directly, which is a seek.

========================================================================================================================
Modification History:

Date:		2026-09-19
Author:		rsincero
Ticket:		T-021
Description:
Created.  Phase 1.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspGetTenantTree
      @SessionTokenHash VARBINARY (32)
    , @ApplicationId    INT = NULL
    , @RootTenantId   INT = NULL
    , @IncludeInactive BIT = 1
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 error-only instrumentation. Boilerplate: copy verbatim.
    -- Shorter than the full block by exactly what a read does not need. Do not reintroduce
    -- @ExecutionId, @StartTimeUtc, @EndTimeUtc or @Comments -- a start row without a completion makes
    -- every call look like a failure in the monitoring grid.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspGetTenantTree]')
          , @KeyParameters  NVARCHAR (MAX) = NULL
          , @ContextMessage NVARCHAR (MAX) = NULL
          , @DynamicSql     NVARCHAR (MAX) = NULL
          , @ErrorMsg       NVARCHAR (MAX) = NULL
          , @ErrorProc      NVARCHAR (300) = NULL
          , @ErrorNumber    INT            = NULL
          , @ErrorLine      INT            = NULL;

    DECLARE @ScopeTenantId INT             = NULL
          , @Failure       NVARCHAR (2000) = NULL;

    -- Identifiers and flags only. No free text reaches this string.
    SET @KeyParameters = CONCAT (N'ApplicationId=',    @ApplicationId
                               , N', RootTenantId=',   @RootTenantId
                               , N', IncludeInactive=', @IncludeInactive);

    -- Says why the row this procedure logs has no ExecutionLogId, so the orphan is not read as a lost start row.
    SET @ContextMessage = N'Error-only instrumented read: no start row is opened, so @ExecutionLogId is NULL by design.';

    BEGIN TRY

        -- Validation inside the TRY, so a bad argument is recorded under this procedure's name rather than swallowed.
        IF (@ApplicationId IS NULL AND @RootTenantId IS NULL)
           OR (@ApplicationId IS NOT NULL AND @RootTenantId IS NOT NULL)
        BEGIN
            SET @Failure = N'Supply exactly one of @ApplicationId or @RootTenantId. The first returns an application '
                         + N'from its root down; the second returns one subtree.';
            ;THROW 50000, @Failure, 1;
        END;

        -- =========================================================================================
        -- ===== The procedure's own work starts here. Everything above and below is boilerplate. ==
        -- =========================================================================================

        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        -- Resolve the scope BEFORE demanding on it: an application request is authorized at that application's root,
        -- because that is the tenant Tenant.Read can be granted at.
        IF @RootTenantId IS NOT NULL
        BEGIN
            SET @ScopeTenantId = @RootTenantId;
        END
        ELSE
        BEGIN
            SELECT @ScopeTenantId = t.TenantId
              FROM auth.Tenant AS t
             WHERE t.ApplicationId  = @ApplicationId
               AND t.ParentTenantId IS NULL
               AND t.IsDeleted      = 0;
        END;

        IF @ScopeTenantId IS NULL
           OR NOT EXISTS (SELECT 1
                            FROM auth.Tenant AS t
                           WHERE t.TenantId  = @ScopeTenantId
                             AND t.IsDeleted = 0)
        BEGIN
            SET @Failure = N'That tenant or application does not exist, has been deleted, or has no root tenant yet.';
            ;THROW 50093, @Failure, 1;
        END;

        -- One authority: read at the requested scope. Unusable scopes are still readable -- an administrator has to be
        -- able to see the deactivated tenant in order to reactivate it.
        EXEC auth.uspDemandPermission @PermissionCode = N'Tenant.Read', @TenantId = @ScopeTenantId;

        SELECT
              v.TenantId
            , v.ApplicationId
            , v.ApplicationCode
            , v.TenantCode
            , v.TenantName
            , v.TenantTypeId
            , v.TenantTypeCode
            , v.TenantTypeName
            , v.ParentTenantId
            , v.RootTenantId
            , v.Depth
            , v.TenantPath
            , v.IsActive
            , v.AnyAncestorInactive
            -- The single definition of usability, section 5.4, which the view cannot carry -- see the header. Inlined
            -- by Froid, so this is part of the plan rather than a call per row.
            , IsUsable = auth.udfIsTenantUsable (v.TenantId)
            -- Depth below the REQUESTED scope, which is what a tree control indents by. Differs from v.Depth whenever
            -- the request was for a subtree rather than a whole application.
            , ScopeDepth = c.Depth
          FROM auth.vwTenantHierarchy AS v
          -- The subtree restriction, one seek. INNER JOIN, so a tenant outside the scope is simply absent, and the
          -- depth-0 self row is what includes the scope tenant itself.
          JOIN auth.TenantClosure     AS c ON c.DescendantTenantId = v.TenantId
                                          AND c.AncestorTenantId   = @ScopeTenantId
                                          AND c.IsDeleted          = 0
         WHERE (@IncludeInactive = 1
                -- Its OWN flag only. Filtering on usability instead would hide a whole subtree because of one
                -- deactivated tenant above it, which is the opposite of what an administrator needs to see.
                OR v.IsActive = 1)
         ORDER BY v.TenantPath;

        -- =========================================================================================
        -- ===== End of the procedure's own work. ===================================================
        -- =========================================================================================

        -- Nothing here. No completion UPDATE: there is no row to complete, by design.

    END TRY
    BEGIN CATCH

        SELECT @ErrorNumber = ERROR_NUMBER ()
             , @ErrorProc   = ERROR_PROCEDURE ()
             , @ErrorLine   = ERROR_LINE ()
             , @ErrorMsg    = ERROR_MESSAGE ()
                            + N' (error '  + CAST (ERROR_NUMBER () AS NVARCHAR (11))
                            + N', line '   + CAST (ERROR_LINE ()   AS NVARCHAR (11)) + N')';

        -- No rollback. Nothing here writes, and a caller's transaction is not this procedure's to end.

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


-- *** 6. auth.uspSetTenantAuthenticationPolicy ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspSetTenantAuthenticationPolicy
Author:       rsincero
CreateDate:   2026-09-21
========================================================================================================================
Description:

Writes one tenant's row in auth.TenantAuthenticationPolicy -- the sign-in rules section 7.2 resolves
nearest-ancestor-wins -- and, optionally, that tenant's trusted-issuer list.  Creates the row if the tenant has none.
Every parameter but @SessionTokenHash and @TenantId is optional and NULL means LEAVE ALONE.  Demands Tenant.Update at the
tenant.  Refuses a combination that would describe a tenant nobody can sign in to (E-50097).  Gap G-43.

========================================================================================================================
Requirements and Key Dependencies:

auth.Tenant, auth.TenantAuthenticationPolicy, auth.TenantTrustedIssuer, config.ApplicationSetting,
auth.uspSetSessionContext, auth.uspDemandPermission, logs.uspRecordAuthorizationChange.  Granted to applicationRole.

========================================================================================================================
Notes:

WHY THIS EXISTS AT ALL.  Section 7.2 designs auth.TenantAuthenticationPolicy as the per-tenant sign-in contract, and
until this procedure there was no shipped writer for it: 900_bootstrap_first_admin.sql writes the root's row and nothing
writes another.  So "require a second factor at this agency" -- the first request a multi-tenant deployment generates --
could only be satisfied by a hand-written UPDATE, which INV-11 forbids the application to issue and which leaves no
authorization trail when a DBA issues it instead.  Two other gaps propose tightening a policy row as their remedy
(G-30's step-up default and G-37's RequireMfaForLocal = 0 at the root) and neither had a supported way to do it.

NULL MEANS LEAVE ALONE, AND ON A ROW THAT DOES NOT EXIST YET IT MEANS TAKE THE TEMPLATE'S DEFAULT.  The same convention
as auth.uspUpdateTenant, and it is the only one that lets a screen with four checkboxes on it save one of them.  The
defaults used when the row is created are the column defaults 035_auth_tenant_policy.sql declares -- federated off,
local password on, MFA for local ON, LocalPassword preferred, 480 and 60 minutes -- WITH ONE DELIBERATE EXCEPTION:

  RequireStepUpForPrivileged is seeded from config.ApplicationSetting's Authn.RequireStepUpForPrivilegedDefault and NOT
  from the column default of 0.  That key is G-30's resolution and it ships as 1, so a policy row created here fails
  CLOSED.  Taking the column default instead would mean that the procedure whose reason for existing is "let an
  administrator tighten a policy" shipped a default that silently loosened one.  The column default stays 0 because
  changing it would rewrite the meaning of every row a project has already inserted by hand.

THE COMBINATION IS CHECKED BEFORE ANYTHING IS WRITTEN, AND THAT IS WHAT E-50097 IS FOR.  Three CHECK constraints on the
table already refuse an unusable policy -- CK_..._PreferredMethod, CK_..._PreferredIsAllowed and CK_..._Lifetimes -- so
the row could not be stored wrong even without this procedure.  What they cannot do is explain themselves: a caller who
sends AllowFederated = 0 with PreferredMethod = 'Federated' gets Msg 547 naming a constraint they have never heard of,
from an application that then has to map constraint names onto messages.  E-50097 is raised for all four ways the
combination is unusable, with the message naming WHICH -- one number because the remedy is the same in every case
(restate the policy), and four messages because the fault is not.

A POLICY THAT ALLOWS NEITHER METHOD IS ALREADY IMPOSSIBLE, WHICH IS WORTH SAYING OUT LOUD.  G-43's resolution asks for
"a policy that allows neither local nor federated sign-in should be refused, not stored", and
CK_..._PreferredIsAllowed already guarantees it: PreferredMethod must be one of the two literals AND that literal must be
the allowed one, so at least one method is always permitted.  The refusal here is therefore a better MESSAGE rather than
a new control, and this note exists so that nobody reading the gap register concludes the control was missing.

INACTIVE IS EDITABLE; DELETED IS NOT.  The tenant must exist and be undeleted (E-50093) and it does NOT have to be
usable.  auth.uspCreateTenant refuses an unusable parent because hanging a live tenant under a dead one creates something
nobody can sign in to; here the opposite holds -- fixing a policy is exactly what somebody does BEFORE putting a tenant
back into service, and refusing it would mean reactivating first and running with the old rules for however long the
edit takes.

THE TRUSTED-ISSUER LIST IS HERE AND NOT IN A PROCEDURE OF ITS OWN -- G-21.  035_auth_tenant_policy.sql added
auth.TenantTrustedIssuer and auth.uspBeginSsoLogin refuses an issuer that is not on the resolved tenant's list
(E-50124), which left the list itself writable only by hand.  It belongs on this call because it is the other half of one
decision: AllowFederated = 1 with an empty issuer list is a tenant that has federation switched on and trusts nobody,
and a screen that can set the first without the second will produce exactly that.  @TrustedIssuersJson follows
auth.uspSetRolePermissions' convention -- NULL means "I did not say", so the list is left alone, and [] means "trust
nobody", which is how a subtree's federation is revoked without switching AllowFederated off.  The combination is
REPORTED and not refused: @Comments names it, and the closing report of 035 already names it for the database as a whole.

THERE IS NO WAY BACK TO INHERITING, AND THAT IS A REAL LIMIT RATHER THAN AN OVERSIGHT.  A tenant with no policy row
inherits its nearest ancestor's; this procedure CREATES a row and can never remove one, so the first call at a tenant
converts it permanently from "follows its parent" to "has its own rules", and every later change at the ancestor stops
reaching it.  Restoring inheritance means soft-deleting the row, which needs table rights INV-11 withholds.  Adding a
@ClearPolicy BIT was considered and left out of this pass: it is the same request as "this tenant deliberately seeds no
default roles" in section 7 -- an intent the schema can hold but no call can express -- so both are filed together as
G-44 rather than half-answered here.  @Comments says "policy row CREATED" precisely so the conversion is visible in the
log of the call that caused it.

THE PERMISSION IS DEMANDED BEFORE THE TENANT IS LOOKED UP, SO AN UNKNOWN @TenantId USUALLY READS AS E-50030 AND NOT AS
E-50093.  Measured, not assumed: @TenantId = 999999 returns 50030, permission denied, because auth.uspDemandPermission
cannot find a scope grant covering a tenant that does not exist.  That is auth.uspCreateTenant's documented trade made
again -- an administrator's typo reads the same as an attempt on a tenant they have no authority over, which is the price
of not leaking which tenant ids exist.  E-50093 is therefore reached in one case: a tenant inside the caller's authority
that has been SOFT-DELETED, where the closure still carries the pair and the row is gone.  Both procedures in this file
behave the same way and the test file probes the soft-deleted path deliberately, because a refusal whose only reachable
route is untested is a message nobody has ever read.

VALIDATION IS OUTSIDE THE TRANSACTION.  auth.uspCreateTenant and its three Phase 1 siblings open the transaction first
and validate inside it; 145_auth_role_procedures.sql does the opposite, and the later pattern is the right one -- a
refusal that rolled nothing back should not have had a transaction to roll back.  The two are not reconciled here
because rewriting four working Phase 1 procedures to move a BEGIN TRANSACTION is a change with no observable effect and
a real chance of moving a validation across the line by accident.

========================================================================================================================
Example Usage and Performance:

-- Require a second factor for local sign-in at one agency, and shorten its idle timeout.
exec auth.uspSetTenantAuthenticationPolicy @SessionTokenHash = 0x9F86..., @TenantId = 7
                                         , @RequireMfaForLocal = 1, @IdleTimeoutMinutes = 15;

-- Turn federation on for a subtree and name the one provider it trusts, in one call.
exec auth.uspSetTenantAuthenticationPolicy @SessionTokenHash = 0x9F86..., @TenantId = 7
                                         , @AllowFederated = 1, @PreferredMethod = 'Federated'
                                         , @TrustedIssuersJson = N'["https://login.microsoftonline.com/abc/v2.0"]';

-- E-50097: prefers a method the same call forbids.
exec auth.uspSetTenantAuthenticationPolicy @SessionTokenHash = 0x9F86..., @TenantId = 7
                                         , @AllowFederated = 0, @PreferredMethod = 'Federated';

One seek for the tenant, one for the policy row, one settings read, and -- where the issuer list was supplied -- one
parse and two anti-joins over a list whose realistic length is one.

========================================================================================================================
Modification History:

Date:		2026-09-21
Author:		rsincero
Ticket:		G-43
Description:
Created.  The first shipped writer of auth.TenantAuthenticationPolicy and auth.TenantTrustedIssuer.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspSetTenantAuthenticationPolicy
      @SessionTokenHash           VARBINARY (32)
    , @TenantId                   INT
    , @AllowFederated             BIT             = NULL
    , @AllowLocalPassword         BIT             = NULL
    , @RequireMfaForLocal         BIT             = NULL
    , @PreferredMethod            VARCHAR (20)    = NULL
    , @SessionLifetimeMinutes     INT             = NULL
    , @IdleTimeoutMinutes         INT             = NULL
    , @RequireStepUpForPrivileged BIT             = NULL
    , @PolicyNote                 NVARCHAR (1000) = NULL
    , @TrustedIssuersJson         NVARCHAR (MAX)  = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspSetTenantAuthenticationPolicy]')
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

    DECLARE @Actor           NVARCHAR (255)  = NULL
          , @ActorProfileId  INT             = NULL
          , @ActingTenantId  INT             = NULL
          , @ApplicationId   INT             = NULL
          , @TenantCode      NVARCHAR (50)   = NULL
          , @IsActive        BIT             = NULL
          , @PolicyId        INT             = NULL
          , @Created         BIT             = 0
          , @Now             DATETIME2 (3)   = SYSUTCDATETIME ()
          , @StepUpDefault   BIT             = NULL
          , @CurFederated    BIT             = NULL
          , @CurLocal        BIT             = NULL
          , @CurMfa          BIT             = NULL
          , @CurPreferred    VARCHAR (20)    = NULL
          , @CurLifetime     INT             = NULL
          , @CurIdle         INT             = NULL
          , @CurStepUp       BIT             = NULL
          , @NewFederated    BIT             = NULL
          , @NewLocal        BIT             = NULL
          , @NewMfa          BIT             = NULL
          , @NewPreferred    VARCHAR (20)    = NULL
          , @NewLifetime     INT             = NULL
          , @NewIdle         INT             = NULL
          , @NewStepUp       BIT             = NULL
          , @FieldsChanged   INT             = 0
          , @IssuersAdded    INT             = 0
          , @IssuersRemoved  INT             = 0
          , @IssuerCount     INT             = 0
          , @BadOrdinal      INT             = NULL
          , @BadType         INT             = NULL
          , @BadRaw          NVARCHAR (200)  = NULL
          , @Issuer          NVARCHAR (512)  = NULL
          , @RowNo           INT             = 1
          , @MaxRowNo        INT             = 0
          , @ChangeId        BIGINT          = NULL
          , @DetailJson      NVARCHAR (2000) = NULL
          , @Failure         NVARCHAR (2000) = NULL;

    -- NO PRIMARY KEY, and the reason is a warning worth not shipping: an index key may be 900 bytes and
    -- NVARCHAR (512) is 1024, so a PK here makes SQL Server print "the insert/update operation will fail" on every
    -- deployment and then really fail on any issuer longer than 450 characters -- which
    -- CK_auth_TenantTrustedIssuer_Issuer permits, since it caps the column at 512 and not at 450.  Deduplication is
    -- done by the DISTINCT on the INSERT below, where it belongs; the key was only ever belt and braces over it.
    DECLARE @Incoming TABLE (Issuer NVARCHAR (512) NOT NULL);

    -- RowNo IDENTITY and a walk from 1 to MAX rather than a drain: the conventions forbid a hard DELETE anywhere in this
    -- codebase, and a table variable is not worth an exception nobody reading it could tell from a real one.
    DECLARE @AddedIssuers   TABLE (RowNo INT IDENTITY (1, 1) PRIMARY KEY, Issuer NVARCHAR (512) NOT NULL);
    DECLARE @RemovedIssuers TABLE (RowNo INT IDENTITY (1, 1) PRIMARY KEY, Issuer NVARCHAR (512) NOT NULL);

    -- Identifiers, flags and counts. The session token is a CREDENTIAL and never appears here -- UI-16. The issuer list
    -- is not a secret but it is unbounded, so its LENGTH goes in and its contents do not.
    SET @KeyParameters = CONCAT (N'TenantId=', @TenantId
                               , N', AllowFederated=',     COALESCE (CAST (@AllowFederated     AS NVARCHAR (1)), N'(null)')
                               , N', AllowLocalPassword=', COALESCE (CAST (@AllowLocalPassword AS NVARCHAR (1)), N'(null)')
                               , N', RequireMfaForLocal=',  COALESCE (CAST (@RequireMfaForLocal AS NVARCHAR (1)), N'(null)')
                               , N', PreferredMethod=',     COALESCE (@PreferredMethod, '(null)')
                               , N', SessionLifetimeMinutes=', COALESCE (CAST (@SessionLifetimeMinutes AS NVARCHAR (11)), N'(null)')
                               , N', IdleTimeoutMinutes=',  COALESCE (CAST (@IdleTimeoutMinutes AS NVARCHAR (11)), N'(null)')
                               , N', RequireStepUpForPrivileged=', COALESCE (CAST (@RequireStepUpForPrivileged AS NVARCHAR (1)), N'(null)')
                               , N', TrustedIssuersJson length=', COALESCE (CAST (LEN (@TrustedIssuersJson) AS NVARCHAR (11)), N'(null)'));

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

        -- Section 14.1: every procedure establishes its own context and never trusts a previous call to have done it.
        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        -- Demanded AT THE TENANT, which is what bounds the authority: Tenant.Update held at an ancestor reaches this
        -- tenant, and held anywhere else it does not. G-43's text proposes "Tenant.Manage or Config.Manage", and neither
        -- code exists -- Appendix A ships Tenant.Create, Tenant.Read, Tenant.Update, Tenant.Deactivate and the four
        -- Config codes. Inventing a code would mean editing Appendix A, 115_seed_reference_data.sql, the shipped role
        -- bundles and 900_bootstrap_first_admin.sql to create a permission that differs from Tenant.Update in nothing a
        -- reader could state, so the existing tenant-scoped write permission is used and the deviation is recorded here
        -- and in the gap register rather than resolved by adding a synonym.
        EXEC auth.uspDemandPermission @PermissionCode = N'Tenant.Update', @TenantId = @TenantId;

        SET @Actor          = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N''), ORIGINAL_LOGIN ());
        SET @ActorProfileId = TRY_CAST (SESSION_CONTEXT (N'UserProfileId')  AS INT);
        SET @ActingTenantId = TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT);

        SELECT @ApplicationId = t.ApplicationId
             , @TenantCode    = t.TenantCode
             , @IsActive      = t.IsActive
          FROM auth.Tenant AS t
         WHERE t.TenantId  = @TenantId
           AND t.IsDeleted = 0;

        IF @ApplicationId IS NULL
        BEGIN
            SET @Failure = N'That tenant does not exist or has been deleted. An INACTIVE tenant is accepted on purpose '
                         + N'-- correcting a policy is what somebody does before putting a tenant back into service. '
                         + N'Nothing was changed.';
            ;THROW 50093, @Failure, 1;
        END;

        -- G-30's key, read before the row is created because it decides one of the values that goes into it. The
        -- COALESCE to 1 rather than to 0 matters on a database where 025_config_tables.sql predates that gap: the
        -- template's stated default is ON, and a missing key must not quietly become the opposite.
        SET @StepUpDefault = COALESCE (TRY_CAST ((SELECT s.SettingValue
                                                    FROM config.ApplicationSetting AS s
                                                   WHERE s.SettingKey = N'Authn.RequireStepUpForPrivilegedDefault'
                                                     AND s.IsDeleted  = 0) AS BIT), 1);

        SELECT @PolicyId     = p.TenantAuthenticationPolicyId
             , @CurFederated = p.AllowFederated
             , @CurLocal     = p.AllowLocalPassword
             , @CurMfa       = p.RequireMfaForLocal
             , @CurPreferred = p.PreferredMethod
             , @CurLifetime  = p.SessionLifetimeMinutes
             , @CurIdle      = p.IdleTimeoutMinutes
             , @CurStepUp    = p.RequireStepUpForPrivileged
          FROM auth.TenantAuthenticationPolicy AS p
         WHERE p.TenantId  = @TenantId
           AND p.IsDeleted = 0;

        -- Where there is no row, "current" is the set of values an INSERT would land on, so that the diff below reads
        -- from the template's default to the caller's choice rather than from NULL to it.
        IF @PolicyId IS NULL
        BEGIN
            SET @CurFederated = 0;
            SET @CurLocal     = 1;
            SET @CurMfa       = 1;
            SET @CurPreferred = 'LocalPassword';
            SET @CurLifetime  = 480;
            SET @CurIdle      = 60;
            SET @CurStepUp    = @StepUpDefault;
        END;

        SET @NewFederated = COALESCE (@AllowFederated,             @CurFederated);
        SET @NewLocal     = COALESCE (@AllowLocalPassword,         @CurLocal);
        SET @NewMfa       = COALESCE (@RequireMfaForLocal,         @CurMfa);
        SET @NewPreferred = COALESCE (@PreferredMethod,            @CurPreferred);
        SET @NewLifetime  = COALESCE (@SessionLifetimeMinutes,     @CurLifetime);
        SET @NewIdle      = COALESCE (@IdleTimeoutMinutes,         @CurIdle);
        SET @NewStepUp    = COALESCE (@RequireStepUpForPrivileged, @CurStepUp);

        -- The four ways the combination is unusable, each raised as E-50097 with its own message. See the notes for why
        -- one number and four messages, and for why these repeat what three CHECK constraints already enforce.
        IF @NewPreferred NOT IN ('Federated', 'LocalPassword')
        BEGIN
            SET @Failure = CONCAT (N'@PreferredMethod must be ''Federated'' or ''LocalPassword'' and was '''
                                 , @NewPreferred, N'''. The value names which button the sign-in page offers FIRST, so '
                                 , N'there are exactly two of them and the set is closed by '
                                 , N'CK_auth_TenantAuthenticationPolicy_PreferredMethod. Nothing was changed.');
            ;THROW 50097, @Failure, 1;
        END;

        IF @NewFederated = 0 AND @NewLocal = 0
        BEGIN
            SET @Failure = N'That policy allows neither federated sign-in nor a local password, which describes a '
                         + N'tenant nobody can enter. One of AllowFederated and AllowLocalPassword must be 1. Use '
                         + N'auth.uspDeactivateTenant to close a tenant -- it is reversible, it says so in '
                         + N'auth.vwTenantHierarchy, and it does not leave a policy row that looks like a mistake. '
                         + N'Nothing was changed.';
            ;THROW 50097, @Failure, 1;
        END;

        IF (@NewPreferred = 'Federated' AND @NewFederated = 0)
           OR (@NewPreferred = 'LocalPassword' AND @NewLocal = 0)
        BEGIN
            SET @Failure = CONCAT (N'That policy prefers ', @NewPreferred, N' and forbids it: AllowFederated would be '
                                 , @NewFederated, N' and AllowLocalPassword would be ', @NewLocal
                                 , N'. The preferred method is the one the sign-in page offers first, so a policy that '
                                 , N'prefers a forbidden method is a button that raises E-50104 when pressed -- '
                                 , N'CK_auth_TenantAuthenticationPolicy_PreferredIsAllowed. Remember that NULL means '
                                 , N'leave alone: changing the preference on a tenant that forbids the new one takes '
                                 , N'both parameters in the same call. Nothing was changed.');
            ;THROW 50097, @Failure, 1;
        END;

        IF @NewLifetime NOT BETWEEN 1 AND 43200 OR @NewIdle NOT BETWEEN 1 AND 43200 OR @NewIdle > @NewLifetime
        BEGIN
            SET @Failure = CONCAT (N'The lifetimes are unusable: SessionLifetimeMinutes would be ', @NewLifetime
                                 , N' and IdleTimeoutMinutes ', @NewIdle, N'. Both must be between 1 and 43200 '
                                 , N'(thirty days) and the idle timeout may not exceed the absolute lifetime -- an idle '
                                 , N'window longer than the session it sits inside is a setting that can never take '
                                 , N'effect, because auth.uspTouchSession ends the session on the absolute expiry '
                                 , N'first. CK_auth_TenantAuthenticationPolicy_Lifetimes. Nothing was changed.');
            ;THROW 50097, @Failure, 1;
        END;

        -- The issuer list, validated before the transaction for the same reason as everything above it. NULL is "I did
        -- not say"; [] is "trust nobody", and the two are not the same intention.
        IF @TrustedIssuersJson IS NOT NULL
        BEGIN
            IF ISJSON (@TrustedIssuersJson, ARRAY) = 0
            BEGIN
                SET @Failure = N'@TrustedIssuersJson must be a JSON ARRAY of issuer strings, for example '
                             + N'["https://login.microsoftonline.com/<tenant>/v2.0"]. An empty array [] is legal and '
                             + N'means this tenant trusts no issuer of its own, which is how a subtree''s federation is '
                             + N'revoked without switching AllowFederated off. NULL is not the same thing: it means '
                             + N'leave the list alone, and it is the default. Nothing was changed.';
                ;THROW 50046, @Failure, 1;
            END;

            -- G-32, third raising site. ISJSON said it is an array; this says every ELEMENT of it is an issuer. j.[type]
            -- 1 is a string; j.[key] on an array is the 0-based ordinal, and both forms are in the message because the
            -- index is what the caller edits and the position is what they count.
            SELECT TOP (1) @BadOrdinal = TRY_CAST (j.[key] AS INT)
                         , @BadType    = j.[type]
                         , @BadRaw     = LEFT (COALESCE (j.[value], N'null'), 200)
              FROM OPENJSON (@TrustedIssuersJson) AS j
             WHERE j.[type] <> 1
                OR LEN (LTRIM (RTRIM (COALESCE (j.[value], N'')))) = 0
                OR j.[value] <> LTRIM (RTRIM (j.[value]))
                OR LEN (j.[value]) > 512
             ORDER BY TRY_CAST (j.[key] AS INT);

            IF @BadOrdinal IS NOT NULL
            BEGIN
                SET @Failure = CONCAT (N'Element at index ', @BadOrdinal, N' of @TrustedIssuersJson (the '
                                     , @BadOrdinal + 1, CASE WHEN @BadOrdinal + 1 = 1 THEN N'st' WHEN @BadOrdinal + 1 = 2
                                            THEN N'nd' WHEN @BadOrdinal + 1 = 3 THEN N'rd' ELSE N'th' END
                                     , N' element) is not an issuer: '
                                     , CASE WHEN @BadType = 0 THEN N'it is null'
                                            WHEN @BadType = 2 THEN N'it is a number'
                                            WHEN @BadType = 3 THEN N'it is a boolean'
                                            WHEN @BadType = 4 THEN N'it is a nested array'
                                            WHEN @BadType = 5 THEN N'it is an object'
                                            WHEN LEN (LTRIM (RTRIM (COALESCE (@BadRaw, N'')))) = 0 THEN N'it is blank'
                                            WHEN LEN (@BadRaw) > 512 THEN N'it is longer than 512 characters'
                                            ELSE N'it has leading or trailing whitespace' END
                                     , N' -- ', @BadRaw, N'. An issuer is compared to the token''s issuer as a STRING '
                                     , N'by auth.uspBeginSsoLogin, so a stored value carrying a space can never match '
                                     , N'one and would silently refuse every federated sign-in it was added to permit '
                                     , N'-- which is why CK_auth_TenantTrustedIssuer_Issuer refuses it too, and why it '
                                     , N'is refused here rather than trimmed for you. The whole call is refused rather '
                                     , N'than partly applied. Only the FIRST bad element is named. Nothing was '
                                     , N'changed.');
                ;THROW 50180, @Failure, 1;
            END;

            INSERT @Incoming (Issuer)
            SELECT DISTINCT j.[value]
              FROM OPENJSON (@TrustedIssuersJson) AS j;
        END;

        BEGIN TRANSACTION;

        IF @PolicyId IS NULL
        BEGIN
            INSERT auth.TenantAuthenticationPolicy
                 (TenantId, AllowFederated, AllowLocalPassword, RequireMfaForLocal, PreferredMethod
                , SessionLifetimeMinutes, IdleTimeoutMinutes, RequireStepUpForPrivileged, PolicyNote
                , auditCreatedBy, auditModifiedBy)
            VALUES (@TenantId, @NewFederated, @NewLocal, @NewMfa, @NewPreferred
                  , @NewLifetime, @NewIdle, @NewStepUp, @PolicyNote
                  , @Actor, @Actor);

            SET @PolicyId = SCOPE_IDENTITY ();
            SET @Created  = 1;
        END
        ELSE
        BEGIN
            -- PolicyNote follows the same NULL-means-leave-alone rule as everything else, which means the note cannot be
            -- CLEARED through this procedure. Deliberate: an empty string is the way to say "there is no longer a
            -- reason", and a parameter whose NULL both leaves a value alone and erases it cannot do either reliably.
            UPDATE p
               SET p.AllowFederated             = @NewFederated
                 , p.AllowLocalPassword         = @NewLocal
                 , p.RequireMfaForLocal         = @NewMfa
                 , p.PreferredMethod            = @NewPreferred
                 , p.SessionLifetimeMinutes     = @NewLifetime
                 , p.IdleTimeoutMinutes         = @NewIdle
                 , p.RequireStepUpForPrivileged = @NewStepUp
                 , p.PolicyNote                 = COALESCE (@PolicyNote, p.PolicyNote)
                 , p.auditModifiedBy            = @Actor
                 , p.auditModifiedDateUtc       = @Now
              FROM auth.TenantAuthenticationPolicy AS p
             WHERE p.TenantAuthenticationPolicyId = @PolicyId;
        END;

        SET @FieldsChanged = CASE WHEN @NewFederated <> @CurFederated THEN 1 ELSE 0 END
                           + CASE WHEN @NewLocal     <> @CurLocal     THEN 1 ELSE 0 END
                           + CASE WHEN @NewMfa       <> @CurMfa       THEN 1 ELSE 0 END
                           + CASE WHEN @NewPreferred <> @CurPreferred THEN 1 ELSE 0 END
                           + CASE WHEN @NewLifetime  <> @CurLifetime  THEN 1 ELSE 0 END
                           + CASE WHEN @NewIdle      <> @CurIdle      THEN 1 ELSE 0 END
                           + CASE WHEN @NewStepUp    <> @CurStepUp    THEN 1 ELSE 0 END;

        -- The issuer list, replace-the-whole-set. Removals first, so that an issuer leaving and an issuer arriving
        -- cannot collide on UX_auth_TenantTrustedIssuer_TenantIssuer inside one transaction.
        IF @TrustedIssuersJson IS NOT NULL
        BEGIN
            UPDATE i
               SET i.IsDeleted            = 1
                 , i.auditDeletedBy       = @Actor
                 , i.auditDeletedDateUtc  = @Now
                 , i.auditModifiedBy      = @Actor
                 , i.auditModifiedDateUtc = @Now
              OUTPUT deleted.Issuer INTO @RemovedIssuers (Issuer)
              FROM auth.TenantTrustedIssuer AS i
             WHERE i.TenantId  = @TenantId
               AND i.IsDeleted = 0
               AND NOT EXISTS (SELECT 1 FROM @Incoming AS n WHERE n.Issuer = i.Issuer);

            SET @IssuersRemoved = @@ROWCOUNT;

            -- Resurrection in place, and both deleted columns are cleared in the SAME statement as IsDeleted because
            -- CK_auth_TenantTrustedIssuer_DeletedPair is evaluated before trg_au_updt_TenantTrustedIssuer ever runs.
            UPDATE i
               SET i.IsDeleted            = 0
                 , i.auditDeletedBy       = NULL
                 , i.auditDeletedDateUtc  = NULL
                 , i.auditModifiedBy      = @Actor
                 , i.auditModifiedDateUtc = @Now
              OUTPUT inserted.Issuer INTO @AddedIssuers (Issuer)
              FROM auth.TenantTrustedIssuer AS i
             INNER JOIN @Incoming AS n ON n.Issuer = i.Issuer
             WHERE i.TenantId  = @TenantId
               AND i.IsDeleted = 1;

            SET @IssuersAdded = @@ROWCOUNT;

            INSERT auth.TenantTrustedIssuer (TenantId, Issuer, IssuerNote, auditCreatedBy, auditModifiedBy)
            OUTPUT inserted.Issuer INTO @AddedIssuers (Issuer)
            SELECT @TenantId, n.Issuer, NULL, @Actor, @Actor
              FROM @Incoming AS n
             WHERE NOT EXISTS (SELECT 1
                                 FROM auth.TenantTrustedIssuer AS i
                                WHERE i.TenantId = @TenantId
                                  AND i.Issuer   = n.Issuer);

            SET @IssuersAdded = @IssuersAdded + @@ROWCOUNT;
        END;

        SELECT @IssuerCount = COUNT (*)
          FROM auth.TenantTrustedIssuer AS i
         WHERE i.TenantId  = @TenantId
           AND i.IsDeleted = 0;

        -- The trail. One row for the policy, and one per issuer moved -- the same grain as
        -- auth.uspSetRolePermissions, because "when did this tenant start trusting that provider" is a question about
        -- one issuer and a summary row would answer it for none of them.
        --
        -- 'TenantPolicyChanged', 'TenantTrustedIssuerAdded' and 'TenantTrustedIssuerRemoved' were added to
        -- CK_logs_AuthorizationChange_ChangeType by this gap, and so was the clause in
        -- CK_logs_AuthorizationChange_Attributable that lets a row name a TENANT and no person, profile or role. See
        -- 085_logs_auth_tables.sql -- the vocabulary already published 'TenantReparented', which nothing could have
        -- written for the same reason.
        IF @Created = 1 OR @FieldsChanged > 0
        BEGIN
            SET @DetailJson = CONCAT (N'{"tenantId":', @TenantId, N',"tenantCode":"', @TenantCode
                                    , N'","policyRowCreated":', CASE WHEN @Created = 1 THEN N'true' ELSE N'false' END
                                    , CASE WHEN @NewFederated <> @CurFederated
                                           THEN CONCAT (N',"allowFederated":{"from":', @CurFederated, N',"to":', @NewFederated, N'}')
                                           ELSE N'' END
                                    , CASE WHEN @NewLocal <> @CurLocal
                                           THEN CONCAT (N',"allowLocalPassword":{"from":', @CurLocal, N',"to":', @NewLocal, N'}')
                                           ELSE N'' END
                                    , CASE WHEN @NewMfa <> @CurMfa
                                           THEN CONCAT (N',"requireMfaForLocal":{"from":', @CurMfa, N',"to":', @NewMfa, N'}')
                                           ELSE N'' END
                                    , CASE WHEN @NewPreferred <> @CurPreferred
                                           THEN CONCAT (N',"preferredMethod":{"from":"', @CurPreferred, N'","to":"', @NewPreferred, N'"}')
                                           ELSE N'' END
                                    , CASE WHEN @NewLifetime <> @CurLifetime
                                           THEN CONCAT (N',"sessionLifetimeMinutes":{"from":', @CurLifetime, N',"to":', @NewLifetime, N'}')
                                           ELSE N'' END
                                    , CASE WHEN @NewIdle <> @CurIdle
                                           THEN CONCAT (N',"idleTimeoutMinutes":{"from":', @CurIdle, N',"to":', @NewIdle, N'}')
                                           ELSE N'' END
                                    , CASE WHEN @NewStepUp <> @CurStepUp
                                           THEN CONCAT (N',"requireStepUpForPrivileged":{"from":', @CurStepUp, N',"to":', @NewStepUp, N'}')
                                           ELSE N'' END
                                    , N',"fieldsChanged":', @FieldsChanged
                                    , N',"policyNoteChars":', COALESCE (CAST (LEN (@PolicyNote) AS NVARCHAR (11)), N'null')
                                    , N',"trustedIssuersLive":', @IssuerCount, N'}');

            EXEC logs.uspRecordAuthorizationChange
                  @ChangeType             = 'TenantPolicyChanged'
                , @TargetUserId           = NULL
                , @TargetUserProfileId    = NULL
                , @RoleId                 = NULL
                , @ScopeTenantId          = @TenantId
                , @ActorUserProfileId     = @ActorProfileId
                , @ActorAuthorityTenantId = @ActingTenantId
                , @DetailJson             = @DetailJson
                , @AuthorizationChangeId  = @ChangeId OUTPUT;
        END;

        SET @RowNo    = 1;
        SET @MaxRowNo = (SELECT COALESCE (MAX (RowNo), 0) FROM @AddedIssuers);

        WHILE @RowNo <= @MaxRowNo
        BEGIN
            SELECT @Issuer = a.Issuer FROM @AddedIssuers AS a WHERE a.RowNo = @RowNo;

            SET @DetailJson = CONCAT (N'{"tenantId":', @TenantId, N',"tenantCode":"', @TenantCode
                                    , N'","issuer":"', REPLACE (@Issuer, N'"', N'\"'), N'"}');

            EXEC logs.uspRecordAuthorizationChange
                  @ChangeType             = 'TenantTrustedIssuerAdded'
                , @TargetUserId           = NULL
                , @TargetUserProfileId    = NULL
                , @RoleId                 = NULL
                , @ScopeTenantId          = @TenantId
                , @ActorUserProfileId     = @ActorProfileId
                , @ActorAuthorityTenantId = @ActingTenantId
                , @DetailJson             = @DetailJson
                , @AuthorizationChangeId  = @ChangeId OUTPUT;

            SET @RowNo = @RowNo + 1;
        END;

        SET @RowNo    = 1;
        SET @MaxRowNo = (SELECT COALESCE (MAX (RowNo), 0) FROM @RemovedIssuers);

        WHILE @RowNo <= @MaxRowNo
        BEGIN
            SELECT @Issuer = r.Issuer FROM @RemovedIssuers AS r WHERE r.RowNo = @RowNo;

            SET @DetailJson = CONCAT (N'{"tenantId":', @TenantId, N',"tenantCode":"', @TenantCode
                                    , N'","issuer":"', REPLACE (@Issuer, N'"', N'\"'), N'"}');

            EXEC logs.uspRecordAuthorizationChange
                  @ChangeType             = 'TenantTrustedIssuerRemoved'
                , @TargetUserId           = NULL
                , @TargetUserProfileId    = NULL
                , @RoleId                 = NULL
                , @ScopeTenantId          = @TenantId
                , @ActorUserProfileId     = @ActorProfileId
                , @ActorAuthorityTenantId = @ActingTenantId
                , @DetailJson             = @DetailJson
                , @AuthorizationChangeId  = @ChangeId OUTPUT;

            SET @RowNo = @RowNo + 1;
        END;

        SET @Comments = CONCAT (N'TenantId=', @TenantId, N' ', @TenantCode, N': '
                              , CASE WHEN @Created = 1
                                     THEN N'policy row CREATED (this tenant had none and was inheriting), '
                                     ELSE N'' END
                              , @FieldsChanged
                              , N' policy field(s) changed. AllowFederated=', @NewFederated
                              , N', AllowLocalPassword=', @NewLocal, N', RequireMfaForLocal=', @NewMfa
                              , N', PreferredMethod=', @NewPreferred, N', SessionLifetimeMinutes=', @NewLifetime
                              , N', IdleTimeoutMinutes=', @NewIdle, N', RequireStepUpForPrivileged=', @NewStepUp
                              , N'. Trusted issuers: ', CASE WHEN @TrustedIssuersJson IS NULL
                                                             THEN N'not supplied, list left alone'
                                                             ELSE CONCAT (@IssuersAdded, N' added, ', @IssuersRemoved
                                                                        , N' removed') END
                              , N'; ', @IssuerCount, N' live at this tenant'
                              , CASE WHEN @NewFederated = 1 AND @IssuerCount = 0
                                     THEN N'. WATCH: federation is allowed here and this tenant trusts no issuer of '
                                        + N'its own, so every federated sign-in resolved to it depends on an ancestor '
                                        + N'carrying the list (E-50124 otherwise)'
                                     ELSE N'' END
                              , CASE WHEN @IsActive = 0
                                     THEN N'. The tenant is INACTIVE, so the policy takes effect when it is '
                                        + N'reactivated' ELSE N'' END, N'.');

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


-- *** 7. auth.uspSetTenantDefaultRoles ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspSetTenantDefaultRoles
Author:       rsincero
CreateDate:   2026-09-21
========================================================================================================================
Description:

Replaces one tenant's ENTIRE auth.TenantDefaultRole set with the JSON array of role codes supplied -- what every profile
created at or beneath that tenant receives on creation (section 8.5, section 11.5).  Demands Tenant.Update AND
Authz.RoleAssign, both at the tenant.  Refuses a code that names no role reachable from this tenant, and one that names a
role nobody may be granted (E-50098).  Gap G-43.

========================================================================================================================
Requirements and Key Dependencies:

auth.Tenant, auth.TenantClosure, auth.Role, auth.TenantDefaultRole, auth.uspSetSessionContext,
auth.uspDemandPermission, logs.uspRecordAuthorizationChange.  Granted to applicationRole.

========================================================================================================================
Notes:

TWO PERMISSIONS, NOT ONE, AND THE SECOND IS THE POINT.  A row in auth.TenantDefaultRole is a STANDING GRANT: it hands
its role to every profile created beneath this tenant from now on, without anybody approving them one at a time.  So this
call demands Authz.RoleAssign as well as Tenant.Update, and demands both AT THE TENANT -- an administrator who may not
grant EDITOR by hand here must not be able to arrange for everybody admitted tomorrow to receive it.  Tenant.Update
alone would have made "edit this tenant's settings" into a way round section 8.6's scoped grant rules.

WHAT 140_auth_profile_procedures.sql SILENTLY SKIPS, THIS REFUSES.  auth.uspGrantTenantDefaultRoles filters the default
set by four conditions -- the role must be live, IsAssignable = 1, in the tenant's application, and owned at or above the
tenant (INV-04) -- and a row failing any of them is skipped, counted and NOT raised, because one bad seed row must not
block every new profile beneath it.  That is the right behaviour for the reader of the set and the wrong behaviour for
its writer: a default role that will never be granted is a promise on a screen that nothing keeps.  So the same four
conditions are enforced HERE, as refusals, which is what makes 140's silence safe rather than lossy.  The two halves are
written to match on purpose; if one is edited, the other is the place to look.

CODES, RESOLVED NEAREST-ANCESTOR-FIRST, BECAUSE A ROLE CODE IS NOT UNIQUE.  UX_auth_Role_Code is unique on
(ApplicationId, OwnerTenantId, RoleCode), so two tenants in one application may each define EDITOR and mean different
things by it.  Taking @RoleCodesJson and resolving each code against the nearest owner at or above this tenant is
therefore a decision and not a lookup: it is the same nearest-ancestor-wins rule section 7.2 uses for policy and section
11.5 uses for these very rows, it cannot be ambiguous (the closure gives exactly one ancestor per depth, and the unique
index gives at most one role per ancestor per code), and it is the reading an administrator typing EDITOR intends.  The
owner actually resolved goes into @Comments and into the trail's DetailJson, because "EDITOR" alone does not identify a
role and a reviewer six months later needs to know which one was meant.

@RoleIdsJson WAS THE ALTERNATIVE AND WAS REJECTED.  Identifiers would remove the ambiguity above by pushing it onto the
caller, who would have to resolve codes to ids first -- through auth.uspListAssignableRoles, which is scoped to a
profile's own authority and so cannot be relied on to surface a role the administrator is allowed to make a default.
Codes also make the call readable in a ticket, which is where these decisions are actually recorded.

AN EMPTY ARRAY MEANS "STOP OVERRIDING", NOT "GRANT NOTHING", AND THAT IS A TRAP WORTH NAMING.  Section 11.5 resolves the
default set by walking UP from the tenant to the first ancestor that has ANY live row, so a tenant with no rows does not
grant nothing -- it INHERITS.  [] therefore retires this tenant's own rows and hands the decision back to its nearest
ancestor, which is a legitimate and useful intent ("undo my override").  What cannot be expressed at all is "new profiles
HERE receive nothing, whatever my parent says": that needs a sentinel the table does not have, and inventing one silently
-- a row pointing at a null role, say -- would be a value 140 would have to know about.  Filed as G-44 rather than
guessed at.  @Comments states which of the two an empty call produced, and names the ancestor that will now be consulted.

NULL IS REFUSED AND [] IS NOT.  The same distinction as auth.uspSetRolePermissions: "I did not say" and "I said none"
are different intentions and only one of them should empty a set.  E-50046 for a payload that is not a JSON array,
E-50180 for an array holding something that is not a code (G-32's second raising site in a shipped procedure -- the one
that gap named, auth.uspAssignRolesToProfiles, was never written; 055_auth_role.sql's header names it as an intention).

REMOVED ROWS ARE SOFT-DELETED AND RE-ADDED ROWS ARE RESURRECTED IN PLACE, because UX_auth_TenantDefaultRole_TenantRole is
filtered on IsDeleted = 0 and CK_auth_TenantDefaultRole_DeletedPair is evaluated before the AFTER trigger runs -- so the
resurrection clears auditDeletedBy and auditDeletedDateUtc in the same statement that clears IsDeleted.

WHAT THIS DOES NOT DO: IT CHANGES NOBODY'S EXISTING GRANTS.  Adding a default role grants it to profiles created AFTER
this call and to nobody already admitted; removing one takes it away from nobody.  That is section 8.5's design and not
an omission -- retroactively granting a role to every existing profile beneath a tenant is a bulk authorization change
that belongs to a procedure somebody calls deliberately, and retroactively revoking one would undo grants that
administrators may since have made by hand for reasons of their own.  @Comments reports the count of live profiles
beneath the tenant that are therefore unaffected, so the number is in front of whoever made the change.

========================================================================================================================
Example Usage and Performance:

exec auth.uspSetTenantDefaultRoles @SessionTokenHash = 0x9F86..., @TenantId = 7
                                 , @RoleCodesJson = N'["CASE_EDITOR","REPORT_READER"]'
                                 , @GrantNote = N'Agreed with the agency, ticket 4471.';

-- Stop overriding: this tenant inherits its parent's set again.
exec auth.uspSetTenantDefaultRoles @SessionTokenHash = 0x9F86..., @TenantId = 7, @RoleCodesJson = N'[]';

One parse, one closure seek per distinct code, two anti-joins and one trail row per role moved.

========================================================================================================================
Modification History:

Date:		2026-09-21
Author:		rsincero
Ticket:		G-43
Description:
Created.  The first shipped writer of auth.TenantDefaultRole.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspSetTenantDefaultRoles
      @SessionTokenHash VARBINARY (32)
    , @TenantId         INT
    , @RoleCodesJson    NVARCHAR (MAX)
    , @GrantNote        NVARCHAR (1000) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspSetTenantDefaultRoles]')
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

    DECLARE @Actor             NVARCHAR (255)  = NULL
          , @ActorProfileId    INT             = NULL
          , @ActingTenantId    INT             = NULL
          , @ApplicationId     INT             = NULL
          , @TenantCode        NVARCHAR (50)   = NULL
          , @Now              DATETIME2 (3)    = SYSUTCDATETIME ()
          , @RequestedCount    INT             = 0
          , @AddedCount        INT             = 0
          , @RemovedCount      INT             = 0
          , @LiveCount         INT             = 0
          , @ProfilesUntouched INT             = 0
          , @InheritFromId     INT             = NULL
          , @InheritFromCode   NVARCHAR (50)   = NULL
          , @BadCode           NVARCHAR (100)  = NULL
            -- 1000 and not 400: the unresolved-code explanation below runs past 400 characters, and a silently
            -- truncated refusal loses its LAST sentence -- which in that message is the one saying codes are
            -- case-sensitive, the single likeliest cause of the refusal.  Measured, not guessed: the first smoke run
            -- printed "... Codes Only the FIRST offending code is named."
          , @BadReason         NVARCHAR (1000) = NULL
          , @BadOrdinal        INT             = NULL
          , @BadType           INT             = NULL
          , @BadRaw            NVARCHAR (200)  = NULL
          , @RoleId            INT             = NULL
          , @RoleCode          NVARCHAR (100)  = NULL
          , @OwnerTenantId     INT             = NULL
          , @RowNo             INT             = 1
          , @MaxRowNo          INT             = 0
          , @ChangeId          BIGINT          = NULL
          , @DetailJson        NVARCHAR (2000) = NULL
          , @Failure           NVARCHAR (2000) = NULL;

    -- RoleId and the rest are filled by the OUTER APPLY below, so they are nullable here: an unresolved code is the
    -- refusal this table exists to find.
    DECLARE @Codes TABLE
    (
        RoleCode      NVARCHAR (100) NOT NULL PRIMARY KEY,
        RoleId        INT                NULL,
        OwnerTenantId INT                NULL,
        OwnerCode     NVARCHAR (50)      NULL,
        Depth         INT                NULL,
        IsAssignable  BIT                NULL
    );

    DECLARE @Added   TABLE (RowNo INT IDENTITY (1, 1) PRIMARY KEY, RoleId INT NOT NULL);
    DECLARE @Removed TABLE (RowNo INT IDENTITY (1, 1) PRIMARY KEY, RoleId INT NOT NULL);

    -- Codes are identifiers rather than secrets, but an unbounded payload does not belong in a log, so the count goes in
    -- and the list does not. The session token is a CREDENTIAL and never appears here at all -- UI-16.
    SET @KeyParameters = CONCAT (N'TenantId=', @TenantId, N', RoleCodesJson length='
                               , COALESCE (CAST (LEN (@RoleCodesJson) AS NVARCHAR (11)), N'NULL')
                               , N', GrantNote chars='
                               , COALESCE (CAST (LEN (@GrantNote) AS NVARCHAR (11)), N'(null)'));

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

        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        -- Both demands are at the tenant, and the second is what stops this becoming a way round section 8.6. See the
        -- notes; and see auth.uspSetTenantAuthenticationPolicy for why Tenant.Update rather than the Tenant.Manage the
        -- gap register's text names, which is not a code this design has.
        EXEC auth.uspDemandPermission @PermissionCode = N'Tenant.Update',    @TenantId = @TenantId;
        EXEC auth.uspDemandPermission @PermissionCode = N'Authz.RoleAssign', @TenantId = @TenantId;

        SET @Actor          = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N''), ORIGINAL_LOGIN ());
        SET @ActorProfileId = TRY_CAST (SESSION_CONTEXT (N'UserProfileId')  AS INT);
        SET @ActingTenantId = TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT);

        SELECT @ApplicationId = t.ApplicationId
             , @TenantCode    = t.TenantCode
          FROM auth.Tenant AS t
         WHERE t.TenantId  = @TenantId
           AND t.IsDeleted = 0;

        IF @ApplicationId IS NULL
        BEGIN
            SET @Failure = N'That tenant does not exist or has been deleted. Nothing was changed.';
            ;THROW 50093, @Failure, 1;
        END;

        IF @RoleCodesJson IS NULL OR ISJSON (@RoleCodesJson, ARRAY) = 0
        BEGIN
            SET @Failure = N'@RoleCodesJson must be a JSON ARRAY of role codes, for example ["CASE_EDITOR"]. An empty '
                         + N'array [] is legal and means this tenant keeps no default set of its own -- new profiles '
                         + N'beneath it then INHERIT the nearest ancestor''s set, which is not the same as receiving '
                         + N'nothing (section 11.5). NULL is not accepted, because "I did not say" and "I said none" '
                         + N'are different intentions and only one of them should empty a set. Nothing was changed.';
            ;THROW 50046, @Failure, 1;
        END;

        -- G-32. Every ELEMENT must be a code. Raised before anything is written, so the whole call is refused rather
        -- than partly applied, and a null element is refused rather than skipped -- skipping it would set the tenant to
        -- a smaller set than the caller listed and report success.
        SELECT TOP (1) @BadOrdinal = TRY_CAST (j.[key] AS INT)
                     , @BadType    = j.[type]
                     , @BadRaw     = LEFT (COALESCE (j.[value], N'null'), 200)
          FROM OPENJSON (@RoleCodesJson) AS j
         WHERE j.[type] <> 1
            OR LEN (LTRIM (RTRIM (COALESCE (j.[value], N'')))) = 0
            OR LEN (LTRIM (RTRIM (j.[value]))) > 100
         ORDER BY TRY_CAST (j.[key] AS INT);

        IF @BadOrdinal IS NOT NULL
        BEGIN
            SET @Failure = CONCAT (N'Element at index ', @BadOrdinal, N' of @RoleCodesJson (the ', @BadOrdinal + 1
                                 , CASE WHEN @BadOrdinal + 1 = 1 THEN N'st' WHEN @BadOrdinal + 1 = 2 THEN N'nd'
                                        WHEN @BadOrdinal + 1 = 3 THEN N'rd' ELSE N'th' END
                                 , N' element) is not a role code: '
                                 , CASE WHEN @BadType = 0 THEN N'it is null'
                                        WHEN @BadType = 2 THEN N'it is a number'
                                        WHEN @BadType = 3 THEN N'it is a boolean'
                                        WHEN @BadType = 4 THEN N'it is a nested array'
                                        WHEN @BadType = 5 THEN N'it is an object'
                                        WHEN LEN (LTRIM (RTRIM (COALESCE (@BadRaw, N'')))) = 0 THEN N'it is blank or whitespace'
                                        ELSE N'it is longer than 100 characters' END
                                 , N' -- ', @BadRaw, N'. Every element must be a non-empty role code, for example '
                                 , N'["CASE_EDITOR","REPORT_READER"]. The whole call is refused rather than partly '
                                 , N'applied. Only the FIRST malformed element is named. Nothing was changed.');
            ;THROW 50180, @Failure, 1;
        END;

        -- DISTINCT, because a caller listing a code twice means the set once and the primary key would otherwise turn a
        -- harmless duplicate into Msg 2627. Trimmed, because a trailing space in a hand-edited list is not an intention.
        INSERT @Codes (RoleCode)
        SELECT DISTINCT LTRIM (RTRIM (j.[value]))
          FROM OPENJSON (@RoleCodesJson) AS j;

        -- Nearest-ancestor-first resolution -- see the notes. OUTER APPLY and not CROSS APPLY: a code that resolves to
        -- nothing must stay in the table as a NULL RoleId, because it is the refusal below. ORDER BY Depth ASC makes
        -- depth 0 -- the tenant's own roles -- win over an ancestor's.
        --
        -- BIN2 on both sides makes the comparison case-sensitive: a role code is an identifier and CASE_EDITOR is not
        -- Case_Editor. The alternative -- matching case-insensitively -- would resolve a typo to a real role and make a
        -- standing grant out of it.
        UPDATE c
           SET c.RoleId        = x.RoleId
             , c.OwnerTenantId = x.OwnerTenantId
             , c.OwnerCode     = x.TenantCode
             , c.Depth         = x.Depth
             , c.IsAssignable  = x.IsAssignable
          FROM @Codes AS c
         OUTER APPLY (SELECT TOP (1) r.RoleId, r.OwnerTenantId, r.IsAssignable, tc.Depth, ot.TenantCode
                        FROM auth.TenantClosure AS tc
                       INNER JOIN auth.Role   AS r  ON r.OwnerTenantId = tc.AncestorTenantId
                       INNER JOIN auth.Tenant AS ot ON ot.TenantId     = r.OwnerTenantId
                       WHERE tc.DescendantTenantId = @TenantId
                         AND tc.IsDeleted          = 0
                         AND r.IsDeleted           = 0
                         AND r.ApplicationId       = @ApplicationId
                         AND r.RoleCode COLLATE Latin1_General_BIN2 = c.RoleCode COLLATE Latin1_General_BIN2
                       ORDER BY tc.Depth ASC) AS x;

        SELECT TOP (1) @BadCode   = c.RoleCode
                     , @BadReason = N'no live role of that code is defined at this tenant or at any tenant above it '
                                  + N'within this application. Role codes are unique only per owner tenant '
                                  + N'(UX_auth_Role_Code), so a code defined in another branch is deliberately NOT '
                                  + N'reachable from here -- INV-04 requires a default role to be owned at or above the '
                                  + N'tenant that seeds it, or the grant it produces would be one nobody was entitled '
                                  + N'to make. Codes are case-sensitive.'
          FROM @Codes AS c
         WHERE c.RoleId IS NULL
         ORDER BY c.RoleCode;

        IF @BadCode IS NULL
        BEGIN
            SELECT TOP (1) @BadCode   = c.RoleCode
                         , @BadReason = CONCAT (N'that role exists (RoleId ', c.RoleId, N', owned by ', c.OwnerCode
                                              , N') and is FROZEN: IsAssignable = 0, so nobody may be granted it. A '
                                              , N'frozen role cannot be a default either -- '
                                              , N'auth.uspGrantTenantDefaultRoles would skip it silently and every new '
                                              , N'profile would quietly not receive what this screen promised. Thaw it '
                                              , N'with auth.uspUpdateRole @IsAssignable = 1, or list a different role.')
              FROM @Codes AS c
             WHERE c.IsAssignable = 0
             ORDER BY c.RoleCode;
        END;

        IF @BadCode IS NOT NULL
        BEGIN
            SET @Failure = CONCAT (N'''', @BadCode, N''' cannot be a default role at this tenant: ', @BadReason
                                 , N' Only the FIRST offending code is named. Nothing was changed.');
            ;THROW 50098, @Failure, 1;
        END;

        SELECT @RequestedCount = COUNT (*) FROM @Codes;

        BEGIN TRANSACTION;

        -- Removals first, so a role leaving and a role arriving cannot collide on the filtered unique index inside one
        -- transaction.
        UPDATE d
           SET d.IsDeleted            = 1
             , d.auditDeletedBy       = @Actor
             , d.auditDeletedDateUtc  = @Now
             , d.auditModifiedBy      = @Actor
             , d.auditModifiedDateUtc = @Now
          OUTPUT deleted.RoleId INTO @Removed (RoleId)
          FROM auth.TenantDefaultRole AS d
         WHERE d.TenantId  = @TenantId
           AND d.IsDeleted = 0
           AND NOT EXISTS (SELECT 1 FROM @Codes AS c WHERE c.RoleId = d.RoleId);

        SET @RemovedCount = @@ROWCOUNT;

        UPDATE d
           SET d.IsDeleted            = 0
             , d.auditDeletedBy       = NULL
             , d.auditDeletedDateUtc  = NULL
             , d.GrantNote            = COALESCE (@GrantNote, d.GrantNote)
             , d.auditModifiedBy      = @Actor
             , d.auditModifiedDateUtc = @Now
          OUTPUT inserted.RoleId INTO @Added (RoleId)
          FROM auth.TenantDefaultRole AS d
         INNER JOIN @Codes AS c ON c.RoleId = d.RoleId
         WHERE d.TenantId  = @TenantId
           AND d.IsDeleted = 1;

        SET @AddedCount = @@ROWCOUNT;

        INSERT auth.TenantDefaultRole (TenantId, RoleId, GrantNote, auditCreatedBy, auditModifiedBy)
        OUTPUT inserted.RoleId INTO @Added (RoleId)
        SELECT @TenantId, c.RoleId, @GrantNote, @Actor, @Actor
          FROM @Codes AS c
         WHERE NOT EXISTS (SELECT 1
                             FROM auth.TenantDefaultRole AS d
                            WHERE d.TenantId = @TenantId
                              AND d.RoleId   = c.RoleId);

        SET @AddedCount = @AddedCount + @@ROWCOUNT;

        -- One trail row per role moved, the same grain as auth.uspSetRolePermissions: "when did new users here start
        -- getting EDITOR" is a question about one role.
        SET @RowNo    = 1;
        SET @MaxRowNo = (SELECT COALESCE (MAX (RowNo), 0) FROM @Added);

        WHILE @RowNo <= @MaxRowNo
        BEGIN
            SELECT @RoleId = a.RoleId FROM @Added AS a WHERE a.RowNo = @RowNo;

            SELECT @RoleCode      = c.RoleCode
                 , @OwnerTenantId = c.OwnerTenantId
              FROM @Codes AS c
             WHERE c.RoleId = @RoleId;

            SET @DetailJson = CONCAT (N'{"tenantId":', @TenantId, N',"tenantCode":"', @TenantCode
                                    , N'","roleCode":"', @RoleCode, N'","roleOwnerTenantId":', @OwnerTenantId
                                    , N',"appliesTo":"profiles created after this change"}');

            EXEC logs.uspRecordAuthorizationChange
                  @ChangeType             = 'TenantDefaultRoleAdded'
                , @TargetUserId           = NULL
                , @TargetUserProfileId    = NULL
                , @RoleId                 = @RoleId
                , @ScopeTenantId          = @TenantId
                , @ActorUserProfileId     = @ActorProfileId
                , @ActorAuthorityTenantId = @ActingTenantId
                , @DetailJson             = @DetailJson
                , @AuthorizationChangeId  = @ChangeId OUTPUT;

            SET @RowNo = @RowNo + 1;
        END;

        SET @RowNo    = 1;
        SET @MaxRowNo = (SELECT COALESCE (MAX (RowNo), 0) FROM @Removed);

        WHILE @RowNo <= @MaxRowNo
        BEGIN
            SELECT @RoleId = r.RoleId FROM @Removed AS r WHERE r.RowNo = @RowNo;

            -- Read from auth.Role and not from @Codes: a removed role is by definition NOT in the requested set.
            SELECT @RoleCode      = r.RoleCode
                 , @OwnerTenantId = r.OwnerTenantId
              FROM auth.Role AS r
             WHERE r.RoleId = @RoleId;

            SET @DetailJson = CONCAT (N'{"tenantId":', @TenantId, N',"tenantCode":"', @TenantCode
                                    , N'","roleCode":"', @RoleCode, N'","roleOwnerTenantId":', @OwnerTenantId
                                    , N',"existingGrantsKept":true}');

            EXEC logs.uspRecordAuthorizationChange
                  @ChangeType             = 'TenantDefaultRoleRemoved'
                , @TargetUserId           = NULL
                , @TargetUserProfileId    = NULL
                , @RoleId                 = @RoleId
                , @ScopeTenantId          = @TenantId
                , @ActorUserProfileId     = @ActorProfileId
                , @ActorAuthorityTenantId = @ActingTenantId
                , @DetailJson             = @DetailJson
                , @AuthorizationChangeId  = @ChangeId OUTPUT;

            SET @RowNo = @RowNo + 1;
        END;

        SELECT @LiveCount = COUNT (*)
          FROM auth.TenantDefaultRole AS d
         WHERE d.TenantId  = @TenantId
           AND d.IsDeleted = 0;

        -- Where the set is now empty, name the ancestor that will be consulted instead: "inherits" is only useful if the
        -- caller can see FROM WHERE. Depth > 0 because the tenant's own set is what was just emptied.
        IF @LiveCount = 0
        BEGIN
            SELECT TOP (1) @InheritFromId   = tc.AncestorTenantId
                         , @InheritFromCode = at.TenantCode
              FROM auth.TenantClosure AS tc
             INNER JOIN auth.Tenant   AS at ON at.TenantId = tc.AncestorTenantId
             WHERE tc.DescendantTenantId = @TenantId
               AND tc.Depth              > 0
               AND tc.IsDeleted          = 0
               AND EXISTS (SELECT 1
                             FROM auth.TenantDefaultRole AS d
                            WHERE d.TenantId  = tc.AncestorTenantId
                              AND d.IsDeleted = 0)
             ORDER BY tc.Depth ASC;
        END;

        -- The count this change does NOT touch, reported because the number is the thing a reviewer assumes wrongly.
        SELECT @ProfilesUntouched = COUNT (*)
          FROM auth.UserProfile AS up
         INNER JOIN auth.TenantClosure AS tc
            ON tc.DescendantTenantId = up.TenantId
           AND tc.IsDeleted          = 0
         WHERE tc.AncestorTenantId = @TenantId
           AND up.IsDeleted        = 0;

        SET @Comments = CONCAT (N'TenantId=', @TenantId, N' ', @TenantCode, N' now seeds ', @LiveCount
                              , N' default role(s): ', @AddedCount, N' added, ', @RemovedCount, N' removed, '
                              , @RequestedCount - @AddedCount, N' already present. '
                              , CASE WHEN @LiveCount = 0 AND @InheritFromId IS NOT NULL
                                     THEN CONCAT (N'The set is now EMPTY, so this tenant no longer overrides and new '
                                                , N'profiles beneath it will receive the set defined at TenantId '
                                                , @InheritFromId, N' ', @InheritFromCode
                                                , N' -- section 11.5, nearest ancestor wins. ')
                                     WHEN @LiveCount = 0
                                     THEN N'The set is now EMPTY and no tenant above this one seeds any either, so new '
                                        + N'profiles beneath it receive no role at all and will need one granted by '
                                        + N'hand. '
                                     ELSE N'' END
                              , @ProfilesUntouched, N' live profile(s) at or beneath this tenant are UNCHANGED by this '
                              , N'call: a default set applies to profiles created after it (section 8.5).');

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


-- *** 8. Descriptions ***
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

    -- Built as rows rather than as seven EXEC calls with concatenated arguments, because an EXEC argument takes a
    -- constant or a variable and never an expression -- a '+' in the parameter position is a parse error (102), exactly
    -- as it is for THROW.
    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    VALUES
      (N'auth', N'PROCEDURE', N'uspRebuildTenantClosure', NULL
     , N'Rebuilds auth.TenantClosure whole, in one transaction, from auth.Tenant''s parent edges. Section 5.3. '
     + N'Parameterless by design: the closure stores no ApplicationId, so there is nothing to restrict a MERGE target '
     + N'on, and a partial rebuild that got the restriction wrong would leave the table internally inconsistent. '
     + N'Retired pairs are SOFT-deleted, never removed, so a re-parenting leaves an audit trail of the old shape. The '
     + N'source CTE deliberately does NOT filter IsDeleted: the closure records shape, auth.udfIsTenantUsable decides '
     + N'usability, and a closure over live rows only would make a program under a deleted administration read as '
     + N'usable -- failing OPEN. BL-020.')
    , (N'auth', N'PROCEDURE', N'uspCreateTenant', NULL
     , N'Creates a tenant under an existing parent and rebuilds the closure. Section 5.3, permission Tenant.Create. '
     + N'Cannot create a root: INV-02 allows exactly one per application and 030_auth_tenant.sql''s seed or a variant '
     + N'fixture creates it (50094). Demands the permission BEFORE validating the parent, so an unauthorized caller '
     + N'gets 50030 whether or not the parent exists -- the cost is that an administrator''s typo also reads as 50030, '
     + N'which is the trade made deliberately in favour of not leaking which tenant ids exist. Raises 50090 unusable '
     + N'parent, 50091 unknown type, 50092 duplicate code, 50094 root.')
    , (N'auth', N'PROCEDURE', N'uspUpdateTenant', NULL
     , N'Renames or re-parents a tenant and rebuilds the closure. Section 5.3, permission Tenant.Update. Every '
     + N'parameter but @SessionTokenHash and @TenantId is optional; NULL means leave alone, which is unambiguous only '
     + N'because INV-02 makes "re-parent to no parent" illegal anyway. Demands Tenant.Update TWICE on a re-parenting -- '
     + N'at the tenant and at its proposed new parent -- because one demand would let an administrator graft their '
     + N'subtree under an agency they have no authority over. The cycle test is one seek against auth.TenantClosure, '
     + N'which catches the self-parent case free through the depth-0 row. Raises 50090, 50091, 50092, 50093, 50094, '
     + N'50095 cycle, 50096 cross-application. RE-PARENTING IS THE CASE PHASE 1 EXISTS TO GET RIGHT.')
    , (N'auth', N'PROCEDURE', N'uspDeactivateTenant', NULL
     , N'Takes a tenant out of service, or puts it back with @IsActive = 1. Section 5.3, permission Tenant.Deactivate. '
     + N'Sets IsActive and NEVER IsDeleted: deactivation is reversible and stays visible in auth.vwTenantHierarchy, '
     + N'whereas a soft delete removes the subtree from the display and is a different permission. NOT cascaded to '
     + N'descendants, which is what makes it reversible -- ancestor-aware auth.udfIsTenantUsable gives the cascade for '
     + N'free and each tenant''s own flag keeps meaning only what somebody set deliberately. Refuses on the root '
     + N'(50094): its closure covers the application, so every sign-in would fail with 50021 and nothing would say why. '
     + N'Rebuilds the closure even though a flag change provably writes 0 rows, because a rule with one exception is a '
     + N'rule somebody extends to a procedure where it does not hold.')
    , (N'auth', N'PROCEDURE', N'uspGetTenantTree', NULL
     , N'The tenant tree for one application or one subtree, with a usability verdict per node. Section 5.3, permission '
     + N'Tenant.Read. ERROR-ONLY instrumented (rule 8): it only reads, so it opens no start row and writes to '
     + N'logs.ExecutionLog on failure only. The object that joins auth.vwTenantHierarchy to auth.udfIsTenantUsable -- '
     + N'the view cannot reference the function because 095 installs before 100 and CREATE VIEW resolves names '
     + N'immediately, whereas a PROCEDURE gets deferred resolution. Does NOT yet restrict rows to what the caller may '
     + N'see: it demands Tenant.Read at the scope and returns that scope. Row-level security (section 21, Phase 2) '
     + N'narrows it with no change here.')
    , (N'auth', N'PROCEDURE', N'uspSetTenantAuthenticationPolicy', NULL
     , N'Sets one tenant''s authentication policy row and, optionally, replaces its whole trusted-issuer list. Sections '
     + N'7.2 and 7.3, permission Tenant.Update. Gap G-43: until this existed auth.TenantAuthenticationPolicy and '
     + N'auth.TenantTrustedIssuer had no writer, so the policy that drives every sign-in was editable only by hand. '
     + N'Every policy parameter is optional and NULL means LEAVE ALONE -- with one deliberate exception, '
     + N'@RequireStepUpForPrivileged, which on a tenant that has no row yet takes the '
     + N'Authn.RequireStepUpForPrivilegedDefault setting rather than the column default, because G-30 made that setting '
     + N'the one place the answer is configured. A tenant with no row is INHERITING (section 7.2, nearest ancestor '
     + N'wins), so creating one is a real change and is reported as such. @TrustedIssuersJson NULL leaves the list '
     + N'alone; [] empties it, which means trust NOBODY. Validates the four CHECK constraints of '
     + N'auth.TenantAuthenticationPolicy itself, BEFORE the transaction, so the caller gets a sentence rather than a '
     + N'constraint name: 50097 for an impossible combination (unknown preferred method, neither method allowed, '
     + N'preferred method not allowed, lifetimes out of range or idle above absolute), 50046 for a payload that is not '
     + N'a JSON array, 50180 for a malformed element, 50093 for an unknown tenant. Writes TenantPolicyChanged, '
     + N'TenantTrustedIssuerAdded and TenantTrustedIssuerRemoved to logs.AuthorizationChange, with a DIFF-ONLY '
     + N'DetailJson. An INACTIVE tenant is editable on purpose: fixing the policy is often why it was deactivated.')
    , (N'auth', N'PROCEDURE', N'uspSetTenantDefaultRoles', NULL
     , N'Replaces one tenant''s ENTIRE auth.TenantDefaultRole set from a JSON array of role codes -- what every profile '
     + N'created at or beneath it receives on creation. Sections 8.5 and 11.5, gap G-43. Demands Tenant.Update AND '
     + N'Authz.RoleAssign, both at the tenant, because a default role is a STANDING GRANT: an administrator who may not '
     + N'grant a role by hand here must not be able to arrange for everybody admitted tomorrow to receive it. Resolves '
     + N'each code against the nearest owner at or above the tenant, case-sensitively (Latin1_General_BIN2), because '
     + N'UX_auth_Role_Code makes a code unique only per owner. Raises 50098 for a code that resolves to nothing or to a '
     + N'frozen role -- the same four conditions auth.uspGrantTenantDefaultRoles SKIPS silently, enforced here as '
     + N'refusals, which is what makes that silence safe rather than lossy. 50046 for a payload that is not a JSON '
     + N'array, 50180 for a malformed element, 50093 for an unknown tenant. AN EMPTY ARRAY MEANS "STOP OVERRIDING", NOT '
     + N'"GRANT NOTHING": section 11.5 walks up to the nearest ancestor with any live row, so [] hands the decision '
     + N'back to that ancestor and @Comments names it. "New profiles here receive nothing whatever my parent says" is '
     + N'inexpressible -- G-44. Changes NOBODY''s existing grants, in either direction, and reports the count of live '
     + N'profiles it therefore did not touch.');

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


-- *** 9. Grants ***
-- EXECUTE on the procedures, and nothing on the tables.  That is INV-11: applicationRole holds no table access to
-- SCHEMA::auth, so the application reaches tenancy only through these six entry points, each of which demands a
-- permission first.  Ownership chaining is what lets the procedure read auth.Tenant on the caller's behalf.
--
-- Each grant is guarded, which is what keeps this file re-runnable against a database where scripts/permissions.sql has
-- not run.  The same guard is how a typo'd role name produces a procedure nobody can execute and no error to say why:
-- check these names against the report at the end of scripts/permissions.sql.
--
-- uspRebuildTenantClosure IS DELIBERATELY NOT GRANTED.  It takes no session token and demands no permission -- it is
-- called by the six procedures above, by ownership chaining, and by a fixture running as db_owner.  Granting it to the
-- application would give any caller a whole-table MERGE with no authorization check in front of it.
IF DATABASE_PRINCIPAL_ID (N'applicationRole') IS NOT NULL
BEGIN
    GRANT EXECUTE ON auth.uspCreateTenant                  TO applicationRole;
    GRANT EXECUTE ON auth.uspUpdateTenant                  TO applicationRole;
    GRANT EXECUTE ON auth.uspDeactivateTenant              TO applicationRole;
    GRANT EXECUTE ON auth.uspGetTenantTree                 TO applicationRole;
    GRANT EXECUTE ON auth.uspSetTenantAuthenticationPolicy TO applicationRole;
    GRANT EXECUTE ON auth.uspSetTenantDefaultRoles         TO applicationRole;
END;
GO


-- *** 10. Closing report ***
DECLARE @Report TABLE
(
    RowNo    INT IDENTITY (1, 1) PRIMARY KEY,
    Severity INT             NOT NULL,
    Status   VARCHAR (10)    NOT NULL,
    Item     NVARCHAR (200)  NOT NULL,
    Detail   NVARCHAR (1000)     NULL
);

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (x.ProcName, N'P') IS NULL THEN 1 ELSE 4 END
     , CASE WHEN OBJECT_ID (x.ProcName, N'P') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Procedure ' + x.ProcName
     , x.Detail
  FROM (VALUES (N'auth.uspRebuildTenantClosure', N'Section 5.3. Full rebuild, one transaction, retired pairs soft-deleted.')
             , (N'auth.uspCreateTenant',         N'Section 5.3. Tenant.Create. Cannot create a root; INV-02.')
             , (N'auth.uspUpdateTenant',         N'Section 5.3. Tenant.Update, demanded at the tenant AND at any new parent.')
             , (N'auth.uspDeactivateTenant',     N'Section 5.3. Tenant.Deactivate. Sets IsActive, never IsDeleted.')
             , (N'auth.uspGetTenantTree',        N'Section 5.3. Tenant.Read. Error-only instrumented; reads only.')
             , (N'auth.uspSetTenantAuthenticationPolicy'
                                              , N'Sections 7.2 and 7.3, G-43. Tenant.Update. The first writer of '
                                              + N'auth.TenantAuthenticationPolicy and auth.TenantTrustedIssuer.')
             , (N'auth.uspSetTenantDefaultRoles'
                                              , N'Sections 8.5 and 11.5, G-43. Tenant.Update AND Authz.RoleAssign. The '
                                              + N'first writer of auth.TenantDefaultRole.')) AS x (ProcName, Detail);

-- THE SIX AUTHORIZED PROCEDURES INSTALL TODAY AND CANNOT BE CALLED UNTIL PHASE 3, and that has to be visible in the
-- transcript rather than discovered at the first call.  Deferred name resolution is what lets them compile against
-- procedures that do not exist yet; the price is error 2812 at call time instead of 208 at deploy time.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (N'auth.uspSetSessionContext', N'P') IS NULL
              OR OBJECT_ID (N'auth.uspDemandPermission',  N'P') IS NULL THEN 3 ELSE 4 END
     , CASE WHEN OBJECT_ID (N'auth.uspSetSessionContext', N'P') IS NULL
              OR OBJECT_ID (N'auth.uspDemandPermission',  N'P') IS NULL THEN 'PENDING' ELSE 'OK' END
     , N'Callability of the six authorized tenant procedures'
     , N'They reference auth.uspSetSessionContext (Phase 2) and auth.uspDemandPermission (Phase 3). Deferred name '
     + N'resolution lets them INSTALL now; a call before those exist fails with 2812. A conditional gate around the '
     + N'EXEC lines was rejected -- that is finding F-07''s shape, where a permission check that is skipped when its '
     + N'dependency is absent becomes a permission check that is skipped. auth.uspRebuildTenantClosure references '
     + N'neither and is callable today, which is what the Phase 1 fixtures use.';

-- Proves the rebuild RUNS, not merely that it compiled -- on an empty tree that is a cheap assertion, and on a
-- populated one it is the whole of INV-02's closure half.
EXEC auth.uspRebuildTenantClosure;

INSERT @Report (Severity, Status, Item, Detail)
SELECT 4, 'OK'
     , N'auth.uspRebuildTenantClosure ran'
     , CONCAT (CAST ((SELECT COUNT (*) FROM auth.Tenant        WHERE IsDeleted = 0) AS NVARCHAR (10)), N' live tenant(s), '
             , CAST ((SELECT COUNT (*) FROM auth.TenantClosure WHERE IsDeleted = 0) AS NVARCHAR (10)), N' live closure pair(s), '
             , CAST ((SELECT COUNT (*) FROM auth.TenantClosure WHERE IsDeleted = 1) AS NVARCHAR (10)), N' retired pair(s) retained. '
             , N'Zeroes are expected until the Phase 1 fixtures or a real seed have run.');

-- The closure is either complete or it is not; there is no useful middle state.  Every live tenant must have its
-- depth-0 self row, or auth.udfIsTenantUsable returns 0 for it and every sign-in at that tenant fails.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Missing = 0 THEN 4 ELSE 1 END
     , CASE WHEN x.Missing = 0 THEN 'OK' ELSE 'VIOLATED' END
     , N'Every live tenant has its depth-0 closure row'
     , CONCAT (x.Missing, N' live tenant(s) have no self row after a rebuild. Anything but 0 means '
             , N'auth.udfIsTenantUsable returns 0 for them and every sign-in at those tenants fails with 50021.')
  FROM (SELECT Missing = COUNT (*)
          FROM auth.Tenant AS t
         WHERE t.IsDeleted = 0
           AND NOT EXISTS (SELECT 1
                             FROM auth.TenantClosure AS c
                            WHERE c.AncestorTenantId   = t.TenantId
                              AND c.DescendantTenantId = t.TenantId
                              AND c.Depth              = 0
                              AND c.IsDeleted          = 0)) AS x;

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 7 THEN 4 ELSE 2 END
     , CASE WHEN COUNT (*) = 7 THEN 'OK' ELSE 'INCOMPLETE' END
     , N'MS_Description on the tenant procedures'
     , CONCAT (COUNT (*), N' of 7 procedures carry a description. Conventions rule 4.')
  FROM sys.extended_properties AS ep
  JOIN sys.objects             AS o ON o.object_id = ep.major_id
 WHERE ep.class = 1
   AND ep.minor_id = 0
   AND ep.name = N'MS_Description'
   AND o.schema_id = SCHEMA_ID (N'auth')
   AND o.type = N'P'
   AND o.name IN (N'uspRebuildTenantClosure', N'uspCreateTenant', N'uspUpdateTenant'
                , N'uspDeactivateTenant', N'uspGetTenantTree', N'uspSetTenantAuthenticationPolicy'
                , N'uspSetTenantDefaultRoles');

-- THE THREE NEW TRAIL VERBS MUST BE IN logs.AuthorizationChange'S VOCABULARY OR SECTION 6 FAILS AT CALL TIME WITH 547,
-- and a foreign-key-shaped constraint failure inside a trail writer is the least readable way to discover it.  The
-- widening lives in 085_logs_auth_tables.sql, which installs at step 19 and this file at step 28, so by the time this
-- report runs the answer is knowable.  TenantPolicyChanged also needs CK_logs_AuthorizationChange_Attributable widened:
-- a policy change names a TENANT and no user, profile or role, and the original check required one of those three --
-- which is also why the published TenantReparented verb had never had a writer either.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Verbs = 1 AND x.Attributable = 1 THEN 4 ELSE 1 END
     , CASE WHEN x.Verbs = 1 AND x.Attributable = 1 THEN 'OK' ELSE 'VIOLATED' END
     , N'logs.AuthorizationChange accepts the tenant-scoped trail verbs'
     , CONCAT (N'ChangeType vocabulary includes the five new Tenant* verbs: ', x.Verbs
             , N'. Attributable check allows a tenant-only row: ', x.Attributable
             , N'. Anything but 1 and 1 means auth.uspSetTenantAuthenticationPolicy and auth.uspSetTenantDefaultRoles '
             , N'install here and fail with Msg 547 on their first successful call. Re-run '
             , N'database/085_logs_auth_tables.sql.')
  FROM (SELECT Verbs = MAX (CASE WHEN c.name = N'CK_logs_AuthorizationChange_ChangeType'
                                 AND c.definition LIKE N'%TenantPolicyChanged%'
                                 AND c.definition LIKE N'%TenantTrustedIssuerAdded%'
                                 AND c.definition LIKE N'%TenantTrustedIssuerRemoved%'
                                 AND c.definition LIKE N'%TenantDefaultRoleAdded%'
                                 AND c.definition LIKE N'%TenantDefaultRoleRemoved%' THEN 1 ELSE 0 END)
             , Attributable = MAX (CASE WHEN c.name = N'CK_logs_AuthorizationChange_Attributable'
                                        AND c.definition LIKE N'%ScopeTenantId%' THEN 1 ELSE 0 END)
          FROM sys.check_constraints AS c
         WHERE c.parent_object_id = OBJECT_ID (N'logs.AuthorizationChange')) AS x;

-- What section 5.3 and section 8.1 name that this file does not yet contain.  Reported rather than omitted, so the gap
-- between this file and the design is visible in a deployment transcript instead of only in the Scripts sheet.
INSERT @Report (Severity, Status, Item, Detail)
SELECT 3, 'PENDING', N'Procedure ' + x.ProcName, x.Reason
  FROM (VALUES (N'auth.uspDeleteTenant', N'Soft delete, permission Tenant.Delete. Needs a decision on what happens to '
                                       + N'profiles scoped to the subtree, which is Phase 2''s question.')
             , (N'auth.uspMoveTenantData', N'Not in the design. Listed here because re-parenting a tenant does NOT move '
                                         + N'its business rows, and somebody will eventually ask.')) AS x (ProcName, Reason)
 WHERE OBJECT_ID (x.ProcName, N'P') IS NULL;

IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
    PRINT N'Tenancy procedures: PROBLEMS found. Read the report below before running the next script.';
ELSE
    PRINT N'Tenancy procedures: no problems found. Items listed as PENDING belong to later phases.';

PRINT N'';

SELECT Severity, Status, Item, Detail
  FROM @Report
 ORDER BY Severity, RowNo;
GO




