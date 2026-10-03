/***********************************************************************************************************************
Script:         165_logs_procedures.sql
Purpose:        The three recorders for the three authorization trails: logs.uspRecordAuthorizationChange,
                logs.uspRecordAuthorizationDenial and logs.uspRecordDataChange.  Every path by which a row reaches
                logs.AuthorizationChange, logs.AuthorizationDenial or logs.DataChangeLog.
Target:         SQL Server 2022.
Run as:         db_owner in the target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/165_logs_procedures.sql
Idempotent:     Yes.  CREATE OR ALTER throughout, and every grant guarded on DATABASE_PRINCIPAL_ID.
Depends on:     database/085_logs_auth_tables.sql, database/045_auth_identity.sql, database/055_auth_role.sql,
                database/030_auth_tenant.sql, scripts/logExecutionLogging.sql, templates/extended-properties.sql.
Implements:     T-056.  DES-AUTH-001 sections 11, 15.5, 19.2 and 19.3, and D-12.
                See docs/10-database-authn-authz-design.md.
To retarget:    Pass it per run:  sqlcmd -d <database> -v DbName=<database>.  There is no in-file default.

THESE THREE ARE FULLY INSTRUMENTED, AND A LOGGING PROCEDURE THAT LOGS ITSELF IS NOT A CONTRADICTION
---------------------------------------------------------------------------------------------------
Conventions rule 8 exempts exactly five procedures from instrumentation, and all five are the logs.ExecutionLog chain
itself: logs.uspStartExecutionLogging, logs.uspStartExecutionLoggingInsert, logs.uspRecordExecutionError,
logs.uspRecordExecutionErrorUpdate and util.uspSetObjectDescription.  "Nothing outside that chain is exempt, whatever it
is called.  A procedure in logs that is not one of the four is instrumented like any other."  These three are not in the
chain -- they write the AUTHORIZATION trails, which is ordinary work that happens to land in the logs schema -- so they
carry the full rule 8 block.

The recursion worry is worth answering explicitly, because it is the first objection anybody raises.  There is none:
these procedures write logs.AuthorizationChange, logs.AuthorizationDenial and logs.DataChangeLog, their instrumentation
writes logs.ExecutionLog through logs.uspStartExecutionLogging, and THAT procedure is exempt and calls nothing.  The
chain is two deep and terminates.

The cost is real and it is accepted: one trail row costs one logs.ExecutionLog insert and one update on top of its own
insert.  The alternative -- an uninstrumented recorder -- means that when the trail stops for a day nothing in the
database says whether it was never called, called and refused, or called and rolled back.  That is the question these
tables exist to answer about OTHER procedures, and exempting them from it would be the one place the argument does not
apply to itself.

A TRAIL ROW WRITTEN INSIDE THE CALLER'S TRANSACTION LIVES OR DIES WITH IT
-------------------------------------------------------------------------
Stated in full in the header of 085_logs_auth_tables.sql and repeated here because this is the file somebody edits when
they notice it.  A recorder called from inside an open transaction writes its row in that transaction, and the caller's
ROLLBACK takes the row with it.  For logs.AuthorizationChange and logs.DataChangeLog that is exactly right: a grant that
did not commit must not appear in the trail as though it did.

For logs.AuthorizationDenial it is a genuine limitation.  auth.uspDemandPermission records the denial and then raises
E-50030, so a demand made inside a transaction the caller had already opened loses its trail row to the rollback that
follows.  The instrumentation flush pattern -- accumulate in a table variable, flush from the CATCH -- cannot rescue it,
because the rollback in question is the CALLER's and SET XACT_ABORT ON dooms that transaction: a CATCH-time insert in a
doomed transaction fails too (3930).  The design's answer is the call ORDER in section 9: authorize at step 5, before
the work opens a transaction at step 6.  A procedure that follows it keeps every denial.  A procedure that demands a
permission halfway through a transaction does not, and that is an accepted limitation recorded as BL-042 rather than a
defect hidden behind a loopback connection.

THE RECORDERS THROW ON A MALFORMED ROW RATHER THAN SWALLOWING IT
----------------------------------------------------------------
E-50130 to E-50135, a new range registered in Appendix B.  Every one of them is a defect in the CALLING procedure, not
anything a user did, and every one of them would be refused by a CHECK constraint on the table a few microseconds later
anyway -- so the choice is not between throwing and succeeding, it is between a number the caller can branch on and a
constraint name in a 547 message.

Swallowing was considered and rejected.  A recorder that returns success after discarding the row produces a trail that
looks complete and is not, which is finding F-07's shape applied to auditing: the mechanism is present, nothing is
recorded, and nothing reports that.  The consequence -- a caller whose business work is rolled back because its audit
row was malformed -- is the correct consequence.  An authorization change that cannot be recorded must not happen.

ActorAuthorityTenantId IS NOT GUESSED, AND SESSION_CONTEXT ('ActingTenantId') IS NOT IT
---------------------------------------------------------------------------------------
P-08.  The column records WHICH grant of Authz.RoleAssign the actor relied on, which is the whole point of the table: a
review can otherwise establish that Smith granted EDITOR at Anne Arundel, but not whether Smith was entitled to.
auth.ProfilePermissionScope is derived and holds no history, so the answer does not survive anywhere else.

Only the calling procedure knows which scope row satisfied its demand, so the recorder takes it as a parameter and
defaults it to NULL.  Defaulting it from SESSION_CONTEXT ('ActingTenantId') was considered and rejected: the acting
tenant is where the actor was WORKING, not where the authority came from, and the two differ in precisely the case a
review cares about -- an administrator scoped at the agency acting on a program three levels down.  A plausible wrong
value is worse than a NULL, because a NULL is visibly missing and 085's closing report counts them.

NULL has two legitimate causes and both are named in 085's header: the bootstrap, which has no acting profile at all,
and a platform administrator acting under a non-tenant-scoped Platform permission, where there is no authority tenant to
name.  Everything else is a caller that should have passed it.

WHAT THE CALLER MUST PASS, AND THE TWO THINGS DEFAULTED FROM SESSION CONTEXT
----------------------------------------------------------------------------
@ActorUserProfileId and @UserProfileId default to TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT) when the caller
passes NULL, because the acting profile is the same value on every call and a caller that forgets it produces an
unattributed row rather than an error.  TRY_CAST, never CAST: an unset key is NULL and a CAST of a malformed one raises
inside the recorder, which is the last place an error should originate.

Nothing else is defaulted.  In particular @KeyJson, @ChangeType and @Operation are mandatory and have no fallback.

@KeyParameters CARRIES IDENTIFIERS AND COUNTS ONLY, WHICH RULES OUT @KeyJson AND THE THREE JSON PARAMETERS.  The rule
comes from the procedure template and it bites harder here than usual: @KeyJson holds the business key of a row in dbo,
@DetailJson holds the shape of an authorization change, and copying either into logs.ExecutionLog would move data into
a table with a different read audience and a different retention policy from the one it was written to.  The recorders
log the table name, the operation and the identifiers, and never the payload.

NO EXISTENCE CHECK ON @SchemaName AND @TableName, AND THE REASON IS MEASURED
----------------------------------------------------------------------------
A typo'd table name in logs.DataChangeLog produces a trail nobody can query, so validating it with
OBJECT_ID (QUOTENAME (@SchemaName) + N'.' + QUOTENAME (@TableName)) looks obviously right.  It is not: OBJECT_ID returns
NULL for a principal denied metadata visibility, and the permission model denies exactly that to both application
logins -- the same measurement that forces the @ProcName literal fallback in every procedure in this database.  A
recorder that validated existence would refuse every legitimate call the application makes and accept every call a
db_owner deployment script makes, which is the worst possible split.  So the parameters are checked for emptiness and
length and nothing else, and 950_verify_deployment.sql is where a table name that matches nothing gets reported.

THE TWO CLOSED VOCABULARIES ARE WRITTEN OUT TWICE AND THE CLOSING REPORT KEEPS THEM HONEST
------------------------------------------------------------------------------------------
ChangeType has twenty-one legal values and Operation has four.  Each list appears in a CHECK constraint in
085_logs_auth_tables.sql and again in the IN test inside the recorder, because a procedure that let a bad value through
to the constraint would report it as 547 with no indication of which value was wrong.  Duplication that a reviewer
cannot see going stale is the problem, so section 6 checks every value in its own list against BOTH the constraint
definition and the procedure definition as stored, and counts the literals in the constraint so that a value added
there and nowhere else is reported too.

NONE OF THE THREE IS GRANTED TO applicationRole, AND A PROBE SAYS THAT COSTS NOTHING
------------------------------------------------------------------------------------
Measured on this instance rather than assumed: a user in applicationRole holding EXECUTE on auth.uspProbeOuter and
nothing on logs.uspProbeInner executed the outer procedure and the nested call succeeded.  Ownership chaining covers a
nested EXEC across schemas when both schemas have the same owner, and auth, logs, config, util and dbo are all owned by
dbo here.  So the procedures that call these recorders reach them by chaining, with no grant.

Withholding the grant is the point rather than a side effect.  A trail the application can write arbitrary rows into is
not a trail: with EXECUTE, a compromised application login could record a RoleRevoked that never happened, or bury a
real denial under ten thousand fabricated ones.  The same argument is why auth.uspRebuildTenantClosure is not granted in
125_auth_tenant_procedures.sql.  INV-11.
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

IF OBJECT_ID (N'logs.AuthorizationChange', N'U') IS NULL
   OR OBJECT_ID (N'logs.AuthorizationDenial', N'U') IS NULL
   OR OBJECT_ID (N'logs.DataChangeLog', N'U') IS NULL
BEGIN
    -- Built into a variable because THROW takes a constant or a variable, never an expression.
    DECLARE @MsgTrails NVARCHAR (2000) =
        N'One of logs.AuthorizationChange, logs.AuthorizationDenial or logs.DataChangeLog is missing. Run '
      + N'database/085_logs_auth_tables.sql first. Unlike a procedure, these recorders write to the tables in the same '
      + N'batch that creates them -- the closing report calls all three -- so deferred name resolution does not save '
      + N'this file the way it saves 125_auth_tenant_procedures.sql.';

    THROW 50000, @MsgTrails, 1;
END
GO

-- The instrumentation chain.  A warning rather than a THROW, for the reason 125 gives: a procedure gets deferred name
-- resolution and installs without it, and refusing to install would make the order of the conventions installer and the
-- local scripts into a hard dependency it does not need to be.  The difference here is that the closing report EXECs
-- all three recorders, so a database missing the chain fails in section 6 rather than on the first application call.
IF OBJECT_ID (N'logs.uspStartExecutionLogging', N'P') IS NULL OR OBJECT_ID (N'logs.uspRecordExecutionError', N'P') IS NULL
BEGIN
    PRINT N'WARNING: logs.uspStartExecutionLogging or logs.uspRecordExecutionError is missing. The three recorders in '
        + N'this file will install and will fail with error 2812 -- including in the closing report below. Run '
        + N'.claude/skills/ponytail-sql-objects/scripts/logExecutionLogging.sql against this database.';
END
GO


-- *** 1. logs.uspRecordAuthorizationChange ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   logs.uspRecordAuthorizationChange
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Records one row in logs.AuthorizationChange: who changed whose authority, to what, and -- P-08 -- which grant of their
own they relied on to do it.  Sections 11 and 15.5.

Called by the administrative procedures of Phase 6 (auth.uspAssignRoleToProfile, auth.uspRevokeRoleFromProfile,
auth.uspCreateProfile, auth.uspSetRolePermissions, auth.uspUpdateRole), by 900_bootstrap_first_admin.sql, and by
auth.uspUpdateTenant for 'TenantReparented'.  Not granted to applicationRole; reached by ownership chaining.

========================================================================================================================
Requirements and Key Dependencies:

logs.AuthorizationChange, and through its six foreign keys auth.[User], auth.UserProfile, auth.Role and auth.Tenant.

logs.uspStartExecutionLogging and logs.uspRecordExecutionError, for the rule 8 instrumentation block, plus
logs.ExecutionLog itself, which the completion UPDATE writes directly.  All three are installed by
scripts/logExecutionLogging.sql.

========================================================================================================================
Notes:

NOT IDEMPOTENT, AND IT MUST NOT BE.  Two identical calls record two rows, because two identical grants at different
moments are two events.  There is no natural key on a trail.  A caller that retries after a failure it did not diagnose
will produce a duplicate pair of rows with different OccurredUtc values, and that is the correct record of what
happened: the call really was made twice.

@ChangeType IS TESTED HERE AS WELL AS BY THE CONSTRAINT.  The IN list duplicates
CK_logs_AuthorizationChange_ChangeType, on purpose, so a bad value gets E-50130 naming the value instead of 547 naming
the constraint.  Section 6 of this script checks the two lists against each other.

THE ATTRIBUTABILITY TEST IS RAISED AS E-50131 AND NOT LEFT TO THE CONSTRAINT for the same reason, and it is the one
validation a correct caller can still trip: 'ScopeRebuilt' after a re-parenting genuinely has no target user, no target
profile and no role, and the procedure that rebuilds scope must name the profiles it rebuilt for rather than logging one
summary row.  If that turns out to be unbearable in Phase 6, the answer is a RoleId on the row, not a relaxed CHECK.

AND IN PHASE 7 IT TURNED OUT TO BE UNBEARABLE FOR A DIFFERENT SHAPE, SO THE RULE GAINED A NARROW FOURTH BRANCH.  G-43's
auth.uspSetTenantAuthenticationPolicy records that a tenant's authentication policy changed.  That names a tenant and
nothing else: no person's authority moved, no profile was touched, no role was defined -- there is no RoleId to put on
the row, and inventing a target would be a lie in an audit trail.  The paragraph above's advice does not apply, because
it assumes the change HAS a target that the caller is being lazy about naming.

So the test, and CK_logs_AuthorizationChange_Attributable with it, now also accepts a row that names only a
@ScopeTenantId -- for five verbs and no others: TenantReparented, TenantPolicyChanged, TenantTrustedIssuerAdded,
TenantTrustedIssuerRemoved and ScopeRebuilt.  Restricting by verb rather than relaxing the rule to "any of four" keeps
the original protection intact: a RoleGranted naming only a tenant is exactly the unreviewable row the check exists to
refuse, and a writer that forgot its @TargetUserProfileId would otherwise get away with writing one.

THE SAME WIDENING IS WHY 'TenantReparented' FINALLY BECAME WRITABLE.  It has been in the vocabulary since the first cut
and has never had a writer.  Half the reason is that auth.uspUpdateTenant predates this recorder; the other half is that
this test would have refused the row if it had tried.  That is worth knowing because it is the failure mode of every
closed vocabulary agreed in advance: a value nothing can write looks identical to a value nothing has needed yet.

@ActorAuthorityTenantId DEFAULTS TO NULL AND IS NEVER DERIVED.  See the file header.

NO PERMISSION IS DEMANDED.  A recorder that demanded Authz.RoleAssign would need auth.uspDemandPermission, which records
its denials by calling a recorder, and the call graph closes on itself.  The protection is the absent grant, not a
check.

========================================================================================================================
Example Usage and Performance:

declare @id bigint;
exec logs.uspRecordAuthorizationChange @ChangeType = 'RoleGranted', @TargetUserProfileId = 12, @RoleId = 4
                                     , @ScopeTenantId = 7, @ActorUserProfileId = 3, @ActorAuthorityTenantId = 2
                                     , @DetailJson = N'{"expiresUtc":"2027-01-01T00:00:00Z"}'
                                     , @AuthorizationChangeId = @id output;

One singleton insert on a table with four filtered nonclustered indexes, plus the two instrumentation writes.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-056
Description: Created.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE logs.uspRecordAuthorizationChange
      @ChangeType             VARCHAR (40)
    , @TargetUserId           INT            = NULL
    , @TargetUserProfileId    INT            = NULL
    , @RoleId                 INT            = NULL
    , @ScopeTenantId          INT            = NULL
    , @ActorUserProfileId     INT            = NULL
    , @ActorAuthorityTenantId INT            = NULL
    , @DetailJson             NVARCHAR (MAX) = NULL
    , @AuthorizationChangeId  BIGINT         = NULL OUTPUT
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
                                                    , N'[logs].[uspRecordAuthorizationChange]')
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
    DECLARE @Now   DATETIME2 (3)  = SYSUTCDATETIME ()
          , @Actor NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                            , ORIGINAL_LOGIN ());

    -- Identifiers and counts ONLY. @DetailJson is deliberately absent; see the file header.
    SET @KeyParameters = CONCAT (N'ChangeType=',             @ChangeType
                               , N', TargetUserId=',         @TargetUserId
                               , N', TargetUserProfileId=',  @TargetUserProfileId
                               , N', RoleId=',               @RoleId
                               , N', ScopeTenantId=',        @ScopeTenantId
                               , N', ActorUserProfileId=',   @ActorUserProfileId
                               , N', ActorAuthorityTenantId=', @ActorAuthorityTenantId);

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

        -- Validation BEFORE BEGIN TRANSACTION. A malformed call has nothing to roll back, and doing
        -- it here means the failure is recorded against a logs.ExecutionLog row that no rollback can
        -- reach when the recorder was called with no ambient transaction.
        SET @ChangeType = LTRIM (RTRIM (@ChangeType));

        IF @ChangeType IS NULL
           OR @ChangeType NOT IN ('RoleGranted', 'RoleRevoked', 'GrantExpiryChanged'
                                , 'RoleCreated', 'RoleModified', 'RoleRetired'
                                , 'RolePermissionAdded', 'RolePermissionRemoved'
                                , 'ProfileCreated', 'ProfileActivated', 'ProfileDeactivated', 'ProfileRetired'
                                , 'PlatformAdminGranted', 'PlatformAdminRevoked'
                                , 'TenantReparented', 'ScopeRebuilt'
                                -- G-43.  The five verbs auth.uspSetTenantAuthenticationPolicy and
                                -- auth.uspSetTenantDefaultRoles write.  Section 6 asserts this list against the
                                -- constraint, in both directions.
                                , 'TenantPolicyChanged'
                                , 'TenantTrustedIssuerAdded', 'TenantTrustedIssuerRemoved'
                                , 'TenantDefaultRoleAdded',   'TenantDefaultRoleRemoved')
        BEGIN
            ;THROW 50130, N'@ChangeType is not one of the twenty-one values CK_logs_AuthorizationChange_ChangeType permits. This is a defect in the calling procedure, not anything a user did: the vocabulary is closed on purpose, because an unconstrained change type becomes three spellings of the same event and every review built on it under-counts. Adding a value means an ALTER to the constraint in 085_logs_auth_tables.sql, the IN list here, and the list in section 6 of 165_logs_procedures.sql.', 1;
        END;

        -- G-43 added the fourth branch, and it is restricted to the tenant-scoped verbs on purpose -- see the notes.
        -- A change to a TENANT's own configuration names a tenant and nothing else, and until this was widened that
        -- shape could not be recorded at all, which is why 'TenantReparented' had been in the vocabulary from the first
        -- cut with nothing able to write it.
        IF @TargetUserId IS NULL AND @TargetUserProfileId IS NULL AND @RoleId IS NULL
           AND NOT (@ChangeType IN ('TenantReparented', 'TenantPolicyChanged'
                                  , 'TenantTrustedIssuerAdded', 'TenantTrustedIssuerRemoved', 'ScopeRebuilt')
                    AND @ScopeTenantId IS NOT NULL)
        BEGIN
            ;THROW 50131, N'The row names neither a user, a profile nor a role, so nobody could ever review it -- CK_logs_AuthorizationChange_Attributable. One of the three is enough: RoleModified names a role and no person, PlatformAdminGranted names a person and no role. There is a fourth case, and it is narrow: the tenant-scoped verbs -- TenantReparented, TenantPolicyChanged, TenantTrustedIssuerAdded, TenantTrustedIssuerRemoved and ScopeRebuilt -- may name a @ScopeTenantId and nothing else, because a change to a tenant''s own configuration moves nobody''s authority. Every other verb still needs one of the three. A summary row for a bulk operation is not a substitute; record one row per profile affected.', 1;
        END;

        IF @DetailJson IS NOT NULL AND ISJSON (@DetailJson) = 0
        BEGIN
            ;THROW 50132, N'@DetailJson was supplied and is not valid JSON -- CK_logs_AuthorizationChange_DetailJson. It carries the SHAPE of the change and never the material: an expiry, a count, a permission code. NULL is the correct value when there is nothing to add.', 1;
        END;

        -- The acting profile is the same value on every call, so a caller that omits it gets the
        -- session's. TRY_CAST, never CAST: an unset key is NULL and a malformed one must not raise
        -- inside a recorder.
        SET @ActorUserProfileId = COALESCE (@ActorUserProfileId
                                          , TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT));

        BEGIN TRANSACTION;

        INSERT logs.AuthorizationChange
            (OccurredUtc, ChangeType, TargetUserId, TargetUserProfileId, RoleId, ScopeTenantId
           , ActorUserProfileId, ActorAuthorityTenantId, DetailJson
           , auditCreatedBy, auditCreatedDateUtc, auditModifiedBy, auditModifiedDateUtc)
        VALUES (@Now, @ChangeType, @TargetUserId, @TargetUserProfileId, @RoleId, @ScopeTenantId
              , @ActorUserProfileId, @ActorAuthorityTenantId, @DetailJson
              , @Actor, @Now, @Actor, @Now);

        -- SCOPE_IDENTITY and not @@IDENTITY: the table carries an AFTER UPDATE trigger today and may
        -- gain more, and @@IDENTITY would return whatever a trigger inserted last. Cast because
        -- SCOPE_IDENTITY is NUMERIC (38, 0) and the column is BIGINT.
        SET @AuthorizationChangeId = CAST (SCOPE_IDENTITY () AS BIGINT);

        SET @Comments = CONCAT (N'AuthorizationChange ', @AuthorizationChangeId, N' recorded, ChangeType='
                              , @ChangeType
                              , CASE WHEN @ActorUserProfileId IS NOT NULL AND @ActorAuthorityTenantId IS NULL
                                     THEN N'. NO ActorAuthorityTenantId -- P-08 unsatisfied unless this was a platform '
                                        + N'administrator acting under a Platform permission.'
                                     ELSE N'.' END);

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

        -- Bare, so the ORIGINAL error number reaches the caller: 50130 to 50132 are branchable and
        -- RAISERROR would flatten every one of them to 50000. The leading semicolon is required.
        ;THROW;

    END CATCH;

    RETURN 0;
END;
GO


-- *** 2. logs.uspRecordAuthorizationDenial ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   logs.uspRecordAuthorizationDenial
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Records one row in logs.AuthorizationDenial: a permission that was demanded and refused, at which tenant, by which
profile, against which object.  Sections 15.5 and 19.2.

Called by auth.uspDemandPermission immediately before it raises E-50030, and by any procedure that enforces one of the
six procedure-only permissions of section 10.4 -- Data.SoftDelete, Data.Restore, Data.Export, Data.Approve,
Data.Reassign, Data.Execute -- which row-level security cannot see and therefore cannot record.  Not granted to
applicationRole; reached by ownership chaining.

========================================================================================================================
Requirements and Key Dependencies:

logs.AuthorizationDenial, and through its two foreign keys auth.UserProfile and auth.Tenant.

logs.uspStartExecutionLogging and logs.uspRecordExecutionError, for the rule 8 instrumentation block, plus
logs.ExecutionLog itself.  All three are installed by scripts/logExecutionLogging.sql.

========================================================================================================================
Notes:

THE ROLLBACK HAZARD IS THIS PROCEDURE'S, AND IT IS THE REASON SECTION 9 ORDERS THE STEPS THE WAY IT DOES.  Spelled out
in the file header and in 085_logs_auth_tables.sql: called inside a transaction the caller had already opened, the row
is lost to the rollback that E-50030 provokes.  Called before any transaction is open -- section 9 step 5, which is
before step 6 -- it is written in autocommit and survives.  Every procedure in this database that demands a permission
does so before it opens a transaction.  BL-042.

PermissionCode IS A STRING AND NOT A FOREIGN KEY, and the consequence lands here: a denial for a permission code that
does not exist in auth.Permission is exactly the row that proves a procedure has a typo in it, and a foreign key would
refuse to record it.  So this procedure does not check the code against auth.Permission either.  E-50031 -- "permission
code does not exist in this application" -- is auth.uspDemandPermission's to raise, AFTER it has recorded the denial
here.

@UserProfileId IS NULLABLE AND NULL IS THE MOST INTERESTING VALUE IT TAKES.  A demand made on a connection with no
session context is refused, and that denial means a procedure is reachable without auth.uspSetSessionContext having
run, which is a worse finding than any individual permission failure.  Recording it is the point.

NO PERMISSION IS DEMANDED, and here the circularity is not hypothetical: auth.uspDemandPermission calls this procedure,
so a demand inside it would recurse until the nesting limit.

@ObjectName IS COERCED RATHER THAN VALIDATED.  An empty string becomes NULL, because a caller passing N'' means "I have
no object to name" and CK_logs_AuthorizationDenial_ObjectName would refuse it.  There is no defect to report and no
reason to fail the caller's work over the difference.

========================================================================================================================
Example Usage and Performance:

declare @id bigint;
exec logs.uspRecordAuthorizationDenial @PermissionCode = N'Data.Export', @TenantId = 7, @UserProfileId = 12
                                      , @ObjectName = N'dbo.uspExportCaseload'
                                      , @AuthorizationDenialId = @id output;

One singleton insert on a table with three filtered nonclustered indexes, plus the two instrumentation writes.  This is
the highest-volume of the three recorders under attack and the lowest under normal operation.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-056
Description: Created.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE logs.uspRecordAuthorizationDenial
      @PermissionCode        NVARCHAR (100)
    , @TenantId              INT            = NULL
    , @UserProfileId         INT            = NULL
    , @ObjectName            NVARCHAR (256) = NULL
    , @DetailJson            NVARCHAR (MAX) = NULL
    , @AuthorizationDenialId BIGINT         = NULL OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[logs].[uspRecordAuthorizationDenial]')
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

    DECLARE @Now   DATETIME2 (3)  = SYSUTCDATETIME ()
          , @Actor NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                            , ORIGINAL_LOGIN ());

    -- Identifiers and counts ONLY. A permission code and an object name are both identifiers.
    SET @KeyParameters = CONCAT (N'PermissionCode=',  @PermissionCode
                               , N', TenantId=',      @TenantId
                               , N', UserProfileId=', @UserProfileId
                               , N', ObjectName=',    @ObjectName);

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

        SET @PermissionCode = LTRIM (RTRIM (@PermissionCode));
        SET @ObjectName     = NULLIF (LTRIM (RTRIM (@ObjectName)), N'');

        IF @PermissionCode IS NULL OR LEN (@PermissionCode) = 0
        BEGIN
            ;THROW 50133, N'@PermissionCode is required and was empty or whitespace -- CK_logs_AuthorizationDenial_PermissionCode. A denial that does not say which permission was refused is a row count. The code is NOT checked against auth.Permission on purpose: a denial for a code that does not exist is the row that proves a procedure has a typo, and refusing it would hide exactly that.', 1;
        END;

        IF @DetailJson IS NOT NULL AND ISJSON (@DetailJson) = 0
        BEGIN
            ;THROW 50132, N'@DetailJson was supplied and is not valid JSON -- CK_logs_AuthorizationDenial_DetailJson. It carries the shape of the refusal and never the material.', 1;
        END;

        SET @UserProfileId = COALESCE (@UserProfileId, TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT));

        BEGIN TRANSACTION;

        INSERT logs.AuthorizationDenial
            (OccurredUtc, UserProfileId, PermissionCode, TenantId, ObjectName, DetailJson
           , auditCreatedBy, auditCreatedDateUtc, auditModifiedBy, auditModifiedDateUtc)
        VALUES (@Now, @UserProfileId, @PermissionCode, @TenantId, @ObjectName, @DetailJson
              , @Actor, @Now, @Actor, @Now);

        SET @AuthorizationDenialId = CAST (SCOPE_IDENTITY () AS BIGINT);

        SET @Comments = CONCAT (N'AuthorizationDenial ', @AuthorizationDenialId, N' recorded, PermissionCode='
                              , @PermissionCode
                              , CASE WHEN @UserProfileId IS NULL
                                     THEN N', NO UserProfileId -- the demand was made on a connection with no session '
                                        + N'context, which means a procedure is reachable without '
                                        + N'auth.uspSetSessionContext having run.'
                                     ELSE N'.' END);

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


-- *** 3. logs.uspRecordDataChange ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   logs.uspRecordDataChange
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Records one row in logs.DataChangeLog: which row of which table changed, how, and who changed it.  Section 15.5 and
D-12 -- written by the domain procedures, deliberately not by a generic audit trigger.

Called by the demo domain procedures of Phase 5, and by any project procedure that changes business data.  Not granted
to applicationRole; reached by ownership chaining.

========================================================================================================================
Requirements and Key Dependencies:

logs.DataChangeLog, and through its one foreign key auth.UserProfile.

logs.uspStartExecutionLogging and logs.uspRecordExecutionError, for the rule 8 instrumentation block, plus
logs.ExecutionLog itself.  All three are installed by scripts/logExecutionLogging.sql.

========================================================================================================================
Notes:

ONE ROW PER CALL, AND A SET-BASED WRITER MUST NOT LOOP OVER IT.  D-12 buys its cost advantage over a generic trigger by
logging the columns that matter, which means the caller decides what to record -- but a MERGE that touches ten thousand
rows and then calls this procedure ten thousand times has thrown that advantage away and added twenty thousand
logs.ExecutionLog writes on top.  Such a caller should INSERT into logs.DataChangeLog directly from its OUTPUT clause,
which ownership chaining permits and which is why the grant section below withholds nothing from a procedure.  This
recorder is for the singleton case, which is the overwhelming majority: one form, one row, one trail entry.

'SoftDelete' AND 'Restore' ARE NOT 'Update' EVEN THOUGH THE STATEMENT IS THE SAME ONE.  That is the whole point of
section 10.4 making them separate permissions: row-level security cannot tell the three apart, the procedure can, and a
trail that recorded a soft delete as an update would throw away the distinction the permissions were bought to make.
E-50135 is what stops a caller collapsing them.

@SchemaName AND @TableName ARE NOT CHECKED FOR EXISTENCE, and the reason is measured rather than stylistic.  See the
file header: OBJECT_ID returns NULL for a principal denied metadata visibility, which is both application logins, so an
existence check would refuse every legitimate application call while passing every deployment-script call.

@KeyJson IS MANDATORY AND NEVER REACHES logs.ExecutionLog.  A change log entry nobody can trace back to a row is a row
count -- hence E-50134 -- and the key of a row in dbo is business data, so it is excluded from @KeyParameters by the
same rule that excludes a payload.  @ChangedColumnsJson is NULL for an insert, where every column is new and the row
itself is the change.

========================================================================================================================
Example Usage and Performance:

declare @id bigint;
exec logs.uspRecordDataChange @SchemaName = N'dbo', @TableName = N'Case', @Operation = 'Update'
                             , @KeyJson = N'{"CaseId":4711}'
                             , @ChangedColumnsJson = N'{"StatusCode":{"from":"Open","to":"Closed"}}'
                             , @DataChangeLogId = @id output;

One singleton insert on a table with three filtered nonclustered indexes, plus the two instrumentation writes.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-056
Description: Created.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE logs.uspRecordDataChange
      @SchemaName         SYSNAME
    , @TableName          SYSNAME
    , @Operation          VARCHAR (20)
    , @KeyJson            NVARCHAR (MAX)
    , @ChangedColumnsJson NVARCHAR (MAX) = NULL
    , @ActorUserProfileId INT            = NULL
    , @DataChangeLogId    BIGINT         = NULL OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[logs].[uspRecordDataChange]')
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

    DECLARE @Now   DATETIME2 (3)  = SYSUTCDATETIME ()
          , @Actor NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                            , ORIGINAL_LOGIN ());

    -- Identifiers and counts ONLY. @KeyJson is business data and is deliberately absent; see the
    -- notes above and the file header.
    SET @KeyParameters = CONCAT (N'SchemaName=',            @SchemaName
                               , N', TableName=',           @TableName
                               , N', Operation=',           @Operation
                               , N', ActorUserProfileId=',  @ActorUserProfileId);

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

        SET @SchemaName = LTRIM (RTRIM (@SchemaName));
        SET @TableName  = LTRIM (RTRIM (@TableName));
        SET @Operation  = LTRIM (RTRIM (@Operation));

        IF @SchemaName IS NULL OR LEN (@SchemaName) = 0
           OR @TableName IS NULL OR LEN (@TableName) = 0
           OR @KeyJson IS NULL OR ISJSON (@KeyJson) = 0
        BEGIN
            ;THROW 50134, N'The row this entry claims to describe cannot be identified: @SchemaName or @TableName was empty, or @KeyJson was missing or is not valid JSON. All three are mandatory -- CK_logs_DataChangeLog_SchemaName, _TableName and _KeyJson. The names are NOT checked against sys.objects, because OBJECT_ID returns NULL for a principal denied metadata visibility and that is both application logins.', 1;
        END;

        IF @Operation NOT IN ('Insert', 'Update', 'SoftDelete', 'Restore')
        BEGIN
            ;THROW 50135, N'@Operation must be Insert, Update, SoftDelete or Restore -- CK_logs_DataChangeLog_Operation. SoftDelete and Restore are deliberately NOT Update although the statement is the same one: section 10.4 makes them separate permissions because row-level security cannot tell them apart and the procedure can, and a trail that collapsed them would discard the distinction the permissions exist to make.', 1;
        END;

        IF @ChangedColumnsJson IS NOT NULL AND ISJSON (@ChangedColumnsJson) = 0
        BEGIN
            ;THROW 50132, N'@ChangedColumnsJson was supplied and is not valid JSON -- CK_logs_DataChangeLog_ChangedColumnsJson. NULL is the correct value for an insert, where every column is new and the row itself is the change.', 1;
        END;

        SET @ActorUserProfileId = COALESCE (@ActorUserProfileId
                                          , TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT));

        BEGIN TRANSACTION;

        INSERT logs.DataChangeLog
            (OccurredUtc, SchemaName, TableName, Operation, KeyJson, ChangedColumnsJson, ActorUserProfileId
           , auditCreatedBy, auditCreatedDateUtc, auditModifiedBy, auditModifiedDateUtc)
        VALUES (@Now, @SchemaName, @TableName, @Operation, @KeyJson, @ChangedColumnsJson, @ActorUserProfileId
              , @Actor, @Now, @Actor, @Now);

        SET @DataChangeLogId = CAST (SCOPE_IDENTITY () AS BIGINT);

        SET @Comments = CONCAT (N'DataChangeLog ', @DataChangeLogId, N' recorded, ', @Operation, N' on '
                              , @SchemaName, N'.', @TableName
                              , CASE WHEN @ActorUserProfileId IS NULL
                                     THEN N', NO ActorUserProfileId -- a deployment script or a migration, or an '
                                        + N'application call that reached the domain without a session context.'
                                     ELSE N'.' END);

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


-- *** 4. Descriptions ***
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

    -- Rows rather than three EXEC calls with concatenated arguments, because an EXEC argument takes a constant or a
    -- variable and never an expression -- a '+' in the parameter position is a parse error (102).
    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    VALUES
      (N'logs', N'PROCEDURE', N'uspRecordAuthorizationChange', NULL
     , N'Records one row in logs.AuthorizationChange. Sections 11 and 15.5, P-08. Fully instrumented (rule 8): a trail '
     + N'recorder is an ordinary writer, and the five exemptions are the logs.ExecutionLog chain itself -- the call '
     + N'graph is two deep and terminates. NOT idempotent, deliberately: two identical grants at different moments are '
     + N'two events and a trail has no natural key. @ActorAuthorityTenantId is taken as a parameter and NEVER derived '
     + N'from SESSION_CONTEXT (''ActingTenantId''), which is where the actor was working and not where the authority '
     + N'came from. Raises 50130 unknown ChangeType, 50131 names neither user, profile nor role, 50132 malformed '
     + N'DetailJson. Not granted to applicationRole: with EXECUTE, a compromised application login could record a '
     + N'revocation that never happened.')
    , (N'logs', N'PROCEDURE', N'uspRecordAuthorizationDenial', NULL
     , N'Records one row in logs.AuthorizationDenial. Sections 15.5 and 19.2. Called by auth.uspDemandPermission '
     + N'immediately before it raises 50030, and by the procedures enforcing the six procedure-only permissions of '
     + N'section 10.4 that row-level security cannot see. A NULL UserProfileId is the most interesting row in the '
     + N'table: it means a procedure was reachable without auth.uspSetSessionContext having run. Does NOT check the '
     + N'code against auth.Permission -- a denial for a non-existent code is the row that proves a procedure has a '
     + N'typo. THE ROLLBACK LIMITATION IS REAL: called inside a transaction the caller already opened, the row dies '
     + N'with the rollback that 50030 provokes; section 9 orders the permission check BEFORE the transaction, which is '
     + N'what keeps it. BL-042. Raises 50133, 50132.')
    , (N'logs', N'PROCEDURE', N'uspRecordDataChange', NULL
     , N'Records one row in logs.DataChangeLog. Section 15.5, D-12 -- written by the domain procedures rather than by a '
     + N'generic audit trigger, which is what buys the cost advantage. Singleton by design: a set-based writer should '
     + N'INSERT from its own OUTPUT clause rather than call this ten thousand times. SoftDelete and Restore are '
     + N'separate operations from Update although the statement is the same, because section 10.4 makes them separate '
     + N'permissions. @SchemaName and @TableName are NOT validated against sys.objects: OBJECT_ID returns NULL for a '
     + N'principal denied metadata visibility, which is both application logins, so the check would refuse every '
     + N'legitimate application call. Raises 50134 unidentifiable row, 50135 unknown operation, 50132 malformed '
     + N'ChangedColumnsJson.');

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


-- *** 5. Grants ***
-- THERE ARE NONE, AND THE ABSENCE IS THE SECURITY CONTROL.  Measured on this instance: a user in applicationRole
-- holding EXECUTE on an outer procedure in auth and nothing at all on an inner procedure in logs executed the outer
-- one and the nested call succeeded.  Ownership chaining covers a nested EXEC across schemas when the schemas share an
-- owner, and auth, config, dbo, logs and util are all owned by dbo here.  So every procedure that needs these
-- recorders can call them, and nothing else can call them at all.
--
-- What the grant would buy an attacker is the reason it is withheld: EXECUTE on logs.uspRecordAuthorizationDenial lets
-- a compromised application login bury a real denial under ten thousand fabricated ones, and EXECUTE on
-- logs.uspRecordAuthorizationChange lets it record a revocation that never happened.  A trail the application can
-- write arbitrary rows into is not a trail.  Same argument as auth.uspRebuildTenantClosure in
-- 125_auth_tenant_procedures.sql, and the same INV-11.
--
-- readOnlyRole gets nothing either.  Reading the trails is auth.uspGetAuthTrail and logs.vwAuthorizationTrail in
-- Phase 6, not EXECUTE on a writer.
PRINT N'No grants. These three recorders are reached by ownership chaining from the procedures that call them; see '
    + N'section 5 for the measurement that makes that safe and the reason the grant is withheld.';
GO


-- *** 6. Closing report ***
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
  FROM (VALUES (N'logs.uspRecordAuthorizationChange'
              , N'Sections 11 and 15.5, P-08. Carries ActorAuthorityTenantId. Raises 50130, 50131, 50132.')
             , (N'logs.uspRecordAuthorizationDenial'
              , N'Sections 15.5 and 19.2. Called by auth.uspDemandPermission before it raises 50030. Raises 50133, 50132.')
             , (N'logs.uspRecordDataChange'
              , N'Section 15.5, D-12. Singleton, written by domain procedures. Raises 50134, 50135, 50132.')) AS x (ProcName, Detail);

-- Rule 8 is checked rather than asserted in a comment.  All three must reference the instrumentation chain, and the
-- cheap proof is the stored definition: a procedure that lost its block during an edit stops mentioning it.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 3 THEN 4 ELSE 1 END
     , CASE WHEN COUNT (*) = 3 THEN 'OK' ELSE 'VIOLATED' END
     , N'All three recorders carry the rule 8 instrumentation block'
     , CONCAT (COUNT (*), N' of 3 reference logs.uspStartExecutionLogging AND logs.uspRecordExecutionError. A trail '
             , N'recorder is NOT one of rule 8''s five exemptions: those are the logs.ExecutionLog chain itself.')
  FROM sys.sql_modules AS m
  JOIN sys.objects     AS o ON o.object_id = m.object_id
 WHERE o.schema_id = SCHEMA_ID (N'logs')
   AND o.type = N'P'
   AND o.name IN (N'uspRecordAuthorizationChange', N'uspRecordAuthorizationDenial', N'uspRecordDataChange')
   -- 'EXEC logs.usp...' and not just the name: every one of these procedures discusses the instrumentation chain in its
   -- header, so a bare name match would pass on the comments alone. The test has to look for a CALL.
   AND m.definition LIKE N'%EXEC logs.uspStartExecutionLogging%'
   AND m.definition LIKE N'%EXEC logs.uspRecordExecutionError%';

-- THE VOCABULARY DRIFT CHECK.  Each value is looked for in the CHECK constraint AND in the recorder as stored, so a
-- value present in one and not the other is reported here rather than discovered as a 547 in Phase 6.
DECLARE @ChangeTypeDef NVARCHAR (MAX) = (SELECT cc.definition
                                           FROM sys.check_constraints AS cc
                                          WHERE cc.parent_object_id = OBJECT_ID (N'logs.AuthorizationChange')
                                            AND cc.name = N'CK_logs_AuthorizationChange_ChangeType')
      , @OperationDef  NVARCHAR (MAX) = (SELECT cc.definition
                                           FROM sys.check_constraints AS cc
                                          WHERE cc.parent_object_id = OBJECT_ID (N'logs.DataChangeLog')
                                            AND cc.name = N'CK_logs_DataChangeLog_Operation')
      , @ChangeProcDef NVARCHAR (MAX) = OBJECT_DEFINITION (OBJECT_ID (N'logs.uspRecordAuthorizationChange'))
      , @DataProcDef   NVARCHAR (MAX) = OBJECT_DEFINITION (OBJECT_ID (N'logs.uspRecordDataChange'));

DECLARE @Vocabulary TABLE (Owner VARCHAR (20) NOT NULL, Value VARCHAR (40) NOT NULL);

INSERT @Vocabulary (Owner, Value)
VALUES ('ChangeType', 'RoleGranted'), ('ChangeType', 'RoleRevoked'), ('ChangeType', 'GrantExpiryChanged')
     , ('ChangeType', 'RoleCreated'), ('ChangeType', 'RoleModified'), ('ChangeType', 'RoleRetired')
     , ('ChangeType', 'RolePermissionAdded'), ('ChangeType', 'RolePermissionRemoved')
     , ('ChangeType', 'ProfileCreated'), ('ChangeType', 'ProfileActivated')
     , ('ChangeType', 'ProfileDeactivated'), ('ChangeType', 'ProfileRetired')
     , ('ChangeType', 'PlatformAdminGranted'), ('ChangeType', 'PlatformAdminRevoked')
     , ('ChangeType', 'TenantReparented'), ('ChangeType', 'ScopeRebuilt')
     -- G-43.  Kept in step with the constraint in 085_logs_auth_tables.sql and the IN test in section 1.
     , ('ChangeType', 'TenantPolicyChanged')
     , ('ChangeType', 'TenantTrustedIssuerAdded'), ('ChangeType', 'TenantTrustedIssuerRemoved')
     , ('ChangeType', 'TenantDefaultRoleAdded'),   ('ChangeType', 'TenantDefaultRoleRemoved')
     , ('Operation', 'Insert'), ('Operation', 'Update'), ('Operation', 'SoftDelete'), ('Operation', 'Restore');

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Adrift = 0 THEN 4 ELSE 2 END
     , CASE WHEN x.Adrift = 0 THEN 'OK' ELSE 'DRIFTED' END
     , N'The two closed vocabularies agree between constraint and procedure'
     , CONCAT (x.Adrift, N' of ', x.Total, N' value(s) are missing from either the CHECK constraint or the recorder '
             , N'that validates it. The lists are written out twice on purpose -- a value that reached the constraint '
             , N'would be reported as 547 naming the constraint instead of 50130 or 50135 naming the value.')
  FROM (SELECT Total = COUNT (*)
             , Adrift = SUM (CASE WHEN v.Owner = 'ChangeType'
                                       AND CHARINDEX (N'''' + v.Value + N'''', COALESCE (@ChangeTypeDef, N'')) > 0
                                       AND CHARINDEX (N'''' + v.Value + N'''', COALESCE (@ChangeProcDef, N'')) > 0
                                  THEN 0
                                  WHEN v.Owner = 'Operation'
                                       AND CHARINDEX (N'''' + v.Value + N'''', COALESCE (@OperationDef, N'')) > 0
                                       AND CHARINDEX (N'''' + v.Value + N'''', COALESCE (@DataProcDef, N'')) > 0
                                  THEN 0
                                  ELSE 1 END)
          FROM @Vocabulary AS v) AS x;

-- The other direction: a value added to a constraint and to nothing else.  Counting quoted literals catches it without
-- parsing, because these two constraints contain nothing quoted but their own vocabularies.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.ChangeTypeCount = 21 AND x.OperationCount = 4 THEN 4 ELSE 2 END
     , CASE WHEN x.ChangeTypeCount = 21 AND x.OperationCount = 4 THEN 'OK' ELSE 'DRIFTED' END
     , N'Neither constraint has gained a value this file does not know'
     , CONCAT (N'CK_logs_AuthorizationChange_ChangeType holds ', x.ChangeTypeCount, N' literal(s), expected 21. '
             , N'CK_logs_DataChangeLog_Operation holds ', x.OperationCount, N' literal(s), expected 4. A value added '
             , N'to the constraint alone is accepted by the table and refused by the recorder, so nothing can ever '
             , N'write it.')
  FROM (SELECT ChangeTypeCount = (LEN (COALESCE (@ChangeTypeDef, N'')) - LEN (REPLACE (COALESCE (@ChangeTypeDef, N''), N'''', N''))) / 2
             , OperationCount  = (LEN (COALESCE (@OperationDef,  N'')) - LEN (REPLACE (COALESCE (@OperationDef,  N''), N'''', N''))) / 2) AS x;

-- Proves the recorders RUN rather than merely compiled, which is the assertion that matters on a file whose three
-- procedures will not be called by anything else until Phase 5 and Phase 6.  Written and then soft-deleted in one
-- transaction that is rolled back, so the trails are left exactly as they were found -- and the roll back is itself
-- the demonstration of BL-042: a trail row written inside somebody else's transaction does not survive it.
-- The change recorder needs something to attribute the row to, or E-50131 refuses it -- correctly.  A user is the
-- cheapest anchor on a database where 115_seed_reference_data.sql has not run yet and auth.Role may still be empty; a
-- role is the fallback; if the database has neither, the probe reports SKIPPED rather than pretending to have passed.
DECLARE @SmokeChange BIGINT        = NULL
      , @SmokeDenial BIGINT        = NULL
      , @SmokeData   BIGINT        = NULL
      , @SmokeOk     BIT           = 0
      , @SmokeError  NVARCHAR (1000) = NULL
      , @ProbeUserId INT           = (SELECT MIN (u.UserId) FROM auth.[User] AS u WHERE u.IsDeleted = 0)
      , @ProbeRoleId INT           = NULL;

IF @ProbeUserId IS NULL
BEGIN
    SET @ProbeRoleId = (SELECT MIN (r.RoleId) FROM auth.Role AS r WHERE r.IsDeleted = 0);
END;

BEGIN TRY
    BEGIN TRANSACTION;

    EXEC logs.uspRecordAuthorizationChange
          @ChangeType            = 'ScopeRebuilt'
        , @TargetUserId          = @ProbeUserId
        , @RoleId                = @ProbeRoleId
        , @DetailJson            = N'{"probe":"165_logs_procedures.sql","rolledBack":true}'
        , @AuthorizationChangeId = @SmokeChange OUTPUT;

    EXEC logs.uspRecordAuthorizationDenial
          @PermissionCode        = N'Probe.NeverGranted'
        , @ObjectName            = N'165_logs_procedures.sql'
        , @DetailJson            = N'{"probe":"165_logs_procedures.sql","rolledBack":true}'
        , @AuthorizationDenialId = @SmokeDenial OUTPUT;

    EXEC logs.uspRecordDataChange
          @SchemaName      = N'logs'
        , @TableName       = N'DataChangeLog'
        , @Operation       = 'Insert'
        , @KeyJson         = N'{"probe":"165_logs_procedures.sql"}'
        , @DataChangeLogId = @SmokeData OUTPUT;

    SET @SmokeOk = CASE WHEN @SmokeChange IS NOT NULL AND @SmokeDenial IS NOT NULL AND @SmokeData IS NOT NULL
                        THEN 1 ELSE 0 END;

    ROLLBACK TRANSACTION;
END TRY
BEGIN CATCH
    IF XACT_STATE () <> 0
    BEGIN
        ROLLBACK TRANSACTION;
    END;

    SET @SmokeOk = 0;
    SET @SmokeError = LEFT (ERROR_MESSAGE (), 500);
END CATCH;

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN @SmokeOk = 1 THEN 4
            WHEN @ProbeUserId IS NULL AND @ProbeRoleId IS NULL THEN 3
            ELSE 1 END
     , CASE WHEN @SmokeOk = 1 THEN 'OK'
            WHEN @ProbeUserId IS NULL AND @ProbeRoleId IS NULL THEN 'SKIPPED'
            ELSE 'FAILED' END
     , N'All three recorders ran and returned an identity'
     , CASE WHEN @SmokeOk = 1
            THEN CONCAT (N'Ids ', COALESCE (CAST (@SmokeChange AS NVARCHAR (20)), N'(none)'), N', '
                       , COALESCE (CAST (@SmokeDenial AS NVARCHAR (20)), N'(none)'), N', '
                       , COALESCE (CAST (@SmokeData AS NVARCHAR (20)), N'(none)')
                       , N' were written and the transaction was ROLLED BACK, so the trails are unchanged -- which is '
                       , N'also the live demonstration of BL-042. The identity values are consumed all the same; gaps '
                       , N'in these tables mean the same thing they mean in logs.ExecutionLog.')
            WHEN @ProbeUserId IS NULL AND @ProbeRoleId IS NULL
            THEN N'Not attempted: the database holds no live user and no live role, so there is nothing to attribute a '
               + N'logs.AuthorizationChange row to and E-50131 would refuse it correctly. Re-run this file after '
               + N'115_seed_reference_data.sql or the Phase 2 fixtures.'
            ELSE CONCAT (N'At least one recorder failed. ', COALESCE (@SmokeError, N'(no message captured)')) END;

-- The fail-closed half: the validations must refuse, not merely exist.  A recorder that accepted a malformed row would
-- produce a trail that looks complete and is not, which is finding F-07's shape applied to auditing.
DECLARE @Refusals INT = 0
      , @Expected INT = 4;

BEGIN TRY
    EXEC logs.uspRecordAuthorizationChange @ChangeType = 'NoSuchChangeType', @RoleId = 1;
END TRY
BEGIN CATCH
    SET @Refusals += CASE WHEN ERROR_NUMBER () = 50130 THEN 1 ELSE 0 END;
END CATCH;

BEGIN TRY
    EXEC logs.uspRecordAuthorizationChange @ChangeType = 'ScopeRebuilt';
END TRY
BEGIN CATCH
    SET @Refusals += CASE WHEN ERROR_NUMBER () = 50131 THEN 1 ELSE 0 END;
END CATCH;

BEGIN TRY
    EXEC logs.uspRecordAuthorizationDenial @PermissionCode = N'   ';
END TRY
BEGIN CATCH
    SET @Refusals += CASE WHEN ERROR_NUMBER () = 50133 THEN 1 ELSE 0 END;
END CATCH;

BEGIN TRY
    EXEC logs.uspRecordDataChange @SchemaName = N'dbo', @TableName = N'Anything', @Operation = 'Delete'
                                , @KeyJson = N'{"Id":1}';
END TRY
BEGIN CATCH
    SET @Refusals += CASE WHEN ERROR_NUMBER () = 50135 THEN 1 ELSE 0 END;
END CATCH;

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN @Refusals = @Expected THEN 4 ELSE 1 END
     , CASE WHEN @Refusals = @Expected THEN 'OK' ELSE 'VIOLATED' END
     , N'The recorders refuse a malformed row with the registered number'
     , CONCAT (@Refusals, N' of ', @Expected, N' refusals arrived with the right number: 50130 unknown ChangeType, '
             , N'50131 unattributable, 50133 empty PermissionCode, 50135 unknown Operation. Each failed call also '
             , N'left a logs.ExecutionLog error row, which is what rule 8 instrumentation on a recorder buys.');

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 3 THEN 4 ELSE 2 END
     , CASE WHEN COUNT (*) = 3 THEN 'OK' ELSE 'INCOMPLETE' END
     , N'MS_Description on the three recorders'
     , CONCAT (COUNT (*), N' of 3 procedures carry a description. Conventions rule 4.')
  FROM sys.extended_properties AS ep
  JOIN sys.objects             AS o ON o.object_id = ep.major_id
 WHERE ep.class = 1
   AND ep.minor_id = 0
   AND ep.name = N'MS_Description'
   AND o.schema_id = SCHEMA_ID (N'logs')
   AND o.type = N'P'
   AND o.name IN (N'uspRecordAuthorizationChange', N'uspRecordAuthorizationDenial', N'uspRecordDataChange');

-- The absence of a grant is a decision and it belongs in the transcript, because the next person to see a 229 from an
-- application call will reach for GRANT EXECUTE before reading section 5.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 0 THEN 4 ELSE 2 END
     , CASE WHEN COUNT (*) = 0 THEN 'OK' ELSE 'REVIEW' END
     , N'No EXECUTE granted on the recorders to applicationRole or readOnlyRole'
     , CONCAT (COUNT (*), N' grant(s) found; 0 is correct. Ownership chaining covers the nested EXEC -- measured on '
             , N'this instance -- so the callers work without it, and withholding it is what stops a compromised '
             , N'application login forging or burying a trail row. INV-11.')
  FROM sys.database_permissions AS p
  JOIN sys.objects             AS o  ON o.object_id = p.major_id
  JOIN sys.database_principals AS dp ON dp.principal_id = p.grantee_principal_id
 WHERE p.class = 1
   AND p.permission_name = N'EXECUTE'
   AND p.state IN (N'G', N'W')
   AND o.schema_id = SCHEMA_ID (N'logs')
   AND o.name IN (N'uspRecordAuthorizationChange', N'uspRecordAuthorizationDenial', N'uspRecordDataChange')
   AND dp.name IN (N'applicationRole', N'readOnlyRole');

-- What section 15.5 and section 15.6 name for these trails that this file does not contain.  Reported rather than
-- omitted, so the gap between the file and the design is visible in a deployment transcript.
INSERT @Report (Severity, Status, Item, Detail)
SELECT 3, 'PENDING', N'Object ' + x.ObjectName, x.Reason
  FROM (VALUES (N'auth.uspGetAuthTrail', N'The read side of logs.AuthorizationChange, section 15.5. Phase 6: it '
                                       + N'demands Authz.TrailRead, which needs auth.uspDemandPermission and the '
                                       + N'seeded permission set.')
             , (N'logs.vwAuthorizationTrail', N'The trail joined to names for the audit screen, section 15.6. Phase 6, '
                                            + N'with the rest of the administrative surface.')) AS x (ObjectName, Reason)
 WHERE OBJECT_ID (x.ObjectName) IS NULL;

INSERT @Report (Severity, Status, Item, Detail)
SELECT 4, 'INFO', N'Trail volumes after this run'
     , CONCAT (N'logs.AuthorizationChange ', (SELECT COUNT (*) FROM logs.AuthorizationChange), N' row(s), '
             , N'logs.AuthorizationDenial ', (SELECT COUNT (*) FROM logs.AuthorizationDenial), N' row(s), '
             , N'logs.DataChangeLog ',       (SELECT COUNT (*) FROM logs.DataChangeLog),       N' row(s). '
             , N'Unchanged by this script: the smoke test rolled back, and the four refusal probes wrote nothing but '
             , N'logs.ExecutionLog error rows.');

IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
    PRINT N'Trail recorders: PROBLEMS found. Read the report below before running the next script.';
ELSE
    PRINT N'Trail recorders: no problems found. Items listed as PENDING belong to Phase 6.';

PRINT N'';

SELECT Severity, Status, Item, Detail
  FROM @Report
 ORDER BY Severity, RowNo;
GO
