/***********************************************************************************************************************
Script:         065_auth_effective_permission.sql
Purpose:        auth.ProfilePermissionScope -- the materialized effective grant -- and
                auth.uspRebuildProfilePermissionScope, the only thing that writes it.
Target:         SQL Server 2022.
Run as:         db_owner in the target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/065_auth_effective_permission.sql
Idempotent:     Yes.  Guarded CREATE TABLE and CREATE INDEX, CREATE OR ALTER trigger and procedure, no seed data.
Depends on:     database/040_auth_userprofile.sql, database/050_auth_permission.sql, database/055_auth_role.sql,
                database/060_auth_profile_role.sql, scripts/logExecutionLogging.sql (rule 8 instrumentation),
                templates/extended-properties.sql.
Implements:     DES-AUTH-001 sections 8.6, 9.2, 10.2, 15.4 and D-07.  PLAN-AUTH-001 tasks T-048 and T-049.
To retarget:    Pass it per run:  sqlcmd -d <database> -v DbName=<database>.  There is no in-file default.

WHAT THIS TABLE IS
------------------
Section 8.6.  The flattening of profile -> grants -> roles -> permissions, with expired, deleted and inactive rows
already removed.  Three columns and nothing else: this profile holds this permission at this scope tenant.

Every authorization decision in the database reads it and nothing else.  auth.udfHasPermission is two seeks against it;
auth.udfTenantReadPredicate -- which runs once per ROW of every query against every tenant-scoped table -- is one seek
against it joined to auth.TenantClosure.  That is the entire reason it exists.  Resolving four tables and a recursive
closure per row was measured and is not a trade anyone would take.  D-07.

IT IS NOT EXPANDED OVER THE TENANT SUBTREE, AND THAT IS THE DESIGN
-----------------------------------------------------------------
D-07.  A grant at the agency reaches every program under it, so the "obvious" materialization would store one row per
descendant tenant -- turning one grant into hundreds of rows, and turning a re-parenting into a rewrite of the scope
table for every profile whose reach changed.  Instead the subtree expansion stays where it belongs: as a join to
auth.TenantClosure at read time, which is one seek on an index that already exists.

The consequence is the rule that governs every reader of this table: a row here says "at this tenant AND BELOW", never
"at exactly this tenant".  Reading it without joining auth.TenantClosure answers a question nobody asked and denies
authority that was granted.

WHAT THE REBUILD FILTERS, AND WHAT IT DELIBERATELY DOES NOT
----------------------------------------------------------
Filtered out, because the row's own state says the authority is gone:

  *  a soft-deleted or expired grant (auth.UserProfileRole);
  *  a soft-deleted role, or a role whose mapping to the permission was soft-deleted;
  *  a soft-deleted permission;
  *  a soft-deleted or INACTIVE profile -- section 8.5: deactivating a profile removes one hat, and a hat that has been
     removed confers nothing.

NOT filtered, and each omission is deliberate:

  *  auth.Role.IsAssignable.  0 stops NEW grants; it does not revoke the ones already made.  Filtering here would make
     retiring a role silently strip authority from everyone holding it, which is what revocation is for.
  *  The USER's state -- inactive, locked out, deleted.  That is a SIGN-IN question, refused by
     auth.uspSetSessionContext with E-50024 before a single scope row is ever read, and it is transient: a lockout that
     required a materialization rebuild to take effect, and another to lift, would be a lockout that failed open for as
     long as the rebuild took.  Section 8.5 keeps the two ideas apart and so does this.
  *  TENANT usability.  Section 5.4 is explicit that deactivating a tenant must not write to any row beneath it --
     auth.udfIsTenantUsable walks the ancestor chain at read time instead, so reactivating restores everything.  If this
     rebuild filtered on usability, deactivating an administration would silently retire scope rows for every profile
     beneath it, and reactivating it would restore nothing until somebody remembered to rebuild.

THE SOURCE MUST BE DISTINCT
---------------------------
Two roles that both confer Data.Read at the same scope produce the same (profile, permission, scope) triple twice, and
"MERGE attempted to UPDATE or DELETE the same row more than once" is the error.  This is not a hypothetical: section
16.2's baseline roles put Data.Read in eight of the sixteen roles on purpose, because D-04 gives permissions no
implication and a contributor who cannot read is useless.  So the source is SELECT DISTINCT, and the loss is real and
accepted: this table cannot say WHICH role supplied a permission.  auth.vwProfilePermission answers that by resolving the
same joins without the DISTINCT, which is exactly the "why does this person have this" question, asked rarely, on one
profile at a time.

WHY A DERIVED TABLE CARRIES THE SEVEN AUDIT COLUMNS
---------------------------------------------------
The same argument auth.TenantClosure settled in Phase 1.  The columns cost seven writes per row on a table rebuilt by
procedure, and they buy the one thing a derived table cannot otherwise have: evidence of WHEN a permission appeared or
disappeared and WHICH actor's action caused it.  "This profile could read Baltimore's records in March and cannot now"
is answerable from auditDeletedDateUtc without a temporal table.  Non-negotiable 3 forbids the hard delete that would be
the alternative anyway.

THE REBUILD IS MAINTENANCE, NOT A REQUEST
-----------------------------------------
auth.uspRebuildProfilePermissionScope takes no session token and demands no permission -- exactly like
auth.uspRebuildTenantClosure, and for the same reason: every caller that IS a request has already authorized itself.
Platform.RebuildSecurityCache is not checked here; it gates the administrative procedure in Phase 6 that lets an operator
trigger a full rebuild from a screen, which is a request.
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

IF OBJECT_ID (N'auth.UserProfileRole', N'U') IS NULL OR OBJECT_ID (N'auth.RolePermission', N'U') IS NULL
BEGIN
    DECLARE @MsgParents NVARCHAR (2000) =
        N'auth.UserProfileRole or auth.RolePermission is missing. Run database/055_auth_role.sql and '
      + N'database/060_auth_profile_role.sql first. Nothing has been changed.';

    THROW 50000, @MsgParents, 1;
END
GO


-- *** 1. auth.ProfilePermissionScope ***
IF OBJECT_ID (N'auth.ProfilePermissionScope', N'U') IS NULL
BEGIN
    CREATE TABLE auth.ProfilePermissionScope
    (
        UserProfileId        INT                            NOT NULL
      , PermissionId         INT                            NOT NULL

        -- "At this tenant AND BELOW", never "at exactly this tenant".  The subtree expansion is a join to
        -- auth.TenantClosure at read time -- D-07 and the file header.
      , ScopeTenantId        INT                            NOT NULL

      , IsDeleted            BIT                            NOT NULL
            CONSTRAINT DF_auth_ProfilePermissionScope_IsDeleted DEFAULT (0)
      , auditDeletedBy       NVARCHAR (255)                     NULL
      , auditDeletedDateUtc  DATETIME2 (3)                      NULL
      , auditCreatedBy       NVARCHAR (255)                 NOT NULL
            CONSTRAINT DF_auth_ProfilePermissionScope_auditCreatedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditCreatedDateUtc  DATETIME2 (3)                  NOT NULL
            CONSTRAINT DF_auth_ProfilePermissionScope_auditCreatedDateUtc DEFAULT (SYSUTCDATETIME ())
      , auditModifiedBy      NVARCHAR (255)                 NOT NULL
            CONSTRAINT DF_auth_ProfilePermissionScope_auditModifiedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditModifiedDateUtc DATETIME2 (3)                  NOT NULL
            CONSTRAINT DF_auth_ProfilePermissionScope_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ())

        -- THE TRIPLE IS THE KEY -- section 15.4, and no surrogate.  Unlike auth.RolePermission this table is rebuilt by
        -- MERGE rather than inserted into, so a retired row is RESURRECTED in place when the authority comes back
        -- instead of being inserted a second time.  That is what makes a natural primary key correct here and wrong
        -- there, and it is also what preserves auditCreatedDateUtc across a revoke-and-regrant.
      , CONSTRAINT PK_auth_ProfilePermissionScope
            PRIMARY KEY CLUSTERED (UserProfileId, PermissionId, ScopeTenantId)

      , CONSTRAINT FK_auth_ProfilePermissionScope_UserProfile
            FOREIGN KEY (UserProfileId) REFERENCES auth.UserProfile (UserProfileId)
      , CONSTRAINT FK_auth_ProfilePermissionScope_Permission
            FOREIGN KEY (PermissionId)  REFERENCES auth.Permission (PermissionId)
      , CONSTRAINT FK_auth_ProfilePermissionScope_ScopeTenant
            FOREIGN KEY (ScopeTenantId) REFERENCES auth.Tenant (TenantId)

      , CONSTRAINT CK_auth_ProfilePermissionScope_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS     NULL AND auditDeletedDateUtc IS     NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL))
    );
END
GO

-- THE INDEX EVERY PERMISSION DECISION IN THE DATABASE SEEKS.  Section 15.4 asks for a covering index leading
-- (UserProfileId, PermissionId), and the reason it is not simply the clustered primary key is width: the clustered index
-- carries the seven audit columns, and auth.udfTenantReadPredicate runs once per ROW of every query against every
-- tenant-scoped table.  This one holds three integers and nothing else.
--
-- Filtered on IsDeleted = 0, which is what makes the predicates able to use it -- and therefore why every reader of this
-- table MUST carry  IsDeleted = 0  in its own WHERE clause.  A predicate that omits the filter cannot seek this index
-- and, far worse, counts retired rows as live authority.  BL-039.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_auth_ProfilePermissionScope_Lookup'
                  AND object_id = OBJECT_ID (N'auth.ProfilePermissionScope'))
BEGIN
    CREATE INDEX IX_auth_ProfilePermissionScope_Lookup
        ON auth.ProfilePermissionScope (UserProfileId, PermissionId, ScopeTenantId)
     WHERE IsDeleted = 0;
END
GO

-- The reverse question: "who holds authority at this tenant?"  Not on any decision path -- it serves the administrative
-- screens and the re-parenting impact report, which are the two places somebody asks about a tenant rather than about a
-- profile.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_auth_ProfilePermissionScope_Scope'
                  AND object_id = OBJECT_ID (N'auth.ProfilePermissionScope'))
BEGIN
    CREATE INDEX IX_auth_ProfilePermissionScope_Scope
        ON auth.ProfilePermissionScope (ScopeTenantId, PermissionId)
     INCLUDE (UserProfileId)
     WHERE IsDeleted = 0;
END
GO


-- *** 2. Audit trigger ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.trg_au_updt_ProfilePermissionScope
Author:       rsincero
CreateDate:   2026-09-20
Description:
AFTER UPDATE audit stamp for auth.ProfilePermissionScope, and the guard that makes the three key columns immutable --
E-50010.

The same argument as auth.trg_au_updt_TenantClosure.  This trigger joins inserted to deleted on the natural key, and
unlike an IDENTITY column nothing in the engine would stop a statement from changing one of those columns and making the
trigger stamp the wrong row.  auth.uspRebuildProfilePermissionScope matches on the triple and writes only the soft-delete
and audit columns, so the guard costs nothing on the intended path and catches the one thing that would corrupt the trail
silently.

Modification History:
2026-09-20  rsincero  Created.  PLAN-AUTH-001 T-048.
***********************************************************************************************************************/
CREATE OR ALTER TRIGGER auth.trg_au_updt_ProfilePermissionScope
    ON auth.ProfilePermissionScope
    AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    IF UPDATE (UserProfileId) OR UPDATE (PermissionId) OR UPDATE (ScopeTenantId)
    BEGIN
        ;THROW 50010, N'auth.ProfilePermissionScope.UserProfileId, PermissionId and ScopeTenantId are immutable: they are the key this trigger joins on, so a statement that changed one would make the audit stamp land on the wrong row. The table is maintained by auth.uspRebuildProfilePermissionScope, which matches on the triple and writes only the soft-delete and audit columns.', 1;
    END;

    DECLARE @Now   DATETIME2 (3)  = SYSUTCDATETIME ()
          , @Actor NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                            , ORIGINAL_LOGIN ());

    UPDATE pps
       SET pps.auditModifiedDateUtc = @Now
         , pps.auditModifiedBy      = CASE WHEN UPDATE (auditModifiedBy)
                                           THEN COALESCE (NULLIF (i.auditModifiedBy, N''), @Actor)
                                           ELSE @Actor END
      FROM auth.ProfilePermissionScope AS pps
      JOIN inserted                    AS i ON i.UserProfileId = pps.UserProfileId
                                           AND i.PermissionId  = pps.PermissionId
                                           AND i.ScopeTenantId = pps.ScopeTenantId;
END;
GO


-- *** 3. auth.uspRebuildProfilePermissionScope ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspRebuildProfilePermissionScope
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Rebuilds auth.ProfilePermissionScope from the live grants, in one transaction.  With @UserProfileId it rebuilds that one
profile; with NULL -- the default -- it rebuilds every profile in the database.  Idempotent: a second call against
unchanged authority affects no rows.  Sections 8.6 and 9.2, D-07.

Called by every procedure that changes authority: auth.uspAssignRoleToProfile, auth.uspRevokeRoleFromProfile,
auth.uspSetRolePermissions, auth.uspCreateProfile, auth.uspDeactivateProfile, and the Phase 3 and Phase 4 test fixtures
after they write grants directly.  Takes no session token and demands no permission -- it is maintenance of a derived
table, and every caller that IS a request has already authorized itself.

========================================================================================================================
Requirements and Key Dependencies:

auth.UserProfile, auth.UserProfileRole, auth.Role, auth.RolePermission, auth.Permission, auth.ProfilePermissionScope.

logs.uspStartExecutionLogging and logs.uspRecordExecutionError for the rule 8 instrumentation block, plus
logs.ExecutionLog itself, which the completion UPDATE writes directly.

========================================================================================================================
Notes:

@UserProfileId = NULL MEANS EVERY PROFILE, and that is the parameterless full rebuild 900_bootstrap_first_admin.sql,
115_seed_reference_data.sql and the deployment verification use.  The per-profile form is what the grant procedures call,
because a grant changes one profile's authority and rebuilding thirty thousand profiles to record it would make every
role assignment a maintenance window.

ONE EXCEPTION IS WORTH KNOWING: auth.uspSetRolePermissions changes what a ROLE means, which changes authority for every
profile holding it.  It loops the profiles from IX_auth_UserProfileRole_Role and calls this procedure once each rather
than calling it with NULL -- fewer rows touched whenever the role is held by less than the whole deployment, and the
work is attributable per profile in logs.ExecutionLog.

THE SOURCE IS  SELECT DISTINCT  AND MUST STAY THAT WAY.  Eight of the sixteen baseline roles include Data.Read, so two
roles conferring the same permission at the same scope is the normal case, not an edge case -- and the duplicate would
raise "MERGE attempted to UPDATE or DELETE the same row more than once", which is a run-time failure on an ordinary
grant.  The header explains what the DISTINCT costs: this table cannot say which role supplied a permission.
auth.vwProfilePermission answers that separately.

THE "NOT MATCHED BY SOURCE" BRANCH IS RESTRICTED TO THE PROFILE, NOT THE ON CLAUSE.  Putting @UserProfileId in the ON
clause would make every OTHER profile's rows unmatched-by-source and retire the authority of the entire deployment on
the next single-profile rebuild.  The predicate belongs in the WHEN clause, where it only decides what to retire.  The
cost is that MERGE evaluates the branch against the whole target; for the per-profile call that is a scan of a
three-integer clustered index, and it is the right trade against the alternative failure.

IT SETS auditDeletedBy AND auditDeletedDateUtc ITSELF rather than leaving them to the trigger, for the reason
auth.uspRebuildTenantClosure gives: CHECK constraints are evaluated BEFORE AFTER triggers, so
CK_auth_ProfilePermissionScope_DeletedPair would reject the soft delete before the trigger could fill the columns in.
The resurrection branch clears the pair the same way, for the same reason.

WHAT IT DOES NOT FILTER ON is as important as what it does -- IsAssignable, the user's state, and tenant usability are
all deliberately absent.  The file header gives the argument for each; changing any of them here would move a decision
out of the layer that owns it.

RESURRECTION PRESERVES auditCreatedDateUtc, which is why the MATCHED branch updates in place instead of inserting a new
row.  "This profile has been able to read Baltimore since February, apart from a fortnight in March" is then still
answerable; an insert-and-soft-delete pattern would leave two rows and no way to tell a re-grant from a first grant.

========================================================================================================================
Example Usage and Performance:

exec auth.uspRebuildProfilePermissionScope;                        -- every profile
exec auth.uspRebuildProfilePermissionScope @UserProfileId = 412;   -- one profile, after a grant

Per-profile: one seek on UX_auth_UserProfileRole_Grant, one seek per role on UX_auth_RolePermission_Pair, and one MERGE.
Full rebuild over the Phase 3 fixtures -- 7 profiles, 14 roles, 35 permissions -- writes under 200 rows.  Instrumentation
adds one singleton insert per call and one singleton update on the successful path.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-049
Description:
Created.  Phase 3.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspRebuildProfilePermissionScope
    @UserProfileId INT = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspRebuildProfilePermissionScope]')
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

    -- The procedure's own working values.  @Now is hoisted so the soft-delete stamp and the modification stamp on one row
    -- are the SAME instant, and so the expiry test is evaluated once rather than per row -- two SYSUTCDATETIME () calls a
    -- millisecond apart could include a grant in the source and exclude it from a later count in the same run.
    DECLARE @Now     DATETIME2 (3)  = SYSUTCDATETIME ()
          , @Actor   NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                              , ORIGINAL_LOGIN ())
          , @Written INT            = 0
          , @Live    INT            = 0;

    SET @KeyParameters = CONCAT (N'UserProfileId=', COALESCE (CAST (@UserProfileId AS NVARCHAR (11)), N'NULL (all)')
                               , N', LiveGrants=', (SELECT COUNT (*)
                                                      FROM auth.UserProfileRole
                                                     WHERE IsDeleted = 0
                                                       AND (@UserProfileId IS NULL OR UserProfileId = @UserProfileId)));

    SET @ContextMessage = N'Rebuild of auth.ProfilePermissionScope. Retired rows are soft-deleted, not removed, and are '
                        + N'resurrected in place if the authority returns.';

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

        MERGE auth.ProfilePermissionScope AS tgt
        USING (
                -- DISTINCT is load-bearing; see the header. Two roles conferring Data.Read at the same scope is the
                -- normal case, and the duplicate would fail the MERGE at run time on an ordinary grant.
                SELECT DISTINCT
                       upr.UserProfileId
                     , rp.PermissionId
                     , upr.ScopeTenantId
                  FROM auth.UserProfileRole AS upr
                  JOIN auth.UserProfile     AS up ON up.UserProfileId = upr.UserProfileId
                  JOIN auth.Role            AS r  ON r.RoleId         = upr.RoleId
                  JOIN auth.RolePermission  AS rp ON rp.RoleId        = r.RoleId
                  JOIN auth.Permission      AS p  ON p.PermissionId   = rp.PermissionId
                 WHERE (@UserProfileId IS NULL OR upr.UserProfileId = @UserProfileId)

                   -- The grant itself: live and not expired. Nothing expires a row; time does, here.
                   AND upr.IsDeleted = 0
                   AND (upr.ExpiresUtc IS NULL OR upr.ExpiresUtc > @Now)

                   -- The hat still exists and is still worn. Section 8.5.
                   AND up.IsDeleted = 0
                   AND up.IsActive  = 1

                   -- The role, its mapping, and the permission. r.IsAssignable is DELIBERATELY not tested: it stops new
                   -- grants, it does not revoke existing ones.
                   AND r.IsDeleted  = 0
                   AND rp.IsDeleted = 0
                   AND p.IsDeleted  = 0
              ) AS src
           ON tgt.UserProfileId = src.UserProfileId
          AND tgt.PermissionId  = src.PermissionId
          AND tgt.ScopeTenantId = src.ScopeTenantId

        -- The authority came back. Resurrected IN PLACE, which preserves auditCreatedDateUtc and therefore the
        -- difference between a re-grant and a first grant. The auditDeleted* pair is cleared explicitly because
        -- CK_auth_ProfilePermissionScope_DeletedPair is checked before the trigger runs.
        WHEN MATCHED AND tgt.IsDeleted = 1
            THEN UPDATE SET tgt.IsDeleted            = 0
                          , tgt.auditDeletedBy       = NULL
                          , tgt.auditDeletedDateUtc  = NULL
                          , tgt.auditModifiedBy      = @Actor
                          , tgt.auditModifiedDateUtc = @Now

        WHEN NOT MATCHED BY TARGET
            THEN INSERT (UserProfileId, PermissionId, ScopeTenantId, auditCreatedBy)
                 VALUES (src.UserProfileId, src.PermissionId, src.ScopeTenantId, @Actor)

        -- "Rebuilt whole" without a DELETE. The profile restriction lives HERE and not in the ON clause -- see the
        -- header; in the ON clause it would retire every other profile's authority on the next single-profile rebuild.
        WHEN NOT MATCHED BY SOURCE
             AND tgt.IsDeleted = 0
             AND (@UserProfileId IS NULL OR tgt.UserProfileId = @UserProfileId)
            THEN UPDATE SET tgt.IsDeleted            = 1
                          , tgt.auditDeletedBy       = @Actor
                          , tgt.auditDeletedDateUtc  = @Now
                          , tgt.auditModifiedBy      = @Actor
                          , tgt.auditModifiedDateUtc = @Now;

        -- @@ROWCOUNT is reset by the next statement, so read it immediately.
        SET @Written = @@ROWCOUNT;

        SET @Live = (SELECT COUNT (*)
                       FROM auth.ProfilePermissionScope
                      WHERE IsDeleted = 0
                        AND (@UserProfileId IS NULL OR UserProfileId = @UserProfileId));

        SET @Comments = CONCAT (@Written, N' scope row(s) inserted, resurrected or retired. ', @Live
                              , N' live row(s) now in scope for '
                              , COALESCE (N'profile ' + CAST (@UserProfileId AS NVARCHAR (11)), N'all profiles')
                              , N'. A row means "this tenant and below" -- the subtree expansion is a read-time join to '
                              , N'auth.TenantClosure, D-07.');

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

    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    VALUES
      (N'auth', N'TABLE', N'ProfilePermissionScope', NULL
     , N'DERIVED. The flattening of profile -> grants -> roles -> permissions, with expired, deleted and inactive rows '
     + N'already removed -- section 8.6, D-07. Every authorization decision in the database reads this table and '
     + N'nothing else: auth.udfHasPermission is two seeks against it, and auth.udfTenantReadPredicate joins it to '
     + N'auth.TenantClosure once per ROW of every query against every tenant-scoped table. Written only by '
     + N'auth.uspRebuildProfilePermissionScope. NOT expanded over the tenant subtree, so a row means "at this tenant '
     + N'AND BELOW" and every reader must join auth.TenantClosure.')
    , (N'auth', N'TABLE', N'ProfilePermissionScope', N'UserProfileId'
     , N'The profile. IMMUTABLE (E-50010) -- it is part of the key this table''s trigger joins on.')
    , (N'auth', N'TABLE', N'ProfilePermissionScope', N'PermissionId'
     , N'The permission. Resolved to a LITERAL at deploy time by 120_rls_policy.sql rather than joined to '
     + N'auth.Permission, because a join inside a per-row predicate is a third seek for a value that never changes. '
     + N'IMMUTABLE (E-50010).')
    , (N'auth', N'TABLE', N'ProfilePermissionScope', N'ScopeTenantId'
     , N'The tenant the authority starts at. "At this tenant AND BELOW", never "at exactly this tenant": the subtree '
     + N'expansion is a read-time join to auth.TenantClosure, which is D-07''s whole point -- materializing it would '
     + N'turn one grant into hundreds of rows and a re-parenting into a rewrite. Reading this column without that join '
     + N'denies authority that was granted. IMMUTABLE (E-50010).')

    , (N'auth', N'PROCEDURE', N'uspRebuildProfilePermissionScope', NULL
     , N'Rebuilds auth.ProfilePermissionScope from the live grants in one transaction -- one profile with '
     + N'@UserProfileId, every profile with NULL. Idempotent. Takes no session token and demands no permission: it is '
     + N'maintenance of a derived table, and every caller that IS a request has already authorized itself '
     + N'(Platform.RebuildSecurityCache gates the Phase 6 procedure an operator triggers from a screen, not this one). '
     + N'Retires by soft delete and resurrects in place, so auditCreatedDateUtc still distinguishes a re-grant from a '
     + N'first grant. Deliberately does NOT filter on auth.Role.IsAssignable, on the user''s state, or on tenant '
     + N'usability -- the script header gives the argument for each.');

    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    SELECT N'auth', N'TABLE', N'ProfilePermissionScope', c.ColumnName, c.Description
      FROM (VALUES
          (N'IsDeleted',            N'Soft-delete flag, set by the rebuild when the authority behind the row is gone. The row stays as evidence of when a permission disappeared -- the reason a derived table carries audit columns at all.')
        , (N'auditDeletedBy',       N'Who ran the rebuild that retired the row. NULL unless IsDeleted = 1. Set by the procedure rather than the trigger, because CHECK constraints are evaluated before AFTER triggers.')
        , (N'auditDeletedDateUtc',  N'When the row was retired, UTC. NULL unless IsDeleted = 1. "This profile could read Baltimore in March and cannot now" is answered from this column.')
        , (N'auditCreatedBy',       N'Who ran the rebuild that first created the row.')
        , (N'auditCreatedDateUtc',  N'When the authority first appeared, UTC. PRESERVED across a revoke-and-regrant, because the rebuild resurrects in place instead of inserting a second row.')
        , (N'auditModifiedBy',      N'Who ran the rebuild that last touched the row.')
        , (N'auditModifiedDateUtc', N'When the row was last touched by a rebuild, UTC.')
       ) AS c (ColumnName, Description);

    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    VALUES (N'auth', N'TRIGGER', N'trg_au_updt_ProfilePermissionScope', NULL
          , N'AFTER UPDATE audit stamp for auth.ProfilePermissionScope, and the guard that makes the three key columns '
          + N'immutable -- E-50010. They are the key the trigger joins on, so a statement that changed one would stamp '
          + N'the wrong row.');

    DECLARE @RowNo    INT = 1
          , @MaxRowNo INT = (SELECT MAX (RowNo) FROM @Descriptions)
          , @dSchema  SYSNAME
          , @dType    SYSNAME
          , @dObject  SYSNAME
          , @dColumn  SYSNAME
          , @dText    NVARCHAR (3750);

    WHILE @RowNo <= @MaxRowNo
    BEGIN
        SELECT @dSchema = SchemaName
             , @dType   = ObjectType
             , @dObject = ObjectName
             , @dColumn = ColumnName
             , @dText   = Description
          FROM @Descriptions
         WHERE RowNo = @RowNo;

        EXEC util.uspSetObjectDescription
              @SchemaName  = @dSchema
            , @ObjectType  = @dType
            , @ObjectName  = @dObject
            , @Description = @dText
            , @ColumnName  = @dColumn;

        SET @RowNo = @RowNo + 1;
    END;
END
ELSE
BEGIN
    PRINT N'util.uspSetObjectDescription is absent. Descriptions were NOT applied. Run '
        + N'.claude/skills/ponytail-sql-objects/templates/extended-properties.sql and then re-run this script.';
END
GO


-- *** 5. Grants ***
--
-- DELIBERATELY EMPTY.  INV-11 and 170_permissions.sql.  Note what a SELECT grant here would cost beyond the usual
-- argument: the RLS predicates read this table through OWNERSHIP CHAINING, which is what lets them see rows the caller
-- cannot.  Granting the application direct SELECT would not help those predicates and would hand a client the resolved
-- authority map of the whole deployment.
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
SELECT CASE WHEN OBJECT_ID (N'auth.ProfilePermissionScope', N'U') IS NULL THEN 1 ELSE 4 END
     , CASE WHEN OBJECT_ID (N'auth.ProfilePermissionScope', N'U') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Table auth.ProfilePermissionScope'
     , N'The materialized effective grant. PK on all three columns -- section 15.4, D-07.';

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN i.name IS NULL THEN 1 WHEN i.is_disabled = 1 THEN 1 ELSE 4 END
     , CASE WHEN i.name IS NULL THEN 'MISSING' WHEN i.is_disabled = 1 THEN 'DISABLED' ELSE 'OK' END
     , N'Index ' + x.IndexName
     , x.Purpose
  FROM (VALUES (N'IX_auth_ProfilePermissionScope_Lookup', N'THE index every permission decision seeks -- three integers, filtered on IsDeleted = 0. auth.udfTenantReadPredicate uses it once per row of every query against every tenant-scoped table. Missing or disabled is a performance emergency, not a warning.')
             , (N'IX_auth_ProfilePermissionScope_Scope',  N'"Who holds authority at this tenant?" -- the administrative screens and the re-parenting impact report. Not on any decision path.'))
       AS x (IndexName, Purpose)
  LEFT JOIN sys.indexes AS i ON i.name = x.IndexName AND i.object_id = OBJECT_ID (N'auth.ProfilePermissionScope');

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (N'auth.uspRebuildProfilePermissionScope', N'P') IS NULL THEN 1 ELSE 4 END
     , CASE WHEN OBJECT_ID (N'auth.uspRebuildProfilePermissionScope', N'P') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Procedure auth.uspRebuildProfilePermissionScope'
     , N'The only writer of the table. @UserProfileId = NULL rebuilds every profile. Retires by soft delete and '
     + N'resurrects in place, so auditCreatedDateUtc distinguishes a re-grant from a first grant.';

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN tr.object_id IS NULL THEN 1 WHEN tr.is_disabled = 1 THEN 1 ELSE 4 END
     , CASE WHEN tr.object_id IS NULL THEN 'MISSING' WHEN tr.is_disabled = 1 THEN 'DISABLED' ELSE 'OK' END
     , N'Trigger auth.trg_au_updt_ProfilePermissionScope'
     , N'Audit stamp, and E-50010 on the three key columns.'
  FROM (SELECT 1 AS one) AS o
  LEFT JOIN sys.triggers AS tr ON tr.object_id = OBJECT_ID (N'auth.trg_au_updt_ProfilePermissionScope');

-- The one check that matters on a rebuilt table: does it agree with its own source?  Recomputes the source and compares
-- both ways.  A difference means something changed authority without rebuilding -- the exact failure D-07 trades
-- correctness-by-construction away for, and therefore the thing this report exists to catch.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Missing = 0 AND x.Extra = 0 THEN 4 ELSE 1 END
     , CASE WHEN x.Missing = 0 AND x.Extra = 0 THEN 'OK' ELSE 'STALE' END
     , N'The materialized scope agrees with the live grants'
     , CASE WHEN x.Missing = 0 AND x.Extra = 0
            THEN N'Yes. ' + CAST (x.LiveRows AS NVARCHAR (11)) + N' live row(s), '
               + CAST (x.RetiredRows AS NVARCHAR (11)) + N' retained after retirement.'
            ELSE CAST (x.Missing AS NVARCHAR (11)) + N' triple(s) implied by the live grants are absent or retired, and '
               + CAST (x.Extra AS NVARCHAR (11)) + N' live row(s) are no longer implied. Something changed authority '
               + N'without calling auth.uspRebuildProfilePermissionScope -- the missing rows are authority a person '
               + N'should have and does not, the extra rows are authority nobody granted. Run the procedure with no '
               + N'parameters.'
       END
  FROM (SELECT LiveRows    = (SELECT COUNT (*) FROM auth.ProfilePermissionScope WHERE IsDeleted = 0)
             , RetiredRows = (SELECT COUNT (*) FROM auth.ProfilePermissionScope WHERE IsDeleted = 1)
             , Missing     = (SELECT COUNT (*) FROM
                                 (SELECT DISTINCT upr.UserProfileId, rp.PermissionId, upr.ScopeTenantId
                                    FROM auth.UserProfileRole AS upr
                                    JOIN auth.UserProfile     AS up ON up.UserProfileId = upr.UserProfileId
                                    JOIN auth.Role            AS r  ON r.RoleId         = upr.RoleId
                                    JOIN auth.RolePermission  AS rp ON rp.RoleId        = r.RoleId
                                    JOIN auth.Permission      AS p  ON p.PermissionId   = rp.PermissionId
                                   WHERE upr.IsDeleted = 0
                                     AND (upr.ExpiresUtc IS NULL OR upr.ExpiresUtc > SYSUTCDATETIME ())
                                     AND up.IsDeleted = 0 AND up.IsActive = 1
                                     AND r.IsDeleted  = 0 AND rp.IsDeleted = 0 AND p.IsDeleted = 0
                                  EXCEPT
                                  SELECT UserProfileId, PermissionId, ScopeTenantId
                                    FROM auth.ProfilePermissionScope WHERE IsDeleted = 0) AS d)
             , Extra       = (SELECT COUNT (*) FROM
                                 (SELECT UserProfileId, PermissionId, ScopeTenantId
                                    FROM auth.ProfilePermissionScope WHERE IsDeleted = 0
                                  EXCEPT
                                  SELECT DISTINCT upr.UserProfileId, rp.PermissionId, upr.ScopeTenantId
                                    FROM auth.UserProfileRole AS upr
                                    JOIN auth.UserProfile     AS up ON up.UserProfileId = upr.UserProfileId
                                    JOIN auth.Role            AS r  ON r.RoleId         = upr.RoleId
                                    JOIN auth.RolePermission  AS rp ON rp.RoleId        = r.RoleId
                                    JOIN auth.Permission      AS p  ON p.PermissionId   = rp.PermissionId
                                   WHERE upr.IsDeleted = 0
                                     AND (upr.ExpiresUtc IS NULL OR upr.ExpiresUtc > SYSUTCDATETIME ())
                                     AND up.IsDeleted = 0 AND up.IsActive = 1
                                     AND r.IsDeleted  = 0 AND rp.IsDeleted = 0 AND p.IsDeleted = 0) AS d)) AS x;

INSERT @Report (Severity, Status, Item, Detail)
VALUES (3, 'NEXT', N'Next scripts'
      , N'100_auth_functions.sql gains auth.udfHasPermission and auth.tvfPermissionScope, which are the only intended '
      + N'readers of this table, and then the three RLS predicates of Phase 4. 120_rls_policy.sql resolves Data.Read to '
      + N'a literal PermissionId, which is why 115_seed_reference_data.sql has to run before it.');

IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
    PRINT N'Effective permission scope: PROBLEMS found. Read the report below before running the next script.';
ELSE
    PRINT N'Effective permission scope: no problems found.';

PRINT N'';

SELECT Severity, Status, Item, Detail
  FROM @Report
 ORDER BY Severity, RowNo;
GO
