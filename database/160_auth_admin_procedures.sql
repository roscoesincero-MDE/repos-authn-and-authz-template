/***********************************************************************************************************************
Script:         160_auth_admin_procedures.sql
Purpose:        The platform-administration surface: auth.uspGrantPlatformAdmin, auth.uspRevokePlatformAdmin,
                auth.uspRebuildEffectivePermissions and auth.uspRebuildSecurityCache.
Target:         SQL Server 2022.
Run as:         db_owner in the target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/160_auth_admin_procedures.sql
Idempotent:     Yes.  CREATE OR ALTER throughout, and every grant guarded on DATABASE_PRINCIPAL_ID.
Depends on:     040_auth_userprofile.sql (auth.[User]), 030_auth_tenant.sql (auth.TenantClosure),
                100_auth_functions.sql (auth.uspRebuildProfilePermissionScope, auth.uspRebuildTenantClosure),
                105_auth_session_procedures.sql (auth.uspSetSessionContext),
                150_auth_query_procedures.sql (auth.uspDemandPermission), 165_logs_procedures.sql
                (logs.uspRecordAuthorizationChange), scripts/logExecutionLogging.sql, templates/extended-properties.sql.
Implements:     T-091.  DES-AUTH-001 sections 5.3, 8.6, 16.3, D-05, INV-09.  Appendix B E-50081 to E-50084.
                See docs/10-database-authn-authz-design.md.
To retarget:    Pass it per run:  sqlcmd -d <database> -v DbName=<database>.  There is no in-file default.

THE FOUR PROCEDURES HERE ARE THE ONLY ONES IN THE DATABASE WHOSE SUBJECT IS THE DATABASE ITSELF
----------------------------------------------------------------------------------------------
Everywhere else a procedure acts on a tenant's data, a tenant's users or a tenant's grants, and the permission it demands
is scoped to a tenant.  These four act on the deployment: who may use the administrator sign-in route at all, and the two
pieces of derived state the whole authorization model reads (auth.TenantClosure and auth.ProfilePermissionScope).  None of
their permissions is tenant-scoped, which is why none of them passes @TenantId to auth.uspDemandPermission.

WHY THE PLATFORM-ADMIN FLAG IS A PAIR OF PROCEDURES AND NOT A COLUMN ON auth.uspUpdateUser
-----------------------------------------------------------------------------------------
D-05 makes platform administration an AUTHENTICATION capability, not a role: it decides which sign-in routes exist for an
account, and a platform administrator with no profile can sign in and do nothing at all.  INV-09 then requires the flag
ON TOP OF the PLATFORM_ADMIN role before any Platform permission takes effect, so the flag is the harder half of a pair.

130_auth_user_procedures.sql therefore refuses @IsPlatformAdmin = 1 outright (E-50155) and auth.uspUpdateUser has no such
parameter.  The consequence -- and the point -- is that every conferral of the capability in the database's whole history
is one logs.AuthorizationChange row with ChangeType 'PlatformAdminGranted' or 'PlatformAdminRevoked', written here.  A
reviewer asking "who can use the bypass route, and who let them" reads one query.  Folding the bit into User.Create would
have meant anybody who may create a person may create an administrator.

THE ACTOR MUST ALREADY HOLD THE FLAG, AND THAT TEST COMES BEFORE THE PERMISSION TEST -- E-50084
----------------------------------------------------------------------------------------------
Appendix B is explicit that holding Platform.ManageApplications is NOT sufficient.  Both procedures therefore read the
ACTING user's own auth.[User].IsPlatformAdmin and refuse with E-50084 before calling auth.uspDemandPermission.

The order is deliberate and it is not redundancy for its own sake.  auth.udfHasPermission already tests IsPlatformAdmin
for the Platform family (INV-09), so a caller without the flag would be refused by the demand as well -- with E-50030,
"you do not hold Platform.ManageApplications", which is the wrong sentence.  They may well hold it.  What they do not
have is the flag, and E-50084 says so.  Checking first buys a true message; checking at all buys independence from
auth.udfHasPermission's internals, which is worth having for the one capability that can lock a deployment out of itself.

E-50084 IS RAISED BY THE REVOKE AS WELL, WHICH IS A DOCUMENTED WIDENING OF APPENDIX B
------------------------------------------------------------------------------------
Appendix B registers E-50084 against auth.uspGrantPlatformAdmin alone and E-50081 against both.  Taken literally that
would let a user who holds Platform.ManageApplications but not the flag strip the capability from everyone who does --
bounded only by E-50082, which stops at the last one.  One administrator is not a working deployment.

The fault class is identical (the actor lacks the capability they are trying to administer), the procedure pair is
identical, and Appendix B's own rationale sentence -- "the capability is an authentication capability, so only a platform
administrator may confer it" -- reads the same with "remove" in place of "confer".  So the number is reused rather than
invented, and the widening is recorded as a gap (G-35) for the design document rather than left as a silent deviation.
This is the same decision, on the same grounds, that E-50062 got in 155_auth_registration_procedures.sql.

THE LAST ADMINISTRATOR CANNOT BE REVOKED -- E-50082, AND IT IS COUNTED INSIDE THE TRANSACTION
--------------------------------------------------------------------------------------------
The count is of LIVE, ACTIVE users with IsPlatformAdmin = 1 other than the target, and it is taken after BEGIN
TRANSACTION so two concurrent revokes cannot both see two administrators and both pass.  Without it, INV-09 makes
Platform.BypassRowSecurity and the bypass sign-in route unreachable, 900_bootstrap_first_admin.sql refuses to run once a
profile exists (section 16.3 clause 1), and the only remedy left is a DBA with sysadmin and a hand-written UPDATE.

auth.uspDeactivateUser's E-50154 is the same guard on the other half of the pair -- deactivating the last administrator's
account achieves the identical lock-out -- and the two counts are written the same way on purpose.

REVOKING THE FLAG DOES NOT END THE TARGET'S SESSIONS, AND DOES NOT NEED TO
-------------------------------------------------------------------------
auth.udfHasPermission reads auth.[User].IsPlatformAdmin on every permission test rather than caching it in
SESSION_CONTEXT, precisely so that removing it takes effect on the target's very next statement (100_auth_functions.sql
says so where it makes the choice).  A revoked administrator's session survives as an ORDINARY session, which is correct:
their profile's tenant-scoped authority is untouched, and ending the session would log out a person who may be in the
middle of legitimate work under a role that was never in question.  Contrast auth.uspDeactivateUser, which ends sessions
because there the whole account is being stopped.

BOTH FLAG PROCEDURES ARE IDEMPOTENT AND A NO-OP WRITES NO TRAIL ROW
------------------------------------------------------------------
Granting to a user who already holds the flag succeeds, reports @FlagChanged = 0, and writes nothing to
logs.AuthorizationChange.  A trail whose rows include "nothing happened" cannot be counted, and the reviewer's question
is "how many times was this capability conferred", not "how many times did somebody press the button".  The execution log
still records the call, which is where "somebody pressed the button" belongs.

THE TWO REBUILDS ARE THE SAME MAINTAINERS EVERY TENANT AND GRANT PROCEDURE ALREADY CALLS
---------------------------------------------------------------------------------------
auth.uspRebuildProfilePermissionScope and auth.uspRebuildTenantClosure are internal: neither demands a permission,
neither takes a session token, and neither is granted to applicationRole -- they are called from inside procedures that
have already established authority.  Exposing them directly to the application would be a way to run the expensive half
of the authorization model with no credential at all.

auth.uspRebuildEffectivePermissions and auth.uspRebuildSecurityCache are the granted surface: they establish session
context, demand Platform.RebuildSecurityCache, instrument the call, and then delegate.  They contain no copy of the
flattening logic, because section 8.6's whole claim is that there is ONE definition of auth.ProfilePermissionScope and
950_verify_deployment.sql recomputes it independently to prove the definition is obeyed.  A second implementation here
would be a second definition, and the two would drift in exactly the way the table itself does.

WHY THE WHOLE-DATABASE REBUILD IS A LOOP, AND WHY IT IS NOT ONE TRANSACTION
--------------------------------------------------------------------------
@UserProfileId = NULL means every live profile, walked one at a time.  Set-based would be faster and would require
re-stating the flattening here; see above.  The loop is also deliberately NOT wrapped in an outer transaction: each
profile's rebuild is already atomic, the operation is idempotent, and a repair run over a few thousand profiles inside one
transaction would hold locks on the table every permission test in the database reads.  Interrupted half way, it has
simply rebuilt half the profiles correctly and can be run again.  That is the right trade for a repair tool.

A DEACTIVATED PROFILE IS NOT AN ERROR FOR THE REBUILD -- E-50083 IS ABOUT EXISTENCE ONLY
---------------------------------------------------------------------------------------
E-50083 fires when @UserProfileId is supplied and matches no row with IsDeleted = 0.  IsActive = 0 passes, because
rebuilding an inactive profile is how its scope rows get CLEARED (section 8.6: expired, deleted and inactive rows are
already removed by the rebuild).  Refusing it would make the one repair path unavailable to precisely the rows most
likely to need repairing.
***********************************************************************************************************************/

:on error exit

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

IF OBJECT_ID (N'auth.User', N'U') IS NULL OR OBJECT_ID (N'auth.UserProfile', N'U') IS NULL
BEGIN
    DECLARE @MsgId NVARCHAR (2000) =
        N'auth.User or auth.UserProfile is missing. Run database/040_auth_userprofile.sql first.';

    THROW 50000, @MsgId, 1;
END
GO

IF OBJECT_ID (N'auth.uspRebuildProfilePermissionScope', N'P') IS NULL
   OR OBJECT_ID (N'auth.uspRebuildTenantClosure', N'P') IS NULL
BEGIN
    DECLARE @MsgMaint NVARCHAR (2000) =
        N'auth.uspRebuildProfilePermissionScope or auth.uspRebuildTenantClosure is missing. Run '
      + N'database/100_auth_functions.sql first: the two rebuild procedures in this file are wrappers around them and '
      + N'deliberately contain no rebuild logic of their own.';

    THROW 50000, @MsgMaint, 1;
END
GO

IF OBJECT_ID (N'logs.uspStartExecutionLogging', N'P') IS NULL
   OR OBJECT_ID (N'logs.uspRecordExecutionError', N'P') IS NULL
BEGIN
    DECLARE @MsgLog NVARCHAR (2000) =
        N'The rule 8 instrumentation procedures are missing. Run scripts/logExecutionLogging.sql first: every '
      + N'procedure in this file opens a start row before its transaction and cannot be created usefully without them.';

    THROW 50000, @MsgLog, 1;
END
GO

-- Procedures resolve their callees at first execution, not at CREATE time, so these two are a warning rather than a
-- refusal: the file installs cleanly against a database where 150 and 165 have not run yet, and fails at run time.
IF OBJECT_ID (N'auth.uspSetSessionContext', N'P')      IS NULL
   OR OBJECT_ID (N'auth.uspDemandPermission', N'P')    IS NULL
   OR OBJECT_ID (N'logs.uspRecordAuthorizationChange', N'P') IS NULL
BEGIN
    PRINT N'WARNING: one or more of auth.uspSetSessionContext, auth.uspDemandPermission and '
        + N'logs.uspRecordAuthorizationChange is absent. The procedures in this file will be created -- name '
        + N'resolution is deferred -- but every call will fail until database/105, database/150 and database/165 have '
        + N'run.';
END
GO


-- *** 1. auth.uspGrantPlatformAdmin ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspGrantPlatformAdmin
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Sets auth.[User].IsPlatformAdmin = 1 on one account.  The ACTING user must already hold the flag (E-50084) and must hold
Platform.ManageApplications.  Idempotent: granting it to somebody who already has it succeeds, reports
@FlagChanged = 0, and writes no trail row.

========================================================================================================================
Requirements and Key Dependencies:

auth.[User], auth.uspSetSessionContext, auth.uspDemandPermission, logs.uspRecordAuthorizationChange.
Granted to applicationRole.  DES-AUTH-001 D-05, INV-09, section 16.3.

========================================================================================================================
Notes:

THE FLAG TEST COMES FIRST, THE PERMISSION TEST SECOND.  Both are required.  A caller with the permission and no flag gets
E-50084 -- "you are not a platform administrator" -- rather than E-50030's "you do not hold Platform.ManageApplications",
which would be false.  See the file header for the full argument.

BOTH REFUSALS HAPPEN BEFORE BEGIN TRANSACTION, which matters because auth.uspDemandPermission writes a
logs.AuthorizationDenial row before it raises.  Inside a transaction that row is rolled back with the rest of the
statement and the denial disappears from the trail (BL-042, G-31).  The conferral of this particular capability is the
last place in the database where a refusal should be invisible.

WHAT GOES IN THE TRAIL.  ChangeType 'PlatformAdminGranted', TargetUserId = @UserId, TargetUserProfileId = NULL (the
capability is not a profile's), ActorUserProfileId and ActorAuthorityTenantId from the session, and a DetailJson carrying
the reason text the administrator typed.  @Reason is free prose, so it is escaped with STRING_ESCAPE and it is NOT copied
into @KeyParameters: the execution log records its LENGTH and nothing else (UI-16).

========================================================================================================================
Example Usage and Performance:

declare @changed bit;
exec auth.uspGrantPlatformAdmin @SessionTokenHash = 0x9F86..., @UserId = 12
                              , @Reason = N'Second administrator for on-call cover, ticket OPS-4471.'
                              , @FlagChanged = @changed output;

Two seeks on auth.[User], one narrow update, one trail row.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-091
Description:
Created.  Phase 6.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspGrantPlatformAdmin
      @SessionTokenHash VARBINARY (32)
    , @UserId           INT
    , @Reason           NVARCHAR (500) = NULL
    , @FlagChanged      BIT            = NULL OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspGrantPlatformAdmin]')
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
          , @ActorUserId    INT             = NULL
          , @ActingTenantId INT             = NULL
          , @ActorIsAdmin   BIT             = NULL
          , @TargetIsAdmin  BIT             = NULL
          , @TargetName     NVARCHAR (256)  = NULL
          , @DetailJson     NVARCHAR (MAX)  = NULL
          , @ChangeId       BIGINT          = NULL
          , @Failure        NVARCHAR (2000) = NULL;

    SET @FlagChanged   = 0;
    SET @KeyParameters = CONCAT (N'UserId=', @UserId, N', ReasonLength='
                               , COALESCE (CAST (LEN (@Reason) AS NVARCHAR (11)), N'(null)'));

    BEGIN TRY

        -- Session, capability and authority are all settled before any transaction opens, so that the denial row
        -- auth.uspDemandPermission writes survives its own refusal. See the header.
        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        SET @ActorProfileId = TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT);
        SET @ActorUserId    = TRY_CAST (SESSION_CONTEXT (N'UserId')        AS INT);
        SET @ActingTenantId = TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT);
        SET @Actor          = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                      , ORIGINAL_LOGIN ());

        SELECT @ActorIsAdmin = u.IsPlatformAdmin
          FROM auth.[User] AS u
         WHERE u.UserId    = @ActorUserId
           AND u.IsDeleted = 0;

        IF COALESCE (@ActorIsAdmin, 0) = 0
        BEGIN
            SET @Failure = N'Platform administration is an authentication capability (D-05), not a permission, so only '
                         + N'a platform administrator may confer it -- holding Platform.ManageApplications is not '
                         + N'sufficient. The acting account''s own IsPlatformAdmin is 0. Nothing was changed.';
            ;THROW 50084, @Failure, 1;
        END;

        -- Not tenant-scoped: the Platform family ignores @TenantId, and INV-09 has already been satisfied above.
        EXEC auth.uspDemandPermission @PermissionCode = N'Platform.ManageApplications'
                                    , @ObjectName     = N'auth.uspGrantPlatformAdmin';

        SELECT @TargetIsAdmin = u.IsPlatformAdmin
             , @TargetName    = u.UserName
          FROM auth.[User] AS u
         WHERE u.UserId    = @UserId
           AND u.IsDeleted = 0;

        IF @TargetIsAdmin IS NULL
        BEGIN
            SET @Failure = N'No such user, or it has been deleted. Nothing was changed.';
            ;THROW 50081, @Failure, 1;
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

        IF @TargetIsAdmin = 0
        BEGIN
            UPDATE u
               SET u.IsPlatformAdmin = 1
                 , u.auditModifiedBy = @Actor
              FROM auth.[User] AS u
             WHERE u.UserId    = @UserId
               AND u.IsDeleted = 0;

            SET @FlagChanged = 1;

            SET @DetailJson = CONCAT (N'{"actorUserId":', COALESCE (CAST (@ActorUserId AS NVARCHAR (11)), N'null')
                                    , N',"reason":'
                                    , COALESCE (N'"' + STRING_ESCAPE (@Reason, 'json') + N'"', N'null')
                                    , N'}');

            EXEC logs.uspRecordAuthorizationChange
                  @ChangeType             = 'PlatformAdminGranted'
                , @TargetUserId           = @UserId
                , @TargetUserProfileId    = NULL
                , @RoleId                 = NULL
                , @ScopeTenantId          = NULL
                , @ActorUserProfileId     = @ActorProfileId
                , @ActorAuthorityTenantId = @ActingTenantId
                , @DetailJson             = @DetailJson
                , @AuthorizationChangeId  = @ChangeId OUTPUT;
        END;

        SET @Comments = CONCAT (N'UserId=', @UserId, N' FlagChanged=', @FlagChanged
                              , CASE WHEN @FlagChanged = 1
                                     THEN CONCAT (N'. AuthorizationChangeId=', @ChangeId, N'.')
                                     ELSE N'. Already a platform administrator, so no row was written to '
                                        + N'logs.AuthorizationChange: the trail counts conferrals, not button presses.'
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


-- *** 2. auth.uspRevokePlatformAdmin ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspRevokePlatformAdmin
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Sets auth.[User].IsPlatformAdmin = 0 on one account.  The ACTING user must already hold the flag (E-50084) and must hold
Platform.ManageApplications.  Refuses to remove the LAST live active platform administrator (E-50082).  Idempotent:
revoking from somebody who does not have it succeeds, reports @FlagChanged = 0, and writes no trail row.

========================================================================================================================
Requirements and Key Dependencies:

auth.[User], auth.uspSetSessionContext, auth.uspDemandPermission, logs.uspRecordAuthorizationChange.
Granted to applicationRole.  DES-AUTH-001 D-05, INV-09, section 16.3.

========================================================================================================================
Notes:

E-50082 IS THE NUMBER THAT STOPS A DEPLOYMENT LOCKING ITSELF OUT.  The count is of live, ACTIVE users with the flag other
than the target, taken INSIDE the transaction so two concurrent revokes cannot both pass it.  An inactive administrator
does not count, because they cannot sign in -- a database whose only flag holder is a deactivated account is already
locked out, and counting them would hide that.

REVOKING FROM YOURSELF IS PERMITTED as long as somebody else holds the flag.  It is the standard way an administrator
steps down, and refusing it would mean the only way to give up the capability is to ask somebody else to take it away.
E-50082 still applies: the last administrator cannot resign.

NO SESSION IS ENDED.  auth.udfHasPermission reads the flag live on every test, so the revoke takes effect on the target's
next statement, and the rest of their session -- their profile, their tenant-scoped roles -- was never in question.  See
the file header.

E-50084 ON THIS PROCEDURE IS A DOCUMENTED WIDENING of Appendix B, which registers the number against the grant alone.
G-35.  The file header has the argument.

========================================================================================================================
Example Usage and Performance:

declare @changed bit;
exec auth.uspRevokePlatformAdmin @SessionTokenHash = 0x9F86..., @UserId = 12
                               , @Reason = N'Left the on-call rota, ticket OPS-4488.'
                               , @FlagChanged = @changed output;

Two seeks on auth.[User], one seek on IX_auth_User_PlatformAdmin for the count, one narrow update, one trail row.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-091
Description:
Created.  Phase 6.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspRevokePlatformAdmin
      @SessionTokenHash VARBINARY (32)
    , @UserId           INT
    , @Reason           NVARCHAR (500) = NULL
    , @FlagChanged      BIT            = NULL OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspRevokePlatformAdmin]')
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
          , @ActorUserId    INT             = NULL
          , @ActingTenantId INT             = NULL
          , @ActorIsAdmin   BIT             = NULL
          , @TargetIsAdmin  BIT             = NULL
          , @AdminsLeft     INT             = NULL
          , @DetailJson     NVARCHAR (MAX)  = NULL
          , @ChangeId       BIGINT          = NULL
          , @Failure        NVARCHAR (2000) = NULL;

    SET @FlagChanged   = 0;
    SET @KeyParameters = CONCAT (N'UserId=', @UserId, N', ReasonLength='
                               , COALESCE (CAST (LEN (@Reason) AS NVARCHAR (11)), N'(null)'));

    BEGIN TRY

        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        SET @ActorProfileId = TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT);
        SET @ActorUserId    = TRY_CAST (SESSION_CONTEXT (N'UserId')        AS INT);
        SET @ActingTenantId = TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT);
        SET @Actor          = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                      , ORIGINAL_LOGIN ());

        SELECT @ActorIsAdmin = u.IsPlatformAdmin
          FROM auth.[User] AS u
         WHERE u.UserId    = @ActorUserId
           AND u.IsDeleted = 0;

        IF COALESCE (@ActorIsAdmin, 0) = 0
        BEGIN
            SET @Failure = N'Platform administration is an authentication capability (D-05), not a permission, so only '
                         + N'a platform administrator may remove it -- holding Platform.ManageApplications is not '
                         + N'sufficient. The acting account''s own IsPlatformAdmin is 0. Nothing was changed.';
            ;THROW 50084, @Failure, 1;
        END;

        EXEC auth.uspDemandPermission @PermissionCode = N'Platform.ManageApplications'
                                    , @ObjectName     = N'auth.uspRevokePlatformAdmin';

        SELECT @TargetIsAdmin = u.IsPlatformAdmin
          FROM auth.[User] AS u
         WHERE u.UserId    = @UserId
           AND u.IsDeleted = 0;

        IF @TargetIsAdmin IS NULL
        BEGIN
            SET @Failure = N'No such user, or it has been deleted. Nothing was changed.';
            ;THROW 50081, @Failure, 1;
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

        IF @TargetIsAdmin = 1
        BEGIN
            -- Counted inside the transaction, and only over accounts that could actually sign in. See the header.
            SELECT @AdminsLeft = COUNT (*)
              FROM auth.[User] AS u
             WHERE u.IsDeleted       = 0
               AND u.IsActive        = 1
               AND u.IsPlatformAdmin = 1
               AND u.UserId         <> @UserId;

            IF @AdminsLeft = 0
            BEGIN
                SET @Failure = N'This is the last live, active platform administrator, so removing the flag would make '
                             + N'the administrator sign-in route and every Platform permission unreachable (INV-09). '
                             + N'900_bootstrap_first_admin.sql refuses to run once any profile exists (section 16.3), '
                             + N'so there would be no route back in short of a DBA with sysadmin and a hand-written '
                             + N'UPDATE. Grant the flag to somebody else first -- auth.uspGrantPlatformAdmin. Nothing '
                             + N'was changed.';
                ;THROW 50082, @Failure, 1;
            END;

            UPDATE u
               SET u.IsPlatformAdmin = 0
                 , u.auditModifiedBy = @Actor
              FROM auth.[User] AS u
             WHERE u.UserId    = @UserId
               AND u.IsDeleted = 0;

            SET @FlagChanged = 1;

            SET @DetailJson = CONCAT (N'{"actorUserId":', COALESCE (CAST (@ActorUserId AS NVARCHAR (11)), N'null')
                                    , N',"selfRevoke":', CASE WHEN @UserId = @ActorUserId THEN N'true' ELSE N'false' END
                                    , N',"administratorsRemaining":'
                                    , COALESCE (CAST (@AdminsLeft AS NVARCHAR (11)), N'null')
                                    , N',"reason":'
                                    , COALESCE (N'"' + STRING_ESCAPE (@Reason, 'json') + N'"', N'null')
                                    , N'}');

            EXEC logs.uspRecordAuthorizationChange
                  @ChangeType             = 'PlatformAdminRevoked'
                , @TargetUserId           = @UserId
                , @TargetUserProfileId    = NULL
                , @RoleId                 = NULL
                , @ScopeTenantId          = NULL
                , @ActorUserProfileId     = @ActorProfileId
                , @ActorAuthorityTenantId = @ActingTenantId
                , @DetailJson             = @DetailJson
                , @AuthorizationChangeId  = @ChangeId OUTPUT;
        END;

        SET @Comments = CONCAT (N'UserId=', @UserId, N' FlagChanged=', @FlagChanged
                              , CASE WHEN @FlagChanged = 1
                                     THEN CONCAT (N'. AdministratorsRemaining=', @AdminsLeft
                                                , N'. AuthorizationChangeId=', @ChangeId, N'.')
                                     ELSE N'. Was not a platform administrator, so no row was written to '
                                        + N'logs.AuthorizationChange.'
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


-- *** 3. auth.uspRebuildEffectivePermissions ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspRebuildEffectivePermissions
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Rebuilds auth.ProfilePermissionScope for one profile, or for every live profile when @UserProfileId is NULL.  Demands
Platform.RebuildSecurityCache.  A thin, instrumented, permission-checked wrapper around
auth.uspRebuildProfilePermissionScope -- it contains no flattening logic of its own.

========================================================================================================================
Requirements and Key Dependencies:

auth.UserProfile, auth.ProfilePermissionScope, auth.uspRebuildProfilePermissionScope, auth.uspSetSessionContext,
auth.uspDemandPermission.  Granted to applicationRole.  DES-AUTH-001 section 8.6, Appendix B E-50083.

========================================================================================================================
Notes:

IT OPENS NO TRANSACTION OF ITS OWN, AND THAT IS THE POINT.  Each call to auth.uspRebuildProfilePermissionScope is already
atomic for the profile it rebuilds.  Wrapping a few thousand of them in one transaction would hold locks on the table that
every permission test in the database reads, for the whole run.  The operation is idempotent, so an interrupted run has
rebuilt some profiles correctly and can simply be run again -- which is the right property for a repair tool and the wrong
one for a business transaction.  Because it owns no transaction it also does not roll one back: the CATCH records and
re-raises, nothing more.

E-50083 IS ABOUT EXISTENCE, NOT ABOUT STATE.  @UserProfileId = NULL means "every profile" and is not an error (section
8.6).  A supplied id that matches no row with IsDeleted = 0 is E-50083.  An INACTIVE profile is accepted: rebuilding it is
how its scope rows get cleared, so refusing it would withhold the repair path from the rows most likely to need it.

THE WHOLE-DATABASE RUN WALKS A NUMBERED TABLE VARIABLE rather than a cursor and rather than deleting rows as it goes.
Conventions rule 12 forbids DELETE, including DELETE FROM a table variable, so the loop is a RowNo IDENTITY with a WHILE
over @MaxRowNo -- the same shape every other loop in this project uses.

WHAT IT REPORTS.  @ProfilesRebuilt counts profiles, not rows.  The execution log's Comments carries the profile count and
the live row count in auth.ProfilePermissionScope afterwards, which is the figure a person running a repair actually wants
to compare against the figure 950_verify_deployment.sql derives independently.

========================================================================================================================
Example Usage and Performance:

declare @n int;
exec auth.uspRebuildEffectivePermissions @SessionTokenHash = 0x9F86..., @UserProfileId = 42, @ProfilesRebuilt = @n out;
exec auth.uspRebuildEffectivePermissions @SessionTokenHash = 0x9F86..., @ProfilesRebuilt = @n output;  -- every profile

One profile is milliseconds.  The whole-database form is linear in profiles and is a deployment and repair tool, not a
request-path call: T-071 measures it at the expected profile count and at ten times it.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-091
Description:
Created.  Phase 6.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspRebuildEffectivePermissions
      @SessionTokenHash VARBINARY (32)
    , @UserProfileId    INT = NULL
    , @ProfilesRebuilt  INT = NULL OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspRebuildEffectivePermissions]')
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

    DECLARE @Exists     BIT             = NULL
          , @RowNo      INT             = 1
          , @MaxRowNo   INT             = 0
          , @EachId     INT             = NULL
          , @ScopeRows  INT             = NULL
          , @Failure    NVARCHAR (2000) = NULL;

    DECLARE @Profiles TABLE
    (
        RowNo         INT IDENTITY (1, 1) PRIMARY KEY,
        UserProfileId INT NOT NULL
    );

    SET @ProfilesRebuilt = 0;
    SET @KeyParameters   = CONCAT (N'UserProfileId='
                                 , COALESCE (CAST (@UserProfileId AS NVARCHAR (11)), N'(null, every live profile)'));

    BEGIN TRY

        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        -- Platform.RebuildSecurityCache is not tenant-scoped: the cache is the deployment's, not a tenant's.
        EXEC auth.uspDemandPermission @PermissionCode = N'Platform.RebuildSecurityCache'
                                    , @ObjectName     = N'auth.uspRebuildEffectivePermissions';

        IF @UserProfileId IS NOT NULL
        BEGIN
            SELECT @Exists = 1
              FROM auth.UserProfile AS up
             WHERE up.UserProfileId = @UserProfileId
               AND up.IsDeleted     = 0;

            IF @Exists IS NULL
            BEGIN
                SET @Failure = N'@UserProfileId names no live profile. Pass NULL to rebuild every profile -- that is '
                             + N'not an error (section 8.6). An INACTIVE profile is accepted, because rebuilding it is '
                             + N'how its scope rows are cleared. Nothing was rebuilt.';
                ;THROW 50083, @Failure, 1;
            END;
        END;

        EXEC logs.uspStartExecutionLogging
              @ProcedureName          = @ProcName
            , @KeyParameters          = @KeyParameters
            , @StartDateUtc           = @StartTimeUtc
            , @ReCreatedAfterRollback = 0
            , @ExecutionLogId         = @ExecutionId OUTPUT;

        -- =========================================================================================
        -- ===== The procedure's own work starts here. Everything above and below is boilerplate. ==
        -- =========================================================================================

        INSERT @Profiles (UserProfileId)
        SELECT up.UserProfileId
          FROM auth.UserProfile AS up
         WHERE up.IsDeleted = 0
           AND (@UserProfileId IS NULL OR up.UserProfileId = @UserProfileId)
         ORDER BY up.UserProfileId;

        SET @MaxRowNo = (SELECT MAX (RowNo) FROM @Profiles);

        WHILE @RowNo <= COALESCE (@MaxRowNo, 0)
        BEGIN
            SELECT @EachId = UserProfileId
              FROM @Profiles
             WHERE RowNo = @RowNo;

            -- The one definition of the flattening lives here, in 100_auth_functions.sql. This procedure adds a session,
            -- a permission and a log row around it and nothing else. See the file header.
            EXEC auth.uspRebuildProfilePermissionScope @UserProfileId = @EachId;

            SET @ProfilesRebuilt += 1;
            SET @RowNo           += 1;
        END;

        SELECT @ScopeRows = COUNT (*)
          FROM auth.ProfilePermissionScope AS pps
         WHERE pps.IsDeleted = 0;

        SET @Comments = CONCAT (N'ProfilesRebuilt=', @ProfilesRebuilt
                              , N', Scope=', COALESCE (CAST (@UserProfileId AS NVARCHAR (11)), N'every live profile')
                              , N'. auth.ProfilePermissionScope now holds ', @ScopeRows, N' live row(s). '
                              , N'No transaction was opened: each profile''s rebuild is atomic and the whole run is '
                              , N'idempotent and restartable.');

        -- =========================================================================================
        -- ===== End of the procedure's own work. ===================================================
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

        -- No ROLLBACK: this procedure opens no transaction, and XACT_STATE () <> 0 would also be true when the CALLER
        -- owns one -- rolling that back would discard work this procedure never did. Conventions rule 8.
        SELECT @ErrorNumber = ERROR_NUMBER ()
             , @ErrorProc   = ERROR_PROCEDURE ()
             , @ErrorLine   = ERROR_LINE ()
             , @ErrorMsg    = ERROR_MESSAGE ()
                            + N' (error '  + CAST (ERROR_NUMBER () AS NVARCHAR (11))
                            + N', line '   + CAST (ERROR_LINE ()   AS NVARCHAR (11)) + N')';

        SET @ContextMessage = CONCAT (N'Rebuilt ', @ProfilesRebuilt, N' profile(s) before the failure. The run is '
                                    , N'idempotent: re-running it is safe and completes the remainder.');

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


-- *** 4. auth.uspRebuildSecurityCache ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspRebuildSecurityCache
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Rebuilds both pieces of derived authorization state for the whole database -- auth.TenantClosure first, then
auth.ProfilePermissionScope for every live profile.  Demands Platform.RebuildSecurityCache.  The granted wrapper around
auth.uspRebuildTenantClosure, which takes no parameters, demands nothing and is not granted to applicationRole.

========================================================================================================================
Requirements and Key Dependencies:

auth.TenantClosure, auth.uspRebuildTenantClosure, auth.uspRebuildEffectivePermissions, auth.uspSetSessionContext,
auth.uspDemandPermission.  Granted to applicationRole.  DES-AUTH-001 sections 5.3, 8.6.

========================================================================================================================
Notes:

THE CLOSURE IS REBUILT FIRST, AND THE ORDER IS DELIBERATE EVEN THOUGH THE DEPENDENCY IS INDIRECT.
auth.ProfilePermissionScope is NOT expanded over the tenant subtree (D-07) -- it stores the scope tenant a grant was made
at, and auth.udfHasPermission joins auth.TenantClosure at read time -- so the flattening does not read the closure and the
two rebuilds are independent in the strict sense.  They are still ordered, because the purpose of running both is
recovering from an unknown state, and a person reading the log wants the foundation rebuilt before the thing that is
checked against it.  Reversing the order would produce the same rows and a worse story.

EACH HALF CAN BE SKIPPED.  @RebuildTenantClosure and @RebuildEffectivePermissions default to 1.  Setting either to 0 is
for the case where one half is known good and the other is being repaired under a maintenance window; both at 0 is
permitted and does nothing, which is a harmless way to find out that the caller holds the permission.

IT DELEGATES TO auth.uspRebuildEffectivePermissions RATHER THAN LOOPING ITSELF, so the permission is demanded twice and
two execution-log rows are written for one run.  That is accepted on purpose: the alternative is a second copy of the
loop, and the point of both wrappers is that there is exactly one copy of everything.  The two log rows are also a more
honest record -- the closure rebuild and the permission rebuild have very different costs and it is useful to see them
separately.

IT OPENS NO TRANSACTION.  auth.uspRebuildTenantClosure already does its whole rebuild inside one (section 5.3), and the
permission half is deliberately many small ones (see auth.uspRebuildEffectivePermissions).  So there is nothing left for
this procedure to own, and it does not roll back what it does not own.

========================================================================================================================
Example Usage and Performance:

declare @closure int, @profiles int;
exec auth.uspRebuildSecurityCache @SessionTokenHash = 0x9F86...
                                , @ClosureRows = @closure output, @ProfilesRebuilt = @profiles output;

exec auth.uspRebuildSecurityCache @SessionTokenHash = 0x9F86..., @RebuildEffectivePermissions = 0;  -- closure only

A deployment and repair tool. 950_verify_deployment.sql derives both tables independently and fails the build on any
difference; this is what a person runs when it does.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-091
Description:
Created.  Phase 6.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspRebuildSecurityCache
      @SessionTokenHash            VARBINARY (32)
    , @RebuildTenantClosure        BIT = 1
    , @RebuildEffectivePermissions BIT = 1
    , @ClosureRows                 INT = NULL OUTPUT
    , @ProfilesRebuilt             INT = NULL OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspRebuildSecurityCache]')
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

    SET @ClosureRows     = NULL;
    SET @ProfilesRebuilt = NULL;
    SET @KeyParameters   = CONCAT (N'RebuildTenantClosure=', @RebuildTenantClosure
                                 , N', RebuildEffectivePermissions=', @RebuildEffectivePermissions);

    BEGIN TRY

        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        EXEC auth.uspDemandPermission @PermissionCode = N'Platform.RebuildSecurityCache'
                                    , @ObjectName     = N'auth.uspRebuildSecurityCache';

        EXEC logs.uspStartExecutionLogging
              @ProcedureName          = @ProcName
            , @KeyParameters          = @KeyParameters
            , @StartDateUtc           = @StartTimeUtc
            , @ReCreatedAfterRollback = 0
            , @ExecutionLogId         = @ExecutionId OUTPUT;

        -- =========================================================================================
        -- ===== The procedure's own work starts here. Everything above and below is boilerplate. ==
        -- =========================================================================================

        IF @RebuildTenantClosure = 1
        BEGIN
            -- Takes no parameters: it is a whole rebuild inside its own transaction, which is what makes it converge
            -- after any sequence of changes including a re-parenting (section 5.3).
            EXEC auth.uspRebuildTenantClosure;

            SELECT @ClosureRows = COUNT (*)
              FROM auth.TenantClosure AS tc
             WHERE tc.IsDeleted = 0;
        END;

        IF @RebuildEffectivePermissions = 1
        BEGIN
            -- Delegated rather than re-implemented, and the session token is passed straight through so the inner
            -- procedure demands the permission for itself. See the header on why two log rows are the right answer.
            EXEC auth.uspRebuildEffectivePermissions
                  @SessionTokenHash = @SessionTokenHash
                , @UserProfileId    = NULL
                , @ProfilesRebuilt  = @ProfilesRebuilt OUTPUT;
        END;

        SET @Comments = CONCAT (N'TenantClosure: '
                              , CASE WHEN @RebuildTenantClosure = 1
                                     THEN CONCAT (N'rebuilt, ', @ClosureRows, N' live row(s)')
                                     ELSE N'skipped'
                                END
                              , N'. ProfilePermissionScope: '
                              , CASE WHEN @RebuildEffectivePermissions = 1
                                     THEN CONCAT (N'rebuilt for ', @ProfilesRebuilt, N' profile(s)')
                                     ELSE N'skipped'
                                END
                              , N'. Both halves are idempotent; 950_verify_deployment.sql derives both independently.');

        -- =========================================================================================
        -- ===== End of the procedure's own work. ===================================================
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

        -- No ROLLBACK: everything this procedure calls owns its own transaction or deliberately owns none, and
        -- XACT_STATE () <> 0 would also be true when the CALLER owns one. Conventions rule 8.
        SELECT @ErrorNumber = ERROR_NUMBER ()
             , @ErrorProc   = ERROR_PROCEDURE ()
             , @ErrorLine   = ERROR_LINE ()
             , @ErrorMsg    = ERROR_MESSAGE ()
                            + N' (error '  + CAST (ERROR_NUMBER () AS NVARCHAR (11))
                            + N', line '   + CAST (ERROR_LINE ()   AS NVARCHAR (11)) + N')';

        SET @ContextMessage = CONCAT (N'ClosureRows='
                                    , COALESCE (CAST (@ClosureRows AS NVARCHAR (11)), N'(not reached)')
                                    , N', ProfilesRebuilt='
                                    , COALESCE (CAST (@ProfilesRebuilt AS NVARCHAR (11)), N'(not reached)')
                                    , N'. Re-running is safe.');

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


-- *** 5. Descriptions ***
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
      (N'uspGrantPlatformAdmin'
     , N'Sets auth.User.IsPlatformAdmin = 1 on one account. The ACTING user must already hold the flag (E-50084) AND '
     + N'hold Platform.ManageApplications -- the flag test comes first so the message is true, because '
     + N'Platform.ManageApplications may well be held and is not what is missing. D-05 makes this an AUTHENTICATION '
     + N'capability, which is why 130''s auth.uspCreateUser refuses @IsPlatformAdmin = 1 with E-50155 and this is the '
     + N'only place it can be conferred. E-50081 no such user. Idempotent: a re-grant writes no trail row.')
    , (N'uspRevokePlatformAdmin'
     , N'Sets auth.User.IsPlatformAdmin = 0 on one account. Same two gates as the grant (E-50084 is a documented '
     + N'widening of Appendix B -- G-35), plus E-50082: the LAST live active platform administrator cannot be revoked, '
     + N'counted inside the transaction so two concurrent revokes cannot both pass. INV-09 would otherwise leave the '
     + N'bypass route and every Platform permission unreachable with no way back in (section 16.3). Revoking yourself '
     + N'is permitted. No session is ended -- auth.udfHasPermission reads the flag live, so it takes effect at once.')
    , (N'uspRebuildEffectivePermissions'
     , N'Rebuilds auth.ProfilePermissionScope for one profile, or for every live profile when @UserProfileId is NULL -- '
     + N'which is not an error (section 8.6). E-50083 is a supplied id matching no live profile; an INACTIVE profile is '
     + N'accepted, because rebuilding it is how its rows get cleared. Demands Platform.RebuildSecurityCache. A wrapper '
     + N'around auth.uspRebuildProfilePermissionScope with no flattening logic of its own, so section 8.6''s claim that '
     + N'there is ONE definition holds. Opens no transaction: idempotent and restartable is the right property here.')
    , (N'uspRebuildSecurityCache'
     , N'Rebuilds both pieces of derived authorization state for the whole database: auth.TenantClosure first, then '
     + N'auth.ProfilePermissionScope for every live profile. Demands Platform.RebuildSecurityCache. This is the granted '
     + N'wrapper around auth.uspRebuildTenantClosure, which takes no parameters, demands nothing and is NOT granted to '
     + N'applicationRole. Either half can be skipped with @RebuildTenantClosure / @RebuildEffectivePermissions = 0. '
     + N'What a person runs when 950_verify_deployment.sql reports drift.');

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

        EXEC util.uspSetObjectDescription @SchemaName  = N'auth'
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


-- *** 6. Grants ***
-- All four, to applicationRole.  The two maintainers they wrap -- auth.uspRebuildProfilePermissionScope and
-- auth.uspRebuildTenantClosure -- are deliberately NOT granted here or anywhere: they take no session token and demand
-- no permission, so a direct grant would be a way to run the expensive half of the model with no credential at all.
IF DATABASE_PRINCIPAL_ID (N'applicationRole') IS NOT NULL
BEGIN
    GRANT EXECUTE ON auth.uspGrantPlatformAdmin         TO applicationRole;
    GRANT EXECUTE ON auth.uspRevokePlatformAdmin        TO applicationRole;
    GRANT EXECUTE ON auth.uspRebuildEffectivePermissions TO applicationRole;
    GRANT EXECUTE ON auth.uspRebuildSecurityCache       TO applicationRole;

    PRINT N'Granted EXECUTE on the four platform-administration procedures to applicationRole. The two internal '
        + N'maintainers they wrap are not granted, on purpose (INV-11 and the file header).';
END
ELSE
BEGIN
    PRINT N'applicationRole does not exist, so no grants were made. Run database/005_schemas_and_roles.sql and then '
        + N're-run this file.';
END
GO


-- *** 7. Closing report ***
DECLARE @Report TABLE
(
    RowNo    INT IDENTITY (1, 1) PRIMARY KEY,
    Severity INT             NOT NULL,
    Status   VARCHAR (10)    NOT NULL,
    Item     NVARCHAR (200)  NOT NULL,
    Detail   NVARCHAR (1000)     NULL
);

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (N'auth.' + x.ProcName, N'P') IS NULL THEN 1 ELSE 4 END
     , CASE WHEN OBJECT_ID (N'auth.' + x.ProcName, N'P') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Procedure auth.' + x.ProcName
     , x.Detail
  FROM (VALUES (N'uspGrantPlatformAdmin',          N'E-50084 flag first, then Platform.ManageApplications, then E-50081. Idempotent.')
             , (N'uspRevokePlatformAdmin',         N'Same gates plus E-50082, counted inside the transaction. Ends no session.')
             , (N'uspRebuildEffectivePermissions', N'Platform.RebuildSecurityCache. E-50083. NULL means every live profile.')
             , (N'uspRebuildSecurityCache',        N'Platform.RebuildSecurityCache. Closure first, then the flattening.')
       ) AS x (ProcName, Detail);

-- The header's central claim, checked mechanically: the actor's own flag is read BEFORE the demand in both flag
-- procedures, so a caller who holds the permission but not the flag is told the truth (E-50084, not E-50030).
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 2 THEN 4 ELSE 2 END
     , CASE WHEN COUNT (*) = 2 THEN 'OK' ELSE 'VIOLATED' END
     , N'E-50084 is raised before the permission is demanded'
     , CONCAT (COUNT (*), N' of 2 flag procedures put ";THROW 50084" ahead of '
             , N'"EXEC auth.uspDemandPermission" in their text. Reversed, the caller is told they lack '
             , N'Platform.ManageApplications, which may be false -- see the file header.')
  FROM sys.sql_modules AS m
  JOIN sys.objects     AS o ON o.object_id = m.object_id
 WHERE o.schema_id = SCHEMA_ID (N'auth')
   AND o.name IN (N'uspGrantPlatformAdmin', N'uspRevokePlatformAdmin')
   AND CHARINDEX (N';THROW 50084', m.definition) > 0
   AND CHARINDEX (N';THROW 50084', m.definition) < CHARINDEX (N'EXEC auth.uspDemandPermission', m.definition);

-- BL-042 / G-31: the demand must precede BEGIN TRANSACTION, or its logs.AuthorizationDenial row is rolled back with the
-- refusal and the denial vanishes from the trail. Matched with the semicolon so the header prose cannot false-positive.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 2 THEN 4 ELSE 2 END
     , CASE WHEN COUNT (*) = 2 THEN 'OK' ELSE 'VIOLATED' END
     , N'The permission demand precedes BEGIN TRANSACTION'
     , CONCAT (COUNT (*), N' of 2 transactional procedures demand before they open. Inside the transaction the '
             , N'denial row auth.uspDemandPermission writes is rolled back with the refusal -- BL-042, G-31.')
  FROM sys.sql_modules AS m
  JOIN sys.objects     AS o ON o.object_id = m.object_id
 WHERE o.schema_id = SCHEMA_ID (N'auth')
   AND o.name IN (N'uspGrantPlatformAdmin', N'uspRevokePlatformAdmin')
   AND CHARINDEX (N'EXEC auth.uspDemandPermission', m.definition) > 0
   AND CHARINDEX (N'EXEC auth.uspDemandPermission', m.definition) < CHARINDEX (N'BEGIN TRANSACTION;', m.definition);

-- The two rebuild wrappers must contain NO rebuild of their own: one definition of the flattening (section 8.6), and the
-- closure rebuilt only by the procedure that owns it (section 5.3).
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 0 THEN 4 ELSE 1 END
     , CASE WHEN COUNT (*) = 0 THEN 'OK' ELSE 'VIOLATED' END
     , N'The rebuild wrappers write neither derived table directly'
     , CONCAT (COUNT (*), N' write reference(s) from the two wrappers to auth.ProfilePermissionScope or '
             , N'auth.TenantClosure. Must be 0: a second implementation of the flattening is a second definition, and '
             , N'the two drift in exactly the way the table itself does. Reads for the row counts are fine.')
  FROM sys.sql_modules AS m
  JOIN sys.objects     AS o ON o.object_id = m.object_id
 CROSS APPLY (VALUES (N'INSERT auth.ProfilePermissionScope'), (N'UPDATE auth.ProfilePermissionScope')
                   , (N'INSERT auth.TenantClosure'),          (N'UPDATE auth.TenantClosure')
                   , (N'MERGE auth.ProfilePermissionScope'),  (N'MERGE auth.TenantClosure')
             ) AS w (Fragment)
 WHERE o.schema_id = SCHEMA_ID (N'auth')
   AND o.name IN (N'uspRebuildEffectivePermissions', N'uspRebuildSecurityCache')
   AND CHARINDEX (w.Fragment, m.definition) > 0;

-- The internal maintainers stay ungranted. This is the whole reason the wrappers exist.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 0 THEN 4 ELSE 1 END
     , CASE WHEN COUNT (*) = 0 THEN 'OK' ELSE 'VIOLATED' END
     , N'The internal maintainers are not granted to applicationRole'
     , CONCAT (COUNT (*), N' EXECUTE grant(s) on auth.uspRebuildProfilePermissionScope or '
             , N'auth.uspRebuildTenantClosure. Must be 0: neither takes a session token or demands a permission, so a '
             , N'grant would let the application run the expensive half of the model with no credential at all.')
  FROM sys.database_permissions AS dp
  JOIN sys.objects              AS o ON o.object_id = dp.major_id
 WHERE dp.grantee_principal_id = DATABASE_PRINCIPAL_ID (N'applicationRole')
   AND dp.permission_name      = N'EXECUTE'
   AND dp.state                = N'G'
   AND o.schema_id             = SCHEMA_ID (N'auth')
   AND o.name IN (N'uspRebuildProfilePermissionScope', N'uspRebuildTenantClosure');

-- INV-09's other half: the flag and the role are independent, and a deployment needs at least one holder of each.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.LiveAdmins = 0 THEN 2 ELSE 4 END
     , CASE WHEN x.LiveAdmins = 0 THEN 'EMPTY' ELSE 'OK' END
     , N'Live, active platform administrators'
     , CONCAT (x.LiveAdmins, N' account(s) with IsPlatformAdmin = 1, IsActive = 1, IsDeleted = 0. Zero is expected '
             , N'before 900_bootstrap_first_admin.sql has run and is a locked-out deployment afterwards: E-50082 and '
             , N'E-50154 exist to keep this figure above zero. ', x.WithRole, N' of them also hold PLATFORM_ADMIN, '
             , N'which INV-09 requires on top of the flag before any Platform permission takes effect.')
  FROM (SELECT LiveAdmins = COUNT (*)
             , WithRole    = COALESCE (SUM (CASE WHEN a.RoleRows > 0 THEN 1 ELSE 0 END), 0)
          FROM (SELECT u.UserId
                     , RoleRows = (SELECT COUNT (*)
                                     FROM auth.UserProfile     AS up
                                     JOIN auth.UserProfileRole AS upr ON upr.UserProfileId = up.UserProfileId
                                                                     AND upr.IsDeleted     = 0
                                     JOIN auth.Role            AS r   ON r.RoleId          = upr.RoleId
                                                                     AND r.IsDeleted       = 0
                                    WHERE up.UserId    = u.UserId
                                      AND up.IsDeleted = 0
                                      AND r.RoleCode   = N'PLATFORM_ADMIN')
                  FROM auth.[User] AS u
                 WHERE u.IsDeleted       = 0
                   AND u.IsActive        = 1
                   AND u.IsPlatformAdmin = 1) AS a) AS x;

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 4 THEN 4 ELSE 2 END
     , CASE WHEN COUNT (*) = 4 THEN 'OK' ELSE 'INCOMPLETE' END
     , N'MS_Description on the administration procedures'
     , CONCAT (COUNT (*), N' of 4. Conventions rule 4.')
  FROM sys.extended_properties AS ep
  JOIN sys.objects             AS o ON o.object_id = ep.major_id
 WHERE ep.name     = N'MS_Description'
   AND ep.minor_id = 0
   AND o.schema_id = SCHEMA_ID (N'auth')
   AND o.name IN (N'uspGrantPlatformAdmin', N'uspRevokePlatformAdmin', N'uspRebuildEffectivePermissions'
                , N'uspRebuildSecurityCache');

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 4 THEN 4 ELSE 2 END
     , CASE WHEN COUNT (*) = 4 THEN 'OK' ELSE 'INCOMPLETE' END
     , N'EXECUTE granted to applicationRole'
     , CONCAT (COUNT (*), N' of 4. Zero means 005_schemas_and_roles.sql has not run.')
  FROM sys.database_permissions AS dp
  JOIN sys.objects              AS o ON o.object_id = dp.major_id
 WHERE dp.grantee_principal_id = DATABASE_PRINCIPAL_ID (N'applicationRole')
   AND dp.permission_name      = N'EXECUTE'
   AND dp.state                = N'G'
   AND o.schema_id             = SCHEMA_ID (N'auth')
   AND o.name IN (N'uspGrantPlatformAdmin', N'uspRevokePlatformAdmin', N'uspRebuildEffectivePermissions'
                , N'uspRebuildSecurityCache');

IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
    PRINT N'Platform administration surface: PROBLEMS found. Read the report below.';
ELSE
    PRINT N'Platform administration surface: no problems found.';

PRINT N'';

SELECT Severity, Status, Item, Detail
  FROM @Report
 ORDER BY Severity, RowNo;
GO

