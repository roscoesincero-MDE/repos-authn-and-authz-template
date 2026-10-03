/***********************************************************************************************************************
Script:         130_auth_user_procedures.sql
Purpose:        The person-record surface: auth.uspCreateUser, auth.uspUpdateUser, auth.uspDeactivateUser,
                auth.uspGetUser and auth.uspSearchUsers.
Target:         SQL Server 2022.
Run as:         db_owner in the target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/130_auth_user_procedures.sql
Idempotent:     Yes.  CREATE OR ALTER throughout, and every grant guarded on DATABASE_PRINCIPAL_ID.
Depends on:     045_auth_identity.sql, 105_auth_session_procedures.sql, 150_auth_query_procedures.sql
                (auth.uspDemandPermission), scripts/logExecutionLogging.sql, templates/extended-properties.sql.
Implements:     T-075.  DES-AUTH-001 sections 6.1, 6.3, 8.5, 11.4, 14.1 to 14.5.
                See docs/10-database-authn-authz-design.md.
To retarget:    Pass it per run:  sqlcmd -d <database> -v DbName=<database>.  There is no in-file default.

EVERY REFERENCE TO THE TABLE IS auth.[User], WITH THE BRACKETS, AND IT IS NOT A STYLE CHOICE
------------------------------------------------------------------------------------------
USER is a reserved word -- the niladic function -- so `FROM auth.User AS u` is Msg 156, "Incorrect syntax near the
keyword 'User'", at CREATE time.  This is the first file in the project whose procedures read and write auth.[User]
directly, so it is the first place it bites; 045_auth_identity.sql already brackets it throughout, which is where the
convention comes from.  Every other table in the database can be written bare and this one cannot.  UI-41.

NOTHING HERE TOUCHES A CREDENTIAL
---------------------------------
Creating a user does not create a way to sign in.  auth.UserCredential, auth.UserFederatedIdentity and
auth.UserMfaFactor are written by 110_auth_authn_procedures.sql and 112_auth_mfa_procedures.sql, from a verifier the
APPLICATION computed (D-08), and no procedure in this file accepts a password, a verifier, a salt or a token.  A user
created here can be looked up and given a profile and still cannot authenticate, which is the correct order: the person
record and the means of proving you are that person are two facts with two lifecycles.

auth.uspUpdateUser deliberately does NOT expose MustChangePassword, IsLockedOut or LockoutEndUtc either.  Those three
belong to the authentication machinery -- 110 sets and clears them from the sign-in path, and a User.Update holder who
could clear IsLockedOut by hand would be able to undo a lockout without the lockout window ever expiring, which is the
throttle the window exists to impose (section 7.4).  Forcing a reset is User.ResetCredential in 110, not User.Update.

WHY User.Create IS DEMANDED AT THE ACTOR'S OWN ACTING TENANT AND NOT AT A TARGET
------------------------------------------------------------------------------
A user is not tenant-scoped -- it has no TenantId -- so there is no target tenant to demand the permission at.  Section
11.4 is explicit and calls this "deliberately weaker": anyone holding User.Create at ANY tenant may create a person
record, because a person with no profile has no access to anything.  Giving that person a profile is Authz.ProfileCreate
in 140_auth_profile_procedures.sql, and THAT is scoped exactly like Authz.RoleAssign.

The same reasoning applies to User.Read, User.Update and User.Deactivate, and it has a consequence worth stating: this
file is where a county administrator can see and rename a person who has no profile in their county at all.  That is the
design's choice, not an oversight (G-27 records it and the mitigation, which is that the person record holds a display
name, a user name and an email and nothing else of interest).

@IsPlatformAdmin CANNOT BE SET HERE, AT ALL, IN EITHER PROCEDURE
---------------------------------------------------------------
auth.uspCreateUser refuses @IsPlatformAdmin = 1 with E-50155 and auth.uspUpdateUser has no such parameter.  D-05 makes
platform administration an AUTHENTICATION capability rather than a role, and INV-09 requires the flag on top of the
PLATFORM_ADMIN role -- so the flag is the harder half of the pair and it gets its own procedure with its own permission
and its own audit row: auth.uspGrantPlatformAdmin in 160_auth_admin_procedures.sql, which demands
Platform.ManageApplications AND requires the ACTOR to hold the flag already.

Folding it into User.Create would mean that anybody who may create a person may create a platform administrator, which
is the whole of the authorization model defeated by one bit in one INSERT.

CREATING AND DEACTIVATING A PERSON GO TO logs.DataChangeLog, NOT TO logs.AuthorizationChange
-------------------------------------------------------------------------------------------
The first draft of this file wrote logs.AuthorizationChange rows with ChangeType 'UserCreate' and 'UserDeactivate' and
they were both refused: CK_logs_AuthorizationChange_ChangeType is a closed set of SIXTEEN values, every one of them about
a profile, a role, a grant, the platform-admin flag or a reparenting, and Appendix B's E-50130 says the vocabulary is
"closed on purpose: a trail whose types are open is a trail nobody can query".  Widening it to admit a user's lifecycle
would have made the authorization trail answer two different questions, and the screen that reads it -- section 15.6's
logs.vwAuthorizationTrail -- exists to answer one.

So both go to logs.DataChangeLog through logs.uspRecordDataChange, which is section 15.5's row-level business audit and
takes Operation = 'Insert' or 'Update' with a KeyJson naming the row.  D-12 is why that table is written by procedures
rather than a trigger, and this is exactly the case it was built for: the procedure knows that the column that changed
was IsActive and that the business meaning was "this person can no longer sign in anywhere", which a generic trigger
serialising `inserted` would not.  BL-054.

auth.uspUpdateUser writes NO trail row of either kind -- the audit columns on auth.User already carry who and when for a
display-name change, and a rename is not an event anybody reviews.

THE LAST PLATFORM ADMINISTRATOR CANNOT BE DEACTIVATED
-----------------------------------------------------
auth.uspDeactivateUser raises E-50154 rather than leaving a database whose only route back in is
900_bootstrap_first_admin.sql -- which refuses to run once any profile exists (section 16.3 clause 1), so there would be
no route back in at all.  auth.uspRevokePlatformAdmin's E-50082 is the other half of the same guard, and both count LIVE
ACTIVE users with the flag, not rows.
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
        N'auth.User or auth.UserProfile is missing. Run database/045_auth_identity.sql and '
      + N'database/040_auth_userprofile.sql first.';

    THROW 50000, @MsgId, 1;
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


-- *** 1. auth.uspCreateUser ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspCreateUser
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Creates a person record.  Demands User.Create at the actor's acting tenant (section 11.4).  Returns the new UserId.

Creates NO credential, NO profile and NO grant, so the user it creates cannot sign in and cannot see anything.  That is
the point: section 11.4 calls User.Create "deliberately weaker" precisely because a person with no profile is harmless.

========================================================================================================================
Requirements and Key Dependencies:

auth.User, auth.uspSetSessionContext, auth.uspDemandPermission, logs.uspRecordDataChange.
Granted to applicationRole.

========================================================================================================================
Notes:

@UserName IS COMPARED CASE-INSENSITIVELY BY THE DATABASE'S COLLATION, WHICH IS THE POINT.  UX_auth_User_UserName is a
filtered unique index on a column in the database collation, so `A.Patel` and `a.patel` are one user.  Any other answer
means two accounts one typo apart, and a support desk that cannot tell which is which.  E-50151 reports the collision
with a message that names the code and not the existing user's details -- it is an administrative path, so confirming
that a name is taken is acceptable, but there is no reason to volunteer anything else.

@Email IS OPTIONAL AND IS NOT A KEY.  auth.User.Email is nullable and carries no unique index: a shared departmental
mailbox on two accounts is ordinary, and a federated user may arrive with no email at all.  Nothing in the sign-in path
reads it.

@AuthPolicyOverrideJson IS VALIDATED, NOT TRUSTED.  ISJSON is checked here (E-50153) as well as by
CK_auth_User_AuthPolicyOverrideJson, because the CHECK's message names a constraint and this one can name the parameter.
Its CONTENT is not validated against a schema -- auth.udfResolveAuthPolicy reads the keys it knows and ignores the rest,
so an unknown key is inert rather than an error, which is what lets a project add one without a migration.

========================================================================================================================
Example Usage and Performance:

declare @UserId int;
exec auth.uspCreateUser @SessionTokenHash = 0x9F86..., @UserName = N'a.patel', @DisplayName = N'Anita Patel'
                      , @Email = N'a.patel@example.gov', @NewUserId = @UserId output;

One seek on UX_auth_User_UserName, one insert, one audit row.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-075
Description:
Created.  Phase 6.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspCreateUser
      @SessionTokenHash       VARBINARY (32)
    , @UserName               NVARCHAR (256)
    , @DisplayName            NVARCHAR (256)
    , @Email                  NVARCHAR (320) = NULL
    , @AuthPolicyOverrideJson NVARCHAR (MAX) = NULL
    , @IsPlatformAdmin        BIT            = 0
    , @NewUserId              INT            OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspCreateUser]')
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
          , @ChangeId       BIGINT          = NULL
          , @KeyJson        NVARCHAR (200)  = NULL
          , @Failure        NVARCHAR (2000) = NULL;

    -- Identifiers only. @Email is a person's contact detail and @AuthPolicyOverrideJson is configuration; neither is a
    -- credential, and neither is an identifier worth logging on every call. UI-16.
    SET @KeyParameters = CONCAT (N'UserName=', @UserName, N', HasEmail='
                               , CASE WHEN @Email IS NULL THEN N'0' ELSE N'1' END
                               , N', HasPolicyOverride='
                               , CASE WHEN @AuthPolicyOverrideJson IS NULL THEN N'0' ELSE N'1' END);

    SET @NewUserId = NULL;

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

        -- Section 14.1: this procedure establishes its own context and never trusts a previous call. UI-05.
        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        SET @ActorProfileId = TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT);
        SET @ActingTenantId = TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT);

        -- Section 11.4: at the ACTOR'S OWN tenant, because a user has no tenant of its own to demand it at.
        EXEC auth.uspDemandPermission @PermissionCode = N'User.Create', @TenantId = @ActingTenantId;

        SET @Actor = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N''), ORIGINAL_LOGIN ());

        -- TRIM on both, because a user name with a trailing space is a user name nobody can type twice.
        SET @UserName    = NULLIF (LTRIM (RTRIM (@UserName)),    N'');
        SET @DisplayName = NULLIF (LTRIM (RTRIM (@DisplayName)), N'');
        SET @Email       = NULLIF (LTRIM (RTRIM (@Email)),       N'');

        IF @UserName IS NULL OR @DisplayName IS NULL
        BEGIN
            SET @Failure = N'@UserName and @DisplayName are both required and neither may be blank or whitespace. '
                         + N'@DisplayName is what UI-01 obliges every screen to show, so a user created without one is '
                         + N'a user the header cannot name. No user was created.';
            ;THROW 50150, @Failure, 1;
        END;

        -- See the file header. The flag is auth.uspGrantPlatformAdmin's business, with its own permission and its own
        -- audit row, and refusing it here is cheaper than explaining later why it was ignored.
        IF @IsPlatformAdmin = 1
        BEGIN
            SET @Failure = N'@IsPlatformAdmin = 1 is refused at creation. D-05 makes platform administration an '
                         + N'authentication capability rather than a role, and INV-09 requires the flag ON TOP OF the '
                         + N'PLATFORM_ADMIN role -- so it is granted by auth.uspGrantPlatformAdmin, which demands '
                         + N'Platform.ManageApplications and requires the actor to hold the flag already. Create the '
                         + N'user, then grant it. No user was created.';
            ;THROW 50155, @Failure, 1;
        END;

        IF @AuthPolicyOverrideJson IS NOT NULL AND ISJSON (@AuthPolicyOverrideJson) = 0
        BEGIN
            SET @Failure = N'@AuthPolicyOverrideJson is not valid JSON. It is a per-user override of the tenant''s '
                         + N'authentication policy (section 7.2); pass NULL for no override rather than an empty '
                         + N'string. No user was created.';
            ;THROW 50153, @Failure, 1;
        END;

        -- Caught here so the caller gets a number to branch on rather than 2601 from UX_auth_User_UserName. The index
        -- is still what GUARANTEES it under a race; this is the courtesy.
        IF EXISTS (SELECT 1 FROM auth.[User] AS u WHERE u.UserName = @UserName AND u.IsDeleted = 0)
        BEGIN
            SET @Failure = N'That user name is already in use. User names are unique across the database and are '
                         + N'compared in the database collation, so they are case-insensitive: one typo apart is one '
                         + N'user, not two. No user was created.';
            ;THROW 50151, @Failure, 1;
        END;

        -- auditCreatedBy set EXPLICITLY: under the pooled application login ORIGINAL_LOGIN () is the application's own
        -- name, identical on every row. Section 14.4, F-02, UI-17.
        INSERT auth.[User] (UserName, DisplayName, Email, IsActive, IsPlatformAdmin, IsLockedOut, MustChangePassword
                        , AuthPolicyOverrideJson, auditCreatedBy, auditModifiedBy)
        VALUES (@UserName, @DisplayName, @Email, 1, 0, 0, 0, @AuthPolicyOverrideJson, @Actor, @Actor);

        SET @NewUserId = CAST (SCOPE_IDENTITY () AS INT);

        -- The trail. logs.DataChangeLog, NOT logs.AuthorizationChange: see the file header -- the authorization trail's
        -- ChangeType vocabulary is a closed set -- twenty-one values since G-43 -- and none of them is a
        -- user's lifecycle (E-50130).
        SET @KeyJson = CONCAT (N'{"UserId":', @NewUserId, N'}');

        EXEC logs.uspRecordDataChange
              @SchemaName          = N'auth'
            , @TableName           = N'User'
            , @Operation           = 'Insert'
            , @KeyJson             = @KeyJson
            , @ChangedColumnsJson  = NULL
            , @ActorUserProfileId  = @ActorProfileId
            , @DataChangeLogId     = @ChangeId OUTPUT;

        SET @Comments = CONCAT (N'Created UserId=', @NewUserId, N'. No credential, no profile, no grant. '
                              , N'DataChangeLogId=', @ChangeId, N'.');

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


-- *** 2. auth.uspUpdateUser ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspUpdateUser
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Changes a person's display name, email or authentication-policy override.  Demands User.Update at the actor's acting
tenant.  Every parameter but @SessionTokenHash and @UserId is optional: NULL means "leave this alone".

========================================================================================================================
Requirements and Key Dependencies:

auth.User, auth.uspSetSessionContext, auth.uspDemandPermission.  Granted to applicationRole.

========================================================================================================================
Notes:

@UserName IS NOT A PARAMETER.  Renaming a sign-in name breaks every external record of who did what -- a federated
issuer's mapping, a spreadsheet of accounts, an incident report from last year -- and it does it silently, because
nothing in this database stores the old name.  A person whose name has genuinely changed gets a new user and a
deactivated old one, which leaves both facts visible.  This is the same argument as auth.Role.RoleCode's immutability.

"NULL MEANS LEAVE ALONE" HAS ONE UNAMBIGUOUS EXCEPTION, AND IT NEEDED A SECOND PARAMETER.  @Email and
@AuthPolicyOverrideJson are both nullable columns, so "pass NULL to leave it" and "pass NULL to clear it" cannot both be
true.  @ClearEmail and @ClearPolicyOverride are the explicit clearing switches.  A sentinel string such as N'' would have
been shorter and would have made clearing an email a typo away from happening by accident.

@IsActive IS NOT HERE EITHER.  Deactivating a person is auth.uspDeactivateUser, which needs its own permission
(User.Deactivate, not User.Update) and its own guard for the last platform administrator.  Section 8.5.

========================================================================================================================
Example Usage and Performance:

exec auth.uspUpdateUser @SessionTokenHash = 0x9F86..., @UserId = 12, @DisplayName = N'Anita Patel-Shah';
exec auth.uspUpdateUser @SessionTokenHash = 0x9F86..., @UserId = 12, @ClearEmail = 1;

One seek on the primary key, one update.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-075
Description:
Created.  Phase 6.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspUpdateUser
      @SessionTokenHash       VARBINARY (32)
    , @UserId                 INT
    , @DisplayName            NVARCHAR (256) = NULL
    , @Email                  NVARCHAR (320) = NULL
    , @ClearEmail             BIT            = 0
    , @AuthPolicyOverrideJson NVARCHAR (MAX) = NULL
    , @ClearPolicyOverride    BIT            = 0
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspUpdateUser]')
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
          , @Failure        NVARCHAR (2000) = NULL
          , @ChangeId       BIGINT          = NULL;

    SET @KeyParameters = CONCAT (N'UserId=', @UserId
                               , N', SetDisplayName=',  CASE WHEN @DisplayName IS NULL THEN N'0' ELSE N'1' END
                               , N', SetEmail=',        CASE WHEN @Email IS NULL THEN N'0' ELSE N'1' END
                               , N', ClearEmail=',      @ClearEmail
                               , N', SetPolicy=',       CASE WHEN @AuthPolicyOverrideJson IS NULL THEN N'0' ELSE N'1' END
                               , N', ClearPolicy=',     @ClearPolicyOverride);

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

        SET @ActorProfileId = TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT);
        SET @ActingTenantId = TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT);

        EXEC auth.uspDemandPermission @PermissionCode = N'User.Update', @TenantId = @ActingTenantId;

        SET @Actor = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N''), ORIGINAL_LOGIN ());

        IF NOT EXISTS (SELECT 1 FROM auth.[User] AS u WHERE u.UserId = @UserId AND u.IsDeleted = 0)
        BEGIN
            SET @Failure = N'No such user, or it has been deleted. Nothing was changed.';
            ;THROW 50152, @Failure, 1;
        END;

        SET @DisplayName = NULLIF (LTRIM (RTRIM (@DisplayName)), N'');
        SET @Email       = NULLIF (LTRIM (RTRIM (@Email)),       N'');

        IF @AuthPolicyOverrideJson IS NOT NULL AND ISJSON (@AuthPolicyOverrideJson) = 0
        BEGIN
            SET @Failure = N'@AuthPolicyOverrideJson is not valid JSON. Pass @ClearPolicyOverride = 1 to remove an '
                         + N'existing override; passing an empty string is not how it is cleared. Nothing was changed.';
            ;THROW 50153, @Failure, 1;
        END;

        -- @ClearEmail and @ClearPolicyOverride win over the corresponding value parameters, because a caller that sends
        -- both has contradicted itself and "clear it" is the less destructive reading -- the value is still in the
        -- caller's hand and can be set on a second call, whereas a silently ignored clear is a value that stays.
        UPDATE u
           SET u.DisplayName            = COALESCE (@DisplayName, u.DisplayName)
             , u.Email                  = CASE WHEN @ClearEmail = 1 THEN NULL
                                               ELSE COALESCE (@Email, u.Email) END
             , u.AuthPolicyOverrideJson = CASE WHEN @ClearPolicyOverride = 1 THEN NULL
                                               ELSE COALESCE (@AuthPolicyOverrideJson, u.AuthPolicyOverrideJson) END
             -- Set explicitly so the acting PROFILE is recorded and not the pooled login. The AFTER UPDATE trigger
             -- honours a supplied value (section 14.4).
             , u.auditModifiedBy        = @Actor
          FROM auth.[User] AS u
         WHERE u.UserId    = @UserId
           AND u.IsDeleted = 0;

        -- A change to a person's details is not an authorization change, so logs.AuthorizationChange gets nothing here:
        -- section 18's trails are about who may do what, and widening one of them to "somebody was renamed" makes the
        -- authorization trail harder to read for no gain. logs.DataChangeLog is where a rename belongs, and the audit
        -- columns on the row already carry who and when.
        SET @Comments = CONCAT (N'Updated UserId=', @UserId, N'. Fields set: '
                              , CASE WHEN @DisplayName IS NOT NULL THEN N'DisplayName ' ELSE N'' END
                              , CASE WHEN @ClearEmail = 1 THEN N'Email(cleared) '
                                     WHEN @Email IS NOT NULL THEN N'Email ' ELSE N'' END
                              , CASE WHEN @ClearPolicyOverride = 1 THEN N'AuthPolicyOverrideJson(cleared) '
                                     WHEN @AuthPolicyOverrideJson IS NOT NULL THEN N'AuthPolicyOverrideJson '
                                     ELSE N'' END
                              , N'(none means every parameter was NULL, which is a legal no-op).');

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


-- *** 3. auth.uspDeactivateUser ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspDeactivateUser
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Stops a person signing in at all, everywhere, regardless of how many profiles they hold -- or puts them back.  Demands
User.Deactivate.  Sets auth.User.IsActive and never IsDeleted.

========================================================================================================================
Requirements and Key Dependencies:

auth.User, auth.UserSession, auth.uspSetSessionContext, auth.uspDemandPermission,
logs.uspRecordDataChange.  Granted to applicationRole.

========================================================================================================================
Notes:

IsActive, NOT IsDeleted, AND THE DIFFERENCE MATTERS TO EVERY TRAIL IN THE DATABASE.  A deleted user is a user whose
rows disappear from every view, so "who approved case 4471 in March" stops being answerable.  A deactivated user is a
user who cannot sign in and whose history is intact.  Section 6.3, P-07.  Nothing in this file sets IsDeleted on
auth.User at all, and nothing should.

EXISTING SESSIONS ARE ENDED IN THE SAME TRANSACTION.  auth.udfIsUserUsable already makes the next
auth.uspSetSessionContext call fail with E-50024, so the sessions would die at their next request anyway -- but "anyway"
is doing a lot of work in that sentence: a request in flight completes, and a background job holding a session does not
make a request for an hour.  Ending them here makes the deactivation immediate and observable rather than eventual.

THE LAST PLATFORM ADMINISTRATOR IS REFUSED -- E-50154.  The count is of LIVE, ACTIVE users with IsPlatformAdmin = 1, and
it is taken INSIDE the transaction so two concurrent deactivations cannot both pass it.  The alternative is a database
whose only administrative route back in is 900_bootstrap_first_admin.sql, which refuses to run once any profile exists
(section 16.3 clause 1) -- so there is no route back in, and the fix is a DBA with sysadmin and a hand-written UPDATE.
auth.uspRevokePlatformAdmin's E-50082 is the same guard on the other half of INV-09's pair.

DEACTIVATING YOURSELF IS PERMITTED.  It is not the same mistake as the last-administrator one: another administrator can
always reverse it, and refusing it would mean an administrator who discovers their own account is compromised cannot shut
it off.  @IsActive = 0 on the actor's own user ends the actor's own session too, which is the correct behaviour and worth
knowing before it surprises somebody.

========================================================================================================================
Example Usage and Performance:

exec auth.uspDeactivateUser @SessionTokenHash = 0x9F86..., @UserId = 12;                 -- stop them signing in
exec auth.uspDeactivateUser @SessionTokenHash = 0x9F86..., @UserId = 12, @IsActive = 1;   -- let them back in

One seek, one update, one range update on auth.UserSession, one audit row.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-075
Description:
Created.  Phase 6.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspDeactivateUser
      @SessionTokenHash VARBINARY (32)
    , @UserId           INT
    , @IsActive         BIT = 0
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspDeactivateUser]')
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
          , @IsPlatformAdmin BIT             = NULL
          , @WasActive       BIT             = NULL
          , @AdminsLeft      INT             = NULL
          , @SessionsEnded   INT             = 0
          , @Failure         NVARCHAR (2000) = NULL
          , @KeyJson         NVARCHAR (200)  = NULL
          , @ChangeId        BIGINT          = NULL;

    SET @KeyParameters = CONCAT (N'UserId=', @UserId, N', IsActive=', @IsActive);

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

        SET @ActorProfileId = TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT);
        SET @ActingTenantId = TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT);

        EXEC auth.uspDemandPermission @PermissionCode = N'User.Deactivate', @TenantId = @ActingTenantId;

        SET @Actor = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N''), ORIGINAL_LOGIN ());

        SELECT @WasActive       = u.IsActive
             , @IsPlatformAdmin = u.IsPlatformAdmin
          FROM auth.[User] AS u
         WHERE u.UserId    = @UserId
           AND u.IsDeleted = 0;

        IF @WasActive IS NULL
        BEGIN
            SET @Failure = N'No such user, or it has been deleted. Nothing was changed.';
            ;THROW 50152, @Failure, 1;
        END;

        -- Read inside the transaction so two concurrent deactivations cannot both see two administrators.
        IF @IsActive = 0 AND @IsPlatformAdmin = 1 AND @WasActive = 1
        BEGIN
            SELECT @AdminsLeft = COUNT (*)
              FROM auth.[User] AS u
             WHERE u.IsDeleted       = 0
               AND u.IsActive        = 1
               AND u.IsPlatformAdmin = 1
               AND u.UserId         <> @UserId;

            IF @AdminsLeft = 0
            BEGIN
                SET @Failure = N'This is the last active platform administrator, so deactivating it would leave the '
                             + N'database with no administrative route back in: 900_bootstrap_first_admin.sql refuses '
                             + N'to run once any profile exists (section 16.3), so the only remedy would be a DBA with '
                             + N'sysadmin and a hand-written UPDATE. Grant the flag to somebody else first -- '
                             + N'auth.uspGrantPlatformAdmin. Nothing was changed.';
                ;THROW 50154, @Failure, 1;
            END;
        END;

        UPDATE u
           SET u.IsActive        = @IsActive
             , u.auditModifiedBy = @Actor
          FROM auth.[User] AS u
         WHERE u.UserId    = @UserId
           AND u.IsDeleted = 0;

        -- End live sessions immediately rather than waiting for each one's next request to fail with E-50024. See the
        -- header. Only on the deactivating direction: reactivating a user does not resurrect their old sessions, and
        -- should not -- they sign in again.
        IF @IsActive = 0
        BEGIN
            UPDATE s
               SET s.EndedUtc        = SYSUTCDATETIME ()
                 , s.EndReason       = 'UserDeactivated'
                 , s.auditModifiedBy = @Actor
              FROM auth.UserSession AS s
             WHERE s.UserId    = @UserId
               AND s.EndedUtc IS NULL
               AND s.IsDeleted = 0;

            SET @SessionsEnded = @@ROWCOUNT;
        END;

        -- logs.DataChangeLog, not logs.AuthorizationChange: see the file header. ChangedColumnsJson names IsActive and
        -- nothing else, because that is the one column that changed and the whole meaning of the call.
        SET @KeyJson = CONCAT (N'{"UserId":', @UserId, N'}');

        EXEC logs.uspRecordDataChange
              @SchemaName          = N'auth'
            , @TableName           = N'User'
            , @Operation           = 'Update'
            , @KeyJson             = @KeyJson
            , @ChangedColumnsJson  = N'["IsActive"]'
            , @ActorUserProfileId  = @ActorProfileId
            , @DataChangeLogId     = @ChangeId OUTPUT;

        SET @Comments = CONCAT (N'UserId=', @UserId, N' IsActive ', @WasActive, N' -> ', @IsActive
                              , N'. Sessions ended: ', @SessionsEnded
                              , N'. DataChangeLogId=', @ChangeId, N'.');

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


-- *** 4. auth.uspGetUser ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspGetUser
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

One person record, with the counts a user-administration screen needs beside it.  Demands User.Read.  Error-only
instrumented -- it reads.

========================================================================================================================
Requirements and Key Dependencies:

auth.User, auth.UserProfile, auth.UserCredential, auth.UserFederatedIdentity, auth.UserMfaFactor,
auth.uspSetSessionContext, auth.uspDemandPermission.  Granted to applicationRole.

========================================================================================================================
Notes:

IT RETURNS WHAT EXISTS, NEVER WHAT IT IS.  HasLocalCredential, FederatedIdentityCount and ConfirmedMfaFactorCount are
counts and flags.  No VerifierPhc, no KeyReference, no SecretCiphertext, no subject id.  A user-administration screen
needs to know that a person has a password and two factors; it never needs the bytes, and a procedure that returned them
would put them in a connection buffer, an ORM's change tracker and a developer's debugger. Section 6.2, UI-16.

MustChangePassword, IsLockedOut AND LockoutEndUtc ARE RETURNED EVEN THOUGH auth.uspUpdateUser CANNOT SET THEM.  Reading
account state is what a support desk does before it does anything else, and the asymmetry is deliberate: see and
diagnose here, act through 110's credential procedures.

E-50152 COVERS "NO SUCH USER" AND NOTHING ELSE, because a user is not tenant-scoped -- there is no "not yours" case to
conflate it with.  That is unlike the dbo procedures, where E-50201 deliberately merges the two.

========================================================================================================================
Example Usage and Performance:

exec auth.uspGetUser @SessionTokenHash = 0x9F86..., @UserId = 12;

One seek on the primary key plus four small aggregates, all on indexed foreign keys.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-075
Description:
Created.  Phase 6.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspGetUser
      @SessionTokenHash VARBINARY (32)
    , @UserId           INT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 error-only instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspGetUser]')
          , @KeyParameters  NVARCHAR (MAX) = NULL
          , @ContextMessage NVARCHAR (MAX) = NULL
          , @DynamicSql     NVARCHAR (MAX) = NULL
          , @ErrorMsg       NVARCHAR (MAX) = NULL
          , @ErrorProc      NVARCHAR (300) = NULL
          , @ErrorNumber    INT            = NULL
          , @ErrorLine      INT            = NULL;

    DECLARE @ActingTenantId INT             = NULL
          , @Failure        NVARCHAR (2000) = NULL;

    SET @KeyParameters = CONCAT (N'UserId=', @UserId);
    SET @ContextMessage = N'Error-only instrumented read: no start row is opened, so @ExecutionLogId is NULL by design.';

    BEGIN TRY

        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        SET @ActingTenantId = TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT);

        EXEC auth.uspDemandPermission @PermissionCode = N'User.Read', @TenantId = @ActingTenantId;

        IF NOT EXISTS (SELECT 1 FROM auth.[User] AS u WHERE u.UserId = @UserId AND u.IsDeleted = 0)
        BEGIN
            SET @Failure = N'No such user, or it has been deleted.';
            ;THROW 50152, @Failure, 1;
        END;

        -- =========================================================================================
        -- ===== The procedure's own work starts here. Everything above and below is boilerplate. ==
        -- =========================================================================================

        SELECT
              u.UserId
            , u.UserName
            , u.DisplayName
            , u.Email
            , u.IsActive
            , u.IsPlatformAdmin
            , u.IsLockedOut
            , u.LockoutEndUtc
            , u.MustChangePassword
            , HasPolicyOverride        = CASE WHEN u.AuthPolicyOverrideJson IS NULL THEN 0 ELSE 1 END
            -- Flags and counts, never the secrets themselves. See the header.
            -- 'Password' is the ONLY value CK_auth_UserCredential_CredentialType permits today. The column exists so a
            -- project can add a type without a schema change to every reader; the CHECK exists so that adding one is a
            -- deliberate act. Writing 'Local' here -- which the first draft did -- returns 0 for everybody, silently.
            , HasLocalCredential       = CASE WHEN EXISTS (SELECT 1 FROM auth.UserCredential AS c
                                                            WHERE c.UserId = u.UserId AND c.IsDeleted = 0
                                                              AND c.CredentialType = 'Password')
                                              THEN 1 ELSE 0 END
            , FederatedIdentityCount   = (SELECT COUNT (*) FROM auth.UserFederatedIdentity AS f
                                           WHERE f.UserId = u.UserId AND f.IsDeleted = 0)
            , ConfirmedMfaFactorCount  = (SELECT COUNT (*) FROM auth.UserMfaFactor AS m
                                           WHERE m.UserId = u.UserId AND m.IsDeleted = 0 AND m.IsConfirmed = 1)
            , ActiveProfileCount       = (SELECT COUNT (*) FROM auth.UserProfile AS p
                                           WHERE p.UserId = u.UserId AND p.IsDeleted = 0 AND p.IsActive = 1)
            , TotalProfileCount        = (SELECT COUNT (*) FROM auth.UserProfile AS p
                                           WHERE p.UserId = u.UserId AND p.IsDeleted = 0)
            , u.auditCreatedBy
            , u.auditCreatedDateUtc
            , u.auditModifiedBy
            , u.auditModifiedDateUtc
          FROM auth.[User] AS u
         WHERE u.UserId    = @UserId
           AND u.IsDeleted = 0;

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


-- *** 5. auth.uspSearchUsers ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspSearchUsers
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

A paged, sorted list of person records for a user-administration grid.  Demands User.Read.  Error-only instrumented.

========================================================================================================================
Requirements and Key Dependencies:

auth.User, auth.UserProfile, auth.uspSetSessionContext, auth.uspDemandPermission.  Granted to applicationRole.

========================================================================================================================
Notes:

@SortBy IS A WHITELIST AND THERE IS NO DYNAMIC SQL.  One CASE per sortable column in the ORDER BY, because a single CASE
with branches of different types forces them to converge -- an int and a datetime2 under one CASE is a conversion error
at runtime or a silent implicit conversion that discards the index.  @DynamicSql stays NULL for the whole procedure
because nothing is built.

@Search MATCHES UserName, DisplayName AND Email WITH A LEADING WILDCARD, which is a SCAN, and that is an accepted cost
rather than an oversight.  auth.User is a table of people: five thousand rows in a large deployment, not five million.
A trigram index or a full-text catalogue to avoid a scan over five thousand rows would be a second thing to keep in step
for no measurable gain.  G-28 records the threshold at which that stops being true.

@TenantId NARROWS TO PEOPLE WITH A PROFILE AT OR BENEATH THAT TENANT, and it is OPTIONAL rather than mandatory.  Section
11.4 makes User.Read explicitly not tenant-scoped, so a mandatory filter here would contradict the design; an optional
one gives the county administrator's screen the list it actually wants without pretending the permission is narrower
than it is.  It walks auth.TenantClosure, so "at or beneath" includes the whole subtree.

THE DETERMINISTIC TIEBREAK IS NOT OPTIONAL.  Without ORDER BY ... , u.UserId two calls for the same page can return
different rows, and a grid silently drops or duplicates records across pages.

========================================================================================================================
Example Usage and Performance:

exec auth.uspSearchUsers @SessionTokenHash = 0x9F86..., @Search = N'patel';
exec auth.uspSearchUsers @SessionTokenHash = 0x9F86..., @TenantId = 4, @IncludeInactive = 1, @PageNumber = 2;

One scan of auth.User when @Search is supplied; a seek otherwise.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-075
Description:
Created.  Phase 6.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspSearchUsers
      @SessionTokenHash VARBINARY (32)
    , @Search           NVARCHAR (256) = NULL
    , @TenantId         INT            = NULL
    , @IncludeInactive  BIT            = 0
    , @PageNumber       INT            = 1
    , @PageSize         INT            = 50
    , @SortBy           NVARCHAR (30)  = N'UserName'
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspSearchUsers]')
          , @KeyParameters  NVARCHAR (MAX) = NULL
          , @ContextMessage NVARCHAR (MAX) = NULL
          , @DynamicSql     NVARCHAR (MAX) = NULL
          , @ErrorMsg       NVARCHAR (MAX) = NULL
          , @ErrorProc      NVARCHAR (300) = NULL
          , @ErrorNumber    INT            = NULL
          , @ErrorLine      INT            = NULL;

    DECLARE @ActingTenantId INT = NULL;

    -- The search TERM is a person's name fragment. It is not a credential, but it is somebody's name on every call, so
    -- only its length is recorded. UI-16's spirit: log what you need to diagnose, not what you happen to have.
    SET @KeyParameters = CONCAT (N'SearchLength=',  COALESCE (LEN (@Search), 0)
                               , N', TenantId=',    @TenantId
                               , N', IncludeInactive=', @IncludeInactive
                               , N', PageNumber=',  @PageNumber
                               , N', PageSize=',    @PageSize
                               , N', SortBy=',      @SortBy);

    SET @ContextMessage = N'Error-only instrumented read: no start row is opened, so @ExecutionLogId is NULL by design.';

    BEGIN TRY

        IF @PageNumber < 1
        BEGIN
            ;THROW 50000, N'@PageNumber must be 1 or greater.', 1;
        END;

        IF @PageSize NOT BETWEEN 1 AND 500
        BEGIN
            ;THROW 50000, N'@PageSize must be between 1 and 500.', 1;
        END;

        IF @SortBy NOT IN (N'UserName', N'DisplayName', N'Email', N'auditModifiedDateUtc')
        BEGIN
            ;THROW 50000, N'@SortBy must be one of UserName, DisplayName, Email, auditModifiedDateUtc.', 1;
        END;

        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        SET @ActingTenantId = TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT);

        EXEC auth.uspDemandPermission @PermissionCode = N'User.Read', @TenantId = @ActingTenantId;

        -- =========================================================================================
        -- ===== The procedure's own work starts here. Everything above and below is boilerplate. ==
        -- =========================================================================================

        SELECT
              u.UserId
            , u.UserName
            , u.DisplayName
            , u.Email
            , u.IsActive
            , u.IsPlatformAdmin
            , u.IsLockedOut
            , ActiveProfileCount = (SELECT COUNT (*) FROM auth.UserProfile AS p
                                     WHERE p.UserId = u.UserId AND p.IsDeleted = 0 AND p.IsActive = 1)
            , u.auditModifiedDateUtc
            -- One window function over the filtered set, so the grid gets its total without a second round trip and
            -- without a second copy of the WHERE clause to keep in step.
            , TotalRows = COUNT (*) OVER ()
          FROM auth.[User] AS u
         WHERE u.IsDeleted = 0
           AND (@IncludeInactive = 1 OR u.IsActive = 1)
           AND (@Search IS NULL
                OR u.UserName    LIKE N'%' + @Search + N'%'
                OR u.DisplayName LIKE N'%' + @Search + N'%'
                OR u.Email       LIKE N'%' + @Search + N'%')
           AND (@TenantId IS NULL
                OR EXISTS (SELECT 1
                             FROM auth.UserProfile  AS p
                             JOIN auth.TenantClosure AS tc ON tc.DescendantTenantId = p.TenantId
                                                          AND tc.IsDeleted           = 0
                            WHERE p.UserId              = u.UserId
                              AND p.IsDeleted           = 0
                              AND tc.AncestorTenantId   = @TenantId))
         ORDER BY CASE WHEN @SortBy = N'UserName'    THEN u.UserName    END
                , CASE WHEN @SortBy = N'DisplayName' THEN u.DisplayName END
                , CASE WHEN @SortBy = N'Email'       THEN u.Email       END
                , CASE WHEN @SortBy = N'auditModifiedDateUtc' THEN u.auditModifiedDateUtc END
                -- Deterministic tiebreak. Without it a grid drops or duplicates rows across pages.
                , u.UserId
        OFFSET (@PageNumber - 1) * @PageSize ROWS
         FETCH NEXT @PageSize ROWS ONLY;

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


-- *** 6. Descriptions ***
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
      (N'uspCreateUser'
     , N'Creates a person record. Demands User.Create at the ACTOR''S OWN acting tenant, because a user has no tenant '
     + N'of its own -- section 11.4 calls this deliberately weaker, since a person with no profile has no access to '
     + N'anything. Creates no credential, no profile and no grant. Refuses @IsPlatformAdmin = 1 with E-50155: D-05 '
     + N'makes the flag an authentication capability and auth.uspGrantPlatformAdmin is where it is set. E-50150 empty '
     + N'name, E-50151 name in use, E-50153 bad policy JSON.')
    , (N'uspUpdateUser'
     , N'Changes a person''s display name, email or authentication-policy override. Demands User.Update. @UserName is '
     + N'deliberately NOT a parameter -- renaming a sign-in name breaks every external record of who did what, '
     + N'silently. Neither are MustChangePassword, IsLockedOut or LockoutEndUtc: those belong to 110''s credential '
     + N'path, and a User.Update holder who could clear a lockout by hand would defeat the throttle. NULL means leave '
     + N'alone; @ClearEmail and @ClearPolicyOverride are the explicit clearing switches. E-50152, E-50153.')
    , (N'uspDeactivateUser'
     , N'Stops a person signing in at all, everywhere, or puts them back. Demands User.Deactivate. Sets IsActive and '
     + N'NEVER IsDeleted -- a deleted user takes "who approved this in March" with them (section 6.3, P-07). Ends '
     + N'live sessions in the same transaction rather than waiting for each one''s next request to fail with E-50024. '
     + N'Refuses the last active platform administrator with E-50154, because 900_bootstrap_first_admin.sql will not '
     + N'run once a profile exists, so there would be no route back in. Deactivating yourself IS permitted.')
    , (N'uspGetUser'
     , N'One person record plus the counts a user-administration screen needs: HasLocalCredential, '
     + N'FederatedIdentityCount, ConfirmedMfaFactorCount, profile counts. Returns what EXISTS, never what it IS -- no '
     + N'verifier, no key reference, no ciphertext, no subject id (section 6.2, UI-16). Demands User.Read. Error-only '
     + N'instrumented. E-50152 covers "no such user" and nothing else, because a user is not tenant-scoped and there '
     + N'is no "not yours" case to conflate it with.')
    , (N'uspSearchUsers'
     , N'A paged, sorted list for a user-administration grid. Demands User.Read. @SortBy is a whitelist and there is '
     + N'no dynamic SQL. @Search matches user name, display name and email with a leading wildcard -- a scan, and an '
     + N'accepted one: auth.User is a table of people, thousands not millions (G-28). @TenantId narrows to people with '
     + N'a profile at or beneath that tenant by walking the closure, and is optional because section 11.4 makes '
     + N'User.Read explicitly not tenant-scoped. TotalRows comes from COUNT (*) OVER () so the grid needs one round '
     + N'trip. Error-only instrumented.');

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


-- *** 7. Grants ***
-- All five, to applicationRole.  EXECUTE on the procedure and nothing on the tables: ownership chaining carries the
-- reads and writes, so applicationRole never needs SELECT on auth.User (INV-11).
IF DATABASE_PRINCIPAL_ID (N'applicationRole') IS NOT NULL
BEGIN
    GRANT EXECUTE ON auth.uspCreateUser     TO applicationRole;
    GRANT EXECUTE ON auth.uspUpdateUser     TO applicationRole;
    GRANT EXECUTE ON auth.uspDeactivateUser TO applicationRole;
    GRANT EXECUTE ON auth.uspGetUser        TO applicationRole;
    GRANT EXECUTE ON auth.uspSearchUsers    TO applicationRole;

    PRINT N'Granted EXECUTE on the five user procedures to applicationRole. No table permission is granted: ownership '
        + N'chaining carries the reads (INV-11).';
END
ELSE
BEGIN
    PRINT N'applicationRole does not exist, so no grants were made. Run database/005_schemas_and_roles.sql and then '
        + N're-run this file.';
END
GO


-- *** 8. Closing report ***
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
  FROM (VALUES (N'uspCreateUser',     N'User.Create at the actor''s own tenant -- section 11.4. Refuses @IsPlatformAdmin = 1 (E-50155).')
             , (N'uspUpdateUser',     N'User.Update. No @UserName, no lockout columns, no @IsActive -- see the description.')
             , (N'uspDeactivateUser', N'User.Deactivate. IsActive not IsDeleted; ends live sessions; E-50154 guards the last admin.')
             , (N'uspGetUser',        N'User.Read. Error-only instrumented. Counts and flags, never secrets.')
             , (N'uspSearchUsers',    N'User.Read. Whitelisted sort, no dynamic SQL, COUNT (*) OVER () for the grid total.')
       ) AS x (ProcName, Detail);

-- The one thing a reader of this file will want checked mechanically, because it is the point of the header.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 0 THEN 4 ELSE 1 END
     , CASE WHEN COUNT (*) = 0 THEN 'OK' ELSE 'VIOLATED' END
     , N'No procedure here touches a credential table'
     , CONCAT (COUNT (*), N' reference(s) to auth.UserCredential, auth.UserFederatedIdentity or auth.UserMfaFactor '
             , N'outside auth.uspGetUser''s EXISTS and COUNT expressions. Must be 0: creating a person and giving them '
             + N'a way to prove they are that person are two facts with two lifecycles, and 110/112 own the second.')
  FROM sys.sql_expression_dependencies AS d
  JOIN sys.objects                     AS o ON o.object_id = d.referencing_id
 WHERE o.schema_id = SCHEMA_ID (N'auth')
   AND o.name IN (N'uspCreateUser', N'uspUpdateUser', N'uspDeactivateUser', N'uspSearchUsers')
   AND d.referenced_entity_name IN (N'UserCredential', N'UserFederatedIdentity', N'UserMfaFactor');

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 5 THEN 4 ELSE 2 END
     , CASE WHEN COUNT (*) = 5 THEN 'OK' ELSE 'INCOMPLETE' END
     , N'EXECUTE granted to applicationRole'
     , CONCAT (COUNT (*), N' of 5. Zero means 005_schemas_and_roles.sql has not run; anything between is a partial '
             , N'deployment and the application will fail on whichever one is missing.')
  FROM sys.database_permissions AS dp
  JOIN sys.objects              AS o ON o.object_id = dp.major_id
 WHERE dp.grantee_principal_id = DATABASE_PRINCIPAL_ID (N'applicationRole')
   AND dp.permission_name      = N'EXECUTE'
   AND dp.state                = N'G'
   AND o.schema_id             = SCHEMA_ID (N'auth')
   AND o.name IN (N'uspCreateUser', N'uspUpdateUser', N'uspDeactivateUser', N'uspGetUser', N'uspSearchUsers');

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 5 THEN 4 ELSE 2 END
     , CASE WHEN COUNT (*) = 5 THEN 'OK' ELSE 'INCOMPLETE' END
     , N'MS_Description on the user procedures'
     , CONCAT (COUNT (*), N' of 5. Conventions rule 4.')
  FROM sys.extended_properties AS ep
  JOIN sys.objects             AS o ON o.object_id = ep.major_id
 WHERE ep.name     = N'MS_Description'
   AND ep.minor_id = 0
   AND o.schema_id = SCHEMA_ID (N'auth')
   AND o.name IN (N'uspCreateUser', N'uspUpdateUser', N'uspDeactivateUser', N'uspGetUser', N'uspSearchUsers');

IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
    PRINT N'User procedures: PROBLEMS found. Read the report below.';
ELSE
    PRINT N'User procedures: no problems found.';

PRINT N'';

SELECT Severity, Status, Item, Detail
  FROM @Report
 ORDER BY Severity, RowNo;
GO
