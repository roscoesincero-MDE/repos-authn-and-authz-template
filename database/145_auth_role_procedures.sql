/***********************************************************************************************************************
Script:         145_auth_role_procedures.sql
Purpose:        The role surface: auth.uspDefineRole, auth.uspUpdateRole, auth.uspSetRolePermissions,
                auth.uspAssignRoleToProfile, auth.uspRevokeRoleFromProfile and auth.uspListAssignableRoles.
Target:         SQL Server 2022.
Run as:         db_owner in the target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/145_auth_role_procedures.sql
Idempotent:     Yes.  CREATE OR ALTER throughout, and every grant guarded on DATABASE_PRINCIPAL_ID.
Depends on:     050_auth_permission.sql, 055_auth_role.sql, 060_auth_profile_role.sql, 065_auth_effective_permission.sql,
                100_auth_functions.sql, 105_auth_session_procedures.sql, 150_auth_query_procedures.sql
                (auth.uspDemandPermission), 165_logs_procedures.sql, scripts/logExecutionLogging.sql,
                templates/extended-properties.sql.
Implements:     T-079, T-080, T-081.  DES-AUTH-001 sections 8.1 to 8.6, 11.1 to 11.3, 14.1 to 14.5, 15.5.
                See docs/10-database-authn-authz-design.md.
To retarget:    Pass it per run:  sqlcmd -d <database> -v DbName=<database>.  There is no in-file default.

A ROLE IS A NAMED BUNDLE OF PERMISSIONS THAT BELONGS TO A TENANT
--------------------------------------------------------------
Section 8.1: auth.Role.OwnerTenantId is not decoration.  INV-04 makes a role grantable at its owner tenant and anywhere
BENEATH it and nowhere else, so choosing the owner IS choosing the role's reach -- which is why E-50176 refuses an owner
tenant the actor has no authority over, and why E-50042 refuses a grant whose scope the owner does not cover.  A role
owned at the root is a role the whole deployment can use; a role owned at one county is that county's business.

UX_auth_Role_Code is unique on (ApplicationId, OwnerTenantId, RoleCode) among live rows, so two counties may each define
REVIEWER and mean different things by it.  E-50170 is that collision and it is scoped to the owner on purpose.

INV-05 IS FOUR CLAUSES AND THEY ARE FOUR ERROR NUMBERS
----------------------------------------------------
Section 11.1 governs auth.uspAssignRoleToProfile and Appendix B gives each clause its own number, because a
four-conditions-in-one-message refusal is a refusal the administrator cannot act on:

  E-50040  the actor must hold Authz.RoleAssign at the TARGET PROFILE'S tenant, or above it       -- clause 1
  E-50041  the actor must hold Authz.RoleAssign at the REQUESTED SCOPE, or above it               -- clause 2
  E-50042  the role's OWNER tenant must cover the requested scope                                -- clause 3, INV-04
  E-50043  the role and the target profile must belong to the same application                   -- clause 4

Clauses 1 and 2 are both tested with auth.udfHasPermission and both write logs.AuthorizationDenial by hand, exactly as
auth.uspCreateProfile does for E-50045: auth.uspDemandPermission can only throw E-50030, so delegating would make four
registered numbers unreachable and collapse four different administrative mistakes into one.  The security decision is
still entirely auth.udfHasPermission's.

Clause 2 is the one that matters most and the one that looks most redundant.  Without it, an actor holding
Authz.RoleAssign at one county could grant a root-owned role at the ROOT scope to a profile in their own county, which
is a privilege escalation dressed as a local administrative act.

A GRANTOR NEED NOT HOLD WHAT THEY GRANT
--------------------------------------
Section 11.2, and it is deliberate.  Authz.RoleAssign is the authority to confer, not a claim to the contents: a records
manager who may appoint approvers need not be an approver.  So nothing in this file compares the role's permission list
against the actor's own, and nothing should.  What bounds the damage is not the grantor's own access but the two scope
clauses above -- they are why this is delegation rather than escalation.

THE SELF-GRANT GUARD, AND THE SWITCH THAT TURNS IT OFF
----------------------------------------------------
INV-06 (section 11.3): a profile may not grant a role to a profile of its OWN user, because the obvious way to escalate
is to put on an administrative hat and hand your other hat something better.  E-50044.  It is overridable by
config.ApplicationSetting key Authz.AllowSelfGrant, which ships 0, because a single-administrator deployment otherwise
cannot give itself a second hat at all.

G-08 records what this is NOT: four-eyes approval.  A second administrator is not required for anything here, and the
design says so rather than implying a control it does not implement.  The guard catches the careless case and the audit
trail catches the rest.

A REVOKED GRANT IS RESURRECTED IN PLACE, NEVER RE-INSERTED
--------------------------------------------------------
UX_auth_UserProfileRole_Grant is unique on (UserProfileId, RoleId, ScopeTenantId) FILTERED on IsDeleted = 0.  A
soft-deleted grant therefore still occupies the tuple, and a second INSERT of the same triple lands on Msg 2601 rather
than creating a second row (section 8.6).  auth.uspAssignRoleToProfile UPDATEs the dead row back to life instead, and
clears auditDeletedBy and auditDeletedDateUtc IN THE SAME STATEMENT -- CK_auth_UserProfileRole_DeletedPair is evaluated
before the AFTER UPDATE trigger runs, so a resurrection that leaves either column set fails the CHECK, not the trigger.

E-50179 is the other half: when the grant is ALREADY LIVE the procedure refuses rather than re-stamping GrantedUtc.
Re-stamping would lose the date the authority was actually conferred, which is the one fact the trail exists to hold.

SYSTEM ROLES: WHAT MAY CHANGE, WHAT MAY NOT, AND WHO SAYS SO TWICE
----------------------------------------------------------------
INV-10 (section 8.3): a role with IsSystemRole = 1 has its code, its flag and its existence fixed, and its permission
list is Appendix A rather than a runtime decision.  RoleName and RoleDescription stay editable -- a deployment may want
PLATFORM_ADMIN to read "System Administrator" on screen.

It is enforced TWICE on purpose.  auth.uspUpdateRole raises E-50172 so the message can name the role and say which
column was refused; auth.trg_au_updt_Role raises E-50012 so the rule also holds for the seed script and for an
administrator holding SSMS.  auth.uspSetRolePermissions refuses a system role OUTRIGHT with E-50172: there is no partial
version of "this role's permissions are the design's".

EVERY CHANGE TO A GRANT OR A ROLE'S PERMISSIONS REBUILDS THE DERIVED SCOPE, INSIDE THE TRANSACTION
------------------------------------------------------------------------------------------------
auth.ProfilePermissionScope is derived (section 10.3) and holds no history, so whoever changes the inputs owes the
rebuild.  Granting or revoking one grant rebuilds ONE profile; changing a role's permission list rebuilds EVERY profile
holding that role, which is why auth.uspSetRolePermissions is the one procedure here that can be slow and why its
closing comment reports how many profiles it touched.  Leaving it to a nightly job would mean an administrator watching
a screen that still shows yesterday's answer.

CONTEXT AND AUTHORITY COME BEFORE THE TRANSACTION IN EVERY PROCEDURE HERE
-----------------------------------------------------------------------
BL-042: a denial row written inside a transaction that the refusal then rolls back is a denial nobody can see.  Section
9 orders the permission check ahead of the transaction for exactly that reason.  G-31 records that 125 and 130 do it the
other way round and owe the same correction; 140 and this file do it correctly.

RoleCode'S GRAMMAR IS A CHECK CONSTRAINT AND APPENDIX B HAS NO NUMBER FOR VIOLATING IT
------------------------------------------------------------------------------------
CK_auth_Role_RoleCode demands uppercase A-Z, 0-9 and underscore, trimmed and non-empty.  auth.uspDefineRole NORMALISES
what it can -- it trims and uppercases, because both are mechanical -- and lets the constraint refuse the rest, which
surfaces as Msg 547 naming the constraint.  That is a worse error message than this file gives anywhere else, and the
reason is that Appendix B's registry is closed ("adding a number means adding it here first") and registers nothing for
a malformed parameter.  G-32 records it and proposes E-50180.
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

IF OBJECT_ID (N'auth.Role', N'U') IS NULL
   OR OBJECT_ID (N'auth.RolePermission', N'U') IS NULL
   OR OBJECT_ID (N'auth.Permission', N'U') IS NULL
   OR OBJECT_ID (N'auth.UserProfileRole', N'U') IS NULL
BEGIN
    DECLARE @MsgId NVARCHAR (2000) =
        N'One of auth.Role, auth.RolePermission, auth.Permission or auth.UserProfileRole is missing. Run '
      + N'database/050_auth_permission.sql, database/055_auth_role.sql and database/060_auth_profile_role.sql first.';

    THROW 50000, @MsgId, 1;
END
GO

IF OBJECT_ID (N'auth.udfHasPermission', N'FN') IS NULL
   OR OBJECT_ID (N'auth.udfIsTenantUsable', N'FN') IS NULL
   OR OBJECT_ID (N'auth.uspRebuildProfilePermissionScope', N'P') IS NULL
BEGIN
    DECLARE @MsgFn NVARCHAR (2000) =
        N'auth.udfHasPermission, auth.udfIsTenantUsable or auth.uspRebuildProfilePermissionScope is missing. Run '
      + N'database/100_auth_functions.sql and database/065_auth_effective_permission.sql first: INV-05''s clauses are '
      + N'tested with the function and every grant change rebuilds the derived scope, and neither is optional.';

    THROW 50000, @MsgFn, 1;
END
GO

IF OBJECT_ID (N'logs.uspStartExecutionLogging', N'P') IS NULL
   OR OBJECT_ID (N'logs.uspRecordExecutionError', N'P') IS NULL
   OR OBJECT_ID (N'logs.uspRecordAuthorizationChange', N'P') IS NULL
   OR OBJECT_ID (N'logs.uspRecordAuthorizationDenial', N'P') IS NULL
BEGIN
    DECLARE @MsgLog NVARCHAR (2000) =
        N'The rule 8 instrumentation procedures or the authorization trail procedures are missing. Run '
      + N'scripts/logExecutionLogging.sql and database/165_logs_procedures.sql first.';

    THROW 50000, @MsgLog, 1;
END
GO


-- *** 1. auth.uspDefineRole ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspDefineRole
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Defines a new role owned by one tenant.  Requires Authz.RoleDefine at the owner tenant or above it (E-50176), because
INV-04 makes the owner the role's reach.  Creates the role with NO permissions: auth.uspSetRolePermissions fills it.

========================================================================================================================
Requirements and Key Dependencies:

auth.Role, auth.Tenant, auth.udfHasPermission, auth.udfIsTenantUsable, auth.uspSetSessionContext,
logs.uspRecordAuthorizationDenial, logs.uspRecordAuthorizationChange.  Granted to applicationRole.

========================================================================================================================
Notes:

@ApplicationId IS NOT A PARAMETER: IT IS READ OFF THE OWNER TENANT.  A role whose application differs from its owner's
would be ungrantable to anybody -- E-50043 refuses exactly that pairing at assignment time -- so accepting it as a
parameter would only create a way to build a role that cannot be used.  auth.Tenant.ApplicationId is the answer and
there is no second opinion to have.

THE ROLE IS CREATED EMPTY AND THAT IS NOT AN OVERSIGHT.  A role with permissions attached at creation would need the
payload validated, the scope rebuilt and the trail written in the same call, and the first two of those are
auth.uspSetRolePermissions' whole job.  Defining a role grants nobody anything, so the empty role is harmless and the
two-step is what makes each step reviewable.

@IsAssignable DEFAULTS TO 1.  Section 8.2: setting it to 0 later freezes new grants without disturbing existing ones
(E-50047 at assignment).  A role defined with 0 is a definition somebody is still drafting.

E-50176 IS TESTED WITH auth.udfHasPermission AND THE DENIAL IS WRITTEN BY HAND, like every other registered authority
number in this file and in 140.  See the file header.

========================================================================================================================
Example Usage and Performance:

declare @RoleId int;
exec auth.uspDefineRole @SessionTokenHash = 0x9F86..., @OwnerTenantId = 7, @RoleCode = N'REVIEWER'
                      , @RoleName = N'Case Reviewer', @NewRoleId = @RoleId output;

One scope test, two seeks, one insert, one trail row.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-079
Description:
Created.  Phase 6.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspDefineRole
      @SessionTokenHash VARBINARY (32)
    , @OwnerTenantId    INT
    , @RoleCode         NVARCHAR (100)
    , @RoleName         NVARCHAR (200)
    , @RoleDescription  NVARCHAR (1000) = NULL
    , @IsAssignable     BIT             = 1
    , @NewRoleId        INT             OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspDefineRole]')
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
          , @ApplicationId  INT             = NULL
          , @RawRoleCode    NVARCHAR (100)  = @RoleCode
          , @ChangeId       BIGINT          = NULL
          , @DenialId       BIGINT          = NULL
          , @DetailJson     NVARCHAR (400)  = NULL
          , @Failure        NVARCHAR (2000) = NULL;

    SET @KeyParameters = CONCAT (N'OwnerTenantId=', @OwnerTenantId, N', RoleCode=', @RoleCode
                               , N', IsAssignable=', @IsAssignable);

    SET @NewRoleId = NULL;

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

        -- Context and authority BEFORE the transaction, so the denial row survives the refusal. BL-042, G-31.
        -- Section 14.1: this procedure establishes its own context and never trusts a previous call. UI-05.
        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        SET @ActorProfileId = TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT);
        SET @ActingTenantId = TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT);

        -- auth.udfHasPermission expands every grant DOWN the tree through auth.TenantClosure, so this one call is the
        -- ancestor-or-self test E-50176 describes -- no hand-written closure walk, which would be a second
        -- implementation of the same rule, drifting from the first.
        IF auth.udfHasPermission (N'Authz.RoleDefine', @OwnerTenantId) = 0
        BEGIN
            SET @DetailJson = CONCAT (N'{"procedure":"auth.uspDefineRole","ownerTenantId":', @OwnerTenantId
                                    , N',"error":50176}');

            EXEC logs.uspRecordAuthorizationDenial
                  @PermissionCode        = N'Authz.RoleDefine'
                , @TenantId              = @OwnerTenantId
                , @UserProfileId         = @ActorProfileId
                , @ObjectName            = N'auth.uspDefineRole'
                , @DetailJson            = @DetailJson
                , @AuthorizationDenialId = @DenialId OUTPUT;

            SET @Failure = N'The proposed owner tenant is outside your authority: you hold Authz.RoleDefine at no '
                         + N'tenant at or above it. INV-04 makes a role grantable anywhere at or below its owner, so '
                         + N'choosing the owner is choosing the role''s reach -- and choosing a reach you do not have '
                         + N'is the INV-05 clause-2 attack wearing a different hat. The refusal has been recorded. No '
                         + N'role was defined.';
            ;THROW 50176, @Failure, 1;
        END;

        SET @Actor = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N''), ORIGINAL_LOGIN ());

        -- Normalised, not munged: CK_auth_Role_RoleCode demands trimmed uppercase, and both of those are mechanical.
        -- An illegal CHARACTER is left to the constraint -- Msg 547 -- because Appendix B registers no number for a
        -- malformed parameter and this file does not invent one. G-32.
        SET @RoleCode = NULLIF (UPPER (LTRIM (RTRIM (@RoleCode))), N'');
        SET @RoleName = NULLIF (LTRIM (RTRIM (@RoleName)), N'');

        BEGIN TRANSACTION;

        -- Section 5.4: "usable" is stricter than "exists". A role owned at a suspended tenant could be granted
        -- nowhere, so refusing now is kinder than a definition nobody can use.
        SELECT @ApplicationId = t.ApplicationId
          FROM auth.Tenant AS t
         WHERE t.TenantId  = @OwnerTenantId
           AND t.IsDeleted = 0;

        IF @ApplicationId IS NULL OR auth.udfIsTenantUsable (@OwnerTenantId) = 0
        BEGIN
            SET @Failure = N'The proposed owner tenant does not exist, has been deleted, or is unusable because it or '
                         + N'a tenant above it is inactive (section 5.4). No role was defined.';
            ;THROW 50173, @Failure, 1;
        END;

        -- Caught here so the caller gets a number to branch on rather than 2601 from UX_auth_Role_Code. The index is
        -- still what guarantees it under a race; this is the courtesy. Scoped to the owner, so two counties may each
        -- define REVIEWER -- that is the design's choice, not a loophole.
        IF EXISTS (SELECT 1
                     FROM auth.Role AS r
                    WHERE r.ApplicationId = @ApplicationId
                      AND r.OwnerTenantId = @OwnerTenantId
                      AND r.RoleCode      = @RoleCode
                      AND r.IsDeleted     = 0)
        BEGIN
            SET @Failure = N'That role code is already in use for that owner tenant in that application '
                         + N'(UX_auth_Role_Code). The uniqueness is scoped to the OWNER on purpose, so a different '
                         + N'tenant may define the same code and mean something different by it. No role was defined.';
            ;THROW 50170, @Failure, 1;
        END;

        -- IsSystemRole is hard 0. INV-10 reserves the flag for the roles Appendix A ships, seeded by
        -- 115_seed_reference_data.sql; a runtime procedure that could set it would let anybody mint a role the trigger
        -- then refuses to let anybody edit or delete. There is no parameter for it and there should not be.
        -- auditCreatedBy set EXPLICITLY: under the pooled login ORIGINAL_LOGIN () is identical on every row (14.4).
        INSERT auth.Role (ApplicationId, OwnerTenantId, RoleCode, RoleName, RoleDescription, IsAssignable, IsSystemRole
                        , auditCreatedBy, auditModifiedBy)
        VALUES (@ApplicationId, @OwnerTenantId, @RoleCode, @RoleName, @RoleDescription, @IsAssignable, 0
              , @Actor, @Actor);

        SET @NewRoleId = CAST (SCOPE_IDENTITY () AS INT);

        SET @DetailJson = CONCAT (N'{"roleCode":"', @RoleCode, N'","ownerTenantId":', @OwnerTenantId
                                , N',"applicationId":', @ApplicationId, N',"isAssignable":', @IsAssignable
                                , N',"permissionCount":0}');

        EXEC logs.uspRecordAuthorizationChange
              @ChangeType             = 'RoleCreated'
            , @TargetUserId           = NULL
            , @TargetUserProfileId    = NULL
            , @RoleId                 = @NewRoleId
            , @ScopeTenantId          = @OwnerTenantId
            , @ActorUserProfileId     = @ActorProfileId
            , @ActorAuthorityTenantId = @ActingTenantId
            , @DetailJson             = @DetailJson
            , @AuthorizationChangeId  = @ChangeId OUTPUT;

        SET @Comments = CONCAT (N'Defined RoleId=', @NewRoleId, N' ', @RoleCode, N' owned by TenantId='
                              , @OwnerTenantId, N' in ApplicationId=', @ApplicationId
                              , CASE WHEN @RawRoleCode <> @RoleCode
                                     THEN CONCAT (N'. Role code normalised from ''', @RawRoleCode
                                                , N''' (trimmed and uppercased -- CK_auth_Role_RoleCode)')
                                     ELSE N'' END
                              , N'. NO permissions attached: auth.uspSetRolePermissions is the next step, and until it '
                              + N'runs this role grants nobody anything.');

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


-- *** 2. auth.uspUpdateRole ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspUpdateRole
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Renames a role, re-describes it, or flips IsAssignable.  Requires Authz.RoleDefine at the role's OWNER tenant or above
(E-50176).  Refuses FREEZING a system role (E-50172) while permitting its name and description, which is what INV-10
actually protects.  Never moves a role between owners and never touches its permissions.

========================================================================================================================
Requirements and Key Dependencies:

auth.Role, auth.udfHasPermission, auth.uspSetSessionContext, logs.uspRecordAuthorizationDenial,
logs.uspRecordAuthorizationChange.  Granted to applicationRole.

========================================================================================================================
Notes:

THERE IS NO @OwnerTenantId PARAMETER AND NO @RoleCode PARAMETER.  Re-owning a role would silently change its reach:
every existing grant of it was validated against the OLD owner under INV-05 clause 3, and moving the owner sideways or
downward would leave grants standing that the new owner never covered.  Re-coding it would break every external
reference to a code the seed data and the application both know by name.  Both are a retire-and-redefine, which is two
audited calls instead of one unaudited surprise.  E-50171 is the only way this procedure learns the role does not exist.

EVERY PARAMETER IS NULL-MEANS-LEAVE-IT.  Passing nothing but the role id is a legal no-op that still writes a
RoleModified row -- somebody tried, and the trail says what they changed, which for a no-op is nothing.  The alternative,
treating NULL as "blank it", makes it impossible to change the name without restating the description.

A SYSTEM ROLE'S NAME AND DESCRIPTION MAY BE CHANGED; ITS IsAssignable FLAG MAY NOT BE CLEARED.  That is the opposite of
the obvious guess and it follows from what INV-10 is actually protecting.  auth.trg_au_updt_Role (E-50012) fixes a system
role's CODE, its FLAG and its EXISTENCE, and says in its own message that "RoleName and RoleDescription may be edited" --
a deployment may well want PLATFORM_ADMIN to read "System Administrator" on screen, and a label is not a meaning.  What
must not happen is a shipped role being FROZEN: 900_bootstrap_first_admin.sql grants several system roles BY CODE, and a
frozen role refuses new grants with E-50047, so freezing one turns the next deployment's bootstrap into a failure nobody
would connect to this call.  Setting the flag back to 1 is therefore permitted -- the refusal is of the clearing, not of
the column.

E-50172 IS THEREFORE THE ONLY REACHABLE SYSTEM-ROLE REFUSAL IN THIS PROCEDURE, because there is no @RoleCode parameter,
no @IsSystemRole parameter and no delete here for the trigger's other three clauses to fire on.  Appendix B's entry for
E-50172 describes it as refusing a change "INV-10 forbids" and then names RoleName and RoleDescription as permitted
without saying what is left; this procedure supplies the answer.  Recorded as G-33.

========================================================================================================================
Example Usage and Performance:

exec auth.uspUpdateRole @SessionTokenHash = 0x9F86..., @RoleId = 42, @RoleName = N'Senior Case Reviewer';
exec auth.uspUpdateRole @SessionTokenHash = 0x9F86..., @RoleId = 42, @IsAssignable = 0;

Two seeks, one update, one trail row.  No scope rebuild: permissions did not change.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-079
Description:
Created.  Phase 6.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspUpdateRole
      @SessionTokenHash VARBINARY (32)
    , @RoleId           INT
    , @RoleName         NVARCHAR (200)  = NULL
    , @RoleDescription  NVARCHAR (1000) = NULL
    , @IsAssignable     BIT             = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspUpdateRole]')
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
          , @OwnerTenantId  INT             = NULL
          , @RoleCode       NVARCHAR (100)  = NULL
          , @IsSystemRole   BIT             = NULL
          , @OldName        NVARCHAR (200)  = NULL
          , @OldAssignable  BIT             = NULL
          , @ChangeId       BIGINT          = NULL
          , @DenialId       BIGINT          = NULL
          , @DetailJson     NVARCHAR (800)  = NULL
          , @Failure        NVARCHAR (2000) = NULL;

    SET @KeyParameters = CONCAT (N'RoleId=', @RoleId
                               , N', RoleName=', CASE WHEN @RoleName IS NULL THEN N'(unchanged)' ELSE N'(supplied)' END
                               , N', RoleDescription='
                               , CASE WHEN @RoleDescription IS NULL THEN N'(unchanged)' ELSE N'(supplied)' END
                               , N', IsAssignable=', COALESCE (CAST (@IsAssignable AS NVARCHAR (1)), N'(unchanged)'));

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

        SET @ActorProfileId = TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT);
        SET @ActingTenantId = TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT);

        -- The lookup comes before the authority test because the authority is measured at the role's OWNER, and until
        -- the role is read there is no tenant to measure at. A nonexistent role is therefore E-50171 for everybody,
        -- which leaks that role ids are dense -- accepted, because a role id is not a secret and the alternative
        -- (refusing with a denial the caller cannot act on) is worse to debug.
        SELECT @OwnerTenantId = r.OwnerTenantId
             , @RoleCode      = r.RoleCode
             , @IsSystemRole  = r.IsSystemRole
             , @OldName       = r.RoleName
             , @OldAssignable = r.IsAssignable
          FROM auth.Role AS r
         WHERE r.RoleId    = @RoleId
           AND r.IsDeleted = 0;

        IF @OwnerTenantId IS NULL
        BEGIN
            SET @Failure = N'No live role has that identifier. It may never have existed or it may have been retired. '
                         + N'Nothing was changed.';
            ;THROW 50171, @Failure, 1;
        END;

        IF auth.udfHasPermission (N'Authz.RoleDefine', @OwnerTenantId) = 0
        BEGIN
            SET @DetailJson = CONCAT (N'{"procedure":"auth.uspUpdateRole","roleId":', @RoleId, N',"ownerTenantId":'
                                    , @OwnerTenantId, N',"error":50176}');

            EXEC logs.uspRecordAuthorizationDenial
                  @PermissionCode        = N'Authz.RoleDefine'
                , @TenantId              = @OwnerTenantId
                , @UserProfileId         = @ActorProfileId
                , @ObjectName            = N'auth.uspUpdateRole'
                , @DetailJson            = @DetailJson
                , @AuthorizationDenialId = @DenialId OUTPUT;

            SET @Failure = N'That role is owned by a tenant outside your authority: you hold Authz.RoleDefine at no '
                         + N'tenant at or above its owner. The refusal has been recorded. Nothing was changed.';
            ;THROW 50176, @Failure, 1;
        END;

        -- The friendly number before the structural one: trg_au_updt_Role's E-50012 is the backstop that also holds for
        -- SSMS, but it does not guard this column at all, so the rule lives here or nowhere. INV-10, G-33.
        IF @IsSystemRole = 1 AND @IsAssignable = 0
        BEGIN
            SET @Failure = N'That is a system role (INV-10) and a system role may not be frozen. '
                         + N'900_bootstrap_first_admin.sql grants several of the shipped roles BY CODE, and a role with '
                         + N'IsAssignable = 0 refuses every new grant with E-50047 -- so freezing one here turns the '
                         + N'next deployment''s bootstrap into a failure nobody would connect back to this call. Its '
                         + N'RoleName and RoleDescription MAY be edited, and so may setting IsAssignable back to 1: '
                         + N'what is refused is the clearing, not the column. Nothing was changed.';
            ;THROW 50172, @Failure, 1;
        END;

        SET @Actor = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N''), ORIGINAL_LOGIN ());

        SET @RoleName = NULLIF (LTRIM (RTRIM (@RoleName)), N'');

        BEGIN TRANSACTION;

        -- auditModifiedBy is set explicitly; auditModifiedDateUtc is left to trg_au_updt_Role, which stamps it (14.4).
        -- COALESCE is what makes every parameter null-means-leave-it.
        UPDATE auth.Role
           SET RoleName        = COALESCE (@RoleName, RoleName)
             , RoleDescription = COALESCE (@RoleDescription, RoleDescription)
             , IsAssignable    = COALESCE (@IsAssignable, IsAssignable)
             , auditModifiedBy = @Actor
         WHERE RoleId    = @RoleId
           AND IsDeleted = 0;

        SET @DetailJson = CONCAT (N'{"roleCode":"', @RoleCode, N'","isSystemRole":', @IsSystemRole
                                , N',"nameChanged":'
                                , CASE WHEN @RoleName IS NOT NULL AND @RoleName <> @OldName THEN N'true'
                                       ELSE N'false' END
                                , N',"descriptionChanged":'
                                , CASE WHEN @RoleDescription IS NULL THEN N'false' ELSE N'true' END
                                , N',"isAssignable":', COALESCE (@IsAssignable, @OldAssignable)
                                , N',"isAssignableChanged":'
                                , CASE WHEN @IsAssignable IS NOT NULL AND @IsAssignable <> @OldAssignable THEN N'true'
                                       ELSE N'false' END
                                , N'}');

        EXEC logs.uspRecordAuthorizationChange
              @ChangeType             = 'RoleModified'
            , @TargetUserId           = NULL
            , @TargetUserProfileId    = NULL
            , @RoleId                 = @RoleId
            , @ScopeTenantId          = @OwnerTenantId
            , @ActorUserProfileId     = @ActorProfileId
            , @ActorAuthorityTenantId = @ActingTenantId
            , @DetailJson             = @DetailJson
            , @AuthorizationChangeId  = @ChangeId OUTPUT;

        SET @Comments = CONCAT (N'Updated RoleId=', @RoleId, N' ', @RoleCode, N' owned by TenantId=', @OwnerTenantId
                              , CASE WHEN @IsAssignable IS NOT NULL AND @IsAssignable <> @OldAssignable
                                     THEN CONCAT (N'. IsAssignable ', @OldAssignable, N' -> ', @IsAssignable
                                                , CASE WHEN @IsAssignable = 0
                                                       THEN N' (existing grants are untouched and keep working; only '
                                                          + N'NEW grants are refused, with E-50047)'
                                                       ELSE N'' END)
                                     ELSE N'' END
                              , CASE WHEN @RoleName IS NULL AND @RoleDescription IS NULL AND @IsAssignable IS NULL
                                     THEN N'. No-op: every parameter was NULL, so nothing changed. The trail row '
                                        + N'records the attempt.'
                                     ELSE N'' END
                              , N'. Permissions were NOT touched: auth.uspSetRolePermissions is the only way to change '
                              + N'them, and no derived scope needed rebuilding.');

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


-- *** 3. auth.uspSetRolePermissions ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspSetRolePermissions
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Replaces a role's ENTIRE permission set with the JSON array of permission codes supplied.  Requires Authz.RoleDefine at
the role's owner tenant or above (E-50176).  Refuses system roles outright (E-50172).  Rebuilds the derived permission
scope of every profile holding the role, inside the same transaction.

========================================================================================================================
Requirements and Key Dependencies:

auth.Role, auth.RolePermission, auth.Permission, auth.UserProfileRole, auth.udfHasPermission,
auth.uspRebuildProfilePermissionScope, auth.uspSetSessionContext, logs.uspRecordAuthorizationDenial,
logs.uspRecordAuthorizationChange.  Granted to applicationRole.

========================================================================================================================
Notes:

THE PARAMETER IS THE WHOLE DESIRED SET, NOT A DELTA.  "Add X" and "remove Y" as separate verbs read more naturally in a
ticket and are far worse in practice: two callers each holding a stale list would each add their own permission and
neither would notice the other, and a lost-update on a permission set is a silent privilege grant.  Restating the set
makes the caller's intent total and makes the diff -- and therefore the trail -- exact.  An empty array is legal and
means "this role grants nothing": that is how a role is emptied without retiring it.

JSON, NOT A TABLE-VALUED PARAMETER.  Section 14.2: the application layer speaks JSON to this database everywhere else,
a TVP would need a user-defined type in the deployment manifest and a matching client-side SqlDbType, and neither buys
anything at these cardinalities.  ISJSON (@x, ARRAY) -- a SQL Server 2022 addition, inside our floor and ceiling --
gives E-50046 a precise test instead of a guess.

A ROLE'S PERMISSIONS ARE NOT SCOPED AND THAT IS THE POINT.  auth.RolePermission carries no tenant: WHERE the role
applies is decided once, per grant, by auth.UserProfileRole.ScopeTenantId under INV-05.  A role is a noun; a grant is a
sentence about a place.

EVERY HOLDING PROFILE IS REBUILT IN THIS TRANSACTION, NOT LATER BY A JOB.  auth.ProfilePermissionScope is derived data,
and derived data that lags is a permission that is wrong for as long as the lag.  The loop is bounded by the number of
profiles holding this role, which in the shapes section 17 describes is small; a role held by tens of thousands of
profiles would want a set-based rebuild, and the Comments field records the count so the measurement exists before the
optimisation does.

REMOVED ROWS ARE SOFT-DELETED AND RE-ADDED ROWS ARE RESURRECTED IN PLACE, for the reason the file header gives at
length: UX_auth_RolePermission_Pair is filtered on IsDeleted = 0, so a second live row is impossible, and
CK_auth_RolePermission_DeletedPair is evaluated BEFORE the AFTER trigger, so the resurrection must clear
auditDeletedBy and auditDeletedDateUtc in the same statement that clears IsDeleted.

E-50174 NAMES THE FIRST OFFENDING CODE, NOT ALL OF THEM.  A caller fixing a list fixes it one line at a time anyway,
and building the full list into the message means building an unbounded string into an error.  Codes are compared
case-sensitively against auth.Permission because Appendix A's codes are mixed case (Authz.RoleDefine, not AUTHZ.ROLEDEFINE)
and a permission code is an identifier, not a word.

THERE ARE NOW THREE REFUSALS ABOUT THE PAYLOAD AND THEY ARE THREE DIFFERENT FAULTS -- G-32.  E-50046 says the payload is
not a JSON array.  E-50180 says it is an array but an ELEMENT of it is not a permission code: null, a number, a boolean,
a nested object, a nested array, or a blank string.  E-50174 says every element is well formed and one of them names a
permission this application does not have.  For two phases the middle case had no number of its own, and it did not fail
silently so much as fail into the WRONG one: a nested object arrived at E-50174 as "not a permission code registered for
this application", which sends the reader to 115_seed_reference_data.sql to look for a code that was never meant to
exist.  A null element was worse -- it was SKIPPED, so the role was set to a smaller set than the caller listed and the
call reported success.  A bulk write that silently narrows its own payload is the one failure in this file nobody would
catch by reading the reply.

E-50180 CARRIES THE ORDINAL, WHICH IS THE POINT OF IT.  "An element is malformed" in a thirty-element array is not an
error message, it is the start of a search.  j.[key] from OPENJSON is the 0-based array index, and the message gives that
and the 1-based position, because the index is what the caller edits and the position is what they count.

========================================================================================================================
Example Usage and Performance:

exec auth.uspSetRolePermissions @SessionTokenHash = 0x9F86..., @RoleId = 42
                              , @PermissionCodesJson = N'["Case.Read","Case.Update","Case.Note.Create"]';

exec auth.uspSetRolePermissions @SessionTokenHash = 0x9F86..., @RoleId = 42, @PermissionCodesJson = N'[]';

-- E-50180: the second element is an object, and the whole call is refused rather than applying the first.
exec auth.uspSetRolePermissions @SessionTokenHash = 0x9F86..., @RoleId = 42
                              , @PermissionCodesJson = N'["Case.Read",{"code":"Case.Update"}]';

One parse for the element check, one parse for the resolution, one anti-join each way, then one scope rebuild per
holding profile.  The element check adds a scan of the payload and nothing else -- it runs before the transaction opens.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-080
Description:
Created.  Phase 6.

-----------------------------------------------------------------------------------------------------------------------

Date:		2026-09-21
Author:		rsincero
Ticket:		G-32
Description:
Added the per-element check and E-50180, after the ISJSON test and before any write.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspSetRolePermissions
      @SessionTokenHash    VARBINARY (32)
    , @RoleId              INT
    , @PermissionCodesJson NVARCHAR (MAX)
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspSetRolePermissions]')
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
          , @OwnerTenantId  INT             = NULL
          , @ApplicationId  INT             = NULL
          , @RoleCode       NVARCHAR (100)  = NULL
          , @IsSystemRole   BIT             = NULL
          , @Now            DATETIME2 (3)   = SYSUTCDATETIME ()
          , @BadCode        NVARCHAR (100)  = NULL
          , @BadOrdinal     INT             = NULL
          , @BadType        INT             = NULL
          , @BadRaw         NVARCHAR (200)  = NULL
          , @RequestedCount INT             = 0
          , @AddedCount     INT             = 0
          , @RemovedCount   INT             = 0
          , @UnchangedCount INT             = 0
          , @ProfileCount   INT             = 0
          , @ProfileId      INT             = NULL
          , @PermissionId   INT             = NULL
          , @ChangeId       BIGINT          = NULL
          , @DenialId       BIGINT          = NULL
          , @DetailJson     NVARCHAR (800)  = NULL
          , @Failure        NVARCHAR (2000) = NULL;

    DECLARE @Requested TABLE (PermissionId INT           NOT NULL PRIMARY KEY
                            , PermissionCode NVARCHAR (100) NOT NULL);

    -- RowNo IDENTITY rather than a bare key, and the loops below walk 1..MAX instead of draining the table: these are
    -- table variables, but the SQL conventions forbid a hard DELETE anywhere in this codebase and the rule is not worth
    -- an exception nobody reading it could distinguish from a real one. Same shape as 140's @GrantedRoles.
    DECLARE @Added TABLE
    (
        RowNo        INT IDENTITY (1, 1) PRIMARY KEY,
        PermissionId INT NOT NULL
    );

    DECLARE @Removed TABLE
    (
        RowNo        INT IDENTITY (1, 1) PRIMARY KEY,
        PermissionId INT NOT NULL
    );

    DECLARE @Profiles TABLE
    (
        RowNo         INT IDENTITY (1, 1) PRIMARY KEY,
        UserProfileId INT NOT NULL
    );

    DECLARE @RowNo    INT = 1
          , @MaxRowNo INT = 0;

    -- The codes themselves are identifiers, not secrets, but an unbounded payload does not belong in the log, so the
    -- count goes in and the list does not (UI-16 is about credentials; this is about size).
    SET @KeyParameters = CONCAT (N'RoleId=', @RoleId, N', PermissionCodesJson length='
                               , COALESCE (CAST (LEN (@PermissionCodesJson) AS NVARCHAR (11)), N'NULL'));

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

        SET @ActorProfileId = TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT);
        SET @ActingTenantId = TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT);

        SELECT @OwnerTenantId = r.OwnerTenantId
             , @ApplicationId = r.ApplicationId
             , @RoleCode      = r.RoleCode
             , @IsSystemRole  = r.IsSystemRole
          FROM auth.Role AS r
         WHERE r.RoleId    = @RoleId
           AND r.IsDeleted = 0;

        IF @OwnerTenantId IS NULL
        BEGIN
            SET @Failure = N'No live role has that identifier. It may never have existed or it may have been retired. '
                         + N'No permissions were changed.';
            ;THROW 50171, @Failure, 1;
        END;

        IF auth.udfHasPermission (N'Authz.RoleDefine', @OwnerTenantId) = 0
        BEGIN
            SET @DetailJson = CONCAT (N'{"procedure":"auth.uspSetRolePermissions","roleId":', @RoleId
                                    , N',"ownerTenantId":', @OwnerTenantId, N',"error":50176}');

            EXEC logs.uspRecordAuthorizationDenial
                  @PermissionCode        = N'Authz.RoleDefine'
                , @TenantId              = @OwnerTenantId
                , @UserProfileId         = @ActorProfileId
                , @ObjectName            = N'auth.uspSetRolePermissions'
                , @DetailJson            = @DetailJson
                , @AuthorizationDenialId = @DenialId OUTPUT;

            SET @Failure = N'That role is owned by a tenant outside your authority: you hold Authz.RoleDefine at no '
                         + N'tenant at or above its owner. Editing a role''s permissions changes what everybody '
                         + N'holding it can do, everywhere they hold it, so it is gated at the owner exactly as '
                         + N'defining the role was. The refusal has been recorded. No permissions were changed.';
            ;THROW 50176, @Failure, 1;
        END;

        -- Refused OUTRIGHT, with no partial-edit escape hatch: a system role's permission set IS the meaning Appendix A
        -- documents, and unlike its IsAssignable flag there is no half of it that may safely move. INV-10.
        --
        -- THE MESSAGE USED TO OFFER A SECOND WAY OUT THAT DOES NOT EXIST -- "or freeze this one with
        -- auth.uspUpdateRole @IsAssignable = 0" -- which uspUpdateRole refuses with this same E-50172, because
        -- 900_bootstrap_first_admin.sql grants shipped roles BY CODE and a frozen one fails the next bootstrap.  An
        -- administrator following that advice would have hit a second refusal quoting the same number, and concluded the
        -- database was broken rather than that they had been misdirected.  Found while reconciling G-33; the remedy is
        -- to offer only the route that works, and to say why the other one is not on offer.
        IF @IsSystemRole = 1
        BEGIN
            SET @Failure = N'That is a system role (INV-10). Its permission set is what the shipped seed data MEANS '
                         + N'and Appendix A documents it, so it may not be edited at all -- not added to, not removed '
                         + N'from, not emptied. Define your own role with the permissions you want and grant that '
                         + N'instead; a role you own may be edited freely and may also be frozen. This one cannot be '
                         + N'frozen either: the bootstrap grants the shipped roles by code, so IsAssignable = 0 on a '
                         + N'system role would fail the next deployment. No permissions were changed.';
            ;THROW 50172, @Failure, 1;
        END;

        -- E-50046 before the parse, so a malformed payload is a named refusal rather than an OPENJSON error nobody
        -- registered. NULL is refused too: "I did not say" and "I said none" are different intents, and [] is the
        -- second one.
        IF @PermissionCodesJson IS NULL OR ISJSON (@PermissionCodesJson, ARRAY) = 0
        BEGIN
            SET @Failure = N'@PermissionCodesJson must be a JSON ARRAY of permission codes, for example '
                         + N'["Case.Read","Case.Update"]. An empty array [] is legal and means the role grants '
                         + N'nothing. NULL is not accepted, because "I did not say" and "I said none" are different '
                         + N'intentions and only one of them should empty a role. No permissions were changed.';
            ;THROW 50046, @Failure, 1;
        END;

        SET @Actor = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N''), ORIGINAL_LOGIN ());

        -- G-32.  ISJSON said the payload is an array; this says every ELEMENT of it is a code.  E-50180, raised before
        -- anything is written, so the whole call is refused rather than partly applied.
        --
        -- The gap this closes is narrow and was easy to miss: the two statements below skip a NULL element (WHERE
        -- j.[value] IS NOT NULL) and would report a nested object or an empty string as E-50174, "not a permission code
        -- registered for this application". Both readings are wrong in the same direction -- they describe a caller whose
        -- generator is broken as a caller who asked for a permission that does not exist, which sends whoever is
        -- debugging it to 115_seed_reference_data.sql to look for a code that was never meant to be there. A skipped NULL
        -- is worse still: the role is then set to a SMALLER set than the caller listed, silently, and the reply says
        -- success.
        --
        -- j.[type]: 0 null, 1 string, 2 number, 3 true/false, 4 array, 5 object. Only 1 is a permission code. j.[key] on
        -- an array is the 0-based ordinal, and both forms are in the message because the array index is what the caller
        -- edits and the ordinal position is what they count.
        SELECT TOP (1) @BadOrdinal = TRY_CAST (j.[key] AS INT)
                     , @BadType    = j.[type]
                     , @BadRaw     = LEFT (COALESCE (j.[value], N'null'), 200)
          FROM OPENJSON (@PermissionCodesJson) AS j
         WHERE j.[type] <> 1
            OR LEN (LTRIM (RTRIM (j.[value]))) = 0
         ORDER BY TRY_CAST (j.[key] AS INT);

        IF @BadOrdinal IS NOT NULL
        BEGIN
            SET @Failure = CONCAT (N'Element at index ', @BadOrdinal, N' of @PermissionCodesJson (the '
                                 , @BadOrdinal + 1, CASE WHEN @BadOrdinal + 1 = 1 THEN N'st' WHEN @BadOrdinal + 1 = 2
                                        THEN N'nd' WHEN @BadOrdinal + 1 = 3 THEN N'rd' ELSE N'th' END
                                 , N' element) is not a permission code: '
                                 , CASE @BadType WHEN 0 THEN N'it is null'
                                                 WHEN 2 THEN N'it is a number'
                                                 WHEN 3 THEN N'it is a boolean'
                                                 WHEN 4 THEN N'it is a nested array'
                                                 WHEN 5 THEN N'it is an object'
                                                 ELSE        N'it is blank or whitespace' END
                                 , N' -- ', @BadRaw, N'. Every element must be a non-empty string, for example '
                                 , N'["Case.Read","Case.Update"]. The whole call is refused rather than partly applied, '
                                 , N'and a null element is refused rather than skipped: skipping it would set the role to '
                                 , N'a smaller set than you listed and report success. Only the FIRST malformed element '
                                 , N'is named. No permissions were changed.');
            ;THROW 50180, @Failure, 1;
        END;

        -- Resolved OUTSIDE the transaction: this is validation, and a validation refusal should not have a transaction
        -- to roll back. LEFT JOIN rather than an EXISTS anti-join because the unmatched row is the one we want to name.
        -- BIN2 makes the comparison case-sensitive: a permission code is an identifier (Authz.RoleDefine), not a word.
        -- DISTINCT, because a caller listing a code twice means the set once, and the primary key on @Requested would
        -- otherwise turn a harmless duplicate into Msg 2627.
        INSERT @Requested (PermissionId, PermissionCode)
        SELECT DISTINCT p.PermissionId, p.PermissionCode
          FROM OPENJSON (@PermissionCodesJson) AS j
         INNER JOIN auth.Permission AS p
            ON p.PermissionCode COLLATE Latin1_General_BIN2 = LTRIM (RTRIM (j.[value])) COLLATE Latin1_General_BIN2
           AND p.ApplicationId = @ApplicationId
           AND p.IsDeleted     = 0
         WHERE j.[value] IS NOT NULL;

        SELECT TOP (1) @BadCode = LTRIM (RTRIM (j.[value]))
          FROM OPENJSON (@PermissionCodesJson) AS j
         WHERE NOT EXISTS (SELECT 1
                             FROM auth.Permission AS p
                            WHERE p.PermissionCode COLLATE Latin1_General_BIN2
                                      = LTRIM (RTRIM (j.[value])) COLLATE Latin1_General_BIN2
                              AND p.ApplicationId = @ApplicationId
                              AND p.IsDeleted     = 0)
         ORDER BY j.[key];

        IF @BadCode IS NOT NULL
        BEGIN
            SET @Failure = CONCAT (N'''', @BadCode, N''' is not a permission code registered for this role''s '
                                 , N'application. Permission codes are fixed by Appendix A and seeded by '
                                 , N'115_seed_reference_data.sql -- a role may only bundle codes that already exist, '
                                 , N'because a permission nothing checks is a permission that does nothing. Codes are '
                                 , N'case-sensitive. Only the FIRST unrecognised code is named. No permissions were '
                                 , N'changed.');
            ;THROW 50174, @Failure, 1;
        END;

        SELECT @RequestedCount = COUNT (*) FROM @Requested;

        BEGIN TRANSACTION;

        -- Removals first, so that a code moving out and a code moving in cannot collide on the filtered unique index
        -- within the same transaction.
        UPDATE rp
           SET rp.IsDeleted            = 1
             , rp.auditDeletedBy       = @Actor
             , rp.auditDeletedDateUtc  = @Now
             , rp.auditModifiedBy      = @Actor
          OUTPUT deleted.PermissionId INTO @Removed (PermissionId)
          FROM auth.RolePermission AS rp
         WHERE rp.RoleId    = @RoleId
           AND rp.IsDeleted = 0
           AND NOT EXISTS (SELECT 1 FROM @Requested AS q WHERE q.PermissionId = rp.PermissionId);

        SET @RemovedCount = @@ROWCOUNT;

        -- Resurrection in place. Both deleted columns are cleared in the SAME statement as IsDeleted because
        -- CK_auth_RolePermission_DeletedPair is checked before trg_au_updt_RolePermission ever runs -- clearing them in
        -- the trigger would be too late and the UPDATE would fail with Msg 547.
        UPDATE rp
           SET rp.IsDeleted            = 0
             , rp.auditDeletedBy       = NULL
             , rp.auditDeletedDateUtc  = NULL
             , rp.auditModifiedBy      = @Actor
          OUTPUT inserted.PermissionId INTO @Added (PermissionId)
          FROM auth.RolePermission AS rp
         INNER JOIN @Requested AS q
            ON q.PermissionId = rp.PermissionId
         WHERE rp.RoleId    = @RoleId
           AND rp.IsDeleted = 1;

        SET @AddedCount = @@ROWCOUNT;

        INSERT auth.RolePermission (RoleId, PermissionId, ApplicationId, auditCreatedBy, auditModifiedBy)
        OUTPUT inserted.PermissionId INTO @Added (PermissionId)
        SELECT @RoleId, q.PermissionId, @ApplicationId, @Actor, @Actor
          FROM @Requested AS q
         WHERE NOT EXISTS (SELECT 1
                             FROM auth.RolePermission AS rp
                            WHERE rp.RoleId       = @RoleId
                              AND rp.PermissionId = q.PermissionId);

        SET @AddedCount     = @AddedCount + @@ROWCOUNT;
        SET @UnchangedCount = @RequestedCount - @AddedCount;

        -- One trail row per code moved, not one per call: a reviewer asking "when did this role gain Case.Delete" wants
        -- a row about Case.Delete, and CK_logs_AuthorizationChange_ChangeType offers exactly these two verbs.
        SET @RowNo    = 1;
        SET @MaxRowNo = (SELECT COALESCE (MAX (RowNo), 0) FROM @Added);

        WHILE @RowNo <= @MaxRowNo
        BEGIN
            SELECT @PermissionId = a.PermissionId FROM @Added AS a WHERE a.RowNo = @RowNo;

            SELECT @DetailJson = CONCAT (N'{"roleCode":"', @RoleCode, N'","permissionCode":"', p.PermissionCode
                                       , N'","permissionId":', @PermissionId, N'}')
              FROM auth.Permission AS p
             WHERE p.PermissionId = @PermissionId;

            EXEC logs.uspRecordAuthorizationChange
                  @ChangeType             = 'RolePermissionAdded'
                , @TargetUserId           = NULL
                , @TargetUserProfileId    = NULL
                , @RoleId                 = @RoleId
                , @ScopeTenantId          = @OwnerTenantId
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
            SELECT @PermissionId = r.PermissionId FROM @Removed AS r WHERE r.RowNo = @RowNo;

            SELECT @DetailJson = CONCAT (N'{"roleCode":"', @RoleCode, N'","permissionCode":"', p.PermissionCode
                                       , N'","permissionId":', @PermissionId, N'}')
              FROM auth.Permission AS p
             WHERE p.PermissionId = @PermissionId;

            EXEC logs.uspRecordAuthorizationChange
                  @ChangeType             = 'RolePermissionRemoved'
                , @TargetUserId           = NULL
                , @TargetUserProfileId    = NULL
                , @RoleId                 = @RoleId
                , @ScopeTenantId          = @OwnerTenantId
                , @ActorUserProfileId     = @ActorProfileId
                , @ActorAuthorityTenantId = @ActingTenantId
                , @DetailJson             = @DetailJson
                , @AuthorizationChangeId  = @ChangeId OUTPUT;

            SET @RowNo = @RowNo + 1;
        END;

        -- Derived data is rebuilt in the SAME transaction as the change that invalidated it. A profile whose scope is
        -- stale is a profile with the wrong permissions, and "wrong for a few seconds" is still wrong. Only live grants
        -- count -- a revoked grant of this role gives nobody anything to rebuild.
        IF @AddedCount > 0 OR @RemovedCount > 0
        BEGIN
            INSERT @Profiles (UserProfileId)
            SELECT DISTINCT upr.UserProfileId
              FROM auth.UserProfileRole AS upr
             WHERE upr.RoleId    = @RoleId
               AND upr.IsDeleted = 0;

            SELECT @ProfileCount = COUNT (*) FROM @Profiles;

            SET @RowNo    = 1;
            SET @MaxRowNo = @ProfileCount;

            WHILE @RowNo <= @MaxRowNo
            BEGIN
                SELECT @ProfileId = p.UserProfileId FROM @Profiles AS p WHERE p.RowNo = @RowNo;

                EXEC auth.uspRebuildProfilePermissionScope @UserProfileId = @ProfileId;

                SET @RowNo = @RowNo + 1;
            END;
        END;

        SET @Comments = CONCAT (N'RoleId=', @RoleId, N' ', @RoleCode, N' now holds ', @RequestedCount
                              , N' permission(s): ', @AddedCount, N' added, ', @RemovedCount, N' removed, '
                              , @UnchangedCount, N' already present. Rebuilt the derived permission scope of '
                              , @ProfileCount, N' holding profile(s) in this transaction'
                              , CASE WHEN @AddedCount = 0 AND @RemovedCount = 0
                                     THEN N'; nothing moved, so no rebuild was needed' ELSE N'' END
                              , CASE WHEN @RequestedCount = 0
                                     THEN N'. The role is now EMPTY: it is still assignable and still appears in '
                                        + N'listings, but it grants nothing.' ELSE N'.' END);

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


-- *** 4. auth.uspAssignRoleToProfile ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspAssignRoleToProfile
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Grants a role to a profile at a scope tenant, optionally with an expiry.  Enforces all four clauses of INV-05 as four
distinct error numbers, the INV-06 self-grant guard, and the IsAssignable freeze.  Resurrects a previously revoked
identical grant in place rather than inserting a second row.  Rebuilds the profile's derived scope in the same
transaction.

========================================================================================================================
Requirements and Key Dependencies:

auth.Role, auth.UserProfile, auth.UserProfileRole, auth.Tenant, auth.TenantClosure, auth.udfHasPermission,
auth.udfIsTenantUsable, auth.uspRebuildProfilePermissionScope, auth.uspSetSessionContext, config.ApplicationSetting,
logs.uspRecordAuthorizationDenial, logs.uspRecordAuthorizationChange.  Granted to applicationRole.

========================================================================================================================
Notes:

THE FOUR CLAUSES ARE CHECKED IN THE ORDER THE CALLER CAN ACT ON.  Existence first (E-50171, E-50177), because a message
about authority over a role that does not exist is a riddle.  Then clause 1 (E-50040: do you have authority over the
PERSON), then clause 2 (E-50041: over the PLACE), because those two are the security boundary and every other check
below them is arithmetic the caller is allowed to see the answer to.  Then clause 3 (E-50042: does the role REACH the
place) and clause 4 (E-50043: same application), which are properties of the objects rather than of the actor.

@ScopeTenantId DEFAULTS TO THE TARGET PROFILE'S OWN TENANT.  That is the grant almost every caller means, and spelling
it out is a chance to get it wrong.  A scope ABOVE the profile's tenant is legal and is how a regional reviewer is made:
clause 2 is what stops it being an escalation.

SELF-GRANT IS REFUSED BY DEFAULT AND THE SWITCH IS A SETTING, NOT A PERMISSION.  INV-06.  Authz.AllowSelfGrant = '1'
turns E-50044 off for the whole deployment, which is honest about what it is: a single-administrator deployment has no
second pair of eyes to offer, and pretending otherwise by inventing a permission that only administrators hold would
make the guard look like four-eyes when it is not.  G-08 says so out loud.  The grant is still audited either way, and
DetailJson records that it was a self-grant, so the trail shows exactly what the deployment chose.

A REVOKED GRANT IS RESURRECTED, A LIVE ONE IS REFUSED.  E-50179 rather than a silent no-op, because "grant this again
with a later expiry" is a real intention and re-stamping GrantedUtc under it would erase when the authority actually
began -- revoke and re-grant, two audited calls.  The resurrection clears both deleted columns in the same statement as
IsDeleted, because CK_auth_UserProfileRole_DeletedPair is evaluated before the AFTER trigger.

A PAST OR EQUAL EXPIRY IS LEFT TO CK_auth_UserProfileRole_Expiry.  Appendix B registers no number for a malformed
parameter (G-32), so the constraint refuses it as Msg 547 rather than this procedure inventing an unregistered code.  A
grant that expires before it begins is not a security hole, only a waste.

========================================================================================================================
Example Usage and Performance:

declare @GrantId int;
exec auth.uspAssignRoleToProfile @SessionTokenHash = 0x9F86..., @UserProfileId = 88, @RoleId = 42
                               , @NewUserProfileRoleId = @GrantId output;

exec auth.uspAssignRoleToProfile @SessionTokenHash = 0x9F86..., @UserProfileId = 88, @RoleId = 42
                               , @ScopeTenantId = 3, @ExpiresUtc = '2027-01-01T00:00:00'
                               , @NewUserProfileRoleId = @GrantId output;

Two scope tests, two closure seeks, one write, one scope rebuild, one trail row.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-081
Description:
Created.  Phase 6.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspAssignRoleToProfile
      @SessionTokenHash     VARBINARY (32)
    , @UserProfileId        INT
    , @RoleId               INT
    , @ScopeTenantId        INT           = NULL
    , @ExpiresUtc           DATETIME2 (3) = NULL
    , @NewUserProfileRoleId INT           OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspAssignRoleToProfile]')
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
          , @OwnerTenantId   INT             = NULL
          , @RoleAppId       INT             = NULL
          , @RoleCode        NVARCHAR (100)  = NULL
          , @IsAssignable    BIT             = NULL
          , @TargetUserId    INT             = NULL
          , @TargetTenantId  INT             = NULL
          , @TargetActive    BIT             = NULL
          , @ScopeAppId      INT             = NULL
          , @AllowSelfGrant  BIT             = NULL
          , @ExistingGrantId INT             = NULL
          , @Resurrected     BIT             = 0
          , @IsSelfGrant     BIT             = 0
          , @Now             DATETIME2 (3)   = SYSUTCDATETIME ()
          , @ChangeId        BIGINT          = NULL
          , @DenialId        BIGINT          = NULL
          , @DetailJson      NVARCHAR (800)  = NULL
          , @Failure         NVARCHAR (2000) = NULL;

    SET @KeyParameters = CONCAT (N'UserProfileId=', @UserProfileId, N', RoleId=', @RoleId, N', ScopeTenantId='
                               , COALESCE (CAST (@ScopeTenantId AS NVARCHAR (11)), N'(profile''s own tenant)')
                               , N', ExpiresUtc='
                               , COALESCE (CONVERT (NVARCHAR (30), @ExpiresUtc, 126), N'(never)'));

    SET @NewUserProfileRoleId = NULL;

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

        -- Everything down to BEGIN TRANSACTION is context, authority and validation. Nothing here writes anything the
        -- caller can see except denial and trail rows, which must NOT be inside a transaction that a refusal rolls
        -- back. BL-042, G-31.
        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        SET @ActorProfileId = TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT);
        SET @ActingTenantId = TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT);
        SET @Actor = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N''), ORIGINAL_LOGIN ());

        SELECT @OwnerTenantId = r.OwnerTenantId
             , @RoleAppId     = r.ApplicationId
             , @RoleCode      = r.RoleCode
             , @IsAssignable  = r.IsAssignable
          FROM auth.Role AS r
         WHERE r.RoleId    = @RoleId
           AND r.IsDeleted = 0;

        IF @OwnerTenantId IS NULL
        BEGIN
            SET @Failure = N'No live role has that identifier. It may never have existed or it may have been retired. '
                         + N'Nothing was granted.';
            ;THROW 50171, @Failure, 1;
        END;

        SELECT @TargetUserId   = up.UserId
             , @TargetTenantId = up.TenantId
             , @TargetActive   = up.IsActive
          FROM auth.UserProfile AS up
         WHERE up.UserProfileId = @UserProfileId
           AND up.IsDeleted     = 0;

        IF @TargetTenantId IS NULL
        BEGIN
            SET @Failure = N'No live profile has that identifier. It may never have existed or it may have been '
                         + N'retired. Nothing was granted.';
            ;THROW 50177, @Failure, 1;
        END;

        -- The default almost every caller means. Written out rather than left implicit because the Comments field says
        -- which one happened, and a reviewer should not have to infer it.
        SET @ScopeTenantId = COALESCE (@ScopeTenantId, @TargetTenantId);

        -- ---- INV-05 clause 1: authority over the PERSON. -----------------------------------------
        -- Measured at the target profile's OWN tenant, not at the scope: granting somebody a role is an act on THEM,
        -- and the actor must be above them to perform it. Section 11.4.
        IF auth.udfHasPermission (N'Authz.RoleAssign', @TargetTenantId) = 0
        BEGIN
            SET @DetailJson = CONCAT (N'{"procedure":"auth.uspAssignRoleToProfile","clause":1,"roleId":', @RoleId
                                    , N',"targetUserProfileId":', @UserProfileId, N',"targetTenantId":'
                                    , @TargetTenantId, N',"error":50040}');

            EXEC logs.uspRecordAuthorizationDenial
                  @PermissionCode        = N'Authz.RoleAssign'
                , @TenantId              = @TargetTenantId
                , @UserProfileId         = @ActorProfileId
                , @ObjectName            = N'auth.uspAssignRoleToProfile'
                , @DetailJson            = @DetailJson
                , @AuthorizationDenialId = @DenialId OUTPUT;

            SET @Failure = N'That profile belongs to a tenant outside your authority: you hold Authz.RoleAssign at no '
                         + N'tenant at or above it (INV-05 clause 1). Granting somebody a role is an act on THEM, so '
                         + N'you must be above them to perform it, whatever the role or the scope. The refusal has '
                         + N'been recorded. Nothing was granted.';
            ;THROW 50040, @Failure, 1;
        END;

        -- ---- INV-05 clause 2: authority over the PLACE. ------------------------------------------
        -- This clause is the one that stops escalation. Without it an actor with authority over a single user could
        -- grant that user a role scoped at the ROOT tenant and then borrow it back by switching profiles.
        IF auth.udfHasPermission (N'Authz.RoleAssign', @ScopeTenantId) = 0
        BEGIN
            SET @DetailJson = CONCAT (N'{"procedure":"auth.uspAssignRoleToProfile","clause":2,"roleId":', @RoleId
                                    , N',"targetUserProfileId":', @UserProfileId, N',"scopeTenantId":', @ScopeTenantId
                                    , N',"error":50041}');

            EXEC logs.uspRecordAuthorizationDenial
                  @PermissionCode        = N'Authz.RoleAssign'
                , @TenantId              = @ScopeTenantId
                , @UserProfileId         = @ActorProfileId
                , @ObjectName            = N'auth.uspAssignRoleToProfile'
                , @DetailJson            = @DetailJson
                , @AuthorizationDenialId = @DenialId OUTPUT;

            SET @Failure = N'The requested scope is outside your authority: you hold Authz.RoleAssign at no tenant at '
                         + N'or above it (INV-05 clause 2). You may not grant authority over a place you have none '
                         + N'over -- otherwise authority over one user would be authority everywhere, by granting '
                         + N'that user a broadly scoped role and then wearing it. The refusal has been recorded. '
                         + N'Nothing was granted.';
            ;THROW 50041, @Failure, 1;
        END;

        -- ---- INV-05 clause 3: the role must REACH the scope. -------------------------------------
        -- auth.TenantClosure holds one row per ancestor/descendant pair including the self-pair at depth 0, so this
        -- single EXISTS covers "the owner IS the scope" as well as "the owner is above it".
        IF NOT EXISTS (SELECT 1
                         FROM auth.TenantClosure AS tc
                        WHERE tc.AncestorTenantId   = @OwnerTenantId
                          AND tc.DescendantTenantId = @ScopeTenantId
                          AND tc.IsDeleted          = 0)
        BEGIN
            SET @Failure = N'That role''s owner tenant is not at or above the requested scope (INV-05 clause 3), so '
                         + N'the role does not reach there. A role belongs to one tenant and may be granted at that '
                         + N'tenant or anywhere beneath it, never sideways and never above. Define an equivalent role '
                         + N'at a tenant that does reach the scope. Nothing was granted.';
            ;THROW 50042, @Failure, 1;
        END;

        -- ---- INV-05 clause 4: one application throughout. ----------------------------------------
        SELECT @ScopeAppId = t.ApplicationId
          FROM auth.Tenant AS t
         WHERE t.TenantId  = @ScopeTenantId
           AND t.IsDeleted = 0;

        IF @ScopeAppId IS NULL OR @ScopeAppId <> @RoleAppId
        BEGIN
            SET @Failure = N'The role, the profile and the scope must all belong to the same application (INV-05 '
                         + N'clause 4). Applications are separate universes of permissions in this database: a role '
                         + N'from one of them names permission codes the other does not register, so the grant would '
                         + N'mean nothing. Nothing was granted.';
            ;THROW 50043, @Failure, 1;
        END;

        -- ---- The IsAssignable freeze. ------------------------------------------------------------
        -- Existing grants are deliberately untouched by the flag; this refuses only NEW ones, including resurrections,
        -- because resurrecting a revoked grant of a frozen role is a new grant wearing an old row. Section 8.2.
        IF @IsAssignable = 0
        BEGIN
            SET @Failure = N'That role is marked not assignable: somebody has frozen it with auth.uspUpdateRole so '
                         + N'that no NEW grants of it are made, while existing grants keep working. Ask whoever froze '
                         + N'it before unfreezing it. Nothing was granted.';
            ;THROW 50047, @Failure, 1;
        END;

        -- ---- INV-06: the self-grant guard. ------------------------------------------------------
        -- Read inline with TRY_CAST and a COALESCE to the documented default, like every other setting in this
        -- database: there is no helper function and one would only hide which default applied.
        SET @IsSelfGrant = CASE WHEN @UserProfileId = @ActorProfileId THEN 1 ELSE 0 END;

        SET @AllowSelfGrant = COALESCE (TRY_CAST ((SELECT s.SettingValue
                                                     FROM config.ApplicationSetting AS s
                                                    WHERE s.SettingKey = N'Authz.AllowSelfGrant'
                                                      AND s.IsDeleted  = 0) AS BIT), 0);

        IF @IsSelfGrant = 1 AND @AllowSelfGrant = 0
        BEGIN
            SET @Failure = N'You may not grant a role to the profile you are currently wearing (INV-06). Ask another '
                         + N'administrator, or -- if this deployment has only one -- set the Authz.AllowSelfGrant '
                         + N'application setting to 1, which turns this guard off deployment-wide and is recorded as '
                         + N'such in the trail of every self-grant thereafter. Nothing was granted.';
            ;THROW 50044, @Failure, 1;
        END;

        -- Section 5.4: usable is stricter than exists. A grant scoped at a suspended subtree would sit dormant and
        -- then wake up whenever somebody reactivated the tenant, which is not what the granter agreed to.
        IF auth.udfIsTenantUsable (@ScopeTenantId) = 0
        BEGIN
            SET @Failure = N'The requested scope tenant is unusable because it or a tenant above it is inactive '
                         + N'(section 5.4). A grant made there would grant nothing today and then come to life the '
                         + N'moment somebody reactivated the subtree, which nobody reviewing this grant agreed to. '
                         + N'Reactivate the tenant first. Nothing was granted.';
            ;THROW 50178, @Failure, 1;
        END;

        SELECT @ExistingGrantId = upr.UserProfileRoleId
          FROM auth.UserProfileRole AS upr
         WHERE upr.UserProfileId = @UserProfileId
           AND upr.RoleId        = @RoleId
           AND upr.ScopeTenantId = @ScopeTenantId
           AND upr.IsDeleted     = 0;

        IF @ExistingGrantId IS NOT NULL
        BEGIN
            SET @Failure = N'That profile already holds that role at that scope, and this procedure will not re-stamp '
                         + N'a live grant: GrantedUtc records when the authority actually began, and quietly moving it '
                         + N'would erase that. To change an expiry, revoke and grant again -- two calls, both audited. '
                         + N'Nothing was changed.';
            ;THROW 50179, @Failure, 1;
        END;

        BEGIN TRANSACTION;

        -- Resurrection in place, for the reason the file header gives: UX_auth_UserProfileRole_Grant is filtered on
        -- IsDeleted = 0, so a second row for the same triple would be refused with Msg 2601 the moment anybody revoked
        -- one of them -- a bug that lies dormant until the unluckiest possible day.
        SELECT @ExistingGrantId = upr.UserProfileRoleId
          FROM auth.UserProfileRole AS upr
         WHERE upr.UserProfileId = @UserProfileId
           AND upr.RoleId        = @RoleId
           AND upr.ScopeTenantId = @ScopeTenantId
           AND upr.IsDeleted     = 1;

        IF @ExistingGrantId IS NOT NULL
        BEGIN
            -- GrantedUtc IS re-stamped here, and only here: this grant genuinely begins now. The previous life of the
            -- row is in logs.AuthorizationChange, which is where a history belongs.
            -- Both deleted columns are cleared in the SAME statement as IsDeleted: the DeletedPair CHECK runs before
            -- trg_au_updt_UserProfileRole, so clearing them in the trigger would be too late (Msg 547).
            UPDATE auth.UserProfileRole
               SET IsDeleted            = 0
                 , auditDeletedBy       = NULL
                 , auditDeletedDateUtc  = NULL
                 , GrantedUtc           = @Now
                 , GrantedByProfileId   = @ActorProfileId
                 , ExpiresUtc           = @ExpiresUtc
                 , auditModifiedBy      = @Actor
             WHERE UserProfileRoleId = @ExistingGrantId;

            SET @NewUserProfileRoleId = @ExistingGrantId;
            SET @Resurrected          = 1;
        END
        ELSE
        BEGIN
            INSERT auth.UserProfileRole (UserProfileId, RoleId, ScopeTenantId, ApplicationId, GrantedByProfileId
                                       , GrantedUtc, ExpiresUtc, auditCreatedBy, auditModifiedBy)
            VALUES (@UserProfileId, @RoleId, @ScopeTenantId, @RoleAppId, @ActorProfileId
                  , @Now, @ExpiresUtc, @Actor, @Actor);

            SET @NewUserProfileRoleId = CAST (SCOPE_IDENTITY () AS INT);
        END;

        -- Derived data, rebuilt in the transaction that invalidated it.
        EXEC auth.uspRebuildProfilePermissionScope @UserProfileId = @UserProfileId;

        SET @DetailJson = CONCAT (N'{"roleCode":"', @RoleCode, N'","roleId":', @RoleId, N',"scopeTenantId":'
                                , @ScopeTenantId, N',"ownerTenantId":', @OwnerTenantId, N',"targetTenantId":'
                                , @TargetTenantId, N',"expiresUtc":'
                                , CASE WHEN @ExpiresUtc IS NULL THEN N'null'
                                       ELSE N'"' + CONVERT (NVARCHAR (30), @ExpiresUtc, 126) + N'"' END
                                , N',"resurrected":', CASE WHEN @Resurrected = 1 THEN N'true' ELSE N'false' END
                                , N',"selfGrant":', CASE WHEN @IsSelfGrant = 1 THEN N'true' ELSE N'false' END
                                , N',"allowSelfGrantSetting":', @AllowSelfGrant, N'}');

        EXEC logs.uspRecordAuthorizationChange
              @ChangeType             = 'RoleGranted'
            , @TargetUserId           = @TargetUserId
            , @TargetUserProfileId    = @UserProfileId
            , @RoleId                 = @RoleId
            , @ScopeTenantId          = @ScopeTenantId
            , @ActorUserProfileId     = @ActorProfileId
            , @ActorAuthorityTenantId = @ActingTenantId
            , @DetailJson             = @DetailJson
            , @AuthorizationChangeId  = @ChangeId OUTPUT;

        SET @Comments = CONCAT (CASE WHEN @Resurrected = 1
                                     THEN N'Resurrected previously revoked grant UserProfileRoleId='
                                     ELSE N'Granted UserProfileRoleId=' END
                              , @NewUserProfileRoleId, N': RoleId=', @RoleId, N' ', @RoleCode
                              , N' to UserProfileId=', @UserProfileId, N' at ScopeTenantId=', @ScopeTenantId
                              , CASE WHEN @ScopeTenantId = @TargetTenantId
                                     THEN N' (the profile''s own tenant, the default)'
                                     ELSE N' (above the profile''s own tenant ' + CAST (@TargetTenantId AS NVARCHAR (11))
                                        + N', permitted because INV-05 clause 2 was satisfied)' END
                              , CASE WHEN @ExpiresUtc IS NULL THEN N'. No expiry.'
                                     ELSE N'. Expires ' + CONVERT (NVARCHAR (30), @ExpiresUtc, 126) + N'.' END
                              , CASE WHEN @IsSelfGrant = 1
                                     THEN N' SELF-GRANT, permitted because Authz.AllowSelfGrant is 1 (INV-06 guard '
                                        + N'disabled deployment-wide).' ELSE N'' END
                              , CASE WHEN @TargetActive = 0
                                     THEN N' NOTE: the target profile is INACTIVE, so this grant gives nobody anything '
                                        + N'until it is reactivated. Refused nothing: pre-provisioning a role for a '
                                        + N'profile that is not yet in use is legitimate.' ELSE N'' END
                              , N' Rebuilt the profile''s derived permission scope in this transaction.');

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


-- *** 5. auth.uspRevokeRoleFromProfile ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspRevokeRoleFromProfile
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Revokes one grant -- one (profile, role, scope) triple -- by soft-deleting it, and rebuilds the profile's derived scope
in the same transaction.  Requires Authz.RoleRevoke at the target profile's tenant or above (E-50040).

========================================================================================================================
Requirements and Key Dependencies:

auth.Role, auth.UserProfile, auth.UserProfileRole, auth.udfHasPermission, auth.uspRebuildProfilePermissionScope,
auth.uspSetSessionContext, logs.uspRecordAuthorizationDenial, logs.uspRecordAuthorizationChange.  Granted to
applicationRole.

========================================================================================================================
Notes:

REVOKING HAS ITS OWN PERMISSION, AND IT IS TESTED AT THE PERSON ONLY.  Authz.RoleRevoke -- not Authz.RoleAssign -- at
the target profile's tenant or above.  Appendix A registers the two separately (section 8.4) so that a help-desk role
can be given the power to take authority away without the power to hand it out, which is the asymmetry a support desk
actually wants; ROLE_ADMIN holds both, so the ordinary administrator notices no difference.

Clause 2 -- authority over the grant's SCOPE -- is deliberately NOT required here, even though granting demands it.  An
administrator who can reach the person should always be able to take authority away from them, including authority
granted at a scope they themselves do not cover, because the failure mode of a too-strict revoke is an over-privileged
account nobody present can fix.  Taking permissions away is never the escalation; giving them is.

THE SCOPE IS PART OF WHAT IS REVOKED.  A profile may hold the same role at two scopes -- REVIEWER at the county and at
one of its offices -- and those are two grants with two rows and two separate revocations.  @ScopeTenantId defaults to
the profile's own tenant, matching auth.uspAssignRoleToProfile, so the common case reads the same in both.

E-50175 MEANS "NO SUCH LIVE GRANT" AND COVERS "ALREADY REVOKED".  Revoking twice is not an error worth its own number:
the second call finds nothing live and says so, and the caller's intent is satisfied either way.  It is still an error
rather than a silent success, because a script that revokes a grant it has the wrong scope for should not report
success.

THE GRANT ROW SURVIVES, WHICH IS WHAT MAKES RESURRECTION POSSIBLE.  Soft delete is not sentiment here: it is what lets
auth.uspAssignRoleToProfile re-grant without tripping the filtered unique index, and it is what lets a reviewer answer
"did this person ever hold that role" from the base table rather than only from the trail.

========================================================================================================================
Example Usage and Performance:

exec auth.uspRevokeRoleFromProfile @SessionTokenHash = 0x9F86..., @UserProfileId = 88, @RoleId = 42;
exec auth.uspRevokeRoleFromProfile @SessionTokenHash = 0x9F86..., @UserProfileId = 88, @RoleId = 42
                                 , @ScopeTenantId = 3;

One seek, one update, one scope rebuild, one trail row.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-081
Description:
Created.  Phase 6.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspRevokeRoleFromProfile
      @SessionTokenHash VARBINARY (32)
    , @UserProfileId    INT
    , @RoleId           INT
    , @ScopeTenantId    INT = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspRevokeRoleFromProfile]')
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
          , @TargetUserId   INT             = NULL
          , @TargetTenantId INT             = NULL
          , @RoleCode       NVARCHAR (100)  = NULL
          , @GrantId        INT             = NULL
          , @GrantedUtc     DATETIME2 (3)   = NULL
          , @ExpiresUtc     DATETIME2 (3)   = NULL
          , @WasExpired     BIT             = 0
          , @Now            DATETIME2 (3)   = SYSUTCDATETIME ()
          , @ChangeId       BIGINT          = NULL
          , @DenialId       BIGINT          = NULL
          , @DetailJson     NVARCHAR (800)  = NULL
          , @Failure        NVARCHAR (2000) = NULL;

    SET @KeyParameters = CONCAT (N'UserProfileId=', @UserProfileId, N', RoleId=', @RoleId, N', ScopeTenantId='
                               , COALESCE (CAST (@ScopeTenantId AS NVARCHAR (11)), N'(profile''s own tenant)'));

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

        SET @ActorProfileId = TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT);
        SET @ActingTenantId = TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT);
        SET @Actor = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N''), ORIGINAL_LOGIN ());

        SELECT @TargetUserId   = up.UserId
             , @TargetTenantId = up.TenantId
          FROM auth.UserProfile AS up
         WHERE up.UserProfileId = @UserProfileId
           AND up.IsDeleted     = 0;

        IF @TargetTenantId IS NULL
        BEGIN
            SET @Failure = N'No live profile has that identifier. It may never have existed or it may have been '
                         + N'retired. Nothing was revoked.';
            ;THROW 50177, @Failure, 1;
        END;

        SET @ScopeTenantId = COALESCE (@ScopeTenantId, @TargetTenantId);

        -- Clause 1 only, and its own permission, for the two reasons the note above gives.
        IF auth.udfHasPermission (N'Authz.RoleRevoke', @TargetTenantId) = 0
        BEGIN
            SET @DetailJson = CONCAT (N'{"procedure":"auth.uspRevokeRoleFromProfile","roleId":', @RoleId
                                    , N',"targetUserProfileId":', @UserProfileId, N',"targetTenantId":'
                                    , @TargetTenantId, N',"scopeTenantId":', @ScopeTenantId, N',"error":50040}');

            EXEC logs.uspRecordAuthorizationDenial
                  @PermissionCode        = N'Authz.RoleRevoke'
                , @TenantId              = @TargetTenantId
                , @UserProfileId         = @ActorProfileId
                , @ObjectName            = N'auth.uspRevokeRoleFromProfile'
                , @DetailJson            = @DetailJson
                , @AuthorizationDenialId = @DenialId OUTPUT;

            SET @Failure = N'That profile belongs to a tenant outside your authority: you hold Authz.RoleRevoke at no '
                         + N'tenant at or above it (INV-05 clause 1). Note that revoking takes Authz.RoleRevoke, which '
                         + N'is a separate permission from Authz.RoleAssign -- holding one does not imply the other, '
                         + N'though ROLE_ADMIN holds both. The refusal has been recorded. Nothing was revoked.';
            ;THROW 50040, @Failure, 1;
        END;

        -- The role is read for the trail and the message, not for a decision: a revocation of a grant whose role has
        -- since been retired must still succeed, so a missing role row is not an error here.
        SELECT @RoleCode = r.RoleCode
          FROM auth.Role AS r
         WHERE r.RoleId = @RoleId;

        SELECT @GrantId    = upr.UserProfileRoleId
             , @GrantedUtc = upr.GrantedUtc
             , @ExpiresUtc = upr.ExpiresUtc
          FROM auth.UserProfileRole AS upr
         WHERE upr.UserProfileId = @UserProfileId
           AND upr.RoleId        = @RoleId
           AND upr.ScopeTenantId = @ScopeTenantId
           AND upr.IsDeleted     = 0;

        IF @GrantId IS NULL
        BEGIN
            SET @Failure = N'That profile holds no live grant of that role at that scope. It may never have held one, '
                         + N'it may have been revoked already, or the scope may be wrong -- the same role granted at a '
                         + N'different tenant is a different grant and needs its own revocation, with @ScopeTenantId '
                         + N'named explicitly. Nothing was revoked.';
            ;THROW 50175, @Failure, 1;
        END;

        -- An already-expired grant is still revoked rather than refused: expiry stops the grant COUNTING, it does not
        -- close it, and an administrator tidying up should not have to care which of the two is true.
        SET @WasExpired = CASE WHEN @ExpiresUtc IS NOT NULL AND @ExpiresUtc <= @Now THEN 1 ELSE 0 END;

        BEGIN TRANSACTION;

        UPDATE auth.UserProfileRole
           SET IsDeleted            = 1
             , auditDeletedBy       = @Actor
             , auditDeletedDateUtc  = @Now
             , auditModifiedBy      = @Actor
         WHERE UserProfileRoleId = @GrantId;

        -- Derived data, rebuilt in the transaction that invalidated it. This is the statement that actually removes the
        -- person's permissions: the soft delete above only changes what the rebuild sees.
        EXEC auth.uspRebuildProfilePermissionScope @UserProfileId = @UserProfileId;

        SET @DetailJson = CONCAT (N'{"roleCode":"', COALESCE (@RoleCode, N'(retired role)'), N'","roleId":', @RoleId
                                , N',"userProfileRoleId":', @GrantId, N',"scopeTenantId":', @ScopeTenantId
                                , N',"grantedUtc":"', CONVERT (NVARCHAR (30), @GrantedUtc, 126)
                                , N'","wasAlreadyExpired":'
                                , CASE WHEN @WasExpired = 1 THEN N'true' ELSE N'false' END, N'}');

        EXEC logs.uspRecordAuthorizationChange
              @ChangeType             = 'RoleRevoked'
            , @TargetUserId           = @TargetUserId
            , @TargetUserProfileId    = @UserProfileId
            , @RoleId                 = @RoleId
            , @ScopeTenantId          = @ScopeTenantId
            , @ActorUserProfileId     = @ActorProfileId
            , @ActorAuthorityTenantId = @ActingTenantId
            , @DetailJson             = @DetailJson
            , @AuthorizationChangeId  = @ChangeId OUTPUT;

        SET @Comments = CONCAT (N'Revoked UserProfileRoleId=', @GrantId, N': RoleId=', @RoleId, N' '
                              , COALESCE (@RoleCode, N'(role since retired)'), N' from UserProfileId='
                              , @UserProfileId, N' at ScopeTenantId=', @ScopeTenantId
                              , N'. Granted ', CONVERT (NVARCHAR (30), @GrantedUtc, 126)
                              , CASE WHEN @WasExpired = 1
                                     THEN N'; the grant had already expired, so this changed no effective permission '
                                        + N'-- expiry stops a grant counting, revocation closes it, and tidying up the '
                                        + N'second after the first is legitimate'
                                     ELSE N'' END
                              , N'. The row was soft-deleted, not removed, so the same grant can be resurrected in '
                              + N'place later and so the history stays answerable from the base table. Rebuilt the '
                              + N'profile''s derived permission scope in this transaction.');

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


-- *** 6. auth.uspListAssignableRoles ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspListAssignableRoles
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Lists the roles that MAY be granted at a scope tenant: owned at or above it (INV-05 clause 3), in its application
(clause 4), IsAssignable = 1 by default.  Requires Authz.RoleRead at the scope.  Reports per row whether the caller
could actually perform the grant, and -- when @UserProfileId is supplied -- whether that profile already holds it.

========================================================================================================================
Requirements and Key Dependencies:

auth.Role, auth.RolePermission, auth.Tenant, auth.TenantClosure, auth.UserProfileRole, auth.udfHasPermission,
auth.uspSetSessionContext, auth.uspDemandPermission.  Granted to applicationRole.

========================================================================================================================
Notes:

ERROR-ONLY INSTRUMENTED.  A list screen is refreshed constantly and a start row per refresh would bury logs.ExecutionLog
in rows nobody reads.  Rule 8's read variant: no start row, so @ExecutionLogId is NULL by design and @ContextMessage says
so; failures are still recorded in full.

THE PERMISSION TO SEE ROLES IS NOT THE PERMISSION TO GRANT THEM, so the two are reported separately: the gate is
Authz.RoleRead (via auth.uspDemandPermission, which logs its own denial and throws E-50030 -- there is no Appendix B
number for "cannot read roles" and none is invented here), and CanAssign is a COLUMN.  A ROLE_ARCHITECT holds RoleDefine
and RoleRead but not RoleAssign: they should see the catalogue they curate with every row saying plainly that granting is
somebody else's job, rather than seeing an empty screen and filing a bug.

CanAssign IS COMPUTED ONCE PER CALL, NOT PER ROW, because INV-05 clauses 1 and 2 do not vary by role -- they are about
the person and the place.  Clause 3 and clause 4 DO vary by role and they are the WHERE clause, so a row that appears
here has already satisfied them.  A caller who takes a row from this list and passes it to
auth.uspAssignRoleToProfile can therefore only be refused by clause 1, the IsAssignable freeze racing them, or E-50179.

@IncludeUnassignable SHOWS THE FROZEN ONES, marked.  Leaving them out entirely makes a frozen role look deleted, and the
administrator who froze it deserves to be able to find it again.

SYSTEM ROLES ARE LISTED LIKE ANY OTHER, with IsSystemRole as a column: they are the most commonly granted roles in the
database and hiding them would be perverse.  The column is there so a screen can explain why the edit button is absent.

========================================================================================================================
Example Usage and Performance:

exec auth.uspListAssignableRoles @SessionTokenHash = 0x9F86...;
exec auth.uspListAssignableRoles @SessionTokenHash = 0x9F86..., @ScopeTenantId = 3, @UserProfileId = 88
                               , @IncludeUnassignable = 1;

One closure seek per candidate owner, one COUNT per role. Cardinality is the role catalogue, not the user population.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-081
Description:
Created.  Phase 6.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspListAssignableRoles
      @SessionTokenHash    VARBINARY (32)
    , @ScopeTenantId       INT = NULL
    , @UserProfileId       INT = NULL
    , @IncludeUnassignable BIT = 0
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation, READ variant: error-only. No start row is opened, so there is no
    -- @ExecutionId, no @StartTimeUtc / @EndTimeUtc pair and no completion UPDATE.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspListAssignableRoles]')
          , @KeyParameters  NVARCHAR (MAX) = NULL
          , @ContextMessage NVARCHAR (MAX) = NULL
          , @DynamicSql     NVARCHAR (MAX) = NULL
          , @ErrorMsg       NVARCHAR (MAX) = NULL
          , @ErrorProc      NVARCHAR (300) = NULL
          , @ErrorNumber    INT            = NULL
          , @ErrorLine      INT            = NULL;

    DECLARE @ActorProfileId INT             = NULL
          , @ActingTenantId INT             = NULL
          , @ScopeAppId     INT             = NULL
          , @TargetTenantId INT             = NULL
          , @CanAssign      BIT             = 0
          , @CanRevoke      BIT             = 0
          , @Now            DATETIME2 (3)   = SYSUTCDATETIME ()
          , @Failure        NVARCHAR (2000) = NULL;

    SET @KeyParameters = CONCAT (N'ScopeTenantId='
                               , COALESCE (CAST (@ScopeTenantId AS NVARCHAR (11)), N'(acting tenant)')
                               , N', UserProfileId='
                               , COALESCE (CAST (@UserProfileId AS NVARCHAR (11)), N'(none)')
                               , N', IncludeUnassignable=', @IncludeUnassignable);

    SET @ContextMessage = N'Error-only instrumented read: no start row is opened, so @ExecutionLogId is NULL by design.';

    BEGIN TRY

        -- =========================================================================================
        -- ===== The procedure's own work starts here. Everything above and below is boilerplate. ==
        -- =========================================================================================

        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        SET @ActorProfileId = TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT);
        SET @ActingTenantId = TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT);

        SET @ScopeTenantId = COALESCE (@ScopeTenantId, @ActingTenantId);

        -- The gate. auth.uspDemandPermission writes its own logs.AuthorizationDenial row and throws E-50030, which is
        -- the right shape here: unlike the grant path there is no registered Appendix B number for "may not read
        -- roles", and this file does not mint one.
        EXEC auth.uspDemandPermission
              @PermissionCode = N'Authz.RoleRead'
            , @TenantId       = @ScopeTenantId
            , @ObjectName     = N'auth.uspListAssignableRoles';

        SELECT @ScopeAppId = t.ApplicationId
          FROM auth.Tenant AS t
         WHERE t.TenantId  = @ScopeTenantId
           AND t.IsDeleted = 0;

        IF @ScopeAppId IS NULL
        BEGIN
            SET @Failure = N'No live tenant has that identifier, so there is no scope to list roles for. Nothing was '
                         + N'returned.';
            ;THROW 50173, @Failure, 1;
        END;

        -- If a profile was named, its tenant is needed for INV-05 clause 1 -- and a bad id is refused rather than
        -- quietly ignored, because a caller passing a profile expects the AlreadyHeld column to mean something.
        IF @UserProfileId IS NOT NULL
        BEGIN
            SELECT @TargetTenantId = up.TenantId
              FROM auth.UserProfile AS up
             WHERE up.UserProfileId = @UserProfileId
               AND up.IsDeleted     = 0;

            IF @TargetTenantId IS NULL
            BEGIN
                SET @Failure = N'No live profile has that identifier. Omit @UserProfileId to list the roles grantable '
                             + N'at the scope without reference to any particular profile. Nothing was returned.';
                ;THROW 50177, @Failure, 1;
            END;
        END;

        -- Computed once: clauses 1 and 2 are about the person and the place, not about the role. When no profile was
        -- named, clause 1 is unknowable, so CanAssign reports clause 2 alone and the column description says so.
        SET @CanAssign = CASE WHEN auth.udfHasPermission (N'Authz.RoleAssign', @ScopeTenantId) = 1
                              AND (@TargetTenantId IS NULL
                                   OR auth.udfHasPermission (N'Authz.RoleAssign', @TargetTenantId) = 1)
                              THEN 1 ELSE 0 END;

        SET @CanRevoke = CASE WHEN @TargetTenantId IS NOT NULL
                              AND auth.udfHasPermission (N'Authz.RoleRevoke', @TargetTenantId) = 1
                              THEN 1 ELSE 0 END;

        -- Clause 3 is the closure EXISTS and clause 4 is the ApplicationId equality: both are in the WHERE, so every
        -- row returned has already satisfied them and the caller does not need a column to check.
        SELECT r.RoleId
             , r.RoleCode
             , r.RoleName
             , r.RoleDescription
             , r.OwnerTenantId
             , ot.TenantCode                AS OwnerTenantCode
             , tc.Depth                     AS OwnerDepthAboveScope
             , r.IsSystemRole
             , r.IsAssignable
             , @ScopeTenantId               AS ScopeTenantId
             , @CanAssign                   AS CanAssign
             , @CanRevoke                   AS CanRevoke
             , (SELECT COUNT (*)
                  FROM auth.RolePermission AS rp
                 WHERE rp.RoleId    = r.RoleId
                   AND rp.IsDeleted = 0)    AS PermissionCount
             , CASE WHEN @UserProfileId IS NULL THEN NULL
                    WHEN EXISTS (SELECT 1
                                   FROM auth.UserProfileRole AS upr
                                  WHERE upr.UserProfileId = @UserProfileId
                                    AND upr.RoleId        = r.RoleId
                                    AND upr.ScopeTenantId = @ScopeTenantId
                                    AND upr.IsDeleted     = 0
                                    AND (upr.ExpiresUtc IS NULL OR upr.ExpiresUtc > @Now))
                    THEN CAST (1 AS BIT) ELSE CAST (0 AS BIT) END AS AlreadyHeldAtScope
             , CASE WHEN @UserProfileId IS NULL THEN NULL
                    WHEN EXISTS (SELECT 1
                                   FROM auth.UserProfileRole AS upr
                                  WHERE upr.UserProfileId = @UserProfileId
                                    AND upr.RoleId        = r.RoleId
                                    AND upr.ScopeTenantId = @ScopeTenantId
                                    AND upr.IsDeleted     = 1)
                    THEN CAST (1 AS BIT) ELSE CAST (0 AS BIT) END AS PreviouslyRevokedAtScope
          FROM auth.Role AS r
         INNER JOIN auth.TenantClosure AS tc
            ON tc.AncestorTenantId   = r.OwnerTenantId
           AND tc.DescendantTenantId = @ScopeTenantId
           AND tc.IsDeleted          = 0
         INNER JOIN auth.Tenant AS ot
            ON ot.TenantId  = r.OwnerTenantId
           AND ot.IsDeleted = 0
         WHERE r.IsDeleted     = 0
           AND r.ApplicationId = @ScopeAppId
           AND (r.IsAssignable = 1 OR @IncludeUnassignable = 1)
         ORDER BY tc.Depth ASC, r.RoleCode ASC;

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


-- *** 7. Extended properties ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
Every object this script creates carries an MS_Description, set idempotently so a re-run updates rather than fails.
***********************************************************************************************************************/
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
      (N'uspDefineRole'
     , N'Defines a new role owned by one tenant, with NO permissions -- auth.uspSetRolePermissions fills it. Requires '
     + N'Authz.RoleDefine at the owner tenant or above (E-50176), because INV-04 makes the owner the role''s reach, so '
     + N'choosing the owner IS choosing the reach. ApplicationId is read off the owner tenant rather than taken as a '
     + N'parameter: a role whose application differed from its owner''s could be granted to nobody (E-50043). '
     + N'IsSystemRole is hard 0 -- INV-10 reserves the flag for what 115_seed_reference_data.sql ships.')
    , (N'uspUpdateRole'
     , N'Renames a role, re-describes it, or flips IsAssignable. Requires Authz.RoleDefine at the OWNER tenant or above '
     + N'(E-50176). Every parameter is null-means-leave-it. There is deliberately no @OwnerTenantId and no @RoleCode: '
     + N're-owning a role would silently rewiden or invalidate every grant it already has (trg_au_updt_Role, E-50010) '
     + N'and re-coding it would break the seed script and the bootstrap, which name roles BY CODE. Refuses to FREEZE a '
     + N'system role (E-50172) while permitting its name and description -- which is what INV-10 actually protects, and '
     + N'what trg_au_updt_Role''s own E-50012 message says. G-33.')
    , (N'uspSetRolePermissions'
     , N'Replaces a role''s ENTIRE permission set with the JSON array of permission codes supplied; [] empties it. A '
     + N'total restatement rather than add/remove verbs, because two callers each holding a stale list would each add '
     + N'their own permission and neither would notice -- a lost update on a permission set is a silent privilege '
     + N'grant. Requires Authz.RoleDefine at the owner tenant or above (E-50176); refuses system roles outright '
     + N'(E-50172, INV-10). Three distinct refusals about the payload, which used to be two: E-50046 for a non-array '
     + N'payload, E-50180 for a malformed ELEMENT with its ordinal in the message (null, number, boolean, nested object '
     + N'or array, blank string -- G-32), E-50174 for the first well-formed code this application does not have. A null '
     + N'element used to be SKIPPED, setting the role to a smaller set than the caller listed and reporting success. '
     + N'Rebuilds the derived permission scope of every profile holding the role, inside the same transaction.')
    , (N'uspAssignRoleToProfile'
     , N'Grants a role to a profile at a scope tenant, optionally with an expiry. Enforces all four clauses of INV-05 '
     + N'as four distinct numbers: E-50040 authority over the PERSON, E-50041 authority over the PLACE (the clause '
     + N'that stops escalation), E-50042 the role must REACH the place, E-50043 one application throughout. Also '
     + N'E-50044 (INV-06 self-grant, overridable deployment-wide by the Authz.AllowSelfGrant setting), E-50047 (frozen '
     + N'role), E-50178 (unusable scope), E-50179 (already live -- revoke and re-grant rather than re-stamp '
     + N'GrantedUtc). Resurrects a previously revoked identical grant in place. Rebuilds the profile''s derived scope '
     + N'in the same transaction.')
    , (N'uspRevokeRoleFromProfile'
     , N'Revokes ONE grant -- one (profile, role, scope) triple -- by soft delete, and rebuilds the profile''s derived '
     + N'scope in the same transaction. Requires Authz.RoleRevoke, a permission separate from Authz.RoleAssign so a '
     + N'support desk can take authority away without being able to hand it out. Tested at the target profile''s '
     + N'tenant only (E-50040): authority over the grant''s SCOPE is deliberately NOT required, because the failure '
     + N'mode of a too-strict revoke is an over-privileged account nobody present can fix. E-50175 means no such live '
     + N'grant and covers a double-submitted revoke, which the caller should treat as success. The row survives, which '
     + N'is what makes resurrection possible.')
    , (N'uspListAssignableRoles'
     , N'Lists the roles that MAY be granted at a scope tenant: owned at or above it (INV-05 clause 3) and in its '
     + N'application (clause 4), which are the WHERE clause, so every row returned has satisfied them. Gated on '
     + N'Authz.RoleRead; whether the caller could actually GRANT is a column (CanAssign), not a filter, so a '
     + N'ROLE_ARCHITECT sees the catalogue they curate instead of an empty screen. When @UserProfileId is supplied, '
     + N'reports AlreadyHeldAtScope and PreviouslyRevokedAtScope. Error-only instrumented: no start row.');

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


-- *** 8. Permissions ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
EXECUTE to applicationRole and to nobody else.  Section 14.3: the application's pooled login reaches these tables only
through procedures, and every one of these six establishes its own session context from @SessionTokenHash before it does
anything -- so a caller who could invoke them without a session would get E-50100 or E-50021, not a bypass.
***********************************************************************************************************************/
IF DATABASE_PRINCIPAL_ID (N'applicationRole') IS NOT NULL
BEGIN
    GRANT EXECUTE ON auth.uspDefineRole            TO applicationRole;
    GRANT EXECUTE ON auth.uspUpdateRole            TO applicationRole;
    GRANT EXECUTE ON auth.uspSetRolePermissions    TO applicationRole;
    GRANT EXECUTE ON auth.uspAssignRoleToProfile   TO applicationRole;
    GRANT EXECUTE ON auth.uspRevokeRoleFromProfile TO applicationRole;
    GRANT EXECUTE ON auth.uspListAssignableRoles   TO applicationRole;
END
ELSE
BEGIN
    PRINT N'applicationRole does not exist, so no EXECUTE was granted. Run 020_security_principals.sql and then '
        + N're-run this file.';
END
GO


-- *** 9. Closing report ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
Reports what this script built and asserts the facts it depends on, so a deployment log shows the outcome rather than
only the absence of errors.
***********************************************************************************************************************/
DECLARE @Expected TABLE
(
    ObjectName SYSNAME NOT NULL PRIMARY KEY
);

INSERT @Expected (ObjectName)
VALUES (N'uspDefineRole'), (N'uspUpdateRole'), (N'uspSetRolePermissions')
     , (N'uspAssignRoleToProfile'), (N'uspRevokeRoleFromProfile'), (N'uspListAssignableRoles');

WITH Findings AS
(
    SELECT 1 AS Seq
         , N'Procedures created' AS Item
         , CONCAT (COUNT (*), N' of 6') AS Detail
         , CASE WHEN COUNT (*) = 6 THEN 4 ELSE 0 END AS Severity
      FROM sys.procedures AS p
      JOIN @Expected AS e ON e.ObjectName = p.name
     WHERE p.schema_id = SCHEMA_ID (N'auth')

    UNION ALL

    SELECT 2
         , N'EXECUTE granted to applicationRole'
         , CONCAT (COUNT (*), N' of 6')
         , CASE WHEN COUNT (*) = 6 THEN 4 ELSE 0 END
      FROM sys.database_permissions AS dp
      JOIN sys.procedures           AS p ON p.object_id = dp.major_id
      JOIN @Expected                AS e ON e.ObjectName = p.name
     WHERE dp.grantee_principal_id = DATABASE_PRINCIPAL_ID (N'applicationRole')
       AND dp.permission_name      = N'EXECUTE'
       AND dp.state                = N'G'
       AND p.schema_id             = SCHEMA_ID (N'auth')

    UNION ALL

    SELECT 3
         , N'MS_Description set'
         , CONCAT (COUNT (*), N' of 6')
         , CASE WHEN COUNT (*) = 6 THEN 4 ELSE 0 END
      FROM sys.extended_properties AS ep
      JOIN sys.procedures          AS p ON p.object_id = ep.major_id
      JOIN @Expected               AS e ON e.ObjectName = p.name
     WHERE ep.minor_id = 0
       AND ep.name     = N'MS_Description'
       AND p.schema_id = SCHEMA_ID (N'auth')

    UNION ALL

    -- INV-05 clause 3 is asked of this index every time a role is granted. Without the closure table populated the
    -- EXISTS would silently return nothing and every grant would be refused with E-50042.
    SELECT 4
         , N'auth.TenantClosure is populated'
         , CONCAT (COUNT (*), N' ancestor/descendant pair(s)')
         , CASE WHEN COUNT (*) > 0 THEN 4 ELSE 2 END
      FROM auth.TenantClosure
     WHERE IsDeleted = 0

    UNION ALL

    -- Both halves of the revoke/assign asymmetry must actually be registered, or uspRevokeRoleFromProfile demands a
    -- permission nobody can ever hold and revocation becomes impossible.
    --
    -- COUNT (DISTINCT PermissionCode), NOT COUNT (*).  THESE TWO LINES USED TO PRINT "8 of 2 -- 0 ERROR" ON A
    -- PERFECTLY HEALTHY DATABASE, and they printed it on the very redeploy that was confirming an unrelated fix.
    -- auth.Permission is scoped by ApplicationId (D-09): every registered application carries its own row for every
    -- permission code, so a database with eight applications holds eight rows per code and COUNT (*) = 2 can only ever
    -- be true on the single-application database the author happened to be looking at.  What the report is asking is
    -- "are both CODES registered", and the distinct count is the only phrasing of that question which survives a
    -- second application being added.  This is BL-047 inverted -- there the concern was an assertion that cannot
    -- fail, here it was one that cannot pass -- and it costs the same thing either way: a report nobody believes.
    SELECT 5
         , N'Authz.RoleAssign and Authz.RoleRevoke are both registered'
         , CONCAT (COUNT (DISTINCT PermissionCode), N' of 2 code(s), '
                 , COUNT (*), N' row(s) across ', COUNT (DISTINCT ApplicationId), N' application(s)')
         , CASE WHEN COUNT (DISTINCT PermissionCode) = 2 THEN 4 ELSE 0 END
      FROM auth.Permission
     WHERE PermissionCode IN (N'Authz.RoleAssign', N'Authz.RoleRevoke')
       AND IsDeleted = 0

    UNION ALL

    SELECT 6
         , N'Authz.RoleDefine and Authz.RoleRead are both registered'
         , CONCAT (COUNT (DISTINCT PermissionCode), N' of 2 code(s), '
                 , COUNT (*), N' row(s) across ', COUNT (DISTINCT ApplicationId), N' application(s)')
         , CASE WHEN COUNT (DISTINCT PermissionCode) = 2 THEN 4 ELSE 0 END
      FROM auth.Permission
     WHERE PermissionCode IN (N'Authz.RoleDefine', N'Authz.RoleRead')
       AND IsDeleted = 0

    UNION ALL

    -- The INV-06 override. Its ABSENCE is a defect, not a default: COALESCE would read a missing row as 0 and the guard
    -- would look deliberate when it was an omission.
    SELECT 7
         , N'Authz.AllowSelfGrant setting is present'
         , CONCAT (N'value = ', COALESCE (MAX (SettingValue), N'(MISSING)'))
         , CASE WHEN COUNT (*) = 1 THEN 4 ELSE 2 END
      FROM config.ApplicationSetting
     WHERE SettingKey = N'Authz.AllowSelfGrant'
       AND IsDeleted  = 0

    UNION ALL

    -- uspSetRolePermissions and uspAssignRoleToProfile both depend on the resurrect-in-place behaviour these filtered
    -- indexes make necessary. If either lost its filter the procedures would still run and would start inserting second
    -- rows for the same logical grant.
    SELECT 8
         , N'UX_auth_UserProfileRole_Grant is filtered on IsDeleted = 0'
         , COALESCE (MAX (i.filter_definition), N'(NO FILTER)')
         , CASE WHEN MAX (CAST (i.has_filter AS INT)) = 1 THEN 4 ELSE 0 END
      FROM sys.indexes AS i
     WHERE i.object_id = OBJECT_ID (N'auth.UserProfileRole')
       AND i.name      = N'UX_auth_UserProfileRole_Grant'

    UNION ALL

    SELECT 9
         , N'UX_auth_RolePermission_Pair is filtered on IsDeleted = 0'
         , COALESCE (MAX (i.filter_definition), N'(NO FILTER)')
         , CASE WHEN MAX (CAST (i.has_filter AS INT)) = 1 THEN 4 ELSE 0 END
      FROM sys.indexes AS i
     WHERE i.object_id = OBJECT_ID (N'auth.RolePermission')
       AND i.name      = N'UX_auth_RolePermission_Pair'

    UNION ALL

    -- Every ChangeType literal this script passes to logs.uspRecordAuthorizationChange must be in the whitelist, or the
    -- trail INSERT fails with Msg 547 AFTER the grant succeeded and takes the whole transaction with it.
    SELECT 10
         , N'CK_logs_AuthorizationChange_ChangeType permits all five verbs used here'
         , CONCAT (SUM (CASE WHEN cc.definition LIKE N'%' + v.Verb + N'%' THEN 1 ELSE 0 END), N' of 5')
         , CASE WHEN SUM (CASE WHEN cc.definition LIKE N'%' + v.Verb + N'%' THEN 1 ELSE 0 END) = 5
                THEN 4 ELSE 0 END
      FROM sys.check_constraints AS cc
     CROSS JOIN (VALUES (N'RoleCreated'), (N'RoleModified'), (N'RolePermissionAdded')
                      , (N'RolePermissionRemoved'), (N'RoleGranted')) AS v (Verb)
     WHERE cc.parent_object_id = OBJECT_ID (N'logs.AuthorizationChange')
       AND cc.name             = N'CK_logs_AuthorizationChange_ChangeType'

    UNION ALL

    SELECT 11
         , N'CK_logs_AuthorizationChange_ChangeType permits RoleRevoked'
         , CASE WHEN cc.definition LIKE N'%RoleRevoked%' THEN N'yes' ELSE N'NO' END
         , CASE WHEN cc.definition LIKE N'%RoleRevoked%' THEN 4 ELSE 0 END
      FROM sys.check_constraints AS cc
     WHERE cc.parent_object_id = OBJECT_ID (N'logs.AuthorizationChange')
       AND cc.name             = N'CK_logs_AuthorizationChange_ChangeType'

    UNION ALL

    -- INV-10's population. A deployment with no system roles has not run 115_seed_reference_data.sql, and E-50172 would
    -- then be unreachable -- which T-094 requires it not to be.
    SELECT 12
         , N'System roles are seeded (E-50172 is reachable)'
         , CONCAT (COUNT (*), N' role(s) with IsSystemRole = 1')
         , CASE WHEN COUNT (*) > 0 THEN 4 ELSE 3 END
      FROM auth.Role
     WHERE IsSystemRole = 1
       AND IsDeleted    = 0
)
SELECT f.Item
     , f.Detail
     , f.Severity
     , CASE f.Severity WHEN 4 THEN N'OK' WHEN 3 THEN N'PENDING' WHEN 2 THEN N'WARNING' ELSE N'ERROR' END AS Outcome
  FROM Findings AS f
 ORDER BY f.Seq;
GO

PRINT N'145_auth_role_procedures.sql complete: 6 procedures. T-079, T-080, T-081.';
GO
