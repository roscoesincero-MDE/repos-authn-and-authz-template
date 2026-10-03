/***********************************************************************************************************************
Script:         140_auth_profile_procedures.sql
Purpose:        The profile surface -- the hat a person wears at one organization: auth.uspCreateProfile,
                auth.uspUpdateProfile, auth.uspDeactivateProfile, auth.uspListProfilesForUser,
                auth.uspListMyProfiles and auth.uspSwitchProfile.
Target:         SQL Server 2022.
Run as:         db_owner in the target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/140_auth_profile_procedures.sql
Idempotent:     Yes.  CREATE OR ALTER throughout, and every grant guarded on DATABASE_PRINCIPAL_ID.
Depends on:     040_auth_userprofile.sql, 045_auth_identity.sql, 060_auth_profile_role.sql, 065_auth_effective_permission.sql,
                070_auth_session.sql, 085_logs_auth_tables.sql, 100_auth_functions.sql, 105_auth_session_procedures.sql,
                110_auth_authn_procedures.sql, 150_auth_query_procedures.sql (auth.uspDemandPermission),
                165_logs_procedures.sql, scripts/logExecutionLogging.sql, templates/extended-properties.sql.
Implements:     T-076, T-077, T-078, T-126, T-127.  DES-AUTH-001 sections 5.4, 6.1, 11.3, 11.4, 11.5, 12.1, 12.2, 12.3, 12.4,
                14.1 to 14.5, 15.5.  See docs/10-database-authn-authz-design.md.
To retarget:    Pass it per run:  sqlcmd -d <database> -v DbName=<database>.  There is no in-file default.

A PROFILE IS A HAT, AND THAT IS THE WHOLE MODEL
----------------------------------------------
Section 12.2: a person is one auth.User row, and every organization they act for is one auth.UserProfile row.  Roles,
grants, scope, row security and every audit attribution hang off the PROFILE, never off the user -- which is why
auth.UserProfileRole.UserProfileId and not UserId is the grant's subject, and why SESSION_CONTEXT ('AppUser') carries
the profile id (section 14.4).  One person doing two jobs for two counties has two profiles, two sets of grants and two
row-security footprints, and nothing in the database has to know they are the same human being.

That also settles what this file is NOT.  Nothing here creates a person (130_auth_user_procedures.sql), grants a role
(145_auth_role_procedures.sql) or touches a credential (110, 112).  A profile created here can be switched into and can
see whatever the default roles of its tenant grant, and nothing more.

Authz.ProfileCreate IS TESTED DIRECTLY, NOT THROUGH auth.uspDemandPermission, AND THE DENIAL IS STILL LOGGED
----------------------------------------------------------------------------------------------------------
Appendix B gives the authority failure in auth.uspCreateProfile its own number -- E-50045, "actor lacks
Authz.ProfileCreate over the requested tenant" -- and auth.uspDemandPermission throws E-50030 for every denial it
handles.  Calling uspDemandPermission would therefore make E-50045 unreachable, and the design registered it because
50040-50049 is the range the UI maps to "show WHICH clause of the administrative authority test failed" (section 19's
table), which is a different screen from 50030's flat "you may not do this".

So this procedure calls auth.udfHasPermission (N'Authz.ProfileCreate', @TenantId) itself and, when the answer is 0,
writes logs.uspRecordAuthorizationDenial -- the SAME trail row uspDemandPermission would have written, with the same
permission code, tenant and profile -- before throwing 50045.  The security decision is still entirely
auth.udfHasPermission's; only the error number and the message differ.  Losing the denial row would have been the real
defect: a refusal nobody can see is a refusal nobody can support.

AND IT IS TESTED AT THE TARGET TENANT, NOT AT THE ACTOR'S OWN
-----------------------------------------------------------
This is the opposite of 130's User.Create and section 11.4 says so in as many words: Authz.ProfileCreate is scoped
"exactly like Authz.RoleAssign", which means the actor must hold it at the target tenant or at a tenant ABOVE it.  A
profile IS access -- it is the thing a grant attaches to -- so the weaker test that makes a person record harmless
would here let a county administrator plant a hat in another county.

The ancestor-or-self part needs no closure walk in this file: auth.tvfPermissionScope already expands each grant DOWN
the tree through auth.TenantClosure, so auth.udfHasPermission (code, T) is TRUE exactly when the profile holds the
permission at T or at any ancestor of T.  That is worth stating because the obvious-looking hand-written walk would be
a second implementation of the same rule, and the two would drift.

DEFAULT ROLES ARE INHERITED FROM THE NEAREST ANCESTOR, NOT COPIED DOWN THE TREE
-----------------------------------------------------------------------------
Section 11.5: auth.TenantDefaultRole is read "inherited from the nearest ancestor if absent".  auth.uspCreateProfile
therefore finds the closest tenant at or above the new profile's tenant that HAS any default-role rows -- ORDER BY
auth.TenantClosure.Depth ASC, where Depth 0 is the tenant itself -- and grants that tenant's set.  It does not union
the sets down the chain, and it does not write auth.TenantDefaultRole rows for the new tenant.

The distinction is load-bearing and BL-052 records it: if a new tenant's defaults were COPIED at creation, changing the
parent's defaults later would leave every child frozen at the old set, and the only way to find out would be to read
every child's rows.  Inheritance means the parent's set is the answer until a child deliberately overrides it.

One filter on the way in: a default role whose auth.Role.OwnerTenantId does not cover the new tenant is SKIPPED rather
than granted, because granting it would violate INV-04 (a grant's scope must be at or beneath the role's owner) and
the FK would not catch it.  That is a seeding error in auth.TenantDefaultRole, not a caller error, so it does not fail
the call -- the count of skipped roles goes into logs.ExecutionLog.Comments where whoever seeded it can find it.

INV-03 IS "EXACTLY ONE DEFAULT", NOT "AT MOST ONE"
-------------------------------------------------
A user with no default profile has nothing to activate at sign-in -- 110's sign-in path reads the default to decide
which hat the session starts in -- so auth.uspCreateProfile FORCES @IsDefault = 1 when the new profile is the user's
first live one, whatever the caller passed, and auth.uspUpdateProfile refuses @IsDefault = 0 on the current default
with E-50164 rather than leaving a user who cannot sign in.  The way to move the flag is to pass @IsDefault = 1 on the
profile that should have it; the procedure clears the old one in the same transaction, because
UX_auth_UserProfile_Default is a filtered unique index and two defaults is error 2601, not a warning.

auth.uspDeactivateProfile moves the flag on for you when it can find another active profile.  When it cannot, the flag
STAYS on the profile it just deactivated, which looks wrong and is not: INV-03 says exactly one profile carries the
flag, not that the profile carrying it is active.  A user whose every profile is inactive cannot sign in for a reason
that has nothing to do with defaults, and blanking the flag would mean reactivating the profile later left them with
none.

SWITCHING YOUR OWN HAT IS NOT A PERMISSION
-----------------------------------------
There is no Authz.ProfileSwitch in the 35 permission codes and there was never meant to be.  Section 12.1's seven
steps test three things -- is the target profile YOURS (E-50050, and D-10 is explicit that this is not impersonation),
is it usable (E-50051), does policy demand step-up for it (E-50052) -- and none of them is a permission test.  The
authority to wear a hat is the existence of the hat; auth.uspCreateProfile is where that authority was exercised.

TWO PROCEDURES LIST PROFILES, AND THE SECOND ONE EXISTS BECAUSE THE FIRST LOCKED PEOPLE OUT -- G-51
-------------------------------------------------------------------------------------------------
auth.uspListProfilesForUser (section 4) demands Authz.ProfileRead and scopes its rows to the tenants the actor holds it
over.  Correct, for the administrative screen it serves.  Fatal, for the screen a user sees immediately after signing
in: a session with no active profile has no acting tenant and holds no permission anywhere, so the procedure refused it,
and refused it with E-50030's "there is NO SESSION CONTEXT on this connection" -- on a connection that had just
established some.  A user with twenty-two hats could not be told about any of them, and the diagnostic pointed at
auth.uspSetSessionContext, where nothing was wrong.  SCEN-AUTH-001 found it on the first call of the scenario.

auth.uspListMyProfiles (section 5) is the answer: no permission demand, no @UserId parameter, no scoping, and it reads
the user id out of the session row rather than off the signature.  The two procedures answer two questions -- "what hats
does THIS PERSON wear, of the ones I may know about" and "which of MY hats can I put on" -- and the second question has
no tenant scope in it at all.  T-126 also split the diagnostic in auth.uspDemandPermission, so that the profileless
session now gets E-50032 and its own message instead of a defect report about a defect that was not there.

WHY NOT AN @Mine FLAG ON THE PROCEDURE THAT ALREADY EXISTED.  Because the permission demand would have had to become
conditional on a parameter, and a conditional permission demand is the shape an authorization bypass is written in.  Two
bodies, two authorities, neither branching, is cheaper to review forever than one body that is right today.

auth.uspSwitchProfile RETURNS TWO RESULT SETS, AND THE SECOND IS A FORWARD REFERENCE TO T-084
-------------------------------------------------------------------------------------------
Section 12.1 step 7: the switch "returns the new profile context and navigation so the UI can repaint in one round
trip".  Two result sets, then -- the context, then the navigation -- because a UI that has to ask twice will render the
old menu against the new tenant for as long as the second call takes, and UI-04 is about exactly that flicker.

The navigation half is auth.uspGetNavigationForProfile, which is T-084 in 150_auth_query_procedures.sql and does not
exist when this file first runs.  The call is therefore guarded on OBJECT_ID and the closing report carries a PENDING
row naming it -- the pattern 125_auth_tenant_procedures.sql used for the same situation.  Its contract is fixed HERE
and now, deliberately:

    auth.uspGetNavigationForProfile @SessionTokenHash VARBINARY (32)

G-26 and BL-053 are what happens when a forward reference is written from a design sketch instead: section 9's and
section 12.1's sketches both say @SessionToken, the implementation has always been @SessionTokenHash VARBINARY (32),
and the mismatch was not found until something called it.  So the moment T-084 lands, the second result set gets
smoke-tested.

It was, during T-091, and it did not work.  See the next essay.

THE SWITCH USED TO THROW E-50022 ON EVERY CALL, AFTER SUCCEEDING -- G-36, BL-057
------------------------------------------------------------------------------
As first written, auth.uspSwitchProfile committed the switch and then called auth.uspSetSessionContext again, so that the
navigation read would see the new hat.  SESSION_CONTEXT keys are read-only for the life of a connection (error 15664),
and E-50022 is this database's own guard on that fact, so the second call raised EVERY TIME: the session had moved, the
logs.AuthenticationEvent row had been written, both were committed -- and the caller was told the call had failed.
Neither result set was ever returned.  A smoke test of 155 found it by accident, when a fixture that signed in and
switched profiles reported an error and then turned out to have switched.

Two fixes were possible and only one of them was real:

  -- Drop the navigation half and tell the client to ask again on its next connection.  That abandons section 12.1 step
     7 and UI-04's one-round-trip requirement for no reason other than the implementation having painted itself in.
  -- Stop routing the navigation read through session context.  auth.uspGetNavigationForProfile grew
     @AssumeUserProfileId (T-091): given a profile id it skips uspSetSessionContext entirely, proves from the session
     hash that the profile belongs to the session's user -- E-50050, the same test and the same number as step 2 here --
     and reads the tree for that profile.  It can answer for a hat the connection is not wearing because it never asks
     the connection what it is wearing.

The second is what shipped.  The consequence to state plainly, because it is now part of the contract: THE CONNECTION
THAT SWITCHES IS SPENT.  Its SESSION_CONTEXT still names the previous profile and cannot be changed, so the next request
must arrive on a new connection -- which is what UI-06 has said from the beginning ("one connection may not serve two
profiles") and what a pooled web application does anyway.  What the caller gets in exchange is both result sets in one
round trip, which is the whole of what step 7 was for.

'ProfileSwitch' HAD TO BE ADDED TO CK_logs_AuthenticationEvent_EventType BEFORE THIS FILE COULD RUN
-------------------------------------------------------------------------------------------------
Section 12.1 step 6 and section 15.5 both name the event type, and the constraint did not permit it: the renaming that
turned 'SignIn' into 'LoginSucceeded' and 'StepUp' into 'SessionElevated' dropped it on the way past, and nothing had
needed the value for four phases.  085_logs_auth_tables.sql was amended and its own drop-and-re-add guard repaired the
live database.  G-29, BL-055.
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

IF OBJECT_ID (N'auth.UserProfile', N'U') IS NULL
   OR OBJECT_ID (N'auth.UserProfileRole', N'U') IS NULL
   OR OBJECT_ID (N'auth.TenantDefaultRole', N'U') IS NULL
   OR OBJECT_ID (N'auth.UserSession', N'U') IS NULL
BEGIN
    DECLARE @MsgId NVARCHAR (2000) =
        N'One of auth.UserProfile, auth.UserProfileRole, auth.TenantDefaultRole or auth.UserSession is missing. Run '
      + N'database/040_auth_userprofile.sql, database/035_auth_tenant_policy.sql, database/060_auth_profile_role.sql '
      + N'and database/070_auth_session.sql first.';

    THROW 50000, @MsgId, 1;
END
GO

IF OBJECT_ID (N'auth.udfHasPermission', N'FN') IS NULL
   OR OBJECT_ID (N'auth.udfIsTenantUsable', N'FN') IS NULL
   OR OBJECT_ID (N'auth.udfResolveAuthPolicy', N'FN') IS NULL
   OR OBJECT_ID (N'auth.uspRebuildProfilePermissionScope', N'P') IS NULL
BEGIN
    DECLARE @MsgFn NVARCHAR (2000) =
        N'The authorization predicate functions or auth.uspRebuildProfilePermissionScope are missing. Run '
      + N'database/100_auth_functions.sql and database/065_auth_effective_permission.sql first: auth.uspCreateProfile '
      + N'makes its own authority decision with auth.udfHasPermission and rebuilds the new profile''s scope in the '
      + N'same transaction, and neither is optional.';

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


-- *** 1. auth.uspCreateProfile ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspCreateProfile
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Gives an existing person a hat at one tenant.  Tests Authz.ProfileCreate at the TARGET tenant (section 11.4, scoped
exactly like Authz.RoleAssign), grants the nearest ancestor's default roles (section 11.5), rebuilds the new profile's
permission scope in the same transaction and returns the new UserProfileId.

========================================================================================================================
Requirements and Key Dependencies:

auth.UserProfile, auth.UserProfileRole, auth.TenantDefaultRole, auth.Role, auth.Tenant, auth.TenantClosure,
auth.udfHasPermission, auth.udfIsTenantUsable, auth.uspSetSessionContext, auth.uspRebuildProfilePermissionScope,
logs.uspRecordAuthorizationDenial, logs.uspRecordAuthorizationChange.  Granted to applicationRole.

========================================================================================================================
Notes:

THE AUTHORITY TEST IS auth.udfHasPermission AND NOT auth.uspDemandPermission, AND THE DENIAL IS STILL WRITTEN.  See the
file header: E-50045 is Appendix B's own number for this failure and uspDemandPermission can only throw E-50030, so
delegating would make the registered number unreachable.  logs.uspRecordAuthorizationDenial is called by hand so the
trail row is identical to the one uspDemandPermission would have written.

@UserId IS CHECKED BEFORE @TenantId, AND THAT ORDER IS IN APPENDIX B.  E-50160's entry says "checked before the tenant,
because the actor chose the user and can act on the answer": a caller who picked a deleted user needs to hear about the
user, and hearing about the tenant first sends them to fix the wrong half of the request.

@ProfileName IS THE LABEL IN THE HAT SWITCHER, NOT AN IDENTIFIER.  UX_auth_UserProfile_UserTenantName makes it unique
per user per tenant among live rows -- E-50162 -- because two identically named hats are indistinguishable in section
12.2's switcher and picking the wrong one silently sets a different ScopeTenantId on everything the session then writes.
It is NOT unique across users or across tenants: "Case Worker" at forty counties is forty rows.

@IsDefault = 0 ON A FIRST PROFILE IS OVERRIDDEN, SILENTLY AND ON PURPOSE.  INV-03 is "exactly one", so a user whose only
profile is not the default has no hat to activate at sign-in.  The override is reported in logs.ExecutionLog.Comments.

A SKIPPED DEFAULT ROLE IS A SEEDING ERROR AND DOES NOT FAIL THE CALL.  A role whose OwnerTenantId does not cover the new
tenant cannot be granted at it without breaking INV-04; the row is omitted, the count is in the comments, and the
profile is still created -- refusing would make one bad auth.TenantDefaultRole row block every new profile beneath it.

========================================================================================================================
Example Usage and Performance:

declare @ProfileId int;
exec auth.uspCreateProfile @SessionTokenHash = 0x9F86..., @UserId = 42, @TenantId = 7
                         , @ProfileName = N'Case Worker', @IsDefault = 0, @NewUserProfileId = @ProfileId output;

One scope test, one closure seek for the default source, one insert, one small insert-select, one scope rebuild for the
new profile only, and one trail row per role granted.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-076
Description:
Created.  Phase 6.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspCreateProfile
      @SessionTokenHash  VARBINARY (32)
    , @UserId            INT
    , @TenantId          INT
    , @ProfileName       NVARCHAR (256)
    , @IsDefault         BIT = 0
    , @NewUserProfileId  INT OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspCreateProfile]')
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

    DECLARE @Actor                 NVARCHAR (255)  = NULL
          , @ActorProfileId        INT             = NULL
          , @ActingTenantId        INT             = NULL
          , @DefaultSourceTenantId INT             = NULL
          , @ApplicationId         INT             = NULL
          , @LiveProfileCount      INT             = NULL
          , @DefaultForced         BIT             = 0
          , @CandidateRoleCount    INT             = 0
          , @GrantedRoleCount      INT             = 0
          , @ChangeId              BIGINT          = NULL
          , @DenialId              BIGINT          = NULL
          , @DetailJson            NVARCHAR (400)  = NULL
          , @Failure               NVARCHAR (2000) = NULL;

    -- Identifiers and counts only. @ProfileName is a label rather than a secret, so it is logged; nothing here is a
    -- credential, a token or a hash. UI-16.
    SET @KeyParameters = CONCAT (N'UserId=', @UserId, N', TenantId=', @TenantId
                               , N', ProfileName=', @ProfileName, N', IsDefault=', @IsDefault);

    SET @NewUserProfileId = NULL;

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

        -- CONTEXT AND AUTHORITY COME BEFORE THE TRANSACTION, AND THAT ORDER IS LOAD-BEARING. BL-042: a denial row
        -- written inside a transaction the refusal then rolls back is a denial nobody can see. Section 9 orders the
        -- permission check ahead of step 6 for exactly this reason, and 165_logs_procedures.sql's header says so in as
        -- many words. G-31 records that 125 and 130 do it the other way round and owe the same correction.
        -- Section 14.1: this procedure establishes its own context and never trusts a previous call. UI-05.
        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        SET @ActorProfileId = TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT);
        SET @ActingTenantId = TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT);

        -- Section 11.4, and the header explains why this is a hand-rolled test rather than a call to
        -- auth.uspDemandPermission. @TenantId, not @ActingTenantId: the permission must be held AT or ABOVE the tenant
        -- the hat is being planted in, and auth.tvfPermissionScope has already expanded every grant down the tree, so
        -- this single call IS the ancestor-or-self test.
        IF auth.udfHasPermission (N'Authz.ProfileCreate', @TenantId) = 0
        BEGIN
            -- The same trail row auth.uspDemandPermission writes, written by hand so that choosing the sharper error
            -- number does not cost the audit its record of the refusal.
            SET @DetailJson = CONCAT (N'{"procedure":"auth.uspCreateProfile","targetUserId":', @UserId
                                    , N',"targetTenantId":', @TenantId, N',"error":50045}');

            EXEC logs.uspRecordAuthorizationDenial
                  @PermissionCode        = N'Authz.ProfileCreate'
                , @TenantId              = @TenantId
                , @UserProfileId         = @ActorProfileId
                , @ObjectName            = N'auth.uspCreateProfile'
                , @DetailJson            = @DetailJson
                , @AuthorizationDenialId = @DenialId OUTPUT;

            SET @Failure = N'You do not hold Authz.ProfileCreate over the requested tenant. Section 11.4 scopes it '
                         + N'exactly like Authz.RoleAssign: it must be held AT that tenant or at a tenant above it, '
                         + N'because a profile is the thing a grant attaches to. Holding it at a sibling tenant is not '
                         + N'enough. The refusal has been recorded. No profile was created.';
            ;THROW 50045, @Failure, 1;
        END;

        SET @Actor = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N''), ORIGINAL_LOGIN ());

        -- Authority settled and its refusal durably recorded. NOW the transaction, which covers the validations, the
        -- insert, the default-role grants, the scope rebuild and the trail as one unit.
        BEGIN TRANSACTION;

        SET @ProfileName = NULLIF (LTRIM (RTRIM (@ProfileName)), N'');

        -- CK_auth_UserProfile_ProfileName would refuse a blank or an untrimmed value anyway; this names the parameter
        -- instead of the constraint. E-50162 is the collision; a blank name is the same class of caller error, so it
        -- rides the same number rather than inventing one Appendix B does not register.
        IF @ProfileName IS NULL
        BEGIN
            SET @Failure = N'@ProfileName is required and may not be blank or whitespace. It is the label the hat '
                         + N'switcher shows (section 12.2), so a profile without one is a hat nobody can pick. No '
                         + N'profile was created.';
            ;THROW 50162, @Failure, 1;
        END;

        -- Appendix B: the user is checked FIRST, deliberately. See the notes.
        IF NOT EXISTS (SELECT 1 FROM auth.[User] AS u WHERE u.UserId = @UserId AND u.IsDeleted = 0)
        BEGIN
            SET @Failure = N'No such user, or the user has been deleted. A profile belongs to a person; create the '
                         + N'person with auth.uspCreateUser first. No profile was created.';
            ;THROW 50160, @Failure, 1;
        END;

        -- Section 5.4: "usable" is stricter than "exists" -- auth.udfIsTenantUsable returns 0 when the tenant or ANY
        -- tenant above it is inactive, because an inactive parent suspends the whole branch. Creating a hat at a
        -- suspended tenant would produce a profile that cannot be switched into (E-50051 in uspSwitchProfile), which
        -- is a worse answer than refusing now.
        SELECT @ApplicationId = t.ApplicationId
          FROM auth.Tenant AS t
         WHERE t.TenantId  = @TenantId
           AND t.IsDeleted = 0;

        IF @ApplicationId IS NULL OR auth.udfIsTenantUsable (@TenantId) = 0
        BEGIN
            SET @Failure = N'The tenant does not exist, has been deleted, or is unusable because it or a tenant above '
                         + N'it is inactive (section 5.4). Reactivate the branch before giving anybody a hat in it. No '
                         + N'profile was created.';
            ;THROW 50161, @Failure, 1;
        END;

        IF EXISTS (SELECT 1
                     FROM auth.UserProfile AS p
                    WHERE p.UserId      = @UserId
                      AND p.TenantId    = @TenantId
                      AND p.ProfileName = @ProfileName
                      AND p.IsDeleted   = 0)
        BEGIN
            SET @Failure = N'This user already has a live profile of that name at that tenant. Names are unique per '
                         + N'user per tenant (UX_auth_UserProfile_UserTenantName, BL-036) because two identically '
                         + N'named hats are indistinguishable in the switcher and picking the wrong one sets a '
                         + N'different ScopeTenantId on everything the session writes. No profile was created.';
            ;THROW 50162, @Failure, 1;
        END;

        -- INV-03 is "exactly one". See the header: a user whose first profile is not the default has no hat to
        -- activate at sign-in, so the caller's 0 is overridden and the override is reported.
        SELECT @LiveProfileCount = COUNT (*)
          FROM auth.UserProfile AS p
         WHERE p.UserId    = @UserId
           AND p.IsDeleted = 0;

        IF @LiveProfileCount = 0 AND @IsDefault = 0
        BEGIN
            SET @IsDefault    = 1;
            SET @DefaultForced = 1;
        END;

        -- UX_auth_UserProfile_Default is filtered unique on IsDefault = 1 AND IsDeleted = 0, so the old default has to
        -- go before the new row lands -- two defaults is error 2601, not a warning.
        IF @IsDefault = 1
        BEGIN
            UPDATE p
               SET p.IsDefault       = 0
                 , p.auditModifiedBy = @Actor
              FROM auth.UserProfile AS p
             WHERE p.UserId    = @UserId
               AND p.IsDefault = 1
               AND p.IsDeleted = 0;
        END;

        -- auditCreatedBy set EXPLICITLY: under the pooled application login ORIGINAL_LOGIN () is the application's own
        -- name, identical on every row. Section 14.4, F-02, UI-17.
        INSERT auth.UserProfile (UserId, TenantId, ProfileName, IsDefault, IsActive, auditCreatedBy, auditModifiedBy)
        VALUES (@UserId, @TenantId, @ProfileName, @IsDefault, 1, @Actor, @Actor);

        SET @NewUserProfileId = CAST (SCOPE_IDENTITY () AS INT);

        -- Section 11.5.  THE RULE LIVES IN auth.uspGrantTenantDefaultRoles (section 7 of this file), not here, because
        -- auth.uspRegisterExternalUser in 155_auth_registration_procedures.sql has to reach the same rule from an
        -- UNAUTHENTICATED entry point where there is no permission to demand.  It writes its own 'RoleGranted' trail
        -- rows and hands back where the set came from and how many candidates it skipped; this procedure reports those
        -- numbers in its Comments, where an operator reads them.
        EXEC auth.uspGrantTenantDefaultRoles
              @UserProfileId          = @NewUserProfileId
            , @TenantId               = @TenantId
            , @ApplicationId          = @ApplicationId
            , @TargetUserId           = @UserId
            , @ActorUserProfileId     = @ActorProfileId
            , @ActorAuthorityTenantId = @ActingTenantId
            , @Actor                  = @Actor
            , @DefaultSourceTenantId  = @DefaultSourceTenantId OUTPUT
            , @CandidateRoleCount     = @CandidateRoleCount    OUTPUT
            , @GrantedRoleCount       = @GrantedRoleCount      OUTPUT;

        -- One rebuild, for one profile, inside the transaction: section 10.3's derived table is only correct if it is
        -- maintained by whoever changed the grants. Doing it here rather than leaving it to the nightly rebuild is the
        -- difference between a new hat that works and a new hat that works tomorrow.
        EXEC auth.uspRebuildProfilePermissionScope @UserProfileId = @NewUserProfileId;

        SET @DetailJson = CONCAT (N'{"tenantId":', @TenantId, N',"isDefault":', @IsDefault
                                , N',"defaultRoleSourceTenantId":'
                                , COALESCE (CAST (@DefaultSourceTenantId AS NVARCHAR (11)), N'null')
                                , N',"defaultRolesGranted":', @GrantedRoleCount, N'}');

        EXEC logs.uspRecordAuthorizationChange
              @ChangeType             = 'ProfileCreated'
            , @TargetUserId           = @UserId
            , @TargetUserProfileId    = @NewUserProfileId
            , @RoleId                 = NULL
            , @ScopeTenantId          = @TenantId
            , @ActorUserProfileId     = @ActorProfileId
            , @ActorAuthorityTenantId = @ActingTenantId
            , @DetailJson             = @DetailJson
            , @AuthorizationChangeId  = @ChangeId OUTPUT;

        -- The per-role 'RoleGranted' trail rows are written by auth.uspGrantTenantDefaultRoles, one each, because
        -- section 15.6's logs.vwAuthorizationTrail answers "how did this profile come to hold this role" one row at a
        -- time. They belong with the grant that caused them rather than with the caller, so that a self-registration
        -- leaves the same trail as an administrator's hat.
        SET @Comments = CONCAT (N'Created UserProfileId=', @NewUserProfileId, N' for UserId=', @UserId
                              , N' at TenantId=', @TenantId, N'. IsDefault=', @IsDefault
                              , CASE WHEN @DefaultForced = 1
                                     THEN N' (forced: first live profile, INV-03 is exactly one)' ELSE N'' END
                              , N'. Default roles: '
                              , CASE WHEN @DefaultSourceTenantId IS NULL
                                     THEN N'none -- no tenant at or above this one seeds auth.TenantDefaultRole'
                                     ELSE CONCAT (@GrantedRoleCount, N' of ', @CandidateRoleCount, N' from TenantId='
                                                , @DefaultSourceTenantId
                                                , CASE WHEN @DefaultSourceTenantId = @TenantId
                                                       THEN N' (its own set)' ELSE N' (inherited)' END
                                                , CASE WHEN @CandidateRoleCount > @GrantedRoleCount
                                                       THEN CONCAT (N'. SKIPPED ', @CandidateRoleCount
                                                                  - @GrantedRoleCount
                                                                  , N': deleted, IsAssignable = 0, wrong '
                                                                  + N'ApplicationId, or an OwnerTenantId that does '
                                                                  + N'not cover this tenant (INV-04) -- a seeding '
                                                                  + N'error in auth.TenantDefaultRole, not a caller '
                                                                  + N'error')
                                                       ELSE N'' END)
                                     END
                              , N'. Scope rebuilt for this profile only.');

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


-- *** 2. auth.uspUpdateProfile ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspUpdateProfile
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Renames a hat, or moves the default flag onto it.  Demands Authz.ProfileUpdate at the profile's OWN tenant.  Changes
nothing else: a profile's user and tenant are its identity and neither is a parameter here.

========================================================================================================================
Requirements and Key Dependencies:

auth.UserProfile, auth.uspSetSessionContext, auth.uspDemandPermission.  Granted to applicationRole.

========================================================================================================================
Notes:

@UserId AND @TenantId ARE NOT PARAMETERS, AND NOT BY OVERSIGHT.  Moving a profile to another tenant would silently
re-scope every grant hanging off it and re-point every row auth.UserProfileRole.ScopeTenantId governs; moving it to
another user would reattribute every audit row that names it.  Both are "create the new hat, deactivate the old one",
which leaves the trail intact, and E-50011's TenantId-immutability trigger on the demo tables exists for the same
reason one layer down.

THE PERMISSION IS DEMANDED BEFORE THE "NO SUCH PROFILE" TEST, WHICH IS WHY THE LOOKUP COMES FIRST.  The tenant to demand
it at can only be read off the profile, so the row is fetched, then the permission is demanded at the profile's tenant if
it was found and at the ACTOR'S OWN acting tenant if it was not, and only then does E-50163 fire.  A caller holding
Authz.ProfileUpdate nowhere therefore gets E-50030 whatever id they pass, and never learns whether it exists.

@IsDefault IS BIT NULL HERE AND BIT NOT NULL IN uspCreateProfile.  NULL means "leave the flag where it is", which is the
common case; 1 moves it here and clears whichever profile had it; 0 is refused on the current default with E-50164,
because INV-03 is "exactly one" and a user with no default cannot sign in.  Passing 0 on a profile that is not the
default is a legal no-op.

NO TRAIL ROW IS WRITTEN, OF EITHER KIND.  A rename is not an authorization change -- nothing about what the hat MAY do
has moved -- and neither is the default flag, which decides only which hat a session starts in.  The audit columns on
the row carry who and when, and logs.ExecutionLog carries the call. Same reasoning as auth.uspUpdateUser (BL-054).

========================================================================================================================
Example Usage and Performance:

exec auth.uspUpdateProfile @SessionTokenHash = 0x9F86..., @UserProfileId = 88, @ProfileName = N'Senior Case Worker';
exec auth.uspUpdateProfile @SessionTokenHash = 0x9F86..., @UserProfileId = 88, @IsDefault = 1;

Two seeks and at most two single-row updates.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-077
Description:
Created.  Phase 6.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspUpdateProfile
      @SessionTokenHash VARBINARY (32)
    , @UserProfileId    INT
    , @ProfileName      NVARCHAR (256) = NULL
    , @IsDefault        BIT            = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspUpdateProfile]')
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
          , @TargetTenantId INT             = NULL
          , @TargetUserId   INT             = NULL
          , @WasDefault     BIT             = NULL
          , @DemandTenantId INT             = NULL
          , @DefaultMoved   BIT             = 0
          , @Renamed        BIT             = 0
          , @Failure        NVARCHAR (2000) = NULL;

    SET @KeyParameters = CONCAT (N'UserProfileId=', @UserProfileId
                               , N', HasProfileName=', CASE WHEN @ProfileName IS NULL THEN N'0' ELSE N'1' END
                               , N', IsDefault=', COALESCE (CAST (@IsDefault AS NVARCHAR (1)), N'null'));

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

        -- Context, lookup and authority BEFORE the transaction, so auth.uspDemandPermission's denial row survives the
        -- refusal it provokes. BL-042, G-31; the same ordering as auth.uspCreateProfile above.
        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        SET @ActorProfileId = TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT);
        SET @ActingTenantId = TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT);

        -- The lookup that the permission test needs. See the notes: this is not validation running ahead of authority,
        -- it is authority needing a tenant to be demanded at.
        SELECT @TargetTenantId = p.TenantId
             , @TargetUserId   = p.UserId
             , @WasDefault     = p.IsDefault
          FROM auth.UserProfile AS p
         WHERE p.UserProfileId = @UserProfileId
           AND p.IsDeleted     = 0;

        -- EXEC will not take an expression for a parameter -- Msg 156 -- so the fallback is resolved into a variable
        -- first. COALESCE, because the id may name nothing: see the comment below.
        SET @DemandTenantId = COALESCE (@TargetTenantId, @ActingTenantId);

        EXEC auth.uspDemandPermission
              @PermissionCode = N'Authz.ProfileUpdate'
              -- COALESCE, because the id may name nothing: demanding the permission at the ACTOR'S OWN tenant in that
              -- case means a caller who holds it nowhere is refused with E-50030 before E-50163 can confirm or deny
              -- that the profile exists.
            , @TenantId       = @DemandTenantId
            , @ObjectName     = N'auth.uspUpdateProfile';

        SET @Actor = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N''), ORIGINAL_LOGIN ());

        IF @TargetTenantId IS NULL
        BEGIN
            SET @Failure = N'No such profile, or it has been deleted. Nothing was changed.';
            ;THROW 50163, @Failure, 1;
        END;

        -- The transaction covers the two updates that have to agree with each other: clearing the old default and
        -- setting the new one. The lookup above is outside it, so a profile soft-deleted in between would be missed --
        -- which is why both updates still carry AND IsDeleted = 0 and change nothing if it happened.
        BEGIN TRANSACTION;

        SET @ProfileName = NULLIF (LTRIM (RTRIM (@ProfileName)), N'');

        IF @ProfileName IS NOT NULL
           AND EXISTS (SELECT 1
                         FROM auth.UserProfile AS p
                        WHERE p.UserId        = @TargetUserId
                          AND p.TenantId      = @TargetTenantId
                          AND p.ProfileName   = @ProfileName
                          AND p.UserProfileId <> @UserProfileId
                          AND p.IsDeleted     = 0)
        BEGIN
            SET @Failure = N'This user already has another live profile of that name at that tenant. Names are unique '
                         + N'per user per tenant (UX_auth_UserProfile_UserTenantName, BL-036): two identically named '
                         + N'hats are indistinguishable in the switcher. Nothing was changed.';
            ;THROW 50162, @Failure, 1;
        END;

        -- INV-03. See the header: the flag is moved, never blanked.
        IF @IsDefault = 0 AND @WasDefault = 1
        BEGIN
            SET @Failure = N'This is the user''s current default profile and the default cannot simply be switched '
                         + N'off. INV-03 is "exactly one", not "at most one": a user with no default has no hat to '
                         + N'activate at sign-in. Pass @IsDefault = 1 on the profile that should have it instead -- '
                         + N'this procedure clears the old one for you. Nothing was changed.';
            ;THROW 50164, @Failure, 1;
        END;

        -- Clear first, set second, both inside the one transaction: UX_auth_UserProfile_Default is filtered unique and
        -- would refuse the overlap with error 2601 if the order were reversed.
        IF @IsDefault = 1 AND @WasDefault = 0
        BEGIN
            UPDATE p
               SET p.IsDefault       = 0
                 , p.auditModifiedBy = @Actor
              FROM auth.UserProfile AS p
             WHERE p.UserId        = @TargetUserId
               AND p.IsDefault     = 1
               AND p.UserProfileId <> @UserProfileId
               AND p.IsDeleted     = 0;

            SET @DefaultMoved = 1;
        END;

        UPDATE p
           SET p.ProfileName = COALESCE (@ProfileName, p.ProfileName)
             , p.IsDefault   = CASE WHEN @IsDefault IS NULL THEN p.IsDefault ELSE @IsDefault END
             -- Set explicitly so the acting PROFILE is recorded and not the pooled login. The AFTER UPDATE trigger
             -- honours a supplied value (section 14.4).
             , p.auditModifiedBy = @Actor
          FROM auth.UserProfile AS p
         WHERE p.UserProfileId = @UserProfileId
           AND p.IsDeleted     = 0;

        SET @Renamed = CASE WHEN @ProfileName IS NULL THEN 0 ELSE 1 END;

        SET @Comments = CONCAT (N'Updated UserProfileId=', @UserProfileId, N' (UserId=', @TargetUserId
                              , N', TenantId=', @TargetTenantId, N'). '
                              , CASE WHEN @Renamed = 1 THEN N'Renamed. ' ELSE N'' END
                              , CASE WHEN @DefaultMoved = 1 THEN N'Default flag moved to this profile. ' ELSE N'' END
                              , CASE WHEN @Renamed = 0 AND @DefaultMoved = 0
                                     THEN N'No field changed -- every parameter was NULL or already the current value, '
                                        + N'which is a legal no-op. ' ELSE N'' END
                              , N'No authorization trail row: neither a rename nor the default flag changes what this '
                              + N'hat may do.');

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


-- *** 3. auth.uspDeactivateProfile ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspDeactivateProfile
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Takes a hat away, or gives it back.  Demands Authz.ProfileDeactivate at the profile's own tenant.  Sets IsActive and
NEVER IsDeleted, moves the default flag on if it has to, and ends any live session still wearing the hat.

========================================================================================================================
Requirements and Key Dependencies:

auth.UserProfile, auth.UserSession, auth.uspSetSessionContext, auth.uspDemandPermission,
logs.uspRecordAuthorizationChange.  Granted to applicationRole.

========================================================================================================================
Notes:

IsActive, NOT IsDeleted, AND THE GRANTS ARE LEFT WHERE THEY ARE.  Section 6.3 and P-07: the profile is what every audit
row, every grant and every governed data row is attributed to, so deleting it takes "who approved this in March" with
it. Nothing is removed from auth.UserProfileRole either -- auth.ProfilePermissionScope is read through a join that
already requires the profile to be active, so an inactive hat grants nothing while it is inactive and grants exactly what
it used to the moment it is reactivated.  Revoking grants on deactivation would make reactivation a re-provisioning
exercise, which is how a "temporary" suspension turns into a support ticket.

E-50165 REFUSES DEACTIVATING THE HAT YOU ARE WEARING, AND THE REASON IS NOT TIDINESS.  The calling session's
ActiveUserProfileId would point at an inactive profile, so the very next call's auth.uspSetSessionContext would fail
with E-50021 -- "the session's active profile is not usable" -- and the user would be locked out of a UI that has no way
to tell them why.  Section 12: switch first, then deactivate.

THE DEFAULT FLAG MOVES IF IT CAN AND STAYS IF IT CANNOT.  See the file header.  When the profile being deactivated holds
the flag, the lowest-numbered other ACTIVE profile takes it -- lowest-numbered because it is the oldest, and the oldest
hat is the likeliest to still be the right one.  When there is no other active profile the flag stays put, which is
legal: INV-03 says exactly one profile carries it, not that the carrier is active.

LIVE SESSIONS ON THE HAT ARE ENDED IN THE SAME TRANSACTION.  EndReason 'ProfileDeactivated'.  A user signed in on a
second device would otherwise keep working until their next request happened to fail; ending it here makes the refusal
happen at a moment somebody is watching.  There is no EndReason whitelist -- CK_auth_UserSession_EndedPair only requires
EndedUtc and EndReason to agree and the reason to be non-empty.

REACTIVATION AT AN UNUSABLE TENANT IS PERMITTED.  Appendix B registers no error for it and refusing would be wrong:
reactivating the hats before reactivating the branch is a perfectly ordinary order to do the work in, and section 5.4's
usability test will keep the hat unusable until the branch is back.  The condition is reported in the comments.

========================================================================================================================
Example Usage and Performance:

exec auth.uspDeactivateProfile @SessionTokenHash = 0x9F86..., @UserProfileId = 88;              -- take the hat away
exec auth.uspDeactivateProfile @SessionTokenHash = 0x9F86..., @UserProfileId = 88, @IsActive = 1; -- give it back

Two seeks, at most three single-row updates and one small update of that profile's live sessions.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-077
Description:
Created.  Phase 6.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspDeactivateProfile
      @SessionTokenHash VARBINARY (32)
    , @UserProfileId    INT
    , @IsActive         BIT = 0
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspDeactivateProfile]')
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
          , @TargetTenantId  INT             = NULL
          , @TargetUserId    INT             = NULL
          , @WasActive       BIT             = NULL
          , @WasDefault      BIT             = NULL
          , @DemandTenantId  INT             = NULL
          , @NewDefaultId    INT             = NULL
          , @SessionsEnded   INT             = 0
          , @TenantUsable    BIT             = NULL
          , @Now             DATETIME2 (3)   = NULL
          , @ChangeType      VARCHAR (40)    = NULL
          , @ChangeId        BIGINT          = NULL
          , @DetailJson      NVARCHAR (400)  = NULL
          , @Failure         NVARCHAR (2000) = NULL;

    SET @KeyParameters = CONCAT (N'UserProfileId=', @UserProfileId, N', IsActive=', @IsActive);

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

        -- Context, lookup and authority BEFORE the transaction: BL-042, G-31. Same ordering as the two procedures above.
        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        SET @ActorProfileId = TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT);
        SET @ActingTenantId = TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT);
        SET @Now            = SYSUTCDATETIME ();

        -- The lookup the permission test needs; same reasoning as auth.uspUpdateProfile's notes.
        SELECT @TargetTenantId = p.TenantId
             , @TargetUserId   = p.UserId
             , @WasActive      = p.IsActive
             , @WasDefault     = p.IsDefault
          FROM auth.UserProfile AS p
         WHERE p.UserProfileId = @UserProfileId
           AND p.IsDeleted     = 0;

        -- Resolved into a variable because EXEC will not take an expression for a parameter (Msg 156).
        SET @DemandTenantId = COALESCE (@TargetTenantId, @ActingTenantId);

        EXEC auth.uspDemandPermission
              @PermissionCode = N'Authz.ProfileDeactivate'
            , @TenantId       = @DemandTenantId
            , @ObjectName     = N'auth.uspDeactivateProfile';

        SET @Actor = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N''), ORIGINAL_LOGIN ());

        IF @TargetTenantId IS NULL
        BEGIN
            SET @Failure = N'No such profile, or it has been deleted. Nothing was changed.';
            ;THROW 50163, @Failure, 1;
        END;

        -- SESSION_CONTEXT ('UserProfileId') IS the calling session's ActiveUserProfileId -- auth.uspSetSessionContext
        -- sets it from that column and nowhere else -- so this comparison is the session test without a second read.
        IF @IsActive = 0 AND @UserProfileId = @ActorProfileId
        BEGIN
            SET @Failure = N'This is the profile your own session is currently using and it cannot be deactivated from '
                         + N'inside itself. Your next call would fail with E-50021 -- the session''s active profile is '
                         + N'not usable -- and the UI would have no way to explain it. Switch to another profile with '
                         + N'auth.uspSwitchProfile first, then deactivate this one. Nothing was changed.';
            ;THROW 50165, @Failure, 1;
        END;

        SET @TenantUsable = auth.udfIsTenantUsable (@TargetTenantId);

        -- The transaction covers the writes that have to agree with each other: the flag leaving, the flag arriving,
        -- the state change, and the live sessions that go with it.
        BEGIN TRANSACTION;

        -- The default flag first, so the profile is never left inactive-and-default while another profile is available
        -- to hold it. UX_auth_UserProfile_Default is filtered unique, so the flag has to leave before it can arrive.
        IF @IsActive = 0 AND @WasDefault = 1
        BEGIN
            SELECT TOP (1) @NewDefaultId = p.UserProfileId
              FROM auth.UserProfile AS p
             WHERE p.UserId         = @TargetUserId
               AND p.UserProfileId <> @UserProfileId
               AND p.IsActive       = 1
               AND p.IsDeleted      = 0
             ORDER BY p.UserProfileId ASC;   -- oldest first; see the notes

            IF @NewDefaultId IS NOT NULL
            BEGIN
                UPDATE p
                   SET p.IsDefault       = 0
                     , p.auditModifiedBy = @Actor
                  FROM auth.UserProfile AS p
                 WHERE p.UserProfileId = @UserProfileId;

                UPDATE p
                   SET p.IsDefault       = 1
                     , p.auditModifiedBy = @Actor
                  FROM auth.UserProfile AS p
                 WHERE p.UserProfileId = @NewDefaultId;
            END;
        END;

        UPDATE p
           SET p.IsActive        = @IsActive
             -- Set explicitly so the acting PROFILE is recorded and not the pooled login (section 14.4).
             , p.auditModifiedBy = @Actor
          FROM auth.UserProfile AS p
         WHERE p.UserProfileId = @UserProfileId
           AND p.IsDeleted     = 0;

        -- Live sessions still wearing the hat, ended here rather than left to fail on their own next request. The
        -- actor's own session cannot be among them: E-50165 above made sure of that.
        IF @IsActive = 0
        BEGIN
            UPDATE s
               SET s.EndedUtc        = @Now
                 , s.EndReason       = 'ProfileDeactivated'
                 , s.auditModifiedBy = @Actor
              FROM auth.UserSession AS s
             WHERE s.ActiveUserProfileId = @UserProfileId
               AND s.EndedUtc IS NULL
               AND s.IsDeleted          = 0;

            SET @SessionsEnded = @@ROWCOUNT;
        END;

        -- The trail. This one IS an authorization change -- a hat that no longer works is access removed -- and both
        -- directions are in CK_logs_AuthorizationChange_ChangeType's closed vocabulary.
        SET @ChangeType = CASE WHEN @IsActive = 0 THEN 'ProfileDeactivated' ELSE 'ProfileActivated' END;

        SET @DetailJson = CONCAT (N'{"wasActive":', @WasActive, N',"isActive":', @IsActive
                                , N',"defaultFlagMovedTo":'
                                , COALESCE (CAST (@NewDefaultId AS NVARCHAR (11)), N'null')
                                , N',"sessionsEnded":', @SessionsEnded
                                , N',"tenantUsable":', @TenantUsable, N'}');

        EXEC logs.uspRecordAuthorizationChange
              @ChangeType             = @ChangeType
            , @TargetUserId           = @TargetUserId
            , @TargetUserProfileId    = @UserProfileId
            , @RoleId                 = NULL
            , @ScopeTenantId          = @TargetTenantId
            , @ActorUserProfileId     = @ActorProfileId
            , @ActorAuthorityTenantId = @ActingTenantId
            , @DetailJson             = @DetailJson
            , @AuthorizationChangeId  = @ChangeId OUTPUT;

        SET @Comments = CONCAT (N'UserProfileId=', @UserProfileId, N' (UserId=', @TargetUserId, N', TenantId='
                              , @TargetTenantId, N') IsActive ', @WasActive, N' -> ', @IsActive, N'. '
                              , CASE WHEN @WasActive = @IsActive
                                     THEN N'No change of state -- a legal no-op. ' ELSE N'' END
                              , CASE WHEN @IsActive = 0 AND @WasDefault = 1 AND @NewDefaultId IS NOT NULL
                                     THEN CONCAT (N'Default flag moved to UserProfileId=', @NewDefaultId, N'. ')
                                     WHEN @IsActive = 0 AND @WasDefault = 1
                                     THEN N'Default flag LEFT on this inactive profile: the user has no other active '
                                        + N'profile to hold it, which INV-03 permits -- exactly one profile carries '
                                        + N'the flag, and nothing requires that one to be active. '
                                     ELSE N'' END
                              , CASE WHEN @IsActive = 0
                                     THEN CONCAT (@SessionsEnded, N' live session(s) ended with EndReason '
                                                + N'ProfileDeactivated. ') ELSE N'' END
                              , CASE WHEN @IsActive = 1 AND @TenantUsable = 0
                                     THEN N'NOTE: the tenant is still unusable (it or a tenant above it is inactive), '
                                        + N'so this hat cannot be switched into until the branch is reactivated -- '
                                        + N'section 5.4. Permitted on purpose. ' ELSE N'' END
                              , N'Grants untouched; IsDeleted untouched.');

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


-- *** 4. auth.uspListProfilesForUser ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspListProfilesForUser
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Every hat one person wears, for a profile-administration screen.  Demands Authz.ProfileRead, and returns only the
profiles at tenants the actor holds it over.  Error-only instrumented: no start row is opened.

========================================================================================================================
Requirements and Key Dependencies:

auth.UserProfile, auth.Tenant, auth.UserProfileRole, auth.tvfPermissionScope, auth.udfIsTenantUsable,
auth.uspSetSessionContext, auth.uspDemandPermission.  Granted to applicationRole.

========================================================================================================================
Notes:

ROWS OUTSIDE THE ACTOR'S Authz.ProfileRead SCOPE ARE OMITTED ENTIRELY RATHER THAN MARKED.  Authz.ProfileRead IS
tenant-scoped -- unlike User.Read, which section 11.4 makes deliberately weaker because a person record is harmless --
and "A has a hat at the neighbouring county" is exactly the fact the scoping exists to keep inside that county.  Omitting
rather than flagging is the same choice T-084's navigation makes for elements the profile cannot view: a greyed-out row
still tells you the thing exists.

The filter is one EXISTS against auth.tvfPermissionScope, which has already expanded every grant DOWN the tree through
auth.TenantClosure -- so "held at this tenant or any tenant above it" needs no closure walk here.

E-50163 MEANS "THIS PERSON HAS NO LIVE PROFILE AT ALL", AND IT IS CHECKED BEFORE THE SCOPE FILTER.  An empty result set
with no error therefore means something quite different and useful: they have hats, and none of them is yours to see.
Conflating the two would let the screen report "no profiles" for somebody who has five.

@IncludeInactive DEFAULTS TO 0 BECAUSE THE COMMON QUESTION IS "WHICH HATS WORK".  Deleted profiles are never returned at
any setting: IsDeleted = 0 is not negotiable in this file.

========================================================================================================================
Example Usage and Performance:

exec auth.uspListProfilesForUser @SessionTokenHash = 0x9F86..., @UserId = 42, @IncludeInactive = 1;

One seek on IX_auth_UserProfile_User, one scope expansion per call and one correlated count of live grants per row.  A
person with forty hats is a large number for this screen and a trivial one for the index.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-077
Description:
Created.  Phase 6.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspListProfilesForUser
      @SessionTokenHash VARBINARY (32)
    , @UserId           INT
    , @IncludeInactive  BIT = 0
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 error-only instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspListProfilesForUser]')
          , @KeyParameters  NVARCHAR (MAX) = NULL
          , @ContextMessage NVARCHAR (MAX) = NULL
          , @DynamicSql     NVARCHAR (MAX) = NULL
          , @ErrorMsg       NVARCHAR (MAX) = NULL
          , @ErrorProc      NVARCHAR (300) = NULL
          , @ErrorNumber    INT            = NULL
          , @ErrorLine      INT            = NULL;

    DECLARE @ActingTenantId INT             = NULL
          , @Failure        NVARCHAR (2000) = NULL;

    SET @KeyParameters = CONCAT (N'UserId=', @UserId, N', IncludeInactive=', @IncludeInactive);
    SET @ContextMessage = N'Error-only instrumented read: no start row is opened, so @ExecutionLogId is NULL by design.';

    BEGIN TRY

        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        SET @ActingTenantId = TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT);

        -- The gate is at the actor's own tenant; the ROW FILTER below is what enforces the scoping. A caller holding
        -- Authz.ProfileRead nowhere is refused here with E-50030 rather than handed an empty grid.
        EXEC auth.uspDemandPermission @PermissionCode = N'Authz.ProfileRead', @TenantId = @ActingTenantId;

        -- Before the filter, on purpose. See the notes: "no such person's profile" and "none of them yours" are two
        -- different answers and the screen needs to tell them apart.
        IF NOT EXISTS (SELECT 1 FROM auth.UserProfile AS p WHERE p.UserId = @UserId AND p.IsDeleted = 0)
        BEGIN
            SET @Failure = N'That user has no live profile at all -- either the user does not exist, or every profile '
                         + N'they had has been deleted. An empty result set with no error means something different: '
                         + N'they have profiles and none of them is at a tenant you hold Authz.ProfileRead over.';
            ;THROW 50163, @Failure, 1;
        END;

        -- =========================================================================================
        -- ===== The procedure's own work starts here. Everything above and below is boilerplate. ==
        -- =========================================================================================

        SELECT
              p.UserProfileId
            , p.UserId
            , p.TenantId
            , t.TenantCode
            , t.TenantName
            , t.TenantTypeCode
            , p.ProfileName
            , p.IsDefault
            , p.IsActive
            -- Section 5.4: a hat at a suspended branch is a hat that cannot be worn, and the screen should say so
            -- rather than leave the user to discover it as E-50051 in the switcher.
            , TenantUsable  = auth.udfIsTenantUsable (p.TenantId)
            , IsSwitchable  = CASE WHEN p.IsActive = 1 AND auth.udfIsTenantUsable (p.TenantId) = 1 THEN 1 ELSE 0 END
            -- Counts, not the grants themselves: auth.uspListAssignableRoles and section 15.6's views are where the
            -- grants are read. An expired grant is still a row, so both numbers are reported.
            , LiveGrantCount = (SELECT COUNT (*)
                                  FROM auth.UserProfileRole AS upr
                                 WHERE upr.UserProfileId = p.UserProfileId
                                   AND upr.IsDeleted     = 0
                                   AND (upr.ExpiresUtc IS NULL OR upr.ExpiresUtc > SYSUTCDATETIME ()))
            , ExpiredGrantCount = (SELECT COUNT (*)
                                     FROM auth.UserProfileRole AS upr
                                    WHERE upr.UserProfileId = p.UserProfileId
                                      AND upr.IsDeleted     = 0
                                      AND upr.ExpiresUtc IS NOT NULL
                                      AND upr.ExpiresUtc <= SYSUTCDATETIME ())
            , p.auditCreatedBy
            , p.auditCreatedDateUtc
            , p.auditModifiedBy
            , p.auditModifiedDateUtc
          FROM auth.UserProfile AS p
          JOIN auth.Tenant      AS t ON t.TenantId = p.TenantId AND t.IsDeleted = 0
         WHERE p.UserId    = @UserId
           AND p.IsDeleted = 0
           AND (@IncludeInactive = 1 OR p.IsActive = 1)
           -- The scoping. One EXISTS, because the function has already expanded each grant down the tree.
           AND EXISTS (SELECT 1
                         FROM auth.tvfPermissionScope (N'Authz.ProfileRead') AS s
                        WHERE s.TenantId = p.TenantId)
         ORDER BY p.IsDefault DESC   -- the default hat first: it is the one the user is likeliest to mean
                , t.TenantName ASC
                , p.ProfileName ASC
                , p.UserProfileId ASC;   -- deterministic tiebreak

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


-- *** 5. auth.uspListMyProfiles ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspListMyProfiles
Author:       rsincero
CreateDate:   2026-09-21
========================================================================================================================
Description:

The hat menu.  Every live profile belonging to the CALLING SESSION'S OWN user, with the one it is currently wearing
marked and every one it cannot put on explained.  Demands no permission, takes no user id, and is callable by a session
that has no active profile at all.  Error-only instrumented.

========================================================================================================================
Requirements and Key Dependencies:

auth.UserSession, auth.UserProfile, auth.Tenant, auth.udfIsTenantUsable, auth.uspSetSessionContext.  Granted to
applicationRole.

It deliberately depends on NEITHER auth.uspDemandPermission NOR auth.tvfPermissionScope, and that absence is the
procedure.  Both of those answer "what may this PROFILE see", and the caller here has no profile to answer for.

========================================================================================================================
Notes:

WHY THIS EXISTS WITH auth.uspListProfilesForUser RIGHT THERE -- G-51, FOUND BY SCEN-AUTH-001
------------------------------------------------------------------------------------------
A session with no active profile could not find out which profiles it had.  Every route to the answer demanded
Authz.ProfileRead at SESSION_CONTEXT ('ActingTenantId'), a profileless session has no acting tenant and holds no
permission anywhere, so auth.uspListProfilesForUser refused it -- and the refusal was E-50030 with a message announcing
that there was NO SESSION CONTEXT on a connection that had just established some.  The user was locked out of the one
screen that could have let them in: they had hats, and the only procedure that could name them required a hat.

That is not a bug in auth.uspListProfilesForUser.  It answers an ADMINISTRATOR'S question -- "what hats does this person
wear, of the ones I am allowed to know about" -- and every part of it is right for that question: the @UserId parameter,
the permission demand, the tenant scoping that omits rather than greys out, the grant counts, E-50163 for a person with
no profiles.  The scoping in particular must stay: "A has a hat at the neighbouring county" is exactly the fact it
exists to keep inside that county.

This procedure answers a different question -- "which of MY hats can I put on" -- whose correct answer is never scoped,
never filtered by permission and never about somebody else.  Widening the other one with an @Mine flag would have put
both questions in one body, where the permission demand has to become conditional, and a conditional permission demand
is the shape every authorization bypass in the literature is written in.  Two procedures, two authorities, neither
branching.

NO PERMISSION, AND THE ABSENCE OF A @UserId PARAMETER IS THE SECURITY CONTROL
---------------------------------------------------------------------------
The authority is the session token and nothing else.  This is the same argument auth.uspSwitchProfile makes in this
file -- "the authority to wear a hat is the existence of the hat", and there is no Authz.ProfileSwitch in the 35
codes -- and auth.uspGetProfileContext in 150_auth_query_procedures.sql makes it too: a procedure that will only ever
tell you about yourself has nothing to authorize.

So there is no @UserId to tamper with.  auth.uspListProfilesForUser needs E-50050-style confinement because it takes a
user id; this one cannot be pointed at anybody, because the WHERE clause reads a variable that came from the session
row and from nowhere else.  Removing the parameter is a stronger control than checking it, and it costs nothing here
because the caller could not usefully name anybody but themselves.

WHAT IT RETURNS, AND WHY THE LIST IS DELIBERATELY SHORTER THAN THE ADMINISTRATOR'S
--------------------------------------------------------------------------------
One row per live profile: identity, tenant, ProfileName, IsDefault, IsActive, and then the four columns a chooser
actually needs -- TenantUsable, IsSwitchable, IsCurrent and SwitchBlockedReason.  No grant counts and no audit columns:
"you hold 7 live and 2 expired role grants here" is an administrative fact on a screen whose only question is which
button to press, and UI-16's habit of mind applies to result sets as much as to logs.

SwitchBlockedReason reports the TENANT before the PROFILE when both are wrong, because they are not equally actionable:
reactivating a profile at a suspended county still gives you a hat you cannot wear, and telling the user to ask for the
wrong thing is worse than telling them nothing.

IsCurrent IS A COLUMN AND NOT AN ORDER BY.  The rows come back in a stable order -- default first, then tenant name,
then profile name -- and the hat you are wearing keeps its place in it.  Sorting the current profile to the top makes
the menu rearrange itself every time it is used, so the entry a user reaches for by muscle memory is the one that just
moved.  UI-06 already forces a new connection per switch; the menu should at least stay still.

AN EMPTY RESULT SET IS A LEGITIMATE ANSWER HERE, WHICH IS THE OPPOSITE OF auth.uspListProfilesForUser
---------------------------------------------------------------------------------------------------
That procedure raises E-50163 when the person has no live profile, because for an administrator "this person has none"
and "none of theirs is yours to see" are different answers and an empty grid would conflate them.  Here there is nothing
to conflate: no filter has been applied, so zero rows means zero hats, and it is the hat menu's job to say so.  A
freshly self-registered user whose tenant has not assigned them anything yet is a supported state (UI-09), not an error,
and throwing at it would hand the UI an exception to render as a screen it has to explain.

INACTIVE PROFILES AND UNUSABLE TENANTS ARE RETURNED, NOT FILTERED.  There is no @IncludeInactive and there should not
be: "you have no profiles" and "your profiles do not work" are the two answers this screen exists to tell apart, and a
filtered list can only ever give the first.  IsDeleted = 0 remains non-negotiable -- a deleted profile is gone.

STEP-UP IS NOT PREDICTED HERE
----------------------------
A privileged profile needs an elevated session before auth.uspSwitchProfile will move to it (E-50052), and this
procedure does not compute that.  IsSwitchable answers "is this hat wearable at all", not "will the next call succeed
without an MFA prompt": the step-up rule reads the target tenant's resolved policy and the session's ElevatedUntilUtc,
both of which can change between drawing a menu and clicking it, so a prediction here would be a second copy of a
security rule that is also frequently stale.  The switch raises E-50052, the UI prompts, auth.uspElevateSession lifts
the window and the switch is retried -- section 12.1 and UI-48.

E-50166 IS A RACE, NOT A VALIDATION
----------------------------------
auth.uspSetSessionContext has already validated the session -- expiry, idle timeout, a deleted user, an unusable active
profile, E-50020 to E-50024 -- so by the time the SELECT below runs, the row is known to have been live one statement
ago.  If it has gone, another connection ended or revoked the session in between, and the right answer is to stop:
handing out a hat menu for a session that no longer exists would invite a switch that must then fail.

========================================================================================================================
Example Usage and Performance:

exec auth.uspListMyProfiles @SessionTokenHash = 0x9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08;

One seek on UX_auth_UserSession_TokenHash, one seek on IX_auth_UserProfile_User, one auth.udfIsTenantUsable per row
(Froid-inlined, computed once per row in a CROSS APPLY rather than three times inline).  Twenty-two hats -- the largest
cohort SCEN-AUTH-001 builds -- is twenty-two rows.

========================================================================================================================
Modification History:

Date:		2026-09-21
Author:		rsincero
Ticket:		T-126
Description:
Created.  Closes G-51 from SCEN-AUTH-001: a session with no active profile had no way to discover its own profiles,
because the only procedure that could name them demanded Authz.ProfileRead at an acting tenant it did not have.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspListMyProfiles
      @SessionTokenHash VARBINARY (32)
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 error-only instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspListMyProfiles]')
          , @KeyParameters  NVARCHAR (MAX) = NULL
          , @ContextMessage NVARCHAR (MAX) = NULL
          , @DynamicSql     NVARCHAR (MAX) = NULL
          , @ErrorMsg       NVARCHAR (MAX) = NULL
          , @ErrorProc      NVARCHAR (300) = NULL
          , @ErrorNumber    INT            = NULL
          , @ErrorLine      INT            = NULL;

    DECLARE @SessionId       BIGINT          = NULL
          , @SessionUserId   INT             = NULL
          , @ActiveProfileId INT             = NULL
          , @Failure         NVARCHAR (2000) = NULL;

    -- Set BEFORE the TRY so that a session error thrown by auth.uspSetSessionContext still lands on an error row that
    -- says something, and refined below once the session resolves. There is nothing else to name at this point: the
    -- only parameter is the session hash, and UI-16 names hashes explicitly among the things never logged.
    SET @KeyParameters = N'UserSessionId=(not yet resolved)';

    SET @ContextMessage = N'Error-only instrumented read: no start row is opened, so @ExecutionLogId is NULL by design. '
                        + N'Demands no permission -- the authority is the session token, and a session with no active '
                        + N'profile is a supported caller here by design (G-51, T-126).';

    BEGIN TRY

        -- Validates the session and raises E-50020 to E-50024 for everything wrong with it. On success it ALWAYS sets
        -- UserId; it sets UserProfileId only when a profile resolved, which is why this procedure can be reached by a
        -- caller that has none.
        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        SET @SessionUserId = TRY_CAST (SESSION_CONTEXT (N'UserId') AS INT);

        -- The session ROW, for the two things SESSION_CONTEXT does not carry on a profileless session: the id to log
        -- and the hat currently worn, which is what IsCurrent below reports.
        SELECT @SessionId       = s.UserSessionId
             , @ActiveProfileId = s.ActiveUserProfileId
          FROM auth.UserSession AS s
         WHERE s.SessionTokenHash = @SessionTokenHash
           AND s.EndedUtc IS NULL
           AND s.IsDeleted        = 0;

        SET @KeyParameters = CONCAT (N'UserSessionId=', COALESCE (CAST (@SessionId AS NVARCHAR (20)), N'null')
                                   , N', UserId=',      COALESCE (CAST (@SessionUserId AS NVARCHAR (11)), N'null')
                                   , N', ActiveUserProfileId='
                                   , COALESCE (CAST (@ActiveProfileId AS NVARCHAR (11)), N'null (profileless, UI-09)'));

        IF @SessionId IS NULL
        BEGIN
            SET @Failure = N'The session was valid one statement ago and is gone now: auth.uspSetSessionContext '
                         + N'accepted it, and the row could not be read back. Another connection ended or revoked this '
                         + N'session in between -- a sign-out elsewhere, an administrative revocation, or a '
                         + N'deactivation of the profile it was wearing. Nothing is wrong with this call. Sign in '
                         + N'again; do not retry (section 14.5).';

            ;THROW 50166, @Failure, 1;
        END;

        -- =========================================================================================
        -- ===== The procedure's own work starts here. Everything above and below is boilerplate. ==
        -- =========================================================================================

        SELECT
              p.UserProfileId
            , p.UserId
            , p.TenantId
            , t.TenantCode
            , t.TenantName
            , t.TenantTypeCode
            , p.ProfileName
            , p.IsDefault
            , p.IsActive
            -- Section 5.4: a hat at a suspended branch is a hat that cannot be worn.
            , TenantUsable = u.Usable
            , IsSwitchable = CASE WHEN p.IsActive = 1 AND u.Usable = 1 THEN 1 ELSE 0 END
            -- The hat this connection is wearing, or none. See the notes: a column, not an ORDER BY.
            , IsCurrent    = CASE WHEN p.UserProfileId = @ActiveProfileId THEN 1 ELSE 0 END
            -- The tenant first when both are wrong: reactivating a profile at a suspended county changes nothing, and
            -- sending the user to ask for the wrong remedy is worse than sending them to ask for nothing.
            , SwitchBlockedReason = CASE WHEN u.Usable  = 0 THEN N'TenantUnusable'
                                         WHEN p.IsActive = 0 THEN N'ProfileInactive'
                                         ELSE NULL END
          FROM auth.UserProfile AS p
          JOIN auth.Tenant      AS t ON t.TenantId = p.TenantId AND t.IsDeleted = 0
         CROSS APPLY (SELECT Usable = auth.udfIsTenantUsable (p.TenantId)) AS u
         -- @SessionUserId came from the session row and from no parameter, which is the whole of the confinement.
         WHERE p.UserId    = @SessionUserId
           AND p.IsDeleted = 0
         ORDER BY p.IsDefault DESC   -- the default hat first: it is the one the user is likeliest to mean
                , t.TenantName ASC
                , p.ProfileName ASC
                , p.UserProfileId ASC;   -- deterministic tiebreak

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


-- *** 6. auth.uspSwitchProfile ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspSwitchProfile
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Changes which of your own hats the live session is wearing.  Section 12.1's seven steps: resolve the session, refuse a
profile that is not yours (E-50050), refuse one that is not usable (E-50051), demand step-up if the target tenant's
policy requires it for a privileged profile (E-50052), move auth.UserSession.ActiveUserProfileId, write a ProfileSwitch
authentication event, re-establish SESSION_CONTEXT, and return the new context AND the navigation in one round trip.

========================================================================================================================
Requirements and Key Dependencies:

auth.UserSession, auth.UserProfile, auth.Tenant, auth.ProfilePermissionScope, auth.Permission,
auth.TenantAuthenticationPolicy, auth.udfResolveAuthPolicy, auth.udfIsTenantUsable, auth.uspSetSessionContext,
logs.AuthenticationEvent, and -- pending T-084 -- auth.uspGetNavigationForProfile.  Granted to applicationRole.

========================================================================================================================
Notes:

NO PERMISSION IS DEMANDED AND NONE SHOULD BE.  There is no Authz.ProfileSwitch among the 35 permission codes.  The
authority to wear a hat is the existence of the hat, and that authority was exercised by whoever ran
auth.uspCreateProfile.  D-10 is explicit that this is not impersonation: E-50050 confines the switch to the session's
OWN user, so no amount of authority lets anybody wear somebody else's hat.

logs.AuthenticationEvent IS WRITTEN WITH AN INLINE INSERT, LIKE EVERY OTHER WRITER OF THAT TABLE.  There is no
logs.uspRecordAuthenticationEvent -- 110 and 112 insert directly too -- and the EventType vocabulary is a closed CHECK,
so 'ProfileSwitch' had to be added to it before this file could run (G-29, BL-055).  Section 15.5 wants both profile
identifiers in the row, which is why DetailJson carries the previous one: this is the only event in the table that
explains why a later insert landed in the tenant it did.

STEP-UP IS TESTED AGAINST THE TARGET'S POLICY AND THE TARGET'S PRIVILEGE, BOTH.  Section 12.3: the target tenant's
resolved auth.TenantAuthenticationPolicy.RequireStepUpForPrivileged must be 1 AND the target profile must hold at least
one permission in the Authz, User, Tenant or Platform categories.  A profile with only Data and Config permissions
switches without a challenge however the policy is set, because nothing it can then do is privileged.

WHEN NO POLICY ROW APPLIES ANYWHERE ABOVE THE TARGET, THE SHIPPED SETTING DECIDES -- AND IT SAYS DEMAND THE FACTOR.
G-30 closed.  auth.udfResolveAuthPolicy returns NULL, and this procedure then reads
config.ApplicationSetting.Authn.RequireStepUpForPrivilegedDefault, which 025_config_tables.sql seeds at 1.  For two
phases the fallback was a hard-coded 0, on the honest reading of section 7.2's inheritance -- a policy row means "this
subtree is different", so its absence means nothing has been asked for.  What made that wrong was not the reasoning but
where it landed: the deployment that has stated no policy is the one that has thought least about this, and shipping it
the permissive answer means the template's default posture is set by a template author rather than by the operator.

A SETTING AND A HARD-CODED 0 ARE NOT THE SAME THING EVEN WHEN THEY HOLD THE SAME VALUE, which is the whole of G-30.  An
operator who wants the old behaviour sets the key to 0, and that is a recorded decision with an audit stamp on the row; a
hard-coded 0 is a decision nobody made and nobody can see.  The distinction between "no policy resolved" and "a policy
resolved and said 0" is carried by @RequireStepUp starting NULL rather than 0 -- the fallback applies to the first only,
because an explicit 0 in a policy row is an operator's answer and must not be overridden by a default.

THE LAST-RESORT VALUE IS 1, NOT 0.  If the setting row is missing entirely -- deleted, or a database predating it -- the
COALESCE lands on 1.  A missing security default is read strictly, because the failure mode is then a challenge somebody
did not expect rather than a privileged hat put on without one.

SATISFACTION IS auth.UserSession.ElevatedUntilUtc, NOT A PARAMETER.  auth.uspElevateSession -- section 5 of
112_auth_mfa_procedures.sql -- is the only procedure that writes that column, and this one only reads it.  A caller
cannot assert its own step-up, which is the entire point.  Until T-125 the writer did not exist, so this sentence named
a procedure nobody had written and E-50052 below was a refusal with no remedy: gap G-48, and the reason the scenario
test could not put on a privileged hat at all.

SESSION_CONTEXT IS RE-ESTABLISHED BEFORE THE RESULT SETS ARE BUILT.  auth.tvfPermissionScope and every predicate
function read the ACTIVE profile out of SESSION_CONTEXT, so the navigation would otherwise be the old hat's menu
rendered under the new hat's name -- which is the flicker UI-04 exists to forbid, arriving in one round trip instead of
two.

THE SECOND RESULT SET IS A FORWARD REFERENCE.  auth.uspGetNavigationForProfile is T-084; the call is guarded on
OBJECT_ID and this file's closing report says PENDING until it exists.  Its contract is
@SessionTokenHash VARBINARY (32) -- see the file header on G-26 and BL-053, which is the same pattern going wrong.

========================================================================================================================
Example Usage and Performance:

exec auth.uspSwitchProfile @SessionTokenHash = 0x9F86..., @TargetUserProfileId = 91;
-- result set 1: the new profile context.  result set 2: the navigation for it.

One seek on UX_auth_UserSession_TokenHash, one on PK_auth_UserProfile, one privileged-permission EXISTS against
auth.ProfilePermissionScope, one single-row update, one event insert, then the two reads.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-078
Description:
Created.  Phase 6.

Date:		2026-09-20
Author:		rsincero
Ticket:		T-091
Description:
Removed the post-commit auth.uspSetSessionContext call, which raised E-50022 on every invocation because
SESSION_CONTEXT keys are read-only -- the switch succeeded and the caller was told it had failed, and neither result set
was returned.  The navigation read is now handed the new profile explicitly.  G-36, BL-057.

Date:		2026-09-21
Author:		rsincero
Ticket:		T-127
Description:
Both logs.AuthenticationEvent inserts now write UserSessionId.  logs.AuthenticationEvent has carried the column and its
foreign key since 085_logs_auth_tables.sql, and this procedure -- the one writer whose entire subject is a session --
left it NULL on both the 'ProfileSwitch' row and the 'MfaChallenged' refusal.  @SessionId was already in scope, so the
rows were anonymous by omission rather than by design.  Scenario SCEN-AUTH-001 measured the consequence: every switch
in a 44,432-user population was attributable only to (UserId, EventUtc), which stops identifying anything the moment
one person has two sessions open, and one person in that population holds 22 profiles.  G-50.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspSwitchProfile
      @SessionTokenHash    VARBINARY (32)
    , @TargetUserProfileId INT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspSwitchProfile]')
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
          , @SessionId        BIGINT          = NULL
          , @SessionUserId    INT             = NULL
          , @PreviousProfile  INT             = NULL
          , @ApplicationId    INT             = NULL
          , @LoginAttemptId   BIGINT          = NULL
          , @ClientAddress    NVARCHAR (45)   = NULL
          , @ElevatedUntilUtc DATETIME2 (3)   = NULL
          , @UserName         NVARCHAR (256)  = NULL
          , @TargetUserId     INT             = NULL
          , @TargetTenantId   INT             = NULL
          , @TargetIsActive   BIT             = NULL
          , @PolicyId         INT             = NULL
          -- NULL, not 0: "no policy resolved" has to be distinguishable from "a policy resolved and said 0", because
          -- G-30's fallback applies to the first and must not override the second.
          , @RequireStepUp    BIT             = NULL
          , @IsPrivileged     BIT             = 0
          , @StepUpRequired   BIT             = 0
          , @Now              DATETIME2 (3)   = NULL
          , @DetailJson       NVARCHAR (400)  = NULL
          , @Failure          NVARCHAR (2000) = NULL;

    -- Identifiers only. @SessionTokenHash is never logged, in any form: UI-16 names hashes explicitly.
    SET @KeyParameters = CONCAT (N'TargetUserProfileId=', @TargetUserProfileId);

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

        -- STEPS 1 TO 4 RUN BEFORE THE TRANSACTION IS OPENED, ON PURPOSE. The step-up refusal below writes a
        -- logs.AuthenticationEvent row and then throws; inside a transaction, the rollback that E-50052 provokes would
        -- take the row with it and the refusal would leave no trace anywhere except logs.ExecutionLogError. BL-042 is
        -- the same hazard stated for authorization denials. The cost is a race -- the profile could be deactivated
        -- between the check and the update -- and it is a cheap one: the session's next call re-tests usability and
        -- fails with E-50021, which is what would have happened anyway.
        -- Section 12.1 step 1. This also validates the session -- expiry, idle timeout, a deleted user, an unusable
        -- active profile -- and raises E-50020 to E-50024 for all of it, so nothing below has to.
        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        SET @SessionUserId = TRY_CAST (SESSION_CONTEXT (N'UserId') AS INT);
        SET @Actor         = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                     , ORIGINAL_LOGIN ());
        SET @Now           = SYSUTCDATETIME ();

        -- The session ROW, for the columns SESSION_CONTEXT does not carry: the id to update, the elevation window that
        -- decides step-up, and the application and address the event row wants.
        SELECT @SessionId        = s.UserSessionId
             , @PreviousProfile  = s.ActiveUserProfileId
             , @ApplicationId    = s.ApplicationId
             , @LoginAttemptId   = s.LoginAttemptId
             , @ClientAddress    = s.ClientAddress
             , @ElevatedUntilUtc = s.ElevatedUntilUtc
          FROM auth.UserSession AS s
         WHERE s.SessionTokenHash = @SessionTokenHash
           AND s.EndedUtc IS NULL
           AND s.IsDeleted        = 0;

        SELECT @UserName = u.UserName
          FROM auth.[User] AS u
         WHERE u.UserId = @SessionUserId;

        SELECT @TargetUserId   = p.UserId
             , @TargetTenantId = p.TenantId
             , @TargetIsActive = p.IsActive
          FROM auth.UserProfile AS p
         WHERE p.UserProfileId = @TargetUserProfileId
           AND p.IsDeleted     = 0;

        -- Section 12.1 step 2. D-10: a switch is never impersonation, so "not yours" and "does not exist" get the SAME
        -- number deliberately -- a caller who could tell them apart could enumerate other people's profile ids.
        IF @TargetUserId IS NULL OR @TargetUserId <> @SessionUserId
        BEGIN
            SET @Failure = N'That profile does not belong to your user. A switch changes which of YOUR OWN hats the '
                         + N'session is wearing and is never impersonation (D-10); a deleted profile and another '
                         + N'person''s profile report the same error on purpose, so the message cannot be used to '
                         + N'enumerate profile ids. The session was not changed.';
            ;THROW 50050, @Failure, 1;
        END;

        -- Section 12.1 step 3. Both halves: the hat itself, and section 5.4's branch usability.
        IF @TargetIsActive = 0 OR auth.udfIsTenantUsable (@TargetTenantId) = 0
        BEGIN
            SET @Failure = N'That profile cannot be used: either it has been deactivated, or its tenant is unusable '
                         + N'because the tenant or a tenant above it is inactive (section 5.4). An administrator has '
                         + N'to reactivate one or the other. The session was not changed.';
            ;THROW 50051, @Failure, 1;
        END;

        -- Section 12.3, and the notes on both halves of this test. The policy first.
        SET @PolicyId = auth.udfResolveAuthPolicy (@TargetTenantId);

        IF @PolicyId IS NOT NULL
        BEGIN
            SELECT @RequireStepUp = pol.RequireStepUpForPrivileged
              FROM auth.TenantAuthenticationPolicy AS pol
             WHERE pol.TenantAuthenticationPolicyId = @PolicyId
               AND pol.IsDeleted                   = 0;
        END;

        -- G-30 closed.  When no policy row applies anywhere above the target, the fallback is the SHIPPED SETTING and no
        -- longer a hard-coded 0.  Authn.RequireStepUpForPrivilegedDefault ships at 1, so a deployment that has stated no
        -- policy now demands a fresh factor to put on a privileged hat rather than waving it through.  The final COALESCE
        -- to 1 rather than 0 is deliberate too: if somebody deletes the setting row, the safe reading of a missing
        -- security default is the strict one, and the operator finds out by being challenged rather than by not being.
        IF @RequireStepUp IS NULL
        BEGIN
            SET @RequireStepUp = COALESCE (TRY_CAST ((SELECT s.SettingValue
                                                        FROM config.ApplicationSetting AS s
                                                       WHERE s.SettingKey = N'Authn.RequireStepUpForPrivilegedDefault'
                                                         AND s.IsDeleted  = 0) AS BIT)
                                         , CAST (1 AS BIT));
        END;

        -- Then the privilege. Read off the TARGET profile's scope, before the switch, because after it the question is
        -- no longer hypothetical. Four categories, from the seven in auth.PermissionCategory: Data and Config are the
        -- ordinary work of the application and Audit is a read of it.
        IF @RequireStepUp = 1
        BEGIN
            IF EXISTS (SELECT 1
                         FROM auth.ProfilePermissionScope AS pps
                         JOIN auth.Permission             AS pm ON pm.PermissionId = pps.PermissionId
                                                               AND pm.IsDeleted    = 0
                        WHERE pps.UserProfileId = @TargetUserProfileId
                          AND pps.IsDeleted     = 0
                          AND pm.PermissionCategoryCode IN (N'Authz', N'User', N'Tenant', N'Platform'))
            BEGIN
                SET @IsPrivileged = 1;
            END;
        END;

        SET @StepUpRequired = CASE WHEN @RequireStepUp = 1 AND @IsPrivileged = 1 THEN 1 ELSE 0 END;

        -- Section 12.1 step 4. Satisfaction is the session's own elevation window and nothing the caller can assert.
        IF @StepUpRequired = 1 AND (@ElevatedUntilUtc IS NULL OR @ElevatedUntilUtc <= @Now)
        BEGIN
            -- The refusal is itself an authentication event: an attempt to put on a privileged hat without a fresh
            -- second factor is exactly what section 18's reviewer is looking for. Warning, not Alert -- it is a
            -- policy working, not a breach.
            -- UserSessionId is written because the refusal is ABOUT a session -- which session was not elevated is the
            -- whole content of the finding, and without the column a reviewer can only guess from UserId and a
            -- timestamp, which is wrong the moment one person has two sessions open (G-50, T-127).
            INSERT logs.AuthenticationEvent
                (EventUtc, EventType, EventSeverity, ApplicationId, UserId, LoginAttemptId, UserSessionId
               , UserName, ClientAddress, Actor, DetailJson)
            VALUES (@Now, 'MfaChallenged', 'Warning', @ApplicationId, @SessionUserId, @LoginAttemptId, @SessionId
                  , @UserName, @ClientAddress, @Actor
                  , CONCAT (N'{"reason":"stepUpRequiredForProfileSwitch","targetUserProfileId":'
                          , @TargetUserProfileId, N',"targetTenantId":', @TargetTenantId, N',"error":50052}'));

            SET @Failure = N'That profile is privileged -- it holds at least one Authz, User, Tenant or Platform '
                         + N'permission -- and the target tenant''s policy requires step-up authentication before it '
                         + N'may be worn (section 12.3). Call auth.uspElevateSession with a TOTP step or a recovery '
                         + N'code hash, which sets the session''s elevation window, and then switch again ON A NEW '
                         + N'CONNECTION -- this one is already contexted and cannot be re-contexted (UI-06). The '
                         + N'session was not changed and the user is still signed in: prompt for the factor, do not '
                         + N'sign them out.';
            ;THROW 50052, @Failure, 1;
        END;

        -- Section 12.1 steps 5 and 6 are one unit: the session must not be left pointing at the new profile with no
        -- event to say when it moved, and the event must not be left claiming a switch that did not happen.
        BEGIN TRANSACTION;

        -- Section 12.1 step 5.
        UPDATE s
           SET s.ActiveUserProfileId = @TargetUserProfileId
             , s.LastSeenUtc         = @Now
             , s.auditModifiedBy     = @Actor
          FROM auth.UserSession AS s
         WHERE s.UserSessionId = @SessionId;

        -- Section 12.1 step 6. Inline insert, like every other writer of this table; both profile identifiers, because
        -- section 15.5 wants this row to explain why a later insert landed in the tenant it did.
        SET @DetailJson = CONCAT (N'{"previousUserProfileId":'
                                , COALESCE (CAST (@PreviousProfile AS NVARCHAR (11)), N'null')
                                , N',"newUserProfileId":', @TargetUserProfileId
                                , N',"tenantId":', @TargetTenantId
                                , N',"stepUpRequired":', @StepUpRequired
                                , N',"noOp":'
                                , CASE WHEN @PreviousProfile = @TargetUserProfileId THEN N'true' ELSE N'false' END
                                , N'}');

        -- UserSessionId, for the same reason the refusal above carries it and one more: this row is the ONLY record of
        -- which hat a session was wearing at a given moment, because auth.UserSession keeps just the current one.
        -- Reconstructing "what was this session allowed to see at 14:07" from UserId alone is guesswork as soon as the
        -- user has a second session open, and 22 hats deep it is guesswork that reaches the wrong tenant (G-50, T-127).
        INSERT logs.AuthenticationEvent
            (EventUtc, EventType, EventSeverity, ApplicationId, UserId, LoginAttemptId, UserSessionId
           , UserName, ClientAddress, Actor, DetailJson)
        VALUES (@Now, 'ProfileSwitch', 'Info', @ApplicationId, @SessionUserId, @LoginAttemptId, @SessionId
              , @UserName, @ClientAddress, @Actor, @DetailJson);

        -- COMMITTED HERE, BEFORE THE TWO RESULT SETS, AND NOT AT THE USUAL PLACE BELOW. The switch is complete: the
        -- session points at the new hat and the event says when it moved. Step 7 is a READ, and a read that failed --
        -- auth.uspGetNavigationForProfile raising, or a caller cancelling mid-fetch -- must not undo it, which is
        -- exactly what would happen if the transaction were still open. The boilerplate COMMIT below then finds
        -- @@TRANCOUNT = 0 and does nothing, which is why it is guarded.
        IF @@TRANCOUNT > 0
        BEGIN
            COMMIT TRANSACTION;
        END;

        -- THE CONTEXT IS NOT RE-ESTABLISHED HERE, AND IT CANNOT BE. The first draft called
        -- auth.uspSetSessionContext again at this point, on the reasoning that everything below should see the NEW hat.
        -- SESSION_CONTEXT keys are read-only for the life of the connection (error 15664), so that call raised E-50022
        -- on EVERY invocation -- after the switch had already been committed above. The caller was told the switch had
        -- failed when it had succeeded, and neither result set was ever returned. G-36, BL-057.
        --
        -- What replaces it: the result sets below read the target profile by id, and the navigation read is handed the
        -- new profile explicitly. Nothing here consults SESSION_CONTEXT for the profile, so nothing here is wrong.
        -- The connection is SPENT once this returns -- its context still names the previous hat and cannot be changed,
        -- so the next request must arrive on a new connection, which is what UI-06 has always said. One round trip is
        -- still delivered, which is what section 12.1 step 7 and UI-04 actually asked for.

        -- Section 12.1 step 7, first result set: the new context.
        SELECT
              UserProfileId       = p.UserProfileId
            , UserId              = p.UserId
            , ProfileName         = p.ProfileName
            , IsDefault           = p.IsDefault
            , TenantId            = t.TenantId
            , TenantCode          = t.TenantCode
            , TenantName          = t.TenantName
            , TenantTypeCode      = t.TenantTypeCode
            , PreviousProfileId   = @PreviousProfile
            , SwitchedUtc         = @Now
            , StepUpWasRequired   = @StepUpRequired
            , ElevatedUntilUtc    = @ElevatedUntilUtc
            , AppUser             = CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255))
          FROM auth.UserProfile AS p
          JOIN auth.Tenant      AS t ON t.TenantId = p.TenantId AND t.IsDeleted = 0
         WHERE p.UserProfileId = @TargetUserProfileId;

        -- Section 12.1 step 7, second result set: the navigation. FORWARD REFERENCE to T-084 -- guarded, so this file
        -- deploys and runs before 150_auth_query_procedures.sql grows the procedure. Deferred name resolution is what
        -- lets it compile; the OBJECT_ID test is what stops it failing at run time.
        --
        -- @AssumeUserProfileId is what makes this answer for the NEW hat: the read cannot get it from session context,
        -- for the reason set out above the first result set. It still proves ownership from the session hash, so the
        -- parameter grants the caller nothing it did not already have. G-36.
        IF OBJECT_ID (N'auth.uspGetNavigationForProfile', N'P') IS NOT NULL
        BEGIN
            EXEC auth.uspGetNavigationForProfile @SessionTokenHash    = @SessionTokenHash
                                              , @AssumeUserProfileId = @TargetUserProfileId;
        END;

        SET @Comments = CONCAT (N'Session ', @SessionId, N' switched from UserProfileId='
                              , COALESCE (CAST (@PreviousProfile AS NVARCHAR (11)), N'(none)')
                              , N' to ', @TargetUserProfileId, N' at TenantId=', @TargetTenantId
                              , N'. StepUpRequired=', @StepUpRequired
                              , CASE WHEN @RequireStepUp = 1 AND @IsPrivileged = 0
                                     THEN N' (policy requires it, but this profile holds no Authz, User, Tenant or '
                                        + N'Platform permission)' ELSE N'' END
                              , CASE WHEN @PolicyId IS NULL
                                     THEN N' (no authentication policy applies to the target tenant, so the requirement '
                                        + N'came from Authn.RequireStepUpForPrivilegedDefault = '
                                        + CAST (@RequireStepUp AS NVARCHAR (1)) + N' -- G-30)' ELSE N'' END
                              , N'. ProfileSwitch event written. '
                              , CASE WHEN OBJECT_ID (N'auth.uspGetNavigationForProfile', N'P') IS NULL
                                     THEN N'NAVIGATION RESULT SET OMITTED: auth.uspGetNavigationForProfile does not '
                                        + N'exist yet (T-084). The UI gets one result set instead of two until it does.'
                                     ELSE N'Navigation returned as the second result set.' END);

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


-- *** 7. auth.uspGrantTenantDefaultRoles ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspGrantTenantDefaultRoles
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Grants a brand-new profile the default role set of its tenant -- or, if that tenant seeds none, of the nearest ancestor
that does.  Section 11.5.  Writes one 'RoleGranted' trail row per role granted, and reports back where the set came from
and how many candidates were skipped.

Called INSIDE the caller's transaction.  Not granted to any role: there are two callers and both are in this database.

========================================================================================================================
Requirements and Key Dependencies:

auth.TenantDefaultRole, auth.TenantClosure, auth.Role, auth.UserProfileRole, logs.uspRecordAuthorizationChange.

========================================================================================================================
Notes:

IT EXISTS BECAUSE THERE ARE TWO WAYS A PROFILE CAN BE BORN AND ONLY ONE OF THEM IS AUTHENTICATED.  auth.uspCreateProfile
is an administrator planting a hat and demands Authz.ProfileCreate.  auth.uspRegisterExternalUser (T-087, section 16.4
step 3) is a member of the public creating their own first hat, with no session and therefore no permission to demand --
its authority is an APPROVED auth.OrganizationRegistration row instead.  Both must end with the same default roles, and
the rule that decides them -- "nearest ancestor, and skip anything whose owner does not cover the tenant" -- is
security-relevant.  Two copies of it would drift, and the copy that drifted would be the one nobody was testing.  So it
lives here once and both call it.  This is the same reasoning that keeps auth.udfHasPermission the single definition of
the permission test.

IT DOES NOT REBUILD auth.ProfilePermissionScope, deliberately.  The caller does, once, after this returns -- because
auth.uspCreateProfile has other grants of its own to make in some deployments and a rebuild per role would be quadratic
in the size of the default set for no benefit.  A caller that forgets leaves a profile holding roles that grant nothing
until the nightly rebuild, so both callers are checked for it by this file's and 155's closing reports.

@Actor IS A PARAMETER RATHER THAN RE-DERIVED, because auth.uspRegisterExternalUser has no session context at all: its
SESSION_CONTEXT ('AppUser') is empty and ORIGINAL_LOGIN () is the pooled application login, which is exactly the
uninformative value section 14.4 exists to avoid.  That procedure passes a constructed actor string naming the
registration; auth.uspCreateProfile passes the administrator's. Defaulted to the usual derivation so a third caller
cannot get it silently wrong.

@ActorUserProfileId MAY BE NULL AND THAT IS NOT AN ERROR HERE.  Section 11.2 wants every grant attributable and "the
system did it" is a worse answer than a name -- but a self-registration genuinely has no acting profile, the same
situation 900_bootstrap_first_admin.sql is in.  The NULL lands in auth.UserProfileRole.GrantedByProfileId and in the
trail, where it means "nobody granted this; the tenant's default set did", and the DetailJson says which registration.

A SKIPPED DEFAULT ROLE IS A SEEDING ERROR AND DOES NOT FAIL THE CALL -- unchanged from auth.uspCreateProfile, where this
logic used to live.  A role whose OwnerTenantId does not cover the tenant violates INV-04 and is filtered out; the
profile is still created.  Refusing would make one bad auth.TenantDefaultRole row block every new profile beneath it,
which is a worse outcome than a hat with fewer roles than intended.  @CandidateRoleCount minus @GrantedRoleCount is the
number, and the caller puts it in its own Comments where an operator will read it.

========================================================================================================================
Example Usage and Performance:

declare @src int, @cand int, @granted int;
exec auth.uspGrantTenantDefaultRoles @UserProfileId = 42, @TenantId = 7, @ApplicationId = 1, @TargetUserId = 11
                                   , @ActorUserProfileId = 3, @ActorAuthorityTenantId = 1
                                   , @DefaultSourceTenantId = @src output, @CandidateRoleCount = @cand output
                                   , @GrantedRoleCount = @granted output;

One seek up auth.TenantClosure to find the source tenant, one set-based INSERT, then one trail row per role granted.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-087
Description:
Created by EXTRACTION from auth.uspCreateProfile, so that auth.uspRegisterExternalUser can reach the same rule instead of
carrying a second copy of it.  Behaviour is unchanged; auth.uspCreateProfile now calls this.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspGrantTenantDefaultRoles
      @UserProfileId          INT
    , @TenantId               INT
    , @ApplicationId          INT
    , @TargetUserId           INT
    , @ActorUserProfileId     INT            = NULL
    , @ActorAuthorityTenantId INT            = NULL
    , @Actor                  NVARCHAR (255) = NULL
    , @DefaultSourceTenantId  INT OUTPUT
    , @CandidateRoleCount     INT OUTPUT
    , @GrantedRoleCount       INT OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspGrantTenantDefaultRoles]')
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

    DECLARE @ChangeId   BIGINT         = NULL
          , @DetailJson NVARCHAR (400) = NULL
          , @RowNo      INT            = NULL
          , @MaxRowNo   INT            = NULL
          , @RoleId     INT            = NULL;

    -- One row per default role actually granted, so the trail loop below has something ordered to walk. The OUTPUT
    -- clause is how it is filled: re-reading auth.UserProfileRole afterwards would also pick up rows a concurrent
    -- grant made, and the trail would then claim this call did something it did not.
    DECLARE @GrantedRoles TABLE
    (
        RowNo  INT IDENTITY (1, 1) PRIMARY KEY,
        RoleId INT NOT NULL
    );

    SET @Actor = COALESCE (@Actor
                         , NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                         , ORIGINAL_LOGIN ());

    SET @DefaultSourceTenantId = NULL;
    SET @CandidateRoleCount    = 0;
    SET @GrantedRoleCount      = 0;

    -- Identifiers and counts only. UI-16.
    SET @KeyParameters = CONCAT (N'UserProfileId=', @UserProfileId, N', TenantId=', @TenantId
                               , N', ApplicationId=', @ApplicationId, N', TargetUserId=', @TargetUserId
                               , N', ActorUserProfileId='
                               , COALESCE (CAST (@ActorUserProfileId AS NVARCHAR (11)), N'NULL (self-registration)'));

    SET @ContextMessage = N'Section 11.5 default-role grant. Called inside the caller''s transaction; the caller rebuilds '
                        + N'auth.ProfilePermissionScope once afterwards.';

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

        -- Section 11.5, and the file header on why this is a lookup rather than a copy. Depth 0 is the tenant itself, so
        -- ORDER BY Depth ASC finds the tenant's own set if it has one and the nearest ancestor's otherwise.
        SELECT TOP (1) @DefaultSourceTenantId = tc.AncestorTenantId
          FROM auth.TenantClosure AS tc
         WHERE tc.DescendantTenantId = @TenantId
           AND tc.IsDeleted         = 0
           AND EXISTS (SELECT 1
                         FROM auth.TenantDefaultRole AS dr
                        WHERE dr.TenantId  = tc.AncestorTenantId
                          AND dr.IsDeleted = 0)
         ORDER BY tc.Depth ASC;

        IF @DefaultSourceTenantId IS NOT NULL
        BEGIN
            SELECT @CandidateRoleCount = COUNT (*)
              FROM auth.TenantDefaultRole AS dr
             WHERE dr.TenantId  = @DefaultSourceTenantId
               AND dr.IsDeleted = 0;

            -- GrantedByProfileId is the ACTOR's profile where there is one: section 11.2 wants every grant attributable,
            -- and "the system did it" is a worse answer than "the administrator who created the hat did it". NULL is for
            -- the two places where there genuinely is no actor -- 900_bootstrap_first_admin.sql and a self-registration.
            INSERT auth.UserProfileRole (UserProfileId, RoleId, ScopeTenantId, ApplicationId, GrantedByProfileId
                                       , GrantedUtc, auditCreatedBy, auditModifiedBy)
            OUTPUT inserted.RoleId INTO @GrantedRoles (RoleId)
            SELECT @UserProfileId, r.RoleId, @TenantId, @ApplicationId, @ActorUserProfileId
                 , SYSUTCDATETIME (), @Actor, @Actor
              FROM auth.TenantDefaultRole AS dr
              JOIN auth.Role              AS r ON r.RoleId = dr.RoleId
             WHERE dr.TenantId       = @DefaultSourceTenantId
               AND dr.IsDeleted      = 0
               AND r.IsDeleted       = 0
               AND r.IsAssignable    = 1
               AND r.ApplicationId   = @ApplicationId
               -- INV-04: the grant's scope must be at or beneath the role's owner. A default role that fails this is a
               -- seeding error in auth.TenantDefaultRole; it is skipped and counted, not raised. See the notes.
               AND EXISTS (SELECT 1
                             FROM auth.TenantClosure AS c
                            WHERE c.AncestorTenantId   = r.OwnerTenantId
                              AND c.DescendantTenantId = @TenantId
                              AND c.IsDeleted          = 0);

            SET @GrantedRoleCount = @@ROWCOUNT;
        END;

        -- One 'RoleGranted' row per default role, because section 15.6's logs.vwAuthorizationTrail answers "how did
        -- this profile come to hold this role" one row at a time. A single summary row would leave the five grants a
        -- default set made invisible to the only screen that asks.
        SET @RowNo    = 1;
        SET @MaxRowNo = (SELECT COALESCE (MAX (RowNo), 0) FROM @GrantedRoles);

        WHILE @RowNo <= @MaxRowNo
        BEGIN
            SELECT @RoleId = g.RoleId FROM @GrantedRoles AS g WHERE g.RowNo = @RowNo;

            SET @DetailJson = CONCAT (N'{"reason":"tenantDefault","sourceTenantId":', @DefaultSourceTenantId
                                    , N',"inherited":'
                                    , CASE WHEN @DefaultSourceTenantId = @TenantId THEN N'false' ELSE N'true' END
                                    , N'}');

            EXEC logs.uspRecordAuthorizationChange
                  @ChangeType             = 'RoleGranted'
                , @TargetUserId           = @TargetUserId
                , @TargetUserProfileId    = @UserProfileId
                , @RoleId                 = @RoleId
                , @ScopeTenantId          = @TenantId
                , @ActorUserProfileId     = @ActorUserProfileId
                , @ActorAuthorityTenantId = @ActorAuthorityTenantId
                , @DetailJson             = @DetailJson
                , @AuthorizationChangeId  = @ChangeId OUTPUT;

            SET @RowNo += 1;
        END;

        SET @Comments = CASE WHEN @DefaultSourceTenantId IS NULL
                             THEN CONCAT (N'No default roles granted to UserProfileId=', @UserProfileId
                                        , N': no tenant at or above TenantId=', @TenantId
                                        , N' seeds auth.TenantDefaultRole.')
                             ELSE CONCAT (@GrantedRoleCount, N' of ', @CandidateRoleCount
                                        , N' default role(s) granted to UserProfileId=', @UserProfileId
                                        , N' from TenantId=', @DefaultSourceTenantId
                                        , CASE WHEN @DefaultSourceTenantId = @TenantId
                                               THEN N' (its own set)' ELSE N' (inherited)' END
                                        , CASE WHEN @CandidateRoleCount > @GrantedRoleCount
                                               THEN CONCAT (N'. SKIPPED ', @CandidateRoleCount - @GrantedRoleCount
                                                          , N': deleted, IsAssignable = 0, wrong ApplicationId, or an '
                                                          + N'OwnerTenantId that does not cover this tenant (INV-04) -- '
                                                          + N'a seeding error in auth.TenantDefaultRole, not a caller '
                                                          + N'error')
                                               ELSE N'' END) END;

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
               SET EndDateUtc            = @EndTimeUtc
                 , ElapsedMilliseconds   = CAST (LEAST (DATEDIFF_BIG (MILLISECOND, @StartTimeUtc, @EndTimeUtc)
                                                      , CAST (2147483647 AS BIGINT)) AS INT)
                 , Successful            = 1
                 , Comments              = @Comments
                 , auditModifiedBy       = ORIGINAL_LOGIN ()
                 , auditModifiedDateUtc  = SYSUTCDATETIME ()
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

        -- The start row went with the rollback, so it is re-created rather than updated. A failure in the
        -- re-creation must not replace the real error, hence the nested TRY.
        BEGIN TRY
            EXEC logs.uspStartExecutionLogging
                  @ProcedureName          = @ProcName
                , @KeyParameters          = @KeyParameters
                , @StartDateUtc           = @StartTimeUtc
                , @ReCreatedAfterRollback = 1
                , @ExecutionLogId         = @ExecutionId OUTPUT;
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
        ObjectName  SYSNAME         NOT NULL,
        Description NVARCHAR (3750) NOT NULL
    );

    INSERT @Descriptions (ObjectName, Description)
    VALUES
      (N'uspCreateProfile'
     , N'Gives an existing person a hat at one tenant. Tests Authz.ProfileCreate at the TARGET tenant -- section 11.4 '
     + N'scopes it exactly like Authz.RoleAssign, because a profile is what a grant attaches to -- with '
     + N'auth.udfHasPermission rather than auth.uspDemandPermission, so that Appendix B''s E-50045 is reachable; the '
     + N'denial is still written to logs.AuthorizationDenial by hand. Grants the NEAREST ANCESTOR''S default roles '
     + N'(section 11.5: inherited, not copied -- BL-052) and skips any whose OwnerTenantId does not cover the tenant, '
     + N'because granting one would break INV-04. Rebuilds the new profile''s permission scope in the same '
     + N'transaction. Forces IsDefault on a first profile: INV-03 is "exactly one". E-50160 no such user (checked '
     + N'first), E-50161 tenant unusable, E-50162 duplicate or blank name.')
    , (N'uspUpdateProfile'
     , N'Renames a hat or moves the default flag onto it. Demands Authz.ProfileUpdate at the profile''s own tenant -- '
     + N'and at the ACTOR''S tenant when the id names nothing, so a caller with no authority anywhere never learns '
     + N'whether it exists. @UserId and @TenantId are deliberately not parameters: moving a profile between tenants '
     + N'would silently re-scope every grant on it, and between users would reattribute every audit row. NULL means '
     + N'leave alone. E-50162 duplicate name, E-50163 no such profile, E-50164 @IsDefault = 0 on the current default. '
     + N'Writes no trail row: neither a rename nor the default flag changes what the hat may do.')
    , (N'uspDeactivateProfile'
     , N'Takes a hat away or gives it back. Demands Authz.ProfileDeactivate. Sets IsActive and NEVER IsDeleted '
     + N'(section 6.3, P-07), and leaves auth.UserProfileRole untouched so reactivation is not a re-provisioning '
     + N'exercise. Refuses the profile the calling session is wearing with E-50165, because the next call would fail '
     + N'with E-50021 and no explanation. Moves the default flag to the oldest other ACTIVE profile, and leaves it '
     + N'where it is when there is none -- INV-03 says exactly one profile carries it, not that the carrier is active. '
     + N'Ends live sessions on the hat with EndReason ProfileDeactivated. E-50163.')
    , (N'uspListProfilesForUser'
     , N'Every hat one person wears, for a profile-administration screen, with TenantUsable, IsSwitchable and live and '
     + N'expired grant COUNTS. Demands Authz.ProfileRead and then returns only the profiles at tenants the actor holds '
     + N'it over -- omitted entirely rather than greyed out, because "A has a hat at the neighbouring county" is the '
     + N'fact the scoping exists to keep inside that county. E-50163 means the person has no live profile at all; an '
     + N'empty result set with no error means they have profiles and none of them is yours to see. Error-only '
     + N'instrumented.')
    , (N'uspListMyProfiles'
     , N'The hat menu: every live profile of the CALLING SESSION''S OWN user, with IsCurrent, IsSwitchable, TenantUsable '
     + N'and SwitchBlockedReason. DEMANDS NO PERMISSION and takes no @UserId -- the authority is the session token, and '
     + N'the absence of the parameter is the control: the WHERE clause reads a user id that came from the session row. '
     + N'Exists because auth.uspListProfilesForUser demands Authz.ProfileRead at the acting tenant, which a session with '
     + N'no active profile does not have, so the one screen that could have let such a user in was the one screen they '
     + N'were refused (G-51, SCEN-AUTH-001). Inactive profiles and unusable tenants are RETURNED with a reason, never '
     + N'filtered: "you have no profiles" and "your profiles do not work" are the two answers this screen exists to '
     + N'tell apart. Zero rows is a legitimate answer and not E-50163. Does not predict step-up -- E-50052 is '
     + N'auth.uspSwitchProfile''s to raise. E-50166 means the session was ended by another connection mid-call. '
     + N'Error-only instrumented.')
    , (N'uspSwitchProfile'
     , N'Changes which of your OWN hats the live session is wearing -- section 12.1''s seven steps. NO permission is '
     + N'demanded and there is no Authz.ProfileSwitch: the authority to wear a hat is the existence of the hat, and '
     + N'E-50050 confines the switch to the session''s own user, so it is never impersonation (D-10). E-50051 refuses '
     + N'an inactive profile or an unusable tenant; E-50052 refuses a privileged profile without step-up, where '
     + N'privileged means it holds an Authz, User, Tenant or Platform permission and the requirement comes from the '
     + N'target tenant''s resolved policy. Writes a ProfileSwitch authentication event carrying BOTH profile ids, '
     + N're-establishes SESSION_CONTEXT, and returns the new context AND the navigation as two result sets so the UI '
     + N'repaints in one round trip (UI-04). The navigation half is auth.uspGetNavigationForProfile, T-084, and is '
     + N'guarded on OBJECT_ID until it exists.')
    , (N'uspGrantTenantDefaultRoles'
     , N'Section 11.5. Grants a brand-new profile the default role set of its tenant, or of the NEAREST ANCESTOR that '
     + N'seeds one -- inherited, not copied (BL-052) -- and writes one ''RoleGranted'' trail row per role. Reports back '
     + N'@DefaultSourceTenantId, @CandidateRoleCount and @GrantedRoleCount so the caller can say in its own Comments '
     + N'how many were skipped. EXTRACTED FROM auth.uspCreateProfile so that auth.uspRegisterExternalUser can reach the '
     + N'same rule: a self-registration is UNAUTHENTICATED and has no permission to demand, and two copies of a '
     + N'security-relevant rule would drift. A role whose OwnerTenantId does not cover the tenant violates INV-04 and '
     + N'is SKIPPED, not raised -- one bad auth.TenantDefaultRole row must not block every new profile beneath it. '
     + N'@ActorUserProfileId may be NULL, which means "the tenant''s default set granted this, not a person", the same '
     + N'situation 900_bootstrap_first_admin.sql is in. Called INSIDE the caller''s transaction and does NOT rebuild '
     + N'auth.ProfilePermissionScope -- the caller does that once, afterwards. Not granted to any role: both callers are '
     + N'in this database.');

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


-- *** 9. Grants ***
-- Six of the seven, to applicationRole.  EXECUTE on the procedure and nothing on the tables: ownership chaining carries
-- the reads and writes, so applicationRole never needs SELECT on auth.UserProfile or UPDATE on auth.UserSession
-- (INV-11).
--
-- auth.uspGrantTenantDefaultRoles is the sixth and is deliberately NOT granted.  It is an internal helper with two
-- callers, both in this database, and it demands no permission of its own -- it grants roles to whatever profile id it
-- is handed.  Reached by ownership chaining; granting it would hand the application login a way to give any profile the
-- default role set of any tenant.
IF DATABASE_PRINCIPAL_ID (N'applicationRole') IS NOT NULL
BEGIN
    GRANT EXECUTE ON auth.uspCreateProfile      TO applicationRole;
    GRANT EXECUTE ON auth.uspUpdateProfile      TO applicationRole;
    GRANT EXECUTE ON auth.uspDeactivateProfile  TO applicationRole;
    GRANT EXECUTE ON auth.uspListProfilesForUser TO applicationRole;
    GRANT EXECUTE ON auth.uspListMyProfiles     TO applicationRole;
    GRANT EXECUTE ON auth.uspSwitchProfile      TO applicationRole;

    PRINT N'Granted EXECUTE on the six profile procedures to applicationRole. No table permission is granted: '
        + N'ownership chaining carries the reads and writes (INV-11).';
END
ELSE
BEGIN
    PRINT N'applicationRole does not exist, so no grants were made. Run database/005_schemas_and_roles.sql and then '
        + N're-run this file.';
END
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
SELECT CASE WHEN OBJECT_ID (N'auth.' + x.ProcName, N'P') IS NULL THEN 1 ELSE 4 END
     , CASE WHEN OBJECT_ID (N'auth.' + x.ProcName, N'P') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Procedure auth.' + x.ProcName
     , x.Detail
  FROM (VALUES (N'uspCreateProfile',      N'Authz.ProfileCreate at the TARGET tenant, tested with auth.udfHasPermission so E-50045 is reachable. Inherits default roles.')
             , (N'uspUpdateProfile',      N'Authz.ProfileUpdate. Rename and the default flag only -- @UserId and @TenantId are not parameters.')
             , (N'uspDeactivateProfile',  N'Authz.ProfileDeactivate. IsActive not IsDeleted; moves the default; ends live sessions; E-50165 guards the caller''s own hat.')
             , (N'uspListProfilesForUser',N'Authz.ProfileRead, scoped: profiles outside the actor''s scope are omitted, not flagged. Error-only instrumented.')
             , (N'uspListMyProfiles',      N'No permission demanded and no @UserId -- the hat menu a profileless session can call. G-51, T-126.')
             , (N'uspSwitchProfile',      N'No permission demanded -- there is no Authz.ProfileSwitch. E-50050/51/52. Two result sets, section 12.1 step 7.')
             , (N'uspGrantTenantDefaultRoles', N'Section 11.5, extracted from uspCreateProfile so 155''s unauthenticated self-registration reaches the same rule. Internal: no grant.')
       ) AS x (ProcName, Detail);

-- THE EXTRACTION IS ASSERTED IN BOTH DIRECTIONS, because a half-finished revert would still compile: uspCreateProfile
-- must CALL the helper and must no longer carry its own copy of the auth.TenantDefaultRole query.  Two copies of the
-- INV-04 filter is the defect this refactor exists to prevent, and the second copy is always the one nobody tests.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Calls = 1 AND x.HasOwnCopy = 0 THEN 4 ELSE 1 END
     , CASE WHEN x.Calls = 1 AND x.HasOwnCopy = 0 THEN 'OK' ELSE 'VIOLATED' END
     , N'auth.uspCreateProfile delegates the default-role rule instead of duplicating it'
     , CONCAT (N'Calls auth.uspGrantTenantDefaultRoles: ', x.Calls, N' (must be 1). Still reads '
             , N'auth.TenantDefaultRole itself: ', x.HasOwnCopy, N' (must be 0). The rule is security-relevant -- '
             , N'INV-04 requires a default role''s OwnerTenantId to cover the tenant -- and it is reached from an '
             , N'UNAUTHENTICATED entry point in 155_auth_registration_procedures.sql as well as from here.')
  FROM (SELECT Calls      = MAX (CASE WHEN m.definition LIKE N'%EXEC auth.uspGrantTenantDefaultRoles%' THEN 1 ELSE 0 END)
             , HasOwnCopy = MAX (CASE WHEN m.definition LIKE N'%auth.TenantDefaultRole AS dr%' THEN 1 ELSE 0 END)
          FROM sys.sql_modules AS m
         WHERE m.object_id = OBJECT_ID (N'auth.uspCreateProfile')) AS x;

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 6 THEN 4 ELSE 2 END
     , CASE WHEN COUNT (*) = 6 THEN 'OK' ELSE 'INCOMPLETE' END
     , N'EXECUTE granted to applicationRole'
     , CONCAT (COUNT (*), N' of 6. Zero means 005_schemas_and_roles.sql has not run; anything between is a partial '
             , N'deployment and the application will fail on whichever one is missing.')
  FROM sys.database_permissions AS dp
  JOIN sys.objects              AS o ON o.object_id = dp.major_id
 WHERE dp.grantee_principal_id = DATABASE_PRINCIPAL_ID (N'applicationRole')
   AND dp.permission_name      = N'EXECUTE'
   AND dp.state                = N'G'
   AND o.schema_id             = SCHEMA_ID (N'auth')
   AND o.name IN (N'uspCreateProfile', N'uspUpdateProfile', N'uspDeactivateProfile', N'uspListProfilesForUser'
                , N'uspListMyProfiles', N'uspSwitchProfile');

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 0 THEN 4 ELSE 2 END
     , CASE WHEN COUNT (*) = 0 THEN 'OK' ELSE 'REVIEW' END
     , N'No EXECUTE on auth.uspGrantTenantDefaultRoles to applicationRole'
     , CONCAT (COUNT (*), N' grant(s); 0 is correct. It is an internal helper that demands no permission of its own -- '
             , N'it grants roles to whatever profile id it is handed -- and both its callers are in this database. '
             , N'Granting it would hand the application login a way to give any profile the default role set of any '
             , N'tenant. INV-11.')
  FROM sys.database_permissions AS dp
  JOIN sys.objects              AS o ON o.object_id = dp.major_id
 WHERE dp.grantee_principal_id = DATABASE_PRINCIPAL_ID (N'applicationRole')
   AND dp.permission_name      = N'EXECUTE'
   AND dp.state                IN (N'G', N'W')
   AND o.schema_id             = SCHEMA_ID (N'auth')
   AND o.name                  = N'uspGrantTenantDefaultRoles';

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 7 THEN 4 ELSE 2 END
     , CASE WHEN COUNT (*) = 7 THEN 'OK' ELSE 'INCOMPLETE' END
     , N'MS_Description on the profile procedures'
     , CONCAT (COUNT (*), N' of 7. Conventions rule 4.')
  FROM sys.extended_properties AS ep
  JOIN sys.objects             AS o ON o.object_id = ep.major_id
 WHERE ep.name     = N'MS_Description'
   AND ep.minor_id = 0
   AND o.schema_id = SCHEMA_ID (N'auth')
   AND o.name IN (N'uspCreateProfile', N'uspUpdateProfile', N'uspDeactivateProfile', N'uspListProfilesForUser'
                , N'uspListMyProfiles', N'uspSwitchProfile', N'uspGrantTenantDefaultRoles');

-- The prerequisite this file could not run without, asserted rather than assumed. G-29, BL-055.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN cc.definition LIKE N'%ProfileSwitch%' THEN 4 ELSE 1 END
     , CASE WHEN cc.definition LIKE N'%ProfileSwitch%' THEN 'OK' ELSE 'BLOCKED' END
     , N'CK_logs_AuthenticationEvent_EventType permits ProfileSwitch'
     , CASE WHEN cc.definition LIKE N'%ProfileSwitch%'
            THEN N'Section 12.1 step 6 and section 15.5 both name the event type and the vocabulary is a closed CHECK. '
               + N'085_logs_auth_tables.sql was amended to add it (G-29, BL-055).'
            ELSE N'auth.uspSwitchProfile WILL FAIL AT RUN TIME with error 547 on every call. Re-run '
               + N'database/085_logs_auth_tables.sql: its drop-and-re-add guard is keyed on the constraint''s own '
               + N'definition text and will repair this.' END
  FROM sys.check_constraints AS cc
 WHERE cc.name = N'CK_logs_AuthenticationEvent_EventType';

-- The filtered unique index the whole default-flag dance exists to satisfy.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 1 THEN 4 ELSE 2 END
     , CASE WHEN COUNT (*) = 1 THEN 'OK' ELSE 'MISSING' END
     , N'UX_auth_UserProfile_Default is present'
     , N'Filtered unique on IsDefault = 1 AND IsDeleted = 0. It is what makes INV-03 a guarantee rather than an '
     + N'intention, and why every procedure here clears the old default before setting the new one.'
  FROM sys.indexes AS i
 WHERE i.object_id = OBJECT_ID (N'auth.UserProfile')
   AND i.name      = N'UX_auth_UserProfile_Default';

-- Not an error: a statement of what the design says should NOT exist.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 0 THEN 4 ELSE 2 END
     , CASE WHEN COUNT (*) = 0 THEN 'OK' ELSE 'UNEXPECTED' END
     , N'No Authz.ProfileSwitch permission exists'
     , CONCAT (COUNT (*), N' row(s). Must be 0. Switching between your OWN hats is not a permission -- the authority '
             , N'to wear one is the existence of the hat, and auth.uspSwitchProfile deliberately demands nothing. A '
             , N'row here means somebody added a code the procedure does not read, which is worse than useless: it '
             , N'looks like a control and is not one.')
  FROM auth.Permission AS p
 WHERE p.PermissionCode = N'Authz.ProfileSwitch'
   AND p.IsDeleted      = 0;

-- The forward reference, declared so it cannot be forgotten. The pattern 125_auth_tenant_procedures.sql used.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (N'auth.uspGetNavigationForProfile', N'P') IS NULL THEN 3 ELSE 4 END
     , CASE WHEN OBJECT_ID (N'auth.uspGetNavigationForProfile', N'P') IS NULL THEN 'PENDING' ELSE 'OK' END
     , N'auth.uspSwitchProfile''s second result set'
     , CASE WHEN OBJECT_ID (N'auth.uspGetNavigationForProfile', N'P') IS NULL
            THEN N'auth.uspGetNavigationForProfile does not exist yet -- it is T-084, in '
               + N'150_auth_query_procedures.sql. The call is guarded on OBJECT_ID, so auth.uspSwitchProfile works '
               + N'now and returns ONE result set instead of two. Its contract is fixed here: @SessionTokenHash '
               + N'VARBINARY (32). SMOKE-TEST THE SWITCH THE MOMENT T-084 LANDS -- G-26 and BL-053 are what happened '
               + N'the last time a forward reference was written from a design sketch instead of a signature.'
            ELSE N'Present. Section 12.1 step 7 is satisfied: the switch returns the new context and the navigation '
               + N'in one round trip, which is the flicker UI-04 forbids.' END;

IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
    PRINT N'Profile procedures: PROBLEMS found. Read the report below.';
ELSE
    PRINT N'Profile procedures: no problems found.';

PRINT N'';

SELECT Severity, Status, Item, Detail
  FROM @Report
 ORDER BY Severity, RowNo;
GO
