/***********************************************************************************************************************
Script:         155_auth_registration_procedures.sql
Purpose:        Self-registration.  The three procedures of section 16.4: an external organization asks to join
                (auth.uspRegisterOrganization), an agency user decides (auth.uspApproveOrganization), and the
                organization's own people then enrol themselves (auth.uspRegisterExternalUser).  Plus the recorder
                that makes the first and the third countable, auth.uspRecordRegistrationAttempt (G-24).
Target:         SQL Server 2022.
Run as:         db_owner in the target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/155_auth_registration_procedures.sql
Idempotent:     Yes.  CREATE OR ALTER throughout.  The closing report writes nothing.
Depends on:     database/080_auth_registration.sql, database/030_auth_tenant.sql, database/035_auth_user.sql,
                database/040_auth_userprofile.sql, database/025_config_application_setting.sql,
                database/100_auth_functions.sql, database/105_auth_session_procedures.sql,
                database/125_auth_tenant_procedures.sql, database/140_auth_profile_procedures.sql,
                database/165_logs_procedures.sql, templates/extended-properties.sql.
Implements:     T-087.  DES-AUTH-001 sections 16.4, 11.5, 14.2 and 15.4.  Appendix B errors 50060-50068.  Gap
                G-24 -- the per-address registration throttle, E-50068.
                See docs/10-database-authn-authz-design.md.
To retarget:    Pass it per run:  sqlcmd -d <database> -v DbName=<database>.  There is no in-file default.

TWO OF THESE THREE PROCEDURES HAVE NO SESSION, AND THAT IS THE WHOLE DIFFICULTY
------------------------------------------------------------------------------
Every other writing procedure in this database opens with auth.uspSetSessionContext and then demands a permission.  Two
of the three here cannot: auth.uspRegisterOrganization is reached by a member of the public who has no account, and
auth.uspRegisterExternalUser is reached by a member of the public who is in the act of creating one.  There is no profile
to check a permission against, so something else has to be the authority, and in each case it is a ROW:

    auth.uspRegisterOrganization    No authority is needed, because it creates no authority.  It writes one
                                    auth.OrganizationRegistration row with Status = 'Pending' and NOTHING ELSE.  No
                                    tenant, no user, no profile, no grant.  Nobody can sign in as a result of it.
    auth.uspRecordRegistrationAttempt
                                    Needs no authority either, and records rather than decides: one
                                    auth.RegistrationAttempt row per public call, plus the per-address count the two
                                    entry points above and below refuse on.  It never refuses anything itself.
    auth.uspApproveOrganization     Fully authenticated, demands Tenant.Create, and is the human gate section 16.4
                                    calls deliberate.  This is the ONLY step that creates a tenant.
    auth.uspRegisterExternalUser    Its authority is an APPROVED registration row naming a usable tenant.  An agency
                                    user already decided, by hand, that people from that organization may enrol; this
                                    procedure enrols one of them and grants only what that tenant's default role set
                                    gives.

So the trust boundary is not "is this caller authorized" but "has a human already approved this organization".
Everything the unauthenticated paths can do was decided in advance by somebody who was authenticated.

WHAT THIS FILE DOES AND DOES NOT DO ABOUT RATE LIMITING -- AND IT USED TO DO NOTHING
-----------------------------------------------------------------------------------
Until G-24 this section said that a counter here would be both ineffective and harmful, and that the whole mitigation
belonged in front of the application.  Half of that was right and the other half was an argument for doing nothing.  The
right half stands and is restated below.  The wrong half was this: a per-address count is not an attempt to distinguish a
flood from a busy morning, it is an attempt to make a flood from ONE PLACE cost something, and that is a question the
database can answer, because it is the only component that can see every arrival that ever reached it.

So both entry points now take a per-address count over auth.RegistrationAttempt and refuse as E-50068 once it is
crossed, driven by config.ApplicationSetting keys Registration.ThrottleThreshold and
Registration.ThrottleWindowMinutes.  Three properties of that count are deliberate and each one would look like a bug to
somebody who had not read this:

  *  IT COUNTS ARRIVALS, NOT FAILURES.  Section 7.4 counts failed sign-ins, because a successful sign-in is proof the
     caller is who they said.  Nothing about a well-formed registration proves anything, and a thousand valid ones from
     one address is the flood rather than the good case.
  *  IT IS COUNTED OVER A SECOND TABLE, NOT OVER THE QUEUE.  A submission refused by E-50062 or E-50063 writes no
     auth.OrganizationRegistration row, so counting the queue would count only the attempts that were well-formed enough
     to reach it, and an attacker who deliberately fails validation would be invisible.
  *  THE ATTEMPT IS RECORDED BEFORE THE CALL IS VALIDATED.  A row that is never concluded stays 'Received' and still
     counts, so an input that trips an error nobody anticipated does not buy a free call.

@ClientAddress IS THEREFORE NO LONGER OPTIONAL ON EITHER PUBLIC PROCEDURE, and that is a breaking change for any caller
that omitted it: it is refused as E-50062 before anything is recorded.  An optional identifier on a throttled endpoint is
simply the bypass, and the address is supplied by the web tier from the connection rather than by the registrant, so
there is no legitimate caller that cannot produce one.

AND THE EDGE STILL OWNS THE REAL DEFENCE -- G-06, WHICH STAYS OPEN.  A threshold of ten per hour per address costs a
botnet nothing: it pays once per address and it has thousands.  Rate limiting at the gateway and a CAPTCHA or equivalent
on the public form are the controls that make a flood expensive, and neither can live in SQL Server.  What this file
guarantees is narrower and still worth having: one address cannot fill the queue, every arrival is counted whether it was
well formed or not, and the evidence of who tried is complete.  A flood also remains CHEAP -- a pending registration
creates no tenant, no user, no login and no grant -- and VISIBLE, through auth.RegistrationAttempt,
IX_auth_OrganizationRegistration_Queue and one logs.ExecutionLog row per call.

WHY A REGISTRANT IS NOT TOLD THAT THEIR PROPOSED TENANT CODE ALREADY EXISTS
--------------------------------------------------------------------------
E-50063 fires only when a PENDING registration already claims the code -- information the registrant themselves supplied
a moment ago and can reasonably be told.  If the code is already a LIVE TENANT, registration SUCCEEDS and the collision
is reported to the reviewer at approval time as E-50065.  That asymmetry is deliberate.  Telling a stranger "AGENCY is
taken" turns this procedure into a tenant enumerator, and the tenant list of a multi-jurisdiction system is not public
information.  The cost is one wasted row and one reviewer's rejection; the alternative cost is a map of the deployment.

auth.uspRegisterExternalUser goes the OTHER way and does report a name collision, as E-50066, and Appendix B says why:
there the caller is choosing their OWN user name, so "that one is taken" tells them nothing they could not learn by
trying to sign in, and refusing to say would leave them unable to complete registration at all.

APPROVAL CREATES A TENANT AND SEEDS NO DEFAULT ROLES
---------------------------------------------------
Section 16.4 step 2 says approval "seeds its default roles (READ_ONLY, CONTRIBUTOR, EDITOR)".  It does not, and the
difference is BL-052.  auth.TenantDefaultRole is read "inherited from the nearest ancestor if absent" (section 11.5), so
the external-organizations branch names the set ONCE and every organization approved beneath it inherits it.  Writing
three rows per new tenant would mean that changing the policy later required finding and editing every child's rows --
and the ones nobody found would keep the old policy silently.  A new organization's tenant therefore has NO
auth.TenantDefaultRole rows of its own, which is not an omission but the mechanism.

An organization that genuinely needs a different default set gets rows written for it deliberately, and from that moment
it stops inheriting.  That is the override, and it is the only case where those rows should exist.

THE REJECTION PATH EXISTS EVEN THOUGH SECTION 16.4 DOES NOT DESCRIBE IT
----------------------------------------------------------------------
CK_auth_OrganizationRegistration_Status permits 'Pending', 'Approved' and 'Rejected', and CK_..._Concluded spells out
what a Rejected row must look like -- reviewed, by someone, with no tenant.  If no procedure could write that state, the
constraint would describe a row the database could never contain, and the review screen would have exactly one button.
So auth.uspApproveOrganization takes @Approve BIT and does both, under the same permission and the same trail.  A
rejection creates nothing, which is why it is safe to put in the same procedure as the one thing on this page that
creates a tenant: the parameter chooses between "make a tenant" and "make nothing", and both end the registration.

@ReviewNote IS THE ONE FREE-TEXT FIELD IN THIS FILE AND IT IS NOT SHOWN TO THE REGISTRANT.  It is the reviewer's record
of why, for the next reviewer.  The application may of course send its own message to the contact email; this column is
not it, and a note written in the belief that the registrant will read it is a note that will not say the useful thing.
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

IF OBJECT_ID (N'auth.OrganizationRegistration', N'U') IS NULL
   OR OBJECT_ID (N'auth.RegistrationAttempt', N'U')     IS NULL
   OR OBJECT_ID (N'auth.Tenant', N'U')                 IS NULL
   OR OBJECT_ID (N'auth.User', N'U')                   IS NULL
   OR OBJECT_ID (N'auth.UserProfile', N'U')            IS NULL
   OR OBJECT_ID (N'config.ApplicationSetting', N'U')   IS NULL
BEGIN
    -- Built into a variable because THROW takes a constant or a variable, never an expression.
    DECLARE @Msg NVARCHAR (2000) =
        N'One of auth.OrganizationRegistration, auth.RegistrationAttempt, auth.Tenant, auth.User, auth.UserProfile '
      + N'or config.ApplicationSetting is missing. Run database/080_auth_registration.sql and the table scripts it '
      + N'depends on first -- auth.RegistrationAttempt arrived with G-24 and a deployment that has 080 from before it '
      + N'will fail here rather than install an unthrottled entry point. Nothing has been changed.';

    THROW 50000, @Msg, 1;
END
GO

-- The procedures these three call.  A procedure gets DEFERRED name resolution, so a missing one does not stop this file
-- installing -- it stops the call, at run time, with 2812, and a warning now is worth more than that error later.
IF OBJECT_ID (N'auth.uspCreateTenant', N'P')             IS NULL
   OR OBJECT_ID (N'auth.uspGrantTenantDefaultRoles', N'P') IS NULL
   OR OBJECT_ID (N'auth.uspRebuildProfilePermissionScope', N'P') IS NULL
   OR OBJECT_ID (N'auth.uspSetSessionContext', N'P')     IS NULL
BEGIN
    PRINT N'WARNING: one or more of auth.uspCreateTenant (125), auth.uspGrantTenantDefaultRoles (140), '
        + N'auth.uspRebuildProfilePermissionScope (065) or auth.uspSetSessionContext (105) does not exist. This file '
        + N'installs anyway -- a procedure gets deferred name resolution -- but the procedures below will fail with '
        + N'2812 when called. Run those files and then re-run this one so the closing report can confirm the chain.';
END
GO

-- *** 1. auth.uspRecordRegistrationAttempt -- one row per public call, and the count ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspRecordRegistrationAttempt
Author:       rsincero
CreateDate:   2026-09-21
========================================================================================================================
Description:

Records ONE auth.RegistrationAttempt row for a call of a public registration entry point, then takes the per-address
count over the throttle window and reports whether that address has crossed Registration.ThrottleThreshold.  Gap G-24.
It records and it counts; it never refuses.  The refusal is E-50068 and belongs to the caller, for the reason the notes
give.

WHAT THE CALLER MUST DO WITH IT, IN ORDER
-----------------------------------------
  1.  Trim @ClientAddress and refuse a blank one (E-50062).  This procedure cannot be reached without an address and
      neither can the throttle.
  2.  Call this FIRST, before validating anything else, and BEFORE opening a transaction.
  3.  If @AddressThrottled comes back 1, raise E-50068 and write nothing.
  4.  Otherwise carry on, and when the outcome is known UPDATE the row this returned: 'Accepted' with the registration
      it produced or used, or 'Refused' with a short reason token.  Do that update OUTSIDE the transaction the work ran
      in -- an arrival is not undone by the failure of what it asked for.

WHY THIS PROCEDURE DOES NOT RAISE E-50068 ITSELF
-----------------------------------------------
It is a recorder, and a recorder that throws leaves its caller unable to record anything -- including the refusal.  More
concretely: if this raised, the attempt row it had just inserted would be the LAST thing it did, the caller's CATCH would
have no id to conclude, and every throttled attempt would sit at 'Received' for ever.  Separating "count" from "refuse"
also means a project that wants to log-only rather than refuse can do it by ignoring one output parameter, with no fork
of this file.  auth.uspRecordLoginFailure takes the same shape for the same reason: it reports @AccountLockedOut and
@AddressThrottled and leaves the refusal to the next call of auth.uspGetLoginVerifier.

WHY IT OPENS ITS OWN TRANSACTION, AND WHY THE CALLER MUST NOT HAVE ONE OPEN
-------------------------------------------------------------------------
The attempt row must survive its caller's rollback: it is the record that a call ARRIVED, and the arrival happened
whether or not the work succeeded.  A nested BEGIN TRANSACTION inside a caller's transaction does not commit -- it only
decrements @@TRANCOUNT -- so calling this from inside one would make every attempt from a failed call disappear, which is
precisely the hole the whole design exists to close.  Both callers therefore call it before their own BEGIN TRANSACTION,
and the closing report asserts that ordering rather than trusting it.

THE COUNT INCLUDES THE ROW THIS CALL JUST WROTE
-----------------------------------------------
So a threshold of 10 admits ten attempts in the window and refuses the eleventh -- "crossing it", which is the word
config.ApplicationSetting's own description of Registration.ThrottleThreshold uses.  A threshold of 0 disables the
database throttle entirely and is still recorded, so a deployment that turns it off keeps the evidence and loses only the
refusal.  A negative or unparseable setting is treated as the shipped default rather than as "off": failing open because
somebody typed a word into a settings screen is the wrong direction for a control.

THROTTLED ATTEMPTS ARE THEMSELVES COUNTED, SO A FLOOD DOES NOT LAPSE WHILE IT CONTINUES
-------------------------------------------------------------------------------------
An address that keeps calling keeps adding rows, so it stays over the line until it has been quiet for a whole window.
That is the opposite of the sign-in address throttle, where a refused exchange writes no auth.LoginAttempt row and the
window therefore drains while the attacker is still knocking.  Both behaviours are defensible and this is the one that
suits a queue a human has to empty by hand.  The cost is borne by whoever shares an address with an attacker -- an office
behind one NAT gateway -- and it is the same cost section 7.4 already accepts for sign-in, bounded here by a window
measured in minutes and clearable by soft-deleting the rows.

NO CREDENTIAL, AND NO TRUSTED INPUT
-----------------------------------
Nothing that reaches this procedure is secret: an application code, a proposed tenant code, an address and a user-agent
string.  Nothing that reaches it is trusted either -- @UserAgent is recorded verbatim and never parsed, and
@ApplicationCode is recorded as the string that was supplied whether or not it names anything.  @KeyParameters carries
the address because on this table the address IS the identifier under investigation, and it is not a credential in any
sense; rule 8 forbids secrets, not identifiers.

========================================================================================================================
Example Usage and Performance:

declare @AttemptId bigint, @Count int, @Throttled bit, @Threshold int, @Window int;
exec auth.uspRecordRegistrationAttempt
      @AttemptKind            = 'Organization'
    , @ClientAddress          = N'203.0.113.45'
    , @ApplicationCode        = N'TEMPLATE'
    , @ProposedTenantCode     = N'ACME'
    , @UserAgent              = N'Mozilla/5.0 ...'
    , @RegistrationAttemptId  = @AttemptId OUTPUT
    , @AddressAttemptCount    = @Count     OUTPUT
    , @AddressThrottled       = @Throttled OUTPUT
    , @Threshold              = @Threshold OUTPUT
    , @WindowMinutes          = @Window    OUTPUT;

Two setting seeks, one insert, and one range seek on IX_auth_RegistrationAttempt_Address bounded by the window -- so the
count costs what the window holds and not what the table holds, which is the reason that index exists.

========================================================================================================================
Modification History:

Date:		2026-09-21
Author:		rsincero
Ticket:		G-24
Description:
Created.  The database half of G-06; the edge half stays open.

-----------------------------------------------------------------------------------------------------------------------
***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspRecordRegistrationAttempt
      @AttemptKind                 VARCHAR (20)
    , @ClientAddress               NVARCHAR (45)
    , @ApplicationCode             NVARCHAR (50)  = NULL
    , @ProposedTenantCode          NVARCHAR (50)  = NULL
    , @UserAgent                   NVARCHAR (512) = NULL
    , @OrganizationRegistrationId  INT            = NULL
    , @RegistrationAttemptId       BIGINT         = NULL OUTPUT
    , @AddressAttemptCount         INT            = NULL OUTPUT
    , @AddressThrottled            BIT            = NULL OUTPUT
    , @Threshold                   INT            = NULL OUTPUT
    , @WindowMinutes               INT            = NULL OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    DECLARE @ProcName       NVARCHAR (400)
          , @ExecutionId    BIGINT
          , @StartTimeUtc   DATETIME2 (7) = SYSUTCDATETIME ()
          , @EndTimeUtc     DATETIME2 (7)
          , @KeyParameters  NVARCHAR (MAX)
          , @Comments       NVARCHAR (MAX)
          , @ContextMessage NVARCHAR (MAX)
          , @DynamicSql     NVARCHAR (MAX) = NULL
          , @ErrorMsg       NVARCHAR (2048)
          , @ErrorProc      NVARCHAR (256)
          , @ErrorNumber    INT
          , @ErrorLine      INT
          , @Failure        NVARCHAR (2048)
          , @Actor          NVARCHAR (255)
          , @Now            DATETIME2 (3);

    SET @ProcName = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID)) + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                            , N'[auth].[uspRecordRegistrationAttempt]');

    -- No session here either.  See section 2 on why ORIGINAL_LOGIN () is the correct attribution for a public path.
    SET @Actor = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N''), ORIGINAL_LOGIN ());

    SET @AddressThrottled = 0;

    SET @KeyParameters = CONCAT (N'AttemptKind=',       COALESCE (@AttemptKind, '(null)')
                               , N'; ClientAddress=',   COALESCE (@ClientAddress, N'(null)')
                               , N'; ApplicationCode=', COALESCE (@ApplicationCode, N'(null)')
                               , N'; RegistrationId=',  COALESCE (CAST (@OrganizationRegistrationId AS NVARCHAR (12))
                                                                , N'(null)'));
    SET @ContextMessage = N'Unauthenticated entry point, and a recorder rather than a decider: it writes one '
                        + N'auth.RegistrationAttempt row and reports the per-address count. G-24. The refusal is '
                        + N'E-50068 and belongs to the caller.';

    BEGIN TRY
        -- *** The two arguments without which nothing can be recorded (E-50062) ***
        SET @ClientAddress   = NULLIF (LTRIM (RTRIM (COALESCE (@ClientAddress,   N''))), N'');
        SET @ApplicationCode = NULLIF (LTRIM (RTRIM (COALESCE (@ApplicationCode, N''))), N'');
        SET @UserAgent       = NULLIF (LTRIM (RTRIM (COALESCE (@UserAgent,       N''))), N'');
        SET @ProposedTenantCode = NULLIF (LTRIM (RTRIM (COALESCE (@ProposedTenantCode, N''))), N'');

        IF @ClientAddress IS NULL
        BEGIN
            SET @Failure = N'@ClientAddress is required and may not be blank or whitespace. The address is the only '
                         + N'thing a per-address count can be taken on, so an attempt with no address is an attempt '
                         + N'outside the throttle -- gap G-24. The web tier reads it from the connection rather than '
                         + N'from the form, so this is a deployment fault and not something the registrant did. '
                         + N'Nothing has been recorded.';

            ;THROW 50062, @Failure, 1;
        END

        -- The closed set lives in CK_auth_RegistrationAttempt_AttemptKind; this is here so a defect in a caller in this
        -- file reads as a sentence rather than as Msg 547 from a constraint the caller cannot see.
        IF @AttemptKind IS NULL OR @AttemptKind NOT IN ('Organization', 'ExternalUser')
        BEGIN
            SET @Failure = N'@AttemptKind must be ''Organization'' (section 16.4 step 1) or ''ExternalUser'' (step 3). '
                         + N'Both are counted on the same per-address total on purpose: a throttle on one public form '
                         + N'beside an untouched one is a throttle nobody pays. Nothing has been recorded.';

            ;THROW 50062, @Failure, 1;
        END

        -- The two settings.  COALESCE to the shipped defaults rather than to "off", because a control that fails open
        -- when somebody types a word into a settings screen is the wrong way round.  0 really does mean off, and it is
        -- the only way to mean it.
        SET @Threshold = COALESCE (TRY_CAST ((SELECT cs.SettingValue
                                                FROM config.ApplicationSetting AS cs
                                               WHERE cs.SettingKey = N'Registration.ThrottleThreshold'
                                                 AND cs.IsDeleted  = 0) AS INT), 10);
        SET @WindowMinutes = COALESCE (TRY_CAST ((SELECT cs.SettingValue
                                                    FROM config.ApplicationSetting AS cs
                                                   WHERE cs.SettingKey = N'Registration.ThrottleWindowMinutes'
                                                     AND cs.IsDeleted  = 0) AS INT), 60);

        IF @Threshold < 0     SET @Threshold     = 10;
        IF @WindowMinutes < 1 SET @WindowMinutes = 60;

        -- FK_auth_RegistrationAttempt_auth_OrganizationRegistration would refuse an id that names nothing, and the
        -- attempt that named nothing is exactly the one worth recording -- so it is dropped from the row instead of
        -- being allowed to refuse the row.  Existence and not IsDeleted = 0, because that is what the foreign key
        -- checks; whether a soft-deleted registration may be enrolled into is section 4's question, answered by
        -- E-50064.
        IF @OrganizationRegistrationId IS NOT NULL
           AND NOT EXISTS (SELECT 1
                             FROM auth.OrganizationRegistration AS orr
                            WHERE orr.OrganizationRegistrationId = @OrganizationRegistrationId)
        BEGIN
            SET @OrganizationRegistrationId = NULL;
        END;

        EXEC logs.uspStartExecutionLogging
              @ProcedureName          = @ProcName
            , @KeyParameters          = @KeyParameters
            , @StartDateUtc           = @StartTimeUtc
            , @ReCreatedAfterRollback = 0
            , @ExecutionLogId         = @ExecutionId OUTPUT;

        BEGIN TRANSACTION;

            SET @Now = SYSUTCDATETIME ();

            INSERT auth.RegistrationAttempt
                 ( AttemptKind,  ApplicationCode,  ProposedTenantCode,  ClientAddress,  UserAgent
                 , Outcome,      OrganizationRegistrationId,  AttemptedUtc
                 , auditCreatedBy, auditModifiedBy)
            VALUES
                 (@AttemptKind, @ApplicationCode, @ProposedTenantCode, @ClientAddress, @UserAgent
                 ,'Received',   @OrganizationRegistrationId, @Now
                 ,@Actor,        @Actor);

            SET @RegistrationAttemptId = SCOPE_IDENTITY ();

            -- The count, INCLUDING the row above -- see the header.  A range seek on
            -- IX_auth_RegistrationAttempt_Address, so it costs what the window holds.
            SET @AddressAttemptCount = (SELECT COUNT (*)
                                          FROM auth.RegistrationAttempt AS a
                                         WHERE a.ClientAddress = @ClientAddress
                                           AND a.IsDeleted     = 0
                                           AND a.AttemptedUtc >= DATEADD (MINUTE, -@WindowMinutes, @Now));

            SET @AddressThrottled = CASE WHEN @Threshold > 0 AND @AddressAttemptCount > @Threshold THEN 1 ELSE 0 END;

        IF @@TRANCOUNT > 0
        BEGIN
            COMMIT TRANSACTION;
        END;

        SET @EndTimeUtc = SYSUTCDATETIME ();
        SET @Comments = CONCAT (N'Attempt ', CAST (@RegistrationAttemptId AS NVARCHAR (20)), N' recorded: kind '
                              , @AttemptKind, N', address count ', CAST (@AddressAttemptCount AS NVARCHAR (11))
                              , N' in the last ', CAST (@WindowMinutes AS NVARCHAR (11)), N' minute(s) against a '
                              , N'threshold of ', CAST (@Threshold AS NVARCHAR (11))
                              , CASE WHEN @Threshold = 0 THEN N' (the database throttle is DISABLED, so the count is '
                                                            + N'recorded and never enforced)'
                                     WHEN @AddressThrottled = 1 THEN N' -- CROSSED, so the caller must refuse with '
                                                                   + N'E-50068'
                                     ELSE N' -- within the allowance' END
                              , N'. Outcome is ''Received'' until the caller concludes it.');

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
    END CATCH

    RETURN 0;
END;
GO

-- *** 2. auth.uspRegisterOrganization -- an organization asks to join ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspRegisterOrganization
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

An external organization asks to be admitted.  Section 16.4 step 1.  Writes one auth.OrganizationRegistration row with
Status = 'Pending' and returns its id; a human decides later, in auth.uspApproveOrganization.  Every call, including every
refused one, is recorded and counted by auth.uspRecordRegistrationAttempt, and an address over
Registration.ThrottleThreshold is refused as E-50068 (G-24).

WHAT IT IS ALLOWED TO DO, WHICH IS ALMOST NOTHING
-------------------------------------------------
One INSERT into auth.OrganizationRegistration with Status = 'Pending', and one row in logs.ExecutionLog to say it
happened.  It creates no tenant, no user, no profile, no role grant and no session, so there is nothing an attacker can
obtain by calling it except a place in a queue that a human reads.  That is the reason it needs no permission, and the
reason it must stay this small: the moment it writes anything a caller could later sign in as, it stops being safe to
expose and the whole design of section 16.4 has to change.

WHY @ApplicationCode IS A PARAMETER AND NOT DERIVED
--------------------------------------------------
It is tempting to look up "the" application, because 115_seed_reference_data.sql seeds exactly one and E-50086 leans on
that.  But a template database is also where the section 17 variants and the test fixtures live, and this database
currently holds eight applications.  Deriving the application by uniqueness would therefore work in production and throw
in every test deployment -- the worst possible split.  So the caller names it, the web tier reads it from its own
configuration (it is the application's own identity, not user input), and an unrecognised code is refused as a bad
argument.

E-50062 IS RAISED FOR @ApplicationCode AND @ClientAddress TOO, WHICH WIDENS ITS APPENDIX B TEXT.  Appendix B names three
arguments because the design's sketch had neither an application parameter nor a throttle.  The fault class is identical --
"unauthenticated entry point, so every argument is validated before anything is written" -- so reusing the number is more
honest than inventing two or letting a NULL reach the foreign key and surface as Msg 515.  Recorded as a documentation
amendment, not a silent reinterpretation.

@ClientAddress IS NOW REQUIRED, AND THAT IS A BREAKING CHANGE WITH A REASON (G-24)
---------------------------------------------------------------------------------
It used to default to NULL, which meant a caller could omit it and leave the row unattributable.  With a per-address
throttle in front of this procedure, an omitted address is not merely untidy: it is the bypass, because a count grouped on
a column that is sometimes absent counts nothing for the callers who leave it out.  So a blank or missing address is
refused as E-50062 BEFORE anything is recorded, and the refusal is deliberately the one case a throttled call cannot be
counted for -- there is nothing to count it against.  The address comes from the connection, not from the form, so no
registrant can influence it and no legitimate caller can fail to supply it.

WHAT HAPPENS IN WHAT ORDER, BECAUSE THE ORDER IS THE CONTROL
-----------------------------------------------------------
  1.  Trim everything.  The throttle groups on the trimmed address, so '203.0.113.9 ' must not be a second address with
      its own allowance.
  2.  Refuse a missing address (E-50062).  Nothing is recorded, for the reason above.
  3.  Record the arrival and read the count.  BEFORE the remaining validation, so that an argument nobody anticipated
      cannot buy a free call, and before BEGIN TRANSACTION, so the record of the arrival survives any rollback.
  4.  Refuse a crossed threshold (E-50068), writing nothing else.
  5.  Validate the rest (E-50062, E-50063), then insert.
  6.  Conclude the attempt row -- 'Accepted' after the COMMIT, 'Refused' or 'Throttled' in the CATCH after the ROLLBACK.
      Never inside the transaction: an arrival is not undone by the failure of what it asked for.

THE CALLER IS TOLD IT WAS THROTTLED, BUT NOT THE NUMBERS.  E-50068's message says a limit was reached and that it lapses;
the count, the threshold and the window go to @Comments and logs.ExecutionLog, where an operator can see them and an
attacker cannot.  UI-26's rule -- never hand a caller the shape of a control -- applies to a public form at least as much
as to a sign-in page.

WHAT IS NORMALISED AND WHY
--------------------------
@ProposedTenantCode is trimmed and upper-cased before it is stored or compared.  The code is what auth.Tenant will be
matched on if this registration is approved, and 'acme' and 'ACME' must not be able to sit in the queue as two different
pending registrations -- UX_auth_OrganizationRegistration_Pending would happily allow them under a case-sensitive
collation, and then approving both would collide at tenant creation instead.  Normalising at the door means the
uniqueness the index enforces is the uniqueness a reviewer sees.

The name, contact name and email are trimmed only.  CK_auth_OrganizationRegistration_Named requires them un-padded, and
an organization's name is its own to capitalise.

========================================================================================================================
Example Usage and Performance:

declare @RegistrationId int;
exec auth.uspRegisterOrganization
      @ApplicationCode            = N'TEMPLATE'
    , @ProposedTenantCode         = N'ACME'
    , @OrganizationName           = N'Acme Contracting'
    , @ContactEmail               = N'registrations@acme.example'
    , @ContactName                = N'A. Coyote'
    , @ClientAddress              = N'203.0.113.45'   -- required since G-24
    , @UserAgent                  = N'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
    , @OrganizationRegistrationId = @RegistrationId output;

One call of auth.uspRecordRegistrationAttempt (two setting seeks, one insert, one windowed range seek), one seek on
auth.Application, one seek on UX_auth_OrganizationRegistration_Pending, one insert, one update to conclude the attempt.
Still cheap on purpose: see the file header on rate limiting -- a flood of these has to stay affordable, because what is
here bounds one address and not a botnet.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-087
Description: Created.

Date:		2026-09-21
Author:		rsincero
Ticket:		G-24
Description:
Per-address throttle: records every arrival through auth.uspRecordRegistrationAttempt, refuses a crossed threshold as
E-50068, and makes @ClientAddress mandatory.  @UserAgent added, recorded and never parsed.

-----------------------------------------------------------------------------------------------------------------------
***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspRegisterOrganization
      @ApplicationCode             NVARCHAR (50)
    , @ProposedTenantCode          NVARCHAR (50)
    , @OrganizationName            NVARCHAR (200)
    , @ContactEmail                NVARCHAR (320)
    , @ContactName                 NVARCHAR (256) = NULL
    -- NOT optional, and G-24 is why -- see the header.  It keeps its default so that a caller that omits it is refused
    -- by a sentence explaining the change rather than by Msg 201 naming a parameter it has never heard of.
    , @ClientAddress               NVARCHAR (45)  = NULL
    , @UserAgent                   NVARCHAR (512) = NULL
    , @OrganizationRegistrationId  INT            = NULL OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    DECLARE @ProcName       NVARCHAR (400)
          , @ExecutionId    BIGINT
          , @StartTimeUtc   DATETIME2 (7) = SYSUTCDATETIME ()
          , @EndTimeUtc     DATETIME2 (7)
          , @KeyParameters  NVARCHAR (MAX)
          , @Comments       NVARCHAR (MAX)
          , @ContextMessage NVARCHAR (MAX)
          , @DynamicSql     NVARCHAR (MAX) = NULL
          , @ErrorMsg       NVARCHAR (2048)
          , @ErrorProc      NVARCHAR (256)
          , @ErrorNumber    INT
          , @ErrorLine      INT
          , @Failure        NVARCHAR (2048)
          , @Actor          NVARCHAR (255)
          , @ApplicationId  INT
          , @Now            DATETIME2 (7)
          -- G-24.  @AttemptId stays NULL until the arrival is recorded, and the CATCH tests it: the one refusal raised
          -- before the recorder (a missing address) has no row to conclude.
          , @AttemptId      BIGINT = NULL
          , @AddressCount   INT    = NULL
          , @Throttled      BIT    = 0
          , @Threshold      INT    = NULL
          , @WindowMinutes  INT    = NULL;

    SET @ProcName = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID)) + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                            , N'[auth].[uspRegisterOrganization]');

    -- THERE IS NO SESSION, SO THERE IS NO SESSION_CONTEXT('AppUser') TO FALL BACK FROM.  ORIGINAL_LOGIN () is the
    -- application's own SQL login, which is the correct and only available attribution: the row records WHO THE SYSTEM
    -- WAS ACTING AS, and here it was acting as itself on behalf of a stranger.  The stranger's own identity claim lives
    -- in ContactEmail and ClientAddress, where it belongs -- unverified, and marked as such by being data rather than
    -- attribution.
    SET @Actor = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N''), ORIGINAL_LOGIN ());

    SET @KeyParameters = CONCAT (N'ApplicationCode=',    COALESCE (@ApplicationCode, N'(null)')
                               , N'; ProposedTenantCode=', COALESCE (@ProposedTenantCode, N'(null)')
                               , N'; ContactEmailLength=', CAST (LEN (COALESCE (@ContactEmail, N'')) AS NVARCHAR (10))
                               -- The address itself and not merely whether one arrived, because with G-24 in place it is
                               -- the identifier an investigation starts from. An address is not a credential.
                               , N'; ClientAddress=', COALESCE (@ClientAddress, N'(null)'));
    SET @ContextMessage = N'Unauthenticated entry point. Writes one Pending auth.OrganizationRegistration row and '
                        + N'nothing else: no tenant, no user, no profile, no grant. Throttled per address over '
                        + N'auth.RegistrationAttempt (G-24, E-50068).';

    BEGIN TRY
        -- *** Validate every argument before anything is written (E-50062) ***
        SET @ApplicationCode    = NULLIF (LTRIM (RTRIM (COALESCE (@ApplicationCode,    N''))), N'');
        SET @ProposedTenantCode = NULLIF (UPPER (LTRIM (RTRIM (COALESCE (@ProposedTenantCode, N'')))), N'');
        SET @OrganizationName   = NULLIF (LTRIM (RTRIM (COALESCE (@OrganizationName,   N''))), N'');
        SET @ContactEmail       = NULLIF (LTRIM (RTRIM (COALESCE (@ContactEmail,       N''))), N'');
        SET @ContactName        = NULLIF (LTRIM (RTRIM (COALESCE (@ContactName,        N''))), N'');
        SET @ClientAddress      = NULLIF (LTRIM (RTRIM (COALESCE (@ClientAddress,      N''))), N'');
        SET @UserAgent          = NULLIF (LTRIM (RTRIM (COALESCE (@UserAgent,          N''))), N'');

        -- *** The address first and on its own, because without it there is no throttle (E-50062, G-24) ***
        IF @ClientAddress IS NULL
        BEGIN
            SET @Failure = N'@ClientAddress is required and may not be blank or whitespace. It stopped being optional '
                         + N'when this endpoint became throttled per address (gap G-24, E-50068): a count grouped on a '
                         + N'column that is sometimes absent counts nothing for the callers who omit it. The web tier '
                         + N'reads the address from the connection rather than from the form, so this is a deployment '
                         + N'fault and not something the registrant did. Nothing has been written and nothing has been '
                         + N'recorded -- this is the one refusal with no attempt row, because there is nothing to '
                         + N'attribute it to.';

            ;THROW 50062, @Failure, 1;
        END

        -- *** Record the arrival BEFORE validating anything else, and BEFORE any transaction (G-24) ***
        -- Order matters twice over: an input that trips an error nobody anticipated must not buy a free call, and the
        -- record of an arrival must not roll back with the work it asked for. See the recorder's header.
        EXEC auth.uspRecordRegistrationAttempt
              @AttemptKind            = 'Organization'
            , @ClientAddress          = @ClientAddress
            , @ApplicationCode        = @ApplicationCode
            , @ProposedTenantCode     = @ProposedTenantCode
            , @UserAgent              = @UserAgent
            , @RegistrationAttemptId  = @AttemptId     OUTPUT
            , @AddressAttemptCount    = @AddressCount  OUTPUT
            , @AddressThrottled       = @Throttled     OUTPUT
            , @Threshold              = @Threshold     OUTPUT
            , @WindowMinutes          = @WindowMinutes OUTPUT;

        -- *** And refuse a crossed threshold (E-50068) ***
        -- No numbers in the message: the count, the threshold and the window are in @Comments and in logs.ExecutionLog,
        -- where an operator can read them and a caller cannot. UI-26.
        IF @Throttled = 1
        BEGIN
            SET @Failure = N'Too many registration requests have arrived from this address recently, so this one has '
                         + N'not been accepted. The limit is per address and it lapses on its own: wait and try again, '
                         + N'or contact the organization you are registering with if this is urgent. Nothing has been '
                         + N'written. Operators: the count, the threshold and the window are in logs.ExecutionLog, and '
                         + N'the settings are Registration.ThrottleThreshold and Registration.ThrottleWindowMinutes.';

            ;THROW 50068, @Failure, 1;
        END

        IF @ApplicationCode IS NULL
           OR @ProposedTenantCode IS NULL
           OR @OrganizationName IS NULL
           OR @ContactEmail IS NULL
        BEGIN
            SET @Failure = N'A registration must name the application, a proposed tenant code, the organization and a '
                         + N'contact email address, and none of them may be blank or whitespace. @ClientAddress is '
                         + N'required too and was checked first, above. Missing: '
                         + STUFF (CONCAT (CASE WHEN @ApplicationCode    IS NULL THEN N', @ApplicationCode'    END
                                        , CASE WHEN @ProposedTenantCode IS NULL THEN N', @ProposedTenantCode' END
                                        , CASE WHEN @OrganizationName   IS NULL THEN N', @OrganizationName'   END
                                        , CASE WHEN @ContactEmail       IS NULL THEN N', @ContactEmail'       END)
                                , 1, 2, N'')
                         + N'. Nothing has been written.';

            ;THROW 50062, @Failure, 1;
        END

        -- An unrecognised application code is the same class of fault: an argument that names nothing.  Checked against
        -- IsActive as well as IsDeleted, because an application that has been switched off should not be accumulating
        -- registrations for somebody to approve into it later.
        SELECT @ApplicationId = a.ApplicationId
          FROM auth.Application AS a
         WHERE a.ApplicationCode = @ApplicationCode
           AND a.IsActive        = 1
           AND a.IsDeleted       = 0;

        IF @ApplicationId IS NULL
        BEGIN
            SET @Failure = N'@ApplicationCode does not name a live, active application. The web tier supplies this from '
                         + N'its own configuration, so this is a deployment fault rather than something the registrant '
                         + N'did: check config against auth.Application. Nothing has been written.';

            ;THROW 50062, @Failure, 1;
        END

        -- *** One pending registration per proposed code (E-50063) ***
        -- UX_auth_OrganizationRegistration_Pending enforces this, and this check exists so the caller gets a sentence
        -- instead of Msg 2601.  Deliberately NOT keyed on the contact email: one organization may correct its contact,
        -- and two organizations may share an agent.  Deliberately NOT extended to live tenants either -- see the file
        -- header; that collision is the reviewer's to find, as E-50065.
        IF EXISTS (SELECT 1
                     FROM auth.OrganizationRegistration AS orr
                    WHERE orr.ApplicationId      = @ApplicationId
                      AND orr.ProposedTenantCode = @ProposedTenantCode
                      AND orr.Status             = N'Pending'
                      AND orr.IsDeleted          = 0)
        BEGIN
            SET @Failure = N'A registration for this proposed tenant code is already waiting for review in this '
                         + N'application. If that is yours, it has not been forgotten; if it is not, choose another '
                         + N'code. Nothing has been written.';

            ;THROW 50063, @Failure, 1;
        END

        EXEC logs.uspStartExecutionLogging
              @ProcedureName          = @ProcName
            , @KeyParameters          = @KeyParameters
            , @StartDateUtc           = @StartTimeUtc
            , @ReCreatedAfterRollback = 0
            , @ExecutionLogId         = @ExecutionId OUTPUT;

        BEGIN TRANSACTION;

            SET @Now = SYSUTCDATETIME ();

            INSERT auth.OrganizationRegistration
                 ( ApplicationId,   ProposedTenantCode,  OrganizationName,  ContactEmail
                 , ContactName,     ClientAddress,       Status,            SubmittedUtc
                 , auditCreatedBy,  auditModifiedBy)
            VALUES
                 (@ApplicationId,  @ProposedTenantCode, @OrganizationName, @ContactEmail
                 ,@ContactName,    @ClientAddress,      N'Pending',        @Now
                 ,@Actor,          @Actor);

            SET @OrganizationRegistrationId = SCOPE_IDENTITY ();

        IF @@TRANCOUNT > 0
        BEGIN
            COMMIT TRANSACTION;
        END;

        -- *** Conclude the attempt, AFTER the COMMIT (G-24) ***
        -- Outside the transaction on purpose, and the direction that matters is the other one: an attempt must not be
        -- rolled back with the work it describes. ApplicationId is set here because it was not known when the row was
        -- written -- a caller naming an unrecognised application gets an attempt row with a code and no id, which is
        -- exactly the evidence an operator wants.
        UPDATE auth.RegistrationAttempt
           SET Outcome                    = 'Accepted'
             , ConcludedUtc               = SYSUTCDATETIME ()
             , ApplicationId              = @ApplicationId
             , OrganizationRegistrationId = @OrganizationRegistrationId
             , auditModifiedBy            = @Actor
         WHERE RegistrationAttemptId = @AttemptId
           AND Outcome               = 'Received'
           AND IsDeleted             = 0;

        SET @EndTimeUtc = SYSUTCDATETIME ();
        SET @Comments = CONCAT (N'Registration ', CAST (@OrganizationRegistrationId AS NVARCHAR (12))
                              , N' queued for review: application ', CAST (@ApplicationId AS NVARCHAR (12))
                              , N', proposed tenant code ', @ProposedTenantCode
                              , N'. No tenant, user, profile or grant was created. Attempt '
                              , CAST (@AttemptId AS NVARCHAR (20)), N' accepted; ', CAST (@AddressCount AS NVARCHAR (11))
                              , N' arrival(s) from this address in the last ', CAST (@WindowMinutes AS NVARCHAR (11))
                              , N' minute(s) against a threshold of ', CAST (@Threshold AS NVARCHAR (11)), N'.');

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

        -- *** Conclude the attempt with the refusal, AFTER the rollback so the update survives it (G-24) ***
        -- This is for the EVIDENCE and not for the count: the count ignores Outcome, so an attempt left at 'Received'
        -- would still be counted and a project that never concluded a row would still be throttled correctly. Guarded
        -- on 'Received' because auth.trg_au_updt_RegistrationAttempt makes the outcome terminal, and swallowed whole
        -- because the caller must receive the error they actually hit rather than a failure to annotate it -- the same
        -- reasoning as the logging CATCH below.
        IF @AttemptId IS NOT NULL
        BEGIN
            BEGIN TRY
                UPDATE auth.RegistrationAttempt
                   SET Outcome       = CASE WHEN @ErrorNumber = 50068 THEN 'Throttled' ELSE 'Refused' END
                     , FailureReason = CASE @ErrorNumber
                                            WHEN 50068 THEN 'AddressThrottled'
                                            WHEN 50062 THEN 'InvalidArgument'
                                            WHEN 50063 THEN 'DuplicatePending'
                                            -- Anything else is a fault nobody anticipated, and naming its number is
                                            -- more useful than calling it 'Unknown'.
                                            ELSE LEFT (CONCAT ('Error', @ErrorNumber), 40) END
                     , ConcludedUtc  = SYSUTCDATETIME ()
                     , ApplicationId = @ApplicationId
                     , auditModifiedBy = @Actor
                 WHERE RegistrationAttemptId = @AttemptId
                   AND Outcome               = 'Received'
                   AND IsDeleted             = 0;
            END TRY
            BEGIN CATCH
                SET @Failure = NULL;   -- deliberately swallowed; see above
            END CATCH;
        END;

        -- Resurrect the start row only if the rollback took it with everything else, or if the failure happened before
        -- it was ever opened -- which is the common case here, because every validation refusal in this file is raised
        -- before logs.uspStartExecutionLogging is called.  The inner CATCH gives up rather than letting a logging
        -- failure replace the error the caller actually needs to see.
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
    END CATCH

    RETURN 0;
END;
GO

-- *** 3. auth.uspApproveOrganization -- a human decides ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspApproveOrganization
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Concludes a pending registration.  Section 16.4 step 2.  @Approve = 1 creates the organization's tenant beneath the
external-organizations branch and marks the registration 'Approved'; @Approve = 0 marks it 'Rejected' and creates
nothing.  Either way the registration leaves the queue, and the row records who decided and when.

THIS IS THE ONLY PROCEDURE IN THE FILE THAT CREATES AUTHORITY, AND THE ONLY ONE THAT DEMANDS A PERMISSION
--------------------------------------------------------------------------------------------------------
Tenant.Create, at the external-organizations branch.  Not at the root, and not at the new tenant -- the new tenant does
not exist yet, so the authority has to be tested against the place it will hang from.  A reviewer whose Tenant.Create is
scoped to their own agency therefore cannot admit an external organization, which is correct: the branch belongs to
whoever runs the platform.

THE PERMISSION IS DEMANDED HERE EVEN THOUGH auth.uspCreateTenant DEMANDS IT AGAIN.  Two reasons, and neither is
belt-and-braces.  First, 125_auth_tenant_procedures.sql demands INSIDE its own transaction (G-31), so a refusal there
rolls its own logs.AuthorizationDenial row back and the denial is lost; demanding here, before BEGIN TRANSACTION,
survives (BL-042).  Second, the denial row then names auth.uspApproveOrganization, which is what a reviewer looking at a
refused approval needs to see -- "you may not create tenants" is true but does not explain which screen failed.

A REJECTION ALSO NEEDS THE BRANCH TO RESOLVE, WHICH LOOKS LIKE OVER-STRICTNESS AND IS NOT.  Rejecting creates nothing,
so E-50067 could have been skipped on that path.  It is not, because the authority to reject an application to join the
branch is the same authority as the authority to accept one -- if the branch cannot be resolved, we do not know whose
permission to test, and defaulting to "anyone may reject" would let a user with no authority over the branch quietly
empty the queue.  A deployment whose branch is misconfigured has one fault to fix, and both buttons report it.

WHY THE COLLISION CHECK IS HERE AND NOT LEFT TO auth.uspCreateTenant
--------------------------------------------------------------------
auth.uspCreateTenant raises E-50092 for a duplicate code, and that message names a code.  A reviewer reading a queue of
forty registrations needs to know WHICH registration cannot be approved, so E-50065 is raised first with the
registration in the sentence.  The check is a superset of nothing -- it is the same check -- so there is no window in
which this one passes and that one fails; the inner one remains as the constraint's spokesman for every other caller.

WHAT APPROVAL DELIBERATELY DOES NOT WRITE
-----------------------------------------
No auth.TenantDefaultRole rows.  See the file header: defaults are inherited from the branch, not copied per tenant
(BL-052).  No auth.[User] and no auth.UserProfile either -- the organization's people enrol themselves in step 3, and an
approval that also created a first user would have to invent a name for them.

No logs.AuthorizationChange row either, and that one is worth stating plainly because it is the only place in the
authorization surface where a change of consequence is not in that table.  CK_logs_AuthorizationChange_ChangeType is a
closed vocabulary with no member for "organization admitted", and 165_logs_procedures.sql is explicit that
widening it costs an ALTER in three files.  The registration row IS the audit record here -- Status, ReviewedUtc,
ReviewedByProfileId, ReviewNote and TenantId together say who admitted whom, when and to what -- and
IX_auth_OrganizationRegistration_Queue is the index that reads it back.  The tenant's own creation is logged by
auth.uspCreateTenant.  Recorded as a gap: if a future reviewer wants one trail rather than two, the vocabulary gains
'OrganizationApproved' and 'OrganizationRejected' and this procedure writes them.

@ReviewNote IS NOT SHOWN TO THE REGISTRANT.  It is the reviewer's note for the next reviewer.  A rejection with no note
is permitted and is a discourtesy to whoever handles the organization's second attempt.

========================================================================================================================
Example Usage and Performance:

declare @TenantId int;
exec auth.uspApproveOrganization
      @SessionTokenHash           = @Hash
    , @OrganizationRegistrationId = 12
    , @Approve                    = 1
    , @ReviewNote                 = N'Contract 4471 verified with procurement.'
    , @TenantId                   = @TenantId output;

exec auth.uspApproveOrganization @SessionTokenHash = @Hash, @OrganizationRegistrationId = 13, @Approve = 0
                               , @ReviewNote = N'No contract on file; asked to reapply with a reference.';

Approval: the session read, one seek on the registration, one on config.ApplicationSetting, one on the branch tenant,
the permission demand, then auth.uspCreateTenant (which rebuilds that tenant's closure rows) and one update.  Rejection
is the same minus the tenant creation.  Either way this runs once per organization, ever, so it is not a hot path.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-087
Description: Created.

-----------------------------------------------------------------------------------------------------------------------
***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspApproveOrganization
      @SessionTokenHash            VARBINARY (32)
    , @OrganizationRegistrationId  INT
    , @Approve                     BIT
    , @ReviewNote                  NVARCHAR (2000) = NULL
    , @TenantId                    INT             = NULL OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    DECLARE @ProcName          NVARCHAR (400)
          , @ExecutionId       BIGINT
          , @StartTimeUtc      DATETIME2 (7) = SYSUTCDATETIME ()
          , @EndTimeUtc        DATETIME2 (7)
          , @KeyParameters     NVARCHAR (MAX)
          , @Comments          NVARCHAR (MAX)
          , @ContextMessage    NVARCHAR (MAX)
          , @DynamicSql        NVARCHAR (MAX) = NULL
          , @ErrorMsg          NVARCHAR (2048)
          , @ErrorProc         NVARCHAR (256)
          , @ErrorNumber       INT
          , @ErrorLine         INT
          , @Failure           NVARCHAR (2048)
          , @Actor             NVARCHAR (255)
          , @ActorProfileId    INT
          , @ApplicationId     INT
          , @Status            NVARCHAR (20)
          , @ProposedCode      NVARCHAR (50)
          , @OrganizationName  NVARCHAR (200)
          , @BranchCode        NVARCHAR (50)
          , @BranchTenantId    INT
          , @Now               DATETIME2 (7);

    SET @ProcName = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID)) + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                            , N'[auth].[uspApproveOrganization]');

    SET @KeyParameters = CONCAT (N'OrganizationRegistrationId=', CAST (@OrganizationRegistrationId AS NVARCHAR (12))
                               , N'; Approve=', CAST (COALESCE (@Approve, 0) AS NVARCHAR (1))
                               , N'; ReviewNoteSupplied=', CASE WHEN @ReviewNote IS NULL THEN N'0' ELSE N'1' END
                               , N'; SessionTokenHash=(32 bytes, not logged)');
    SET @ContextMessage = N'Concludes one registration. Approval creates the organization tenant under the '
                        + N'external-organizations branch and writes no auth.TenantDefaultRole rows (BL-052).';

    BEGIN TRY
        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        SET @ActorProfileId = TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT);
        SET @ApplicationId  = TRY_CAST (SESSION_CONTEXT (N'ApplicationId') AS INT);
        SET @Actor          = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                      , ORIGINAL_LOGIN ());
        SET @ReviewNote     = NULLIF (LTRIM (RTRIM (COALESCE (@ReviewNote, N''))), N'');
        SET @Approve        = COALESCE (@Approve, 0);
        SET @TenantId       = NULL;

        -- *** Find the registration (E-50064) ***
        -- SCOPED TO THE SESSION'S APPLICATION.  A reviewer signed in to one application must not be able to conclude
        -- another application's registration, and the honest answer to "may I see registration 12" from an application
        -- it does not belong to is the same as the answer for an id that was never issued: no such registration.  That
        -- also means the id cannot be used to count another application's queue.
        SELECT @Status           = orr.Status
             , @ProposedCode     = orr.ProposedTenantCode
             , @OrganizationName = orr.OrganizationName
          FROM auth.OrganizationRegistration AS orr
         WHERE orr.OrganizationRegistrationId = @OrganizationRegistrationId
           AND orr.ApplicationId              = @ApplicationId
           AND orr.IsDeleted                  = 0;

        IF @Status IS NULL
        BEGIN
            SET @Failure = N'No registration with that id is awaiting review in this application. It may never have '
                         + N'existed, it may have been deleted, or it may belong to a different application than the '
                         + N'one this session is signed in to. Nothing has been changed.';

            ;THROW 50064, @Failure, 1;
        END

        -- *** It must still be pending (E-50060) ***
        IF @Status <> N'Pending'
        BEGIN
            SET @Failure = CONCAT (N'Registration ', CAST (@OrganizationRegistrationId AS NVARCHAR (12))
                                 , N' has already been processed: its status is ', @Status
                                 , N'. A conclusion is final -- an organization that needs to be re-admitted registers '
                                 + N'again, so that the second decision has its own row and its own reviewer. Nothing '
                                 + N'has been changed.');

            ;THROW 50060, @Failure, 1;
        END

        -- *** Resolve the external-organizations branch (E-50067) ***
        -- Read inline, the way every setting in this database is read: there is no helper, and TRY_CAST + COALESCE keeps
        -- a missing or mistyped row from becoming a NULL that silently matches nothing.
        SET @BranchCode = NULLIF (LTRIM (RTRIM (COALESCE (
                              (SELECT s.SettingValue
                                 FROM config.ApplicationSetting AS s
                                WHERE s.SettingKey = N'Registration.ExternalBranchTenantCode'
                                  AND s.IsDeleted  = 0)
                            , N''))), N'');

        IF @BranchCode IS NOT NULL
            SELECT @BranchTenantId = t.TenantId
              FROM auth.Tenant AS t
             WHERE t.TenantCode    = @BranchCode
               AND t.ApplicationId = @ApplicationId
               AND t.IsActive      = 1
               AND t.IsDeleted     = 0;

        IF @BranchTenantId IS NULL
        BEGIN
            SET @Failure = CONCAT (N'The external-organizations branch cannot be resolved for this application. '
                                 , N'config.ApplicationSetting key Registration.ExternalBranchTenantCode is '
                                 , COALESCE (N'''' + @BranchCode + N'''', N'missing or blank')
                                 , N', and no live, active tenant in application '
                                 , CAST (@ApplicationId AS NVARCHAR (12))
                                 , N' has that code. This is a configuration fault, not something the registrant or the '
                                 + N'reviewer did: run 115_seed_reference_data.sql, or correct the setting to name the '
                                 + N'branch this application actually uses. Nothing has been changed.');

            ;THROW 50067, @Failure, 1;
        END

        -- *** Authority, before the transaction opens so the denial survives a refusal (BL-042) ***
        EXEC auth.uspDemandPermission
              @PermissionCode = N'Tenant.Create'
            , @TenantId       = @BranchTenantId
            , @ObjectName     = N'auth.uspApproveOrganization';

        -- *** The proposed code must still be free (E-50065) ***
        -- Only on the approving path: a rejection creates no tenant, and refusing to reject a registration because its
        -- code collides would leave it stuck in the queue forever.
        IF @Approve = 1
           AND EXISTS (SELECT 1
                         FROM auth.Tenant AS t
                        WHERE t.TenantCode    = @ProposedCode
                          AND t.ApplicationId = @ApplicationId
                          AND t.IsDeleted     = 0)
        BEGIN
            SET @Failure = CONCAT (N'Registration ', CAST (@OrganizationRegistrationId AS NVARCHAR (12))
                                 , N' (', @OrganizationName, N') proposes tenant code ', @ProposedCode
                                 , N', which is already in use in this application. Approving it would collide with an '
                                 + N'existing tenant. Reject the registration and ask the organization to propose '
                                 + N'another code -- the code cannot be edited here, because the reviewer choosing it '
                                 + N'would be admitting an organization under a name it never asked for. Nothing has '
                                 + N'been changed.');

            ;THROW 50065, @Failure, 1;
        END

        EXEC logs.uspStartExecutionLogging
              @ProcedureName          = @ProcName
            , @KeyParameters          = @KeyParameters
            , @StartDateUtc           = @StartTimeUtc
            , @ReCreatedAfterRollback = 0
            , @ExecutionLogId         = @ExecutionId OUTPUT;

        BEGIN TRANSACTION;

            IF @Approve = 1
            BEGIN
                -- auth.uspCreateTenant opens its own transaction; nesting merely increments @@TRANCOUNT, and the
                -- precedent is auth.uspRebuildProfilePermissionScope called from inside a grant.  It takes the tenant
                -- type by code, and 'ExternalOrganization' is the one auth.TenantType exists to carry for this path.
                EXEC auth.uspCreateTenant
                      @SessionTokenHash = @SessionTokenHash
                    , @ParentTenantId   = @BranchTenantId
                    , @TenantCode       = @ProposedCode
                    , @TenantName       = @OrganizationName
                    , @TenantTypeCode   = N'ExternalOrganization'
                    , @NewTenantId      = @TenantId OUTPUT;
            END

            SET @Now = SYSUTCDATETIME ();

            -- ONE UPDATE FOR BOTH OUTCOMES.  CK_auth_OrganizationRegistration_Concluded requires TenantId NOT NULL for
            -- 'Approved' and NULL for 'Rejected', and @TenantId is exactly that by construction: set by the branch above
            -- on the approving path, left NULL on the other.  auditModifiedDateUtc is not set -- trg_au_updt stamps it.
            UPDATE orr
               SET Status               = CASE WHEN @Approve = 1 THEN N'Approved' ELSE N'Rejected' END
                 , ReviewedUtc          = @Now
                 , ReviewedByProfileId  = @ActorProfileId
                 , ReviewNote           = @ReviewNote
                 , TenantId             = @TenantId
                 , auditModifiedBy      = @Actor
              FROM auth.OrganizationRegistration AS orr
             WHERE orr.OrganizationRegistrationId = @OrganizationRegistrationId
               AND orr.IsDeleted                  = 0;

        IF @@TRANCOUNT > 0
        BEGIN
            COMMIT TRANSACTION;
        END;

        SET @EndTimeUtc = SYSUTCDATETIME ();
        SET @Comments = CONCAT (N'Registration ', CAST (@OrganizationRegistrationId AS NVARCHAR (12))
                              , CASE WHEN @Approve = 1
                                     THEN CONCAT (N' approved: tenant ', CAST (@TenantId AS NVARCHAR (12))
                                                , N' created under branch ', CAST (@BranchTenantId AS NVARCHAR (12))
                                                , N' with no TenantDefaultRole rows of its own (inherited).')
                                     ELSE N' rejected: nothing was created.' END
                              , N' Reviewer profile ', COALESCE (CAST (@ActorProfileId AS NVARCHAR (12)), N'(none)')
                              , N'.');

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

        -- Resurrect the start row only if the rollback took it with everything else, or if the failure happened before
        -- it was ever opened -- which is the common case here, because every validation refusal in this file is raised
        -- before logs.uspStartExecutionLogging is called.  The inner CATCH gives up rather than letting a logging
        -- failure replace the error the caller actually needs to see.
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
    END CATCH

    RETURN 0;
END;
GO

-- *** 4. auth.uspRegisterExternalUser -- the organization's people enrol themselves ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspRegisterExternalUser
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Enrols one person into an already-approved organization.  Section 16.4 step 3.  Creates the auth.[User] row, one
auth.UserProfile at the organization's tenant, grants that tenant's default roles and rebuilds the profile's scope.
Unauthenticated: its authority is the approved registration row, not a permission.  Every call, including every refused
one, is recorded and counted by auth.uspRecordRegistrationAttempt, and an address over Registration.ThrottleThreshold is
refused as E-50068 (G-24).

ITS AUTHORITY IS A ROW SOMEBODY ELSE WROTE
------------------------------------------
@OrganizationRegistrationId must name a registration whose Status is 'Approved' and whose TenantId still points at a
live, active tenant.  That row was written by auth.uspApproveOrganization, under Tenant.Create, by a named reviewer at a
recorded time.  So the decision "people from this organization may enrol" was made by an authenticated human in advance,
and this procedure only carries it out.  E-50061 is what refusal looks like when that row does not say yes.

THE ID IS NOT A SECRET AND IS NOT TREATED AS ONE.  It is a small integer, so anyone can guess another organization's.
That is survivable because guessing it buys nothing an attacker wants: the enrolment it produces has no credential, so
nobody can sign in with it, and it grants only the branch's default roles -- which section 11.5 and the seed set to
READ_ONLY-class permissions over the organization's own tenant, and row-level security confines to that tenant's rows.
The real protection against mass enrolment into a stranger's organization is the same as in step 1: G-24's per-address
count makes one address pay for a burst, G-06's gateway and CAPTCHA are what make a distributed one expensive, and the
evidence of every attempt is here either way.  What the id must NOT be is a way to enrol into a tenant that was never approved,
and that is what the Status and tenant-usability tests are for.

NO CREDENTIAL IS WRITTEN, AND THAT IS WHAT MAKES THE ACCOUNT SAFE UNTIL SOMEBODY INVITES IT
------------------------------------------------------------------------------------------
This procedure writes no auth.UserCredential row, so the account it creates cannot be signed in to by anybody, including
the person who registered it.  Storing a verifier is a separate, deliberate act -- the invitation or the
set-your-own-password flow of section 12 -- and keeping it out of here means a flood of self-registrations produces a pile
of inert rows rather than a pile of accounts.  A reviewer who decides the enrolment was a mistake deletes the profile
before the credential ever exists.

WHY THE USER NAME COLLISION IS REPORTED AND THE TENANT CODE COLLISION IN STEP 1 IS NOT
-------------------------------------------------------------------------------------
E-50066 says "that name is in use", which is an enumeration signal, and Appendix B accepts it because the caller is
choosing their OWN name on a self-service path: they could learn the same thing by trying to sign in, and a registration
form that cannot say "pick another" is a registration form nobody can complete.  UX_auth_User_UserName is global, not
per-application, so the collision can be with a user of an entirely different application -- unhelpful, and still the
truth the caller needs.  The signal is not free, though, and G-24 is why: E-50066 concludes an auth.RegistrationAttempt
row like every other outcome, so enumerating names through this door spends the enumerator's per-address allowance at one
name per call.

WHAT THIS PROCEDURE DELEGATES, AND WHY IT MUST
----------------------------------------------
It cannot call auth.uspCreateUser or auth.uspCreateProfile: both demand a permission and there is no session, so they
would refuse.  It therefore inserts into auth.[User] and auth.UserProfile directly -- a duplication of two INSERTs, which
is tolerable -- but it does NOT re-implement the default-role rule.  That rule is INV-04 ("a role may only be granted
where its owning tenant covers the scope"), it is security-bearing, and two copies of a security rule drift; the copy
that drifts is the one nobody is testing.  So auth.uspGrantTenantDefaultRoles was extracted from auth.uspCreateProfile
for this caller (BL-056) and both paths now grant through it.

The scope rebuild is called ONCE, after the grant, because auth.uspGrantTenantDefaultRoles deliberately does not rebuild
-- a caller that granted three roles should pay for one rebuild, not three.

@ClientAddress IS REQUIRED HERE FOR THE SAME REASON AS IN STEP 1, AND THE COUNT IS THE SAME COUNT
-----------------------------------------------------------------------------------------------
A blank or missing address is refused as E-50062 before anything is recorded, and the per-address total this procedure is
measured against is SHARED with auth.uspRegisterOrganization: one allowance covers both public doors, because a throttle
on one beside an untouched one is a throttle nobody pays.  An address that has just spent its allowance queueing
registrations cannot then spend it again enrolling users.

The arrival is recorded before the registration is even looked up, so E-50064 ("no such registration") costs the caller a
slot -- which is the point, because probing ids is exactly the traffic that error represents.  The attempt row names the
registration when the id resolves to a real row and leaves it NULL when it does not; the recorder makes that decision, so
that a probe for a registration that never existed cannot be refused by a foreign key instead of being recorded.

ProfileName IS THE TENANT'S NAME, NOT THE PERSON'S
--------------------------------------------------
UX_auth_UserProfile_UserTenantName is unique on (UserId, TenantId, ProfileName), and a profile name answers "which hat am
I wearing", which for an external user is the organization they belong to.  Using the person's display name would read
oddly on the profile switcher ("A. Coyote" as a hat worn by A. Coyote) and would collide with nothing useful.  The
profile is also IsDefault = 1: it is the person's only one, UX_auth_UserProfile_Default permits exactly one per user, and
a user whose sole profile is not the default has nowhere to be sent at sign-in.

========================================================================================================================
Example Usage and Performance:

declare @UserId int, @ProfileId int;
exec auth.uspRegisterExternalUser
      @OrganizationRegistrationId = 12
    , @UserName                   = N'wcoyote'
    , @DisplayName                = N'Wile E. Coyote'
    , @Email                      = N'wcoyote@acme.example'
    , @ClientAddress              = N'203.0.113.45'   -- required since G-24
    , @UserAgent                  = N'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
    , @NewUserId                  = @UserId    output
    , @NewUserProfileId           = @ProfileId output;

One call of auth.uspRecordRegistrationAttempt, two seeks to validate, two inserts, then the default-role grant and one
scope rebuild for one profile -- the rebuild is the dominant cost and is bounded by the branch's default role set, which
is three roles in the shipped seed.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-087
Description: Created.

Date:		2026-09-21
Author:		rsincero
Ticket:		G-24
Description:
Per-address throttle, on the same count as step 1: records every arrival through auth.uspRecordRegistrationAttempt,
refuses a crossed threshold as E-50068, and makes @ClientAddress mandatory.  @UserAgent added, recorded and never parsed.

-----------------------------------------------------------------------------------------------------------------------
***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspRegisterExternalUser
      @OrganizationRegistrationId  INT
    , @UserName                    NVARCHAR (256)
    , @DisplayName                 NVARCHAR (256)
    , @Email                       NVARCHAR (320)
    -- NOT optional, and G-24 is why -- see the header and step 1's.
    , @ClientAddress               NVARCHAR (45)  = NULL
    , @UserAgent                   NVARCHAR (512) = NULL
    , @NewUserId                   INT            = NULL OUTPUT
    , @NewUserProfileId            INT            = NULL OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    DECLARE @ProcName          NVARCHAR (400)
          , @ExecutionId       BIGINT
          , @StartTimeUtc      DATETIME2 (7) = SYSUTCDATETIME ()
          , @EndTimeUtc        DATETIME2 (7)
          , @KeyParameters     NVARCHAR (MAX)
          , @Comments          NVARCHAR (MAX)
          , @ContextMessage    NVARCHAR (MAX)
          , @DynamicSql        NVARCHAR (MAX) = NULL
          , @ErrorMsg          NVARCHAR (2048)
          , @ErrorProc         NVARCHAR (256)
          , @ErrorNumber       INT
          , @ErrorLine         INT
          , @Failure           NVARCHAR (2048)
          , @Actor             NVARCHAR (255)
          , @Status            NVARCHAR (20)
          , @TenantId          INT
          , @TenantName        NVARCHAR (200)
          , @ApplicationId     INT
          , @DefaultSourceId   INT
          , @CandidateRoles    INT
          , @GrantedRoles      INT
          , @ChangeId          BIGINT
          , @DetailJson        NVARCHAR (MAX)
          -- G-24.  NULL until the arrival is recorded; the CATCH tests it, because the missing-address refusal has no
          -- row to conclude.
          , @AttemptId         BIGINT = NULL
          , @AddressCount      INT    = NULL
          , @Throttled         BIT    = 0
          , @Threshold         INT    = NULL
          , @WindowMinutes     INT    = NULL;

    SET @ProcName = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID)) + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                            , N'[auth].[uspRegisterExternalUser]');

    -- No session, so ORIGINAL_LOGIN () is the attribution -- the application acting as itself.  See section 2.
    SET @Actor = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N''), ORIGINAL_LOGIN ());

    SET @KeyParameters = CONCAT (N'OrganizationRegistrationId=', CAST (@OrganizationRegistrationId AS NVARCHAR (12))
                               , N'; UserName=', COALESCE (@UserName, N'(null)')
                               , N'; EmailLength=', CAST (LEN (COALESCE (@Email, N'')) AS NVARCHAR (10))
                               -- The address itself, not merely whether one arrived: with G-24 in place it is the
                               -- identifier an investigation starts from, and it is not a credential.
                               , N'; ClientAddress=', COALESCE (@ClientAddress, N'(null)'));
    SET @ContextMessage = N'Unauthenticated entry point. Authority is an Approved auth.OrganizationRegistration row. '
                        + N'Writes no credential, so the account cannot be signed in to until one is stored. Throttled '
                        + N'per address over auth.RegistrationAttempt, on the same count as auth.uspRegisterOrganization '
                        + N'(G-24, E-50068).';

    BEGIN TRY
        -- *** Validate every argument before anything is written (E-50062) ***
        SET @UserName    = NULLIF (LTRIM (RTRIM (COALESCE (@UserName,    N''))), N'');
        SET @DisplayName = NULLIF (LTRIM (RTRIM (COALESCE (@DisplayName, N''))), N'');
        SET @Email       = NULLIF (LTRIM (RTRIM (COALESCE (@Email,       N''))), N'');
        SET @ClientAddress = NULLIF (LTRIM (RTRIM (COALESCE (@ClientAddress, N''))), N'');
        SET @UserAgent     = NULLIF (LTRIM (RTRIM (COALESCE (@UserAgent,     N''))), N'');

        -- *** The address first and on its own, because without it there is no throttle (E-50062, G-24) ***
        IF @ClientAddress IS NULL
        BEGIN
            SET @Failure = N'@ClientAddress is required and may not be blank or whitespace. It stopped being optional '
                         + N'when this endpoint became throttled per address (gap G-24, E-50068), on the same count as '
                         + N'auth.uspRegisterOrganization. The web tier reads the address from the connection rather '
                         + N'than from the form, so this is a deployment fault and not something the registrant did. '
                         + N'Nothing has been written and nothing has been recorded.';

            ;THROW 50062, @Failure, 1;
        END

        -- *** Record the arrival BEFORE validating anything else, and BEFORE any transaction (G-24) ***
        -- @OrganizationRegistrationId is passed so that a real enrolment attempt names its registration from the start
        -- and IX_auth_RegistrationAttempt_Registration answers "who has been knocking at this organization" for
        -- refusals too. The recorder drops an id that resolves to nothing, so probing for registrations that do not
        -- exist is recorded rather than refused by a foreign key.
        EXEC auth.uspRecordRegistrationAttempt
              @AttemptKind                = 'ExternalUser'
            , @ClientAddress              = @ClientAddress
            , @UserAgent                  = @UserAgent
            , @OrganizationRegistrationId = @OrganizationRegistrationId
            , @RegistrationAttemptId      = @AttemptId     OUTPUT
            , @AddressAttemptCount        = @AddressCount  OUTPUT
            , @AddressThrottled           = @Throttled     OUTPUT
            , @Threshold                  = @Threshold     OUTPUT
            , @WindowMinutes              = @WindowMinutes OUTPUT;

        -- *** And refuse a crossed threshold (E-50068) ***
        -- No numbers in the message; they are in @Comments and logs.ExecutionLog. UI-26.
        IF @Throttled = 1
        BEGIN
            SET @Failure = N'Too many registration requests have arrived from this address recently, so this enrolment '
                         + N'has not been accepted. The limit is per address, it is shared with the organization '
                         + N'registration form, and it lapses on its own: wait and try again, or ask the organization '
                         + N'to enrol you directly. Nothing has been written. Operators: the count, the threshold and '
                         + N'the window are in logs.ExecutionLog, and the settings are Registration.ThrottleThreshold '
                         + N'and Registration.ThrottleWindowMinutes.';

            ;THROW 50068, @Failure, 1;
        END

        IF @OrganizationRegistrationId IS NULL
           OR @UserName IS NULL
           OR @DisplayName IS NULL
           OR @Email IS NULL
        BEGIN
            SET @Failure = N'An enrolment must name the approved registration it belongs to, a user name, a display '
                         + N'name and an email address, and none of them may be blank or whitespace. @ClientAddress is '
                         + N'required too and was checked first, above. Missing: '
                         + STUFF (CONCAT (CASE WHEN @OrganizationRegistrationId IS NULL
                                               THEN N', @OrganizationRegistrationId' END
                                        , CASE WHEN @UserName    IS NULL THEN N', @UserName'    END
                                        , CASE WHEN @DisplayName IS NULL THEN N', @DisplayName' END
                                        , CASE WHEN @Email       IS NULL THEN N', @Email'       END)
                                , 1, 2, N'')
                         + N'. Nothing has been written.';

            ;THROW 50062, @Failure, 1;
        END

        -- CK_auth_User_Email is the gatekeeper for shape and it accepts almost anything with an @ in the middle.  It is
        -- checked here as well so the caller gets a sentence rather than Msg 547 from a constraint they cannot see.
        IF LEN (@Email) < 3
           OR @Email NOT LIKE N'%_@_%'
        BEGIN
            SET @Failure = N'@Email is not shaped like an address. CK_auth_User_Email requires at least one character '
                         + N'either side of an @, which is as much as a database can usefully assert -- whether the '
                         + N'address exists is settled by sending to it, not by a constraint. Nothing has been written.';

            ;THROW 50062, @Failure, 1;
        END

        -- *** Find the registration (E-50064) ***
        SELECT @Status   = orr.Status
             , @TenantId = orr.TenantId
          FROM auth.OrganizationRegistration AS orr
         WHERE orr.OrganizationRegistrationId = @OrganizationRegistrationId
           AND orr.IsDeleted                  = 0;

        IF @Status IS NULL
        BEGIN
            SET @Failure = N'No registration with that id exists, or it has been deleted. An enrolment link that no '
                         + N'longer resolves usually means the organization was removed after the link was sent; ask '
                         + N'the organization to register again. Nothing has been written.';

            ;THROW 50064, @Failure, 1;
        END

        -- *** It must be approved, and its tenant must still be usable (E-50061) ***
        -- The tenant is re-checked rather than trusted, because approval may have been months ago and a tenant can be
        -- deactivated or soft-deleted since.  An enrolment into a deactivated tenant would produce a profile whose
        -- every read returns nothing, which looks like a broken account rather than a closed organization.
        IF @Status <> N'Approved'
            SET @TenantName = NULL;
        ELSE
            SELECT @TenantName    = t.TenantName
                 , @ApplicationId = t.ApplicationId
              FROM auth.Tenant AS t
             WHERE t.TenantId  = @TenantId
               AND t.IsActive  = 1
               AND t.IsDeleted = 0;

        IF @TenantName IS NULL
        BEGIN
            SET @Failure = CONCAT (N'Registration ', CAST (@OrganizationRegistrationId AS NVARCHAR (12))
                                 , N' is not open for enrolment: its status is ', @Status
                                 , CASE WHEN @Status = N'Approved'
                                        THEN N' but the tenant it names is inactive or has been deleted'
                                        ELSE N', so no tenant exists to enrol into' END
                                 , N'. Nothing has been written.');

            ;THROW 50061, @Failure, 1;
        END

        -- *** The user name must be free (E-50066) ***
        IF EXISTS (SELECT 1
                     FROM auth.[User] AS u
                    WHERE u.UserName  = @UserName
                      AND u.IsDeleted = 0)
        BEGIN
            SET @Failure = N'That user name is already in use. User names are unique across the whole deployment, not '
                         + N'per organization, so the holder may belong to another one. Choose another. Nothing has '
                         + N'been written.';

            ;THROW 50066, @Failure, 1;
        END

        EXEC logs.uspStartExecutionLogging
              @ProcedureName          = @ProcName
            , @KeyParameters          = @KeyParameters
            , @StartDateUtc           = @StartTimeUtc
            , @ReCreatedAfterRollback = 0
            , @ExecutionLogId         = @ExecutionId OUTPUT;

        BEGIN TRANSACTION;

            INSERT auth.[User]
                 ( UserName,  DisplayName,  Email,  IsActive, IsPlatformAdmin, auditCreatedBy, auditModifiedBy)
            VALUES
                 (@UserName, @DisplayName, @Email,  1,        0,               @Actor,         @Actor);

            SET @NewUserId = SCOPE_IDENTITY ();

            INSERT auth.UserProfile
                 ( UserId,     TenantId,  ProfileName, IsDefault, IsActive, auditCreatedBy, auditModifiedBy)
            VALUES
                 (@NewUserId, @TenantId, @TenantName,  1,         1,        @Actor,         @Actor);

            SET @NewUserProfileId = SCOPE_IDENTITY ();

            -- The default-role rule lives in one place for both the authenticated and the self-service path.  The actor
            -- parameters are NULL because there is no acting profile: the same situation 900_bootstrap_first_admin.sql
            -- is in, and the trail records it as a self-registration rather than inventing an actor.
            EXEC auth.uspGrantTenantDefaultRoles
                  @UserProfileId          = @NewUserProfileId
                , @TenantId               = @TenantId
                , @ApplicationId          = @ApplicationId
                , @TargetUserId           = @NewUserId
                , @ActorUserProfileId     = NULL
                , @ActorAuthorityTenantId = NULL
                , @Actor                  = @Actor
                , @DefaultSourceTenantId  = @DefaultSourceId OUTPUT
                , @CandidateRoleCount     = @CandidateRoles  OUTPUT
                , @GrantedRoleCount       = @GrantedRoles    OUTPUT;

            -- Once, after the grant, not once per role.
            EXEC auth.uspRebuildProfilePermissionScope @UserProfileId = @NewUserProfileId;

            SET @DetailJson = CONCAT (N'{"selfRegistration":true,"organizationRegistrationId":'
                                    , CAST (@OrganizationRegistrationId AS NVARCHAR (12))
                                    , N',"grantedRoleCount":', CAST (@GrantedRoles AS NVARCHAR (12))
                                    , N',"clientAddress":'
                                    , COALESCE (N'"' + STRING_ESCAPE (@ClientAddress, 'json') + N'"', N'null')
                                    , N'}');

            EXEC logs.uspRecordAuthorizationChange
                  @ChangeType             = 'ProfileCreated'
                , @TargetUserId           = @NewUserId
                , @TargetUserProfileId    = @NewUserProfileId
                , @RoleId                 = NULL
                , @ScopeTenantId          = @TenantId
                , @ActorUserProfileId     = NULL
                , @ActorAuthorityTenantId = NULL
                , @DetailJson             = @DetailJson
                , @AuthorizationChangeId  = @ChangeId OUTPUT;

        IF @@TRANCOUNT > 0
        BEGIN
            COMMIT TRANSACTION;
        END;

        -- *** Conclude the attempt, AFTER the COMMIT (G-24) ***
        -- Outside the transaction on purpose: an attempt must not be rolled back with the work it describes.
        UPDATE auth.RegistrationAttempt
           SET Outcome                    = 'Accepted'
             , ConcludedUtc               = SYSUTCDATETIME ()
             , ApplicationId              = @ApplicationId
             , OrganizationRegistrationId = @OrganizationRegistrationId
             , auditModifiedBy            = @Actor
         WHERE RegistrationAttemptId = @AttemptId
           AND Outcome               = 'Received'
           AND IsDeleted             = 0;

        SET @EndTimeUtc = SYSUTCDATETIME ();
        SET @Comments = CONCAT (N'Enrolled user ', CAST (@NewUserId AS NVARCHAR (12))
                              , N' as profile ', CAST (@NewUserProfileId AS NVARCHAR (12))
                              , N' at tenant ', CAST (@TenantId AS NVARCHAR (12))
                              , N' from registration ', CAST (@OrganizationRegistrationId AS NVARCHAR (12))
                              , N'. Default roles: ', CAST (@GrantedRoles AS NVARCHAR (12))
                              , N' of ', CAST (@CandidateRoles AS NVARCHAR (12))
                              , N' candidates, inherited from tenant '
                              , COALESCE (CAST (@DefaultSourceId AS NVARCHAR (12)), N'(none)')
                              , N'. No credential was written, so the account cannot yet sign in. Attempt '
                              , CAST (@AttemptId AS NVARCHAR (20)), N' accepted; ', CAST (@AddressCount AS NVARCHAR (11))
                              , N' arrival(s) from this address in the last ', CAST (@WindowMinutes AS NVARCHAR (11))
                              , N' minute(s) against a threshold of ', CAST (@Threshold AS NVARCHAR (11)), N'.');

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

        -- *** Conclude the attempt with the refusal, AFTER the rollback so the update survives it (G-24) ***
        -- Evidence, not count: the count ignores Outcome entirely. Guarded on 'Received' because
        -- auth.trg_au_updt_RegistrationAttempt makes the outcome terminal, and swallowed whole because the caller must
        -- receive the error they actually hit rather than a failure to annotate it.
        IF @AttemptId IS NOT NULL
        BEGIN
            BEGIN TRY
                UPDATE auth.RegistrationAttempt
                   SET Outcome       = CASE WHEN @ErrorNumber = 50068 THEN 'Throttled' ELSE 'Refused' END
                     , FailureReason = CASE @ErrorNumber
                                            WHEN 50068 THEN 'AddressThrottled'
                                            WHEN 50062 THEN 'InvalidArgument'
                                            WHEN 50064 THEN 'NoSuchRegistration'
                                            WHEN 50061 THEN 'NotOpenForEnrolment'
                                            WHEN 50066 THEN 'UserNameInUse'
                                            ELSE LEFT (CONCAT ('Error', @ErrorNumber), 40) END
                     , ConcludedUtc  = SYSUTCDATETIME ()
                     , ApplicationId = @ApplicationId
                     , auditModifiedBy = @Actor
                 WHERE RegistrationAttemptId = @AttemptId
                   AND Outcome               = 'Received'
                   AND IsDeleted             = 0;
            END TRY
            BEGIN CATCH
                SET @Failure = NULL;   -- deliberately swallowed; see above
            END CATCH;
        END;

        -- Resurrect the start row only if the rollback took it with everything else, or if the failure happened before
        -- it was ever opened -- which is the common case here, because every validation refusal in this file is raised
        -- before logs.uspStartExecutionLogging is called.  The inner CATCH gives up rather than letting a logging
        -- failure replace the error the caller actually needs to see.
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
    END CATCH

    RETURN 0;
END;
GO

-- *** 5. Descriptions ***
-- Extended properties, through the re-runnable helper.  sp_addextendedproperty fails on the second run and
-- sp_updateextendedproperty fails on the first, so neither is usable in a file that has to be idempotent.
IF OBJECT_ID (N'util.uspSetObjectDescription', N'P') IS NOT NULL
BEGIN
    DECLARE @Descriptions TABLE
    (
        RowNo       INT IDENTITY (1, 1) PRIMARY KEY,
        ObjectName  SYSNAME         NOT NULL,
        Description NVARCHAR (MAX)  NOT NULL
    );

    INSERT @Descriptions (ObjectName, Description)
    VALUES
        (N'uspRecordRegistrationAttempt'
       , N'Gap G-24. Records ONE auth.RegistrationAttempt row for a call of a public registration entry point -- '
       + N'whatever that call''s outcome -- and reports the per-address count over Registration.ThrottleWindowMinutes '
       + N'against Registration.ThrottleThreshold. It COUNTS and never REFUSES: the refusal is E-50068 and belongs to '
       + N'the caller, because a recorder that threw would leave its caller with no id to conclude and every throttled '
       + N'attempt stuck at Outcome = Received for ever. Three deliberate properties: the count is on ARRIVALS and '
       + N'ignores Outcome (a thousand valid registrations from one address is the flood, not the good case); it is '
       + N'taken over a second table and NOT over auth.OrganizationRegistration, because a submission refused by '
       + N'E-50062 or E-50063 writes no queue row and would be invisible; and the row is written BEFORE the caller '
       + N'validates anything, so an unanticipated error does not buy a free call. The count INCLUDES the row just '
       + N'written, so a threshold of 10 admits ten and refuses the eleventh. Threshold 0 disables the refusal and '
       + N'keeps the record. Opens its own transaction and MUST NOT be called from inside one: a nested BEGIN '
       + N'TRANSACTION does not commit, so the arrival would vanish with the caller''s rollback -- which is the hole '
       + N'this exists to close. Raises only E-50062, for a blank @ClientAddress or an @AttemptKind outside '
       + N'Organization | ExternalUser.')
      , (N'uspRegisterOrganization'
       , N'Section 16.4 step 1. UNAUTHENTICATED: an external organization asks to join. Writes one '
       + N'auth.OrganizationRegistration row with Status = Pending and nothing else -- no tenant, no user, no profile, '
       + N'no grant -- which is why it needs no permission. Validates every argument first (E-50062, widened from '
       + N'Appendix B''s three arguments to include @ApplicationCode) and refuses a second pending registration for the '
       + N'same proposed tenant code (E-50063). Upper-cases and trims @ProposedTenantCode so the uniqueness '
       + N'UX_auth_OrganizationRegistration_Pending enforces is the uniqueness a reviewer sees. Deliberately does NOT '
       + N'report a collision with an existing live tenant: that would make it a tenant enumerator, so the collision is '
       + N'the reviewer''s to find as E-50065. THROTTLED PER ADDRESS (G-24): every call, including every refused one, '
       + N'is recorded by auth.uspRecordRegistrationAttempt before anything else is validated and before any '
       + N'transaction is opened, and an address over Registration.ThrottleThreshold is refused as E-50068. '
       + N'@ClientAddress is therefore MANDATORY -- an optional identifier on a throttled endpoint is the bypass -- and '
       + N'a missing one is the only refusal that records no attempt, because there is nothing to attribute it to. What '
       + N'the database cannot do is make a DISTRIBUTED flood expensive: gateway rate limiting and a CAPTCHA on the '
       + N'public form are G-06, which stays open.')
      , (N'uspApproveOrganization'
       , N'Section 16.4 step 2. The human gate, and the only procedure in 155 that creates authority. Demands '
       + N'Tenant.Create at the external-organizations branch -- not at the root and not at the new tenant, which does '
       + N'not exist yet -- BEFORE opening a transaction, so a refusal''s logs.AuthorizationDenial row survives '
       + N'(BL-042) and names this procedure rather than auth.uspCreateTenant. @Approve = 1 creates the tenant under '
       + N'the branch via auth.uspCreateTenant and sets Status = Approved; @Approve = 0 sets Status = Rejected and '
       + N'creates nothing. Raises E-50064 (no such registration in this application), E-50060 (already processed), '
       + N'E-50067 (the branch named by config.ApplicationSetting key Registration.ExternalBranchTenantCode does not '
       + N'resolve -- a configuration fault) and E-50065 (proposed code already a live tenant). Writes NO '
       + N'auth.TenantDefaultRole rows: defaults are inherited from the branch, not copied per tenant (BL-052). Writes '
       + N'no logs.AuthorizationChange row either, because the closed ChangeType vocabulary has no member '
       + N'for it and the registration row is itself the audit record.')
      , (N'uspRegisterExternalUser'
       , N'Section 16.4 step 3. UNAUTHENTICATED: one person enrols into an already-approved organization. Its authority '
       + N'is the Approved auth.OrganizationRegistration row a named reviewer wrote, re-checked here along with the '
       + N'tenant''s usability (E-50061), because approval may have been months ago. Inserts auth.[User] and one '
       + N'auth.UserProfile directly -- auth.uspCreateUser and auth.uspCreateProfile both demand permissions and there '
       + N'is no session -- then grants the tenant''s default roles through auth.uspGrantTenantDefaultRoles rather than '
       + N're-implementing INV-04, and rebuilds the profile''s scope ONCE. Writes NO credential, so the account it '
       + N'creates cannot be signed in to by anybody until a verifier is stored deliberately; that is what makes a '
       + N'flood of self-registrations a pile of inert rows rather than a pile of accounts. Raises E-50062 (blank or '
       + N'malformed argument), E-50064 (no such registration), E-50066 (@UserName in use -- an enumeration signal '
       + N'Appendix B accepts on a self-service path, where the caller is choosing their own name) and E-50068 (this '
       + N'address has crossed Registration.ThrottleThreshold -- G-24, on the SAME per-address count as step 1, so one '
       + N'allowance covers both public doors). @ClientAddress is mandatory for that reason. The profile is IsDefault = '
       + N'1 and named after the tenant, because a profile name answers which hat the person is wearing.');

    DECLARE @RowNo       INT = 1
          , @MaxRowNo    INT = (SELECT MAX (d.RowNo) FROM @Descriptions AS d)
          , @ObjectName  SYSNAME
          , @Description NVARCHAR (MAX);

    -- A WHILE walk rather than DELETE FROM @Descriptions: the hard-delete rule in .claude/hooks/validate-sql.py is
    -- enforced on table variables too, and a cursor for four rows is not worth its declaration.
    WHILE @RowNo <= @MaxRowNo
    BEGIN
        SELECT @ObjectName  = d.ObjectName
             , @Description = d.Description
          FROM @Descriptions AS d
         WHERE d.RowNo = @RowNo;

        EXEC util.uspSetObjectDescription
              @SchemaName  = N'auth'
            , @ObjectType  = N'PROCEDURE'
            , @ObjectName  = @ObjectName
            , @Description = @Description
            , @ColumnName  = NULL;

        SET @RowNo += 1;
    END
END
ELSE
    PRINT N'WARNING: util.uspSetObjectDescription does not exist, so no MS_Description was written for the four '
        + N'registration procedures. Run templates/extended-properties.sql and then re-run this file.';
GO


-- *** 6. Grants ***
-- ALL FOUR GO TO applicationRole, INCLUDING THE THREE WITH NO SESSION.  The application is the only caller of any of
-- them; "unauthenticated" describes the END USER, not the connection.  The web tier connects as the same login it always
-- does, and what makes the public entry points safe is what they are allowed to write (section 2 and section 4 headers),
-- not a second database principal.  A separate lower-privileged login for the public pages would be a real improvement
-- and is a deployment decision, not a template one: it needs a login this script cannot create and a connection string
-- this database cannot see.
--
-- auth.uspRecordRegistrationAttempt IS GRANTED AND auth.RegistrationAttempt IS NOT.  080_auth_registration.sql grants no
-- table permission on it at all, which is what stops a caller clearing its own throttle: EXECUTE on this procedure buys
-- the ability to ADD an arrival and to read a count, and nothing else.  Granting it to the application is unavoidable
-- (the two public procedures call it, and ownership chaining would cover that, but a project may also want to call it
-- directly from a third public form it adds) and it is harmless in the only direction that matters -- calling it more
-- makes the caller MORE throttled, not less.
IF DATABASE_PRINCIPAL_ID (N'applicationRole') IS NOT NULL
BEGIN
    GRANT EXECUTE ON auth.uspRecordRegistrationAttempt TO applicationRole;
    GRANT EXECUTE ON auth.uspRegisterOrganization  TO applicationRole;
    GRANT EXECUTE ON auth.uspApproveOrganization   TO applicationRole;
    GRANT EXECUTE ON auth.uspRegisterExternalUser  TO applicationRole;
END
ELSE
    PRINT N'WARNING: database role applicationRole does not exist, so no EXECUTE was granted on the four registration '
        + N'procedures. Run database/005_schemas_and_roles.sql and then re-run this file.';
GO


-- *** 7. Closing report ***
-- Reads only.  Every row here asserts a decision that would still COMPILE if it were reversed -- which is exactly the
-- class of decision a deployment transcript has to carry, because nothing else will notice.
DECLARE @Report TABLE
(
    RowNo    INT IDENTITY (1, 1) PRIMARY KEY,
    Severity INT             NOT NULL,
    Status   VARCHAR (10)    NOT NULL,
    Item     NVARCHAR (200)  NOT NULL,
    Detail   NVARCHAR (1000)     NULL
);

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 4 THEN 4 ELSE 1 END
     , CASE WHEN COUNT (*) = 4 THEN 'OK' ELSE 'MISSING' END
     , N'All four registration procedures exist'
     , CONCAT (COUNT (*), N' of 4 created: uspRecordRegistrationAttempt (G-24, the per-address counter), '
             , N'uspRegisterOrganization (16.4 step 1, unauthenticated), '
             , N'uspApproveOrganization (step 2, demands Tenant.Create), uspRegisterExternalUser (step 3, '
             , N'unauthenticated, authority is the approved registration row).')
  FROM (VALUES (N'auth.uspRecordRegistrationAttempt')
             , (N'auth.uspRegisterOrganization')
             , (N'auth.uspApproveOrganization')
             , (N'auth.uspRegisterExternalUser')) AS x (ProcName)
 WHERE OBJECT_ID (x.ProcName, N'P') IS NOT NULL;

-- All four WRITE, so all four take the full instrumentation shape -- unlike 150, where every procedure is a read and
-- the absence of a start row is the decision being asserted.  Here the presence of one is.  The recorder is included
-- deliberately: it is the cheapest procedure in the file and the most tempting to leave un-instrumented, and it is also
-- the one whose failure would silently disable a control.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN SUM (x.Conforms) = 4 THEN 4 ELSE 1 END
     , CASE WHEN SUM (x.Conforms) = 4 THEN 'OK' ELSE 'VIOLATED' END
     , N'All four carry the FULL instrumentation shape'
     , CONCAT (SUM (x.Conforms), N' of 4 call both logs.uspStartExecutionLogging and logs.uspRecordExecutionError. '
             , N'Non-conforming: '
             , COALESCE (STRING_AGG (CASE WHEN x.Conforms = 0 THEN x.ProcName END, N', '), N'(none)')
             , N'. A writing procedure with no start row leaves a rollback invisible.')
  FROM (SELECT p.ProcName
             , Conforms = CASE WHEN m.definition LIKE N'%EXEC logs.uspStartExecutionLogging%'
                               AND  m.definition LIKE N'%EXEC logs.uspRecordExecutionError%' THEN 1 ELSE 0 END
          FROM (VALUES (N'auth.uspRecordRegistrationAttempt')
                     , (N'auth.uspRegisterOrganization')
                     , (N'auth.uspApproveOrganization')
                     , (N'auth.uspRegisterExternalUser')) AS p (ProcName)
         INNER JOIN sys.sql_modules AS m ON m.object_id = OBJECT_ID (p.ProcName)) AS x;

-- THE CENTRAL ASSERTION OF THE FILE, IN BOTH DIRECTIONS.  The three public procedures must demand nothing and set no
-- session context -- adding either would break the very callers they exist for, in production, at the moment a stranger
-- first used the form.  And the approval must demand, or an unauthenticated stranger could admit their own
-- organization.  Asserted on the CALL text, not the bare name, because these procedures' headers discuss both by name.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.PublicOffenders = 0 AND x.ApprovalDemands = 1 THEN 4 ELSE 1 END
     , CASE WHEN x.PublicOffenders = 0 AND x.ApprovalDemands = 1 THEN 'OK' ELSE 'VIOLATED' END
     , N'The three public procedures demand nothing; the approval demands Tenant.Create'
     , CONCAT (N'Public procedures calling auth.uspSetSessionContext or auth.uspDemandPermission: '
             , x.PublicOffenders, N' (must be 0 of 3 -- there is no session to set and no profile to test). '
             , N'auth.uspApproveOrganization calls auth.uspDemandPermission: ', x.ApprovalDemands
             , N' (must be 1). The public paths'' authority is a row: Status = Pending creates nothing, Status = '
             , N'Approved was written by a named reviewer under Tenant.Create, and the recorder''s authority is that it '
             , N'decides nothing at all.')
  FROM (SELECT PublicOffenders = SUM (CASE WHEN p.IsPublic = 1
                                            AND (m.definition LIKE N'%EXEC auth.uspSetSessionContext%'
                                              OR m.definition LIKE N'%EXEC auth.uspDemandPermission%')
                                           THEN 1 ELSE 0 END)
             , ApprovalDemands = MAX (CASE WHEN p.IsPublic = 0
                                            AND m.definition LIKE N'%EXEC auth.uspDemandPermission%'
                                           THEN 1 ELSE 0 END)
          FROM (VALUES (N'auth.uspRecordRegistrationAttempt', 1)
                     , (N'auth.uspRegisterOrganization', 1)
                     , (N'auth.uspRegisterExternalUser', 1)
                     , (N'auth.uspApproveOrganization',  0)) AS p (ProcName, IsPublic)
         INNER JOIN sys.sql_modules AS m ON m.object_id = OBJECT_ID (p.ProcName)) AS x;

-- G-24, AND THE ORDERING IS THE CONTROL.  Both public entry points must call the recorder BEFORE they open a
-- transaction, or every arrival that failed would roll back with the work it asked for and the count would see only the
-- successes -- which is the same defect as counting auth.OrganizationRegistration, arrived at by a different route.
-- Both must also refuse: a recorder whose verdict nobody reads is an audit table with extra steps.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Wired = 2 THEN 4 ELSE 1 END
     , CASE WHEN x.Wired = 2 THEN 'OK' ELSE 'VIOLATED' END
     , N'Both public entry points record BEFORE any transaction, and refuse on the verdict (E-50068)'
     , CONCAT (x.Wired, N' of 2 conforming. Not conforming: '
             , COALESCE (x.Offenders, N'(none)')
             , N'. Each must (a) call auth.uspRecordRegistrationAttempt, (b) do so at a character position BEFORE its '
             , N'first BEGIN TRANSACTION, and (c) contain a THROW of 50068. An arrival recorded inside the transaction '
             , N'it precedes is an arrival that vanishes when that transaction aborts, and a flood made entirely of '
             , N'failures would then be uncounted.')
  FROM (SELECT Wired     = SUM (x2.Conforms)
             , Offenders = STRING_AGG (CASE WHEN x2.Conforms = 0 THEN x2.ProcName END, N', ')
          FROM (SELECT p.ProcName
                     , Conforms = CASE WHEN CHARINDEX (N'EXEC auth.uspRecordRegistrationAttempt', m.definition) > 0
                                        AND CHARINDEX (N'BEGIN TRANSACTION;', m.definition) > 0
                                        AND CHARINDEX (N'EXEC auth.uspRecordRegistrationAttempt', m.definition)
                                          < CHARINDEX (N'BEGIN TRANSACTION;', m.definition)
                                        AND m.definition LIKE N'%THROW 50068%'
                                       THEN 1 ELSE 0 END
                  FROM (VALUES (N'auth.uspRegisterOrganization')
                             , (N'auth.uspRegisterExternalUser')) AS p (ProcName)
                 INNER JOIN sys.sql_modules AS m ON m.object_id = OBJECT_ID (p.ProcName)) AS x2) AS x;

-- G-24's other half, and the one a reviewer would most plausibly undo as a kindness to a caller.  @ClientAddress has to
-- be refused when it is absent, because a per-address count grouped on a sometimes-absent column counts nothing for the
-- callers who omit it.  Asserted on the parameter's presence in the refusal text, which is the only trace a compiled
-- module keeps of a validation rule.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Guarded = 2 THEN 4 ELSE 1 END
     , CASE WHEN x.Guarded = 2 THEN 'OK' ELSE 'VIOLATED' END
     , N'@ClientAddress is mandatory on both public entry points'
     , CONCAT (x.Guarded, N' of 2 refuse a blank or missing @ClientAddress with E-50062 before recording anything. '
             , N'Not guarded: ', COALESCE (x.Offenders, N'(none)')
             , N'. The parameter keeps its = NULL default on purpose, so that an old caller gets a sentence explaining '
             , N'G-24 rather than Msg 201 naming a parameter it has never heard of. The address comes from the '
             , N'connection and not from the form, so no registrant can influence it.')
  FROM (SELECT Guarded   = SUM (x2.Conforms)
             , Offenders = STRING_AGG (CASE WHEN x2.Conforms = 0 THEN x2.ProcName END, N', ')
          FROM (SELECT p.ProcName
                     , Conforms = CASE WHEN m.definition LIKE N'%@ClientAddress is required and may not be blank%'
                                        AND m.definition LIKE N'%THROW 50062%' THEN 1 ELSE 0 END
                  FROM (VALUES (N'auth.uspRegisterOrganization')
                             , (N'auth.uspRegisterExternalUser')) AS p (ProcName)
                 INNER JOIN sys.sql_modules AS m ON m.object_id = OBJECT_ID (p.ProcName)) AS x2) AS x;

-- BL-042: the demand must precede the transaction, or a refusal rolls its own denial row back and the only record that
-- somebody tried to admit an organization they had no authority over disappears with it.  Matched on 'BEGIN
-- TRANSACTION;' with the semicolon, because the procedure's header discusses the ordering in prose and that sentence
-- comes first in the stored text.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.DemandPos > 0 AND x.TranPos > 0 AND x.DemandPos < x.TranPos THEN 4 ELSE 1 END
     , CASE WHEN x.DemandPos > 0 AND x.TranPos > 0 AND x.DemandPos < x.TranPos THEN 'OK' ELSE 'VIOLATED' END
     , N'auth.uspApproveOrganization demands its permission BEFORE it opens a transaction'
     , CONCAT (N'Demand at character ', x.DemandPos, N', BEGIN TRANSACTION at character ', x.TranPos
             , N'. This is the ordering 125_auth_tenant_procedures.sql gets wrong (G-31): a denial written inside the '
             , N'transaction it is about to abort is not a denial anybody can read afterwards.')
  FROM (SELECT DemandPos = CHARINDEX (N'EXEC auth.uspDemandPermission', m.definition)
             , TranPos   = CHARINDEX (N'BEGIN TRANSACTION;',            m.definition)
          FROM sys.sql_modules AS m
         WHERE m.object_id = OBJECT_ID (N'auth.uspApproveOrganization')) AS x;

-- BL-052 and BL-056, asserted as absences.  Either one could be "fixed" by a well-meaning edit that made the file
-- longer and the system wrong: copying default roles per tenant looks more explicit, and inlining the grant looks like
-- one less dependency.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.ApprovalSeeds = 0 AND x.EnrolDelegates = 1 AND x.EnrolReimplements = 0 THEN 4 ELSE 1 END
     , CASE WHEN x.ApprovalSeeds = 0 AND x.EnrolDelegates = 1 AND x.EnrolReimplements = 0 THEN 'OK' ELSE 'VIOLATED' END
     , N'Default roles are inherited, not copied, and the rule lives in one place'
     , CONCAT (N'auth.uspApproveOrganization inserts auth.TenantDefaultRole rows: ', x.ApprovalSeeds
             , N' (must be 0 -- section 11.5 inherits from the nearest ancestor, so the branch names the set once). '
             , N'auth.uspRegisterExternalUser calls auth.uspGrantTenantDefaultRoles: ', x.EnrolDelegates
             , N' (must be 1) and reads auth.TenantDefaultRole itself: ', x.EnrolReimplements
             , N' (must be 0 -- INV-04 is security-bearing and two copies of it drift).')
  FROM (SELECT ApprovalSeeds     = MAX (CASE WHEN p.ProcName = N'auth.uspApproveOrganization'
                                              AND m.definition LIKE N'%INSERT auth.TenantDefaultRole%'
                                             THEN 1 ELSE 0 END)
             , EnrolDelegates    = MAX (CASE WHEN p.ProcName = N'auth.uspRegisterExternalUser'
                                              AND m.definition LIKE N'%EXEC auth.uspGrantTenantDefaultRoles%'
                                             THEN 1 ELSE 0 END)
             , EnrolReimplements = MAX (CASE WHEN p.ProcName = N'auth.uspRegisterExternalUser'
                                              AND m.definition LIKE N'%auth.TenantDefaultRole AS%'
                                             THEN 1 ELSE 0 END)
          FROM (VALUES (N'auth.uspApproveOrganization')
                     , (N'auth.uspRegisterExternalUser')) AS p (ProcName)
         INNER JOIN sys.sql_modules AS m ON m.object_id = OBJECT_ID (p.ProcName)) AS x;

-- The enrolment must not write a credential.  An account with no verifier cannot be signed in to by anyone, which is
-- what keeps a flood of self-registrations harmless; a helpful edit that set a default password would quietly convert
-- every one of those inert rows into a live account with a guessable secret.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.WritesCredential = 0 THEN 4 ELSE 1 END
     , CASE WHEN x.WritesCredential = 0 THEN 'OK' ELSE 'VIOLATED' END
     , N'auth.uspRegisterExternalUser writes no credential'
     , CONCAT (N'INSERT into a credential table: ', x.WritesCredential, N' (must be 0). Storing a verifier is the '
             , N'invitation step of section 12 and is a separate, deliberate act. Until it happens the enrolled account '
             , N'is inert, and a reviewer who decides the enrolment was a mistake can retire it before it was ever '
             , N'usable.')
  FROM (SELECT WritesCredential = CASE WHEN m.definition LIKE N'%INSERT auth.UserCredential%'
                                       OR   m.definition LIKE N'%INSERT INTO auth.UserCredential%' THEN 1 ELSE 0 END
          FROM sys.sql_modules AS m
         WHERE m.object_id = OBJECT_ID (N'auth.uspRegisterExternalUser')) AS x;

-- CAN AN APPROVAL ACTUALLY SUCCEED IN THIS DATABASE?  E-50067 is a configuration fault, and the configuration is one
-- global setting row against a per-application tenant code -- so a deployment can be internally inconsistent in a way
-- no constraint catches and no test notices until the first organization is approved.  This row goes looking for it.
DECLARE @BranchCode  NVARCHAR (50) = NULLIF (LTRIM (RTRIM (COALESCE (
                          (SELECT s.SettingValue
                             FROM config.ApplicationSetting AS s
                            WHERE s.SettingKey = N'Registration.ExternalBranchTenantCode'
                              AND s.IsDeleted  = 0)
                        , N''))), N'');

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN @BranchCode IS NULL THEN 1
            WHEN x.UnresolvedWithQueue IS NOT NULL THEN 2
            WHEN x.Resolved = 0 THEN 2
            ELSE 4 END
     , CASE WHEN @BranchCode IS NULL THEN 'MISSING'
            WHEN x.UnresolvedWithQueue IS NOT NULL THEN 'REVIEW'
            WHEN x.Resolved = 0 THEN 'REVIEW'
            ELSE 'OK' END
     , N'The external-organizations branch resolves for the applications that use registration'
     , CONCAT (N'config.ApplicationSetting key Registration.ExternalBranchTenantCode = '
             , COALESCE (N'''' + @BranchCode + N'''', N'(missing or blank)'), N'. It resolves to a live, active tenant '
             , N'in ', x.Resolved, N' of ', x.LiveApps, N' live applications. Applications holding registrations where '
             , N'it does NOT resolve, and where auth.uspApproveOrganization would therefore raise E-50067: '
             , COALESCE (x.UnresolvedWithQueue, N'(none)')
             , N'. The setting is global while the tenant code is per application, so a deployment that seeds one '
             , N'branch code and a fixture that seeds another disagree silently -- see the gap recorded against '
             , N'section 17.3, which writes EXT_ORGS where 115_seed_reference_data.sql writes EXTORG.')
  FROM (SELECT LiveApps = COUNT (*)
             , Resolved = SUM (a.BranchResolves)
             , UnresolvedWithQueue = STRING_AGG (CASE WHEN a.BranchResolves = 0 AND a.HasRegistrations = 1
                                                      THEN a.ApplicationCode END, N', ')
          FROM (SELECT ap.ApplicationCode
                     , BranchResolves = CASE WHEN EXISTS (SELECT 1
                                                            FROM auth.Tenant AS t
                                                           WHERE t.ApplicationId = ap.ApplicationId
                                                             AND t.TenantCode    = @BranchCode
                                                             AND t.IsActive      = 1
                                                             AND t.IsDeleted     = 0) THEN 1 ELSE 0 END
                     , HasRegistrations = CASE WHEN EXISTS (SELECT 1
                                                              FROM auth.OrganizationRegistration AS orr
                                                             WHERE orr.ApplicationId = ap.ApplicationId
                                                               AND orr.IsDeleted     = 0) THEN 1 ELSE 0 END
                  FROM auth.Application AS ap
                 WHERE ap.IsActive  = 1
                   AND ap.IsDeleted = 0) AS a) AS x;

-- The queue as it stands, so the transcript says what the file inherited.
INSERT @Report (Severity, Status, Item, Detail)
SELECT 4
     , 'OK'
     , N'Registration queue as this file found it'
     -- COALESCE around every SUM: an empty table gives NULL, CONCAT renders NULL as nothing, and the first deployment
     -- of this file reported "0 live rows:  Pending,  Approved,  Rejected".
     , CONCAT (N'auth.OrganizationRegistration holds ', COUNT (*), N' live rows: '
             , COALESCE (SUM (CASE WHEN orr.Status = N'Pending'  THEN 1 ELSE 0 END), 0), N' Pending, '
             , COALESCE (SUM (CASE WHEN orr.Status = N'Approved' THEN 1 ELSE 0 END), 0), N' Approved, '
             , COALESCE (SUM (CASE WHEN orr.Status = N'Rejected' THEN 1 ELSE 0 END), 0)
             , N' Rejected. Approved rows whose tenant is missing, inactive or deleted, and which therefore refuse '
             , N'enrolment with E-50061: ', COALESCE (SUM (orr.TenantUnusable), 0), N'.')
  -- The unusable-tenant flag is computed per row in a derived table rather than inside the SUM: an aggregate may not
  -- contain a subquery (Msg 130), and EXISTS is a subquery however small it looks.
  FROM (SELECT r.Status
             , TenantUnusable = CASE WHEN r.Status = N'Approved'
                                      AND NOT EXISTS (SELECT 1
                                                        FROM auth.Tenant AS t
                                                       WHERE t.TenantId  = r.TenantId
                                                         AND t.IsActive  = 1
                                                         AND t.IsDeleted = 0) THEN 1 ELSE 0 END
          FROM auth.OrganizationRegistration AS r
         WHERE r.IsDeleted = 0) AS orr;

-- The throttle as this deployment has it configured, and the arrivals it has seen.  Two settings and one table, printed
-- together, because "is the throttle on?" is not answerable from either alone.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Threshold IS NULL THEN 2
            WHEN x.Threshold = 0 THEN 3
            ELSE 4 END
     , CASE WHEN x.Threshold IS NULL THEN 'MISSING'
            WHEN x.Threshold = 0 THEN 'PENDING'
            ELSE 'OK' END
     , N'G-24: the registration throttle is wired, and G-06''s edge half is still required'
     , CONCAT (N'Registration.ThrottleThreshold = '
             , COALESCE (CAST (x.Threshold AS NVARCHAR (11)), N'(missing -- the procedures fall back to 10)')
             , N', Registration.ThrottleWindowMinutes = '
             , COALESCE (CAST (x.WindowMinutes AS NVARCHAR (11)), N'(missing -- falls back to 60)')
             , CASE WHEN x.Threshold = 0 THEN N'. The threshold is 0, so arrivals are RECORDED AND NEVER REFUSED -- '
                                            + N'which is a legitimate deployment choice and is reported here so it is '
                                            + N'not an accident.' ELSE N'.' END
             , N' auth.RegistrationAttempt holds ', x.Live, N' live row(s) across ', x.Addresses, N' address(es): '
             , x.Accepted, N' Accepted, ', x.Refused, N' Refused, ', x.Throttled, N' Throttled, ', x.Received
             , N' still Received. THIS IS THE DATABASE HALF ONLY. A threshold per address costs a botnet nothing, so '
             , N'gateway rate limiting and a CAPTCHA on the public form remain required and remain G-06, which stays '
             , N'open and still blocks a Variant 3 production go-live.')
  FROM (SELECT Threshold     = TRY_CAST ((SELECT s.SettingValue FROM config.ApplicationSetting AS s
                                           WHERE s.SettingKey = N'Registration.ThrottleThreshold'
                                             AND s.IsDeleted  = 0) AS INT)
             , WindowMinutes = TRY_CAST ((SELECT s.SettingValue FROM config.ApplicationSetting AS s
                                           WHERE s.SettingKey = N'Registration.ThrottleWindowMinutes'
                                             AND s.IsDeleted  = 0) AS INT)
             , Live      = COUNT (*)
             , Addresses = COUNT (DISTINCT a.ClientAddress)
             , Accepted  = COALESCE (SUM (CASE WHEN a.Outcome = 'Accepted'  THEN 1 ELSE 0 END), 0)
             , Refused   = COALESCE (SUM (CASE WHEN a.Outcome = 'Refused'   THEN 1 ELSE 0 END), 0)
             , Throttled = COALESCE (SUM (CASE WHEN a.Outcome = 'Throttled' THEN 1 ELSE 0 END), 0)
             , Received  = COALESCE (SUM (CASE WHEN a.Outcome = 'Received'  THEN 1 ELSE 0 END), 0)
          FROM auth.RegistrationAttempt AS a
         WHERE a.IsDeleted = 0) AS x;

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 4 THEN 4 ELSE 2 END
     , CASE WHEN COUNT (*) = 4 THEN 'OK' ELSE 'PARTIAL' END
     , N'MS_Description present on all four procedures'
     , CONCAT (COUNT (*), N' of 4 carry an MS_Description extended property. A reader who opens these in Object '
             , N'Explorer sees why three of them need no permission, which is the question they will have.')
  FROM sys.extended_properties AS ep
 WHERE ep.class = 1
   AND ep.minor_id = 0
   AND ep.name = N'MS_Description'
   AND ep.major_id IN (OBJECT_ID (N'auth.uspRecordRegistrationAttempt')
                     , OBJECT_ID (N'auth.uspRegisterOrganization')
                     , OBJECT_ID (N'auth.uspApproveOrganization')
                     , OBJECT_ID (N'auth.uspRegisterExternalUser'));

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN DATABASE_PRINCIPAL_ID (N'applicationRole') IS NULL THEN 3
            WHEN COUNT (*) = 4 THEN 4 ELSE 2 END
     , CASE WHEN DATABASE_PRINCIPAL_ID (N'applicationRole') IS NULL THEN 'PENDING'
            WHEN COUNT (*) = 4 THEN 'OK' ELSE 'PARTIAL' END
     , N'EXECUTE granted to applicationRole on all four'
     , CASE WHEN DATABASE_PRINCIPAL_ID (N'applicationRole') IS NULL
            THEN N'applicationRole does not exist. Run database/005_schemas_and_roles.sql and re-run this file.'
            ELSE CONCAT (COUNT (*), N' of 4 granted. All four are called by the application, including the three the '
                       , N'public reaches: "unauthenticated" describes the end user, not the connection. There is no '
                       , N'grant on auth.RegistrationAttempt itself, which is what stops a caller clearing its own '
                       , N'throttle.') END
  FROM sys.database_permissions AS dp
 WHERE dp.class = 1
   AND dp.permission_name = N'EXECUTE'
   AND dp.state_desc = N'GRANT'
   AND dp.grantee_principal_id = COALESCE (DATABASE_PRINCIPAL_ID (N'applicationRole'), -1)
   AND dp.major_id IN (OBJECT_ID (N'auth.uspRecordRegistrationAttempt')
                     , OBJECT_ID (N'auth.uspRegisterOrganization')
                     , OBJECT_ID (N'auth.uspApproveOrganization')
                     , OBJECT_ID (N'auth.uspRegisterExternalUser'));

IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
    PRINT N'Registration surface: PROBLEMS found. Read the report below before running the next script.';
ELSE
    PRINT N'Registration surface: no problems found.';

PRINT N'';

SELECT Severity, Status, Item, Detail
  FROM @Report
 ORDER BY Severity, RowNo;
GO

