/***********************************************************************************************************************
Script:         150_auth_query_procedures.sql
Purpose:        The authorization query surface, complete: auth.uspDemandPermission, which every business procedure in
                the database calls before it writes anything, and the three procedures the USER INTERFACE calls to find
                out what to draw -- uspGetProfileContext, uspGetNavigationForProfile and uspCheckPermission.
Target:         SQL Server 2022.
Run as:         db_owner in the target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/150_auth_query_procedures.sql
Idempotent:     Yes.  CREATE OR ALTER throughout, and every grant guarded on DATABASE_PRINCIPAL_ID.
Depends on:     database/050_auth_permission.sql, database/065_auth_effective_permission.sql,
                database/070_auth_session.sql, database/075_auth_ui_catalog.sql, database/085_logs_auth_tables.sql,
                database/095_auth_views.sql, database/100_auth_functions.sql, database/105_auth_session_procedures.sql,
                database/165_logs_procedures.sql, scripts/logExecutionLogging.sql, templates/extended-properties.sql.
Implements:     T-052, T-083, T-084, T-085, T-126.  DES-AUTH-001 sections 9, 9.1, 13.2, 13.4, 14.2 and 15.5.
                See docs/10-database-authn-authz-design.md.
To retarget:    Pass it per run:  sqlcmd -d <database> -v DbName=<database>.  There is no in-file default.

FOUR PROCEDURES, AND ONE OF THEM IS NOT LIKE THE OTHERS
-------------------------------------------------------
auth.uspDemandPermission is the SERVER'S question, asked of itself: "may this go ahead?", answered by proceeding or by
throwing.  The other three are the UI'S questions -- "who am I and where am I?", "what may I draw?", "may I enable this
button?" -- and every one of them answers with a result set and never throws on a negative.  That difference is why the
first is not granted to applicationRole and the other three are.

The four were designed together and delivered apart.  Phase 3 delivered uspDemandPermission alone because nothing else in
the database could be finished without it: five procedures in 125_auth_tenant_procedures.sql referenced it and failed at
call time with 2812 until it existed.  Phase 6 adds the other three, and 140_auth_profile_procedures.sql has been waiting
on one of them since it was written -- auth.uspSwitchProfile guards its second result set on
OBJECT_ID (N'auth.uspGetNavigationForProfile', N'P') IS NOT NULL, so running this file is what turns that PENDING row in
140's closing report into a working two-result-set switch.  G-26, BL-053.

THE SESSION PARAMETER IS @SessionTokenHash VARBINARY (32) IN ALL THREE, NEVER @SessionToken
------------------------------------------------------------------------------------------
Sections 9 and 12.1 sketch these signatures as taking @SessionToken.  They are wrong and the design amendment is owed:
the database never sees a session token, only its SHA-256, because a token that reached the database would be a
credential sitting in logs.ExecutionLog.KeyParameters and in every plan-cache entry that mentioned it.  Every procedure
in 105, 130, 140 and 145 takes the hash, and these three match them.  G-26, BL-053, and UI-16 is the rule they all obey.

A NEGATIVE ANSWER IS NOT AN ERROR IN ANY OF THE THREE
-----------------------------------------------------
uspCheckPermission returns HasPermission = 0.  uspGetNavigationForProfile returns fewer rows.  uspGetProfileContext
returns the one row it always returns.  None of them throws because the answer was no, and that is what makes them safe
to call on every page load: an exception is a thing a caller can forget to catch, and a UI that crashed rather than
greyed out a button would be a worse outcome than one that drew the button.

They DO throw when the SESSION is the problem -- E-50100 for a malformed hash, E-50020/E-50021 from
auth.uspSetSessionContext for a session that has ended or a profile that has become unusable -- because that is not a
permission answer at all, and section 14.5 has the UI sign the user out on the 5002x range.  The distinction is the whole
design: "no" is data, "you are not here any more" is an error.

WHY THE NAVIGATION PROCEDURE OMITS RATHER THAN FLAGS
----------------------------------------------------
Section 13.2: an element the profile cannot view is left out of the payload entirely, not returned with CanView = 0.  A
navigation tree listing the screens you may not open is an information leak that is usually visible in a browser's
network tab, and it is the same leak auth.uspListProfilesForUser avoids by omitting other people's profiles.  CanEdit = 0
with CanView = 1 IS returned, because that is the read-only case and it is the common one -- the county read-only user
sees the case screen with every control disabled, which is a design outcome rather than an accident.

An element with NO permission row at all is visible to every authenticated profile (section 13.1).  That is the right
default for a home page and the wrong one for everything else, which is why 950_verify_deployment.sql lists unmapped
elements as a warning rather than this procedure refusing to return them.

AND WHY IT PRUNES ORPHANS
-------------------------
A Command whose Screen was pruned must be pruned too, or the UI receives a button with a parent it never got and either
crashes or draws it at the root.  The tree is walked DOWNWARD from the Areas with a recursive CTE, so a node appears only
if every ancestor of it appeared: viewability is inherited as a precondition, not recomputed.  This is the one place in
the file where MAXRECURSION matters, and the hierarchy is five levels deep by CK_auth_UiElement_ElementType, so the
default of 100 is never approached.

WHY uspCheckPermission WRITES NOTHING AT ALL
--------------------------------------------
No logs.ExecutionLog start row, no logs.AuthorizationDenial row, not even on a negative answer.  It is called once per
button per page render -- hundreds of times per screen in a rich UI -- and a trail row per render would bury the real
denials that uspDemandPermission records under noise that means nothing: "the UI asked whether to enable a button and the
answer was no" is not a security event, it is a layout decision.  E-50031 is still raised for a permission code that
does not exist, because that is an application defect and silence would hide it.


WHY THIS PROCEDURE THROWS INSTEAD OF RETURNING A VERDICT
-------------------------------------------------------
Section 9 makes steps 5 and 6 deliberately redundant: this procedure is step 5, row-level security is step 6.  Step 5
exists to produce a clean, catchable E-50030 that the UI can render as "you do not have permission to update this
case"; step 6 is the guarantee that a procedure which forgot step 5 still cannot touch another tenant's rows.  A
procedure that returned a bit instead of throwing would make the caller responsible for checking it, and a caller that
forgets to check a return value has silently skipped the whole permission model -- which is finding F-07's shape.

The non-throwing form is a separate procedure, auth.uspCheckPermission (T-085), and it exists for one purpose: deciding
whether to render a button.  Keeping them apart is what lets the demand be unconditional.

ONE PROCEDURE, THREE ERROR NUMBERS, AND THE ORDER THEY ARE DECIDED IN
---------------------------------------------------------------------
E-50030 is "denied", E-50031 is "there is no such permission code in this application", and E-50032 -- added by T-126,
see the next essay -- is "signed in, wearing no hat, so there is nothing for a permission to be held by".  All three are
raised only AFTER the
denial has been recorded in logs.AuthorizationDenial, because a code that does not exist is the single most useful row
that table can hold: it means a procedure in this database asks for a permission nobody can ever hold, so the feature it
guards is dead and no test noticed.  Deciding the number first and recording afterwards would have been the natural
shape and would have lost exactly that row on the path where it matters most.

E-50031 is NOT a security decision and must not be read as one.  It says the same thing to everybody, it is reached only
after the caller has already been refused, and the alternative -- collapsing it into E-50030 -- would mean a deployment
with a typo'd permission code looked identical to a correctly configured one.  It is an application defect reported as
an error number, and section 14.5 puts the whole 50030 range under "show a permission message; do not sign out".

A DEMAND WITH NO SESSION CONTEXT IS A DENIAL; A DEMAND WITH NO PROFILE IS E-50032 -- G-51
---------------------------------------------------------------------------------------
auth.udfHasPermission reads SESSION_CONTEXT ('UserProfileId') itself and returns 0 when it is absent, so both of these
land on the denied path and both produce a logs.AuthorizationDenial row whose UserProfileId is NULL.  They are not the
same thing, and until 2026-09-21 they shared one error number and one message:

  NO CONTEXT AT ALL   SESSION_CONTEXT ('UserId') is NULL too.  Nothing called auth.uspSetSessionContext on this
                      connection.  E-50030, whose message says "server-side defect", because that is what it is, and
                      the NULL UserProfileId in the trail is the finding.
  SIGNED IN, NO HAT   UserId is set, UserProfileId is not.  E-50032.  UI-09 ships this state deliberately: a user who
                      registered externally, or whose only profile was just deactivated, has a perfectly good session
                      and no active profile, and the hat menu is the screen they are meant to land on.

The discriminator is auth.uspSetSessionContext's own contract and nothing cleverer.  On success it ALWAYS sets UserId,
AppUser and ApplicationId, and it sets UserProfileId and ActingTenantId only when a profile resolved.  So UserId present
with UserProfileId absent is the legitimate profileless session, and UserId absent means the procedure really was
reached with no context.

SCEN-AUTH-001 is why this is now two numbers.  The scenario's first call after sign-in was auth.uspListProfilesForUser,
which demands Authz.ProfileRead -- and a session with no hat holds no permission anywhere, so the answer was E-50030
announcing that there was NO SESSION CONTEXT on a connection that had just successfully established some.  The
investigation went to auth.uspSetSessionContext, where nothing was wrong.  A WRONG diagnostic costs more than a missing
one: a missing one makes you look, a wrong one tells you where not to.  T-126 split the number and also gave that
session the procedure it actually needed, auth.uspListMyProfiles in 140_auth_profile_procedures.sql, which demands
nothing at all.

Raising E-50020 for either was considered and rejected.  The 5002x range means "your session is gone, sign in again" and
section 14.5 has the UI sign the user out on it.  Neither of these sessions is gone: one is a server-side defect that
signing out would hide behind a plausible-looking re-authentication, and the other is a valid session that needs a hat,
not a password.  Section 14.5 puts 50032 where 50030 already was -- show a message, do NOT sign out -- except that the
message is "choose a profile" and the screen is the chooser.

@TenantId IS OPTIONAL AND OMITTING IT FAILS CLOSED
--------------------------------------------------
A non-tenant-scoped permission -- the Platform category -- ignores @TenantId entirely, which is why the parameter has a
default.  A TENANT-scoped permission demanded with @TenantId = NULL is refused, every time, because
auth.udfHasPermission looks for a closure row whose DescendantTenantId equals NULL and finds none.  That is the correct
direction to fail in and it is stated here because the opposite reading -- "no tenant means any tenant" -- is the one
somebody will assume.

THE DENIAL RECORD IS SANITIZED AND THE RECORDER CALL IS SWALLOWED
-----------------------------------------------------------------
logs.AuthorizationDenial carries foreign keys to auth.Tenant and auth.UserProfile, and a demand made with a tenant id
that does not exist is both a plausible caller bug and exactly the demand worth recording.  Passed through raw, the
recorder would fail with 547 and the caller would receive a foreign-key error instead of E-50030 -- a database error on
screen where a permission message belonged.  So the ids are checked against their parents first and replaced with NULL
when they do not resolve, with the raw value preserved in @DetailJson where no constraint can object to it.

On top of that, the recorder call sits in a nested TRY whose CATCH swallows.  The rule comes from the instrumentation
reference: a failure in the logging of an error must never replace the error being reported.  Here that rule is load
bearing rather than tidy -- E-50030 is the one thing the caller must be able to branch on.  A swallowed failure is
still visible, because the recorder is fully instrumented and wrote its own logs.ExecutionLog error row on the way out.

AND THE DENIAL CAN STILL BE ROLLED BACK, WHICH IS WHY SECTION 9 ORDERS THE STEPS AS IT DOES
------------------------------------------------------------------------------------------
Called inside a transaction the caller had already opened, the denial row is written in that transaction and E-50030
provokes the rollback that removes it.  The flush pattern cannot rescue it: SET XACT_ABORT ON dooms the caller's
transaction, so a CATCH-time re-insert fails too (3930).  Section 9 authorizes at step 5, BEFORE the work opens a
transaction at step 6, and every procedure in this database follows that order -- which is what keeps the trail.  A
procedure that demands a permission halfway through a transaction loses the trail row and keeps the refusal.  Stated as
an accepted limitation, BL-042, rather than papered over with a loopback connection.

NOT GRANTED TO applicationRole
------------------------------
Business procedures reach it by ownership chaining, measured on this instance and recorded in the header of
165_logs_procedures.sql: a nested EXEC across schemas needs no grant when the schemas share an owner, and auth, dbo and
logs are all owned by dbo here.  The application has no reason to call it directly -- the UI asks
auth.uspGetNavigationForProfile and auth.uspCheckPermission what to render -- and two reasons not to be able to.  First,
the pair of numbers is an oracle: E-50031 distinguishes a permission code that exists in this application from one that
does not, which is a map of the authorization model handed to whoever holds the application credential.  Second, every
call writes a row to logs.AuthorizationDenial, so an attacker with EXECUTE could bury a real denial under a hundred
thousand fabricated ones.  Neither matters when the only callers are procedures.
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

-- auth.udfHasPermission is asserted rather than warned about, unlike the instrumentation chain below: a FUNCTION is
-- resolved when the procedure is created, not deferred, so a missing one fails this deployment with 208 anyway.  Named
-- here so the failure says which file to run instead of naming a line number.
IF OBJECT_ID (N'auth.Permission', N'U') IS NULL
   OR OBJECT_ID (N'auth.udfHasPermission', N'FN') IS NULL
   OR OBJECT_ID (N'logs.AuthorizationDenial', N'U') IS NULL
   OR OBJECT_ID (N'logs.uspRecordAuthorizationDenial', N'P') IS NULL
BEGIN
    DECLARE @MsgParents NVARCHAR (2000) =
        N'A parent object is missing. auth.Permission comes from database/050_auth_permission.sql, '
      + N'auth.udfHasPermission from database/100_auth_functions.sql, logs.AuthorizationDenial from '
      + N'database/085_logs_auth_tables.sql and logs.uspRecordAuthorizationDenial from '
      + N'database/165_logs_procedures.sql. Run them first.';

    THROW 50000, @MsgParents, 1;
END
GO

-- The three UI procedures' parents.  Asserted rather than warned about for the same reason as the block above: two of
-- these are a VIEW and a FUNCTION, which are resolved when the procedure is created rather than deferred, so a missing
-- one fails this deployment with 208 regardless -- and a 208 naming a column is far harder to act on than this message.
IF OBJECT_ID (N'auth.UiElement', N'U') IS NULL
   OR OBJECT_ID (N'auth.UiElementPermission', N'U') IS NULL
   OR OBJECT_ID (N'auth.ProfilePermissionScope', N'U') IS NULL
   OR OBJECT_ID (N'auth.UserSession', N'U') IS NULL
   OR OBJECT_ID (N'auth.vwTenantHierarchy', N'V') IS NULL
   OR OBJECT_ID (N'auth.udfIsTenantUsable', N'FN') IS NULL
BEGIN
    DECLARE @MsgUiParents NVARCHAR (2000) =
        N'A parent object of the three UI procedures is missing. auth.UiElement and auth.UiElementPermission come from '
      + N'database/075_auth_ui_catalog.sql, auth.ProfilePermissionScope from '
      + N'database/065_auth_effective_permission.sql, auth.UserSession from database/070_auth_session.sql, '
      + N'auth.vwTenantHierarchy from database/095_auth_views.sql and auth.udfIsTenantUsable from '
      + N'database/100_auth_functions.sql. Run them first.';

    THROW 50000, @MsgUiParents, 1;
END
GO

-- auth.uspSetSessionContext is a PROCEDURE and therefore deferred, so this is a warning -- but it is the load-bearing
-- one: all three UI procedures open by establishing context from @SessionTokenHash, and without it every one of them
-- installs cleanly and then fails with 2812 on its first call, which is the first page load.
IF OBJECT_ID (N'auth.uspSetSessionContext', N'P') IS NULL
BEGIN
    PRINT N'WARNING: auth.uspSetSessionContext is missing. auth.uspGetProfileContext, '
        + N'auth.uspGetNavigationForProfile and auth.uspCheckPermission will install and will then fail with error '
        + N'2812 on their FIRST CALL, which is the first page load. Run database/105_auth_session_procedures.sql.';
END
GO

-- The instrumentation chain.  A warning rather than a THROW: a procedure gets deferred name resolution and installs
-- without it, and the failure would arrive on the first call.
IF OBJECT_ID (N'logs.uspRecordExecutionError', N'P') IS NULL
BEGIN
    PRINT N'WARNING: logs.uspRecordExecutionError is missing. auth.uspDemandPermission will install and will fail with '
        + N'error 2812 on its FIRST DENIAL -- not on its first call, which makes it the worst kind of latent break. '
        + N'Run .claude/skills/ponytail-sql-objects/scripts/logExecutionLogging.sql against this database.';
END
GO


-- *** 1. auth.uspDemandPermission ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspDemandPermission
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Refuses the call unless the session's active profile holds @PermissionCode at @TenantId.  Section 9 step 5, section
14.2.  Returns silently when the permission is held; records the refusal in logs.AuthorizationDenial and raises
E-50030 -- or E-50031 when the code does not exist in this application, or E-50032 when the session is signed in with no
active profile -- when it is not.

Called near the top of every procedure that writes, once per distinct authority it needs, BEFORE it opens a
transaction.  A read that returns a filtered set demands nothing: row-level security returns what the profile may see,
and an empty result is the right answer for a profile with no read scope (section 14.2).

========================================================================================================================
Requirements and Key Dependencies:

auth.udfHasPermission -- the whole decision.  This procedure adds the trail and the error number and no logic.
auth.Permission       -- read only to tell E-50031 from E-50030, after the decision is already made.
SESSION_CONTEXT       -- UserProfileId for the decision, and UserId to tell E-50032 from E-50030.
auth.Tenant, auth.UserProfile -- existence checks that sanitize the two ids before they reach a foreign key.
logs.uspRecordAuthorizationDenial -- the trail.  Fully instrumented itself, which is why the swallow below is safe.

logs.uspRecordExecutionError.  NOT logs.uspStartExecutionLogging: this is the error-only shape, per rule 8.

========================================================================================================================
Notes:

ERROR-ONLY INSTRUMENTED, AND THAT IS A DELIBERATE READING OF RULE 8 rather than a shortcut.  The procedure's own writes
are none: the granted path reads two indexes and returns, and the denied path delegates its one write to
logs.uspRecordAuthorizationDenial, which carries the full block.  A start row and a completion update here would double
the instrumentation cost of every write in the database -- this is the most frequently called procedure in it -- to
record that a permission check succeeded, which is the least interesting fact the log could hold.  A denial still
produces a logs.ExecutionLog error row, because it throws and the CATCH is reached.

THE DECISION IS auth.udfHasPermission'S AND NOTHING HERE SECOND-GUESSES IT.  No IsActive test, no usability test, no
platform-admin branch: they are all inside the function, which is also what the row-level security predicates call,
and a second copy of a security rule drifts from the first.  Section 9.1.

@ObjectName IS PASSED IN, BECAUSE T-SQL CANNOT DISCOVER ITS CALLER.  OBJECT_NAME (@@PROCID) inside this procedure names
this procedure.  sys.dm_exec_requests would need VIEW SERVER STATE, which no application login has, and returns the
outermost batch rather than the immediate caller.  So the caller names itself, the parameter is optional, and a NULL
ObjectName in the trail means the caller did not bother -- which is worth seeing on a dashboard.

THE TWO IDS ARE SANITIZED BEFORE THEY REACH THE RECORDER, and the raw values survive in @DetailJson.  See the file
header: a demand with a tenant id that does not exist must produce E-50030 and a trail row, not 547.

RETURNS 0 AND NOTHING ELSE.  No result set, no OUTPUT parameter: a caller that wants a verdict rather than a refusal
wants auth.uspCheckPermission (T-085, Phase 6).

========================================================================================================================
Example Usage and Performance:

exec auth.uspDemandPermission @PermissionCode = N'Data.Update', @TenantId = 7;
exec auth.uspDemandPermission @PermissionCode = N'Platform.ManageApplications';          -- no tenant: Platform category
exec auth.uspDemandPermission @PermissionCode = N'Data.Approve', @TenantId = 7, @ObjectName = N'dbo.uspApproveCase';

Granted path: two index seeks inside auth.udfHasPermission, inlined by Froid, and nothing else.  Denied path adds one
seek on auth.Permission, two existence seeks, one insert through the recorder and the error row.  Denials are meant to
be rare; if a dashboard shows them as the common case, that is the finding, not the cost.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-052
Description: Created.

-----------------------------------------------------------------------------------------------------------------------

Date:		2026-09-21
Author:		rsincero
Ticket:		T-126
Description:
G-51.  Split the diagnostic: E-50032 for a session that is signed in with no active profile, which UI-09 ships on
purpose, leaving E-50030's "there is NO SESSION CONTEXT on this connection -- a server-side defect" true of the case
that is actually one.  The number is now decided once, in step 3b, so the trail row's "errorNumber" and the THROW cannot
drift.  "hadSessionContext" in the denial JSON was reporting UserProfileId and now reports UserId; the old fact moved to
"profileSelected".

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspDemandPermission
      @PermissionCode NVARCHAR (100)
    , @TenantId       INT            = NULL
    , @ObjectName     NVARCHAR (256) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 error-only instrumentation. Boilerplate: copy verbatim.
    -- Shorter than the full block by exactly what a procedure that writes nothing does not need. Do
    -- not reintroduce @ExecutionId, @StartTimeUtc, @EndTimeUtc or @Comments -- a start row without a
    -- completion makes every call look like a failure in the monitoring grid, and this is the most
    -- frequently called procedure in the database.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspDemandPermission]')
          , @KeyParameters  NVARCHAR (MAX) = NULL
          , @ContextMessage NVARCHAR (MAX) = NULL
          , @DynamicSql     NVARCHAR (MAX) = NULL
          , @ErrorMsg       NVARCHAR (MAX) = NULL
          , @ErrorProc      NVARCHAR (300) = NULL
          , @ErrorNumber    INT            = NULL
          , @ErrorLine      INT            = NULL;

    DECLARE @ProfileId      INT             = TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT)
          -- Read for ONE purpose: telling a session that has no hat from a connection that has no context. See the
          -- file header. It takes no part in the decision, which is auth.udfHasPermission's alone.
          , @SessionUserId  INT             = TRY_CAST (SESSION_CONTEXT (N'UserId') AS INT)
          , @ApplicationId  INT             = TRY_CAST (SESSION_CONTEXT (N'ApplicationId') AS INT)
          , @Allowed        BIT             = 0
          , @CodeExists     BIT             = 0
          , @TrailTenantId  INT             = NULL
          , @TrailProfileId INT             = NULL
          , @NumberToRaise  INT             = NULL
          , @DetailJson     NVARCHAR (MAX)  = NULL
          , @Failure        NVARCHAR (2000) = NULL;

    -- Identifiers only. A permission code and an object name are both identifiers; there is no free text here.
    SET @KeyParameters = CONCAT (N'PermissionCode=',  @PermissionCode
                               , N', TenantId=',      @TenantId
                               , N', ObjectName=',    @ObjectName
                               , N', UserProfileId=', @ProfileId);

    -- Says why the row this procedure logs has no ExecutionLogId, so the orphan is not read as a lost start row.
    SET @ContextMessage = N'Error-only instrumented check: no start row is opened, so @ExecutionLogId is NULL by '
                        + N'design. A row here is a denial or a defect, never a successful call.';

    BEGIN TRY

        SET @PermissionCode = LTRIM (RTRIM (@PermissionCode));

        -- =========================================================================================
        -- ===== The procedure's own work starts here. Everything above and below is boilerplate. ==
        -- =========================================================================================

        -- 1.  The decision, and the only place one is made. Reads SESSION_CONTEXT ('UserProfileId')
        --     itself and returns 0 when it is absent, so a connection that never called
        --     auth.uspSetSessionContext lands on the denied path with a NULL profile in the trail.
        IF @PermissionCode IS NOT NULL AND LEN (@PermissionCode) > 0
        BEGIN
            SET @Allowed = auth.udfHasPermission (@PermissionCode, @TenantId);
        END;

        -- 1b. The sampled probe.  ONE self-contained block, and the only thing this procedure does
        --     that is not the decision itself.  Delete it in full -- from this comment to the line
        --     marked "end of the sampled probe" -- and the procedure is exactly what it was before
        --     Phase 5: nothing above or below refers to a single one of its variables.  That is the
        --     documented remedy if the config read below is ever measured as too expensive, and the
        --     reason the block is written as one contiguous lump instead of being spread tidily
        --     between the DECLARE section and here.
        --
        --     175_perf_instrumentation.sql supplies logs.PermissionProbe, the recorder, and the two
        --     settings read here; this block does nothing whatever on a database where that file has
        --     not been run, which is why the dependency is a runtime OBJECT_ID guard and not an
        --     install-time assertion.  175's file header carries the design: why the measurement is
        --     a burst rather than a single call, why the sample-rate read is a config SELECT rather
        --     than a SESSION_CONTEXT key or an install-time literal, and what the probe deliberately
        --     does not record.  T-070.
        --
        --     THE PROBE NEVER WRITES INSIDE SOMEBODY ELSE'S TRANSACTION.  @@TRANCOUNT = 0 is the
        --     outermost gate, before even the config read, so a demand made inside a caller's
        --     transaction -- which is most of them, every procedure in 140/145/155/160 demands
        --     before it opens one -- costs nothing at all and is never sampled.  The population the
        --     probe sees is therefore the uncommitted-read population, and that is a stated bias
        --     rather than an accident: those calls are the ones on the latency path a user feels.
        IF @@TRANCOUNT = 0
        BEGIN
            -- The whole cost of the probe when it is switched off: one seek on config.ApplicationSetting.
            DECLARE @ProbeSampleRate INT = TRY_CAST ((SELECT s.SettingValue
                                                        FROM config.ApplicationSetting AS s
                                                       WHERE s.SettingKey = N'Perf.PermissionProbeSampleRate'
                                                         AND s.IsDeleted  = 0) AS INT);

            -- One call in N.  ABS is applied to the REMAINDER and never to CHECKSUM itself: CHECKSUM can
            -- return -2147483648, whose absolute value has no representation in INT, and ABS (CHECKSUM (...))
            -- therefore raises an arithmetic overflow at a rate of roughly one call in four billion -- which
            -- is precisely often enough to be found in production and never in a test.
            IF COALESCE (@ProbeSampleRate, 0) > 0
               AND OBJECT_ID (N'logs.uspRecordPermissionProbe', N'P') IS NOT NULL
               AND ABS (CHECKSUM (NEWID ()) % @ProbeSampleRate) = 0
            BEGIN
                BEGIN TRY
                    DECLARE @ProbeBurst   INT             = TRY_CAST ((SELECT s.SettingValue
                                                                         FROM config.ApplicationSetting AS s
                                                                        WHERE s.SettingKey = N'Perf.PermissionProbeBurstCount'
                                                                          AND s.IsDeleted  = 0) AS INT)
                          , @ProbeIter    INT             = 0
                          , @ProbeSink    BIT             = 0
                          , @ProbeFromUtc DATETIME2 (7)   = NULL
                          , @ProbeToUtc   DATETIME2 (7)   = NULL
                          , @ProbeMicro   BIGINT          = NULL
                          , @ProbeScope   INT             = NULL
                          , @ProbeClosure INT             = NULL
                          , @ProbeDetail  NVARCHAR (MAX)  = NULL
                          , @ProbeId      BIGINT          = NULL;

                    -- A burst outside the recorder's own 2..10000 CHECK would be refused on write; falling
                    -- back to the shipped 25 here means a fat-fingered setting loses its sample rather than
                    -- filling logs.ExecutionLog with E-50191 on the hot path.
                    SET @ProbeBurst = CASE WHEN COALESCE (@ProbeBurst, 0) BETWEEN 2 AND 10000
                                           THEN @ProbeBurst
                                           ELSE 25 END;

                    -- The measured burst.  It includes this WHILE loop's own overhead -- a variable
                    -- assignment and a comparison per iteration -- and that is not subtracted, because the
                    -- number this feeds is a comparison between deployments and between tenant depths, not
                    -- an absolute cost for the function in isolation.  The loop is also why the decision is
                    -- re-taken rather than reused: measuring the call is the entire point.
                    SET @ProbeFromUtc = SYSUTCDATETIME ();

                    WHILE @ProbeIter < @ProbeBurst
                    BEGIN
                        SET @ProbeSink = auth.udfHasPermission (@PermissionCode, @TenantId);
                        SET @ProbeIter = @ProbeIter + 1;
                    END;

                    SET @ProbeToUtc = SYSUTCDATETIME ();
                    SET @ProbeMicro = DATEDIFF_BIG (MICROSECOND, @ProbeFromUtc, @ProbeToUtc);

                    -- The two counts that turn a duration into a data point.  A microsecond figure means
                    -- nothing without the size of the two sets the predicate walks, and taking them here
                    -- rather than at report time is what makes the row still true a month later.
                    SELECT @ProbeScope = COUNT (*)
                      FROM auth.ProfilePermissionScope AS pps
                     WHERE pps.UserProfileId = @ProfileId
                       AND pps.IsDeleted     = 0;

                    IF @TenantId IS NOT NULL
                    BEGIN
                        SELECT @ProbeClosure = COUNT (*)
                          FROM auth.TenantClosure AS tc
                         WHERE tc.AncestorTenantId = @TenantId
                           AND tc.IsDeleted        = 0;
                    END;

                    -- Identifiers, counts and settings only (UI-16). No token, no hash, no free text.
                    SET @ProbeDetail = (SELECT SampleRate     = @ProbeSampleRate
                                             , BurstCount     = @ProbeBurst
                                             , ObjectName     = @ObjectName
                                             , ApplicationId  = @ApplicationId
                                             , InTransaction  = CAST (0 AS BIT)
                                          FOR JSON PATH, WITHOUT_ARRAY_WRAPPER);

                    EXEC logs.uspRecordPermissionProbe
                          @PermissionCode       = @PermissionCode
                        , @BurstCount           = @ProbeBurst
                        , @TotalMicroseconds    = @ProbeMicro
                        , @Allowed              = @Allowed
                        , @TenantId             = @TenantId
                        , @UserProfileId        = @ProfileId
                        , @ScopeRowsForProfile  = @ProbeScope
                        , @ClosureRowsForTenant = @ProbeClosure
                        , @ProbeContext         = N'auth.uspDemandPermission'
                        , @DetailJson           = @ProbeDetail
                        , @PermissionProbeId    = @ProbeId OUTPUT;
                END TRY
                BEGIN CATCH
                    -- SWALLOWED, DELIBERATELY, AND THIS IS THE ONLY CATCH IN THE PROJECT THAT SWALLOWS.
                    -- A measurement that can refuse an authorised request is worse than no measurement:
                    -- this block is instrumentation bolted to the side of the most frequently called
                    -- procedure in the database, and the caller asked whether it may act, not how long
                    -- the asking took. So a missing table, a revoked grant, a full log or a bad setting
                    -- all cost the sample and nothing else.
                    --
                    -- There is no ROLLBACK here and there must not be: this procedure opens no
                    -- transaction of its own anywhere (which is why it can be demanded from inside one),
                    -- the block does not run unless @@TRANCOUNT was already 0, and the recorder rolls
                    -- back its own batch in its own CATCH before re-throwing. A ROLLBACK at this point
                    -- could only ever unwind somebody else's work.
                    SET @ProbeId = NULL;
                END CATCH;
            END;
        END;
        -- ===== end of the sampled probe =====

        IF @Allowed = 1
        BEGIN
            -- The overwhelmingly common path: nothing logged, nothing written, no result set.
            RETURN 0;
        END;

        -- 2.  Refused. Everything from here to the THROW exists to make the refusal reviewable.
        --     Whether the code exists at all is decided AFTER the denial, never before: a demand for
        --     a code no profile can hold is the most useful row this trail can carry, and deciding
        --     the error number first would have lost it on exactly that path.
        SET @CodeExists = CASE WHEN EXISTS (SELECT 1
                                              FROM auth.Permission AS p
                                             WHERE p.PermissionCode = @PermissionCode
                                               AND p.IsDeleted      = 0
                                               AND (@ApplicationId IS NULL
                                                    OR p.ApplicationId = @ApplicationId))
                               THEN 1 ELSE 0 END;

        -- 3.  Sanitize the two ids that are about to meet a foreign key. A tenant id that does not
        --     resolve is a caller defect AND a demand worth recording, so it becomes NULL on the row
        --     and survives verbatim in @DetailJson where no constraint can object to it.
        SET @TrailTenantId = (SELECT t.TenantId FROM auth.Tenant AS t WHERE t.TenantId = @TenantId);

        SET @TrailProfileId = (SELECT up.UserProfileId
                                 FROM auth.UserProfile AS up
                                WHERE up.UserProfileId = @ProfileId);

        -- 3b. The number, decided once and used twice: the "errorNumber" in the JSON below and the
        --     THROW at the end of section 5 must not be able to disagree, and before T-126 they were
        --     two copies of one CASE expression that only happened to agree.
        --
        --     THREE OUTCOMES, NOT TWO -- G-51. E-50030 used to carry both "you do not hold this
        --     permission" and "you are signed in wearing no hat", guessing between them in its
        --     message from @ProfileId IS NULL and calling the second a server-side defect. It is not:
        --     UI-09 ships the profileless session on purpose. The file header has the discriminator
        --     and the two hours SCEN-AUTH-001 lost to the wrong message.
        --
        --     50031 WINS WHEN BOTH APPLY, deliberately. A demand for a code that does not exist is an
        --     application defect -- a feature guarded by a permission nobody can hold -- and it is
        --     true for every caller, hat or no hat. Reporting the caller's missing profile instead
        --     would hide a permanent defect behind a transient state.
        SET @NumberToRaise = CASE WHEN @CodeExists = 0                                   THEN 50031
                                  WHEN @SessionUserId IS NOT NULL AND @ProfileId IS NULL THEN 50032
                                  ELSE 50030 END;

        -- Shape, never material: identifiers, flags and the numbers. STRING_ESCAPE because a
        -- permission code and an object name arrive as parameters and a stray quote would produce
        -- JSON that CK_logs_AuthorizationDenial_DetailJson refuses -- which would cost the trail row.
        SET @DetailJson = CONCAT (N'{"raisedBy":"auth.uspDemandPermission"'
                                , N',"errorNumber":',      CAST (@NumberToRaise AS NVARCHAR (11))
                                , N',"permissionCode":"',  STRING_ESCAPE (COALESCE (@PermissionCode, N''), 'json'), N'"'
                                , N',"codeExistsInApplication":', CASE WHEN @CodeExists = 1 THEN N'true' ELSE N'false' END
                                , N',"requestedTenantId":', COALESCE (CAST (@TenantId AS NVARCHAR (11)), N'null')
                                , N',"tenantIdResolved":',  CASE WHEN @TrailTenantId IS NOT NULL THEN N'true' ELSE N'false' END
                                , N',"sessionProfileId":',  COALESCE (CAST (@ProfileId AS NVARCHAR (11)), N'null')
                                , N',"sessionUserId":',     COALESCE (CAST (@SessionUserId AS NVARCHAR (11)), N'null')
                                -- Answers its own name from T-126 onwards. It used to report @ProfileId, so a
                                -- profileless session -- which HAS context -- looked on every dashboard exactly like a
                                -- procedure reached with none, and that conflation is gap G-51. The old fact is now
                                -- "profileSelected", where it says what it means.
                                , N',"hadSessionContext":', CASE WHEN @SessionUserId IS NOT NULL THEN N'true' ELSE N'false' END
                                , N',"profileSelected":',   CASE WHEN @ProfileId IS NOT NULL THEN N'true' ELSE N'false' END
                                , N',"applicationId":',     COALESCE (CAST (@ApplicationId AS NVARCHAR (11)), N'null')
                                , N'}');

        -- 4.  The trail, in a nested TRY that swallows. Nothing the recorder can do may replace the
        --     number the caller has to branch on. A swallowed failure is not a silent one: the
        --     recorder is fully instrumented and wrote its own logs.ExecutionLog error row first.
        BEGIN TRY
            EXEC logs.uspRecordAuthorizationDenial
                  @PermissionCode = @PermissionCode
                , @TenantId       = @TrailTenantId
                , @UserProfileId  = @TrailProfileId
                , @ObjectName     = @ObjectName
                , @DetailJson     = @DetailJson;
        END TRY
        BEGIN CATCH
            -- Recorded on this procedure's own error row, below, rather than re-raised.
            SET @ContextMessage = @ContextMessage
                                + N' logs.uspRecordAuthorizationDenial FAILED and the failure was swallowed so that it '
                                + N'could not replace the permission error: ' + ERROR_MESSAGE ();
        END CATCH;

        -- 5.  The number. All three messages name the permission and the tenant, per section 14.2,
        --     and each is built into a variable because THROW takes a constant or a variable and
        --     never an expression. Which one is raised was settled in 3b; these branches only phrase
        --     it, so the trail row and the exception can never disagree about what happened.
        IF @NumberToRaise = 50031
        BEGIN
            SET @Failure = N'Permission ''' + COALESCE (@PermissionCode, N'(none supplied)')
                         + N''' does not exist in this application'
                         + COALESCE (N' (ApplicationId ' + CAST (@ApplicationId AS NVARCHAR (11)) + N')', N'')
                         + N'. The demand was refused and recorded in logs.AuthorizationDenial first. This is an '
                         + N'APPLICATION DEFECT, not a user''s problem: a procedure is guarding a feature with a code '
                         + N'no profile can ever hold, so the feature is unreachable and no test noticed. Check the '
                         + N'spelling against auth.Permission, and check that 115_seed_reference_data.sql has run for '
                         + N'this application. Show a generic error and log it (section 14.5).';

            ;THROW 50031, @Failure, 1;
        END;

        -- Signed in, no hat. UI-09's supported state, and the reason it needs its own number is that the
        -- remedy is a screen rather than a fix: nothing is broken, the user has simply not put a hat on.
        IF @NumberToRaise = 50032
        BEGIN
            SET @Failure = N'No profile is active on this connection, so there is nothing for a permission to be held '
                         + N'BY: ''' + @PermissionCode + N''' was demanded'
                         + COALESCE (N' at tenant ' + CAST (@TenantId AS NVARCHAR (11)), N'')
                         + N' and the session (UserId ' + CAST (@SessionUserId AS NVARCHAR (11)) + N') is signed in '
                         + N'without one. THIS IS NOT A DEFECT AND NOT A LOST SESSION: UI-09 ships the profileless '
                         + N'session deliberately -- a user who registered externally, or whose only profile was just '
                         + N'deactivated -- and auth.uspSetSessionContext leaves UserProfileId unset for it on '
                         + N'purpose. The remedy is a hat, not a password: call auth.uspListMyProfiles, which demands '
                         + N'no permission and is built for exactly this caller, and then auth.uspSwitchProfile ON A '
                         + N'NEW CONNECTION (UI-06). If the list comes back empty the user has no profile at all and '
                         + N'somebody must create one. Recorded in logs.AuthorizationDenial. Show the profile chooser '
                         + N'and do NOT sign the user out (section 14.5).';

            ;THROW 50032, @Failure, 1;
        END;

        -- 50030, and @ProfileId IS NULL here now MEANS what the second half of this message says it does:
        -- the profileless session left through 50032 above, so the only way to reach this line without a
        -- profile is to reach it without a session context at all.
        SET @Failure = N'Permission denied: '''  + @PermissionCode + N''' is required'
                     + COALESCE (N' at tenant ' + CAST (@TenantId AS NVARCHAR (11)), N' (no tenant supplied, which a '
                     + N'tenant-scoped permission always refuses -- the parameter is optional only for the Platform '
                     + N'category)')
                     + N' and the active profile does not hold it'
                     + COALESCE (N' (UserProfileId ' + CAST (@ProfileId AS NVARCHAR (11)) + N')'
                               , N'. There is NO SESSION CONTEXT on this connection, which means this procedure was '
                               + N'reached without auth.uspSetSessionContext having run -- a server-side defect, not a '
                               + N'permission problem')
                     + N'. Recorded in logs.AuthorizationDenial. Show a permission message and do NOT sign the user '
                     + N'out (section 14.5).';

        ;THROW 50030, @Failure, 1;

        -- =========================================================================================
        -- ===== End of the procedure's own work. ==================================================
        -- =========================================================================================

    END TRY
    BEGIN CATCH

        SELECT @ErrorNumber = ERROR_NUMBER ()
             , @ErrorProc   = ERROR_PROCEDURE ()
             , @ErrorLine   = ERROR_LINE ()
             , @ErrorMsg    = ERROR_MESSAGE ()
                            + N' (error '  + CAST (ERROR_NUMBER () AS NVARCHAR (11))
                            + N', line '   + CAST (ERROR_LINE ()   AS NVARCHAR (11)) + N')';

        -- No rollback. This procedure opens no transaction, and a caller's transaction is not its to
        -- end -- E-50030 inside a caller's transaction dooms it, and the caller's own CATCH is what
        -- unwinds it.
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

        -- Bare, so 50030 and 50031 reach the caller unchanged. The whole design depends on the UI
        -- being able to branch on them; RAISERROR would flatten both to 50000. The leading semicolon
        -- is required.
        ;THROW;

    END CATCH;

    RETURN 0;
END;
GO


-- *** 2. auth.uspGetProfileContext ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspGetProfileContext
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Everything a persistent page header needs, in ONE row: display name, user name, profile name, tenant name, the tenant's
full path from the root, the tenant type label, how many profiles the user could switch to, whether the session is on the
platform-administrator bypass route, and -- gap G-12 -- how many days until the caller's password expires together with
the flag that says it is time to say so.  Section 13.4.  Demands no permission.

========================================================================================================================
Requirements and Key Dependencies:

auth.[User], auth.UserProfile, auth.UserCredential, auth.UserSession, auth.vwTenantHierarchy,
auth.udfIsTenantUsable, config.ApplicationSetting (Authn.PasswordExpiryWarningDays, G-12), auth.uspSetSessionContext,
logs.uspRecordExecutionError.  Granted to applicationRole.

========================================================================================================================
Notes:

THIS PROCEDURE IS THE REQUIREMENT'S OWN GOTCHA, ANSWERED.  UI-01, the first row of the UI Gotchas workbook, quotes it:
"I have seen UIs where your username or userid was not even displayed anywhere in the application. This oversight
shouldn't be duplicated for newer applications."  Every column below exists so that a UI has no excuse.

THE TENANT PATH MATTERS MORE THAN THE TENANT NAME.  Section 13.4: "Root > Agency > Land Management > Hazardous Waste".
In the section 17 Variant 2 shape the program names are not unique-sounding, and a user with several profiles needs to see
which BRANCH they are in, not just the leaf.  TenantPath comes from auth.vwTenantHierarchy rather than being rebuilt here,
so there is one definition of what a path looks like and the tenant-read procedures and this one cannot disagree.

NO PERMISSION IS DEMANDED, and that is not an oversight.  The answer is entirely about the CALLER -- their own name,
their own profile, their own tenant -- and a permission test would be asking whether you may know who you are.  The
session hash is the authority: without a live one there is no row to return and auth.uspSetSessionContext refuses first.

SwitchableProfileCount COUNTS WHAT auth.uspSwitchProfile WOULD ACCEPT, which is narrower than "profiles this user has":
active, not deleted, at a usable tenant, in the session's application.  A header that offered a switcher listing three
organizations of which two are suspended would send the user into E-50021 after the click -- the UI-33 mistake, made in
the one place every page renders.  The count INCLUDES the current profile, so > 1 is the test for "show the switcher".

ElevatedUntilUtc AND MfaSatisfied ARE RETURNED so the header can show a step-up countdown and a lock icon.  Neither is a
secret and both are about the caller's own session; ElevatedUntilUtc is what auth.uspSwitchProfile's E-50052 test reads.

IsBypassRoute IS RETURNED AND MUST BE VISIBLE.  Section 6.3: the platform-administrator bypass exists so the product
can be supported when a tenant's own federation is broken, and a support engineer who has forgotten they are on it is
the exact hazard the flag defends against.  The design asks for it by name in 13.4's column list.

PasswordExpiresInDays AND PasswordExpiryWarning ARE HERE BECAUSE THE HEADER IS THE ONLY PLACE A USER LOOKS EVERY DAY --
G-12.  025_config_tables.sql's description of Authn.PasswordExpiryWarningDays names this procedure and these two column
names, so the setting promised them before anything returned them; this is the half that keeps the promise.  The window is
resolved from the setting on every call rather than cached, because a deployment that lengthens the warning from 14 days
to 30 expects the next page load to say so.

  PasswordExpiresInDays is DATEDIFF (DAY, now, ExpiresUtc), and it is returned WHETHER OR NOT the warning is on, so a
  profile page can show "expires in 62 days" without a second call.  NULL for a user with no live credential and for a
  credential with no ExpiresUtc -- which is every credential until a project sets Authn.PasswordLifetimeDays above 0.
  NULL means "there is nothing to count down to", and a UI must not read it as zero.

  PasswordExpiryWarning is 1 only inside the window: the credential has an ExpiresUtc, the setting is above 0, and the
  remaining days are at or below it.  It goes to 1 when the countdown reaches the threshold and STAYS 1 once the expiry
  has passed -- a negative PasswordExpiresInDays with the flag still up is the state between the deadline and the next
  run of auth.uspExpireCredentials, and a header that dropped the warning in that gap would go quiet at the one moment
  the user most needs to act.  MustChangePassword is the flag that tells the UI to stop asking and start blocking; the
  two are different questions and both are in this row.

A NEGATIVE COUNT IS NOT AN ERROR AND IS NOT CLAMPED.  auth.uspExpireCredentials is a batched sweep, so a credential can
be past its ExpiresUtc for as long as it takes the next run, and -3 says exactly that to a support engineer reading a
screenshot.  Clamping to 0 would hide the sweep's own lateness, which is the thing worth seeing.

NO PERMISSION AND NO SECRET.  Both columns are about the caller's own credential and neither is any part of it: a date
and a count, never the verifier, never the history, never a hash -- UI-16.  Nothing here reveals whether the password is
strong or what it was.

ERROR-ONLY INSTRUMENTED.  Called on every page load; a start row per render would make logs.ExecutionLog unreadable.

========================================================================================================================
Example Usage and Performance:

exec auth.uspGetProfileContext @SessionTokenHash = 0x9F86...;

One seek per base table and one count. auth.vwTenantHierarchy is the only recursive part and it is bounded by the tenant
depth, not by the user population.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-083
Description:
Created.  Phase 6.

Date:		2026-09-21
Author:		rsincero
Ticket:		G-12
Description:
Added PasswordExpiresInDays and PasswordExpiryWarning, the two column names 025_config_tables.sql's description of
Authn.PasswordExpiryWarningDays had been promising since the setting was seeded.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspGetProfileContext
      @SessionTokenHash VARBINARY (32)
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation, READ variant: error-only. No start row is opened.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspGetProfileContext]')
          , @KeyParameters  NVARCHAR (MAX) = NULL
          , @ContextMessage NVARCHAR (MAX) = NULL
          , @DynamicSql     NVARCHAR (MAX) = NULL
          , @ErrorMsg       NVARCHAR (MAX) = NULL
          , @ErrorProc      NVARCHAR (300) = NULL
          , @ErrorNumber    INT            = NULL
          , @ErrorLine      INT            = NULL;

    DECLARE @UserId         INT = NULL
          , @UserProfileId  INT = NULL
          , @ActingTenantId INT = NULL
          , @ApplicationId  INT = NULL
          -- G-12. 0 means "never warn", which is also what an absent or unparseable setting has to mean: a header
          -- that started nagging every user because somebody typed "fourteen" into a settings screen would be a
          -- worse failure than one that stayed quiet.
          , @WarningDays    INT = 0
          , @Now            DATETIME2 (3) = SYSUTCDATETIME ();

    -- The HASH is never logged, not even in part: it is the session credential's only representation in this database
    -- and a prefix of it is still a prefix of a credential. UI-16.
    SET @KeyParameters  = N'SessionTokenHash=(32 bytes, not logged)';
    SET @ContextMessage = N'Error-only instrumented read: no start row is opened, so @ExecutionLogId is NULL by design.';

    BEGIN TRY

        -- =========================================================================================
        -- ===== The procedure's own work starts here. Everything above and below is boilerplate. ==
        -- =========================================================================================

        -- This is the authority. E-50100 for a malformed hash, E-50020 for a session that has ended, E-50021 for a
        -- profile whose tenant has become unusable -- all three thrown from there, all three in the range section 14.5
        -- has the UI sign the user out on.
        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        SET @UserProfileId  = TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT);
        SET @ActingTenantId = TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT);

        SELECT @UserId        = s.UserId
             , @ApplicationId = s.ApplicationId
          FROM auth.UserSession AS s
         WHERE s.SessionTokenHash = @SessionTokenHash
           AND s.EndedUtc         IS NULL
           AND s.IsDeleted        = 0;

        -- G-12. Read on every call and not cached: lengthening the window is expected to take effect on the next page
        -- load, and this is one seek on a table with a handful of rows. TRY_CAST and COALESCE for the reason in the
        -- declaration above.
        SET @WarningDays = COALESCE (TRY_CAST ((SELECT cs.SettingValue
                                                  FROM config.ApplicationSetting AS cs
                                                 WHERE cs.SettingKey = N'Authn.PasswordExpiryWarningDays'
                                                   AND cs.IsDeleted  = 0) AS INT), 0);

        SELECT u.UserId
             , u.UserName
             , u.DisplayName
             , u.Email
             , u.IsPlatformAdmin
             , u.MustChangePassword
             -- G-12. NULL when there is nothing to count down to -- no live credential, or a credential with no
             -- ExpiresUtc because Authn.PasswordLifetimeDays is still 0. NOT clamped at zero: a negative count is the
             -- interval between the deadline and the next run of auth.uspExpireCredentials, and it is worth seeing.
             , CASE WHEN cr.ExpiresUtc IS NULL THEN NULL
                    ELSE DATEDIFF (DAY, @Now, cr.ExpiresUtc) END      AS PasswordExpiresInDays
             -- 1 inside the window and 1 after the deadline too, because the sweep is batched and a warning that
             -- disappeared at the moment it came true would be the worst possible behaviour. See the header note.
             , CAST (CASE WHEN cr.ExpiresUtc IS NOT NULL
                           AND @WarningDays   > 0
                           AND DATEDIFF (DAY, @Now, cr.ExpiresUtc) <= @WarningDays
                          THEN 1 ELSE 0 END AS BIT)                   AS PasswordExpiryWarning
             , cr.ExpiresUtc                                          AS PasswordExpiresUtc
             , up.UserProfileId
             , up.ProfileName
             , up.IsDefault                              AS IsDefaultProfile
             , th.TenantId                               AS ActingTenantId
             , th.TenantCode                             AS ActingTenantCode
             , th.TenantName                             AS ActingTenantName
             , th.TenantPath                             AS ActingTenantPath
             , th.TenantTypeCode                         AS ActingTenantTypeCode
             , th.TenantTypeName                         AS ActingTenantTypeName
             , th.Depth                                  AS ActingTenantDepth
             , th.RootTenantId
             , th.ApplicationCode
             -- What SESSION_CONTEXT ('AppUser') holds, returned so a support engineer reading a
             -- logs.ExecutionLog row can match it to a screenshot of the header without a join. Section 14.4.
             , CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)) AS AppUser
             , s.UserSessionId
             , s.StartedUtc                              AS SessionStartedUtc
             , s.LastSeenUtc                             AS SessionLastSeenUtc
             , s.AbsoluteExpiryUtc
             , s.IdleExpiryUtc
             , s.ElevatedUntilUtc
             , s.MfaSatisfied
             , s.AuthenticationMethod
             , s.IsBypassRoute
             -- Counts what auth.uspSwitchProfile would ACCEPT, not what the user merely has: active, live, at a usable
             -- tenant, in this session's application. Includes the current profile, so > 1 means "show the switcher".
             -- UI-33 is the mistake this avoids.
             , (SELECT COUNT (*)
                  FROM auth.UserProfile AS p2
                  JOIN auth.Tenant      AS t2 ON t2.TenantId = p2.TenantId AND t2.IsDeleted = 0
                 WHERE p2.UserId        = u.UserId
                   AND p2.IsDeleted     = 0
                   AND p2.IsActive      = 1
                   AND t2.ApplicationId = @ApplicationId
                   AND auth.udfIsTenantUsable (p2.TenantId) = 1) AS SwitchableProfileCount
          FROM auth.[User] AS u
          JOIN auth.UserProfile AS up
            ON up.UserProfileId = @UserProfileId
           AND up.IsDeleted     = 0
          JOIN auth.vwTenantHierarchy AS th
            ON th.TenantId = up.TenantId
          JOIN auth.UserSession AS s
            ON s.SessionTokenHash = @SessionTokenHash
           AND s.EndedUtc         IS NULL
           AND s.IsDeleted        = 0
          -- LEFT JOIN, and it has to be: a federated-only user has no credential row at all and still needs a page
          -- header. An INNER JOIN here would have turned "this user signs in with SSO" into an empty result set,
          -- which every caller would read as an ended session. auth.uspGetPasswordChangeContext (110) took the same
          -- decision for the same reason. UX_auth_UserCredential_UserType makes it one seek.
          LEFT JOIN auth.UserCredential AS cr
            ON cr.UserId    = u.UserId
           AND cr.IsDeleted = 0
         WHERE u.UserId    = @UserId
           AND u.IsDeleted = 0;

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


-- *** 3. auth.uspGetNavigationForProfile ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspGetNavigationForProfile
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

The whole navigable tree for the session's active profile, in one round trip, with CanView and CanEdit per element.
Elements the profile cannot view are OMITTED ENTIRELY.  Section 13.2.  Demands no permission -- the permissions ARE the
answer.

========================================================================================================================
Requirements and Key Dependencies:

auth.UiElement, auth.UiElementPermission, auth.ProfilePermissionScope, auth.TenantClosure, auth.UserSession,
config.ApplicationSetting (Ui.CatalogueVersion, G-18), auth.uspSetSessionContext, logs.uspRecordExecutionError.
Granted to applicationRole.

========================================================================================================================
Notes:

THE CONTRACT THE UI PROJECT BINDS TO.  Section 13.3, UI-02: "Bind to element codes and the two booleans. Never to role
names, never to tenant names, never to permission codes directly."  if (nav["Command.ApproveCase"].CanEdit), never
if (user.IsInRole("Approver")).  ElementCode and the two bits are therefore the load-bearing columns and everything else
in the result set is presentation.  No permission code appears in the output at all, deliberately: a UI that could see
them would eventually branch on them, and then a county redefining its own role structure would need a UI change.

VIEWABILITY IS INHERITED DOWN THE TREE, NOT RECOMPUTED PER ROW.  The recursive CTE starts at the Areas and only descends
into a child whose parent was already admitted, so a Command survives exactly when itself AND every ancestor of it is
viewable.  Computing each row independently and filtering afterwards would leave orphans -- a button whose screen was
pruned -- and the UI would either crash or draw it at the root.  CK_auth_UiElement_AreaHasNoParent guarantees the anchor
is exactly the Areas, and CK_auth_UiElement_ElementType bounds the depth at five, so MAXRECURSION's default of 100 is
never approached.

AN ELEMENT WITH NO PERMISSION ROW IS VISIBLE TO EVERYONE.  Section 13.1, and it is stated in the predicate rather than
left implicit: "NOT EXISTS any View mapping" OR "holds one of them".  That is the right default for a home page and the
wrong one for everything else, which is why 950_verify_deployment.sql warns about unmapped elements instead of this
procedure silently hiding them -- hiding them would make a cataloguing omission look like a permission decision.

CanEdit HAS NO INHERITANCE AND NO DEFAULT.  An element with no Edit mapping is NOT editable, which is the opposite of the
View rule and is deliberate: "nobody said who may look" sensibly means "anyone", and "nobody said who may change"
sensibly means "nobody".  CanEdit = 0 with CanView = 1 is the read-only case and it is the common one.

PERMISSIONS ARE TESTED AT THE ACTING TENANT VIA THE CLOSURE, WHICH IS WHY auth.ProfilePermissionScope IS JOINED DIRECTLY
rather than auth.udfHasPermission being called per element.  udfHasPermission is a scalar function and the natural way to
write this would put it inside a correlated EXISTS evaluated once per element per permission mapping; joining the derived
scope table once gives the optimiser a set to work with instead.  The semantics are identical -- a grant at an ancestor
covers the descendant, which is what auth.TenantClosure is for -- and §10.6 is the measurement that says so.

@ElementCodePrefix IS A CONVENIENCE, NOT A SECURITY BOUNDARY.  It narrows the payload for a UI that only wants one Area's
subtree.  It is applied to the ANCHOR only, so the subtree beneath the match still arrives intact; narrowing every level
would return an Area with no children.

ERROR-ONLY INSTRUMENTED, like the other two reads here.

@AssumeUserProfileId EXISTS FOR ONE CALLER -- auth.uspSwitchProfile -- AND IT IS THE REASON SECTION 12.1 STEP 7 WORKS
NULL, the default, is the ordinary behaviour: establish context from the token and read the profile out of it.

Supplied, the procedure does NOT call auth.uspSetSessionContext, and reads the navigation for the profile named instead.
That is not a shortcut, it is the only possible implementation.  SESSION_CONTEXT keys are read-only for the life of a
connection (sp_set_session_context @read_only = 1, error 15664), so on the connection that has just switched profiles the
context still names the OLD profile and CANNOT be replaced -- every attempt raises E-50022.  A navigation read that
insisted on going through session context would therefore either fail outright or answer for the profile the caller has
just stopped wearing, and both of those were observed before this parameter existed (G-36).

The session credential is still the authority: the hash is looked up in auth.UserSession exactly as before, and
@AssumeUserProfileId is accepted only when it names a live profile belonging to THAT session's user -- E-50050, the same
number and the same rationale as auth.uspSwitchProfile's own ownership test (D-10: a switch is never impersonation, and
"not yours" and "does not exist" are deliberately indistinguishable).  So the parameter widens what a caller may ask
about by exactly nothing: any profile it accepts is one the caller could have switched into and then asked about.

The acting tenant comes from the named profile's own TenantId rather than from context, for the same reason.

@ExpectedCatalogueVersion IS THE CATALOGUE CONTRACT, ASSERTED BY THE DATABASE BECAUSE AN ASSERTION THE CALLER MAY SKIP
IS ADVICE.  G-18.  115_seed_reference_data.sql computes config.ApplicationSetting's Ui.CatalogueVersion as
<elements>.<triples>.<16 hex of SHA-256> over the live (ElementCode, PermissionCode, AccessMode) triples; the application
reads it at start-up, and passes the value it was BUILT against here.  A disagreement is E-50230 and NOTHING is returned.

Refusing the read rather than warning about it is the whole point.  The failure this catches is a UI binding to
"Command.ApproveCase" against a database where that element was renamed or newly gated: navigation comes back missing the
element, the UI draws nothing where a button belongs, and the bug presents as a permission problem in a completely
different part of the system.  Half a catalogue is worse than no catalogue, because it looks like an answer.

NULL means NOT ASSERTED, and that is the shipped default, so every existing caller keeps working unchanged.  That is a
deliberate weakening: a project that never passes the parameter gets no protection at all.  The alternative -- making it
mandatory -- would have broken auth.uspSwitchProfile, 950_verify_deployment.sql and every test in one stroke, and a
control that cannot be adopted incrementally does not get adopted.  Section 13.1 states the obligation on the UI side.

The check is global rather than per application, because config.ApplicationSetting is not scoped to an application and
Ui.CatalogueVersion is computed for the TEMPLATE application only.  A deployment that seeds a SECOND application's
catalogue therefore has one version string covering one of them; that is recorded as the stated limit rather than
papered over, and the fix if a project needs it is a per-application key, not a per-application procedure.

ERROR NUMBERS THIS ADDS: E-50050, and only on the @AssumeUserProfileId path; E-50230, and only when
@ExpectedCatalogueVersion is supplied.

========================================================================================================================
Example Usage and Performance:

exec auth.uspGetNavigationForProfile @SessionTokenHash = 0x9F86...;
exec auth.uspGetNavigationForProfile @SessionTokenHash = 0x9F86..., @ElementCodePrefix = N'Area.Cases';
exec auth.uspGetNavigationForProfile @SessionTokenHash = 0x9F86..., @AssumeUserProfileId = 91;  -- uspSwitchProfile only

-- What the application does on every navigation read once it has adopted G-18. The string comes from its own
-- configuration, written there by the build, and is NOT read out of this database first -- reading it from here and
-- then comparing it to itself asserts nothing.
exec auth.uspGetNavigationForProfile @SessionTokenHash = 0x9F86..., @ExpectedCatalogueVersion = N'26.28.4f1c0a9b2d7e5638';

-- And how to find the value to compile against:
select SettingValue from config.ApplicationSetting where SettingKey = N'Ui.CatalogueVersion' and IsDeleted = 0;

One pass over auth.UiElement per level, with two semi-joins into the derived scope. Cardinality is the catalogue, which
is tens of rows, not the user population. The G-18 check adds one seek on UX_config_ApplicationSetting_SettingKey when
asserted and one NULL comparison when not.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-084
Description:
Created.  Phase 6.  Closes the forward reference auth.uspSwitchProfile has carried since T-078.

Date:		2026-09-20
Author:		rsincero
Ticket:		T-091
Description:
Added @AssumeUserProfileId.  auth.uspSwitchProfile could not return its second result set at all: it re-established
session context after committing the switch, and the keys are read-only, so every call raised E-50022 AFTER the switch
had already happened.  G-36, BL-057.

Date:		2026-09-21
Author:		rsincero
Ticket:		T-111
Description:
Added @ExpectedCatalogueVersion and E-50230, closing G-18.  The element catalogue was a published interface with no
version on it: a UI compiled against one catalogue and run against another was told nothing, and the symptom was a
missing screen rather than an error.  The version itself is computed by 115_seed_reference_data.sql; this is the end
that refuses to answer when it does not match.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspGetNavigationForProfile
      @SessionTokenHash    VARBINARY (32)
    , @ElementCodePrefix   NVARCHAR (200) = NULL
    , @AssumeUserProfileId INT            = NULL
      -- G-18. Appended at the END of the list rather than inserted next to @ElementCodePrefix where it reads better,
      -- because a positional caller -- a test, a script, an older build -- would otherwise start passing its prefix
      -- into this parameter and get E-50230 for its trouble. Parameter ORDER is part of a shipped contract too.
    , @ExpectedCatalogueVersion NVARCHAR (100) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation, READ variant: error-only. No start row is opened.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspGetNavigationForProfile]')
          , @KeyParameters  NVARCHAR (MAX) = NULL
          , @ContextMessage NVARCHAR (MAX) = NULL
          , @DynamicSql     NVARCHAR (MAX) = NULL
          , @ErrorMsg       NVARCHAR (MAX) = NULL
          , @ErrorProc      NVARCHAR (300) = NULL
          , @ErrorNumber    INT            = NULL
          , @ErrorLine      INT            = NULL;

    DECLARE @UserProfileId  INT             = NULL
          , @ActingTenantId INT             = NULL
          , @ApplicationId  INT             = NULL
          , @SessionUserId  INT             = NULL
          , @LiveCatalogueVersion NVARCHAR (100) = NULL
          , @Failure        NVARCHAR (2000) = NULL;

    SET @KeyParameters  = CONCAT (N'SessionTokenHash=(32 bytes, not logged), ElementCodePrefix='
                                , COALESCE (@ElementCodePrefix, N'(whole tree)')
                                , N', AssumeUserProfileId='
                                , COALESCE (CAST (@AssumeUserProfileId AS NVARCHAR (11)), N'(session context)')
                                  -- A catalogue digest is not a secret: it is a count and a hash of PUBLISHED element
                                  -- codes, and the failure is unreadable without it.
                                , N', ExpectedCatalogueVersion='
                                , COALESCE (@ExpectedCatalogueVersion, N'(not asserted)'));
    SET @ContextMessage = N'Error-only instrumented read: no start row is opened, so @ExecutionLogId is NULL by design.';

    BEGIN TRY

        -- =========================================================================================
        -- ===== The procedure's own work starts here. Everything above and below is boilerplate. ==
        -- =========================================================================================

        -- G-18: the catalogue contract check, and it runs BEFORE the session is resolved on purpose. A caller whose
        -- build disagrees with the catalogue is broken for every session it will ever open, so there is nothing to be
        -- learned by validating its token first, and failing fast puts the real fault at the top of the log instead of
        -- behind a token error. Cost when not asserted is one comparison against NULL.
        IF @ExpectedCatalogueVersion IS NOT NULL
        BEGIN
            -- Blank is NOT "do not assert". Omitting the parameter is how a caller says that; supplying whitespace is
            -- how a caller says "assert against the value in my configuration" while its configuration is empty, and
            -- treating that as consent would turn a misconfigured deployment into a silently unchecked one.
            SET @ExpectedCatalogueVersion = NULLIF (LTRIM (RTRIM (@ExpectedCatalogueVersion)), N'');

            SELECT @LiveCatalogueVersion = s.SettingValue
              FROM config.ApplicationSetting AS s
             WHERE s.SettingKey = N'Ui.CatalogueVersion'
               AND s.IsDeleted  = 0;

            IF @ExpectedCatalogueVersion IS NULL
               OR @LiveCatalogueVersion   IS NULL
               OR @LiveCatalogueVersion  <> @ExpectedCatalogueVersion
            BEGIN
                SET @Failure = CONCAT (N'The UI element catalogue in this database is not the one this build was '
                                     , N'compiled against. Expected '
                                     , COALESCE (QUOTENAME (@ExpectedCatalogueVersion, N''''), N'(blank)')
                                     , N', database holds '
                                     , COALESCE (QUOTENAME (@LiveCatalogueVersion, N''''), N'(the key Ui.CatalogueVersion '
                                                                                         + N'is absent)')
                                     , N'. Nothing was returned: navigation built from a catalogue the build does not '
                                     , N'know is navigation with missing screens or dead commands in it. Either deploy '
                                     , N'the matching build, or re-run 115_seed_reference_data.sql if the catalogue was '
                                     , N'extended and the version was never recomputed. G-18, section 13.1.');
                ;THROW 50230, @Failure, 1;
            END;
        END;

        IF @AssumeUserProfileId IS NULL
        BEGIN
            EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

            SET @UserProfileId  = TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT);
            SET @ActingTenantId = TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT);

            -- The catalogue is per application, and the session's application is the one whose catalogue applies. Taken
            -- from session context rather than re-read from auth.UserSession or derived from the tenant:
            -- uspSetSessionContext has just set it read-only from the session row, so it is both cheaper and impossible
            -- to disagree with the profile and tenant read on the two lines above.
            SET @ApplicationId = TRY_CAST (SESSION_CONTEXT (N'ApplicationId') AS INT);
        END
        ELSE
        BEGIN
            -- The auth.uspSwitchProfile path. No uspSetSessionContext call is possible here -- the keys are read-only
            -- and still name the profile the caller has just stopped wearing, so the call would raise E-50022 (G-36).
            -- The session row is therefore read directly, and it is still the whole authority: an unknown or ended
            -- session resolves nothing and falls into E-50050 below, exactly as an unowned profile does.
            SELECT @SessionUserId = s.UserId
                 , @ApplicationId = s.ApplicationId
              FROM auth.UserSession AS s
             WHERE s.SessionTokenHash = @SessionTokenHash
               AND s.EndedUtc         IS NULL
               AND s.IsDeleted        = 0;

            SELECT @UserProfileId  = up.UserProfileId
                 , @ActingTenantId = up.TenantId
              FROM auth.UserProfile AS up
             WHERE up.UserProfileId = @AssumeUserProfileId
               AND up.UserId        = @SessionUserId
               AND up.IsDeleted     = 0;

            IF @UserProfileId IS NULL
            BEGIN
                SET @Failure = N'That profile does not belong to your user. @AssumeUserProfileId names a profile the '
                             + N'session''s own user does not hold, or no profile at all -- the two are deliberately '
                             + N'indistinguishable (D-10), so the parameter cannot be used to enumerate profile ids. '
                             + N'Nothing was returned.';
                ;THROW 50050, @Failure, 1;
            END;
        END;

        -- Resolved ONCE into a set, rather than auth.udfHasPermission being called per element: the closure join is what
        -- makes a grant at an ancestor cover the acting tenant, and it is the same rule auth.tvfPermissionScope applies.
        WITH HeldPermission AS
        (
            SELECT DISTINCT pps.PermissionId
              FROM auth.ProfilePermissionScope AS pps
             INNER JOIN auth.TenantClosure     AS tc
                ON tc.AncestorTenantId   = pps.ScopeTenantId
               AND tc.DescendantTenantId = @ActingTenantId
               AND tc.IsDeleted          = 0
             WHERE pps.UserProfileId = @UserProfileId
               AND pps.IsDeleted     = 0
        )
        , Viewable AS
        (
            SELECT e.UiElementId
                 , e.ElementCode
                 , e.ElementType
                 , e.ParentUiElementId
                 , e.DisplayLabel
                 , e.SortOrder
                 , Depth = 1
                 -- The two rules, stated side by side because they are deliberately different. View: unmapped means
                 -- everyone (section 13.1). Edit: unmapped means nobody.
                 , CanEdit = CAST (CASE WHEN EXISTS (SELECT 1
                                                       FROM auth.UiElementPermission AS uep
                                                      INNER JOIN HeldPermission      AS hp
                                                         ON hp.PermissionId = uep.PermissionId
                                                      WHERE uep.UiElementId = e.UiElementId
                                                        AND uep.AccessMode  = N'Edit'
                                                        AND uep.IsDeleted   = 0)
                                        THEN 1 ELSE 0 END AS BIT)
              FROM auth.UiElement AS e
             WHERE e.IsDeleted         = 0
               AND e.ApplicationId     = @ApplicationId
               AND e.ParentUiElementId IS NULL
               AND (@ElementCodePrefix IS NULL OR e.ElementCode LIKE @ElementCodePrefix + N'%')
               AND (NOT EXISTS (SELECT 1
                                  FROM auth.UiElementPermission AS uep
                                 WHERE uep.UiElementId = e.UiElementId
                                   AND uep.AccessMode  = N'View'
                                   AND uep.IsDeleted   = 0)
                    OR EXISTS (SELECT 1
                                 FROM auth.UiElementPermission AS uep
                                INNER JOIN HeldPermission      AS hp
                                   ON hp.PermissionId = uep.PermissionId
                                WHERE uep.UiElementId = e.UiElementId
                                  AND uep.AccessMode  = N'View'
                                  AND uep.IsDeleted   = 0))

            UNION ALL

            -- A child is reached only THROUGH an admitted parent, which is what prunes orphans: the join to Viewable is
            -- the inheritance, and the predicate below is the element's own viewability. Both must hold.
            SELECT e.UiElementId
                 , e.ElementCode
                 , e.ElementType
                 , e.ParentUiElementId
                 , e.DisplayLabel
                 , e.SortOrder
                 , v.Depth + 1
                 , CanEdit = CAST (CASE WHEN EXISTS (SELECT 1
                                                       FROM auth.UiElementPermission AS uep
                                                      INNER JOIN HeldPermission      AS hp
                                                         ON hp.PermissionId = uep.PermissionId
                                                      WHERE uep.UiElementId = e.UiElementId
                                                        AND uep.AccessMode  = N'Edit'
                                                        AND uep.IsDeleted   = 0)
                                        THEN 1 ELSE 0 END AS BIT)
              FROM auth.UiElement AS e
             INNER JOIN Viewable  AS v ON v.UiElementId = e.ParentUiElementId
             WHERE e.IsDeleted     = 0
               AND e.ApplicationId = @ApplicationId
               AND (NOT EXISTS (SELECT 1
                                  FROM auth.UiElementPermission AS uep
                                 WHERE uep.UiElementId = e.UiElementId
                                   AND uep.AccessMode  = N'View'
                                   AND uep.IsDeleted   = 0)
                    OR EXISTS (SELECT 1
                                 FROM auth.UiElementPermission AS uep
                                INNER JOIN HeldPermission      AS hp
                                   ON hp.PermissionId = uep.PermissionId
                                WHERE uep.UiElementId = e.UiElementId
                                  AND uep.AccessMode  = N'View'
                                  AND uep.IsDeleted   = 0))
        )
        SELECT v.UiElementId
             , v.ElementCode
             , v.ElementType
             , v.ParentUiElementId
             , v.DisplayLabel
             , v.SortOrder
             , v.Depth
             -- Constant 1: a row that reached this result set is one the profile may view. The column exists because the
             -- design's contract names it and a UI binding to nav[code].CanView should not have to know it is always
             -- true here; the FILTERING is the security, not this bit.
             , CAST (1 AS BIT) AS CanView
             , v.CanEdit
             , @ActingTenantId AS ActingTenantId
          FROM Viewable AS v
         ORDER BY v.Depth ASC, v.SortOrder ASC, v.ElementCode ASC;

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


-- *** 4. auth.uspCheckPermission ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspCheckPermission
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

The NON-THROWING counterpart of auth.uspDemandPermission: returns HasPermission as a bit and writes nothing at all.
Section 9.1.  Exists for one purpose -- deciding whether to render a control.

========================================================================================================================
Requirements and Key Dependencies:

auth.Permission, auth.udfHasPermission, auth.uspSetSessionContext, logs.uspRecordExecutionError.  Granted to
applicationRole -- the only one of the four that is.

========================================================================================================================
Notes:

KEEPING THIS APART FROM uspDemandPermission IS WHAT LETS THE DEMAND BE UNCONDITIONAL.  The file header and section 9 both
say it: a demand that returned a bit would make the caller responsible for checking it, and a caller that forgets to
check a return value has silently skipped the whole permission model -- finding F-07's shape.  So the throwing form
throws always and the asking form never does, and no procedure is ever tempted to use the wrong one because they do
different things to the trail.

IT WRITES NOTHING.  No logs.ExecutionLog start row, no logs.AuthorizationDenial row on a negative answer.  A rich screen
asks this question once per control, and a trail row per render would bury the real denials uspDemandPermission records
under rows that mean "the UI decided not to enable a button" -- which is a layout decision, not a security event.  This
is the ONE place in the database where a negative authorization answer is deliberately not recorded, and the reason it is
safe is that nothing is permitted on the strength of it: the actual write still calls uspDemandPermission, which does
record.  G-09 covers the residual risk -- an attacker can probe this procedure silently -- and accepts it, because the
probe teaches them only what their own UI would have shown them anyway.

E-50031 IS STILL RAISED, for a permission code that does not exist in the session's application.  "No such code" is not
an answer to "may I", it is an application defect, and returning HasPermission = 0 for it would let a typo'd code sit in
a UI for years looking like a deliberate restriction.  This is the only way this procedure throws for an authorization
reason, and section 14.5 puts the whole 50030 range under "show a permission message; do not sign out".

@TenantId DEFAULTS TO THE ACTING TENANT, which is what a UI asking "may I do this HERE" means.  Passing it explicitly is
for a screen that acts on another tenant in the subtree. A tenant-scoped permission asked with an explicit NULL is
refused, for the reason the file header gives: auth.udfHasPermission finds no closure row for NULL, and failing closed is
the correct direction.

ONE ROW, ALWAYS, so a Dapper QuerySingle never throws for the wrong reason (UI-04).

========================================================================================================================
Example Usage and Performance:

exec auth.uspCheckPermission @SessionTokenHash = 0x9F86..., @PermissionCode = N'Data.Approve';
exec auth.uspCheckPermission @SessionTokenHash = 0x9F86..., @PermissionCode = N'Data.Approve', @TenantId = 7;

Two index seeks, the same as auth.udfHasPermission, plus one seek to validate the code.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-085
Description:
Created.  Phase 6.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspCheckPermission
      @SessionTokenHash VARBINARY (32)
    , @PermissionCode   NVARCHAR (100)
    , @TenantId         INT = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation, READ variant: error-only. No start row is opened.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspCheckPermission]')
          , @KeyParameters  NVARCHAR (MAX) = NULL
          , @ContextMessage NVARCHAR (MAX) = NULL
          , @DynamicSql     NVARCHAR (MAX) = NULL
          , @ErrorMsg       NVARCHAR (MAX) = NULL
          , @ErrorProc      NVARCHAR (300) = NULL
          , @ErrorNumber    INT            = NULL
          , @ErrorLine      INT            = NULL;

    DECLARE @UserProfileId  INT             = NULL
          , @ActingTenantId INT             = NULL
          , @ApplicationId  INT             = NULL
          , @PermissionId   INT             = NULL
          , @IsTenantScoped BIT             = NULL
          , @HasPermission  BIT             = 0
          , @Failure        NVARCHAR (2000) = NULL;

    SET @KeyParameters  = CONCAT (N'SessionTokenHash=(32 bytes, not logged), PermissionCode=', @PermissionCode
                                , N', TenantId=', COALESCE (CAST (@TenantId AS NVARCHAR (11)), N'(acting tenant)'));
    SET @ContextMessage = N'Error-only instrumented read: no start row is opened, so @ExecutionLogId is NULL by design.';

    BEGIN TRY

        -- =========================================================================================
        -- ===== The procedure's own work starts here. Everything above and below is boilerplate. ==
        -- =========================================================================================

        EXEC auth.uspSetSessionContext @SessionTokenHash = @SessionTokenHash;

        SET @UserProfileId  = TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT);
        SET @ActingTenantId = TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT);

        -- Set read-only by uspSetSessionContext from the session row a moment ago: see the note in
        -- auth.uspGetNavigationForProfile for why this is read from context rather than from auth.UserSession again.
        SET @ApplicationId = TRY_CAST (SESSION_CONTEXT (N'ApplicationId') AS INT);

        -- COALESCE and not ISNULL, and assigned to the parameter rather than a second variable, so the value passed to
        -- auth.udfHasPermission below and the value reported in the result set cannot drift apart.
        SET @TenantId = COALESCE (@TenantId, @ActingTenantId);

        SELECT @PermissionId   = p.PermissionId
             , @IsTenantScoped = p.IsTenantScoped
          FROM auth.Permission AS p
         WHERE p.PermissionCode COLLATE Latin1_General_BIN2 = @PermissionCode COLLATE Latin1_General_BIN2
           AND p.ApplicationId = @ApplicationId
           AND p.IsDeleted     = 0;

        -- The one authorization-flavoured throw here, and it is a defect report rather than a refusal: see the notes.
        -- Nothing is written to logs.AuthorizationDenial -- that is uspDemandPermission's job and this procedure has
        -- promised to be silent.
        IF @PermissionId IS NULL
        BEGIN
            SET @Failure = N'There is no such permission code in this application. This is an APPLICATION DEFECT rather '
                         + N'than a refusal: a UI asking about a code nobody can ever hold has a typo or is bound to a '
                         + N'permission some other application registers, and answering "no" would let that sit '
                         + N'undiscovered for years looking like a deliberate restriction. Permission codes are '
                         + N'case-sensitive and are fixed by Appendix A.';
            ;THROW 50031, @Failure, 1;
        END;

        -- The decision is entirely auth.udfHasPermission's. No second copy of a security rule lives in this file, which
        -- is the same discipline auth.uspDemandPermission keeps -- and it is what guarantees the button the UI draws and
        -- the write the server permits agree with each other.
        SET @HasPermission = auth.udfHasPermission (@PermissionCode, @TenantId);

        SELECT @PermissionCode  AS PermissionCode
             , @TenantId        AS TenantId
             , @IsTenantScoped  AS IsTenantScoped
             , @UserProfileId   AS UserProfileId
             , @HasPermission   AS HasPermission
             -- The caller's own courtesy explanation, so a support engineer looking at a greyed-out button has
             -- something better than a bare 0. It names no other profile, no other tenant and no role.
             , CASE WHEN @HasPermission = 1 THEN N'Held at this tenant or at one above it.'
                    WHEN @IsTenantScoped = 1 AND @TenantId IS NULL
                    THEN N'Not held: this is a tenant-scoped permission and no tenant was supplied or resolved, which '
                       + N'always refuses -- there is no closure row for a NULL tenant. Supply @TenantId or establish '
                       + N'session context first.'
                    ELSE N'Not held at this tenant or at any tenant above it.' END AS Explanation;

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


-- *** 5. Descriptions ***
IF OBJECT_ID (N'util.uspSetObjectDescription', N'P') IS NOT NULL
BEGIN
    -- Loaded into a table variable and walked, because an EXEC argument takes a constant or a variable and never an
    -- expression: a '+' in the parameter position is a parse error (102), exactly as it is for THROW.
    DECLARE @Descriptions TABLE
    (
        RowNo       INT IDENTITY (1, 1) PRIMARY KEY,
        ObjectName  SYSNAME         NOT NULL,
        Description NVARCHAR (3750) NOT NULL
    );

    INSERT @Descriptions (ObjectName, Description)
    VALUES
      (N'uspDemandPermission'
     , N'Section 9 step 5 and section 14.2. Returns silently when the session''s active profile holds @PermissionCode '
     + N'at @TenantId; otherwise records the refusal in logs.AuthorizationDenial and raises 50030, or 50031 when the '
     + N'code does not exist in this application, or 50032 when the session is signed in with no active profile. '
     + N'THE DENIAL IS RECORDED BEFORE THE NUMBER IS DECIDED, because a demand '
     + N'for a code no profile can hold is the most useful row the trail can carry. Error-only instrumented (rule 8): '
     + N'the granted path writes nothing and the denied path delegates its write to a fully instrumented recorder. The '
     + N'decision is entirely auth.udfHasPermission''s -- no second copy of a security rule here. A demand with no '
     + N'session context at all is a DENIAL with a NULL UserProfileId in the trail, not a 5002x: that NULL is the '
     + N'finding. A demand from a session that HAS context and no active profile is 50032 instead, because UI-09 ships '
     + N'that state deliberately and E-50030''s message used to call it a server-side defect (G-51, T-126). '
     + N'@TenantId is optional for the Platform category and omitting it for a tenant-scoped permission always refuses. '
     + N'Not granted to applicationRole: reached by ownership chaining, and the 50030/50031 split would otherwise be an '
     + N'enumeration oracle.')
    , (N'uspGetProfileContext'
     , N'Section 13.4 and UI-01. One row for the header of every page: user, active profile, tenant, the full tenant '
     + N'path from auth.vwTenantHierarchy, session timings, the elevation expiry, the MFA and bypass flags, and '
     + N'SwitchableProfileCount. DEMANDS NO PERMISSION -- a profile is always allowed to know who it is, and a header '
     + N'that could be refused would make every page conditional on a permission check. SwitchableProfileCount COUNTS '
     + N'THE CURRENT PROFILE, so the switcher is shown when it is greater than 1 (UI-33). Always exactly one row, so a '
     + N'Dapper QuerySingle is safe (UI-04); an expired or ended session is an error from '
     + N'auth.uspSetSessionContext, not an empty result. Error-only instrumented (rule 8). Granted to applicationRole.')
    , (N'uspGetNavigationForProfile'
     , N'Section 13.2 and UI-02. The whole navigable UI tree for the session''s active profile in one round trip, with '
     + N'CanView and CanEdit per element. ELEMENTS THE PROFILE CANNOT VIEW ARE OMITTED ENTIRELY rather than flagged, so '
     + N'there is nothing for a UI to accidentally render. Viewability is INHERITED: the recursive CTE descends only '
     + N'into a child whose parent was admitted, which is what prevents an orphaned button whose screen was pruned. An '
     + N'element with NO View mapping is visible to every authenticated profile (section 13.1); an element with no Edit '
     + N'mapping is editable by nobody -- the two defaults are deliberately opposite. Permissions are resolved once '
     + N'through auth.ProfilePermissionScope joined to auth.TenantClosure, so a grant at an ancestor covers the acting '
     + N'tenant. @ElementCodePrefix narrows the ANCHOR only and is a payload convenience, not a security boundary. '
     + N'Error-only instrumented (rule 8). Granted to applicationRole. Bind to element codes and the two booleans, '
     + N'never to role or permission names. @AssumeUserProfileId exists for auth.uspSwitchProfile alone: on the '
     + N'connection that has just switched, SESSION_CONTEXT is read-only and still names the OLD profile, so a read '
     + N'that went through it would raise E-50022 or answer for the wrong hat (G-36). The session hash is still the '
     + N'authority -- a profile the session''s user does not hold is E-50050, indistinguishable from one that does not '
     + N'exist (D-10). @ExpectedCatalogueVersion asserts the CATALOGUE CONTRACT (G-18): supplied, it is compared with '
     + N'config.ApplicationSetting''s Ui.CatalogueVersion and a disagreement is E-50230 with nothing returned, because a '
     + N'UI bound to element codes its database no longer has presents as a missing screen rather than an error. NULL is '
     + N'the default and means not asserted, so adoption is incremental; blank is a refusal, not consent. The check runs '
     + N'before the session is resolved, and it is global rather than per application.')
    , (N'uspCheckPermission'
     , N'Section 9.1. The NON-THROWING counterpart of auth.uspDemandPermission: returns HasPermission as a bit, in '
     + N'exactly one row, for deciding whether to render a control. IT WRITES NOTHING AT ALL -- no execution log start '
     + N'row and, uniquely in this database, NO logs.AuthorizationDenial row on a negative answer, because a rich '
     + N'screen asks this once per control and a trail row per render would bury the real denials under layout '
     + N'decisions. That is safe only because nothing is permitted on the strength of it: the write still calls '
     + N'uspDemandPermission, which does record. G-09 accepts the residual silent-probe risk. Still raises 50031 for a '
     + N'code that does not exist in this application, because that is an application defect rather than a refusal. '
     + N'@TenantId defaults to the acting tenant. The decision is entirely auth.udfHasPermission''s, which is what '
     + N'makes the button the UI draws and the write the server permits agree. Granted to applicationRole -- the only '
     + N'one of the four that is.');

    DECLARE @RowNo INT = 1
          , @MaxRowNo INT = (SELECT COALESCE (MAX (RowNo), 0) FROM @Descriptions)
          , @ObjectName SYSNAME
          , @Description NVARCHAR (3750);

    -- Walked by RowNo rather than drained, for the reason 140 and 145 give: the conventions validator forbids DELETE
    -- outright and does not distinguish a table variable from a table, and the rule is not worth an exception nobody
    -- reading it could tell from a real one.
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

        SET @RowNo = @RowNo + 1;
    END;
END
ELSE
BEGIN
    PRINT N'util.uspSetObjectDescription is absent, so no descriptions were set. Run templates/extended-properties.sql '
        + N'and then re-run this file to add them.';
END
GO


-- *** 6. Grants ***
-- THREE OF THE FOUR, and the one omission is the decision.  Business procedures in dbo and auth reach
-- auth.uspDemandPermission by ownership chaining -- measured on this instance, see the header of 165_logs_procedures.sql
-- -- so no grant is needed for it to work, and withholding it denies a compromised application login both an
-- enumeration oracle (50031 distinguishes a code that exists from one that does not) and a way to flood
-- logs.AuthorizationDenial.
--
-- The application's legitimate question, "may this profile do X, so should I render the button", is
-- auth.uspCheckPermission, which returns a bit and writes no trail.  That one is granted; the throwing form is not.
IF DATABASE_PRINCIPAL_ID (N'applicationRole') IS NOT NULL
BEGIN
    GRANT EXECUTE ON auth.uspGetProfileContext       TO applicationRole;
    GRANT EXECUTE ON auth.uspGetNavigationForProfile TO applicationRole;
    GRANT EXECUTE ON auth.uspCheckPermission         TO applicationRole;

    PRINT N'Granted EXECUTE on the three read procedures to applicationRole. auth.uspDemandPermission is deliberately '
        + N'NOT granted: it is reached by ownership chaining from the procedures that call it.';
END
ELSE
BEGIN
    PRINT N'WARNING: applicationRole does not exist, so no grants were made. Run 005_schemas_and_roles.sql and then '
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
SELECT CASE WHEN COUNT (*) = 4 THEN 4 ELSE 1 END
     , CASE WHEN COUNT (*) = 4 THEN 'OK' ELSE 'MISSING' END
     , N'All four authorization query procedures exist'
     , CONCAT (COUNT (*), N' of 4 created: uspDemandPermission (section 9 step 5, raises 50030/50031/50032 after recording '
             , N'the denial), uspGetProfileContext (13.4), uspGetNavigationForProfile (13.2), uspCheckPermission (9.1).')
  FROM (VALUES (N'auth.uspDemandPermission')
             , (N'auth.uspGetProfileContext')
             , (N'auth.uspGetNavigationForProfile')
             , (N'auth.uspCheckPermission')) AS x (ProcName)
 WHERE OBJECT_ID (x.ProcName, N'P') IS NOT NULL;

-- THE FIVE TENANCY PROCEDURES BECOME CALLABLE WITH THIS FILE, which is the one externally visible effect of running it
-- and belongs in the transcript.  They have referenced auth.uspDemandPermission since Phase 1 and failed at call time
-- with 2812; deferred name resolution is what let them install.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (N'auth.uspSetSessionContext', N'P') IS NULL THEN 3 ELSE 4 END
     , CASE WHEN OBJECT_ID (N'auth.uspSetSessionContext', N'P') IS NULL THEN 'PENDING' ELSE 'OK' END
     , N'Callability of the four authorized tenant procedures'
     , CASE WHEN OBJECT_ID (N'auth.uspSetSessionContext', N'P') IS NULL
            THEN N'auth.uspDemandPermission now exists, so half the dependency in 125_auth_tenant_procedures.sql is '
               + N'satisfied. auth.uspSetSessionContext does not exist yet -- it is T-053, in '
               + N'database/105_auth_session_procedures.sql -- so those four still fail with 2812.'
            ELSE N'Both auth.uspDemandPermission and auth.uspSetSessionContext exist. The four authorized procedures in '
               + N'125_auth_tenant_procedures.sql are callable.' END;

-- Error-only instrumentation is a decision that looks like an omission, so it is asserted rather than trusted, for ALL
-- FOUR: each must reference the error recorder and none may reference the start procedure.  Every procedure in this file
-- is a read, and a read that opens a start row to record that it read something turns the execution log into a traffic
-- counter.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN SUM (x.Conforms) = 4 THEN 4 ELSE 1 END
     , CASE WHEN SUM (x.Conforms) = 4 THEN 'OK' ELSE 'VIOLATED' END
     , N'All four carry the ERROR-ONLY instrumentation shape'
     , CONCAT (SUM (x.Conforms), N' of 4 reference logs.uspRecordExecutionError and do NOT reference '
             , N'logs.uspStartExecutionLogging. Non-conforming: '
             , COALESCE (STRING_AGG (CASE WHEN x.Conforms = 0 THEN x.ProcName END, N', '), N'(none)')
             , N'. A start row on the most frequently called procedure in the database would double the instrumentation '
             , N'cost of every write in it to record that a check succeeded.')
  -- 'EXEC logs.usp...' and not just the name: these procedures' headers and comments discuss
  -- logs.uspStartExecutionLogging at length in order to explain why it is absent, and a bare name match found those
  -- comments and reported the file as VIOLATED on its first deployment.  The test has to look for a CALL.
  FROM (SELECT p.ProcName
             , Conforms = CASE WHEN m.definition LIKE N'%EXEC logs.uspRecordExecutionError%'
                               AND  m.definition NOT LIKE N'%EXEC logs.uspStartExecutionLogging%' THEN 1 ELSE 0 END
          FROM (VALUES (N'auth.uspDemandPermission')
                     , (N'auth.uspGetProfileContext')
                     , (N'auth.uspGetNavigationForProfile')
                     , (N'auth.uspCheckPermission')) AS p (ProcName)
         INNER JOIN sys.sql_modules AS m ON m.object_id = OBJECT_ID (p.ProcName)) AS x;

-- It must refuse, and it must refuse with the registered numbers.  Run here rather than left to the Phase 3 test file,
-- because a permission check that silently permits is the one defect that must never survive a deployment.  No session
-- context is set on this connection, so every demand below is denied -- which is itself assertion number one.
DECLARE @Refusals INT = 0
      , @Expected INT = 3
      , @Granted  INT = 0
      , @KnownCode NVARCHAR (100) = (SELECT MIN (p.PermissionCode)
                                       FROM auth.Permission AS p
                                      WHERE p.IsDeleted = 0
                                        AND p.IsTenantScoped = 1);

-- Resolved into its own variable because an EXEC argument takes a constant or a variable and never an expression -- a
-- COALESCE in the parameter position is a parse error (156), the same rule that forces the description above into a
-- variable.  NULL until 115_seed_reference_data.sql has run, and the probe still has to work then.
SET @KnownCode = COALESCE (@KnownCode, N'Data.Read');

-- 1. A real code, a real tenant, no session context: denied 50030. This is the fail-closed assertion.
BEGIN TRY
    EXEC auth.uspDemandPermission @PermissionCode = N'Data.Read'
                                , @TenantId       = 1
                                , @ObjectName     = N'150_auth_query_procedures.sql';
    SET @Granted += 1;
END TRY
BEGIN CATCH
    SET @Refusals += CASE WHEN ERROR_NUMBER () = 50030 OR ERROR_NUMBER () = 50031 THEN 1 ELSE 0 END;
END CATCH;

-- 2. A code that cannot exist: denied 50031, and the denial is recorded BEFORE the number is decided.
BEGIN TRY
    EXEC auth.uspDemandPermission @PermissionCode = N'Probe.NeverSeeded'
                                , @TenantId       = 1
                                , @ObjectName     = N'150_auth_query_procedures.sql';
    SET @Granted += 1;
END TRY
BEGIN CATCH
    SET @Refusals += CASE WHEN ERROR_NUMBER () = 50031 THEN 1 ELSE 0 END;
END CATCH;

-- 3. A tenant id that does not resolve: still 50030 or 50031 and NOT 547, which is what the sanitizing is for.
BEGIN TRY
    EXEC auth.uspDemandPermission @PermissionCode = @KnownCode
                                , @TenantId       = -424242
                                , @ObjectName     = N'150_auth_query_procedures.sql';
    SET @Granted += 1;
END TRY
BEGIN CATCH
    SET @Refusals += CASE WHEN ERROR_NUMBER () IN (50030, 50031) THEN 1 ELSE 0 END;
END CATCH;

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN @Refusals = @Expected AND @Granted = 0 THEN 4 ELSE 1 END
     , CASE WHEN @Refusals = @Expected AND @Granted = 0 THEN 'OK' ELSE 'VIOLATED' END
     , N'It fails closed with no session context, and with the registered numbers'
     , CONCAT (@Refusals, N' of ', @Expected, N' demands were refused with 50030 or 50031, and ', @Granted
             , N' were GRANTED (must be 0). This connection has no session context, so every demand must be refused; '
             , N'the third used a tenant id of -424242 to prove the trail row is sanitized rather than failing with '
             , N'547 and replacing the permission error with a foreign-key error.');

-- The trail rows those three demands left. Written outside any transaction here, so they SURVIVE -- which is the
-- positive half of BL-042: the same three calls inside a caller's open transaction would leave nothing.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) >= 3 THEN 4 ELSE 2 END
     , CASE WHEN COUNT (*) >= 3 THEN 'OK' ELSE 'INCOMPLETE' END
     , N'The three probe demands are in logs.AuthorizationDenial'
     , CONCAT (COUNT (*), N' row(s) named 150_auth_query_procedures.sql, at least 3 expected, every one with a NULL '
             , N'UserProfileId because this connection has no session context. They were written OUTSIDE a transaction '
             , N'and therefore survive -- inside a caller''s open transaction the rollback that E-50030 provokes would '
             , N'take them with it, which is BL-042. Every re-run of this file adds three more; they are real denials '
             , N'that really happened and they name the script that caused them, which is why they are kept rather '
             , N'than rolled back: a deployment transcript that proves the trail works is worth three rows.')
  FROM logs.AuthorizationDenial AS d
 WHERE d.ObjectName = N'150_auth_query_procedures.sql';

-- THE CATALOGUE CONTRACT (G-18), probed rather than asserted from the module text, and it is probeable HERE -- with no
-- session, no profile and no catalogue -- for exactly the reason the check sits where it does: it runs BEFORE the session
-- token is resolved, so a deliberately wrong version refuses on any connection.  The garbage hash below is never looked
-- up.  That also makes E-50230 an OBSERVED number in logs.ExecutionLog on every deployment rather than one _tests/080
-- has to take on trust.
DECLARE @CatalogueRefused   BIT            = 0
      , @CatalogueNumber    INT            = NULL
      , @LiveCatalogueValue NVARCHAR (100) = (SELECT s.SettingValue
                                                FROM config.ApplicationSetting AS s
                                               WHERE s.SettingKey = N'Ui.CatalogueVersion'
                                                 AND s.IsDeleted  = 0);

BEGIN TRY
    EXEC auth.uspGetNavigationForProfile @SessionTokenHash         = 0x00
                                       , @ExpectedCatalogueVersion = N'0.0.notthecatalogueversion';
END TRY
BEGIN CATCH
    SET @CatalogueNumber  = ERROR_NUMBER ();
    SET @CatalogueRefused = CASE WHEN ERROR_NUMBER () = 50230 THEN 1 ELSE 0 END;
END CATCH;

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN @CatalogueRefused = 1 AND @LiveCatalogueValue IS NOT NULL THEN 4
            WHEN @CatalogueRefused = 1                                     THEN 3
            ELSE 1 END
     , CASE WHEN @CatalogueRefused = 1 AND @LiveCatalogueValue IS NOT NULL THEN 'OK'
            WHEN @CatalogueRefused = 1                                     THEN 'PENDING'
            ELSE 'VIOLATED' END
     , N'uspGetNavigationForProfile refuses a stale catalogue version (G-18)'
     , CONCAT (N'A deliberately wrong @ExpectedCatalogueVersion raised error '
             , COALESCE (CAST (@CatalogueNumber AS NVARCHAR (11)), N'(nothing -- the call SUCCEEDED)')
             , N', where 50230 is required. Ui.CatalogueVersion currently holds '
             , COALESCE (QUOTENAME (@LiveCatalogueValue, N''''), N'NOTHING -- run 115_seed_reference_data.sql, which '
                                                              + N'computes it')
             , N'. Omitting the parameter asserts nothing, which is how every existing caller keeps working; passing the '
             , N'version the build was compiled against is what turns the element catalogue from a published interface '
             , N'into an enforced one.');

-- THE DEFINING PROPERTY OF auth.uspCheckPermission, asserted rather than trusted, because it is the one place in this
-- database where a negative authorization answer is deliberately not recorded and a well-meaning future edit that "added
-- the missing audit" would flood the trail with layout decisions.  If this ever has to change, change the note in
-- section 4 and G-09 first.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.WritesDenial = 0 THEN 4 ELSE 1 END
     , CASE WHEN x.WritesDenial = 0 THEN 'OK' ELSE 'VIOLATED' END
     , N'auth.uspCheckPermission writes no denial row'
     , CONCAT (N'References logs.uspRecordAuthorizationDenial: ', x.WritesDenial, N' (must be 0). A rich screen asks '
             , N'this question once per control; a trail row per render would bury the real denials '
             , N'auth.uspDemandPermission records. Safe only because nothing is permitted on the strength of the '
             , N'answer -- the write itself still demands. G-09 accepts the silent-probe risk.')
  FROM (SELECT WritesDenial = MAX (CASE WHEN m.definition LIKE N'%EXEC logs.uspRecordAuthorizationDenial%' THEN 1 ELSE 0 END)
          FROM sys.sql_modules AS m
         WHERE m.object_id = OBJECT_ID (N'auth.uspCheckPermission')) AS x;

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 4 THEN 4 ELSE 2 END
     , CASE WHEN COUNT (*) = 4 THEN 'OK' ELSE 'INCOMPLETE' END
     , N'MS_Description on all four procedures'
     , CONCAT (COUNT (*), N' of 4 procedures carry a description. Conventions rule 4.')
  FROM sys.extended_properties AS ep
 WHERE ep.class = 1
   AND ep.minor_id = 0
   AND ep.name = N'MS_Description'
   AND ep.major_id IN (OBJECT_ID (N'auth.uspDemandPermission')
                     , OBJECT_ID (N'auth.uspGetProfileContext')
                     , OBJECT_ID (N'auth.uspGetNavigationForProfile')
                     , OBJECT_ID (N'auth.uspCheckPermission'));

-- THE THREE-OF-FOUR SPLIT, asserted in both directions in ONE row, because each half is meaningless without the other:
-- three grants with the fourth also granted is the enumeration oracle, and no grants at all is an application that
-- cannot draw a page.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.ReadGrants = 3 AND x.DemandGrants = 0 THEN 4 ELSE 2 END
     , CASE WHEN x.ReadGrants = 3 AND x.DemandGrants = 0 THEN 'OK' ELSE 'REVIEW' END
     , N'EXECUTE granted on the three reads and withheld on the demand'
     , CONCAT (x.ReadGrants, N' of 3 read procedures granted to applicationRole, and ', x.DemandGrants
             , N' grant(s) on auth.uspDemandPermission where 0 is correct. Ownership chaining covers the nested EXEC, '
             , N'and withholding that one grant denies a compromised application login an enumeration oracle -- 50031 '
             , N'distinguishes a code that exists from one that does not -- and a way to flood the denial trail. '
             , N'INV-11.')
  FROM (SELECT ReadGrants   = COUNT (DISTINCT CASE WHEN p.major_id IN (OBJECT_ID (N'auth.uspGetProfileContext')
                                                                    , OBJECT_ID (N'auth.uspGetNavigationForProfile')
                                                                    , OBJECT_ID (N'auth.uspCheckPermission'))
                                                   AND dp.name = N'applicationRole'
                                                   THEN p.major_id END)
             , DemandGrants = COUNT (CASE WHEN p.major_id = OBJECT_ID (N'auth.uspDemandPermission') THEN 1 END)
          FROM sys.database_permissions AS p
         INNER JOIN sys.database_principals AS dp ON dp.principal_id = p.grantee_principal_id
         WHERE p.class = 1
           AND p.permission_name = N'EXECUTE'
           AND p.state IN (N'G', N'W')
           AND dp.name IN (N'applicationRole', N'readOnlyRole')) AS x;

-- THE FORWARD REFERENCE 140_auth_profile_procedures.sql HAS CARRIED SINCE T-078 closes here, and the transcript should
-- say so, because the effect is invisible in this file: auth.uspSwitchProfile returns the new profile's navigation as a
-- SECOND result set by calling auth.uspGetNavigationForProfile, and until that procedure existed it returned one result
-- set and printed a note.  Re-run 140 after this file so its own closing report agrees.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (N'auth.uspSwitchProfile', N'P') IS NULL THEN 3
            WHEN x.CallsNavigation = 1 THEN 4 ELSE 3 END
     , CASE WHEN OBJECT_ID (N'auth.uspSwitchProfile', N'P') IS NULL THEN 'PENDING'
            WHEN x.CallsNavigation = 1 THEN 'OK' ELSE 'PENDING' END
     , N'auth.uspSwitchProfile can now return navigation as its second result set'
     , CASE WHEN OBJECT_ID (N'auth.uspSwitchProfile', N'P') IS NULL
            THEN N'auth.uspSwitchProfile does not exist yet (T-078, 140_auth_profile_procedures.sql). Run that file '
               + N'after this one and the second result set will be live.'
            WHEN x.CallsNavigation = 1
            THEN N'It calls auth.uspGetNavigationForProfile, which now exists, so the switch returns the new profile''s '
               + N'tree in the same round trip -- the UI never has to ask twice and never draws the old menu against '
               + N'the new tenant.'
            ELSE N'auth.uspSwitchProfile exists but does not reference auth.uspGetNavigationForProfile. If it was '
               + N'deployed before this file, RE-RUN 140_auth_profile_procedures.sql now.' END
  FROM (SELECT CallsNavigation = MAX (CASE WHEN m.definition LIKE N'%auth.uspGetNavigationForProfile%' THEN 1 ELSE 0 END)
          FROM sys.sql_modules AS m
         WHERE m.object_id = OBJECT_ID (N'auth.uspSwitchProfile')) AS x;

IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
    PRINT N'Authorization query surface: PROBLEMS found. Read the report below before running the next script.';
ELSE
    PRINT N'Authorization query surface: no problems found.';

PRINT N'';

SELECT Severity, Status, Item, Detail
  FROM @Report
 ORDER BY Severity, RowNo;
GO
