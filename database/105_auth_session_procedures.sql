/***********************************************************************************************************************
Script:         105_auth_session_procedures.sql
Purpose:        The session-context surface: the FIRST STATEMENT of every authenticated request, its counterpart, and
                the controlled door out of row-level security.
                  auth.uspSetSessionContext       -- T-053, sections 9 and 14.3
                  auth.uspClearSessionContext     -- T-054, section 14.3
                  auth.uspBeginMaintenanceSession -- T-066, section 10.5
                  auth.uspEndMaintenanceSession   -- T-066, section 10.5
Target:         SQL Server 2022.
Run as:         db_owner in the target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/105_auth_session_procedures.sql
Idempotent:     Yes.  CREATE OR ALTER throughout, every grant guarded on DATABASE_PRINCIPAL_ID, nothing dropped.
Depends on:     database/025_config_tables.sql, database/030_auth_tenant.sql, database/035_auth_tenant_policy.sql,
                database/040_auth_userprofile.sql, database/070_auth_session.sql, database/085_logs_auth_tables.sql, database/100_auth_functions.sql,
                database/110_auth_authn_procedures.sql (auth.uspEndSession), scripts/logExecutionLogging.sql,
                templates/extended-properties.sql.
Implements:     T-053, T-054, T-066.  DES-AUTH-001 sections 9, 10.5, 14.3, 14.4 and 14.5.
                See docs/10-database-authn-authz-design.md.
To retarget:    Pass it per run:  sqlcmd -d <database> -v DbName=<database>.  There is no in-file default.

THE PARAMETER IS THE HASH, NOT THE TOKEN, AND SECTION 9'S SKETCH SAYS OTHERWISE
------------------------------------------------------------------------------
Section 9 step 3 is written as  EXEC auth.uspSetSessionContext @SessionToken = @token  and says the procedure "hashes
the token".  This file takes @SessionTokenHash VARBINARY (32) instead, and every other object in the database already
agrees with it: 070_auth_session.sql stores SHA-256 and states that the token is never stored anywhere, 110 and 112 take
a hash in five procedures, and auth.udfResolveSessionUser's own notes say "the application hashes; this resolves" --
because a procedure that hashed would have to fix an encoding, and two callers that disagreed about UTF-8 versus UTF-16
would produce two hashes of one token with nothing to say which was wrong.

So the deviation is the design document's, not this file's, and section 9 has been corrected rather than the code.
BL-043.  The consequence worth stating plainly: inside this database the HASH is the credential.  Anybody who can read
auth.UserSession can call this procedure with a stored hash and be issued another user's session context, which is why
no application login is granted SELECT on it (INV-11) and why @SessionTokenHash is never written to logs.ExecutionLog --
@KeyParameters records "(supplied)" and the resolved ids, never the bytes.

WHY THE PROCEDURE ON THE HOT PATH WRITES NO START ROW
----------------------------------------------------
auth.uspSetSessionContext is the first statement of every authenticated request in the estate, and it writes: it slides
the idle window.  Rule 8's full block would therefore be the default choice, and it is the wrong one here.  One
logs.ExecutionLog row per request, at a modest fifty requests a second, is four and a third million rows a day whose
entire content is "authentication context was established, as it was the previous time".  The first performance review
to notice that does not delete this one call site; it deletes the instrumentation, everywhere, and the template loses
rule 8 altogether.

So this file uses the ERROR-ONLY shape for both session-context procedures, and the reasoning is recorded rather than
assumed:

  - The write is a liveness slide, not a business change, and it is already recorded where it belongs.
    auth.UserSession.LastSeenUtc IS the per-request record: one row per session that moves, instead of one row per
    request that accumulates.
  - A single UPDATE is atomic on its own, so there is nothing for a transaction to protect.
  - Everything that can go wrong here is an E-5002x refusal or a defect, and all of them are recorded: the CATCH calls
    logs.uspRecordExecutionError with @ExecutionLogId = NULL, which is the orphan row the MERGE in
    logs.uspRecordExecutionErrorUpdate inserts on purpose.

G-22 records the middle position nobody needs yet -- sampled instrumentation, one row in N -- so that the choice is
revisited deliberately if the request log turns out to be wanted after all.  The two MAINTENANCE procedures are fully
instrumented: they are called by a human being a handful of times a month, and what they do is worth a row each.

SESSION CONTEXT IS NOT TRANSACTIONAL, AND THAT DECIDES THE ORDER OF EVERY STATEMENT BELOW
-----------------------------------------------------------------------------------------
Measured on this instance, 2026-09-20:

    BEGIN TRANSACTION;
    EXEC sp_set_session_context @key = N'ProbeTx', @value = 3;
    ROLLBACK TRANSACTION;
    SELECT SESSION_CONTEXT (N'ProbeTx');     -- 3.  The rollback did not take it.

A key set inside a transaction SURVIVES the rollback of that transaction.  Two consequences, and both of them are
orderings rather than comments:

  1. auth.uspSetSessionContext sets its five keys AFTER its work, not before, so that a failure cannot leave a
     connection carrying an identity whose only database write was rolled back.
  2. auth.uspBeginMaintenanceSession COMMITS the logs.AuthenticationEvent row BEFORE it sets the bypass key -- which is
     what section 10.5's "before setting the key, so the record exists even if the session then fails" requires, and
     which the obvious shape (work inside the transaction, key with it) gets exactly backwards: the row would vanish on
     a rollback and the bypass would stay on.

And the mirror of it: auth.uspEndMaintenanceSession CLEARS the key first and records afterwards.  Begin records before
it grants, End revokes before it records; both orderings err in the direction of the trail never overstating what
access existed.

READ-ONLY KEYS CANNOT BE UNSET, WHICH IS WHAT auth.uspClearSessionContext IS ABOUT
---------------------------------------------------------------------------------
Also measured, on the same instance:

    EXEC sp_set_session_context @key = N'ProbeRo', @value = 7, @read_only = 1;
    EXEC sp_set_session_context @key = N'ProbeRo', @value = 7, @read_only = 1;
        -- Msg 15664: Cannot set key 'ProbeRo' in the session context. The key has been set as read_only for this session.
    EXEC sp_set_session_context @key = N'ProbeRo', @value = NULL;
        -- Msg 15664 again.  A read-only key cannot be cleared either.

Section 14.3 point 1 is therefore exactly right and this is the proof of it: the SAME VALUE fails, so the three-way
branch -- absent, set it; present and equal, return silently; present and different, E-50022 -- is not a nicety, it is
the only way the second legitimate call on one pooled connection can succeed.

It also means auth.uspClearSessionContext cannot do what its name suggests to the five identity keys.  It clears every
WRITABLE key this template sets, which today is BypassRowSecurity, and it reports through @IdentityKeysRemain whether
the identity is still attached -- because the only thing that detaches it is sp_reset_connection, which the pool issues
when the connection goes back (section 14.3 point 2).  A procedure that pretended otherwise would be worse than no
procedure: a background job would "clear" the context, iterate to the next profile, and silently keep acting as the
first one.

A SESSION WITH NO ACTIVE PROFILE IS VALID, AND IT GETS THREE KEYS INSTEAD OF FIVE
--------------------------------------------------------------------------------
auth.UserSession.ActiveUserProfileId is nullable and a fresh sign-in leaves it NULL -- 110 inserts it that way.  Such a
session is accepted here: UserId, AppUser and ApplicationId are set, UserProfileId and ActingTenantId are NOT SET AT
ALL, and the call returns 0.  That is section 8.5 and UI-09: a person with no usable profile must be able to reach the
screen that tells them so, and refusing the context would leave them unable to call the procedure that lists their
profiles.

Leaving the two keys absent rather than setting them to NULL is deliberate twice over.  Absent, every row-level
security predicate reads NULL from SESSION_CONTEXT, compares it, and returns no rows -- the fail-closed direction, so a
profileless session can see nothing.  Set to NULL with @read_only = 1, the key would be LOCKED at NULL for the life of
the connection, and the profile-selection procedure Phase 6 adds could never fill it in.

WHAT EACH REFUSAL MEANS, AND WHY udfResolveSessionUser IS NOT USED HERE
----------------------------------------------------------------------
auth.udfResolveSessionUser folds all four liveness conditions into one answer and returns NULL for every failure.  That
is right for its callers in 112 and wrong for this one, because Appendix B asks this procedure to distinguish:

    E-50020  no such session, or it has ended          -- the token is not a session at all
    E-50023  expired, or idle beyond the tenant's timeout
    E-50024  the user is inactive or locked out        -- auth.udfIsUserUsable
    E-50021  the profile, or its tenant, is unusable   -- auth.udfIsTenantUsable, itself and every ancestor
    E-50022  context already set for a DIFFERENT profile on this connection

Collapsing 50020 and 50023 would make "your session timed out, sign in again" indistinguishable from "that token was
never valid", and section 14.5 has the UI say different things.  So the session row is read once, here, and the four
conditions are tested separately.

THE EXPIRY PATH ENDS THE SESSION IT REFUSES, AS HOUSEKEEPING AND BEST-EFFORT
---------------------------------------------------------------------------
On E-50023 the procedure calls auth.uspEndSession with 'IdleExpired' or 'AbsoluteExpired' before it throws, so an
expired session stops being a live row and leaves a logs.AuthenticationEvent behind.  The call is wrapped in a
swallowing TRY/CATCH and its failure is appended to @ContextMessage: the caller must receive E-50023 and never some
error out of the housekeeping.  And if the caller had a transaction open, its rollback takes the housekeeping with it
(BL-042) -- which is why the refusal does not depend on it having worked.

NOT EVERY CALLER OF THIS FILE IS THE APPLICATION
------------------------------------------------
The two session-context procedures are granted to applicationRole: the application cannot function without them and
they are the gate everything else stands behind.  The two MAINTENANCE procedures are granted to rlsBypassRole ONLY, and
section 10.5's rule is enforced inside the procedure as well, with IS_ROLEMEMBER -- because a grant can be widened by
somebody who does not read this file, and the role test refuses anyway.  Measured on this instance: db_owner is NOT a
member of rlsBypassRole (IS_ROLEMEMBER returns 0, and returns NULL for a role that does not exist, which this treats as
"no"), so the deploying principal itself is refused with E-50070 -- and the closing report asserts that refusal rather
than demonstrating a bypass.
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

-- The functions are asserted rather than warned about: a FUNCTION is resolved when the procedure is created, not
-- deferred, so a missing one fails this deployment with 208 anyway.  Named here so the failure says which file to run.
IF OBJECT_ID (N'auth.UserSession', N'U') IS NULL
   OR OBJECT_ID (N'auth.UserProfile', N'U') IS NULL
   OR OBJECT_ID (N'auth.[User]', N'U') IS NULL
   OR OBJECT_ID (N'auth.TenantAuthenticationPolicy', N'U') IS NULL
   OR OBJECT_ID (N'config.ApplicationSetting', N'U') IS NULL
   OR OBJECT_ID (N'logs.AuthenticationEvent', N'U') IS NULL
   OR OBJECT_ID (N'auth.udfIsUserUsable', N'FN') IS NULL
   OR OBJECT_ID (N'auth.udfIsTenantUsable', N'FN') IS NULL
   OR OBJECT_ID (N'auth.udfResolveAuthPolicy', N'FN') IS NULL
BEGIN
    DECLARE @MsgParents NVARCHAR (2000) =
        N'A parent object is missing. auth.UserSession comes from database/070_auth_session.sql, auth.UserProfile and '
      + N'auth.User from database/040_auth_userprofile.sql, auth.TenantAuthenticationPolicy from '
      + N'database/035_auth_tenant_policy.sql, config.ApplicationSetting from database/025_config_tables.sql, '
      + N'logs.AuthenticationEvent from database/085_logs_auth_tables.sql and the three functions from '
      + N'database/100_auth_functions.sql. Run them first.';

    THROW 50000, @MsgParents, 1;
END
GO

-- Deferred name resolution means these two install the procedures anyway and fail on a CALL instead, which is the worst
-- kind of latent break -- so they are warnings that name the file, not silent omissions.
IF OBJECT_ID (N'logs.uspRecordExecutionError', N'P') IS NULL
BEGIN
    PRINT N'WARNING: logs.uspRecordExecutionError is missing. All four procedures in this file will install and will '
        + N'fail with error 2812 the first time one of them handles an error. Run '
        + N'.claude/skills/ponytail-sql-objects/scripts/logExecutionLogging.sql against this database.';
END
GO

IF OBJECT_ID (N'auth.uspEndSession', N'P') IS NULL
BEGIN
    PRINT N'WARNING: auth.uspEndSession is missing (database/110_auth_authn_procedures.sql). '
        + N'auth.uspSetSessionContext installs and works, and its E-50023 path will fail to end the expired session it '
        + N'refuses -- the failure is swallowed and recorded in the @ContextMessage of the error row, so the caller '
        + N'still receives E-50023 and the only loss is the housekeeping.';
END
GO

-- logs.AuthenticationEvent's EventType is a CLOSED SET.  auth.uspBeginMaintenanceSession writes 'MaintenanceBypass'
-- and its counterpart writes 'MaintenanceBypassEnded'; both were added to the vocabulary by T-066, in
-- 085_logs_auth_tables.sql, which has an ALTER that brings an existing database up to date.  Without it the INSERT
-- fails with 547 at call time and nothing says which script is out of step.
IF EXISTS (SELECT 1 FROM sys.check_constraints
            WHERE name             = N'CK_logs_AuthenticationEvent_EventType'
              AND parent_object_id = OBJECT_ID (N'logs.AuthenticationEvent')
              AND (definition NOT LIKE N'%MaintenanceBypass%' OR definition NOT LIKE N'%MaintenanceBypassEnded%'))
BEGIN
    PRINT N'WARNING: CK_logs_AuthenticationEvent_EventType does not permit MaintenanceBypass or '
        + N'MaintenanceBypassEnded. auth.uspBeginMaintenanceSession will install and will fail with error 547 on its '
        + N'first call. Re-run database/085_logs_auth_tables.sql, which replaces the constraint in place and changes '
        + N'no row.';
END
GO


-- *** 1. auth.uspSetSessionContext ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspSetSessionContext
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Section 9 step 3: THE FIRST STATEMENT ON EVERY AUTHENTICATED CONNECTION, ALWAYS.  Turns a session token hash into the
five SESSION_CONTEXT keys the rest of the database reads -- UserId, UserProfileId, ActingTenantId, AppUser and
ApplicationId -- after checking, in this order, that the session exists and is live, that it has not expired or gone
idle, that the user may act, and that the profile and its whole ancestry are usable.

Returns 0 and sets the keys.  Any failure raises in the E-5002x range and NOTHING FURTHER RUNS: no key is set, no work
is authorized, and section 14.5 has the UI sign the user out on the whole range.

Also slides the idle window: LastSeenUtc and IdleExpiryUtc move forward by the tenant's IdleTimeoutMinutes, capped at
AbsoluteExpiryUtc.  That cap is section 7.3's rule that activity extends the idle window and never the absolute one.

========================================================================================================================
Notes:

ERROR-ONLY INSTRUMENTED, ON PURPOSE, AND THE FILE HEADER ARGUES IT AT LENGTH.  One start row per request would make
logs.ExecutionLog the request log of the estate; auth.UserSession.LastSeenUtc is the per-request record, one row per
session rather than one per call.  The CATCH is not optional and is not weakened: every refusal here lands in
logs.ExecutionLog as an orphan error row with @ExecutionLogId = NULL.

THE FIVE KEYS ARE SET AFTER THE WORK, NOT BEFORE, BECAUSE SESSION CONTEXT IS NOT TRANSACTIONAL.  Measured: a key set
inside a transaction survives that transaction's rollback.  Setting first would mean a connection could end up carrying
an identity whose only database write had been undone.  Setting last means the only failure that can leave a key set is
one in the sp_set_session_context calls themselves, and those cannot fail once the values are known -- 15664 is the
single possibility and it is what E-50022 exists to have already ruled out.

THE THREE-WAY BRANCH OF SECTION 14.3 IS TESTED AFTER VALIDATION, NOT BEFORE IT.  "Present and equal, return silently"
is about the second call within one request, and a second call whose session has meanwhile expired must still be refused
with E-50023 -- so the token is resolved and checked first, and only then compared with what the connection already
carries.  The comparison is NULL-safe (EXISTS ... INTERSECT), which is what makes a profileless session compare equal to
itself instead of raising E-50022 against its own second call.

E-50022 IS RAISED BEFORE THE IDLE WINDOW IS TOUCHED.  A connection that already belongs to profile A must not slide
profile B's session forward on its way to being refused, or a background job with that bug would keep somebody else's
session alive indefinitely.

@SessionTokenHash IS NEVER LOGGED.  Inside this database the hash is the credential -- it is what this procedure accepts
-- so @KeyParameters records '(supplied)' and the ids that were resolved from it.  A support engineer reading an error
row gets the session id, the user and the profile, which is everything except the one value that would let them
impersonate.

THE TOUCH IS ATTRIBUTED TO @Actor, WHICH ON THE FIRST CALL OF A REQUEST IS THE APPLICATION LOGIN.  Section 14.4 stamps
audit columns from SESSION_CONTEXT ('AppUser'), and this is the one procedure in the database that runs BEFORE that key
exists, so auditModifiedBy on the touched session row reads as the application login rather than the person.  Naming the
person instead was considered and rejected: auditModifiedBy would then hold two vocabularies in one column -- login
names everywhere else, user names here -- and every report that groups by it would split.  The person is not lost;
UserId on the row is who it is.

NO METADATA READS ANYWHERE.  The application login is denied metadata visibility, so OBJECT_ID returns NULL for it
(measured in 165_logs_procedures.sql).  This procedure asks only for rows.

========================================================================================================================
Example Usage and Performance:

declare @UserId int, @ProfileId int, @TenantId int;

exec auth.uspSetSessionContext @SessionTokenHash = 0x9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08
   , @UserId = @UserId output, @UserProfileId = @ProfileId output, @ActingTenantId = @TenantId output;

select SESSION_CONTEXT (N'AppUser') as AppUser, SESSION_CONTEXT (N'ActingTenantId') as ActingTenantId;

One seek on UX_auth_UserSession_TokenHash, one on the profile, one on the user, one on the policy, and one narrow
UPDATE.  Section 10.6: everything it reads is small and stays in cache.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-053
Description:
Created.  Phase 3.  Sections 9 and 14.3, with the parameter taking the hash rather than the token (BL-043).

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspSetSessionContext
      @SessionTokenHash VARBINARY (32)
    , @UserId           INT = NULL OUTPUT
    , @UserProfileId    INT = NULL OUTPUT
    , @ActingTenantId   INT = NULL OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 error-only instrumentation. Boilerplate: copy verbatim.
    -- Shorter than the full block by exactly what a procedure on the hot path must not pay for. Do
    -- not reintroduce @ExecutionId, @StartTimeUtc, @EndTimeUtc or @Comments -- the file header
    -- records why, and one row per request is the thing being avoided.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspSetSessionContext]')
          , @KeyParameters  NVARCHAR (MAX) = NULL
          , @ContextMessage NVARCHAR (MAX) = NULL
          , @DynamicSql     NVARCHAR (MAX) = NULL
          , @ErrorMsg       NVARCHAR (MAX) = NULL
          , @ErrorProc      NVARCHAR (300) = NULL
          , @ErrorNumber    INT            = NULL
          , @ErrorLine      INT            = NULL;

    DECLARE @Now   DATETIME2 (3)  = SYSUTCDATETIME ()
          , @Actor NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                            , ORIGINAL_LOGIN ());

    DECLARE @UserSessionId      BIGINT          = NULL
          , @ResolvedUserId     INT             = NULL
          , @ResolvedProfileId  INT             = NULL
          , @ResolvedTenantId   INT             = NULL
          , @ApplicationId      INT             = NULL
          , @UserName           NVARCHAR (256)  = NULL
          , @EndedUtc           DATETIME2 (3)   = NULL
          , @AbsoluteExpiryUtc  DATETIME2 (3)   = NULL
          , @IdleExpiryUtc      DATETIME2 (3)   = NULL
          , @NewIdleExpiryUtc   DATETIME2 (3)   = NULL
          , @ExistingUserId     INT             = NULL
          , @ExistingProfileId  INT             = NULL
          , @ContextWasSet      BIT             = 0
          , @AlreadyEqual       BIT             = 0
          , @PolicyId           INT             = NULL
          , @IdleMinutes        INT             = NULL
          , @EndReason          VARCHAR (40)    = NULL
          , @Failure            NVARCHAR (2000) = NULL;

    -- Identifiers only, and NOT the hash: inside this database the hash is the credential. See the notes.
    SET @KeyParameters = N'SessionTokenHash=(supplied, never logged)';

    SET @ContextMessage = N'Error-only instrumented session-context establishment: no start row is opened, so '
                        + N'@ExecutionLogId is NULL by design. A row here is an E-5002x refusal or a defect, never a '
                        + N'successful call. Section 9 step 3.';

    BEGIN TRY

        -- =========================================================================================
        -- ===== The procedure's own work starts here. Everything above and below is boilerplate. ==
        -- =========================================================================================

        -- 1.  The parameter. Checked before anything is read, so a malformed call is refused without
        --     touching a table, and 50100 rather than 5002x because it is a caller defect and not a
        --     reason to sign anybody out.
        IF @SessionTokenHash IS NULL OR DATALENGTH (@SessionTokenHash) <> 32
        BEGIN
            ;THROW 50100, N'@SessionTokenHash must be exactly 32 bytes -- the SHA-256 of the session token the APPLICATION holds. The token itself is never a parameter in this database (070_auth_session.sql), and section 9''s sketch of @SessionToken is corrected in BL-043. Nothing was read and no key was set.', 1;
        END;

        -- 2.  The session row, read once. The unique filtered index on the hash makes this at most
        --     one row, and every later decision is made from these six columns rather than from a
        --     second read -- so the session cannot change shape halfway through the checks.
        SELECT @UserSessionId     = s.UserSessionId
             , @ResolvedUserId    = s.UserId
             , @ResolvedProfileId = s.ActiveUserProfileId
             , @ApplicationId     = s.ApplicationId
             , @EndedUtc          = s.EndedUtc
             , @AbsoluteExpiryUtc = s.AbsoluteExpiryUtc
             , @IdleExpiryUtc     = s.IdleExpiryUtc
          FROM auth.UserSession AS s
         WHERE s.SessionTokenHash = @SessionTokenHash
           AND s.IsDeleted        = 0;

        -- Everything that is safe to log, now that it is known. The hash is still not among it.
        SET @KeyParameters = CONCAT (@KeyParameters
                                   , N', UserSessionId=',   COALESCE (CAST (@UserSessionId     AS NVARCHAR (20)), N'(none)')
                                   , N', UserId=',          COALESCE (CAST (@ResolvedUserId    AS NVARCHAR (11)), N'(none)')
                                   , N', ActiveProfileId=', COALESCE (CAST (@ResolvedProfileId AS NVARCHAR (11)), N'(none)')
                                   , N', ApplicationId=',   COALESCE (CAST (@ApplicationId     AS NVARCHAR (11)), N'(none)'));

        -- 3.  E-50020: it is not a session, or it is over. One number for both, because a caller that
        --     presents an ended token and one that presents a fabricated token are told the same
        --     thing on purpose -- a difference would say whether a hash had ever been real.
        IF @UserSessionId IS NULL OR @EndedUtc IS NOT NULL
        BEGIN
            ;THROW 50020, N'No live session matches this token: it has never existed, it has been signed out, it was revoked, or the row has been soft-deleted. No SESSION_CONTEXT key was set, so nothing this connection does next can be authorized. Sign the user out and return them to sign-in (section 14.5).', 1;
        END;

        -- 4.  E-50023: expired or idle. Tested against the row read in step 2 rather than through
        --     auth.udfResolveSessionUser, which returns NULL for this case and for step 3's and so
        --     cannot tell the UI which message to show -- see the file header.
        IF @AbsoluteExpiryUtc <= @Now OR @IdleExpiryUtc <= @Now
        BEGIN
            SET @EndReason = CASE WHEN @AbsoluteExpiryUtc <= @Now THEN 'AbsoluteExpired' ELSE 'IdleExpired' END;

            -- Housekeeping, and best-effort by design: the session stops being a live row and leaves
            -- a logs.AuthenticationEvent behind. Swallowed, because the caller must receive E-50023
            -- and never an error out of the tidying. Inside a caller's open transaction the rollback
            -- that E-50023 provokes takes this with it, which is BL-042 -- so the refusal below does
            -- not depend on it having worked.
            BEGIN TRY
                EXEC auth.uspEndSession @UserSessionId = @UserSessionId, @EndReason = @EndReason;
            END TRY
            BEGIN CATCH
                SET @ContextMessage = @ContextMessage
                                    + N' The expired session could not be ended as housekeeping and the failure was '
                                    + N'swallowed so that it could not replace E-50023: ' + ERROR_MESSAGE ();
            END CATCH;

            SET @Failure = N'This session has expired: '
                         + CASE WHEN @AbsoluteExpiryUtc <= @Now
                                THEN N'it reached its ABSOLUTE lifetime at '
                                   + CONVERT (NVARCHAR (30), @AbsoluteExpiryUtc, 126)
                                   + N', which activity cannot extend (section 7.3)'
                                ELSE N'it went IDLE at ' + CONVERT (NVARCHAR (30), @IdleExpiryUtc, 126)
                                   + N', beyond the timeout the tenant''s authentication policy allows' END
                         + N'. It has been ended with reason ''' + @EndReason + N''' and no SESSION_CONTEXT key was '
                         + N'set. Sign the user out and return them to sign-in (section 14.5).';

            ;THROW 50023, @Failure, 1;
        END;

        -- 5.  E-50024: the account. auth.udfIsUserUsable holds the single copy of the effective
        --     lockout expression -- inactive, deleted, or locked out and the lockout not lapsed. A
        --     session that began before the lockout is still a live row, which is exactly why this is
        --     tested here and not folded into liveness.
        IF auth.udfIsUserUsable (@ResolvedUserId) = 0
        BEGIN
            ;THROW 50024, N'The account behind this session can no longer act: it is inactive, deleted, or locked out and the lockout has not lapsed. The session row is still live -- the account was disabled after sign-in -- and it is refused here rather than at authentication because this is the first statement of every request. No SESSION_CONTEXT key was set. Sign the user out (section 14.5).', 1;
        END;

        SELECT @UserName = u.UserName
          FROM auth.[User] AS u
         WHERE u.UserId = @ResolvedUserId;

        -- 6.  E-50021: the profile and its ancestry. A NULL ActiveUserProfileId is NOT an error --
        --     see the file header and UI-09 -- so the whole block is conditional, and a profileless
        --     session comes out of it with @ResolvedTenantId still NULL and three keys to set.
        IF @ResolvedProfileId IS NOT NULL
        BEGIN
            -- up.UserId = @ResolvedUserId is a defence and not a formality: a session row whose
            -- active profile belongs to somebody else is impersonation with no sign-in, and the
            -- extra predicate costs nothing on a primary-key seek.
            SELECT @ResolvedTenantId = up.TenantId
              FROM auth.UserProfile AS up
             WHERE up.UserProfileId = @ResolvedProfileId
               AND up.UserId        = @ResolvedUserId
               AND up.IsActive      = 1
               AND up.IsDeleted     = 0;

            IF @ResolvedTenantId IS NULL
            BEGIN
                ;THROW 50021, N'The profile this session is acting as is unusable: it is inactive, soft-deleted, or it does not belong to the user who holds the session. Section 8.5 -- deactivating a profile removes one hat and leaves the others, so the application should offer the user their remaining profiles rather than treating this as a failed sign-in. No SESSION_CONTEXT key was set.', 1;
            END;

            -- Ancestor-aware, which is section 5.4's logical cascade: a program office is unusable
            -- the moment the administration above it is, with no row of its own having changed.
            IF auth.udfIsTenantUsable (@ResolvedTenantId) = 0
            BEGIN
                SET @Failure = N'The tenant this profile belongs to (TenantId '
                             + CAST (@ResolvedTenantId AS NVARCHAR (11)) + N') is unusable: it, or one of its '
                             + N'ancestors, is inactive or deleted. Section 5.4 -- deactivation cascades logically, so '
                             + N'nothing about this profile''s own row has changed and the cause is somewhere above it '
                             + N'in auth.vwTenantHierarchy. No SESSION_CONTEXT key was set.';

                ;THROW 50021, @Failure, 1;
            END;
        END;

        -- 7.  Section 14.3's three-way branch. UserId is the key that is ALWAYS set on a successful
        --     call, so it -- and not UserProfileId -- is what says whether this connection already
        --     carries an identity. The comparison is NULL-safe: INTERSECT treats two NULLs as equal,
        --     which is what lets a profileless session's second call return silently instead of
        --     raising E-50022 against itself.
        SET @ExistingUserId    = TRY_CAST (SESSION_CONTEXT (N'UserId')        AS INT);
        SET @ExistingProfileId = TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT);
        SET @ContextWasSet     = CASE WHEN SESSION_CONTEXT (N'UserId') IS NULL THEN 0 ELSE 1 END;

        IF @ContextWasSet = 1
        BEGIN
            IF EXISTS (SELECT @ExistingUserId, @ExistingProfileId
                       INTERSECT
                       SELECT @ResolvedUserId, @ResolvedProfileId)
            BEGIN
                -- Present and equal. The keys are read-only and re-setting even the same value fails
                -- with 15664 (measured), so they are left alone -- and the call still slides the idle
                -- window below, because a second legitimate call in one request is activity.
                SET @AlreadyEqual = 1;
            END
            ELSE
            BEGIN
                -- Present and different. Raised BEFORE the touch, so the other profile's session is
                -- not kept alive by a call that was refused.
                SET @Failure = N'This connection already carries session context for UserId '
                             + COALESCE (CAST (@ExistingUserId AS NVARCHAR (11)), N'(none)')
                             + N' / UserProfileId '
                             + COALESCE (CAST (@ExistingProfileId AS NVARCHAR (11)), N'(none, a profileless session)')
                             + N', and this token resolves to UserId '
                             + CAST (@ResolvedUserId AS NVARCHAR (11)) + N' / UserProfileId '
                             + COALESCE (CAST (@ResolvedProfileId AS NVARCHAR (11)), N'(none, a profileless session)')
                             + N'. The keys are read-only for the life of a connection and cannot be replaced (error '
                             + N'15664), which is deliberate: it is what stops a later statement -- injected or merely '
                             + N'careless -- changing the acting identity mid-request. ONE CONNECTION MAY NOT SERVE '
                             + N'TWO PROFILES (section 14.3, UI-06): a background job iterating over profiles must '
                             + N'close and reopen, or use a connection per profile. Nothing was changed.';

                ;THROW 50022, @Failure, 1;
            END;
        END;

        -- 8.  The idle window. The tenant's policy first, the configured default second, 60 minutes
        --     last -- the same chain 110_auth_authn_procedures.sql uses when it issues the session,
        --     so activity and issue agree about the timeout. A profileless session has no tenant and
        --     lands on the configured default, which is correct: it has no policy to be governed by.
        SET @PolicyId = auth.udfResolveAuthPolicy (@ResolvedTenantId);

        SELECT @IdleMinutes = p.IdleTimeoutMinutes
          FROM auth.TenantAuthenticationPolicy AS p
         WHERE p.TenantAuthenticationPolicyId = @PolicyId;

        SET @IdleMinutes = COALESCE (@IdleMinutes
                                   , TRY_CAST ((SELECT SettingValue FROM config.ApplicationSetting
                                                 WHERE SettingKey = N'Authn.IdleTimeoutMinutes'
                                                   AND IsDeleted  = 0) AS INT), 60);

        -- LEAST is the cap, and the cap is section 7.3: activity extends the idle window and never
        -- the absolute one. Without it a long-lived request pattern would slide IdleExpiryUtc past
        -- AbsoluteExpiryUtc and the session would look alive to any check that reads only the idle
        -- column.
        SET @NewIdleExpiryUtc = LEAST (DATEADD (MINUTE, @IdleMinutes, @Now), @AbsoluteExpiryUtc);

        -- No transaction: one UPDATE is atomic by itself, and this procedure opening one on the hot
        -- path would hold a lock across the caller's whole request for no gain.
        UPDATE s
           SET s.LastSeenUtc          = @Now
             , s.IdleExpiryUtc        = @NewIdleExpiryUtc
             , s.auditModifiedBy      = @Actor
             , s.auditModifiedDateUtc = @Now
          FROM auth.UserSession AS s
         WHERE s.UserSessionId = @UserSessionId;

        -- 9.  The keys, last, and only if they are not already there. Set as a block with nothing
        --     between them that can fail, because session context is NOT rolled back with a
        --     transaction (measured) and a half-set identity is worse than none.
        --
        --     @read_only = 1 on all five: that immutability is the control section 14.3 is about.
        --
        --     UserProfileId and ActingTenantId are SKIPPED, not set to NULL, when the session has no
        --     active profile. A key set to NULL read-only is LOCKED at NULL for the life of the
        --     connection, and the profile-selection procedure Phase 6 adds could never fill it in;
        --     absent, every RLS predicate reads NULL, compares it and returns no rows -- the
        --     fail-closed direction, and what UI-09's "you have no usable profile" screen runs on.
        IF @AlreadyEqual = 0
        BEGIN
            EXEC sp_set_session_context @key = N'UserId',        @value = @ResolvedUserId, @read_only = 1;
            EXEC sp_set_session_context @key = N'AppUser',       @value = @UserName,       @read_only = 1;
            EXEC sp_set_session_context @key = N'ApplicationId', @value = @ApplicationId,  @read_only = 1;

            IF @ResolvedProfileId IS NOT NULL
            BEGIN
                EXEC sp_set_session_context @key = N'UserProfileId',  @value = @ResolvedProfileId, @read_only = 1;
                EXEC sp_set_session_context @key = N'ActingTenantId', @value = @ResolvedTenantId,  @read_only = 1;
            END;
        END;

        -- The caller is told what it is acting as rather than having to read five keys back. A NULL
        -- @UserProfileId here is the UI-09 signal, and the one thing the application must branch on.
        SET @UserId         = @ResolvedUserId;
        SET @UserProfileId  = @ResolvedProfileId;
        SET @ActingTenantId = @ResolvedTenantId;

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
        -- end -- an E-5002x inside one dooms it and the caller's own CATCH is what unwinds it.
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

        -- Bare, so the 5002x number reaches the caller unchanged: section 14.5 has the UI branch on
        -- the range, and RAISERROR would flatten every one of them to 50000.
        ;THROW;

    END CATCH;

    RETURN 0;
END;
GO


-- *** 2. auth.uspClearSessionContext ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspClearSessionContext
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Section 14.3's counterpart to auth.uspSetSessionContext.  Clears every WRITABLE session-context key this template sets
-- today that is BypassRowSecurity, and only it -- and reports through @IdentityKeysRemain whether the connection is
still carrying an identity.  Writes to no table.  Idempotent: calling it on a connection with nothing set is a
successful no-op.

IT CANNOT CLEAR THE FIVE IDENTITY KEYS, AND NOTHING CAN.  UserId, UserProfileId, ActingTenantId, AppUser and
ApplicationId are set with @read_only = 1, which makes them immutable for the LIFE OF THE CONNECTION -- measured, error
15664, on a re-set with the same value and on an attempt to set NULL.  The only thing that clears them is
sp_reset_connection, which the connection pool issues when the connection goes back.  So @IdentityKeysRemain = 1 is not
a failure; it is the truth about how this arrangement works, and the caller's answer to it is to close the connection.

========================================================================================================================
Notes:

WHY THIS EXISTS AT ALL, GIVEN THAT.  Three reasons, and the third is the one that matters:

  1. BypassRowSecurity IS clearable, and a maintenance session that ends without clearing it is a connection that keeps
     seeing every tenant's rows. auth.uspEndMaintenanceSession is the named way to do that; this is the sweep-up that
     does not care whether a bypass was set.
  2. A background job or a test fixture wants one call that means "leave this connection in a neutral state", without
     knowing which keys the current version of the template sets. When Phase 6 adds a writable key, it is cleared here
     and every caller inherits it.
  3. It is the ONE PLACE where the read-only limitation is stated in executable form. A procedure that pretended to
     clear the identity would be worse than no procedure: a job would "clear" the context, iterate to the next profile,
     and silently keep acting as the first one -- which is precisely the bug E-50022 exists to catch, arriving through
     the door marked safe.

IT DOES NOT THROW WHEN THE IDENTITY REMAINS.  Raising would make the honest call -- clear the bypass, keep the identity,
carry on with the same request -- into an error path, and callers would stop making it. The fact is REPORTED, in an
output parameter and in the description, and 950_verify_deployment.sql is where a connection that should have been
recycled and was not becomes visible.

ERROR-ONLY INSTRUMENTED: it writes to no table, opens no transaction, and its only failure modes are a failure inside
sp_set_session_context itself and an error in the instrumentation chain.  Rule 8's CATCH is still here, because "it only
clears a key" is exactly the reasoning that produced the finding rule 8 exists for.

========================================================================================================================
Example Usage and Performance:

declare @Remain bit;
exec auth.uspClearSessionContext @IdentityKeysRemain = @Remain output;
-- @Remain = 1 on any connection that has called auth.uspSetSessionContext. Close it to clear them.

No reads, no writes, no locks.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-054
Description:
Created.  Phase 3.  Section 14.3.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspClearSessionContext
      @IdentityKeysRemain BIT = NULL OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 error-only instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspClearSessionContext]')
          , @KeyParameters  NVARCHAR (MAX) = NULL
          , @ContextMessage NVARCHAR (MAX) = NULL
          , @DynamicSql     NVARCHAR (MAX) = NULL
          , @ErrorMsg       NVARCHAR (MAX) = NULL
          , @ErrorProc      NVARCHAR (300) = NULL
          , @ErrorNumber    INT            = NULL
          , @ErrorLine      INT            = NULL;

    DECLARE @BypassWasSet BIT = CASE WHEN SESSION_CONTEXT (N'BypassRowSecurity') IS NULL THEN 0 ELSE 1 END;

    SET @KeyParameters = CONCAT (N'BypassRowSecurityWasSet=', @BypassWasSet
                               , N', UserProfileId=', COALESCE (CAST (TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT)
                                                                     AS NVARCHAR (11)), N'(none)'));

    SET @ContextMessage = N'Error-only instrumented: clears the writable session-context keys only. The five identity '
                        + N'keys are read-only for the life of the connection (error 15664) and only '
                        + N'sp_reset_connection clears them -- section 14.3.';

    BEGIN TRY

        -- =========================================================================================
        -- ===== The procedure's own work starts here. Everything above and below is boilerplate. ==
        -- =========================================================================================

        -- The writable keys, one statement each. @read_only is omitted deliberately: passing 1 here
        -- would LOCK the key at NULL for the life of the connection and auth.uspBeginMaintenanceSession
        -- could never set it again.
        EXEC sp_set_session_context @key = N'BypassRowSecurity', @value = NULL;

        -- The honest answer, read back rather than assumed.
        SET @IdentityKeysRemain = CASE WHEN SESSION_CONTEXT (N'UserId')         IS NULL
                                        AND SESSION_CONTEXT (N'UserProfileId')  IS NULL
                                        AND SESSION_CONTEXT (N'ActingTenantId') IS NULL
                                        AND SESSION_CONTEXT (N'AppUser')        IS NULL
                                        AND SESSION_CONTEXT (N'ApplicationId')  IS NULL
                                       THEN 0 ELSE 1 END;

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

        -- No rollback: no transaction was opened, and a caller's is not this procedure's to end.
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


-- *** 3. auth.uspBeginMaintenanceSession ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspBeginMaintenanceSession
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Section 10.5.  Sets SESSION_CONTEXT ('BypassRowSecurity') = 1 for THIS CONNECTION ONLY, so that a named human being can
see every tenant's rows for as long as they stay connected.  Requires membership of the rlsBypassRole database role and
a stated reason, and writes a logs.AuthenticationEvent row of type 'MaintenanceBypass' -- committed BEFORE the key is
set -- so the record exists even if the session then fails.

Raises E-50070 when the caller is not a member of rlsBypassRole.  Nothing is set and nothing is written.

========================================================================================================================
Notes:

THE PROBLEM THIS SOLVES IS A HUMAN ONE.  Row-level security applies to db_owner and to sysadmin: a DBA who connects with
SSMS and selects from a protected table sees an empty grid -- no error, no warning -- and several people who meet that
cold will conclude the data has been lost.  Pretending the need does not exist produces the worst outcome available,
which is somebody disabling the policy at three in the morning and not re-enabling it.  So the door exists, it is
narrow, and every use of it is on the record.

THE KEY IS NOT read_only, AND THAT IS THE ONE PLACE THIS TEMPLATE WANTS A MUTABLE KEY.  The identity keys are immutable
because a request must not change who it is acting as; this key must be clearable, or auth.uspEndMaintenanceSession
could not exist and the only way out of a bypass would be to close the connection.

THE EVENT IS COMMITTED BEFORE THE KEY IS SET, AND THAT ORDER IS MEASURED RATHER THAN STYLISTIC.  Session context is NOT
transactional: a key set inside a transaction survives that transaction's rollback (see the file header).  So the
obvious shape -- event and key together inside the work block -- fails in the worst direction: a rollback would remove
the record and leave the bypass in force.  Committing first means the only possible mismatch is a record of a bypass
that was never granted, which is the harmless half.

WHY THE ROLE IS TESTED HERE AND NOT ONLY BY THE GRANT.  EXECUTE on this procedure is granted to rlsBypassRole alone, and
that ought to be enough.  It is tested again with IS_ROLEMEMBER because a grant is one ALTER away from being widened by
somebody who has not read this file, and because the test is what makes the refusal say WHY.  IS_ROLEMEMBER returns NULL
for a role that does not exist, and COALESCE turns that into a refusal -- fail closed, so a database missing the role
cannot be bypassed at all.

MEASURED: db_owner IS NOT A MEMBER.  On this instance IS_ROLEMEMBER (N'rlsBypassRole') returns 0 for the deploying
principal, which is dbo.  Membership of db_owner does not imply membership of a user-defined role, so the DBA who needs
this must be added to rlsBypassRole by name -- which is the whole point -- and the closing report of this file asserts
the refusal rather than demonstrating a bypass.

@Reason IS MANDATORY AND IS FREE TEXT.  Every other free-text field in this database is avoided on principle; this one is
the exception, because the value of the trail is the sentence "restoring the case file a caseworker deleted, ticket
INC-4412" and no closed vocabulary would have contained it.  It is escaped into DetailJson with STRING_ESCAPE.

THIS PROCEDURE DOES NOT CARE WHETHER SESSION CONTEXT IS ALREADY SET.  A maintenance connection normally has no identity
at all.  One that does keeps it: the bypass widens what the predicates allow and changes nothing about who the audit
columns name.

========================================================================================================================
Example Usage and Performance:

exec auth.uspBeginMaintenanceSession @Reason = N'Restoring rows a caseworker soft-deleted in error'
                                   , @TicketReference = N'INC-4412';

select count (*) from dbo.CaseFile;      -- now visible across every tenant

exec auth.uspEndMaintenanceSession;

One INSERT and one session-context write.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-066
Description:
Created.  Phase 4.  Section 10.5, and the reason auth.tvfTenantReadPredicate tests a key rather than a role.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspBeginMaintenanceSession
      @Reason          NVARCHAR (400)
    , @TicketReference NVARCHAR (100) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- FULL block, unlike the two session-context procedures above: this one is called by a person, a
    -- handful of times a month, and what it does is worth a row each time whether it succeeds or not.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspBeginMaintenanceSession]')
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

    DECLARE @IsMember     BIT            = COALESCE (IS_ROLEMEMBER (N'rlsBypassRole'), 0)
          , @ClientAddr   NVARCHAR (45)  = NULLIF (LTRIM (RTRIM (CONVERT (NVARCHAR (45)
                                                  , CONNECTIONPROPERTY ('client_net_address')))), N'')
          , @DetailJson   NVARCHAR (MAX) = NULL
          , @WasAlreadyOn BIT            = CASE WHEN SESSION_CONTEXT (N'BypassRowSecurity') IS NULL THEN 0 ELSE 1 END;

    SET @KeyParameters = CONCAT (N'@Reason=',            COALESCE (@Reason, N'(null)')
                               , N', @TicketReference=', COALESCE (@TicketReference, N'(null)')
                               , N', rlsBypassRole=',    @IsMember
                               , N', alreadyOn=',        @WasAlreadyOn);
    SET @ContextMessage = N'Section 10.5 maintenance bypass. The logs.AuthenticationEvent row is committed BEFORE the '
                        + N'session key is set, because session context is not transactional.';

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

        -- 1.  A stated reason is the price of the door. Checked before the role, so that a member who
        --     calls it carelessly is corrected and a non-member learns nothing from the difference --
        --     the refusal below is the same either way.
        IF @Reason IS NULL OR LEN (LTRIM (RTRIM (@Reason))) = 0
        BEGIN
            ;THROW 50100, N'@Reason is required and must not be blank. It is written verbatim into logs.AuthenticationEvent and it is the whole value of the trail: a bypass with no stated reason is indistinguishable, six months later, from somebody who turned row-level security off because it was in the way. Name the incident or the ticket.', 1;
        END;

        -- 2.  E-50070. COALESCE makes a missing role a refusal rather than a NULL that no branch
        --     catches, which is the fail-closed direction: a database without rlsBypassRole cannot be
        --     bypassed at all.
        IF @IsMember <> 1
        BEGIN
            ;THROW 50070, N'Refused: the caller is not a member of the rlsBypassRole database role, so row-level security is not bypassed and nothing was written. Section 10.5 -- this role is granted to NAMED HUMAN ACCOUNTS only and no application login is a member of it. Membership of db_owner or sysadmin does NOT imply it: that is measured, not assumed, and it is deliberate, because the point of the role is that somebody had to be added to it by name. Ask a DBA to add the account, and expect to say why.', 1;
        END;

        -- 3.  The record, and it goes in BEFORE the key. UserId is NULL because no auth.User row is
        --     involved -- a maintenance bypass is the only row in this table written by a person
        --     rather than by an application login, and Actor is who that person is.
        --
        --     UserName CARRIES THAT SAME NAME, and not NULL, because of
        --     CK_logs_AuthenticationEvent_Attributable: (UserId IS NOT NULL OR UserName IS NOT NULL).
        --     An event nobody can be attributed to is the one kind this table refuses to hold, and it
        --     is right to -- an audit trail with an anonymous row in it is worse than no row, because
        --     it looks like evidence. The column already exists for exactly this case: it records the
        --     name a principal PRESENTED, which for a maintenance bypass is the login that opened it.
        --     Found by database/_tests/060_row_security.sql, which is the first thing ever to reach
        --     this INSERT with a real member of rlsBypassRole; the deployment probe in section 7 only
        --     ever reaches the refusal above.
        SET @DetailJson = CONCAT (N'{"reason":"',          STRING_ESCAPE (LTRIM (RTRIM (@Reason)), 'json')
                                , N'","ticketReference":', CASE WHEN @TicketReference IS NULL THEN N'null'
                                                               ELSE N'"' + STRING_ESCAPE (@TicketReference, 'json')
                                                                  + N'"' END
                                , N',"originalLogin":"',   STRING_ESCAPE (ORIGINAL_LOGIN (), 'json')
                                , N'","effectiveLogin":"', STRING_ESCAPE (SUSER_SNAME (), 'json')
                                , N'","databaseUser":"',   STRING_ESCAPE (USER_NAME (), 'json')
                                , N'","spid":',            @@SPID
                                , N',"bypassWasAlreadySet":', @WasAlreadyOn
                                , N',"sessionProfileId":', COALESCE (CAST (TRY_CAST (SESSION_CONTEXT (N'UserProfileId')
                                                                                   AS INT) AS NVARCHAR (11)), N'null')
                                , N'}');

        INSERT logs.AuthenticationEvent
            (EventUtc, EventType, EventSeverity, ApplicationId, UserId, UserName, LoginAttemptId, UserSessionId
           , ClientAddress, Actor, DetailJson
           , auditCreatedBy, auditCreatedDateUtc, auditModifiedBy, auditModifiedDateUtc)
        VALUES
            (@Now, 'MaintenanceBypass', 'Warning'
           , TRY_CAST (SESSION_CONTEXT (N'ApplicationId') AS INT), NULL, @Actor, NULL, NULL
           , @ClientAddr, @Actor, @DetailJson
           , @Actor, @Now, @Actor, @Now);

        SET @Comments = CONCAT (N'Row-level security bypassed for SPID ', @@SPID, N' by ', ORIGINAL_LOGIN ()
                              , N'. Reason recorded in logs.AuthenticationEvent.');

        -- =========================================================================================
        -- ===== End of the procedure's own work. ==================================================
        -- =========================================================================================
        IF @@TRANCOUNT > 0
        BEGIN
            COMMIT TRANSACTION;
        END;

        -- 4.  AND ONLY NOW THE KEY. Deliberately after the COMMIT and deliberately not inside the
        --     work block: section 10.5 requires the record to exist even if the session then fails,
        --     and session context survives a rollback while the row would not. Still inside the TRY,
        --     so a failure here is recorded like any other.
        --
        --     @read_only is omitted on purpose -- this is the one key the template wants mutable, or
        --     auth.uspEndMaintenanceSession could not clear it.
        EXEC sp_set_session_context @key = N'BypassRowSecurity', @value = 1;

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


-- *** 4. auth.uspEndMaintenanceSession ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.uspEndMaintenanceSession
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Section 10.5.  Clears SESSION_CONTEXT ('BypassRowSecurity') for this connection, restoring row-level security, and
writes a logs.AuthenticationEvent row of type 'MaintenanceBypassEnded' so that the bypass window has a closing time.

Returns @BypassCleared = 1 when a bypass was in force and has been cleared, 0 when there was nothing to clear.  Calling
it when no bypass is set is a silent no-op, not an error.

========================================================================================================================
Notes:

THE KEY IS CLEARED FIRST AND THE EVENT IS WRITTEN SECOND, WHICH IS THE OPPOSITE ORDER FROM auth.uspBeginMaintenanceSession
AND FOR THE SAME REASON.  Begin records before it grants; End revokes before it records.  Both orders err towards the
trail overstating the window rather than understating it: the worst case here is a bypass that ended without a closing
row, which a reviewer can see, instead of a closing row for a bypass that is still in force, which they cannot.

CLEARING IS A WRITE OF NULL, AND IT ONLY WORKS BECAUSE Begin DID NOT PASS @read_only.  A read-only key cannot be set to
NULL -- that is Msg 15664, measured, and it is recorded in this file's header.  So the one mutable key in the template is
mutable precisely so that this procedure can exist.

THE CLEAR IS INSIDE THE TRANSACTION AND THAT IS NOT A MISTAKE.  Session context is not transactional, so the clear takes
effect immediately and survives a rollback of the event INSERT.  Inside the work block it reads naturally and behaves
correctly; there is no need for the deliberate after-the-COMMIT placement that Begin requires.

NO ROLE TEST.  Begin refuses a caller who is not in rlsBypassRole; End refuses nobody.  If the key is set the caller
already has the access, and a procedure that would not let them give it back would be a strange kind of security.
EXECUTE is still granted to rlsBypassRole only, so in practice the same people call both.

THE NO-OP PATH STILL WRITES AN ExecutionLog ROW.  A DBA who calls this twice, or who calls it on the wrong connection,
gets Successful = 1 and Comments saying nothing was set.  That is worth more than silence: it answers "did I actually
turn it off on that session?" without anybody having to guess.

========================================================================================================================
Example Usage and Performance:

declare @cleared bit;
exec auth.uspEndMaintenanceSession @BypassCleared = @cleared output;
select @cleared;                          -- 1 if a bypass was in force

One session-context write and at most one INSERT.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-066
Description:
Created.  Phase 4.  Section 10.5, the closing half of the maintenance bypass.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER PROCEDURE auth.uspEndMaintenanceSession
      @BypassCleared BIT = NULL OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- =============================================================================================
    -- Rule 8 instrumentation. Boilerplate: copy verbatim.
    -- =============================================================================================
    DECLARE @ProcName       NVARCHAR (300) = COALESCE (QUOTENAME (OBJECT_SCHEMA_NAME (@@PROCID))
                                                     + N'.' + QUOTENAME (OBJECT_NAME (@@PROCID))
                                                    , N'[auth].[uspEndMaintenanceSession]')
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

    DECLARE @WasOn      BIT            = CASE WHEN SESSION_CONTEXT (N'BypassRowSecurity') IS NULL THEN 0 ELSE 1 END
          , @ClientAddr NVARCHAR (45)  = NULLIF (LTRIM (RTRIM (CONVERT (NVARCHAR (45)
                                               , CONNECTIONPROPERTY ('client_net_address')))), N'')
          , @DetailJson NVARCHAR (MAX) = NULL;

    SET @BypassCleared = 0;
    SET @KeyParameters = CONCAT (N'bypassWasSet=', @WasOn, N', spid=', @@SPID);
    SET @ContextMessage = N'Section 10.5. The key is cleared BEFORE the closing event is written, the mirror of '
                        + N'auth.uspBeginMaintenanceSession, so the trail can only overstate the window.';

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

        IF @WasOn = 0
        BEGIN
            -- 1.  Nothing to do, and saying so is the useful answer. No event: there was no window
            --     to close, and a 'MaintenanceBypassEnded' row with no matching 'MaintenanceBypass'
            --     would be a lie told to whoever reviews this table.
            SET @Comments = N'No bypass was in force on this connection; nothing cleared and no event written.';
        END
        ELSE
        BEGIN
            -- 2.  Revoke first. @read_only was never passed by Begin, so NULL is accepted here; a
            --     read-only key would fail with Msg 15664 and the bypass would outlive the intent.
            EXEC sp_set_session_context @key = N'BypassRowSecurity', @value = NULL;

            SET @BypassCleared = 1;

            -- 3.  Record second. The rollback case leaves the bypass off and this row absent, which
            --     is the direction that cannot mislead anybody. UserName carries the actor for the
            --     same reason as the opening row: CK_logs_AuthenticationEvent_Attributable will not
            --     hold an event with neither a UserId nor a UserName.
            SET @DetailJson = CONCAT (N'{"originalLogin":"',  STRING_ESCAPE (ORIGINAL_LOGIN (), 'json')
                                    , N'","effectiveLogin":"', STRING_ESCAPE (SUSER_SNAME (), 'json')
                                    , N'","databaseUser":"',  STRING_ESCAPE (USER_NAME (), 'json')
                                    , N'","spid":',           @@SPID
                                    , N',"stillSet":',        CASE WHEN SESSION_CONTEXT (N'BypassRowSecurity') IS NULL
                                                                   THEN N'false' ELSE N'true' END
                                    , N'}');

            INSERT logs.AuthenticationEvent
                (EventUtc, EventType, EventSeverity, ApplicationId, UserId, UserName, LoginAttemptId, UserSessionId
               , ClientAddress, Actor, DetailJson
               , auditCreatedBy, auditCreatedDateUtc, auditModifiedBy, auditModifiedDateUtc)
            VALUES
                (@Now, 'MaintenanceBypassEnded', 'Info'
               , TRY_CAST (SESSION_CONTEXT (N'ApplicationId') AS INT), NULL, @Actor, NULL, NULL
               , @ClientAddr, @Actor, @DetailJson
               , @Actor, @Now, @Actor, @Now);

            SET @Comments = CONCAT (N'Row-level security restored for SPID ', @@SPID, N' by ', ORIGINAL_LOGIN (), N'.');
        END;

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
        SchemaName  SYSNAME         NOT NULL,
        ObjectType  SYSNAME         NOT NULL,
        ObjectName  SYSNAME         NOT NULL,
        ColumnName  SYSNAME             NULL,
        Description NVARCHAR (3750) NOT NULL
    );

    -- Rows rather than four EXEC calls with concatenated arguments, because an EXEC argument takes a constant or a
    -- variable and never an expression -- a '+' in the parameter position is a parse error (102), as it is for THROW.
    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    VALUES
      (N'auth', N'PROCEDURE', N'uspSetSessionContext', NULL
     , N'Turns a session token hash into the five SESSION_CONTEXT keys every row-level security predicate and audit '
     + N'default reads: UserId, AppUser, ApplicationId, UserProfileId, ActingTenantId. Sections 9, 14.3 and 14.4. THE '
     + N'PARAMETER IS THE HASH, NOT THE TOKEN -- section 9''s sketch says @SessionToken and "hashes the token", and it '
     + N'is wrong for this template (BL-043): the hash is what auth.UserSession stores and what the application sends, '
     + N'and inside the database the hash IS the credential, so it is never written to logs.ExecutionLog. ERROR-ONLY '
     + N'instrumented (rule 8) because it runs once per request: a start row per call is 4.3 million rows a day at '
     + N'fifty requests a second, and the first performance review would delete rule 8 everywhere rather than here. '
     + N'G-22. LastSeenUtc is the per-request record instead, and one narrow UPDATE needs no transaction. Keys are set '
     + N'AFTER the work because session context survives ROLLBACK (measured). A session whose ActiveUserProfileId is '
     + N'NULL is VALID and gets three keys, not five, with the profile pair left ABSENT rather than NULL -- a read-only '
     + N'NULL could never be cleared. Raises 50100 hash not 32 bytes, 50020 no such or ended session, 50023 expired or '
     + N'idle (and ends the session it refuses), 50024 user inactive or locked out, 50021 profile or tenant unusable, '
     + N'50022 already set for a different profile. Does not call auth.udfResolveSessionUser: that returns NULL for '
     + N'every failure and collapses 50020 with 50023.')
    , (N'auth', N'PROCEDURE', N'uspClearSessionContext', NULL
     , N'Clears SESSION_CONTEXT (''BypassRowSecurity'') and reports, through @IdentityKeysRemain, whether the five '
     + N'identity keys are still in force. Section 14.3. IT CANNOT DETACH AN IDENTITY AND DOES NOT PRETEND TO: the '
     + N'identity keys are set with @read_only = 1, and a read-only key can be neither re-set nor set to NULL -- Msg '
     + N'15664, measured on this instance. So the honest contract is "the bypass is off, and here is whether this '
     + N'connection is still somebody". Exists for three reasons: a pooled connection returned without '
     + N'sp_reset_connection, a maintenance window ended by a caller who does not know which half set what, and a '
     + N'background job that must be able to ASK rather than assume. It deliberately does not throw when the identity '
     + N'remains -- a caller that treats a returned 1 as fatal is free to, but a procedure that threw here would make '
     + N'every pooled clean-up call an error. ERROR-ONLY instrumented.')
    , (N'auth', N'PROCEDURE', N'uspBeginMaintenanceSession', NULL
     , N'Sets SESSION_CONTEXT (''BypassRowSecurity'') = 1 for THIS CONNECTION ONLY, so a named human being can see '
     + N'every tenant''s rows. Section 10.5. Requires membership of rlsBypassRole -- tested with IS_ROLEMEMBER as well '
     + N'as by the grant, and COALESCE turns a missing role into a refusal, so a database without the role cannot be '
     + N'bypassed at all. Membership of db_owner does NOT imply it (measured), which is the point: somebody had to be '
     + N'added by name. @Reason is mandatory and free text, escaped into DetailJson -- the value of the trail is the '
     + N'sentence a closed vocabulary would not have contained. The logs.AuthenticationEvent row of type '
     + N'MaintenanceBypass is COMMITTED BEFORE the key is set, because session context is not transactional and the '
     + N'obvious order fails in the worst direction: a rollback would remove the record and leave the bypass in force. '
     + N'The key is the one key in this template deliberately NOT read_only, or uspEndMaintenanceSession could not '
     + N'clear it. Raises 50070 when the caller is not in rlsBypassRole and 50100 on a blank reason; nothing is set and '
     + N'nothing is written. FULLY instrumented, unlike the two session-context procedures: a person calls it a few '
     + N'times a month.')
    , (N'auth', N'PROCEDURE', N'uspEndMaintenanceSession', NULL
     , N'Clears SESSION_CONTEXT (''BypassRowSecurity''), restoring row-level security, and writes the '
     + N'MaintenanceBypassEnded half of the trail so the bypass window has a closing time. Section 10.5. Returns '
     + N'@BypassCleared = 1 when a bypass was in force, 0 when there was nothing to clear -- calling it twice is a '
     + N'silent no-op, not an error, and the no-op still writes an ExecutionLog row so "did I turn it off on that '
     + N'session?" has an answer. THE KEY IS CLEARED FIRST AND THE EVENT WRITTEN SECOND, the mirror of '
     + N'uspBeginMaintenanceSession: Begin records before it grants, End revokes before it records, and both orders err '
     + N'towards a trail that overstates the window rather than one that understates it. No role test -- if the key is '
     + N'set the caller already has the access, and refusing to let them give it back would be a strange kind of '
     + N'security. EXECUTE is granted to rlsBypassRole only. FULLY instrumented.');

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


-- *** 6. Grants ***
-- Two audiences, and they are not the same audience.  The session pair is what the application calls at the start and
-- the end of every request, so applicationRole holds EXECUTE on those two and on nothing else here.  The maintenance
-- pair is for a named human being, so it goes to rlsBypassRole ALONE -- no application login is a member of that role,
-- and if one ever is, the grant is not what failed.
--
-- applicationRole is deliberately NOT granted the maintenance pair.  It would be one EXEC away from an application that
-- can read every tenant's rows, which is the whole thing sections 10 and 21 exist to prevent, and the reason
-- auth.tvfTenantReadPredicate tests a session key rather than role membership is that the key is per connection and
-- cannot be granted permanently by mistake.
--
-- Each grant is guarded on DATABASE_PRINCIPAL_ID, which keeps the file re-runnable against a database where
-- scripts/permissions.sql has not run.  The same guard is how a mistyped role name produces a procedure nobody can
-- execute and no error to say why: check these names against the report at the end of scripts/permissions.sql.
IF DATABASE_PRINCIPAL_ID (N'applicationRole') IS NOT NULL
BEGIN
    GRANT EXECUTE ON auth.uspSetSessionContext   TO applicationRole;
    GRANT EXECUTE ON auth.uspClearSessionContext TO applicationRole;
END;
GO

IF DATABASE_PRINCIPAL_ID (N'rlsBypassRole') IS NOT NULL
BEGIN
    GRANT EXECUTE ON auth.uspBeginMaintenanceSession TO rlsBypassRole;
    GRANT EXECUTE ON auth.uspEndMaintenanceSession   TO rlsBypassRole;
END;
GO


-- *** 7. Closing report ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

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
  FROM (VALUES (N'auth.uspSetSessionContext',       N'Sections 9, 14.3, 14.4. Hash in, five keys out. T-053.')
             , (N'auth.uspClearSessionContext',     N'Section 14.3. Clears the bypass; reports whether the identity remains. T-054.')
             , (N'auth.uspBeginMaintenanceSession', N'Section 10.5. rlsBypassRole only; records before it grants. T-066.')
             , (N'auth.uspEndMaintenanceSession',   N'Section 10.5. Revokes before it records; no-op is not an error. T-066.')) AS x (ProcName, Detail);

-- THE INSTRUMENTATION SHAPES ARE ASSERTED, NOT TRUSTED, because the difference between them is a judgement call that
-- somebody will "tidy up" one day.  The two session-context procedures are ERROR-ONLY: recorder present, start-logging
-- ABSENT.  The two maintenance procedures are FULL: both present.  The LIKE patterns carry the EXEC prefix on purpose --
-- sys.sql_modules.definition includes the header comment block, so a pattern matching a bare procedure name matches the
-- paragraphs that explain why the call is not there (the lesson from 150 and 165).
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Wrong = 0 THEN 4 ELSE 2 END
     , CASE WHEN x.Wrong = 0 THEN 'OK' ELSE 'WRONGSHAPE' END
     , N'Error-only instrumentation on the two session-context procedures'
     , CONCAT (x.Wrong, N' of 2 have the wrong shape. Error-only means the CATCH calls logs.uspRecordExecutionError and '
             , N'the procedure opens NO start row: one row per request would be roughly 4.3 million a day at fifty '
             , N'requests a second. G-22. LastSeenUtc is the per-request record instead.')
  FROM (SELECT Wrong = COUNT (*)
          FROM sys.sql_modules AS m
          JOIN sys.objects     AS o ON o.object_id = m.object_id
         WHERE o.schema_id = SCHEMA_ID (N'auth')
           AND o.name IN (N'uspSetSessionContext', N'uspClearSessionContext')
           AND (m.definition NOT LIKE N'%EXEC logs.uspRecordExecutionError%'
             OR m.definition LIKE N'%EXEC logs.uspStartExecutionLogging%')) AS x;

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Wrong = 0 THEN 4 ELSE 2 END
     , CASE WHEN x.Wrong = 0 THEN 'OK' ELSE 'WRONGSHAPE' END
     , N'Full instrumentation on the two maintenance procedures'
     , CONCAT (x.Wrong, N' of 2 have the wrong shape. These two are called by a person a few times a month, so every '
             , N'call earns a start row, a completion UPDATE and a transaction -- and a maintenance bypass nobody can '
             , N'account for afterwards is the failure this whole file exists to prevent.')
  FROM (SELECT Wrong = COUNT (*)
          FROM sys.sql_modules AS m
          JOIN sys.objects     AS o ON o.object_id = m.object_id
         WHERE o.schema_id = SCHEMA_ID (N'auth')
           AND o.name IN (N'uspBeginMaintenanceSession', N'uspEndMaintenanceSession')
           AND (m.definition NOT LIKE N'%EXEC logs.uspRecordExecutionError%'
             OR m.definition NOT LIKE N'%EXEC logs.uspStartExecutionLogging%'
             OR m.definition NOT LIKE N'%BEGIN TRANSACTION%')) AS x;

-- =====================================================================================================================
-- Live probes.  Every one of them is a REFUSAL or a no-op, and that is deliberate: a probe that succeeded would set
-- read-only identity keys on the deploying connection, which cannot then be cleared for the life of that connection --
-- Msg 15664, measured.  Anybody who ran this file in an SSMS window would find their next statement acting as a
-- borrowed identity.  The positive end-to-end path is exercised in database/_tests/060_*.sql, on a disposable session.
-- =====================================================================================================================
DECLARE @ErrNo  INT             = NULL
      , @ErrMsg NVARCHAR (2048) = NULL
      , @Hash   VARBINARY (32)  = HASHBYTES ('SHA2_256', N'deploy-time probe, no session has this hash')
      , @Remain BIT             = NULL;

BEGIN TRY
    EXEC auth.uspSetSessionContext @SessionTokenHash = 0x00;
END TRY
BEGIN CATCH
    SELECT @ErrNo = ERROR_NUMBER (), @ErrMsg = LEFT (ERROR_MESSAGE (), 300);
END CATCH;

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN @ErrNo = 50100 THEN 4 ELSE 2 END
     , CASE WHEN @ErrNo = 50100 THEN 'OK' ELSE 'UNEXPECTED' END
     , N'auth.uspSetSessionContext refuses a hash that is not 32 bytes (E-50100)'
     , CONCAT (N'Error ', COALESCE (CAST (@ErrNo AS NVARCHAR (11)), N'(none -- it SUCCEEDED, which is worse)')
             , N'. A short binary is silently right-padded by an implicit conversion, so the length is checked rather '
             , N'than assumed: without this, 0x00 would be compared against every stored hash, match none of them, and '
             , N'the caller would be told there was no such session.');

SET @ErrNo = NULL;

BEGIN TRY
    EXEC auth.uspSetSessionContext @SessionTokenHash = @Hash;
END TRY
BEGIN CATCH
    SELECT @ErrNo = ERROR_NUMBER (), @ErrMsg = LEFT (ERROR_MESSAGE (), 300);
END CATCH;

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN @ErrNo = 50020 THEN 4 ELSE 2 END
     , CASE WHEN @ErrNo = 50020 THEN 'OK' ELSE 'UNEXPECTED' END
     , N'auth.uspSetSessionContext refuses an unknown session (E-50020)'
     , CONCAT (N'Error ', COALESCE (CAST (@ErrNo AS NVARCHAR (11)), N'(none)')
             , N'. This is the whole procedure running end to end -- the session SELECT, the refusal, the CATCH and an '
             , N'orphan logs.ExecutionLog row with no start row before it -- without setting a single key. Appendix B: '
             , N'50020 and 50023 are separate numbers because the UI does different things with them, which is why '
             , N'this procedure reads auth.UserSession itself instead of calling auth.udfResolveSessionUser.');

SET @ErrNo = NULL;

BEGIN TRY
    EXEC auth.uspClearSessionContext @IdentityKeysRemain = @Remain OUTPUT;
    SET @ErrNo = 0;
END TRY
BEGIN CATCH
    SELECT @ErrNo = ERROR_NUMBER (), @ErrMsg = LEFT (ERROR_MESSAGE (), 300);
END CATCH;

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN @ErrNo = 0 AND @Remain = 0 THEN 4 ELSE 2 END
     , CASE WHEN @ErrNo = 0 AND @Remain = 0 THEN 'OK' ELSE 'UNEXPECTED' END
     , N'auth.uspClearSessionContext runs and reports no identity on this connection'
     , CONCAT (N'@IdentityKeysRemain = ', COALESCE (CAST (@Remain AS NVARCHAR (11)), N'(null)')
             , N', error ', COALESCE (CAST (@ErrNo AS NVARCHAR (11)), N'(none)')
             , N'. 0 is the expected answer for a deployment connection, which is nobody. Clearing when nothing is set '
             , N'is a no-op by design: the pooled-connection case cannot know what the last request left behind.');

SET @ErrNo = NULL;

-- The negative half of section 10.5, and the only half a deployment can prove.  IS_ROLEMEMBER (N'rlsBypassRole')
-- returns 0 for dbo on this instance: membership of db_owner is not membership of a user-defined role.  If this row
-- ever reads VIOLATED on a fresh database, somebody has added the deploying principal to rlsBypassRole -- which is a
-- finding, not a test failure.
BEGIN TRY
    EXEC auth.uspBeginMaintenanceSession @Reason = N'Deploy-time probe. This call is EXPECTED to be refused.';
END TRY
BEGIN CATCH
    SELECT @ErrNo = ERROR_NUMBER (), @ErrMsg = LEFT (ERROR_MESSAGE (), 300);
END CATCH;

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN @ErrNo = 50070 THEN 4
            WHEN @ErrNo IS NULL THEN 1
            ELSE 2 END
     , CASE WHEN @ErrNo = 50070 THEN 'OK'
            WHEN @ErrNo IS NULL THEN 'VIOLATED'
            ELSE 'UNEXPECTED' END
     , N'auth.uspBeginMaintenanceSession refuses the deploying principal (E-50070)'
     , CONCAT (N'Error ', COALESCE (CAST (@ErrNo AS NVARCHAR (11)), N'(none -- THE BYPASS WAS GRANTED)')
             , N'. IS_ROLEMEMBER (N''rlsBypassRole'') = '
             , COALESCE (CAST (IS_ROLEMEMBER (N'rlsBypassRole') AS NVARCHAR (11)), N'(null: the role does not exist)')
             , N'. The positive path -- a user WITHOUT LOGIN added to rlsBypassRole, the MaintenanceBypass row, the '
             , N'bypass, the MaintenanceBypassEnded row -- is exercised in database/_tests/060_*.sql.');

-- Belt and braces: the refusal above must have left no key behind, because a bypass set by a refused call is the one
-- failure mode nothing downstream would notice.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN SESSION_CONTEXT (N'BypassRowSecurity') IS NULL THEN 4 ELSE 1 END
     , CASE WHEN SESSION_CONTEXT (N'BypassRowSecurity') IS NULL THEN 'OK' ELSE 'VIOLATED' END
     , N'The refused bypass set no session key'
     , N'SESSION_CONTEXT (N''BypassRowSecurity'') must still be NULL on this connection. Session context is not '
     + N'transactional, so a key set before a refusal would survive the rollback that follows it -- which is exactly '
     + N'why that procedure sets the key AFTER its COMMIT and not inside its work block.';

-- And the refused calls must still be ON THE RECORD.  A refusal nobody can find afterwards is how "who tried to bypass
-- row security" becomes an unanswerable question.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Refusals >= 3 THEN 4 ELSE 2 END
     , CASE WHEN x.Refusals >= 3 THEN 'OK' ELSE 'INCOMPLETE' END
     , N'The refusals reached logs.ExecutionLog'
     , CONCAT (x.Refusals, N' failed row(s) recorded by the probes above in the last five minutes; three are expected. '
             , N'Rule 8 is not decoration: there is no separate error table -- logs.uspRecordExecutionError writes the '
             , N'error columns of logs.ExecutionLog, and for an error-only procedure that row is the ONLY evidence a '
             , N'request was refused and why. Two of these three rows have no start row before them, which is the '
             , N'orphan shape @ContextMessage exists to explain to whoever reads them.')
  FROM (SELECT Refusals = COUNT (*)
          FROM logs.ExecutionLog
         WHERE ProcedureName IN (N'[auth].[uspSetSessionContext]', N'[auth].[uspClearSessionContext]'
                               , N'[auth].[uspBeginMaintenanceSession]', N'[auth].[uspEndMaintenanceSession]')
           AND Successful = 0
           AND ErrorNumber IN (50100, 50020, 50070)
           AND auditCreatedDateUtc >= DATEADD (MINUTE, -5, SYSUTCDATETIME ())) AS x;

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 4 THEN 4 ELSE 2 END
     , CASE WHEN COUNT (*) = 4 THEN 'OK' ELSE 'INCOMPLETE' END
     , N'MS_Description on the session procedures'
     , CONCAT (COUNT (*), N' of 4 procedures carry a description. Conventions rule 4.')
  FROM sys.extended_properties AS ep
  JOIN sys.objects             AS o ON o.object_id = ep.major_id
 WHERE ep.class = 1
   AND ep.minor_id = 0
   AND ep.name = N'MS_Description'
   AND o.schema_id = SCHEMA_ID (N'auth')
   AND o.type = N'P'
   AND o.name IN (N'uspSetSessionContext', N'uspClearSessionContext'
                , N'uspBeginMaintenanceSession', N'uspEndMaintenanceSession');

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN DATABASE_PRINCIPAL_ID (x.RoleName) IS NULL THEN 3
            WHEN x.Granted = 2 THEN 4
            ELSE 2 END
     , CASE WHEN DATABASE_PRINCIPAL_ID (x.RoleName) IS NULL THEN 'PENDING'
            WHEN x.Granted = 2 THEN 'OK'
            ELSE 'INCOMPLETE' END
     , N'EXECUTE granted to ' + x.RoleName
     , CONCAT (x.Granted, N' of 2. ', x.Detail)
  FROM (SELECT RoleName = N'applicationRole'
             , Detail   = N'uspSetSessionContext and uspClearSessionContext. The application reaches session context '
                        + N'through these two and through nothing else -- INV-11.'
             , Granted  = (SELECT COUNT (*)
                             FROM sys.database_permissions AS dp
                             JOIN sys.database_principals  AS pr ON pr.principal_id = dp.grantee_principal_id
                            WHERE dp.class = 1
                              AND dp.permission_name = 'EXECUTE'
                              AND dp.state = 'G'
                              AND pr.name = N'applicationRole'
                              AND dp.major_id IN (COALESCE (OBJECT_ID (N'auth.uspSetSessionContext'), -1)
                                                , COALESCE (OBJECT_ID (N'auth.uspClearSessionContext'), -2)))
        UNION ALL
        SELECT RoleName = N'rlsBypassRole'
             , Detail   = N'uspBeginMaintenanceSession and uspEndMaintenanceSession, and NOT applicationRole: an '
                        + N'application one EXEC away from reading every tenant is what section 21 exists to prevent.'
             , Granted  = (SELECT COUNT (*)
                             FROM sys.database_permissions AS dp
                             JOIN sys.database_principals  AS pr ON pr.principal_id = dp.grantee_principal_id
                            WHERE dp.class = 1
                              AND dp.permission_name = 'EXECUTE'
                              AND dp.state = 'G'
                              AND pr.name = N'rlsBypassRole'
                              AND dp.major_id IN (COALESCE (OBJECT_ID (N'auth.uspBeginMaintenanceSession'), -3)
                                                , COALESCE (OBJECT_ID (N'auth.uspEndMaintenanceSession'), -4)))) AS x;

-- The vocabulary this file's two maintenance procedures INSERT.  085 owns the constraint; in a database where 085 has
-- not been re-run since T-066 neither event is accepted, and the INSERT fails at 3 a.m. rather than here.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Ok = 1 THEN 4 ELSE 1 END
     , CASE WHEN x.Ok = 1 THEN 'OK' ELSE 'STALE' END
     , N'CK_logs_AuthenticationEvent_EventType accepts the maintenance events'
     , CASE WHEN x.Ok = 1 THEN N'MaintenanceBypass and MaintenanceBypassEnded are both in the closed vocabulary.'
            ELSE N'The check constraint predates T-066. Re-run database/085_logs_auth_tables.sql, which drops and '
               + N're-adds it, or both maintenance procedures fail at the INSERT with error 547.' END
  FROM (SELECT Ok = CASE WHEN EXISTS (SELECT 1
                                        FROM sys.check_constraints
                                       WHERE name = N'CK_logs_AuthenticationEvent_EventType'
                                         AND definition LIKE N'%MaintenanceBypass%'
                                         AND definition LIKE N'%MaintenanceBypassEnded%') THEN 1 ELSE 0 END) AS x;

-- What sections 9, 10.5 and 14 need that this file does not itself contain, reported rather than omitted.
INSERT @Report (Severity, Status, Item, Detail)
SELECT 3, 'PENDING', x.Item, x.Reason
  FROM (VALUES (N'Re-run database/150_auth_query_procedures.sql'
              , N'Its closing report carries a PENDING row saying auth.uspSetSessionContext does not exist yet. It does '
              + N'now. Re-running the file re-evaluates the row; nothing else about it changes.')
             , (N'Positive path coverage'
              , N'A live sign-in, the five keys, the same-profile silent re-set and the different-profile E-50022 are '
              + N'in database/_tests/050_*.sql; the maintenance bypass window is in database/_tests/060_*.sql. A '
              + N'deployment cannot prove them without leaving a borrowed identity on its own connection.')) AS x (Item, Reason);

IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
    PRINT N'Session context and maintenance bypass: PROBLEMS found. Read the report below before the next script.';
ELSE
    PRINT N'Session context and maintenance bypass: no problems found. Items listed as PENDING belong to later scripts.';

PRINT N'';

SELECT Severity, Status, Item, Detail
  FROM @Report
 ORDER BY Severity, RowNo;
GO
