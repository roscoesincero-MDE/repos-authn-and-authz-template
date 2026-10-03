/***********************************************************************************************************************
Script:         S1_prove_duties.sql
Purpose:        Prove that the population S1_load_agency.sql generated can actually do its job -- sign in by the route
                its cohort is supposed to use, wear the hats it holds, switch between them repeatedly inside ONE session,
                and be refused what it must be refused -- entirely THROUGH THE SHIPPED PROCEDURES.
Task:           T-123.
Run with:       sqlcmd -S MDE-55TT2J4 -E -d <db> -I -C -b
                       -v DbName=<db> -v Seed=<unique-text-no-spaces> -v RunLabel=<unique-text-no-spaces>
                       -v AgencyCode=DEP -v Wave=w1
                       -i database/_scenarios/S1_prove_duties.sql
Author:         Template project
CreateDate:     2026-09-21

WHAT THIS FILE IS, AGAINST WHAT S1_load_agency.sql IS
-----------------------------------------------------
The loader is a set generator and says so: it writes auth.[User], auth.UserProfile and auth.UserProfileRole directly and
proves nothing about any procedure.  This file is the other half.  It touches no table by name except to read evidence in
the closing report, and every action a person takes here goes through auth.uspGetLoginVerifier, auth.uspVerifyMfa,
auth.uspCompleteLogin, auth.uspBeginSsoLogin, auth.uspCompleteSsoLogin, auth.uspSetSessionContext,
auth.uspSwitchProfile, auth.uspListProfilesForUser, auth.uspCreateUser, auth.uspCreateProfile and the dbo.uspCase*
family.  There is ONE exception and it is the finding this file exists to record; see section 7.

A SAMPLE, NOT A CENSUS, AND WHY THAT IS THE RIGHT TEST
-----------------------------------------------------
12,830 people signing in is 12,830 round trips and about nine hours.  What varies between two members of one cohort is
the row, not the code path: they hold the same roles at the same kind of tenant and reach the same procedures.  What
varies between COHORTS is everything.  So this file takes one member of each distinct shape and exercises it fully, and
the population's own consistency -- that every one of the 30,490 profiles has a permission scope, that every local user
has a confirmed factor -- is asserted set-wise by the loader's section 9 instead.

Between them that covers the scenario's question.  What it does NOT cover is contention: 12,830 people signing in AT ONCE
is a concurrency test and wants a load harness, not sqlcmd.  That gap is stated rather than papered over -- G-49.

ONE CONNECTION CANNOT WEAR TWO HATS, WHICH IS WHY THIS FILE IS MOSTLY :connect
-----------------------------------------------------------------------------
sp_set_session_context with @read_only = 1 cannot be re-set or cleared -- Msg 15664, measured in
database/105_auth_session_procedures.sql's header -- so a connection that has established one profile's context keeps it
until the connection dies.  auth.uspSwitchProfile therefore moves auth.UserSession.ActiveUserProfileId and leaves the
CALLING connection still wearing the old hat: UI-36 and BL-057.  The new hat arrives on the next connection.

The scenario asks for "the ability to switch profiles multiple times a session", and that sentence has a cost this file
is built to make visible: N switches in one session cost N + 1 connections.  Section 6 spends six of them on one
session -- agency, four counties, agency again -- and every hop does real work under the new hat before handing on, so a
switch that reported success but changed nothing would fail the hop after it rather than passing quietly.

$(SQLCMDSERVER) is sqlcmd's own record of the -S it was given, so a reconnection cannot drift to another instance.

HOW A FAILURE SHOWS UP
----------------------
Every observation is an IF that PRINTs "OK: ..." or PRINTs "VIOLATED: ..." and THROWs.  With sqlcmd -b a THROW ends the
run with exit code 1, so the pass criterion is exit 0 -- there is no ledger to mis-total, and a section that never ran
cannot be counted as passing.  The closing report then re-derives the whole run from DURABLE EVIDENCE that the procedures
themselves wrote -- logs.AuthenticationEvent, logs.AuthorizationDenial and dbo.CaseFile -- rather than from anything this
script remembers, because a test that believes its own bookkeeping is testing its bookkeeping.

RUNNING IT TWICE
----------------
Pass a different -v RunLabel.  RunLabel is part of every case number and every name this file creates, and -v Seed
decides the session token hashes, so two runs neither collide nor share a session.

Depends on:     database/_scenarios/S1_load_agency.sql, run for the same -v AgencyCode and -v Wave.
Implements:     test_scenario_1.txt.  See docs/60-scenario-test-1.md.
***********************************************************************************************************************/

SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;
GO

PRINT N'--- S1_prove_duties.sql: $(AgencyCode) wave $(Wave), run $(RunLabel), in [$(DbName)] ---';
GO


/*---------------------------------------------------------------------------------------------------------------------
CONNECTION 1.  db_owner, no session.  Establishes that the population this file expects is actually present and names
the seven sample people, so that a failure downstream can be traced to a person rather than to a cohort.
---------------------------------------------------------------------------------------------------------------------*/

-- *** 1. Preflight ***
DECLARE @Pfx    NVARCHAR (100) = LOWER (N'$(AgencyCode)') + N'.$(Wave).'
      , @App    INT = (SELECT ApplicationId FROM auth.Application WHERE ApplicationCode = N'TEMPLATE' AND IsDeleted = 0)
      , @Agency INT
      , @Users  INT
      , @Miss   INT = 0;

SELECT @Agency = TenantId FROM auth.Tenant
 WHERE ApplicationId = @App AND TenantCode = N'$(AgencyCode)' AND IsDeleted = 0 AND IsActive = 1;

SELECT @Users = COUNT (*) FROM auth.[User] WHERE UserName LIKE @Pfx + N'%' AND IsDeleted = 0;

IF @Agency IS NULL OR @Users = 0
BEGIN
    PRINT N'VIOLATED: no $(AgencyCode) agency, or no wave $(Wave) users. Run S1_load_agency.sql first.';
    THROW 59200, N'Scenario population absent.', 1;
END;

SELECT @Miss = COUNT (*)
  FROM (VALUES (@Pfx + N'd1.0001'), (@Pfx + N'd4.0001'), (@Pfx + N'd5.0001')
             , (@Pfx + N'c1.002.0001'), (@Pfx + N'c2.001.0001'), (@Pfx + N'c4.001.0001')
       ) AS w (UserName)
 WHERE NOT EXISTS (SELECT 1 FROM auth.[User] AS u WHERE u.UserName = w.UserName AND u.IsDeleted = 0);

IF @Miss > 0
BEGIN
    PRINT CONCAT (N'VIOLATED: ', @Miss, N' of the six named sample users is missing from wave $(Wave).');
    THROW 59201, N'Sample users absent.', 1;
END;

PRINT CONCAT (N'OK: section 1 -- agency tenant ', @Agency, N' with ', @Users
            , N' wave $(Wave) users present; all six named samples resolve.');

-- The C6 sample cannot be named in advance: which ten counties hold the eleven-county cohort is a seeded draw. Taking
-- the lowest user name is deterministic for a given seed and is printed so the run can be reproduced.
DECLARE @C6 NVARCHAR (512) = (SELECT MIN (UserName) FROM auth.[User]
                               WHERE UserName LIKE @Pfx + N'c6.%' AND IsDeleted = 0)
      , @C6Profiles INT;

SELECT @C6Profiles = COUNT (*) FROM auth.UserProfile AS up
 INNER JOIN auth.[User] AS u ON u.UserId = up.UserId
 WHERE u.UserName = @C6 AND up.IsDeleted = 0;

PRINT CONCAT (N'OK: section 1 -- eleven-county sample is ', @C6, N', holding ', @C6Profiles, N' profiles.');
GO


/*---------------------------------------------------------------------------------------------------------------------
CONNECTION 2.  A county CRUD user signs in the way every county user must: local credentials, and a second factor the
tenant policy insists on.  This connection AUTHENTICATES and is then spent -- it declares the hat and cannot wear it.
---------------------------------------------------------------------------------------------------------------------*/
:connect $(SQLCMDSERVER)
USE [$(DbName)];
GO
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;
GO

-- *** 2. Local sign-in with 2FA, then declare the CRUD hat ***
DECLARE @Name  NVARCHAR (512) = LOWER (N'$(AgencyCode)') + N'.$(Wave).c2.001.0001'
      , @Hash  VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|countycrud')
      , @Att   BIGINT, @Phc NVARCHAR (1024), @Mfa BIT, @Ok BIT
      , @Sid   BIGINT, @Uid INT, @Must BIT, @Abs DATETIME2 (7), @Idle DATETIME2 (7)
      , @Pid   INT
      , @Step  BIGINT
      , @Last  BIGINT;

-- A TOTP step may be spent ONCE, ever, and must sit within Authn.TotpWindowSteps of the server's own step -- both halves
-- of E-50111.  So a test that signs the same person in twice inside one 30-second window is refused, and the refusal is
-- CORRECT: measured against dep.w1.c2.001.0001, which reported step 59666672 twenty seconds after spending it.  The fix
-- is not to fudge the step, which would test nothing; it is to do what a person does and wait for the next code.  The
-- step itself always comes from the clock, never from the stored value.
SELECT @Last = MAX (m.LastUsedTimeStep)
  FROM auth.UserMfaFactor AS m
 INNER JOIN auth.[User]   AS u ON u.UserId = m.UserId
 WHERE u.UserName = @Name AND m.FactorType = 'Totp' AND m.IsConfirmed = 1 AND m.IsDeleted = 0;

SET @Step = DATEDIFF_BIG (SECOND, CAST (N'1970-01-01T00:00:00' AS DATETIME2 (0)), SYSUTCDATETIME ()) / 30;

IF @Last >= @Step
BEGIN
    PRINT CONCAT (N'   (waiting 31s for the next TOTP step: ', @Name, N' already spent step ', @Last, N'.)');
    WAITFOR DELAY '00:00:31';
    SET @Step = DATEDIFF_BIG (SECOND, CAST (N'1970-01-01T00:00:00' AS DATETIME2 (0)), SYSUTCDATETIME ()) / 30;
END;

IF @Last >= @Step
BEGIN
    PRINT CONCAT (N'VIOLATED: ', @Name, N' holds LastUsedTimeStep ', @Last, N', which is ahead of the server step '
                , @Step, N'. A clock has moved backwards and no code can be accepted.');
    THROW 59222, N'TOTP step is ahead of the server clock.', 1;
END;

SELECT @Pid = up.UserProfileId
  FROM auth.UserProfile AS up
 INNER JOIN auth.[User] AS u ON u.UserId   = up.UserId
 INNER JOIN auth.Tenant AS t ON t.TenantId = up.TenantId
 WHERE u.UserName = @Name AND t.TenantCode = N'$(AgencyCode)-C001' AND up.ProfileName = N'CRUD'
   AND up.IsDeleted = 0 AND u.IsDeleted = 0;

EXEC auth.uspGetLoginVerifier @ApplicationCode = N'TEMPLATE', @UserName = @Name
                            , @ClientAddress = N'198.51.100.11', @TenantCode = N'$(AgencyCode)-C001'
                            , @UserAgent = N'S1_prove_duties'
                            , @LoginAttemptId = @Att OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;

IF @Mfa <> 1
BEGIN
    PRINT N'VIOLATED: a county user with a confirmed TOTP factor under a RequireMfaForLocal policy was not asked for one.';
    THROW 59202, N'MFA not demanded.', 1;
END;

PRINT CONCAT (N'OK: section 2 -- login attempt ', @Att, N' opened, verifier returned, MFA demanded.');

EXEC auth.uspVerifyMfa @LoginAttemptId = @Att, @TimeStep = @Step, @FactorType = 'Totp', @MfaSatisfied = @Ok OUTPUT;

IF @Ok <> 1
BEGIN
    PRINT N'VIOLATED: auth.uspVerifyMfa did not satisfy the second factor for a confirmed Totp enrolment.';
    THROW 59203, N'MFA not satisfied.', 1;
END;

EXEC auth.uspCompleteLogin @LoginAttemptId = @Att, @PasswordVerified = 1, @SessionTokenHash = @Hash
                         , @IsBypassRoute = 0, @UserSessionId = @Sid OUTPUT, @UserId = @Uid OUTPUT
                         , @MustChangePassword = @Must OUTPUT, @AbsoluteExpiryUtc = @Abs OUTPUT
                         , @IdleExpiryUtc = @Idle OUTPUT;

EXEC auth.uspSwitchProfile @SessionTokenHash = @Hash, @TargetUserProfileId = @Pid;

PRINT CONCAT (N'OK: section 2 -- session ', @Sid, N' established for a county CRUD user and pointed at profile ', @Pid
            , N'. This connection still reports ActingTenantId '
            , COALESCE (TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS NVARCHAR (20)), N'(none)')
            , N' and always will.');
GO


/*---------------------------------------------------------------------------------------------------------------------
CONNECTION 3.  The same session, a working connection.  Read, insert, update, soft delete -- four of the five verbs the
scenario's "CRUD access profile" is defined by, through the demo domain, with row security live.
---------------------------------------------------------------------------------------------------------------------*/
:connect $(SQLCMDSERVER)
USE [$(DbName)];
GO
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;
GO

-- *** 3. A county CRUD profile does the county's work ***
DECLARE @Hash VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|countycrud')
      , @U INT, @P INT, @T INT, @Case INT, @Note BIGINT, @Tc NVARCHAR (100), @Rows INT;

EXEC auth.uspSetSessionContext @SessionTokenHash = @Hash, @UserId = @U OUTPUT, @UserProfileId = @P OUTPUT
                            , @ActingTenantId = @T OUTPUT;

SELECT @Tc = TenantCode FROM auth.Tenant WHERE TenantId = @T;

IF @Tc <> N'$(AgencyCode)-C001'
BEGIN
    PRINT CONCAT (N'VIOLATED: the hat declared on connection 2 did not arrive. ActingTenantId resolves to ', @Tc, N'.');
    THROW 59204, N'Hat did not arrive.', 1;
END;

PRINT CONCAT (N'OK: section 3 -- context established: user ', @U, N', profile ', @P, N', acting tenant ', @Tc, N'.');

EXEC dbo.uspCreateCaseFile @SessionTokenHash = @Hash, @CaseNumber = N'$(RunLabel)-C001-01'
                         , @Title = N'County inspection, opened by a CRUD profile', @AssignedToProfileId = @P
                         , @CaseFileId = @Case OUTPUT;

IF @Case IS NULL
BEGIN
    PRINT N'VIOLATED: a profile holding Data.Insert could not create a case file.';
    THROW 59205, N'Insert refused.', 1;
END;

-- 'approved' is not in this procedure's vocabulary and that is deliberate: dbo.uspApproveCaseFile owns approval because
-- it is a timestamp and a person, not a status. The permitted set is draft, open, pending, rejected, closed, withdrawn.
EXEC dbo.uspUpdateCaseFile @SessionTokenHash = @Hash, @CaseFileId = @Case
                         , @Title = N'County inspection, amended', @CaseStatus = 'pending';

EXEC dbo.uspAddCaseNote @SessionTokenHash = @Hash, @CaseFileId = @Case
                      , @NoteText = N'Note added by the county CRUD profile.', @IsInternal = 0
                      , @CaseNoteId = @Note OUTPUT;

EXEC dbo.uspGetCaseFile @SessionTokenHash = @Hash, @CaseFileId = @Case;

PRINT CONCAT (N'OK: section 3 -- case file ', @Case, N' created, updated, annotated (note ', @Note
            , N') and read back. Insert, update and read all exercised.');

-- The fourth verb. Soft delete demands BOTH Data.SoftDelete and Data.Update, which is why CRUD_ACCESS carries both.
EXEC dbo.uspSoftDeleteCaseFile @SessionTokenHash = @Hash, @CaseFileId = @Case
                             , @Reason = N'Exercising the soft-delete verb of the scenario''s CRUD definition.';

SELECT @Rows = COUNT (*) FROM dbo.CaseFile WHERE CaseFileId = @Case AND IsDeleted = 1;

IF @Rows <> 1
BEGIN
    PRINT N'VIOLATED: dbo.uspSoftDeleteCaseFile reported success and the row is not soft deleted.';
    THROW 59206, N'Soft delete did not land.', 1;
END;

PRINT N'OK: section 3 -- the case file is soft deleted, not gone. Four of CRUD''s five verbs proved.';

-- A second case file, left live, so that section 5 has something a DIFFERENT county must not be able to see.
EXEC dbo.uspCreateCaseFile @SessionTokenHash = @Hash, @CaseNumber = N'$(RunLabel)-C001-02'
                         , @Title = N'County inspection, left open for the row-security check'
                         , @AssignedToProfileId = @P, @CaseFileId = @Case OUTPUT;

PRINT CONCAT (N'OK: section 3 -- case file ', @Case, N' left live in $(AgencyCode)-C001 for section 5.');
GO


/*---------------------------------------------------------------------------------------------------------------------
CONNECTION 4.  A read-only county user in a DIFFERENT county signs in.  Two things have to be true of them and only one
is about permissions: they may not write, and they may not SEE county C001 at all.
---------------------------------------------------------------------------------------------------------------------*/
:connect $(SQLCMDSERVER)
USE [$(DbName)];
GO
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;
GO

-- *** 4. Read-only sign-in ***
DECLARE @Name  NVARCHAR (512) = LOWER (N'$(AgencyCode)') + N'.$(Wave).c1.002.0001'
      , @Hash  VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|countyread')
      , @Att   BIGINT, @Phc NVARCHAR (1024), @Mfa BIT, @Ok BIT
      , @Sid   BIGINT, @Uid INT, @Must BIT, @Abs DATETIME2 (7), @Idle DATETIME2 (7), @Pid INT
      , @Step  BIGINT
      , @Last  BIGINT;

-- A TOTP step may be spent ONCE, ever, and must sit within Authn.TotpWindowSteps of the server's own step -- both halves
-- of E-50111.  So a test that signs the same person in twice inside one 30-second window is refused, and the refusal is
-- CORRECT: measured against dep.w1.c2.001.0001, which reported step 59666672 twenty seconds after spending it.  The fix
-- is not to fudge the step, which would test nothing; it is to do what a person does and wait for the next code.  The
-- step itself always comes from the clock, never from the stored value.
SELECT @Last = MAX (m.LastUsedTimeStep)
  FROM auth.UserMfaFactor AS m
 INNER JOIN auth.[User]   AS u ON u.UserId = m.UserId
 WHERE u.UserName = @Name AND m.FactorType = 'Totp' AND m.IsConfirmed = 1 AND m.IsDeleted = 0;

SET @Step = DATEDIFF_BIG (SECOND, CAST (N'1970-01-01T00:00:00' AS DATETIME2 (0)), SYSUTCDATETIME ()) / 30;

IF @Last >= @Step
BEGIN
    PRINT CONCAT (N'   (waiting 31s for the next TOTP step: ', @Name, N' already spent step ', @Last, N'.)');
    WAITFOR DELAY '00:00:31';
    SET @Step = DATEDIFF_BIG (SECOND, CAST (N'1970-01-01T00:00:00' AS DATETIME2 (0)), SYSUTCDATETIME ()) / 30;
END;

IF @Last >= @Step
BEGIN
    PRINT CONCAT (N'VIOLATED: ', @Name, N' holds LastUsedTimeStep ', @Last, N', which is ahead of the server step '
                , @Step, N'. A clock has moved backwards and no code can be accepted.');
    THROW 59222, N'TOTP step is ahead of the server clock.', 1;
END;

SELECT @Pid = up.UserProfileId
  FROM auth.UserProfile AS up
 INNER JOIN auth.[User] AS u ON u.UserId   = up.UserId
 INNER JOIN auth.Tenant AS t ON t.TenantId = up.TenantId
 WHERE u.UserName = @Name AND t.TenantCode = N'$(AgencyCode)-C002' AND up.IsDeleted = 0 AND u.IsDeleted = 0;

EXEC auth.uspGetLoginVerifier @ApplicationCode = N'TEMPLATE', @UserName = @Name
                            , @ClientAddress = N'198.51.100.12', @TenantCode = N'$(AgencyCode)-C002'
                            , @UserAgent = N'S1_prove_duties'
                            , @LoginAttemptId = @Att OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;

EXEC auth.uspVerifyMfa @LoginAttemptId = @Att, @TimeStep = @Step, @FactorType = 'Totp', @MfaSatisfied = @Ok OUTPUT;

EXEC auth.uspCompleteLogin @LoginAttemptId = @Att, @PasswordVerified = 1, @SessionTokenHash = @Hash
                         , @IsBypassRoute = 0, @UserSessionId = @Sid OUTPUT, @UserId = @Uid OUTPUT
                         , @MustChangePassword = @Must OUTPUT, @AbsoluteExpiryUtc = @Abs OUTPUT
                         , @IdleExpiryUtc = @Idle OUTPUT;

-- A read-only profile holds Data.Read only. Nothing in the Authz, User, Tenant or Platform categories, so it is NOT
-- privileged and auth.uspSwitchProfile's step-up test does not apply to it. That is the control for section 7.
EXEC auth.uspSwitchProfile @SessionTokenHash = @Hash, @TargetUserProfileId = @Pid;

PRINT CONCAT (N'OK: section 4 -- session ', @Sid, N' established for a read-only county user, profile ', @Pid
            , N'. An unprivileged profile switched with no step-up, which is the control for section 7.');
GO


/*---------------------------------------------------------------------------------------------------------------------
CONNECTION 5.  The read-only hat at work: what it can do, what it is refused, and what it cannot see.
---------------------------------------------------------------------------------------------------------------------*/
:connect $(SQLCMDSERVER)
USE [$(DbName)];
GO
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;
GO

-- *** 5. Read-only means read, and row security means one county ***
DECLARE @Hash VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|countyread')
      , @U INT, @P INT, @T INT, @Case INT, @Err INT = 0, @Seen INT, @Tc NVARCHAR (100);

EXEC auth.uspSetSessionContext @SessionTokenHash = @Hash, @UserId = @U OUTPUT, @UserProfileId = @P OUTPUT
                            , @ActingTenantId = @T OUTPUT;

SELECT @Tc = TenantCode FROM auth.Tenant WHERE TenantId = @T;

EXEC dbo.uspListCaseFiles @SessionTokenHash = @Hash, @TopN = 10;

PRINT CONCAT (N'OK: section 5 -- the read-only profile listed case files from ', @Tc, N' without error.');

BEGIN TRY
    EXEC dbo.uspCreateCaseFile @SessionTokenHash = @Hash, @CaseNumber = N'$(RunLabel)-C002-01'
                             , @Title = N'A read-only profile must not be able to open this'
                             , @AssignedToProfileId = @P, @CaseFileId = @Case OUTPUT;
END TRY
BEGIN CATCH
    SET @Err = ERROR_NUMBER ();
END CATCH;

IF @Err = 0
BEGIN
    PRINT N'VIOLATED: a profile holding only Data.Read created a case file.';
    THROW 59207, N'Read-only profile could write.', 1;
END;

PRINT CONCAT (N'OK: section 5 -- the insert was refused with error ', @Err
            , N'. Read-only is enforced by permission, not by the user interface.');

-- Row security. The live case file section 3 left in C001 exists; from C002 it must not be visible AT ALL -- not as a
-- forbidden row, as no row. auth.tvfTenantReadPredicate is what makes the difference.
SELECT @Seen = COUNT (*) FROM dbo.CaseFile WHERE CaseNumber = N'$(RunLabel)-C001-02';

IF @Seen <> 0
BEGIN
    PRINT CONCAT (N'VIOLATED: a $(AgencyCode)-C002 profile can see ', @Seen, N' row(s) belonging to $(AgencyCode)-C001.');
    THROW 59208, N'Row security leaked across counties.', 1;
END;

PRINT N'OK: section 5 -- C001''s live case file is invisible from C002. Counties are isolated from each other.';
GO


/*---------------------------------------------------------------------------------------------------------------------
CONNECTION 6.  The agency's CRUD switcher arrives through Microsoft Entra -- no password, no second factor, a federated
identity and a trusted issuer.  This is the first hop of the six-hop tour that answers the scenario's hardest sentence.
---------------------------------------------------------------------------------------------------------------------*/
:connect $(SQLCMDSERVER)
USE [$(DbName)];
GO
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;
GO

-- *** 6. Entra SSO sign-in, and hop 1 of the tour ***
DECLARE @Name   NVARCHAR (512) = LOWER (N'$(AgencyCode)') + N'.$(Wave).d4.0001'
      , @Hash   VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|tour')
      , @Issuer NVARCHAR (1024) = N'https://login.microsoftonline.com/$(AgencyCode)-tenant/v2.0'
      , @Att    BIGINT, @Sid BIGINT, @Uid INT, @Must BIT, @Abs DATETIME2 (7), @Idle DATETIME2 (7)
      , @Sub    NVARCHAR (512), @Pid INT, @Cred INT;

SET @Sub = N'sub-' + CONVERT (NVARCHAR (64), HASHBYTES ('SHA2_256', @Name), 2);

SELECT @Cred = COUNT (*) FROM auth.UserCredential AS c
 INNER JOIN auth.[User] AS u ON u.UserId = c.UserId
 WHERE u.UserName = @Name AND c.IsDeleted = 0;

IF @Cred <> 0
BEGIN
    PRINT N'VIOLATED: an Entra-only agency user holds a local password row.';
    THROW 59209, N'Federated user has a password.', 1;
END;

SELECT @Pid = up.UserProfileId
  FROM auth.UserProfile AS up
 INNER JOIN auth.[User] AS u ON u.UserId   = up.UserId
 INNER JOIN auth.Tenant AS t ON t.TenantId = up.TenantId
 WHERE u.UserName = @Name AND t.TenantCode = N'$(AgencyCode)' AND up.IsDeleted = 0 AND u.IsDeleted = 0;

EXEC auth.uspBeginSsoLogin @ApplicationCode = N'TEMPLATE', @ClientAddress = N'203.0.113.21'
                         , @TenantCode = N'$(AgencyCode)', @Issuer = @Issuer, @UserNameHint = @Name
                         , @UserAgent = N'S1_prove_duties', @LoginAttemptId = @Att OUTPUT;

EXEC auth.uspCompleteSsoLogin @LoginAttemptId = @Att, @Issuer = @Issuer, @SubjectId = @Sub
                            , @SessionTokenHash = @Hash, @UserSessionId = @Sid OUTPUT, @UserId = @Uid OUTPUT
                            , @MustChangePassword = @Must OUTPUT, @AbsoluteExpiryUtc = @Abs OUTPUT
                            , @IdleExpiryUtc = @Idle OUTPUT;

EXEC auth.uspSwitchProfile @SessionTokenHash = @Hash, @TargetUserProfileId = @Pid;

PRINT CONCAT (N'OK: section 6 -- Entra sign-in for an agency CRUD switcher. Session ', @Sid
            , N', no password row, no second factor, hop 1 hat is agency profile ', @Pid, N'.');
GO


/*---------------------------------------------------------------------------------------------------------------------
CONNECTION 7.  TOUR HOP 1 -- the agency.  Every hop has the same three beats: pick up the hat, do work that only that
hat can do, hand the session on to the next hat.  The switch at the end of a hop SPENDS this connection, which is why
there are six of these blocks and not one loop.
---------------------------------------------------------------------------------------------------------------------*/
:connect $(SQLCMDSERVER)
USE [$(DbName)];
GO
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;
GO

DECLARE @Hash VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|tour')
      , @Here NVARCHAR (100) = N'$(AgencyCode)'
      , @Next NVARCHAR (100) = N'$(AgencyCode)-C005'
      , @Hop  INT            = 1
      , @U INT, @P INT, @T INT, @Tc NVARCHAR (100), @Case INT, @Pid INT;

EXEC auth.uspSetSessionContext @SessionTokenHash = @Hash, @UserId = @U OUTPUT, @UserProfileId = @P OUTPUT
                            , @ActingTenantId = @T OUTPUT;
SELECT @Tc = TenantCode FROM auth.Tenant WHERE TenantId = @T;
IF @Tc <> @Here
BEGIN
    PRINT CONCAT (N'VIOLATED: hop ', @Hop, N' expected to be wearing ', @Here, N' and is wearing ', @Tc, N'.');
    THROW 59210, N'Tour hop landed on the wrong tenant.', 1;
END;

EXEC dbo.uspCreateCaseFile @SessionTokenHash = @Hash
                         , @CaseNumber = N'$(RunLabel)-TOUR-1', @Title = N'Tour hop 1, worn at $(AgencyCode)'
                         , @AssignedToProfileId = @P, @CaseFileId = @Case OUTPUT;

SELECT @Pid = up.UserProfileId FROM auth.UserProfile AS up
 INNER JOIN auth.Tenant AS t ON t.TenantId = up.TenantId
 WHERE up.UserId = @U AND t.TenantCode = @Next AND up.IsDeleted = 0;

EXEC auth.uspSwitchProfile @SessionTokenHash = @Hash, @TargetUserProfileId = @Pid;

PRINT CONCAT (N'OK: section 6 -- hop ', @Hop, N' at ', @Tc, N': case file ', @Case
            , N' opened, session handed to ', @Next, N' (profile ', @Pid, N').');
GO


/*---------------------------------------------------------------------------------------------------------------------
CONNECTION 8.  TOUR HOP 2 -- county C005.  Switch number 1 of the session has happened; this proves it took effect.
---------------------------------------------------------------------------------------------------------------------*/
:connect $(SQLCMDSERVER)
USE [$(DbName)];
GO
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;
GO

DECLARE @Hash VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|tour')
      , @Here NVARCHAR (100) = N'$(AgencyCode)-C005'
      , @Next NVARCHAR (100) = N'$(AgencyCode)-C010'
      , @Hop  INT            = 2
      , @U INT, @P INT, @T INT, @Tc NVARCHAR (100), @Case INT, @Pid INT, @Cross INT;

EXEC auth.uspSetSessionContext @SessionTokenHash = @Hash, @UserId = @U OUTPUT, @UserProfileId = @P OUTPUT
                            , @ActingTenantId = @T OUTPUT;
SELECT @Tc = TenantCode FROM auth.Tenant WHERE TenantId = @T;
IF @Tc <> @Here
BEGIN
    PRINT CONCAT (N'VIOLATED: hop ', @Hop, N' expected to be wearing ', @Here, N' and is wearing ', @Tc, N'.');
    THROW 59210, N'Tour hop landed on the wrong tenant.', 1;
END;

-- The agency case file from hop 1 must now be OUT OF REACH. The same person, the same session, one switch, and the
-- visible world has changed -- which is the whole claim of per-profile row security and the thing a UI most easily gets
-- wrong by caching the previous hat's rows.
SELECT @Cross = COUNT (*) FROM dbo.CaseFile WHERE CaseNumber = N'$(RunLabel)-TOUR-1';
IF @Cross <> 0
BEGIN
    PRINT N'VIOLATED: the county hat can still see the case file the agency hat created one switch ago.';
    THROW 59211, N'Switch did not narrow the visible set.', 1;
END;

EXEC dbo.uspCreateCaseFile @SessionTokenHash = @Hash
                         , @CaseNumber = N'$(RunLabel)-TOUR-2', @Title = N'Tour hop 2, worn at C005'
                         , @AssignedToProfileId = @P, @CaseFileId = @Case OUTPUT;

SELECT @Pid = up.UserProfileId FROM auth.UserProfile AS up
 INNER JOIN auth.Tenant AS t ON t.TenantId = up.TenantId
 WHERE up.UserId = @U AND t.TenantCode = @Next AND up.IsDeleted = 0;

EXEC auth.uspSwitchProfile @SessionTokenHash = @Hash, @TargetUserProfileId = @Pid;

PRINT CONCAT (N'OK: section 6 -- hop ', @Hop, N' at ', @Tc, N': hop 1''s agency case file is out of reach, case file '
            , @Case, N' opened here, session handed to ', @Next, N'.');
GO


/*---------------------------------------------------------------------------------------------------------------------
CONNECTION 9.  TOUR HOP 3 -- county C010.  Switch 2.
---------------------------------------------------------------------------------------------------------------------*/
:connect $(SQLCMDSERVER)
USE [$(DbName)];
GO
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;
GO

DECLARE @Hash VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|tour')
      , @Here NVARCHAR (100) = N'$(AgencyCode)-C010'
      , @Next NVARCHAR (100) = N'$(AgencyCode)-C020'
      , @Hop  INT            = 3
      , @U INT, @P INT, @T INT, @Tc NVARCHAR (100), @Case INT, @Pid INT;

EXEC auth.uspSetSessionContext @SessionTokenHash = @Hash, @UserId = @U OUTPUT, @UserProfileId = @P OUTPUT
                            , @ActingTenantId = @T OUTPUT;
SELECT @Tc = TenantCode FROM auth.Tenant WHERE TenantId = @T;
IF @Tc <> @Here
BEGIN
    PRINT CONCAT (N'VIOLATED: hop ', @Hop, N' expected to be wearing ', @Here, N' and is wearing ', @Tc, N'.');
    THROW 59210, N'Tour hop landed on the wrong tenant.', 1;
END;

EXEC dbo.uspCreateCaseFile @SessionTokenHash = @Hash
                         , @CaseNumber = N'$(RunLabel)-TOUR-3', @Title = N'Tour hop 3, worn at C010'
                         , @AssignedToProfileId = @P, @CaseFileId = @Case OUTPUT;

SELECT @Pid = up.UserProfileId FROM auth.UserProfile AS up
 INNER JOIN auth.Tenant AS t ON t.TenantId = up.TenantId
 WHERE up.UserId = @U AND t.TenantCode = @Next AND up.IsDeleted = 0;

EXEC auth.uspSwitchProfile @SessionTokenHash = @Hash, @TargetUserProfileId = @Pid;

PRINT CONCAT (N'OK: section 6 -- hop ', @Hop, N' at ', @Tc, N': case file ', @Case, N' opened, handed to ', @Next, N'.');
GO


/*---------------------------------------------------------------------------------------------------------------------
CONNECTION 10.  TOUR HOP 4 -- county C020.  Switch 3.
---------------------------------------------------------------------------------------------------------------------*/
:connect $(SQLCMDSERVER)
USE [$(DbName)];
GO
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;
GO

DECLARE @Hash VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|tour')
      , @Here NVARCHAR (100) = N'$(AgencyCode)-C020'
      , @Next NVARCHAR (100) = N'$(AgencyCode)-C030'
      , @Hop  INT            = 4
      , @U INT, @P INT, @T INT, @Tc NVARCHAR (100), @Case INT, @Pid INT;

EXEC auth.uspSetSessionContext @SessionTokenHash = @Hash, @UserId = @U OUTPUT, @UserProfileId = @P OUTPUT
                            , @ActingTenantId = @T OUTPUT;
SELECT @Tc = TenantCode FROM auth.Tenant WHERE TenantId = @T;
IF @Tc <> @Here
BEGIN
    PRINT CONCAT (N'VIOLATED: hop ', @Hop, N' expected to be wearing ', @Here, N' and is wearing ', @Tc, N'.');
    THROW 59210, N'Tour hop landed on the wrong tenant.', 1;
END;

EXEC dbo.uspCreateCaseFile @SessionTokenHash = @Hash
                         , @CaseNumber = N'$(RunLabel)-TOUR-4', @Title = N'Tour hop 4, worn at C020'
                         , @AssignedToProfileId = @P, @CaseFileId = @Case OUTPUT;

SELECT @Pid = up.UserProfileId FROM auth.UserProfile AS up
 INNER JOIN auth.Tenant AS t ON t.TenantId = up.TenantId
 WHERE up.UserId = @U AND t.TenantCode = @Next AND up.IsDeleted = 0;

EXEC auth.uspSwitchProfile @SessionTokenHash = @Hash, @TargetUserProfileId = @Pid;

PRINT CONCAT (N'OK: section 6 -- hop ', @Hop, N' at ', @Tc, N': case file ', @Case, N' opened, handed to ', @Next, N'.');
GO


/*---------------------------------------------------------------------------------------------------------------------
CONNECTION 11.  TOUR HOP 5 -- county C030.  Switch 4, and the hand-off goes back UP to the agency, because a tour that
only ever descended would not prove that the widening direction works too.
---------------------------------------------------------------------------------------------------------------------*/
:connect $(SQLCMDSERVER)
USE [$(DbName)];
GO
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;
GO

DECLARE @Hash VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|tour')
      , @Here NVARCHAR (100) = N'$(AgencyCode)-C030'
      , @Next NVARCHAR (100) = N'$(AgencyCode)'
      , @Hop  INT            = 5
      , @U INT, @P INT, @T INT, @Tc NVARCHAR (100), @Case INT, @Pid INT;

EXEC auth.uspSetSessionContext @SessionTokenHash = @Hash, @UserId = @U OUTPUT, @UserProfileId = @P OUTPUT
                            , @ActingTenantId = @T OUTPUT;
SELECT @Tc = TenantCode FROM auth.Tenant WHERE TenantId = @T;
IF @Tc <> @Here
BEGIN
    PRINT CONCAT (N'VIOLATED: hop ', @Hop, N' expected to be wearing ', @Here, N' and is wearing ', @Tc, N'.');
    THROW 59210, N'Tour hop landed on the wrong tenant.', 1;
END;

EXEC dbo.uspCreateCaseFile @SessionTokenHash = @Hash
                         , @CaseNumber = N'$(RunLabel)-TOUR-5', @Title = N'Tour hop 5, worn at C030'
                         , @AssignedToProfileId = @P, @CaseFileId = @Case OUTPUT;

SELECT @Pid = up.UserProfileId FROM auth.UserProfile AS up
 INNER JOIN auth.Tenant AS t ON t.TenantId = up.TenantId
 WHERE up.UserId = @U AND t.TenantCode = @Next AND up.IsDeleted = 0;

EXEC auth.uspSwitchProfile @SessionTokenHash = @Hash, @TargetUserProfileId = @Pid;

PRINT CONCAT (N'OK: section 6 -- hop ', @Hop, N' at ', @Tc, N': case file ', @Case
            , N' opened, session handed back UP to ', @Next, N'.');
GO


/*---------------------------------------------------------------------------------------------------------------------
CONNECTION 12.  TOUR HOP 6 -- back at the agency.  Five switches in one session are now behind us.  The agency hat must
see ALL FOUR county case files the tour left behind, because its permission scope sits at the agency and
auth.tvfTenantReadPredicate expands it down the closure -- which is what "oversees 67 counties" has to mean in rows.
---------------------------------------------------------------------------------------------------------------------*/
:connect $(SQLCMDSERVER)
USE [$(DbName)];
GO
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;
GO

DECLARE @Hash VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|tour')
      , @U INT, @P INT, @T INT, @Tc NVARCHAR (100), @Visible INT, @Switches INT, @Sid BIGINT, @Ended INT
      , @Started DATETIME2 (7), @UserName NVARCHAR (512), @Foreign INT
      , @SwitchesById INT, @Orphans INT;

EXEC auth.uspSetSessionContext @SessionTokenHash = @Hash, @UserId = @U OUTPUT, @UserProfileId = @P OUTPUT
                            , @ActingTenantId = @T OUTPUT;
SELECT @Tc = TenantCode FROM auth.Tenant WHERE TenantId = @T;
IF @Tc <> N'$(AgencyCode)'
BEGIN
    PRINT CONCAT (N'VIOLATED: hop 6 expected to be back at $(AgencyCode) and is wearing ', @Tc, N'.');
    THROW 59210, N'Tour hop landed on the wrong tenant.', 1;
END;

SELECT @Visible = COUNT (*) FROM dbo.CaseFile
 WHERE CaseNumber IN (N'$(RunLabel)-TOUR-1', N'$(RunLabel)-TOUR-2', N'$(RunLabel)-TOUR-3'
                    , N'$(RunLabel)-TOUR-4', N'$(RunLabel)-TOUR-5');

IF @Visible <> 5
BEGIN
    PRINT CONCAT (N'VIOLATED: the agency hat sees ', @Visible, N' of the tour''s 5 case files. '
                , N'An agency that oversees its counties must see all of them.');
    THROW 59212, N'Agency scope does not expand down the closure.', 1;
END;

-- The agency hat expands DOWN its own closure and NO FURTHER. With a second agency in the database -- the scenario's
-- fourth run adds EPA over 100 counties beside DEP over 67 -- that stops being a tautology: every row this hat can see
-- must belong to a tenant inside this agency's subtree, or two agencies are reading each other's case files. The
-- assertion is deliberately framed as "nothing outside", not "n rows inside", because a leak is something APPEARING.
SELECT @Foreign = COUNT (*)
  FROM dbo.CaseFile AS cf
 WHERE NOT EXISTS (SELECT 1 FROM auth.TenantClosure AS tc
                    WHERE tc.AncestorTenantId = @T AND tc.DescendantTenantId = cf.TenantId AND tc.IsDeleted = 0);

IF @Foreign <> 0
BEGIN
    PRINT CONCAT (N'VIOLATED: the $(AgencyCode) agency hat can see ', @Foreign
                , N' case file(s) outside its own tenant subtree.');
    THROW 59224, N'Row security leaked across agencies.', 1;
END;

PRINT CONCAT (N'OK: section 6 -- every case file visible to the $(AgencyCode) agency hat lies inside '
            , N'$(AgencyCode)''s own subtree. No other agency''s rows are reachable.');

-- The switches are not this script's word for it: auth.uspSwitchProfile writes one ProfileSwitch row per successful
-- switch, and since T-127 that row names the session the switch belonged to.
--
-- G-50, CLOSED, AND THIS SECTION IS WHAT KEEPS IT CLOSED.  auth.uspSwitchProfile's inline INSERT into
-- logs.AuthenticationEvent used to list (EventUtc, EventType, EventSeverity, ApplicationId, UserId, LoginAttemptId,
-- UserName, ClientAddress, Actor, DetailJson) and omit UserSessionId -- even though the procedure had just validated
-- @SessionTokenHash and was holding the session the switch belonged to.  Measured when the gap was open: 73 of 73
-- ProfileSwitch rows carried NULL, against LoginSucceeded, SessionStarted, SessionEnded, SessionRevoked, SsoSucceeded
-- and PasswordChanged, which all carried it.  The same omission affected the MfaChallenged row a step-up refusal writes.
--
-- The consequence was exactly the question this scenario asks.  "Did THIS session switch profiles, and how many times?"
-- could not be answered by a join; it had to be inferred from a user name and a time window, which is ambiguous the
-- moment one person holds two concurrent sessions -- and a user with 22 profiles across eleven counties is precisely the
-- person who will.  DetailJson.previousUserProfileId chained the hops together, so the ORDER survived; the ATTRIBUTION
-- did not.
--
-- So BOTH counts are taken below: the correlated one an auditor used to be forced into, and the joined one they can use
-- now, and they are asserted EQUAL.  That equality is the assertion, not the presence of the column: if the column is
-- ever dropped from that INSERT again the joined count falls to zero while the correlated count does not, and this
-- section fails with both numbers in the message rather than quietly going back to guessing.
SELECT @Sid = UserSessionId, @Started = StartedUtc
  FROM auth.UserSession WHERE SessionTokenHash = @Hash AND IsDeleted = 0;

SELECT @UserName = UserName FROM auth.[User] WHERE UserId = @U;

SELECT @Switches = COUNT (*) FROM logs.AuthenticationEvent
 WHERE UserName = @UserName AND EventType = N'ProfileSwitch' AND EventUtc >= @Started AND IsDeleted = 0;

-- The same question, asked the way T-127 made possible: by the session id, with no user name and no time window.
SELECT @SwitchesById = COUNT (*) FROM logs.AuthenticationEvent
 WHERE UserSessionId = @Sid AND EventType = N'ProfileSwitch' AND IsDeleted = 0;

-- And the rows that would prove a regression: a switch on this session's watch that cannot say which session it was.
SELECT @Orphans = COUNT (*) FROM logs.AuthenticationEvent
 WHERE UserName = @UserName AND EventType = N'ProfileSwitch' AND EventUtc >= @Started AND IsDeleted = 0
   AND UserSessionId IS NULL;

IF @Switches < 6
BEGIN
    PRINT CONCAT (N'VIOLATED: ', @UserName, N' recorded ', @Switches
                , N' ProfileSwitch events since session ', @Sid, N' started; the tour made six.');
    THROW 59213, N'Switch audit trail incomplete.', 1;
END;

IF @Orphans > 0 OR @SwitchesById <> @Switches
BEGIN
    PRINT CONCAT (N'VIOLATED: ', @Switches, N' ProfileSwitch event(s) correlate to ', @UserName
                , N' since session ', @Sid, N' started, but only ', @SwitchesById
                , N' name that session by its id, and ', @Orphans, N' carry no UserSessionId at all. G-50 has '
                , N'reopened: auth.uspSwitchProfile''s INSERT into logs.AuthenticationEvent has stopped writing the '
                , N'session it is holding, so "which session switched hats" is back to being a guess from a name and a '
                , N'time window.');
    THROW 59225, N'ProfileSwitch rows are not attributable to a session -- G-50 has reopened.', 1;
END;

PRINT CONCAT (N'OK: section 6 -- hop 6 back at $(AgencyCode). All 5 tour case files visible from the agency, and '
            , @Switches, N' ProfileSwitch events recorded for ', @UserName, N' since session ', @Sid
            , N' started. "Switch profiles multiple times a session" is proved, at one connection per hat.');

PRINT CONCAT (N'OK: section 6 -- G-50 CLOSED: all ', @SwitchesById, N' of those ProfileSwitch rows name session '
            , @Sid, N' by its id, the count reached by joining matches the count reached by correlating on user name '
            , N'and time, and none is orphaned. "Which session changed hats, and in what order" is now one join.');

-- Exactly ONE of the three identifiers, and the other two explicitly NULL -- E-50100. "Two of them together is a
-- caller that does not know which session it means", and ending the intersection or the union would both be guesses.
EXEC auth.uspEndSession @SessionTokenHash = @Hash, @UserSessionId = NULL, @UserId = NULL
                      , @EndReason = 'SignedOut', @SessionsEnded = @Ended OUTPUT;

PRINT CONCAT (N'OK: section 6 -- session ', @Sid, N' ended (', @Ended, N' session(s) closed).');
GO


/*---------------------------------------------------------------------------------------------------------------------
CONNECTION 13.  THE FINDING.  A platform admin signs in with local credentials and a second factor, exactly as the
scenario requires, and then tries to put on the hat they were created to wear.
---------------------------------------------------------------------------------------------------------------------*/
:connect $(SQLCMDSERVER)
USE [$(DbName)];
GO
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;
GO

-- *** 7. Step-up: the refusal, and the procedure that satisfies it ***
-- auth.uspSwitchProfile refuses with E-50052 when the target profile is PRIVILEGED -- it holds any permission in the
-- Authz, User, Tenant or Platform categories -- and the tenant's policy sets RequireStepUpForPrivileged, unless
-- auth.UserSession.ElevatedUntilUtc is in the future.
--
-- Nothing used to write that column.  Not auth.uspVerifyMfa, which satisfies a LOGIN ATTEMPT and says so at line 1508
-- of database/110_auth_authn_procedures.sql: "of an ESTABLISHED session is auth.UserSession.ElevatedUntilUtc, which is
-- Phase 5's business, not this procedure's."  Phase 5 built the performance work and the procedure was never written.
-- Every auth.TenantAuthenticationPolicy row in the repository's own test fixtures set RequireStepUpForPrivileged = 0, so
-- the refusal had never been reached; the shipped default Authn.RequireStepUpForPrivilegedDefault is 1, so any real
-- deployment reaches it on its first privileged switch, and every privileged cohort in this scenario -- the platform
-- admins and every "can assign profiles" cohort -- was locked out of its own hat.  G-48, and T-125 closed it.
--
-- So this section does the whole sequence a real administrator does, in order, and asserts each step: the switch is
-- refused, the second factor is re-proved TO THE SESSION, and the same switch then succeeds.  What it no longer does is
-- write the column by hand.  That UPDATE was the only direct DML in this file and it existed to show what the missing
-- procedure would have done; there is a procedure now, and using it is the assertion.
DECLARE @Name  NVARCHAR (512) = LOWER (N'$(AgencyCode)') + N'.$(Wave).d5.0001'
      , @Hash  VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|admin')
      , @Att   BIGINT, @Phc NVARCHAR (1024), @Mfa BIT, @Ok BIT
      , @Sid   BIGINT, @Uid INT, @Must BIT, @Abs DATETIME2 (7), @Idle DATETIME2 (7)
      , @Pid   INT, @Err INT = 0, @Msg NVARCHAR (2048) = NULL, @Priv INT
      , @Step  BIGINT
      , @Last  BIGINT
      , @Until DATETIME2 (3), @Before DATETIME2 (3), @After DATETIME2 (3);

-- A TOTP step may be spent ONCE, ever, and must sit within Authn.TotpWindowSteps of the server's own step -- both halves
-- of E-50111.  So a test that signs the same person in twice inside one 30-second window is refused, and the refusal is
-- CORRECT: measured against dep.w1.c2.001.0001, which reported step 59666672 twenty seconds after spending it.  The fix
-- is not to fudge the step, which would test nothing; it is to do what a person does and wait for the next code.  The
-- step itself always comes from the clock, never from the stored value.
SELECT @Last = MAX (m.LastUsedTimeStep)
  FROM auth.UserMfaFactor AS m
 INNER JOIN auth.[User]   AS u ON u.UserId = m.UserId
 WHERE u.UserName = @Name AND m.FactorType = 'Totp' AND m.IsConfirmed = 1 AND m.IsDeleted = 0;

SET @Step = DATEDIFF_BIG (SECOND, CAST (N'1970-01-01T00:00:00' AS DATETIME2 (0)), SYSUTCDATETIME ()) / 30;

IF @Last >= @Step
BEGIN
    PRINT CONCAT (N'   (waiting 31s for the next TOTP step: ', @Name, N' already spent step ', @Last, N'.)');
    WAITFOR DELAY '00:00:31';
    SET @Step = DATEDIFF_BIG (SECOND, CAST (N'1970-01-01T00:00:00' AS DATETIME2 (0)), SYSUTCDATETIME ()) / 30;
END;

IF @Last >= @Step
BEGIN
    PRINT CONCAT (N'VIOLATED: ', @Name, N' holds LastUsedTimeStep ', @Last, N', which is ahead of the server step '
                , @Step, N'. A clock has moved backwards and no code can be accepted.');
    THROW 59222, N'TOTP step is ahead of the server clock.', 1;
END;

SELECT @Pid = up.UserProfileId
  FROM auth.UserProfile AS up
 INNER JOIN auth.[User] AS u ON u.UserId   = up.UserId
 INNER JOIN auth.Tenant AS t ON t.TenantId = up.TenantId
 WHERE u.UserName = @Name AND t.TenantCode = N'$(AgencyCode)' AND up.IsDeleted = 0 AND u.IsDeleted = 0;

SELECT @Priv = COUNT (*)
  FROM auth.ProfilePermissionScope AS s
 INNER JOIN auth.Permission         AS p ON p.PermissionId = s.PermissionId
 INNER JOIN auth.PermissionCategory AS c ON c.PermissionCategoryId = p.PermissionCategoryId
 WHERE s.UserProfileId = @Pid AND c.CategoryCode IN (N'Authz', N'User', N'Tenant', N'Platform');

IF @Priv = 0
BEGIN
    PRINT N'VIOLATED: the platform-admin profile holds no Authz, User, Tenant or Platform permission.';
    THROW 59214, N'Platform admin is not privileged.', 1;
END;

PRINT CONCAT (N'OK: section 7 -- the platform-admin profile ', @Pid, N' holds ', @Priv
            , N' privileged permission(s), so the step-up rule applies to it.');

EXEC auth.uspGetLoginVerifier @ApplicationCode = N'TEMPLATE', @UserName = @Name
                            , @ClientAddress = N'203.0.113.22', @TenantCode = N'$(AgencyCode)'
                            , @UserAgent = N'S1_prove_duties'
                            , @LoginAttemptId = @Att OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;

EXEC auth.uspVerifyMfa @LoginAttemptId = @Att, @TimeStep = @Step, @FactorType = 'Totp', @MfaSatisfied = @Ok OUTPUT;

EXEC auth.uspCompleteLogin @LoginAttemptId = @Att, @PasswordVerified = 1, @SessionTokenHash = @Hash
                         , @IsBypassRoute = 0, @UserSessionId = @Sid OUTPUT, @UserId = @Uid OUTPUT
                         , @MustChangePassword = @Must OUTPUT, @AbsoluteExpiryUtc = @Abs OUTPUT
                         , @IdleExpiryUtc = @Idle OUTPUT;

PRINT CONCAT (N'OK: section 7 -- platform admin signed in with local credentials and a confirmed second factor. '
            , N'Session ', @Sid, N', MFA demanded ', @Mfa, N', MFA satisfied ', @Ok, N'.');

BEGIN TRY
    EXEC auth.uspSwitchProfile @SessionTokenHash = @Hash, @TargetUserProfileId = @Pid;
END TRY
BEGIN CATCH
    SET @Err = ERROR_NUMBER ();
    SET @Msg = ERROR_MESSAGE ();
END CATCH;

IF @Err <> 50052
BEGIN
    PRINT CONCAT (N'VIOLATED: expected E-50052 on a privileged switch with no elevation and got ', @Err
                , N' -- "', COALESCE (@Msg, N'no error at all'), N'".');
    THROW 59215, N'Step-up refusal did not happen.', 1;
END;

PRINT CONCAT (N'OK: section 7 -- the switch was refused with E-50052: "', @Msg, N'". That refusal is CORRECT and '
            , N'it is not the gap: a 2FA sign-in satisfies a LOGIN ATTEMPT, and the second factor this session '
            , N'presented was proved to a different question minutes ago.');

-- The step must be a NEW one, and the wait below is not a workaround for a flaky test -- it is the anti-replay rule
-- being obeyed. The sign-in above spent a step; a TOTP step may be spent ONCE, ever, and E-50128 refuses any step that
-- is not strictly later than the last one this factor accepted, which is exactly what makes replaying an observed code
-- useless to whoever observed it. A step-up that did NOT have to wait here would be the defect.
SELECT @Before = s.ElevatedUntilUtc FROM auth.UserSession AS s WHERE s.UserSessionId = @Sid;

SELECT @Last = MAX (m.LastUsedTimeStep)
  FROM auth.UserMfaFactor AS m
 INNER JOIN auth.[User]   AS u ON u.UserId = m.UserId
 WHERE u.UserName = @Name AND m.FactorType = 'Totp' AND m.IsConfirmed = 1 AND m.IsDeleted = 0;

SET @Step = DATEDIFF_BIG (SECOND, CAST (N'1970-01-01T00:00:00' AS DATETIME2 (0)), SYSUTCDATETIME ()) / 30;

IF @Last >= @Step
BEGIN
    PRINT CONCAT (N'   (waiting 31s for the next TOTP step before the step-up: ', @Name, N' spent step ', @Last
                , N' signing in.)');
    WAITFOR DELAY '00:00:31';
    SET @Step = DATEDIFF_BIG (SECOND, CAST (N'1970-01-01T00:00:00' AS DATETIME2 (0)), SYSUTCDATETIME ()) / 30;
END;

IF @Last >= @Step
BEGIN
    PRINT CONCAT (N'VIOLATED: ', @Name, N' holds LastUsedTimeStep ', @Last, N', which is ahead of the server step '
                , @Step, N'. A clock has moved backwards and no code can be accepted.');
    THROW 59222, N'TOTP step is ahead of the server clock.', 1;
END;

-- The procedure T-125 added. No @UserId, no @UserProfileId and no permission demanded: the authority is the session
-- token plus a factor the account already holds, which is why it works on a session that is wearing no hat at all --
-- and it HAS to work on one, because the hat is the thing being put on.
EXEC auth.uspElevateSession @SessionTokenHash = @Hash, @TimeStep = @Step, @FactorType = 'Totp'
                          , @ElevatedUntilUtc = @Until OUTPUT;

SELECT @After = s.ElevatedUntilUtc FROM auth.UserSession AS s WHERE s.UserSessionId = @Sid;

-- FOUR separate claims, and the reason there are four is that the gap was that the COLUMN WAS NEVER WRITTEN. An OUTPUT
-- parameter on its own proves nothing about the row: a procedure that returned a time it had not persisted would leave
-- the E-50052 refusal above exactly where it is, and G-48 would be open again underneath a green test. So the row is
-- read back and compared to what the caller was told -- and the pre-state is checked too, because "it was already
-- elevated" would mean the refusal above proved nothing either.
IF @Until IS NULL OR @After IS NULL OR @After <= SYSUTCDATETIME () OR @After <> @Until
   OR (@Before IS NOT NULL AND @Before > SYSUTCDATETIME ())
BEGIN
    PRINT CONCAT (N'VIOLATED: auth.uspElevateSession reported '
                , COALESCE (CONVERT (NVARCHAR (30), @Until, 126), N'NULL'), N' and session ', @Sid, N' carries '
                , COALESCE (CONVERT (NVARCHAR (30), @After, 126), N'NULL'), N', against '
                , COALESCE (CONVERT (NVARCHAR (30), @Before, 126), N'NULL')
                , N' before the step-up. G-48 has reopened: a step-up that does not persist a future '
                , N'ElevatedUntilUtc leaves every privileged cohort in this scenario unable to put on its own hat.');
    THROW 59226, N'Step-up did not elevate the session -- G-48 has reopened.', 1;
END;

EXEC auth.uspSwitchProfile @SessionTokenHash = @Hash, @TargetUserProfileId = @Pid;

PRINT CONCAT (N'OK: section 7 -- G-48 CLOSED. auth.uspElevateSession accepted a fresh TOTP step on the ESTABLISHED '
            , N'session, ElevatedUntilUtc went from '
            , COALESCE (CONVERT (NVARCHAR (30), @Before, 126), N'NULL'), N' to '
            , CONVERT (NVARCHAR (30), @After, 126)
            , N', and the same switch that was refused a moment ago then succeeded. No hand-written UPDATE of that '
            , N'column anywhere in this file.');
GO


/*---------------------------------------------------------------------------------------------------------------------
CONNECTION 14.  The platform admin, now wearing the hat, does the four things the scenario says they must: create a
user, create a profile for them, assign a role to it, and deactivate a user.
---------------------------------------------------------------------------------------------------------------------*/
:connect $(SQLCMDSERVER)
USE [$(DbName)];
GO
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;
GO

-- *** 8. Administering user creation, profiles and roles ***
DECLARE @Hash VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|admin')
      , @U INT, @P INT, @T INT, @NewU INT, @NewP INT, @Grant INT, @RoleId INT, @Tc NVARCHAR (100)
      , @NewName NVARCHAR (512) = LOWER (N'$(AgencyCode)') + N'.$(Wave).new.$(RunLabel)';

EXEC auth.uspSetSessionContext @SessionTokenHash = @Hash, @UserId = @U OUTPUT, @UserProfileId = @P OUTPUT
                            , @ActingTenantId = @T OUTPUT;
SELECT @Tc = TenantCode FROM auth.Tenant WHERE TenantId = @T;

IF @T IS NULL
BEGIN
    PRINT N'VIOLATED: the platform admin''s hat did not arrive on the working connection.';
    THROW 59216, N'Admin hat did not arrive.', 1;
END;

EXEC auth.uspCreateUser @SessionTokenHash = @Hash
                      , @UserName = @NewName
                      , @DisplayName = N'Created by a platform admin during run $(RunLabel)'
                      , @Email = N'new.$(RunLabel)@example.gov', @IsPlatformAdmin = 0, @NewUserId = @NewU OUTPUT;

IF @NewU IS NULL
BEGIN
    PRINT N'VIOLATED: a platform admin holding User.Create could not create a user.';
    THROW 59217, N'User creation refused.', 1;
END;

EXEC auth.uspCreateProfile @SessionTokenHash = @Hash, @UserId = @NewU, @TenantId = @T
                         , @ProfileName = N'Read-only', @IsDefault = 1, @NewUserProfileId = @NewP OUTPUT;

SELECT @RoleId = RoleId FROM auth.Role
 WHERE RoleCode = N'READ_ONLY' AND IsDeleted = 0
   AND ApplicationId = (SELECT ApplicationId FROM auth.Application
                         WHERE ApplicationCode = N'TEMPLATE' AND IsDeleted = 0);

EXEC auth.uspAssignRoleToProfile @SessionTokenHash = @Hash, @UserProfileId = @NewP, @RoleId = @RoleId
                               , @ScopeTenantId = @T, @NewUserProfileRoleId = @Grant OUTPUT;

PRINT CONCAT (N'OK: section 8 -- platform admin at ', @Tc, N' created user ', @NewU, N', profile ', @NewP
            , N' and role grant ', @Grant, N'. Assign profiles, create profiles and assign roles all exercised.');

EXEC auth.uspListProfilesForUser @SessionTokenHash = @Hash, @UserId = @NewU, @IncludeInactive = 0;

EXEC auth.uspDeactivateUser @SessionTokenHash = @Hash, @UserId = @NewU, @IsActive = 0;

PRINT N'OK: section 8 -- and deactivated them again. "Administer user creation and deactivation" is proved.';
GO


/*---------------------------------------------------------------------------------------------------------------------
CONNECTION 15.  The eleven-county user.  Twenty-two profiles across eleven counties is the scenario's widest shape, and
the thing to prove is not that the rows exist -- the loader asserted that -- but that the person can MOVE between two
counties inside one session and that each hat sees only its own county.
---------------------------------------------------------------------------------------------------------------------*/
:connect $(SQLCMDSERVER)
USE [$(DbName)];
GO
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;
GO

-- *** 9. Eleven counties, and the shape of the switch list ***
DECLARE @Name  NVARCHAR (512) = (SELECT MIN (UserName) FROM auth.[User]
                                  WHERE UserName LIKE LOWER (N'$(AgencyCode)') + N'.$(Wave).c6.%' AND IsDeleted = 0)
      , @Hash  VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|eleven')
      , @Att   BIGINT, @Phc NVARCHAR (1024), @Mfa BIT, @Ok BIT
      , @Sid   BIGINT, @Uid INT, @Must BIT, @Abs DATETIME2 (7), @Idle DATETIME2 (7)
      , @Home  NVARCHAR (100), @Pid INT, @Profiles INT, @Tenants INT, @Err INT = 0
      , @Msg NVARCHAR (2048) = NULL, @Listed INT, @Mine INT, @Current INT, @Defaults INT
      , @Step  BIGINT
      , @Last  BIGINT;

-- A TOTP step may be spent ONCE, ever, and must sit within Authn.TotpWindowSteps of the server's own step -- both halves
-- of E-50111.  So a test that signs the same person in twice inside one 30-second window is refused, and the refusal is
-- CORRECT: measured against dep.w1.c2.001.0001, which reported step 59666672 twenty seconds after spending it.  The fix
-- is not to fudge the step, which would test nothing; it is to do what a person does and wait for the next code.  The
-- step itself always comes from the clock, never from the stored value.
SELECT @Last = MAX (m.LastUsedTimeStep)
  FROM auth.UserMfaFactor AS m
 INNER JOIN auth.[User]   AS u ON u.UserId = m.UserId
 WHERE u.UserName = @Name AND m.FactorType = 'Totp' AND m.IsConfirmed = 1 AND m.IsDeleted = 0;

SET @Step = DATEDIFF_BIG (SECOND, CAST (N'1970-01-01T00:00:00' AS DATETIME2 (0)), SYSUTCDATETIME ()) / 30;

IF @Last >= @Step
BEGIN
    PRINT CONCAT (N'   (waiting 31s for the next TOTP step: ', @Name, N' already spent step ', @Last, N'.)');
    WAITFOR DELAY '00:00:31';
    SET @Step = DATEDIFF_BIG (SECOND, CAST (N'1970-01-01T00:00:00' AS DATETIME2 (0)), SYSUTCDATETIME ()) / 30;
END;

IF @Last >= @Step
BEGIN
    PRINT CONCAT (N'VIOLATED: ', @Name, N' holds LastUsedTimeStep ', @Last, N', which is ahead of the server step '
                , @Step, N'. A clock has moved backwards and no code can be accepted.');
    THROW 59222, N'TOTP step is ahead of the server clock.', 1;
END;

SELECT @Home = t.TenantCode
  FROM auth.UserProfile AS up
 INNER JOIN auth.[User] AS u ON u.UserId   = up.UserId
 INNER JOIN auth.Tenant AS t ON t.TenantId = up.TenantId
 WHERE u.UserName = @Name AND up.IsDefault = 1 AND up.IsDeleted = 0;

SELECT @Profiles = COUNT (*), @Tenants = COUNT (DISTINCT up.TenantId)
  FROM auth.UserProfile AS up
 INNER JOIN auth.[User] AS u ON u.UserId = up.UserId
 WHERE u.UserName = @Name AND up.IsDeleted = 0;

IF @Profiles <> 22 OR @Tenants <> 11
BEGIN
    PRINT CONCAT (N'VIOLATED: the eleven-county sample holds ', @Profiles, N' profiles over ', @Tenants
                , N' tenants; the scenario says 22 over 11.');
    THROW 59218, N'Eleven-county shape wrong.', 1;
END;

SELECT @Pid = up.UserProfileId
  FROM auth.UserProfile AS up
 INNER JOIN auth.[User] AS u ON u.UserId   = up.UserId
 INNER JOIN auth.Tenant AS t ON t.TenantId = up.TenantId
 WHERE u.UserName = @Name AND t.TenantCode = @Home AND up.ProfileName = N'Read-only' AND up.IsDeleted = 0;

EXEC auth.uspGetLoginVerifier @ApplicationCode = N'TEMPLATE', @UserName = @Name
                            , @ClientAddress = N'198.51.100.33', @TenantCode = @Home
                            , @UserAgent = N'S1_prove_duties'
                            , @LoginAttemptId = @Att OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;

EXEC auth.uspVerifyMfa @LoginAttemptId = @Att, @TimeStep = @Step, @FactorType = 'Totp', @MfaSatisfied = @Ok OUTPUT;

EXEC auth.uspCompleteLogin @LoginAttemptId = @Att, @PasswordVerified = 1, @SessionTokenHash = @Hash
                         , @IsBypassRoute = 0, @UserSessionId = @Sid OUTPUT, @UserId = @Uid OUTPUT
                         , @MustChangePassword = @Must OUTPUT, @AbsoluteExpiryUtc = @Abs OUTPUT
                         , @IdleExpiryUtc = @Idle OUTPUT;

-- G-51, CLOSED, AND THE HAT MENU IS NOW INSIDE THE PROCEDURE SURFACE.  This person holds 22 profiles over eleven
-- counties and has just authenticated, so the very next thing any user interface must do is ask "which hat?".  When
-- this scenario was first written, nothing in the procedure surface would answer.  auth.uspListProfilesForUser was the
-- only lister, its own header calls it "for a profile-administration screen", and it DEMANDS Authz.ProfileRead scoped
-- to the tenants being listed -- while a freshly signed-in session is profileless BY DESIGN (three session keys, not
-- five) and so holds no permission at all.  That refusal is still there, it is still correct for that procedure, and it
-- is proved again below; what changed is that it is no longer the only answer.
--
-- Two consequences, and T-126 answered both:
--   *  The application had to read auth.UserProfile and auth.Tenant DIRECTLY to build the menu, which put the one
--      screen every single one of the 12,830 users sees first outside the procedure surface -- and therefore outside
--      auth.udfIsTenantUsable, the soft-delete filters and the instrumentation that surface applies for it.
--      auth.uspListMyProfiles demands nothing, takes NO user id, and reads the caller's own hats out of the session
--      row, so the menu is built through the surface and the confinement is the session rather than an argument.
--   *  auth.uspDemandPermission MISDIAGNOSED the refusal. Its message read "There is NO SESSION CONTEXT on this
--      connection, which means this procedure was reached without auth.uspSetSessionContext having run -- a server-side
--      defect, not a permission problem."  Context HAD been established; it was legitimately profileless.  The message
--      inferred "no context" from a NULL UserProfileId and sent whoever read the log hunting a defect that was not
--      there.  E-50032 says what is actually true, and the remedy it implies is a profile chooser rather than a bug
--      report.
--
-- Which is why the assertion below is on the NUMBER and not merely on the failure.  E-50030 coming back here would mean
-- the two cases have been merged again, and the difference between them is the difference between "ask this user to
-- choose a hat" and "go and find a server defect".
BEGIN TRY
    EXEC auth.uspListProfilesForUser @SessionTokenHash = @Hash, @UserId = @Uid, @IncludeInactive = 0;
END TRY
BEGIN CATCH
    SET @Err = ERROR_NUMBER ();
    SET @Msg = ERROR_MESSAGE ();
END CATCH;

IF @Err <> 50032
BEGIN
    PRINT CONCAT (N'VIOLATED: expected E-50032 -- "this session is wearing no profile" -- from the ADMINISTRATIVE '
                , N'lister on a profileless session, and got ', @Err, N': "', COALESCE (@Msg, N'no error at all')
                , N'". E-50030 means T-126''s split has been reverted and a hatless session is being reported as a '
                , N'missing grant again; 0 means auth.uspListProfilesForUser has stopped demanding Authz.ProfileRead, '
                , N'which is a far larger change than this line.');
    THROW 59223, N'The profileless diagnostic has regressed.', 1;
END;

PRINT CONCAT (N'OK: section 9 -- the administrative lister still refuses a profileless session, and now refuses it '
            , N'with E-50032, which names the missing hat instead of blaming the connection.');

-- The self-service lister, which is the half of G-51 that actually closes it. INSERT ... EXEC rather than a bare EXEC
-- because an assertion needs the ROWS, not a result set on its way to the console -- and the counts ARE the assertion:
-- every one of this user's hats, nobody else's, none of them worn, and exactly one default to offer first.
CREATE TABLE #MyHats
    ( UserProfileId       INT
    , UserId              INT
    , TenantId            INT
    , TenantCode          NVARCHAR (100)
    , TenantName          NVARCHAR (400)
    , TenantTypeCode      NVARCHAR (50)
    , ProfileName         NVARCHAR (400)
    , IsDefault           BIT
    , IsActive            BIT
    , TenantUsable        BIT
    , IsSwitchable        INT
    , IsCurrent           INT
    , SwitchBlockedReason NVARCHAR (50) );

INSERT INTO #MyHats EXEC auth.uspListMyProfiles @SessionTokenHash = @Hash;

SELECT @Listed   = COUNT (*)
     , @Mine     = COUNT (DISTINCT UserId)
     , @Current  = SUM (CAST (IsCurrent AS INT))
     , @Defaults = SUM (CAST (IsDefault AS INT))
  FROM #MyHats;

IF @Listed <> @Profiles OR @Mine <> 1 OR @Current <> 0 OR @Defaults <> 1
BEGIN
    PRINT CONCAT (N'VIOLATED: auth.uspListMyProfiles returned ', @Listed, N' row(s) for a user holding ', @Profiles
                , N' profile(s), over ', @Mine, N' distinct user id(s), with ', @Current
                , N' marked as the hat currently worn and ', @Defaults
                , N' marked as the default. A profileless session must be shown every one of its own hats, nobody '
                , N'else''s, none of them current, and one default to put at the top of the menu.');
    THROW 59227, N'The self-service profile list is wrong.', 1;
END;

DROP TABLE #MyHats;

PRINT CONCAT (N'OK: section 9 -- G-51 CLOSED. auth.uspListMyProfiles listed all ', @Listed, N' of this session''s own '
            , N'hats across ', @Tenants, N' counties while the session was wearing none of them, demanding no '
            , N'permission and taking no user id. The hat menu is built through the procedure surface, not around it.');

-- And the switch target is now resolved from that list rather than from a direct table read.
EXEC auth.uspSwitchProfile @SessionTokenHash = @Hash, @TargetUserProfileId = @Pid;

PRINT CONCAT (N'OK: section 9 -- ', @Name, N' signed in at ', @Home
            , N' with 22 profiles over 11 counties and is wearing the home read-only one. Session ', @Sid, N'.');
GO


/*---------------------------------------------------------------------------------------------------------------------
CONNECTION 16.  The eleven-county user at home, then away.  Two hats in two counties, one session.
---------------------------------------------------------------------------------------------------------------------*/
:connect $(SQLCMDSERVER)
USE [$(DbName)];
GO
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;
GO

DECLARE @Hash VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|eleven')
      , @U INT, @P INT, @T INT, @Tc NVARCHAR (100), @Away INT, @AwayTc NVARCHAR (100), @Err INT = 0, @Case INT;

EXEC auth.uspSetSessionContext @SessionTokenHash = @Hash, @UserId = @U OUTPUT, @UserProfileId = @P OUTPUT
                            , @ActingTenantId = @T OUTPUT;
SELECT @Tc = TenantCode FROM auth.Tenant WHERE TenantId = @T;

-- The home hat is the READ-ONLY one -- the loader makes it the default so that an unswitched session cannot write.
BEGIN TRY
    EXEC dbo.uspCreateCaseFile @SessionTokenHash = @Hash, @CaseNumber = N'$(RunLabel)-C6-BAD'
                             , @Title = N'The default read-only hat must not be able to open this'
                             , @AssignedToProfileId = @P, @CaseFileId = @Case OUTPUT;
END TRY
BEGIN CATCH
    SET @Err = ERROR_NUMBER ();
END CATCH;

IF @Err = 0
BEGIN
    PRINT N'VIOLATED: the default read-only hat wrote a case file.';
    THROW 59219, N'Default hat could write.', 1;
END;

PRINT CONCAT (N'OK: section 9 -- at ', @Tc, N' the default read-only hat was refused a write with error ', @Err, N'.');

-- Now the CRUD hat in ANOTHER of the eleven counties.
SELECT TOP (1) @Away = up.UserProfileId, @AwayTc = t.TenantCode
  FROM auth.UserProfile AS up
 INNER JOIN auth.Tenant AS t ON t.TenantId = up.TenantId
 WHERE up.UserId = @U AND up.ProfileName = N'CRUD' AND up.TenantId <> @T AND up.IsDeleted = 0
 ORDER BY t.TenantCode;

EXEC auth.uspSwitchProfile @SessionTokenHash = @Hash, @TargetUserProfileId = @Away;

PRINT CONCAT (N'OK: section 9 -- session handed from the read-only hat at ', @Tc, N' to the CRUD hat at ', @AwayTc, N'.');
GO


/*---------------------------------------------------------------------------------------------------------------------
CONNECTION 17.  The away county's CRUD hat works, and the "no switching" cohort is checked for the thing that makes it
true: one profile, so nothing to switch to.
---------------------------------------------------------------------------------------------------------------------*/
:connect $(SQLCMDSERVER)
USE [$(DbName)];
GO
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;
GO

DECLARE @Hash VARBINARY (32) = HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|eleven')
      , @U INT, @P INT, @T INT, @Tc NVARCHAR (100), @Case INT, @Ended INT, @Sid BIGINT;

EXEC auth.uspSetSessionContext @SessionTokenHash = @Hash, @UserId = @U OUTPUT, @UserProfileId = @P OUTPUT
                            , @ActingTenantId = @T OUTPUT;
SELECT @Tc = TenantCode FROM auth.Tenant WHERE TenantId = @T;

EXEC dbo.uspCreateCaseFile @SessionTokenHash = @Hash, @CaseNumber = N'$(RunLabel)-C6-AWAY'
                         , @Title = N'Opened in a second county by a user who works for eleven'
                         , @AssignedToProfileId = @P, @CaseFileId = @Case OUTPUT;

PRINT CONCAT (N'OK: section 9 -- case file ', @Case, N' opened at ', @Tc
            , N' by the away CRUD hat. One person, two counties, one session.');

SELECT @Sid = UserSessionId FROM auth.UserSession WHERE SessionTokenHash = @Hash AND IsDeleted = 0;

-- Exactly ONE of the three identifiers, and the other two explicitly NULL -- E-50100. "Two of them together is a
-- caller that does not know which session it means", and ending the intersection or the union would both be guesses.
EXEC auth.uspEndSession @SessionTokenHash = @Hash, @UserSessionId = NULL, @UserId = NULL
                      , @EndReason = 'SignedOut', @SessionsEnded = @Ended OUTPUT;

-- *** 10. "No profile switching" is a shape, not a setting ***
DECLARE @Solo NVARCHAR (512) = LOWER (N'$(AgencyCode)') + N'.$(Wave).d1.0001', @Count INT;

SELECT @Count = COUNT (*) FROM auth.UserProfile AS up
 INNER JOIN auth.[User] AS u ON u.UserId = up.UserId
 WHERE u.UserName = @Solo AND up.IsDeleted = 0 AND u.IsDeleted = 0;

IF @Count <> 1
BEGIN
    PRINT CONCAT (N'VIOLATED: the no-switching cohort holds ', @Count, N' profiles. It must hold exactly one.');
    THROW 59220, N'No-switching cohort can switch.', 1;
END;

PRINT CONCAT (N'OK: section 10 -- the no-switching cohort holds exactly ', @Count
            , N' profile. There is no "switching disabled" flag in this design and there does not need to be: '
            , N'auth.uspSwitchProfile refuses any profile that is not yours, so one profile IS the restriction.');
GO


/*---------------------------------------------------------------------------------------------------------------------
CONNECTION 18.  The closing report, from evidence the PROCEDURES wrote rather than from anything this script remembers.
---------------------------------------------------------------------------------------------------------------------*/
:connect $(SQLCMDSERVER)
USE [$(DbName)];
GO
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;
GO

-- *** 11. Evidence ***
-- This connection has no session, and dbo.CaseFile is under row security, so without a bypass it would count zero of
-- everything and report that as agreement -- checks 4 and 5 did exactly that on the first pass. BypassRowSecurity is the
-- one session key that is WRITABLE (auth.uspClearSessionContext's whole job is clearing it), and a closing report is
-- precisely the case _tests/060 and _tests/070 set it for. It is set for the count and cleared immediately after, so
-- nothing below the INSERT runs privileged.
DECLARE @Bad INT = 0;

EXEC sys.sp_set_session_context @key = N'BypassRowSecurity', @value = 1;

CREATE TABLE #Evidence
(
    Seq      INT            NOT NULL PRIMARY KEY
  , Subject  NVARCHAR (200) NOT NULL
  , Expected INT            NOT NULL
  , Actual   INT            NOT NULL
  , Detail   NVARCHAR (400) NOT NULL
);

INSERT #Evidence (Seq, Subject, Expected, Actual, Detail)
SELECT 1, N'Sessions opened by this run', 5
     , (SELECT COUNT (*) FROM auth.UserSession
         WHERE IsDeleted = 0
           AND SessionTokenHash IN (HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|countycrud')
                                  , HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|countyread')
                                  , HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|tour')
                                  , HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|admin')
                                  , HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|eleven')))
     , N'County CRUD, county read-only, the agency tour, the platform admin and the eleven-county user.'
UNION ALL SELECT 2, N'ProfileSwitch events on the tour session', 6
     , (SELECT COUNT (*) FROM logs.AuthenticationEvent AS e
         WHERE e.UserName = LOWER (N'$(AgencyCode)') + N'.$(Wave).d4.0001'
           AND e.EventType = N'ProfileSwitch' AND e.IsDeleted = 0
           AND e.EventUtc >= (SELECT StartedUtc FROM auth.UserSession
                               WHERE SessionTokenHash = HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|tour')))
     , N'One at sign-in and five hand-offs, correlated by user name -- the way an auditor had to before T-127.'
UNION ALL SELECT 3, N'Distinct tenants worn on the tour session', 5
     , (SELECT COUNT (DISTINCT JSON_VALUE (e.DetailJson, N'$.tenantId')) FROM logs.AuthenticationEvent AS e
         WHERE e.UserName = LOWER (N'$(AgencyCode)') + N'.$(Wave).d4.0001'
           AND e.EventType = N'ProfileSwitch' AND e.IsDeleted = 0
           AND e.EventUtc >= (SELECT StartedUtc FROM auth.UserSession
                               WHERE SessionTokenHash = HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|tour')))
     , N'The agency and four counties. Six switches over five tenants, because hop 6 returns to the agency.'
UNION ALL SELECT 4, N'Tour case files on disk', 5
     , (SELECT COUNT (*) FROM dbo.CaseFile WHERE CaseNumber LIKE N'$(RunLabel)-TOUR-%')
     , N'One per hop, each written under a different hat by the same person in one session.'
UNION ALL SELECT 5, N'County case files on disk', 3
     , (SELECT COUNT (*) FROM dbo.CaseFile
         WHERE CaseNumber IN (N'$(RunLabel)-C001-01', N'$(RunLabel)-C001-02', N'$(RunLabel)-C6-AWAY'))
     , N'Two by the county CRUD user and one by the eleven-county user in a county that is not their home.'
UNION ALL SELECT 6, N'Case files a read-only hat managed to create', 0
     , (SELECT COUNT (*) FROM dbo.CaseFile
         WHERE CaseNumber IN (N'$(RunLabel)-C002-01', N'$(RunLabel)-C6-BAD'))
     , N'Two attempts, both refused. The absence of these rows is the assertion.'
UNION ALL SELECT 7, N'Distinct read-only profiles denied Data.Insert', 2
     , (SELECT COUNT (DISTINCT d.UserProfileId) FROM logs.AuthorizationDenial AS d
         INNER JOIN auth.UserProfile AS up ON up.UserProfileId = d.UserProfileId
         INNER JOIN auth.[User]      AS u  ON u.UserId         = up.UserId
         WHERE d.PermissionCode = N'Data.Insert' AND up.ProfileName = N'Read-only'
           AND u.UserName LIKE LOWER (N'$(AgencyCode)') + N'.$(Wave).%')
     , N'A refusal that is not recorded is a refusal nobody can audit. auth.uspDemandPermission logged both attempts.'
UNION ALL SELECT 8, N'Step-up refusals logged for the platform admin', 1
     , (SELECT COUNT (*) FROM logs.AuthenticationEvent AS e
         WHERE e.UserName = LOWER (N'$(AgencyCode)') + N'.$(Wave).d5.0001'
           AND e.EventType = N'MfaChallenged' AND e.IsDeleted = 0
           AND JSON_VALUE (e.DetailJson, N'$.reason') = N'stepUpRequiredForProfileSwitch'
           AND e.EventUtc >= (SELECT StartedUtc FROM auth.UserSession
                               WHERE SessionTokenHash = HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|admin')))
     , N'One refusal, before the step-up. auth.uspSwitchProfile logs the challenge it is about to demand.'
UNION ALL SELECT 9, N'Sessions still open after this run', 3
     , (SELECT COUNT (*) FROM auth.UserSession
         WHERE EndedUtc IS NULL AND IsDeleted = 0
           AND SessionTokenHash IN (HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|countycrud')
                                  , HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|countyread')
                                  , HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|tour')
                                  , HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|admin')
                                  , HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|eleven')))
     , N'The tour and the eleven-county user signed out; the other three are left open on purpose, as a real estate is.'
-- Rows 10 and 11 are G-50 asked as a whole-database question rather than a per-section one: the SAME six switches
-- counted by JOINING on the session id, and then every ProfileSwitch row this run produced, from any of its five
-- sessions, required to name the session it belonged to. Row 11 is scoped to this run's start on purpose -- this
-- database still holds the 73 orphaned rows that were written before T-127, and they are history, not a regression.
UNION ALL SELECT 10, N'Tour ProfileSwitch events that NAME the tour session', 6
     , (SELECT COUNT (*) FROM logs.AuthenticationEvent AS e
         WHERE e.EventType = N'ProfileSwitch' AND e.IsDeleted = 0
           AND e.UserSessionId = (SELECT UserSessionId FROM auth.UserSession
                                   WHERE SessionTokenHash = HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|tour')))
     , N'G-50 closed. The same six as evidence 2, reached by a join instead of a user name and a time window.'
UNION ALL SELECT 11, N'ProfileSwitch events in this run that name no session', 0
     , (SELECT COUNT (*) FROM logs.AuthenticationEvent AS e
         WHERE e.EventType = N'ProfileSwitch' AND e.IsDeleted = 0 AND e.UserSessionId IS NULL
           AND e.UserName LIKE LOWER (N'$(AgencyCode)') + N'.$(Wave).%'
           AND e.EventUtc >= (SELECT MIN (StartedUtc) FROM auth.UserSession
                               WHERE SessionTokenHash IN (HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|countycrud')
                                                        , HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|countyread')
                                                        , HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|tour')
                                                        , HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|admin')
                                                        , HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|eleven'))))
     , N'G-50 closed. The absence of these rows is the assertion, scoped to this run: older orphans are history.'
UNION ALL SELECT 12, N'Sessions this run elevated with a real second factor', 1
     , (SELECT COUNT (*) FROM auth.UserSession
         WHERE IsDeleted = 0 AND ElevatedUntilUtc IS NOT NULL
           AND SessionTokenHash = HASHBYTES ('SHA2_256', N'$(Seed)|$(RunLabel)|admin'))
     , N'G-48 closed. When the gap was open this was 0 of 271 sessions, and no query could have made it 1.';

EXEC sys.sp_set_session_context @key = N'BypassRowSecurity', @value = NULL;

SELECT @Bad = COUNT (*) FROM #Evidence WHERE Expected <> Actual;

SELECT Seq
     , Result   = CASE WHEN Expected = Actual THEN N'OK' ELSE N'VIOLATED' END
     , Subject
     , Expected
     , Actual
     , Detail
  FROM #Evidence
 ORDER BY Seq;

IF @Bad > 0
BEGIN
    PRINT CONCAT (N'E-59221: ', @Bad, N' evidence check(s) VIOLATED.');
    THROW 59221, N'Scenario evidence does not match the run.', 1;
END;

PRINT N'--- S1_prove_duties.sql: every observation OK, 12 evidence checks, 0 violations. ---';
PRINT N'--- THE THREE FINDINGS THIS SCENARIO WAS WRITTEN TO PROVE ARE CLOSED, AND THIS RUN IS WHAT SAYS SO:     ---';
PRINT N'---   G-48  auth.uspElevateSession (T-125) writes auth.UserSession.ElevatedUntilUtc. Section 7 presents  ---';
PRINT N'---         a fresh TOTP step to an ESTABLISHED session, the column goes from NULL to a future time, and ---';
PRINT N'---         the privileged switch refused with E-50052 a moment earlier then succeeds. The hand-written  ---';
PRINT N'---         UPDATE that used to stand in for the missing procedure is gone from this file. Evidence 12.  ---';
PRINT N'---   G-50  auth.uspSwitchProfile (T-127) writes UserSessionId on its ProfileSwitch event, and on the    ---';
PRINT N'---         MfaChallenged event a step-up refusal raises. Evidence 10 counts the tour''s six switches by  ---';
PRINT N'---         JOINING on the session id, and evidence 11 requires that no switch in this run is orphaned.  ---';
PRINT N'---   G-51  auth.uspListMyProfiles (T-126) lists a session''s own hats, demanding no permission and       ---';
PRINT N'---         taking no user id, so the first authenticated screen is inside the procedure surface.        ---';
PRINT N'---         Section 9 lists all 22 from a session wearing none of them, and the administrative lister    ---';
PRINT N'---         still refuses that session -- now with E-50032, which names the missing hat rather than       ---';
PRINT N'---         blaming the connection.                                                                     ---';
PRINT N'--- G-51 is the one with no evidence row: auth.uspListMyProfiles is error-only instrumented, so a call   ---';
PRINT N'--- that SUCCEEDS leaves nothing behind to count. That is by design, and section 9''s own assertion is    ---';
PRINT N'--- therefore the whole of its evidence -- which is worth knowing before someone goes looking for a row. ---';
GO
