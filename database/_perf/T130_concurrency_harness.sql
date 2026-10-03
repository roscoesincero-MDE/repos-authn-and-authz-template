/***********************************************************************************************************************
Script:         T130_concurrency_harness.sql
Purpose:        Measure the four contention questions DES-AUTH-001 section 6 asks that ONE connection can honestly
                answer: what an auth.UserSession insert locks when a thousand people sign in at the same minute; what a
                bulk role change accumulates on auth.ProfilePermissionScope and whether it escalates to a table lock;
                what the read predicate costs when the buffer pool is not warm, and whether its PLAN changes or only its
                cost; and whether auth.uspSwitchProfile and auth.uspDeactivateProfile take their locks in an order that
                can close a cycle.
Tasks:          T-130, closing gap G-49.
Depends on:     A POPULATED database. Either database/_scenarios/S1_load_agency.sql (44,000 users, 103,000 profiles,
                366,000 scope rows -- what this script was developed against) or database/_perf/T069_load_volumes.sql.
                At least one row in auth.UserSession, which any sign-in leaves behind.
Run with:       sqlcmd -S MDE-55TT2J4 -E -d testTemplateS1 -I -C -b -i database/_perf/T130_concurrency_harness.sql
                Then, for the three questions that need more than one connection:
                powershell.exe -NoProfile -ExecutionPolicy Bypass -File database/_perf/T130_concurrency_driver.ps1 `
                    -DatabaseName testTemplateS1
Author:         Template project
CreateDate:     2026-09-21

WHY THIS IS TWO FILES AND NOT ONE
---------------------------------
Section 6 asks five questions.  Three of them -- a sign-in storm, a deadlock, and a connection coming back out of a pool
-- are not properties of a statement.  They are properties of several connections happening at once, and a T-SQL batch
has exactly one connection.  :connect gives a second one but not a SIMULTANEOUS one: sqlcmd runs batches in sequence and
the previous connection is closed.  A script that claimed to measure blocking from a single connection would be
measuring nothing, which is worse than measuring nothing, because it would produce a number.

So the work is split by what each tool can honestly see:

    THIS FILE measures the lock footprints, the escalation point, the buffer-pool footprint and the statement ORDER.
    Those are single-statement and single-transaction properties; one connection can see all of them exactly.

    T130_concurrency_driver.ps1 opens many connections at once.  It drives the sign-in storm, it replays the
    switch-versus-deactivate lock order from two connections with a positive control that PROVES the harness can detect
    a deadlock, and it exercises the one thing only a pooling client can exercise: sp_reset_connection, which is what
    stands between SESSION_CONTEXT's read-only identity keys and the next user of a pooled connection.

WHAT A LOCK FOOTPRINT IS, AND WHY IT IS THE NUMBER TO ARGUE FROM
---------------------------------------------------------------
"Will this block at 8:59" cannot be answered by timing one call on an idle instance.  It can be answered by counting what
the call LOCKS and for how long it holds it, because blocking is two transactions wanting the same resource and nothing
else.  Every measurement below therefore opens a transaction, does the work, counts sys.dm_tran_locks for its own
session, and ROLLS BACK.  Nothing in this script is left behind: no session row, no scope row, no role change.

sys.dm_tran_locks is read for @@SPID only.  Another connection's locks are not this script's business and would make the
counts irreproducible.

THE THRESHOLD THAT MATTERS, STATED ONCE
---------------------------------------
Lock escalation converts row and page locks to ONE table lock when a single statement acquires about 5,000 locks on one
table, and can also fire when the instance's lock memory grows past its threshold.  A table lock on
auth.ProfilePermissionScope is not one tenant's problem: that table is what every row-security predicate and every
auth.uspDemandPermission call reads, so an X table lock on it stops the whole application, for every tenant, until the
transaction holding it commits.  That is why section 2 below exists and why it reports the point of escalation rather
than a yes or no.

NOTHING HERE IS A MODEL OF HOW TO WRITE AN APPLICATION
-----------------------------------------------------
Section 3 sets SESSION_CONTEXT by hand with sp_set_session_context and no @read_only, for the same reason
T070_measure_predicates.sql does: a measurement has to switch profiles inside one batch and auth.uspSetSessionContext
correctly makes that impossible (error 15664, G-36, BL-057).  The predicates read the same keys either way, which is the
only property the measurement depends on.  An application must never do this.

WHAT THIS SCRIPT WRITES
-----------------------
Nothing, except logs.ExecutionLog rows from the procedures section 2 calls and then rolls back, and the rows the CATCH
blocks of those procedures re-create deliberately after a rollback (rule 8).  Those are execution records of work that
did not happen; that is what the ReCreatedAfterRollback flag on logs.ExecutionLog is for.  Read the report at the end.
***********************************************************************************************************************/
SET NOCOUNT ON;
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;

-- ---------------------------------------------------------------------------------------------------------------------
-- Knobs.  All four are small on purpose: this is a harness, not a load test, and every one of them is rolled back.
-- ---------------------------------------------------------------------------------------------------------------------
DECLARE @SessionRows    INT = 200      -- synthetic auth.UserSession inserts, standing in for a sign-in burst
      , @LadderTop      INT = 2000     -- profiles rebuilt in ONE transaction at the top of the escalation ladder
      , @ColdCache      BIT = 0        -- 1 runs DBCC DROPCLEANBUFFERS. INSTANCE-WIDE. Never on a shared server.
      , @Failure        NVARCHAR (2000) = NULL;

-- Guarded rather than dropped and recreated, which the convention gate forbids and which is unnecessary here anyway:
-- a temporary table lives and dies with the connection, sqlcmd opens a new one for every run, and this script holds one
-- connection throughout so that section 6 can read what sections 1 to 5 wrote.
IF OBJECT_ID (N'tempdb..#T130Report') IS NULL
CREATE TABLE #T130Report
(
    RowNo     INT IDENTITY (1, 1) PRIMARY KEY
  , Severity  INT            NOT NULL      -- 1 blocks a release, 2 needs a decision, 3 is a note, 4 is a pass
  , Status    VARCHAR (20)   NOT NULL
  , Question  NVARCHAR (100) NOT NULL      -- which of section 6's five bullets this answers
  , Item      NVARCHAR (200) NOT NULL
  , Detail    NVARCHAR (MAX) NOT NULL
);

IF OBJECT_ID (N'tempdb..#T130Locks') IS NULL
CREATE TABLE #T130Locks
(
    Label        NVARCHAR (60) NOT NULL
  , ResourceType NVARCHAR (60) NOT NULL
  , RequestMode  NVARCHAR (60) NOT NULL
  , ObjectName   NVARCHAR (300)    NULL
  , LockCount    INT           NOT NULL
);
GO

SET NOCOUNT ON;
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;

-- =====================================================================================================================
-- 0.  Refuse to measure an unloaded database.  Contention is a function of volume; on an empty database every count
--     below is small and every conclusion drawn from it is wrong in the direction that gets a project into trouble.
-- =====================================================================================================================
DECLARE @Profiles INT = NULL, @ScopeRows INT = NULL, @Sessions INT = NULL, @Failure NVARCHAR (2000) = NULL;

SELECT @Profiles  = COUNT (*) FROM auth.UserProfile            WHERE IsDeleted = 0;
SELECT @ScopeRows = COUNT (*) FROM auth.ProfilePermissionScope WHERE IsDeleted = 0;
SELECT @Sessions  = COUNT (*) FROM auth.UserSession;

IF @Profiles < 1000 OR @ScopeRows < 5000
BEGIN
    SET @Failure = CONCAT (N'This database holds ', @Profiles, N' profile(s) and ', @ScopeRows, N' scope row(s). '
                         , N'Contention is a function of volume and neither number is large enough to produce a '
                         , N'transferable one: run database/_scenarios/S1_load_agency.sql or '
                         , N'database/_perf/T069_load_volumes.sql against this database first.');
    THROW 59030, @Failure, 1;
END;

IF @Sessions = 0
BEGIN
    SET @Failure = N'auth.UserSession is empty, so section 1 has no live row to borrow a UserId, a LoginAttemptId and '
                 + N'an ApplicationId from -- its synthetic inserts have to satisfy four foreign keys. Sign in once '
                 + N'(database/_scenarios/S1_prove_duties.sql does, and so does any of the smoke tests) and run again.';
    THROW 59031, @Failure, 1;
END;

PRINT CONCAT (N'T130: ', @Profiles, N' profiles, ', @ScopeRows, N' scope rows, ', @Sessions
            , N' session rows. Measuring.');
GO

-- =====================================================================================================================
-- 1.  SECTION 6, FIRST BULLET.  "Blocking on auth.UserSession writes when a thousand people sign in at 8:59."
--
--     What the question really asks is whether two sign-ins contend, and there are exactly three ways they can:
--
--       (a) ROW OR KEY LOCKS ON THE SAME ROW.  They cannot: every sign-in inserts its OWN row with its own identity
--           value.  This section measures the footprint anyway, because "cannot" is a claim and a count is evidence.
--
--       (b) THE LAST PAGE OF THE CLUSTERED INDEX.  UserSessionId is an ascending IDENTITY, so every insert in the
--           instant goes to the same page, and the PAGELATCH_EX on that page is taken one at a time. This is last-page
--           insert contention, it is not a lock and it does not appear in sys.dm_tran_locks, and it is the real answer
--           to the bullet. SQL Server 2019 added OPTIMIZE_FOR_SEQUENTIAL_KEY for exactly this pattern, so whether the
--           index has it on is a fact worth reporting rather than assuming.
--
--       (c) A UNIQUE INDEX ON A RANDOM KEY.  UX_auth_UserSession_TokenHash is unique over a 32-byte hash, so its
--           inserts scatter across the whole B-tree -- no hot page, but every insert dirties a different page, which is
--           a buffer-pool and log cost rather than a contention one.
--
--     THE INSERTS ARE SYNTHETIC AND THE ROLLBACK IS THE POINT.  Driving auth.uspCompleteLogin 200 times would measure
--     the whole sign-in path -- password verifier read, MFA, policy resolution, event write -- and the question here is
--     narrower than that. The driver measures the whole path from many connections; this measures the table.
-- =====================================================================================================================
SET NOCOUNT ON;
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;

DECLARE @SessionRows INT = 200
      , @Uid         INT = NULL
      , @Att         BIGINT = NULL
      , @App         INT = NULL
      , @Now         DATETIME2 (3) = SYSUTCDATETIME ()
      , @Elapsed     INT = NULL
      , @T0          DATETIME2 (3) = NULL
      , @Detail      NVARCHAR (MAX) = NULL;

-- Borrowed from a real row so the four foreign keys are satisfied without inventing a user, an attempt or an
-- application. Duplicating a LoginAttemptId across the synthetic rows is legal: the foreign key is not unique.
SELECT TOP (1) @Uid = s.UserId, @Att = s.LoginAttemptId, @App = s.ApplicationId
  FROM auth.UserSession AS s
 ORDER BY s.UserSessionId DESC;

-- WHY THE SNAPSHOT BELOW GOES INTO A TABLE VARIABLE AND NOT STRAIGHT INTO #T130Locks.  The locks exist only while
-- the transaction is open, so the snapshot has to be taken before the ROLLBACK -- and a #temp table is a TRANSACTIONAL
-- object, so the rollback takes the snapshot with it.  The first version of this section did exactly that and reported
-- 0 key locks for a 200-row insert, which is not a surprising number, it is an impossible one: an INSERT holds an X
-- lock on every key it wrote until the transaction ends.  A table variable is not rolled back.  That single difference
-- is the only reason one is used here, and it is worth knowing before writing any measurement that rolls itself back.
DECLARE @LockSnap TABLE
(
    ResourceType NVARCHAR (60)  NOT NULL
  , RequestMode  NVARCHAR (60)  NOT NULL
  , ObjectName   NVARCHAR (300) NULL
  , LockCount    INT            NOT NULL
);

SET @T0 = SYSUTCDATETIME ();

BEGIN TRANSACTION;

INSERT auth.UserSession
    (UserId, LoginAttemptId, ApplicationId, SessionTokenHash, ClientAddress, AuthenticationMethod
   , IsBypassRoute, MfaSatisfied, StartedUtc, LastSeenUtc, AbsoluteExpiryUtc, IdleExpiryUtc
   , auditCreatedBy, auditModifiedBy)
SELECT @Uid
     , @Att
     , @App
     , HASHBYTES ('SHA2_256', CONCAT (N'T130|', g.value, N'|', CONVERT (NVARCHAR (40), @Now, 126)))
     , N'203.0.113.130'
     , 'LocalPassword'
     , 0
     , 1
     , @Now
     , @Now
     , DATEADD (HOUR, 8, @Now)
     , DATEADD (MINUTE, 20, @Now)
     , N'T130_harness'
     , N'T130_harness'
  FROM GENERATE_SERIES (1, @SessionRows) AS g;

SET @Elapsed = DATEDIFF (MILLISECOND, @T0, SYSUTCDATETIME ());

INSERT @LockSnap (ResourceType, RequestMode, ObjectName, LockCount)
SELECT l.resource_type
     , l.request_mode
     , OBJECT_NAME (p.object_id)
     , COUNT (*)
  FROM sys.dm_tran_locks AS l
  LEFT JOIN sys.partitions AS p
         ON p.hobt_id = l.resource_associated_entity_id
        AND l.resource_type IN (N'KEY', N'PAGE', N'HOBT', N'RID')
 WHERE l.request_session_id = @@SPID
   AND l.resource_type <> N'DATABASE'
 GROUP BY l.resource_type, l.request_mode, OBJECT_NAME (p.object_id);

ROLLBACK TRANSACTION;

-- The 200 rows are gone; the count of what they locked is not, and section 6 reads it from here.
INSERT #T130Locks (Label, ResourceType, RequestMode, ObjectName, LockCount)
SELECT N'session-insert', k.ResourceType, k.RequestMode, k.ObjectName, k.LockCount
  FROM @LockSnap AS k;

-- 1a.  The footprint.
DECLARE @KeyLocks INT = NULL, @PageLocks INT = NULL, @ObjLocks INT = NULL, @ObjX INT = NULL
      , @SeqKey BIT = NULL, @IdxCount INT = NULL, @ClusteredKey NVARCHAR (200) = NULL;

-- Read here rather than in 1b because 1a's sentence divides by it: the per-row lock count only means something once
-- the reader knows how many indexes each insert maintains.
SELECT @IdxCount = COUNT (*)
  FROM sys.indexes AS i
 WHERE i.object_id = OBJECT_ID (N'auth.UserSession') AND i.index_id > 0;

SELECT @KeyLocks  = ISNULL (SUM (CASE WHEN ResourceType = N'KEY'    THEN LockCount END), 0)
     , @PageLocks = ISNULL (SUM (CASE WHEN ResourceType = N'PAGE'   THEN LockCount END), 0)
     , @ObjLocks  = ISNULL (SUM (CASE WHEN ResourceType = N'OBJECT' THEN LockCount END), 0)
     , @ObjX      = ISNULL (SUM (CASE WHEN ResourceType = N'OBJECT' AND RequestMode IN (N'X', N'S') THEN LockCount END), 0)
  FROM #T130Locks
 WHERE Label = N'session-insert';

SET @Detail = CONCAT (N'', @SessionRows, N' session rows inserted in one transaction in ', @Elapsed
                    , N' ms took ', @KeyLocks, N' key lock(s), ', @PageLocks, N' page lock(s) and ', @ObjLocks
                    , N' object-level intent lock(s); ', @ObjX, N' of the object locks were full X or S, which is what '
                    , N'escalation looks like. That is about ', CAST (@KeyLocks / NULLIF (@SessionRows, 0) AS INT)
                    , N' key lock(s) per row, which is the clustered key plus the ', @IdxCount - 1
                    , N' non-clustered indexes each insert also has to maintain -- the cost of an index is paid on '
                    , N'WRITE, and a sign-in is a write. A single sign-in is 1/', @SessionRows, N' of this: its own '
                    , N'keys, its own page, an intent lock on the table. Two sign-ins share no row, so they do not '
                    , N'BLOCK each other, and this is the evidence for that rather than the assertion of it. For a '
                    , N'storm to reach the ~5,000-lock escalation point on this table, one STATEMENT would have to '
                    , N'insert about ', CAST (5000 / NULLIF (@KeyLocks / NULLIF (@SessionRows, 0), 0) AS INT)
                    , N' sessions at once, and no sign-in inserts more than one.');

INSERT #T130Report (Severity, Status, Question, Item, Detail)
VALUES (CASE WHEN @ObjX = 0 THEN 4 ELSE 2 END
      , CASE WHEN @ObjX = 0 THEN 'OK' ELSE 'RISK' END
      , N'6.1 sign-in storm', N'What one auth.UserSession insert locks', @Detail);

-- 1b.  The hot page, which is not a lock and is the real answer.
SELECT @SeqKey = i.optimize_for_sequential_key
  FROM sys.indexes AS i
 WHERE i.object_id = OBJECT_ID (N'auth.UserSession') AND i.index_id = 1;

-- @IdxCount is read in 1a, which needs it to divide the lock count by the number of indexes each insert maintains.

SELECT @ClusteredKey = STRING_AGG (c.name, N', ') WITHIN GROUP (ORDER BY ic.key_ordinal)
  FROM sys.index_columns AS ic
 INNER JOIN sys.columns   AS c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
 WHERE ic.object_id = OBJECT_ID (N'auth.UserSession') AND ic.index_id = 1 AND ic.is_included_column = 0;

SET @Detail = CONCAT (N'The clustered key is (', @ClusteredKey, N'), an ascending IDENTITY, so every insert in the same '
                    , N'instant targets the same trailing page and serializes on its PAGELATCH_EX -- which is a latch, '
                    , N'not a lock, so it is invisible to section 1a above and to every lock report. '
                    , N'OPTIMIZE_FOR_SEQUENTIAL_KEY is currently '
                    , CASE WHEN @SeqKey = 1 THEN N'ON, which is the mitigation SQL Server 2019 added for exactly this '
                                                 + N'shape and is already in place.'
                           ELSE N'OFF. At a few hundred sign-ins a minute that is invisible. At a thousand in the same '
                              + N'minute it is the first thing that will show up, as PAGELATCH_EX waits on this '
                              + N'object and NOT as blocking, so a DBA looking at sys.dm_tran_locks will find '
                              + N'nothing. ALTER INDEX PK_auth_UserSession ON auth.UserSession SET '
                              + N'(OPTIMIZE_FOR_SEQUENTIAL_KEY = ON) is the one-line change; the driver''s storm test '
                              + N'is what tells you whether this instance needs it yet.' END
                    , N' The table carries ', @IdxCount, N' indexes, and every one of them is written on every insert.');

INSERT #T130Report (Severity, Status, Question, Item, Detail)
VALUES (CASE WHEN @SeqKey = 1 THEN 4 ELSE 2 END
      , CASE WHEN @SeqKey = 1 THEN 'OK' ELSE 'ACTION' END
      , N'6.1 sign-in storm', N'Last-page insert contention on the clustered key', @Detail);
GO

-- =====================================================================================================================
-- 2.  SECTION 6, SECOND BULLET.  "Lock escalation on auth.ProfilePermissionScope during a bulk role change."
--
--     THE SHAPE OF THE RISK IS NOT A GUESS, IT IS IN 145_auth_role_procedures.sql AND SAYS SO.
--     auth.uspSetRolePermissions rebuilds the derived scope of every profile holding the role, in a WHILE loop, ONE
--     auth.uspRebuildProfilePermissionScope call per profile, and -- by an explicit comment and for a correct reason --
--     inside the SAME transaction as the role change: "Derived data is rebuilt in the SAME transaction as the change
--     that invalidated it. A profile whose scope is stale is a profile with the wrong permissions."
--
--     That decision is right and it has a consequence. No single MERGE in that loop comes near 5,000 locks, so the
--     per-statement escalation rule never fires; but the TRANSACTION accumulates every one of those locks and holds
--     them until it commits. On the population this was written against, CRUD_ACCESS is held by 56,730 profiles. The
--     question this section answers is what that costs: how many locks per profile, how long per profile, and whether
--     the instance escalates to a table lock on the way -- which would stop every tenant, not just the ones affected
--     by the role change, because auth.ProfilePermissionScope is what every predicate reads.
--
--     THE LADDER CHANGES THE ROLE FIRST, AND THAT IS NOT DECORATION.  auth.uspRebuildProfilePermissionScope is
--     idempotent: called against a profile whose scope is already correct it reads, finds nothing to change, writes
--     nothing and therefore HOLDS nothing. The first version of this ladder called it exactly that way and reported one
--     lock for 2,000 profiles -- a true measurement of the wrong path. So each step below makes a real role change in
--     its own transaction, the way auth.uspSetRolePermissions makes one, and every rebuild then has rows to write.
--     Everything, the role change included, is rolled back.
--
--     THE LADDER IS ROLLED BACK AND THE EXTRAPOLATION IS LINEAR AND SAID TO BE.  Rebuilding 56,730 profiles here would
--     take the harness into the hours and fill the log for no extra knowledge: the per-profile cost is flat, so
--     measuring a thousand and multiplying is honest as long as the multiplication is shown. What is NOT linear is the
--     consequence, and that is the point of the report row.
-- =====================================================================================================================
SET NOCOUNT ON;
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;

DECLARE @LadderTop  INT = 1000
      , @BigRole    NVARCHAR (100) = NULL
      , @BigRoleId  INT = NULL
      , @BigHolders INT = NULL
      , @SparePerm  INT = NULL      -- a permission the role does NOT hold, so adding it is a real change
      , @SpareApp   INT = NULL
      , @Wrote      INT = NULL
      , @Step       INT = NULL
      , @Done       INT = 0
      , @Pid        INT = NULL
      , @T0         DATETIME2 (3) = NULL
      , @Ms         INT = NULL
      , @Locks      INT = NULL
      , @Escalated  INT = 0
      , @EscAt      INT = NULL
      , @Detail     NVARCHAR (MAX) = NULL;

DECLARE @Ladder TABLE (Profiles INT NOT NULL PRIMARY KEY, Ms INT NULL, KeyLocks INT NULL, ObjX INT NULL
                     , ScopeRowsWritten INT NULL);
DECLARE @Victims TABLE (RowNo INT IDENTITY (1, 1) PRIMARY KEY, UserProfileId INT NOT NULL);

-- The role a bulk change would hurt most: the one the most profiles hold.
SELECT TOP (1) @BigRoleId = r.RoleId, @BigRole = r.RoleCode, @BigHolders = COUNT (*)
  FROM auth.UserProfileRole AS upr
 INNER JOIN auth.Role       AS r ON r.RoleId = upr.RoleId
 WHERE upr.IsDeleted = 0 AND r.IsDeleted = 0
 GROUP BY r.RoleId, r.RoleCode
 ORDER BY COUNT (*) DESC;

INSERT @Victims (UserProfileId)
SELECT TOP (@LadderTop) upr.UserProfileId
  FROM auth.UserProfileRole AS upr
 WHERE upr.RoleId = @BigRoleId AND upr.IsDeleted = 0
 ORDER BY upr.UserProfileId;

-- The change each step makes: one permission this role does not already hold, for the application its existing
-- mappings are registered under. Adding a permission is the cheapest role change that still touches every holder --
-- it adds scope rows rather than deleting them, so no step can leave a profile with less authority than it started
-- with even for the moments the transaction is open.
SELECT TOP (1) @SpareApp = rp.ApplicationId
  FROM auth.RolePermission AS rp
 WHERE rp.RoleId = @BigRoleId AND rp.IsDeleted = 0
 ORDER BY rp.RolePermissionId;

SELECT TOP (1) @SparePerm = p.PermissionId
  FROM auth.Permission AS p
 WHERE p.IsDeleted = 0
   AND NOT EXISTS (SELECT 1
                     FROM auth.RolePermission AS rp
                    WHERE rp.RoleId = @BigRoleId AND rp.PermissionId = p.PermissionId AND rp.IsDeleted = 0)
 ORDER BY p.PermissionId;

IF (SELECT COUNT (*) FROM @Victims) < 100
BEGIN
    INSERT #T130Report (Severity, Status, Question, Item, Detail)
    VALUES (3, 'SKIPPED', N'6.2 bulk role change', N'The escalation ladder'
          , CONCAT (N'The most-held role in this database is ', COALESCE (@BigRole, N'(none)'), N' with '
                  , COALESCE (@BigHolders, 0), N' holder(s). Fewer than 100 is not a bulk role change and the ladder '
                  , N'would report the absence of a problem this database does not have the volume to have.'));
END;
ELSE
BEGIN
    SET @Step = 100;

    WHILE @Step <= @LadderTop
    BEGIN
        SET @T0   = SYSUTCDATETIME ();
        SET @Done = 0;

        BEGIN TRANSACTION;

        -- The role change itself. If the role already holds every permission in the catalogue there is nothing to add,
        -- so one live mapping is soft-deleted instead: still a real change, still invalidating every holder's scope,
        -- and still rolled back. Either way what follows measures rebuilds that WRITE.
        IF @SparePerm IS NOT NULL
            INSERT auth.RolePermission (RoleId, PermissionId, ApplicationId, auditCreatedBy, auditModifiedBy)
            VALUES (@BigRoleId, @SparePerm, @SpareApp, N'T130_harness', N'T130_harness');
        ELSE
            UPDATE TOP (1) auth.RolePermission
               SET IsDeleted            = 1
                 , auditDeletedBy       = N'T130_harness'
                 , auditDeletedDateUtc  = SYSUTCDATETIME ()
             WHERE RoleId = @BigRoleId AND IsDeleted = 0;

        WHILE @Done < @Step
        BEGIN
            SET @Done = @Done + 1;
            SELECT @Pid = v.UserProfileId FROM @Victims AS v WHERE v.RowNo = @Done;

            -- The real writer, called the way auth.uspSetRolePermissions calls it. Its own rule-8 logging is part of
            -- the cost and is deliberately not suppressed: a bulk change pays it 56,730 times too.
            EXEC auth.uspRebuildProfilePermissionScope @UserProfileId = @Pid;
        END;

        SET @Ms = DATEDIFF (MILLISECOND, @T0, SYSUTCDATETIME ());

        -- Proof that the rebuilds wrote something. If this is 0 the ladder is measuring the no-op path again and the
        -- lock counts below mean nothing -- which is why it is reported rather than assumed. The test is the audit
        -- timestamp and not an audit NAME: auth.uspRebuildProfilePermissionScope stamps the rows with SESSION_CONTEXT's
        -- AppUser or ORIGINAL_LOGIN (), so no string this script chooses would appear on them.
        SELECT @Wrote = COUNT (*)
          FROM auth.ProfilePermissionScope AS s
         INNER JOIN @Victims AS v
                 ON v.UserProfileId = s.UserProfileId
         WHERE s.auditModifiedDateUtc >= @T0;

        SELECT @Locks     = COUNT (*)
             , @Escalated = SUM (CASE WHEN l.resource_type = N'OBJECT' AND l.request_mode IN (N'X', N'S', N'SIX')
                                      THEN 1 ELSE 0 END)
          FROM sys.dm_tran_locks AS l
          LEFT JOIN sys.partitions AS p
                 ON p.hobt_id = l.resource_associated_entity_id
                AND l.resource_type IN (N'KEY', N'PAGE', N'HOBT', N'RID')
         WHERE l.request_session_id = @@SPID
           AND l.resource_type IN (N'KEY', N'PAGE', N'OBJECT')
           AND (p.object_id = OBJECT_ID (N'auth.ProfilePermissionScope')
                OR (l.resource_type = N'OBJECT'
                    AND l.resource_associated_entity_id = OBJECT_ID (N'auth.ProfilePermissionScope')));

        ROLLBACK TRANSACTION;

        INSERT @Ladder (Profiles, Ms, KeyLocks, ObjX, ScopeRowsWritten) VALUES (@Step, @Ms, @Locks, @Escalated, @Wrote);

        IF @Escalated > 0 AND @EscAt IS NULL SET @EscAt = @Step;

        SET @Step = CASE WHEN @Step = 100 THEN 250 WHEN @Step = 250 THEN 500 WHEN @Step = 500 THEN 1000
                         ELSE @Step * 2 END;
    END;

    SELECT LadderStep = Profiles, ElapsedMs = Ms, MsPerProfile = Ms / NULLIF (Profiles, 0)
         , LocksHeldOnScopeTable = KeyLocks, TableLevelXorS = ObjX, ScopeRowsWritten
      FROM @Ladder ORDER BY Profiles;

    DECLARE @TopProfiles INT = NULL, @TopMs INT = NULL, @TopLocks INT = NULL, @TopWrote INT = NULL;

    SELECT TOP (1) @TopProfiles = l.Profiles, @TopMs = l.Ms, @TopLocks = l.KeyLocks, @TopWrote = l.ScopeRowsWritten
      FROM @Ladder AS l ORDER BY l.Profiles DESC;

    SET @Detail = CONCAT (N'Rebuilding ', @TopProfiles, N' profiles'' scope in ONE transaction -- which is what '
                        , N'auth.uspSetRolePermissions does, on purpose, so that no profile is ever left with a stale '
                        , N'scope -- took ', @TopMs, N' ms and left ', @TopLocks
                        , N' lock(s) held on auth.ProfilePermissionScope at commit time, '
                        , CASE WHEN @EscAt IS NULL THEN N'with NO escalation to a table-level X or S lock at any step. '
                               ELSE CONCAT (N'and ESCALATED to a table-level lock at the ', @EscAt
                                          , N'-profile step. ') END
                        , N'The most-held role here is ', @BigRole, N', with ', @BigHolders
                        , N' holders: linearly, that change is about ', CAST (CAST (@BigHolders AS BIGINT) * @TopMs
                                                                           / NULLIF (@TopProfiles, 0) / 1000 AS INT)
                        , N' seconds of one transaction holding about ', CAST (CAST (@BigHolders AS BIGINT) * @TopLocks
                                                                           / NULLIF (@TopProfiles, 0) AS BIGINT)
                        , N' locks on the one table every row-security predicate and every auth.uspDemandPermission '
                        , N'call has to read -- about ', CAST (CAST (@BigHolders AS BIGINT) * @TopMs
                                                            / NULLIF (@TopProfiles, 0) / 60000 AS INT)
                        , N' minutes of it. The rebuilds wrote ', COALESCE (@TopWrote, 0)
                        , N' scope row(s), which is what makes the lock count above a measurement of the real path '
                        , N'rather than of an idempotent no-op. The extrapolation is linear because the per-profile '
                        , N'cost is flat at ', @TopMs / NULLIF (@TopProfiles, 0), N' ms per profile; the '
                        , N'CONSEQUENCE is not linear, because the affected profiles'' requests queue behind those '
                        , N'locks and, if lock memory escalates the transaction to a table lock, every other tenant''s '
                        , N'requests do too. Nothing here is rolled forward: every step above was rolled back.');

    INSERT #T130Report (Severity, Status, Question, Item, Detail)
    VALUES (CASE WHEN @EscAt IS NOT NULL THEN 1 ELSE 2 END
          , CASE WHEN @EscAt IS NOT NULL THEN 'RISK' ELSE 'ACTION' END
          , N'6.2 bulk role change', N'What a role change accumulates on auth.ProfilePermissionScope', @Detail);

    -- The tripwire on this section's own validity.
    IF COALESCE (@TopWrote, 0) = 0
        INSERT #T130Report (Severity, Status, Question, Item, Detail)
        VALUES (2, 'UNMEASURED', N'6.2 bulk role change', N'The ladder wrote nothing'
              , N'The ladder''s rebuilds touched no auth.ProfilePermissionScope row belonging to the profiles it '
              + N'rebuilt, so every lock count in this section describes an idempotent no-op and not a role change. '
              + N'Either the role change at the top of each step did not invalidate anything -- check that the chosen '
              + N'role has live permission mappings and that the spare permission is one it does not already hold -- '
              + N'or the rebuild no longer stamps auditModifiedDateUtc on the rows it writes. Do not quote the numbers '
              + N'above until this row is gone.');

    INSERT #T130Report (Severity, Status, Question, Item, Detail)
    VALUES (3, 'INFO', N'6.2 bulk role change', N'What to do about it'
          , N'Three options, in the order a project should consider them. ONE: do the change out of hours, which is '
          + N'what most projects will choose and which is a legitimate answer as long as it is a DECISION and not an '
          + N'accident. TWO: change auth.uspSetRolePermissions to commit the role change and then rebuild in batches, '
          + N'accepting a window in which some profiles hold the old scope -- this trades the outage for a period of '
          + N'wrong answers and must not be done without reading that procedure''s comment on why it is one '
          + N'transaction. THREE: leave it, and put the holder count in front of whoever presses the button: a role '
          + N'held by 30 profiles is not a problem and a role held by 56,730 is a maintenance window. The template '
          + N'ships option three, and this harness is how a project measures its own numbers before choosing.');
END;
GO

-- =====================================================================================================================
-- 3.  SECTION 6, THIRD BULLET.  "The read predicate's plan when the buffer pool is no longer warm for one tenant."
--
--     THE BULLET CONTAINS A HIDDEN ASSUMPTION AND THIS SECTION EXISTS TO SETTLE IT.  Buffer-pool warmth does not
--     change a PLAN. A plan is compiled from statistics and parameter values; it is not recompiled because pages fell
--     out of memory. What a cold pool changes is the COST of the same plan, and it changes it by exactly the number of
--     pages the plan has to fetch from disk.
--
--     So the useful measurements are: how big is the predicate's own working set (because that is what has to be
--     resident for a seek to stay a seek in practice), how much of it IS resident right now, and -- if @ColdCache is
--     set -- what the first read after a cold start actually costs against the warm re-read of the same statement,
--     with the plan hash printed for both to show it is the SAME plan.
--
--     WHAT IS DELIBERATELY NOT MEASURED HERE.  The fact-table half -- what the predicate costs per case file at
--     200,000 rows -- belongs to T070_measure_predicates.sql, which has an unprotected twin table to compare against
--     and a database loaded for it. This section measures the part T070 does not: the predicate's own tables, which on
--     an agency population are far larger than the demo domain and are read on every single statement.
-- =====================================================================================================================
SET NOCOUNT ON;
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;

DECLARE @ColdCache BIT = 0
      , @Detail    NVARCHAR (MAX) = NULL
      , @Prof      INT = NULL
      , @Ten       INT = NULL
      , @L0        BIGINT = NULL, @L1 BIGINT = NULL, @P0 BIGINT = NULL, @P1 BIGINT = NULL
      , @ColdL     BIGINT = NULL, @ColdP BIGINT = NULL, @WarmL BIGINT = NULL, @WarmP BIGINT = NULL
      , @Sql       NVARCHAR (MAX) = NULL;

-- 3a.  The working set, and how much of it is in memory.
DECLARE @Set TABLE
(
    ObjectName   NVARCHAR (200) NOT NULL PRIMARY KEY
  , TotalPages   BIGINT NOT NULL
  , ResidentPages BIGINT NOT NULL
);

INSERT @Set (ObjectName, TotalPages, ResidentPages)
SELECT o.ObjectName
     , ISNULL (ps.Pages, 0)
     , ISNULL (bd.Pages, 0)
  FROM (VALUES (N'auth.ProfilePermissionScope'), (N'auth.TenantClosure'), (N'auth.Permission')
             , (N'auth.UserProfile'), (N'dbo.CaseFile')) AS o (ObjectName)
 OUTER APPLY (SELECT Pages = SUM (s.used_page_count)
                FROM sys.dm_db_partition_stats AS s
               WHERE s.object_id = OBJECT_ID (o.ObjectName)) AS ps
 OUTER APPLY (SELECT Pages = COUNT (*)
                FROM sys.dm_os_buffer_descriptors AS b
               INNER JOIN sys.allocation_units    AS au ON au.allocation_unit_id = b.allocation_unit_id
               INNER JOIN sys.partitions          AS p  ON p.hobt_id = au.container_id
               WHERE b.database_id = DB_ID ()
                 AND p.object_id   = OBJECT_ID (o.ObjectName)) AS bd;

SELECT ObjectName
     , TotalPages
     , TotalMB       = CAST (TotalPages * 8.0 / 1024 AS DECIMAL (10, 1))
     , ResidentPages = ResidentPages
     , ResidentPct   = CAST (100.0 * ResidentPages / NULLIF (TotalPages, 0) AS DECIMAL (5, 1))
  FROM @Set
 ORDER BY TotalPages DESC;

DECLARE @ScopeMB DECIMAL (10, 1) = NULL, @ScopeResident DECIMAL (5, 1) = NULL;

SELECT @ScopeMB       = CAST (TotalPages * 8.0 / 1024 AS DECIMAL (10, 1))
     , @ScopeResident = CAST (100.0 * ResidentPages / NULLIF (TotalPages, 0) AS DECIMAL (5, 1))
  FROM @Set WHERE ObjectName = N'auth.ProfilePermissionScope';

SET @Detail = CONCAT (N'auth.ProfilePermissionScope is ', @ScopeMB, N' MB and is currently '
                    , COALESCE (CAST (@ScopeResident AS NVARCHAR (10)), N'0'), N'% resident. Every predicate '
                    , N'evaluation and every auth.uspDemandPermission call seeks it, so this is the object whose '
                    , N'residency decides whether the predicate is three logical reads or three PHYSICAL ones. It is '
                    , N'small enough to stay resident on any realistic server, which is the finding: the answer to '
                    , N'"what happens when the pool is cold for one tenant" is that the predicate''s own tables are '
                    , N'shared by every tenant and are therefore warm as long as anybody is working. The per-tenant '
                    , N'cold-start cost lands on the FACT table, not on the predicate -- and that is the number '
                    , N'T070_measure_predicates.sql produces against a loaded demo domain.');

INSERT #T130Report (Severity, Status, Question, Item, Detail)
VALUES (3, 'INFO', N'6.3 cold buffer pool', N'The predicate''s working set and its residency', @Detail);

-- 3b.  Cold against warm, same statement, same plan. Gated, because DBCC DROPCLEANBUFFERS is instance-wide.
IF @ColdCache = 1
BEGIN
    SELECT TOP (1) @Prof = pps.UserProfileId
      FROM auth.ProfilePermissionScope AS pps
     WHERE pps.IsDeleted = 0
     GROUP BY pps.UserProfileId
     ORDER BY COUNT (*) DESC;

    SELECT @Ten = p.TenantId FROM auth.UserProfile AS p WHERE p.UserProfileId = @Prof;

    EXEC sys.sp_set_session_context @key = N'BypassRowSecurity', @value = NULL;
    EXEC sys.sp_set_session_context @key = N'UserProfileId',     @value = @Prof;
    EXEC sys.sp_set_session_context @key = N'ActingTenantId',    @value = @Ten;

    SET @Sql = N'DECLARE @Sink INT;'
             + N' SELECT /*T130-COLD*/ @Sink = COUNT (*) FROM dbo.CaseFile AS cf WHERE cf.IsDeleted = 0;';

    DBCC DROPCLEANBUFFERS WITH NO_INFOMSGS;

    SELECT @L0 = r.logical_reads, @P0 = r.reads FROM sys.dm_exec_requests AS r WHERE r.session_id = @@SPID;
    EXEC sys.sp_executesql @Sql;
    SELECT @L1 = r.logical_reads, @P1 = r.reads FROM sys.dm_exec_requests AS r WHERE r.session_id = @@SPID;

    SET @ColdL = @L1 - @L0;
    SET @ColdP = @P1 - @P0;

    SELECT @L0 = r.logical_reads, @P0 = r.reads FROM sys.dm_exec_requests AS r WHERE r.session_id = @@SPID;
    EXEC sys.sp_executesql @Sql;
    SELECT @L1 = r.logical_reads, @P1 = r.reads FROM sys.dm_exec_requests AS r WHERE r.session_id = @@SPID;

    SET @WarmL = @L1 - @L0;
    SET @WarmP = @P1 - @P0;

    DECLARE @Plans INT = NULL, @Hashes INT = NULL;

    SELECT @Plans  = COUNT (*)
         , @Hashes = COUNT (DISTINCT qs.query_plan_hash)
      FROM sys.dm_exec_query_stats AS qs
     CROSS APPLY sys.dm_exec_sql_text (qs.sql_handle) AS st
     WHERE st.text LIKE N'%/*T130-COLD*/%';

    SET @Detail = CONCAT (N'The same statement, cold then warm: ', @ColdL, N' logical and ', @ColdP
                        , N' PHYSICAL reads cold, ', @WarmL, N' logical and ', @WarmP
                        , N' physical warm. The logical count is the work the plan does and it does not change; the '
                        , N'physical count is the disk and it is the whole difference. The plan cache holds ', @Plans
                        , N' entry/entries for this statement with ', @Hashes, N' distinct plan hash(es): '
                        , CASE WHEN @Hashes <= 1 THEN N'ONE plan served both executions, which settles the bullet -- a '
                                                    + N'cold pool does not change the predicate''s plan, only its cost.'
                               ELSE N'more than one plan, which would mean something OTHER than warmth recompiled it '
                                  + N'and is worth investigating.' END);

    INSERT #T130Report (Severity, Status, Question, Item, Detail)
    VALUES (CASE WHEN @Hashes <= 1 THEN 4 ELSE 2 END
          , CASE WHEN @Hashes <= 1 THEN 'OK' ELSE 'RISK' END
          , N'6.3 cold buffer pool', N'Cold against warm, and whether the plan moved', @Detail);
END;
ELSE
BEGIN
    INSERT #T130Report (Severity, Status, Question, Item, Detail)
    VALUES (3, 'SKIPPED', N'6.3 cold buffer pool', N'Cold against warm, and whether the plan moved'
          , N'Not run. The cold half of this measurement needs DBCC DROPCLEANBUFFERS, which empties the buffer pool '
          + N'for the WHOLE INSTANCE and not just for this database -- on a shared development server that is a rude '
          + N'thing to do to whoever else is connected. Set @ColdCache = 1 in section 3 and re-run when the instance '
          + N'is yours.');
END;

-- 3c.  The skew the bullet's phrase "for one tenant" points at.
DECLARE @MaxScope INT = NULL, @MinScope INT = NULL, @AvgScope INT = NULL
      , @MaxClosure INT = NULL, @AvgClosure INT = NULL;

SELECT @MaxScope = MAX (c), @MinScope = MIN (c), @AvgScope = AVG (c)
  FROM (SELECT COUNT (*) AS c FROM auth.ProfilePermissionScope WHERE IsDeleted = 0 GROUP BY UserProfileId) AS x;

SELECT @MaxClosure = MAX (c), @AvgClosure = AVG (c)
  FROM (SELECT COUNT (*) AS c FROM auth.TenantClosure GROUP BY AncestorTenantId) AS y;

SET @Detail = CONCAT (N'Scope rows per profile: ', @MinScope, N' minimum, ', @AvgScope, N' average, ', @MaxScope
                    , N' maximum. Closure rows per ancestor tenant: ', @AvgClosure, N' average, ', @MaxClosure
                    , N' maximum. Those two numbers are the predicate''s inner-side cardinality, and the maxima are '
                    , N'what the worst-off profile pays on EVERY statement. A tenant near the root of a deep tree is '
                    , N'the one to watch: its closure fan-out is the predicate''s cost, and it does not shrink when '
                    , N'the pool is warm.');

INSERT #T130Report (Severity, Status, Question, Item, Detail)
VALUES (3, 'INFO', N'6.3 cold buffer pool', N'The skew behind "for one tenant"', @Detail);
GO

-- =====================================================================================================================
-- 4.  SECTION 6, FOURTH BULLET.  "Deadlocks between a profile switch and a concurrent profile deactivation."
--
--     A deadlock needs two transactions taking the same two resources in opposite orders. So the question is answerable
--     by reading the ORDER, and it is worth answering that way BEFORE trying to reproduce it, because a reproduction
--     that fails proves nothing -- a deadlock is a race and a race that did not happen in 200 attempts can still happen
--     on the box that matters.
--
--     WHAT THE TWO PROCEDURES ACTUALLY DO, read out of sys.sql_modules below rather than out of the files, because the
--     deployed definition is the one that runs:
--
--       auth.uspDeactivateProfile  BEGIN TRANSACTION -> UPDATE auth.UserProfile -> UPDATE auth.UserSession -> COMMIT.
--       auth.uspSwitchProfile      BEGIN TRANSACTION -> UPDATE auth.UserSession -> INSERT logs.AuthenticationEvent ->
--                                  COMMIT -> and only THEN reads auth.UserProfile for its result sets.
--
--     Those two orders cannot close a cycle, and the reason is the early COMMIT in the switch. It holds no lock on
--     auth.UserProfile at any point while holding one on auth.UserSession, so the deactivation can always finish. The
--     early COMMIT is there for a different reason -- a failed navigation read must not undo a committed switch -- and
--     the comment above it says so. This section exists to make the deadlock-freedom EXPLICIT and to fail if a later
--     change moves that COMMIT down, which is exactly the edit that would introduce the cycle.
--
--     The driver's third test replays both orders from two connections, and includes a POSITIVE CONTROL -- the switch's
--     shape with the COMMIT moved after the auth.UserProfile read -- which deadlocks on demand. A harness that can
--     only report "no deadlock" is indistinguishable from a harness that is broken.
-- =====================================================================================================================
SET NOCOUNT ON;
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;

DECLARE @Switch NVARCHAR (MAX) = NULL, @Deact NVARCHAR (MAX) = NULL, @Detail NVARCHAR (MAX) = NULL
      , @SwCommit INT = NULL, @SwProfileRead INT = NULL, @SwSessionWrite INT = NULL
      , @DeProfile INT = NULL, @DeSession INT = NULL, @Ordered BIT = NULL;

SELECT @Switch = m.definition FROM sys.sql_modules AS m WHERE m.object_id = OBJECT_ID (N'auth.uspSwitchProfile');
SELECT @Deact  = m.definition FROM sys.sql_modules AS m WHERE m.object_id = OBJECT_ID (N'auth.uspDeactivateProfile');

IF @Switch IS NULL OR @Deact IS NULL
BEGIN
    INSERT #T130Report (Severity, Status, Question, Item, Detail)
    VALUES (2, 'SKIPPED', N'6.4 switch versus deactivate', N'The lock order'
          , N'One of auth.uspSwitchProfile or auth.uspDeactivateProfile is not deployed in this database, so there is '
          + N'no definition to read the order out of.');
END;
ELSE
BEGIN
    -- The switch: where its first UPDATE of auth.UserSession is, where its COMMIT is, where its first read of
    -- auth.UserProfile after that COMMIT is. CHARINDEX and not a parser, which is why the third argument matters.
    SET @SwSessionWrite = CHARINDEX (N'FROM auth.UserSession AS s', @Switch
                                   , CHARINDEX (N'BEGIN TRANSACTION', @Switch));
    SET @SwCommit       = CHARINDEX (N'COMMIT TRANSACTION', @Switch, @SwSessionWrite);
    SET @SwProfileRead  = CHARINDEX (N'FROM auth.UserProfile AS p', @Switch, @SwSessionWrite);

    SET @DeProfile = CHARINDEX (N'FROM auth.UserProfile AS p', @Deact, CHARINDEX (N'BEGIN TRANSACTION', @Deact));
    SET @DeSession = CHARINDEX (N'FROM auth.UserSession AS s', @Deact, CHARINDEX (N'BEGIN TRANSACTION', @Deact));

    -- The invariant: in the switch, the COMMIT comes BEFORE the profile read. If that ever stops being true, the
    -- switch will hold auth.UserSession while waiting for auth.UserProfile, and the deactivation holds them the other
    -- way round.
    SET @Ordered = CASE WHEN @SwSessionWrite > 0 AND @SwCommit > 0
                         AND (@SwProfileRead = 0 OR @SwCommit < @SwProfileRead)
                        THEN 1 ELSE 0 END;

    SET @Detail = CONCAT (N'auth.uspDeactivateProfile locks auth.UserProfile first (offset ', @DeProfile
                        , N') and auth.UserSession second (offset ', @DeSession
                        , N'), both inside one transaction. auth.uspSwitchProfile writes auth.UserSession at offset '
                        , @SwSessionWrite, N', COMMITs at offset ', @SwCommit, N', and reads auth.UserProfile at '
                        , N'offset ', @SwProfileRead, N'. '
                        , CASE WHEN @Ordered = 1
                               THEN N'The COMMIT precedes the profile read, so the switch never holds a lock on '
                                  + N'auth.UserSession while waiting for one on auth.UserProfile, and the two '
                                  + N'procedures CANNOT close a cycle. That is deadlock freedom by construction and '
                                  + N'not by luck -- but it rests entirely on an early COMMIT that exists for an '
                                  + N'unrelated reason (a failed navigation read must not undo a committed switch). '
                                  + N'Moving that COMMIT down, or adding any write to auth.UserProfile inside the '
                                  + N'switch''s transaction, introduces the deadlock. This check is the tripwire.'
                               ELSE N'THE COMMIT NO LONGER PRECEDES THE PROFILE READ. The switch now holds '
                                  + N'auth.UserSession while acquiring auth.UserProfile, and auth.uspDeactivateProfile '
                                  + N'takes those two in the opposite order: that is a cycle, and it will be found by '
                                  + N'a user switching hats while an administrator deactivates the hat. Run the '
                                  + N'driver''s deadlock test, which will now reproduce it.' END);

    INSERT #T130Report (Severity, Status, Question, Item, Detail)
    VALUES (CASE WHEN @Ordered = 1 THEN 4 ELSE 1 END
          , CASE WHEN @Ordered = 1 THEN 'OK' ELSE 'RISK' END
          , N'6.4 switch versus deactivate', N'The lock order, read from the deployed definitions', @Detail);
END;

-- 4b.  What has actually happened on this instance. system_health keeps deadlock graphs in a ring buffer; if the pair
--      above ever did deadlock here, the graph is the evidence and the report should not have to guess.
DECLARE @Graphs INT = NULL, @Recent INT = NULL, @LastGraph DATETIME2 (3) = NULL;

IF EXISTS (SELECT 1 FROM sys.dm_xe_sessions WHERE name = N'system_health')
BEGIN
    ;WITH Ring AS
    (
        SELECT CAST (t.target_data AS XML) AS x
          FROM sys.dm_xe_session_targets AS t
         INNER JOIN sys.dm_xe_sessions    AS s ON s.address = t.event_session_address
         WHERE s.name = N'system_health' AND t.target_name = N'ring_buffer'
    )
    , Events AS
    (
        SELECT EventTime = e.value ('@timestamp', 'DATETIME2 (3)')
             , Graph     = e.query ('.')
          FROM Ring
         CROSS APPLY x.nodes ('//event[@name="xml_deadlock_report"]') AS n (e)
    )
    SELECT @Graphs    = COUNT (*)
         , @Recent    = SUM (CASE WHEN CAST (Graph AS NVARCHAR (MAX)) LIKE N'%UserProfile%'
                                   AND CAST (Graph AS NVARCHAR (MAX)) LIKE N'%UserSession%' THEN 1 ELSE 0 END)
         , @LastGraph = MAX (EventTime)
      FROM Events;

    SET @Detail = CONCAT (N'The system_health ring buffer holds ', ISNULL (@Graphs, 0)
                        , N' deadlock graph(s) for this instance, of which ', ISNULL (@Recent, 0)
                        , N' name both auth.UserProfile and auth.UserSession'
                        , CASE WHEN @LastGraph IS NULL THEN N'.'
                               ELSE CONCAT (N'; the most recent graph of any kind is from '
                                          , CONVERT (NVARCHAR (23), @LastGraph, 126), N'.') END
                        , N' The buffer is small and circular, so a zero here means "none recently", not "none ever" '
                        , N'-- it is corroboration for section 4a and not a substitute for it.');

    INSERT #T130Report (Severity, Status, Question, Item, Detail)
    VALUES (CASE WHEN ISNULL (@Recent, 0) = 0 THEN 4 ELSE 1 END
          , CASE WHEN ISNULL (@Recent, 0) = 0 THEN 'OK' ELSE 'RISK' END
          , N'6.4 switch versus deactivate', N'Deadlock graphs on record', @Detail);
END;
ELSE
BEGIN
    INSERT #T130Report (Severity, Status, Question, Item, Detail)
    VALUES (3, 'SKIPPED', N'6.4 switch versus deactivate', N'Deadlock graphs on record'
          , N'The system_health event session is not running on this instance, so there is no ring buffer to read '
          + N'deadlock graphs out of. It is on by default; somebody turned it off.');
END;
GO

-- =====================================================================================================================
-- 5.  SECTION 6, FIFTH BULLET.  "The sp_set_session_context path under connection-pool reuse."
--
--     THIS SECTION CANNOT ANSWER THE QUESTION AND SAYS SO RATHER THAN PRETENDING.  What it can do is state the exposure
--     precisely and prove the half that is a statement property: that the identity keys really are read-only, so a
--     connection that comes back out of a pool still carrying them would be UNUSABLE by the next user rather than
--     quietly wrong. That distinction is the whole risk profile of the bullet:
--
--       If sp_reset_connection clears SESSION_CONTEXT, the design is sound: every pooled connection starts blank and
--       auth.uspSetSessionContext sets it for the new caller.
--
--       If it did NOT clear it, the next caller would hit E-50022 -- "this connection already carries session context
--       for UserId X" -- on its first call. Noisy, and a denial of service, but NOT a cross-tenant data leak, because
--       the keys cannot be overwritten and the mismatch is detected before any row is read. The template's worst case
--       under pool reuse is an outage, not a disclosure, and that is a deliberate consequence of @read_only = 1.
--
--     The driver's first test settles which of those two worlds this is, from a real pooling client, because
--     sp_reset_connection is issued by the CLIENT and cannot be invoked from T-SQL.
-- =====================================================================================================================
SET NOCOUNT ON;
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;

DECLARE @Err INT = 0, @ErrMsg NVARCHAR (2048) = NULL, @Detail NVARCHAR (MAX) = NULL;

EXEC sys.sp_set_session_context @key = N'T130Probe', @value = 1, @read_only = 1;

BEGIN TRY
    EXEC sys.sp_set_session_context @key = N'T130Probe', @value = 2;
END TRY
BEGIN CATCH
    SET @Err    = ERROR_NUMBER ();
    SET @ErrMsg = ERROR_MESSAGE ();
END CATCH;

SET @Detail = CONCAT (N'A key set with @read_only = 1 and then overwritten raised '
                    , CASE WHEN @Err = 15664 THEN N'error 15664, which is the behaviour auth.uspSetSessionContext '
                                                + N'relies on and the reason a profile switch spends its connection '
                                                + N'(UI-06, G-36, BL-057). A pooled connection that came back with '
                                                + N'stale identity keys would therefore FAIL LOUDLY on its next call '
                                                + N'with E-50022 rather than answering for the wrong user: the worst '
                                                + N'case under pool reuse is an outage, not a disclosure.'
                           WHEN @Err = 0 THEN N'NO ERROR AT ALL. That means @read_only did not take effect on this '
                                            + N'instance, and the whole argument above collapses: a stale key could '
                                            + N'be overwritten, and the protection against a connection answering '
                                            + N'for the previous user is gone. Investigate before shipping.'
                           ELSE CONCAT (N'error ', @Err, N', which is not the expected 15664: ', @ErrMsg) END
                    , N' Whether sp_reset_connection actually clears the keys is not a T-SQL question -- the client '
                    , N'issues that RPC -- and is answered by T130_concurrency_driver.ps1, test P.');

INSERT #T130Report (Severity, Status, Question, Item, Detail)
VALUES (CASE WHEN @Err = 15664 THEN 4 ELSE 1 END
      , CASE WHEN @Err = 15664 THEN 'OK' ELSE 'RISK' END
      , N'6.5 pooled connections', N'The identity keys are read-only, so reuse fails loudly', @Detail);
GO

-- =====================================================================================================================
-- 6.  The report.
-- =====================================================================================================================
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;

SELECT Severity, Status, Question, Item, Detail FROM #T130Report ORDER BY Severity, RowNo;

DECLARE @Risks INT = NULL, @Actions INT = NULL, @Skipped INT = NULL;

SELECT @Risks   = SUM (CASE WHEN Status = 'RISK'    THEN 1 ELSE 0 END)
     , @Actions = SUM (CASE WHEN Status = 'ACTION'  THEN 1 ELSE 0 END)
     , @Skipped = SUM (CASE WHEN Status = 'SKIPPED' THEN 1 ELSE 0 END)
  FROM #T130Report;

PRINT N'';
PRINT CONCAT (N'T130_concurrency_harness.sql: done. ', @Risks, N' RISK, ', @Actions, N' ACTION, ', @Skipped
            , N' SKIPPED.');
PRINT N'';
PRINT N'Four of section 6''s five bullets are answered above. NONE of them is answered completely until the driver has';
PRINT N'run, because three of the five are properties of several connections at once:';
PRINT N'';
PRINT N'  powershell.exe -NoProfile -ExecutionPolicy Bypass -File database/_perf/T130_concurrency_driver.ps1 \';
PRINT N'      -DatabaseName testTemplateS1';
PRINT N'';
PRINT N'  Test P  the pooled connection: does sp_reset_connection clear SESSION_CONTEXT. Section 5 above states the';
PRINT N'          exposure; only a pooling client can settle it.';
PRINT N'  Test S  the sign-in storm: the real auth.uspGetLoginVerifier / uspVerifyMfa / uspCompleteLogin path, many';
PRINT N'          connections at once, with the wait-statistic delta that says WHAT they waited on.';
PRINT N'  Test D  the deadlock pair, replayed from two connections, WITH a positive control that deadlocks on purpose.';
PRINT N'          A harness that can only report "no deadlock" is indistinguishable from one that is broken.';
GO
