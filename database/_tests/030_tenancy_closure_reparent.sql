/***********************************************************************************************************************
Script:         _tests/030_tenancy_closure_reparent.sql
Purpose:        The Phase 1 exit criterion that matters: "closure is correct after a RE-PARENTING, not only after a
                fresh build -- the case an incremental algorithm gets wrong".  Moves a populated subtree three times,
                verifies the closure after each move against an independent calculation, proves the move is reversible
                to an identical closure, proves a second rebuild writes nothing at all, and proves the rebuild refuses a
                cycle loudly instead of quietly.
Target:         SQL Server 2022 or newer.
Run as:         db_owner in the target database.
Run in:         The target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/_tests/030_tenancy_closure_reparent.sql
Idempotent:     Yes, and unconditionally so -- see "WHY IT RESETS FIRST" below.
Depends on:     database/_tests/020_tenancy_variant_trees.sql, which builds the VARIANT2 tree this file moves a branch
                of.  Run that first; this file refuses to guess.
Implements:     PLAN-AUTH-001 Phase 1 exit criteria.  Task T-023.  DES-AUTH-001 section 5.3.  INV-02.
To retarget:    Pass it per run:  -d <database> -v DbName=<database>.  There is no in-file default.

WHY A RE-PARENTING IS THE ONE CASE WORTH A TEST OF ITS OWN
----------------------------------------------------------
Every closure implementation gets a fresh build right, because a fresh build is a straightforward recursion over parent
edges.  What separates a correct implementation from a plausible one is the MOVE, because a move does not ADD ancestors
to a subtree -- it REPLACES them.  An incremental algorithm that inserts the new ancestor pairs and forgets to remove the
old ones leaves a closure that still says the moved subtree is beneath its former parent.  Nothing complains: the rows
are well-formed, the foreign keys hold, the depths are plausible.  The only symptom is that a scope grant at the old
parent still reaches the moved tenant, which is a silent authorization leak and precisely the failure this design refuses
to accept anywhere.

That is why auth.uspRebuildTenantClosure rebuilds WHOLE rather than incrementally, and this file is the evidence that the
decision was the right one.  Three moves, chosen so that between them they exercise all three MERGE branches:

  Move 1  LMA from AGENCY to WSA.   DEEPENS the subtree. Adds WSA as an ancestor and re-depths the ones it keeps.
                                    Retires nothing: LMA is still under AGENCY, just further down.
                                    -- exercises WHEN NOT MATCHED BY TARGET and WHEN MATCHED (depth change).
  Move 2  LMA from WSA to ROOT.     REPLACES the subtree's ancestors. AGENCY and WSA stop being ancestors of LMA and of
                                    HAZ_WASTE beneath it, so four pairs are retired.
                                    -- exercises WHEN NOT MATCHED BY SOURCE, which is the branch the incremental version
                                       forgets, and it is the whole reason this file exists.
  Move 3  LMA back to AGENCY.       RESTORES. The four retired pairs must come back, and the live closure must be
                                    IDENTICAL to what it was before move 1 -- byte for byte in the columns that describe
                                    shape.
                                    -- exercises WHEN MATCHED against a soft-deleted row, which is a resurrection rather
                                       than an insert. Had the MERGE tried to insert, the primary key would have stopped
                                       it; the failure mode this proves is absent is a duplicate, not an error.

LMA is moved rather than a leaf because a leaf would prove nothing about the subtree: HAZ_WASTE travels with it, and
HAZ_WASTE's ancestor set is the one an incremental algorithm gets wrong two levels away from the row it updated.

WHY IT RESETS FIRST, AND WHY THAT IS NOT DEFENSIVENESS
------------------------------------------------------
Step 1 of the experiment sets LMA's parent back to AGENCY before capturing the baseline.  Not a guard -- a design
decision, and the alternative is worse than it looks.  A test that checks whether the movement is needed and skips it
when the tree is already in the target shape is a test that reports success on a second run WITHOUT PERFORMING THE
MOVEMENT.  It stops being a test of re-parenting and becomes a test of the previous run's leftovers, and nothing in its
output says which of the two happened.  So this file always moves, always three times, and its first act is to make that
possible.

_tests/020_tenancy_variant_trees.sql restates every tenant's parent for the same reason, so the two files may be run in
either order, any number of times.

WHAT THE ASSERTIONS COMPARE, AND WHY NONE OF THE INTERESTING ONES IS A CONSTANT
------------------------------------------------------------------------------
The load-bearing assertion at every stage is  SUM (Depth + 1) over auth.vwTenantHierarchy  =  COUNT (*) over the live
auth.TenantClosure.  The view walks parent edges and knows nothing about the closure; the closure was built by a MERGE
that knows nothing about the view.  A tenant at depth d has exactly d + 1 ancestors including itself, so the two numbers
must agree -- and they agree for a WRONG reason only if both objects are wrong in the same direction, which no single
defect does.  Four live-pair totals ARE stated as constants (27, 29, 25, 27), because they are this file's claim about
what each move should cost and deriving them from the thing under test would assert nothing.

TWO SCOPING RULES, AND BOTH WERE ADDED BECAUSE THIS FILE FAILED WITHOUT THEM (T-120, BL-074)
-------------------------------------------------------------------------------------------
The four constants above are a claim about the NINE tenants 020 declares, and until 2026-09-21 they were compared
against every live pair in the VARIANT2 application.  Those are the same number only on a database where nothing else
has ever added a tenant to that tree -- and _tests/070 adds two, because a variant walked end to end creates an
administration and a programme beneath the root it signs in at.  Run 030 after 070 and all five stages reported
VIOLATED while every independent assertion in the file passed, which is the worst failure a test can produce: a real
report, in the right shape, about nothing.  So 4b now measures only the pairs whose ANCESTOR AND DESCENDANT are both in
@Declared, and 4a keeps the whole tree, because the invariant is about the tree and the constants are about the fixture.

The second rule is the one worth reading, because it is a fact about the DESIGN rather than about the fixtures.
auth.vwTenantHierarchy excludes a soft-deleted tenant AND everything beneath it; auth.uspRebuildTenantClosure walks an
edge list DELIBERATELY NOT filtered on IsDeleted, so that tenant's pairs stay LIVE.  Both are correct and both are
documented -- 095's view header and 125's rebuild header each say why -- which means SUM (Depth + 1) over the view and
COUNT (*) over the live closure DISAGREE, legitimately, by one pair per depth for every soft-deleted tenant.  The
paragraph above says two objects agree for a wrong reason only if both are wrong in the same direction; this is the
third case it did not anticipate, where they disagree for a RIGHT reason.  Every count in this file that is compared
against the view is therefore restricted to descendants the view can see.  _tests/070 creates exactly this state when
it re-runs -- it soft-deletes the organization tenant its previous run approved and approves a fresh one -- so VARIANT3
carried a soft-deleted tenant with three live pairs, and 4j read it as damage the rebuild had done to a tree nobody
touched.

WHAT IT DELIBERATELY DOES NOT TEST
----------------------------------
The REFUSALS in auth.uspUpdateTenant -- 50095 cycle, 50096 cross-application, 50094 root -- are not tested here, because
that procedure demands a session and a permission and cannot be called until Phase 3 (error 2812).  This file writes
auth.Tenant directly as db_owner, which means it can create states the procedure would have refused.  It uses that
deliberately once, in section 5, to make a cycle and prove the REBUILD refuses it -- the last line of defence, below the
procedure's guard, and the only one in force today.  The procedure-level refusals are Phase 3's tests and the task list
says so.
***********************************************************************************************************************/

:on error exit

-- THE TARGET DATABASE IS SUPPLIED ON THE COMMAND LINE AND HAS NO DEFAULT.  There is deliberately no `:setvar DbName`
-- line: measured on sqlcmd 17, a :setvar in the file OVERRIDES -v rather than acting as a fallback for its absence.

SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;
GO


-- *** 0. Assert the target ***
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


-- *** 1. Assert the machinery and the fixture ***
DECLARE @Absent NVARCHAR (2000) = NULL;

SELECT @Absent = STRING_AGG (x.ObjectName, N', ')
  FROM (VALUES (N'auth.Tenant')
             , (N'auth.TenantClosure')
             , (N'auth.vwTenantHierarchy')
             , (N'auth.udfIsTenantUsable')
             , (N'auth.uspRebuildTenantClosure')
             , (N'logs.ExecutionLog')) AS x (ObjectName)
 WHERE OBJECT_ID (x.ObjectName) IS NULL;

IF @Absent IS NOT NULL
BEGIN
    DECLARE @NotInstalled NVARCHAR (2000) =
        N'The tenancy objects this test exercises are not installed. Absent: ' + @Absent
      + N'. Run database/Install-TemplateDatabase.ps1 first. Nothing has been changed.';

    THROW 50000, @NotInstalled, 1;
END
GO

-- The fixture, not merely the schema.  This file MOVES a named branch of a named tree; without it there is nothing to
-- move, and a test that silently does nothing is worse than one that refuses.
IF NOT EXISTS (SELECT 1
                 FROM auth.Tenant      AS t
                 JOIN auth.Application AS a ON a.ApplicationId = t.ApplicationId
                WHERE a.ApplicationCode = N'VARIANT2'
                  AND t.TenantCode      = N'HAZ_WASTE'
                  AND t.IsDeleted       = 0)
BEGIN
    DECLARE @NoFixture NVARCHAR (2000) =
        N'The VARIANT2 tree is not built, so there is no populated subtree to re-parent. Run '
      + N'database/_tests/020_tenancy_variant_trees.sql first. Nothing has been changed.';

    THROW 50000, @NoFixture, 1;
END
GO


-- *** 2. The experiment, as data ***
-- Sections 2 to 4 are ONE BATCH: the snapshots live in table variables, which do not survive a GO, and the whole point
-- is to compare states captured at different moments in the same run.
DECLARE @AppId     INT = NULL
      , @RootId    INT = NULL
      , @AgencyId  INT = NULL
      , @WsaId     INT = NULL
      , @LmaId     INT = NULL
      , @HazId     INT = NULL;

SELECT @AppId = a.ApplicationId
  FROM auth.Application AS a
 WHERE a.ApplicationCode = N'VARIANT2'
   AND a.IsDeleted       = 0;

-- Five scalar subqueries rather than one pass with MAX (CASE ...): the aggregate form raises "Null value is eliminated by
-- an aggregate" for every code it does not find, and a warning in a test transcript reads as a finding.  A scalar
-- subquery simply yields NULL, which the check below is looking for anyway.
SELECT @RootId   = (SELECT t.TenantId FROM auth.Tenant AS t WHERE t.ApplicationId = @AppId AND t.TenantCode = N'ROOT'      AND t.IsDeleted = 0)
     , @AgencyId = (SELECT t.TenantId FROM auth.Tenant AS t WHERE t.ApplicationId = @AppId AND t.TenantCode = N'AGENCY'    AND t.IsDeleted = 0)
     , @WsaId    = (SELECT t.TenantId FROM auth.Tenant AS t WHERE t.ApplicationId = @AppId AND t.TenantCode = N'WSA'       AND t.IsDeleted = 0)
     , @LmaId    = (SELECT t.TenantId FROM auth.Tenant AS t WHERE t.ApplicationId = @AppId AND t.TenantCode = N'LMA'       AND t.IsDeleted = 0)
     , @HazId    = (SELECT t.TenantId FROM auth.Tenant AS t WHERE t.ApplicationId = @AppId AND t.TenantCode = N'HAZ_WASTE' AND t.IsDeleted = 0);

IF @RootId IS NULL OR @AgencyId IS NULL OR @WsaId IS NULL OR @LmaId IS NULL OR @HazId IS NULL
BEGIN
    DECLARE @Unresolved NVARCHAR (2000) =
        N'One of the VARIANT2 tenants this test moves could not be resolved (ROOT, AGENCY, WSA, LMA, HAZ_WASTE). '
      + N'Re-run database/_tests/020_tenancy_variant_trees.sql. Nothing has been changed.';

    THROW 50000, @Unresolved, 1;
END;

-- THE NINE TENANTS 020 DECLARES, and the only ones the four pair-count constants in section 2 are a claim about.  Stated
-- as codes rather than resolved once into a list of ids, because the point is to name the fixture: a tenant another test
-- adds to this tree is not in this list, and must not move a count this file asserts.  See the header, T-120.
DECLARE @Declared TABLE (TenantId INT NOT NULL PRIMARY KEY, TenantCode NVARCHAR (50) NOT NULL UNIQUE);

INSERT @Declared (TenantId, TenantCode)
SELECT t.TenantId, t.TenantCode
  FROM auth.Tenant AS t
  JOIN (VALUES (N'ROOT'), (N'AGENCY'), (N'ARA'), (N'HAZ_WASTE'), (N'IT')
             , (N'LMA'),  (N'RAD_HEALTH'), (N'WSA'), (N'WW_PERMITS')) AS d (TenantCode)
    ON d.TenantCode = t.TenantCode
 WHERE t.ApplicationId = @AppId
   AND t.IsDeleted     = 0;

-- Nine or nothing.  A list that silently resolved eight would quietly lower every constant below it by the pairs of the
-- one it missed, and the file would then pass while measuring a different tree.
IF (SELECT COUNT (*) FROM @Declared) <> 9
BEGIN
    DECLARE @ShortList NVARCHAR (2000) =
        N'Expected the nine VARIANT2 tenants 020 declares and resolved '
      + CAST ((SELECT COUNT (*) FROM @Declared) AS NVARCHAR (10))
      + N'. Re-run database/_tests/020_tenancy_variant_trees.sql. Nothing has been changed.';

    THROW 50000, @ShortList, 1;
END;

-- Every ExecutionLog row above this number belongs to this run.  Captured before anything is called, so section 5 can
-- assert on the failure the cycle probe causes without depending on what else is in the table.
DECLARE @BaselineLogId BIGINT = (SELECT COALESCE (MAX (ExecutionLogId), 0) FROM logs.ExecutionLog);

DECLARE @Actor NVARCHAR (255) = CONCAT (N'fixture@030_tenancy_closure_reparent#', ORIGINAL_LOGIN ());

-- THE EXPERIMENT.  Written as a table so the five stages read in one place and the capture code below is written once
-- rather than five times.  NewParentCode NULL means "move nothing, rebuild again", which is the idempotence probe.
DECLARE @Plan TABLE
(
    Step              INT           NOT NULL PRIMARY KEY,
    Label             NVARCHAR (30) NOT NULL UNIQUE,
    NewParentCode     NVARCHAR (50)     NULL,
    ExpectedLivePairs INT           NOT NULL,
    Narrative         NVARCHAR (400) NOT NULL
);

INSERT @Plan (Step, Label, NewParentCode, ExpectedLivePairs, Narrative)
VALUES (1, N'Baseline',  N'AGENCY', 27, N'Reset: LMA under AGENCY, which is the shape 020 declares. Always performed, never skipped -- a test that checks whether it needs to move is a test that can report success without moving.')
     , (2, N'Move1',     N'WSA',    29, N'LMA (with HAZ_WASTE beneath it) moved one level deeper, under WSA. Adds WSA as an ancestor of both and re-depths the ancestors they keep. Retires nothing.')
     , (3, N'Move2',     N'ROOT',   25, N'LMA moved to the root. AGENCY and WSA stop being ancestors of LMA AND of HAZ_WASTE two levels away: four pairs retired. THE CASE AN INCREMENTAL ALGORITHM GETS WRONG.')
     , (4, N'Restored',  N'AGENCY', 27, N'LMA moved back. The four retired pairs must be resurrected, not re-inserted, and the live closure must be identical to Baseline.')
     , (5, N'ReRebuild', NULL,      27, N'Nothing moved; the rebuild called again. Must write nothing at all -- not merely produce the same answer.');

-- Per-stage summary.  SumDepthPlus1 comes from auth.vwTenantHierarchy, which walks parent edges; LivePairs comes from
-- auth.TenantClosure, which the MERGE built.  Two objects, two calculations, and the assertions compare them.
-- DeclaredPairs is the same count narrowed to the nine tenants 020 declares, and it exists so the four constants in
-- section 2 keep meaning what they meant on the day they were written.  See the header's two scoping rules.
DECLARE @Stage TABLE
(
    Step          INT            NOT NULL PRIMARY KEY,
    Label         NVARCHAR (30)  NOT NULL,
    TenantsInView INT            NOT NULL,
    SumDepthPlus1 INT            NOT NULL,
    LivePairs     INT            NOT NULL,
    DeclaredPairs INT            NOT NULL,
    RetiredPairs  INT            NOT NULL,
    LmaPath       NVARCHAR (4000)    NULL,
    HazPath       NVARCHAR (4000)    NULL
);

-- Every closure row for VARIANT2, live and retired, at each stage.  This is what the round-trip and idempotence
-- assertions compare set against set.
DECLARE @Snapshot TABLE
(
    Label                NVARCHAR (30) NOT NULL,
    AncestorTenantId     INT           NOT NULL,
    DescendantTenantId   INT           NOT NULL,
    Depth                INT           NOT NULL,
    IsDeleted            BIT           NOT NULL,
    auditModifiedDateUtc DATETIME2 (3) NOT NULL,
    PRIMARY KEY (Label, AncestorTenantId, DescendantTenantId)
);


-- *** 3. Run it ***
DECLARE @Step        INT           = 1
      , @MaxStep     INT           = (SELECT MAX (Step) FROM @Plan)
      , @Label       NVARCHAR (30)
      , @ParentCode  NVARCHAR (50)
      , @NewParentId INT;

WHILE @Step <= @MaxStep
BEGIN
    SELECT @Label      = p.Label
         , @ParentCode = p.NewParentCode
      FROM @Plan AS p
     WHERE p.Step = @Step;

    SET @NewParentId = NULL;

    IF @ParentCode IS NOT NULL
    BEGIN
        SELECT @NewParentId = t.TenantId
          FROM auth.Tenant AS t
         WHERE t.ApplicationId = @AppId
           AND t.TenantCode    = @ParentCode
           AND t.IsDeleted     = 0;

        -- The move itself, written directly because auth.uspUpdateTenant cannot be called until Phase 3. Guarded with
        -- IS DISTINCT FROM so a step that is already in position does not churn the audit columns -- which matters,
        -- because the idempotence assertion in step 5 compares auditModifiedDateUtc.
        UPDATE auth.Tenant
           SET ParentTenantId  = @NewParentId
             , auditModifiedBy = @Actor
         WHERE TenantId        = @LmaId
           AND ParentTenantId IS DISTINCT FROM @NewParentId;
    END;

    -- Called, never reimplemented. The object under test.
    EXEC auth.uspRebuildTenantClosure;

    INSERT @Stage (Step, Label, TenantsInView, SumDepthPlus1, LivePairs, DeclaredPairs, RetiredPairs, LmaPath, HazPath)
    SELECT @Step
         , @Label
         , (SELECT COUNT (*)                        FROM auth.vwTenantHierarchy WHERE ApplicationId = @AppId)
         , (SELECT COALESCE (SUM (Depth + 1), 0)    FROM auth.vwTenantHierarchy WHERE ApplicationId = @AppId)
         -- Restricted to descendants the view can see, which is the header's second scoping rule.  A descendant in the
         -- view has its whole ancestor chain in the view, so this counts the same pairs SUM (Depth + 1) does -- and it
         -- leaves out the live pairs a soft-deleted tenant deliberately keeps.
         , (SELECT COUNT (*)
              FROM auth.TenantClosure AS c
              JOIN auth.Tenant        AS d ON d.TenantId = c.DescendantTenantId
             WHERE d.ApplicationId = @AppId AND c.IsDeleted = 0
               AND EXISTS (SELECT 1 FROM auth.vwTenantHierarchy AS v WHERE v.TenantId = c.DescendantTenantId))
         -- Both ends in @Declared.  A pair from a declared tenant to one another test added is not this file's business.
         , (SELECT COUNT (*)
              FROM auth.TenantClosure AS c
             WHERE c.IsDeleted = 0
               AND EXISTS (SELECT 1 FROM @Declared AS a WHERE a.TenantId = c.AncestorTenantId)
               AND EXISTS (SELECT 1 FROM @Declared AS x WHERE x.TenantId = c.DescendantTenantId))
         , (SELECT COUNT (*)
              FROM auth.TenantClosure AS c
              JOIN auth.Tenant        AS d ON d.TenantId = c.DescendantTenantId
             WHERE d.ApplicationId = @AppId AND c.IsDeleted = 1)
         , (SELECT TenantPath FROM auth.vwTenantHierarchy WHERE TenantId = @LmaId)
         , (SELECT TenantPath FROM auth.vwTenantHierarchy WHERE TenantId = @HazId);

    INSERT @Snapshot (Label, AncestorTenantId, DescendantTenantId, Depth, IsDeleted, auditModifiedDateUtc)
    SELECT @Label, c.AncestorTenantId, c.DescendantTenantId, c.Depth, c.IsDeleted, c.auditModifiedDateUtc
      FROM auth.TenantClosure AS c
      JOIN auth.Tenant        AS d ON d.TenantId = c.DescendantTenantId
     WHERE d.ApplicationId = @AppId;

    SET @Step += 1;
END;


-- *** 4. Assert ***
DECLARE @Report TABLE
(
    RowNo    INT IDENTITY (1, 1) PRIMARY KEY,
    Severity INT             NOT NULL,
    Status   VARCHAR (10)    NOT NULL,
    Item     NVARCHAR (200)  NOT NULL,
    Detail   NVARCHAR (1000)     NULL
);

-- 4a. THE INVARIANT, AT EVERY STAGE INCLUDING THE INTERMEDIATE ONES.  A tenant at depth d has d + 1 ancestors including
-- itself, so the hierarchy's SUM (Depth + 1) and the closure's live row count must agree. The mid-movement stages matter
-- as much as the final one: a closure that is right at the start and right at the end and wrong in between is a closure
-- that is wrong whenever somebody is actually using the application.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN s.SumDepthPlus1 = s.LivePairs THEN 4 ELSE 1 END
     , CASE WHEN s.SumDepthPlus1 = s.LivePairs THEN 'OK' ELSE 'VIOLATED' END
     , CONCAT (N'Stage ', s.Step, N' ', s.Label, N': closure agrees with the hierarchy')
     , CONCAT (N'SUM (Depth + 1) over auth.vwTenantHierarchy = ', s.SumDepthPlus1
             , N'; live rows in auth.TenantClosure = ', s.LivePairs
             , N'. ', s.TenantsInView, N' tenant(s) in view, ', s.RetiredPairs, N' pair(s) retired so far. LMA is at '
             , s.LmaPath, N' and HAZ_WASTE at ', s.HazPath, N'.')
  FROM @Stage AS s;

-- 4b. The cost of each move, against what this file claims it should be.  Catches a rebuild that produces a
-- SELF-CONSISTENT but wrong closure -- 4a would pass if both objects agreed on a tree that was not the one asked for.
-- Measured over @Declared and NOT over the application, for the reason the header gives at length: the constants are a
-- claim about the fixture 020 builds, and another test's tenants in the same tree are not a defect in this one.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN s.DeclaredPairs = p.ExpectedLivePairs THEN 4 ELSE 1 END
     , CASE WHEN s.DeclaredPairs = p.ExpectedLivePairs THEN 'OK' ELSE 'VIOLATED' END
     , CONCAT (N'Stage ', s.Step, N' ', s.Label, N': expected pair count')
     , CONCAT (s.DeclaredPairs, N' live pair(s) among the nine declared tenants, ', p.ExpectedLivePairs
             , N' expected; ', s.LivePairs, N' live pair(s) in the whole VARIANT2 tree, which 4a checks instead. '
             , p.Narrative)
  FROM @Stage AS s
  JOIN @Plan  AS p ON p.Step = s.Step;

-- 4c. Move 1 added WSA as an ancestor of BOTH the moved tenant and the child that travelled with it.  The child is the
-- interesting half: nothing wrote to HAZ_WASTE, and its ancestor set changed.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.WsaOverLma = 1 AND x.WsaOverHaz = 2 AND x.AgencyOverLma = 2 AND x.RootOverHaz = 4 THEN 4 ELSE 1 END
     , CASE WHEN x.WsaOverLma = 1 AND x.WsaOverHaz = 2 AND x.AgencyOverLma = 2 AND x.RootOverHaz = 4 THEN 'OK' ELSE 'VIOLATED' END
     , N'Move 1: the subtree deepened and the child followed'
     , CONCAT (N'Depths after moving LMA under WSA -- (WSA,LMA)=', x.WsaOverLma, N' expected 1; (WSA,HAZ_WASTE)='
             , x.WsaOverHaz, N' expected 2; (AGENCY,LMA)=', x.AgencyOverLma, N' expected 2 (was 1); (ROOT,HAZ_WASTE)='
             , x.RootOverHaz, N' expected 4 (was 3). NULL means the pair is absent or retired. Nothing wrote to '
             , N'HAZ_WASTE, and its ancestor set changed anyway -- that is what a closure is for.')
  -- Scalar subqueries, so an absent pair yields NULL without raising "Null value is eliminated by an aggregate". NULL is
  -- a meaningful answer here -- it is what a missing or retired pair looks like -- and each comparison rejects it.
  FROM (SELECT WsaOverLma    = (SELECT s.Depth FROM @Snapshot AS s WHERE s.Label = N'Move1' AND s.IsDeleted = 0 AND s.AncestorTenantId = @WsaId    AND s.DescendantTenantId = @LmaId)
             , WsaOverHaz    = (SELECT s.Depth FROM @Snapshot AS s WHERE s.Label = N'Move1' AND s.IsDeleted = 0 AND s.AncestorTenantId = @WsaId    AND s.DescendantTenantId = @HazId)
             , AgencyOverLma = (SELECT s.Depth FROM @Snapshot AS s WHERE s.Label = N'Move1' AND s.IsDeleted = 0 AND s.AncestorTenantId = @AgencyId AND s.DescendantTenantId = @LmaId)
             , RootOverHaz   = (SELECT s.Depth FROM @Snapshot AS s WHERE s.Label = N'Move1' AND s.IsDeleted = 0 AND s.AncestorTenantId = @RootId   AND s.DescendantTenantId = @HazId)) AS x;

-- 4d. THE ASSERTION THE INCREMENTAL VERSION FAILS.  After move 2 the old ancestors must no longer be live for either
-- tenant. If (AGENCY, HAZ_WASTE) were still live, a scope grant at AGENCY would still reach a program that is no longer
-- anywhere beneath it -- well-formed rows, valid foreign keys, plausible depths, and a silent authorization leak.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.StaleLive = 0 THEN 4 ELSE 1 END
     , CASE WHEN x.StaleLive = 0 THEN 'OK' ELSE 'VIOLATED' END
     , N'Move 2: the old ancestors were REMOVED, not merely supplemented'
     , CONCAT (x.StaleLive, N' of the 4 replaced pairs -- (AGENCY,LMA), (AGENCY,HAZ_WASTE), (WSA,LMA), (WSA,HAZ_WASTE) '
             , N'-- are still LIVE after LMA moved to the root. Anything but 0 is the incremental-algorithm defect: a '
             , N'scope grant at AGENCY would still reach a program that is no longer beneath it, with no symptom '
             , N'anywhere but in an authorization decision.')
  FROM (SELECT StaleLive = COUNT (*)
          FROM @Snapshot AS s
         WHERE s.Label     = N'Move2'
           AND s.IsDeleted = 0
           AND s.AncestorTenantId   IN (@AgencyId, @WsaId)
           AND s.DescendantTenantId IN (@LmaId, @HazId)) AS x;

-- 4e. Retired, not removed.  The four pairs must still be present with IsDeleted = 1, which is what makes the movement
-- auditable -- the closure keeps a record of the shape the tree used to have.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Retired = 4 THEN 4 ELSE 1 END
     , CASE WHEN x.Retired = 4 THEN 'OK' ELSE 'VIOLATED' END
     , N'Move 2: the replaced pairs were SOFT-deleted and kept'
     , CONCAT (x.Retired, N' of 4 replaced pairs carry IsDeleted = 1 after the move. Conventions non-negotiable 3: '
             , N'auth.uspRebuildTenantClosure has no hard delete, so a re-parenting leaves the old shape on record '
             , N'rather than erasing it. A count below 4 means rows went missing.')
  FROM (SELECT Retired = COUNT (*)
          FROM @Snapshot AS s
         WHERE s.Label     = N'Move2'
           AND s.IsDeleted = 1
           AND s.AncestorTenantId   IN (@AgencyId, @WsaId)
           AND s.DescendantTenantId IN (@LmaId, @HazId)) AS x;

-- 4f. Also after move 2: the new ancestors are right.  LMA is a child of the root, HAZ_WASTE is a grandchild, and
-- neither is any deeper than that.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.LmaAncestors = 2 AND x.HazAncestors = 3 THEN 4 ELSE 1 END
     , CASE WHEN x.LmaAncestors = 2 AND x.HazAncestors = 3 THEN 'OK' ELSE 'VIOLATED' END
     , N'Move 2: the new ancestor sets are complete and no larger'
     , CONCAT (N'LMA has ', x.LmaAncestors, N' live ancestor pair(s), 2 expected (itself and ROOT); HAZ_WASTE has '
             , x.HazAncestors, N', 3 expected (itself, LMA, ROOT). Too many means the old pairs are still there; too '
             , N'few means an ancestor was lost and a legitimate scope grant would stop reaching the tenant.')
  FROM (SELECT LmaAncestors = SUM (CASE WHEN s.DescendantTenantId = @LmaId THEN 1 ELSE 0 END)
             , HazAncestors = SUM (CASE WHEN s.DescendantTenantId = @HazId THEN 1 ELSE 0 END)
          FROM @Snapshot AS s
         WHERE s.Label     = N'Move2'
           AND s.IsDeleted = 0) AS x;

-- 4g. THE HEADLINE ASSERTION: the move is reversible to an IDENTICAL closure.  Set difference in both directions over
-- the columns that describe shape, so a missing pair, an extra pair and a wrong depth are all caught and no count can
-- mask any of them. An incremental implementation fails this even when its totals agree.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Differences = 0 THEN 4 ELSE 1 END
     , CASE WHEN x.Differences = 0 THEN 'OK' ELSE 'VIOLATED' END
     , N'Round trip: the restored closure is identical to the baseline'
     , CONCAT (x.Differences, N' row(s) differ between the live closure before move 1 and after move 3, compared on '
             , N'(ancestor, descendant, depth) in both directions. 0 means three re-parentings and their inverse left '
             , N'the closure exactly as it was. auditModifiedDateUtc is deliberately NOT compared: those rows were '
             , N'genuinely rewritten, and the audit trail is supposed to show it.')
  FROM (SELECT Differences =
               (SELECT COUNT (*) FROM
                    (SELECT AncestorTenantId, DescendantTenantId, Depth FROM @Snapshot WHERE Label = N'Baseline' AND IsDeleted = 0
                     EXCEPT
                     SELECT AncestorTenantId, DescendantTenantId, Depth FROM @Snapshot WHERE Label = N'Restored' AND IsDeleted = 0) AS a)
             + (SELECT COUNT (*) FROM
                    (SELECT AncestorTenantId, DescendantTenantId, Depth FROM @Snapshot WHERE Label = N'Restored' AND IsDeleted = 0
                     EXCEPT
                     SELECT AncestorTenantId, DescendantTenantId, Depth FROM @Snapshot WHERE Label = N'Baseline' AND IsDeleted = 0) AS b)) AS x;

-- 4h. Resurrection, not duplication.  (AGENCY, LMA) was retired by move 2 and must be live again after move 3 -- and
-- there must be exactly ONE row for the pair, because the MERGE's MATCHED branch updated the existing row rather than
-- inserting beside it. Had it tried to insert, PK_auth_TenantClosure would have raised 2627; what this rules out is the
-- version where a hard delete preceded the insert and the audit trail was lost.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Rows = 1 AND x.LiveAtDepthOne = 1 THEN 4 ELSE 1 END
     , CASE WHEN x.Rows = 1 AND x.LiveAtDepthOne = 1 THEN 'OK' ELSE 'VIOLATED' END
     , N'Restore: the retired pair was resurrected in place'
     , CONCAT (x.Rows, N' row(s) for (AGENCY, LMA) after the restore, 1 expected, of which ', x.LiveAtDepthOne
             , N' live at depth 1, 1 expected. The pair was soft-deleted by move 2 and undeleted by move 3 -- the same '
             , N'row throughout, which is what keeps the movement on record.')
  FROM (SELECT Rows           = COUNT (*)
             , LiveAtDepthOne = SUM (CASE WHEN s.IsDeleted = 0 AND s.Depth = 1 THEN 1 ELSE 0 END)
          FROM @Snapshot AS s
         WHERE s.Label = N'Restored'
           AND s.AncestorTenantId   = @AgencyId
           AND s.DescendantTenantId = @LmaId) AS x;

-- 4i. The second rebuild wrote NOTHING, which is stronger than "produced the same answer".  auditModifiedDateUtc is
-- included in the comparison, so a MERGE that updated every row to the values it already held would be caught -- and
-- that version is not harmless: it rewrites the audit trail of every pair on every call and makes auditModifiedBy
-- useless for finding out who last moved a tenant.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Differences = 0 THEN 4 ELSE 1 END
     , CASE WHEN x.Differences = 0 THEN 'OK' ELSE 'VIOLATED' END
     , N'A second rebuild changes nothing at all'
     , CONCAT (x.Differences, N' row(s) differ between the closure after move 3 and after an immediate second rebuild, '
             , N'compared on (ancestor, descendant, depth, IsDeleted, auditModifiedDateUtc). 0 means the MERGE touched '
             , N'no row -- not merely that it arrived at the same answer. A rebuild that rewrote every row to the value '
             , N'it already held would pass a count check and destroy the audit trail.')
  FROM (SELECT Differences =
               (SELECT COUNT (*) FROM
                    (SELECT AncestorTenantId, DescendantTenantId, Depth, IsDeleted, auditModifiedDateUtc FROM @Snapshot WHERE Label = N'Restored'
                     EXCEPT
                     SELECT AncestorTenantId, DescendantTenantId, Depth, IsDeleted, auditModifiedDateUtc FROM @Snapshot WHERE Label = N'ReRebuild') AS a)
             + (SELECT COUNT (*) FROM
                    (SELECT AncestorTenantId, DescendantTenantId, Depth, IsDeleted, auditModifiedDateUtc FROM @Snapshot WHERE Label = N'ReRebuild'
                     EXCEPT
                     SELECT AncestorTenantId, DescendantTenantId, Depth, IsDeleted, auditModifiedDateUtc FROM @Snapshot WHERE Label = N'Restored') AS b)) AS x;

-- 4j. The neighbours.  The rebuild is whole-table and parameterless, so a defect in it could damage VARIANT1 or VARIANT3
-- while VARIANT2's own assertions all passed.  Checked with the same independent calculation, and additionally for
-- spurious retirement: nothing in those two trees was ever moved, so no pair in them has any business being retired.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.SumDepthPlus1 = x.LivePairs AND x.RetiredPairs = 0 THEN 4 ELSE 1 END
     , CASE WHEN x.SumDepthPlus1 = x.LivePairs AND x.RetiredPairs = 0 THEN 'OK' ELSE 'VIOLATED' END
     , N'Untouched applications: ' + a.ApplicationCode
     , CONCAT (N'SUM (Depth + 1) = ', x.SumDepthPlus1, N', live pairs = ', x.LivePairs, N', retired pairs = '
             , x.RetiredPairs, N'. Nothing in this tree was moved, so retired must be 0. The rebuild is whole-table and '
             , N'parameterless, which is exactly why a test that only checked the tree it moved would miss this. Both '
             , N'pair counts are restricted to descendants auth.vwTenantHierarchy can see: a soft-deleted tenant keeps '
             , N'its live pairs on purpose, and counting them here would report the design as damage.')
  FROM auth.Application AS a
 CROSS APPLY (SELECT SumDepthPlus1 = (SELECT COALESCE (SUM (Depth + 1), 0) FROM auth.vwTenantHierarchy WHERE ApplicationId = a.ApplicationId)
                   , LivePairs     = (SELECT COUNT (*) FROM auth.TenantClosure AS c JOIN auth.Tenant AS d ON d.TenantId = c.DescendantTenantId
                                       WHERE d.ApplicationId = a.ApplicationId AND c.IsDeleted = 0
                                         AND EXISTS (SELECT 1 FROM auth.vwTenantHierarchy AS v WHERE v.TenantId = c.DescendantTenantId))
                   , RetiredPairs  = (SELECT COUNT (*) FROM auth.TenantClosure AS c JOIN auth.Tenant AS d ON d.TenantId = c.DescendantTenantId
                                       WHERE d.ApplicationId = a.ApplicationId AND c.IsDeleted = 1
                                         AND EXISTS (SELECT 1 FROM auth.vwTenantHierarchy AS v WHERE v.TenantId = c.DescendantTenantId))) AS x
 WHERE a.ApplicationCode IN (N'VARIANT1', N'VARIANT3')
   AND a.IsDeleted = 0;

-- 4k. Usability survived the movement.  The closure is what auth.udfIsTenantUsable reads, so a closure that lost a
-- depth-0 self row during a rebuild would make a tenant unusable and every sign-in at it fail with 50021 -- a whole
-- branch of an application locked out by a tenant move somewhere else.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Unusable = 0 THEN 4 ELSE 1 END
     , CASE WHEN x.Unusable = 0 THEN 'OK' ELSE 'VIOLATED' END
     , N'Every live tenant is still usable after three movements'
     , CONCAT (x.Unusable, N' of ', x.Total, N' tenant(s) read as unusable. The population is every tenant '
             , N'auth.vwTenantHierarchy can see whose own IsActive is 1 and none of whose ancestors is inactive, so '
             , N'anything but 0 means a rebuild dropped a depth-0 self row and locked those tenants out with 50021. '
             , N'A tenant deliberately disabled by another test -- 080 keeps one, to probe 50021 -- is legitimately '
             , N'unusable and is not evidence of anything, which is why the population is not simply IsDeleted = 0.')
  -- The view defines the population and auth.udfIsTenantUsable, which reads the closure, delivers the verdict: still two
  -- independent objects, which is the property this assertion depends on.
  FROM (SELECT Total    = COUNT (*)
             , Unusable = SUM (CASE WHEN auth.udfIsTenantUsable (v.TenantId) = 0 THEN 1 ELSE 0 END)
          FROM auth.vwTenantHierarchy AS v
         WHERE v.IsActive            = 1
           AND v.AnyAncestorInactive = 0) AS x;

SELECT Severity, Status, Item, Detail
  FROM @Report
 ORDER BY Severity, RowNo;

IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
BEGIN
    DECLARE @Failed NVARCHAR (2000) =
        N'Re-parenting test FAILED. Read the report above: a VIOLATED row means the closure is wrong after a movement, '
      + N'which is the Phase 1 exit criterion. The tree has been left in its restored shape.';

    THROW 50000, @Failed, 1;
END;

PRINT N'Re-parenting: three movements, closure correct after each, round trip identical, second rebuild wrote nothing.';
GO


-- *** 5. The cycle, and the last line of defence ***
-- auth.uspUpdateTenant refuses a cycle with 50095, and cannot be called until Phase 3.  Below it there is exactly one
-- guard in force today: the recursive CTE inside auth.uspRebuildTenantClosure runs under OPTION (MAXRECURSION 100) and
-- raises 530 when it does not terminate.  That is a deliberate choice of failure mode -- MAXRECURSION 0 would let the
-- rebuild run until it exhausted tempdb, and a cycle is a data-entry accident, not a deep hierarchy.
--
-- This section MAKES a cycle by writing auth.Tenant directly -- which is the one thing this file does that no procedure
-- would permit -- confirms the rebuild refuses it, and puts the tree back.  CK_auth_Tenant_NotOwnParent stops only the
-- one-node case; a two-node cycle is not declaratively preventable, so it has to be tested.
DECLARE @AppId  INT = (SELECT ApplicationId FROM auth.Application WHERE ApplicationCode = N'VARIANT2' AND IsDeleted = 0);

DECLARE @LmaId    INT = (SELECT TenantId FROM auth.Tenant WHERE ApplicationId = @AppId AND TenantCode = N'LMA'       AND IsDeleted = 0)
      , @HazId    INT = (SELECT TenantId FROM auth.Tenant WHERE ApplicationId = @AppId AND TenantCode = N'HAZ_WASTE' AND IsDeleted = 0)
      , @AgencyId INT = (SELECT TenantId FROM auth.Tenant WHERE ApplicationId = @AppId AND TenantCode = N'AGENCY'    AND IsDeleted = 0);

DECLARE @Actor         NVARCHAR (255) = CONCAT (N'fixture@030_tenancy_closure_reparent#', ORIGINAL_LOGIN ())
      , @BaselineLogId BIGINT         = (SELECT COALESCE (MAX (ExecutionLogId), 0) FROM logs.ExecutionLog)
      , @PairsBefore   INT            = NULL
      , @PairsAfter    INT            = NULL
      , @CycleError    INT            = NULL
      , @LoggedError   INT            = NULL
      , @LoggedReCreated BIT          = NULL;

SELECT @PairsBefore = COUNT (*)
  FROM auth.TenantClosure AS c
  JOIN auth.Tenant        AS d ON d.TenantId = c.DescendantTenantId
 WHERE d.ApplicationId = @AppId
   AND c.IsDeleted     = 0;

-- LMA's child becomes LMA's parent.  HAZ_WASTE's parent is already LMA, so one write closes the loop, and the pair is
-- now unreachable from the root -- which the rebuild does not care about, because it anchors on every tenant.
UPDATE auth.Tenant
   SET ParentTenantId  = @HazId
     , auditModifiedBy = @Actor
 WHERE TenantId = @LmaId;

BEGIN TRY
    EXEC auth.uspRebuildTenantClosure;
END TRY
BEGIN CATCH
    SET @CycleError = ERROR_NUMBER ();
    -- No rollback: the procedure owns its transaction and rolled it back itself. XACT_STATE () is 0 here.
END CATCH;

-- Put it back BEFORE asserting, so a failed assertion still leaves a usable tree.  A test that abandons the database in
-- a broken state on failure is a test people stop running.
UPDATE auth.Tenant
   SET ParentTenantId  = @AgencyId
     , auditModifiedBy = @Actor
 WHERE TenantId = @LmaId;

EXEC auth.uspRebuildTenantClosure;

SELECT @PairsAfter = COUNT (*)
  FROM auth.TenantClosure AS c
  JOIN auth.Tenant        AS d ON d.TenantId = c.DescendantTenantId
 WHERE d.ApplicationId = @AppId
   AND c.IsDeleted     = 0;

-- Rule 8, end to end, on a real failure rather than a probe's artificial one: the rebuild's CATCH must have recorded
-- what happened.  Its start row was opened in autocommit BEFORE the transaction, so the procedure's own ROLLBACK could
-- not reach it, the CATCH found it present, and ReCreatedAfterRollback stays 0 -- path 2 of the three in
-- _tests/010_phase0_instrumentation.sql, arrived at from the opposite direction.
SELECT TOP (1) @LoggedError = l.ErrorNumber
             , @LoggedReCreated = l.ReCreatedAfterRollback
  FROM logs.ExecutionLog AS l
 WHERE l.ExecutionLogId > @BaselineLogId
   AND l.ProcedureName  = N'[auth].[uspRebuildTenantClosure]'
   AND l.Successful     = 0
 ORDER BY l.ExecutionLogId DESC;

DECLARE @CycleReport TABLE
(
    RowNo    INT IDENTITY (1, 1) PRIMARY KEY,
    Severity INT             NOT NULL,
    Status   VARCHAR (10)    NOT NULL,
    Item     NVARCHAR (200)  NOT NULL,
    Detail   NVARCHAR (1000)     NULL
);

INSERT @CycleReport (Severity, Status, Item, Detail)
VALUES
  (CASE WHEN @CycleError = 530 THEN 4 ELSE 1 END
 , CASE WHEN @CycleError = 530 THEN 'OK' ELSE 'VIOLATED' END
 , N'A cycle makes the rebuild fail loudly'
 , CONCAT (N'auth.uspRebuildTenantClosure raised error ', COALESCE (CAST (@CycleError AS NVARCHAR (11)), N'(none)')
         , N' on a two-node cycle; 530 expected -- "maximum recursion 100 has been exhausted". NULL means it SUCCEEDED, '
         , N'which would mean the MERGE wrote a closure for a tree that has no valid closure. OPTION (MAXRECURSION 100) '
         , N'is what makes this an error rather than a rebuild that runs until tempdb is full.'))
, (CASE WHEN @PairsAfter = @PairsBefore THEN 4 ELSE 1 END
 , CASE WHEN @PairsAfter = @PairsBefore THEN 'OK' ELSE 'VIOLATED' END
 , N'The failed rebuild left the closure untouched'
 , CONCAT (@PairsBefore, N' live pair(s) before the cycle, ', @PairsAfter, N' after the failure and the restore. The '
         , N'rebuild does its whole MERGE in one transaction and its CATCH rolls back, so a rebuild that cannot finish '
         , N'must leave the previous closure intact rather than a partial one -- a partially rebuilt closure is an '
         , N'authorization table with rows missing.'))
, (CASE WHEN @LoggedError = 530 AND @LoggedReCreated = 0 THEN 4 ELSE 2 END
 , CASE WHEN @LoggedError = 530 AND @LoggedReCreated = 0 THEN 'OK' ELSE 'INCOMPLETE' END
 , N'The failure was recorded in logs.ExecutionLog'
 , CONCAT (N'Latest unsuccessful row for [auth].[uspRebuildTenantClosure] carries ErrorNumber '
         , COALESCE (CAST (@LoggedError AS NVARCHAR (11)), N'(no row)'), N' and ReCreatedAfterRollback '
         , COALESCE (CAST (@LoggedReCreated AS NVARCHAR (11)), N'(no row)'), N'; 530 and 0 expected. 0 because the '
         , N'start row was opened in autocommit BEFORE the transaction, so the procedure''s own ROLLBACK could not '
         , N'destroy it and the CATCH took the MATCHED branch. Rule 8 on a real failure, not a probe''s.'));

SELECT Severity, Status, Item, Detail
  FROM @CycleReport
 ORDER BY Severity, RowNo;

IF EXISTS (SELECT 1 FROM @CycleReport WHERE Severity <= 2)
BEGIN
    DECLARE @CycleFailed NVARCHAR (2000) =
        N'The cycle probe FAILED. Read the report above. The tree has been restored either way.';

    THROW 50000, @CycleFailed, 1;
END;

PRINT N'Cycle: refused with 530, closure left intact, failure recorded. Phase 1 exit criterion 2 satisfied.';
GO


-- *** 6. The restored tree, for the transcript ***
SELECT v.ApplicationCode
     , v.Depth
     , Tenant = REPLICATE (N'    ', v.Depth) + v.TenantCode
     , v.TenantPath
     , IsUsable = auth.udfIsTenantUsable (v.TenantId)
  FROM auth.vwTenantHierarchy AS v
 WHERE v.ApplicationCode = N'VARIANT2'
 ORDER BY v.TenantPath;
GO

-- The pairs this run retired and did not erase.  Not an assertion -- a record, so a deployment transcript shows what a
-- re-parenting leaves behind.  Empty on a database where LMA has never been moved anywhere but back.
SELECT Ancestor   = anc.TenantCode
     , Descendant = des.TenantCode
     , c.Depth
     , c.auditDeletedBy
     , c.auditDeletedDateUtc
  FROM auth.TenantClosure AS c
  JOIN auth.Tenant        AS anc ON anc.TenantId = c.AncestorTenantId
  JOIN auth.Tenant        AS des ON des.TenantId = c.DescendantTenantId
  JOIN auth.Application   AS a   ON a.ApplicationId = des.ApplicationId
 WHERE c.IsDeleted = 1
   AND a.ApplicationCode = N'VARIANT2'
 ORDER BY anc.TenantCode, des.TenantCode;
GO
