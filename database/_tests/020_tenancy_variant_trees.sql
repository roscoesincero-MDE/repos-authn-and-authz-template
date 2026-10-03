/***********************************************************************************************************************
Script:         _tests/020_tenancy_variant_trees.sql
Purpose:        The Phase 1 exit criterion "all three trees build from script".  Creates three applications -- VARIANT1,
                VARIANT2 and VARIANT3 -- and the three tenant hierarchy shapes section 17 names, then rebuilds the
                closure and verifies the result against an INDEPENDENT calculation rather than against a constant.
Target:         SQL Server 2022 or newer.
Run as:         db_owner in the target database.
Run in:         The target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/_tests/020_tenancy_variant_trees.sql
Idempotent:     Yes, and the idempotence is load-bearing rather than incidental -- see below.
Depends on:     database/030_auth_tenant.sql, database/095_auth_views.sql, database/100_auth_functions.sql,
                database/125_auth_tenant_procedures.sql.
Implements:     PLAN-AUTH-001 Phase 1 exit criteria.  Task T-022.  DES-AUTH-001 sections 5.2, 5.3, 15.2 and 17.
To retarget:    Pass it per run:  -d <database> -v DbName=<database>.  There is no in-file default.

WHY THREE APPLICATIONS AND NOT THREE DATABASES
----------------------------------------------
The three variants are the three tenancy shapes this template has to support, and the whole point of D-01 -- one
hierarchy, not one hierarchy per shape -- is that they coexist in ONE auth.Tenant table.  Three databases would prove
the schema can hold each shape; three applications in one database prove they do not interfere, which is the claim that
matters and the only one INV-02 can be tested against.  Running them side by side is also what makes
UX_auth_Tenant_ApplicationRoot meaningful: three rows with a NULL ParentTenantId, all legal, because the index is
filtered per application.

  VARIANT1  flat, jurisdictional.  A root with an agency and two county jurisdictions directly under it.  4 tenants.
  VARIANT2  deep, programmatic.    Root, one agency, four administrations, three programs beneath three of them.  9.
  VARIANT3  mixed.                 Root, an agency with four administrations, and a division holding three external
                                   organizations.  10 tenants, and the variant that exercises the two tenant types the
                                   other two do not.

Between them the three trees use all seven seeded tenant types, which is asserted rather than asserted-in-a-comment: a
type nobody builds a tenant of is a type nobody has tested the CHECK constraint against.

WHY IT WRITES auth.Tenant DIRECTLY INSTEAD OF CALLING auth.uspCreateTenant
--------------------------------------------------------------------------
Two reasons, and the first is temporary while the second is permanent.

  1.  auth.uspCreateTenant demands a session and a permission, which means auth.uspSetSessionContext (Phase 2) and
      auth.uspDemandPermission (Phase 3).  Calling it today fails with 2812.  When those arrive, the ORDINARY tenants
      in these trees could be created through it, and a later phase should switch them over -- that is a better test
      than this one.

  2.  The three ROOTS could never be created through it.  auth.uspCreateTenant refuses to create a root (50094, INV-02),
      deliberately, because a root has no parent to authorize the creation at.  A root arrives with its application, by
      a script running as db_owner.  So this file would need a direct write for the roots whatever happens in Phase 3.

The rebuild, however, IS called rather than reimplemented: auth.uspRebuildTenantClosure is parameterless and demands
nothing, so it is callable today, and a fixture that built its own closure would be testing its own arithmetic.

WHY IT IS A MERGE, AND WHY THAT IS THE POINT RATHER THAN TIDINESS
-----------------------------------------------------------------
_tests/030_tenancy_closure_reparent.sql MOVES a tenant.  Running this file afterwards puts it back, because every
tenant's parent is restated by the MERGE -- so the two files can be run in either order, any number of times, and the
tree returns to its declared shape.  That is what lets 030 be written as an unconditional movement instead of a
conditional one that skips itself on a second run and reports success for a test it did not perform.

WHAT IT DELIBERATELY DOES NOT DO
--------------------------------
It does not clean up, and it is not in the install manifest.  The three variant applications are development fixtures;
they have no business meaning and no place in a database a project team puts real data in, so they live here and are run
by hand.  Nothing in this file deletes anything -- soft delete only (conventions non-negotiable 3) applies to a test
script exactly as it applies to a procedure, and a fixture that tidied up after itself would have DELETE in it.

It also does not test authorization, because it cannot yet.  Every write here is db_owner's.  The permission demands in
auth.uspCreateTenant and auth.uspUpdateTenant become testable in Phase 3, and the task list says so.
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


-- *** 1. Assert the machinery this test is testing ***
-- Without this block the failure arrives as "invalid object name" two hundred lines down, which reads as a defect in the
-- test rather than as a script that was never run.
DECLARE @Absent NVARCHAR (2000) = NULL;

SELECT @Absent = STRING_AGG (x.ObjectName, N', ')
  FROM (VALUES (N'auth.Application')
             , (N'auth.TenantType')
             , (N'auth.Tenant')
             , (N'auth.TenantClosure')
             , (N'auth.vwTenantHierarchy')
             , (N'auth.udfIsTenantUsable')
             , (N'auth.uspRebuildTenantClosure')) AS x (ObjectName)
 WHERE OBJECT_ID (x.ObjectName) IS NULL;

IF @Absent IS NOT NULL
BEGIN
    DECLARE @NotInstalled NVARCHAR (2000) =
        N'The tenancy objects this test exercises are not installed. Absent: ' + @Absent
      + N'. Run database/Install-TemplateDatabase.ps1 first. Nothing has been changed.';

    THROW 50000, @NotInstalled, 1;
END
GO

-- The seven types are seeded by 030_auth_tenant.sql.  Asserted separately from the object list because a present but
-- unseeded auth.TenantType fails later as a foreign key violation, which says nothing about the cause.
IF (SELECT COUNT (*) FROM auth.TenantType WHERE IsDeleted = 0) < 7
BEGIN
    DECLARE @Unseeded NVARCHAR (2000) =
        N'auth.TenantType holds fewer than the seven seeded types. Re-run database/030_auth_tenant.sql, which seeds '
      + N'them. Nothing has been changed.';

    THROW 50000, @Unseeded, 1;
END
GO


-- *** 2. The fixture, declared as data ***
-- Sections 2, 3 and 4 are ONE BATCH, deliberately: a table variable does not survive a GO, so a GO between the
-- declaration and the insert would mean writing the three trees out twice and maintaining the diff between the copies.
-- The whole fixture is therefore declared once, here, and written under one transaction below.
DECLARE @Applications TABLE
(
    ApplicationCode NVARCHAR (50)  NOT NULL PRIMARY KEY,
    ApplicationName NVARCHAR (200) NOT NULL,
    Shape           NVARCHAR (200) NOT NULL
);

INSERT @Applications (ApplicationCode, ApplicationName, Shape)
VALUES (N'VARIANT1', N'Variant 1 - Flat Jurisdictional',  N'Root with an agency and two county jurisdictions directly beneath it.')
     , (N'VARIANT2', N'Variant 2 - Deep Programmatic',     N'Root, one agency, four administrations, three programs.')
     , (N'VARIANT3', N'Variant 3 - Mixed External',        N'Root, an agency with four administrations, and a division of three external organizations.');

-- The trees.  Depth is stated rather than derived, because the insert below walks levels in order and a derived depth
-- would need the tree to exist first.  It is also cross-checked against auth.vwTenantHierarchy's independently computed
-- Depth in section 6, so a wrong number here is caught rather than believed.
DECLARE @Tenants TABLE
(
    RowNo             INT IDENTITY (1, 1) PRIMARY KEY,
    ApplicationCode   NVARCHAR (50)  NOT NULL,
    TenantCode        NVARCHAR (50)  NOT NULL,
    TenantName        NVARCHAR (200) NOT NULL,
    TenantTypeCode    NVARCHAR (50)  NOT NULL,
    ParentTenantCode  NVARCHAR (50)      NULL,
    Depth             INT            NOT NULL,
    UNIQUE (ApplicationCode, TenantCode)
);

INSERT @Tenants (ApplicationCode, TenantCode, TenantName, TenantTypeCode, ParentTenantCode, Depth)
VALUES
  -- ===== VARIANT1: flat, jurisdictional. 4 tenants, deepest depth 1. =====
  -- The shape a single-agency deployment with county partners has: no intermediate layer at all, so every scope grant is
  -- either "everything" or "one county". It is the variant that would pass a design with no closure table, which is
  -- exactly why it is not the only one.
  (N'VARIANT1', N'ROOT',           N'Variant 1 Root',              N'Root',         NULL,     0)
, (N'VARIANT1', N'AGENCY',         N'State Agency',                N'Agency',       N'ROOT',  1)
, (N'VARIANT1', N'ANNE_ARUNDEL',   N'Anne Arundel County',         N'Jurisdiction', N'ROOT',  1)
, (N'VARIANT1', N'BALTIMORE_CITY', N'Baltimore City',              N'Jurisdiction', N'ROOT',  1)

  -- ===== VARIANT2: deep, programmatic. 9 tenants, deepest depth 3. =====
  -- The shape the design was written for: an agency, its administrations, and the programs inside them. The variant
  -- where an ancestor-aware usability rule earns its keep -- deactivating LMA has to make HAZ_WASTE unusable, and
  -- nothing writes to HAZ_WASTE to achieve it.
, (N'VARIANT2', N'ROOT',        N'Variant 2 Root',                      N'Root',           NULL,      0)
, (N'VARIANT2', N'AGENCY',      N'Department of the Environment',       N'Agency',         N'ROOT',   1)
, (N'VARIANT2', N'LMA',         N'Land and Materials Administration',   N'Administration', N'AGENCY', 2)
, (N'VARIANT2', N'WSA',         N'Water and Science Administration',    N'Administration', N'AGENCY', 2)
, (N'VARIANT2', N'ARA',         N'Air and Radiation Administration',    N'Administration', N'AGENCY', 2)
, (N'VARIANT2', N'IT',          N'Information Technology',              N'Administration', N'AGENCY', 2)
, (N'VARIANT2', N'HAZ_WASTE',   N'Hazardous Waste Program',             N'Program',        N'LMA',    3)
, (N'VARIANT2', N'WW_PERMITS',  N'Wastewater Permits Program',          N'Program',        N'WSA',    3)
, (N'VARIANT2', N'RAD_HEALTH',  N'Radiological Health Program',         N'Program',        N'ARA',    3)

  -- ===== VARIANT3: mixed. 10 tenants, deepest depth 2. =====
  -- Two branches of different KINDS under one root: an internal agency branch and a division holding organizations that
  -- are not part of the agency at all. The variant that exercises Division and ExternalOrganization, and the one where
  -- "my subtree" means two quite different things depending on which branch a profile sits in.
, (N'VARIANT3', N'ROOT',      N'Variant 3 Root',                    N'Root',                 NULL,        0)
, (N'VARIANT3', N'AGENCY',    N'Department of the Environment',     N'Agency',               N'ROOT',     1)
, (N'VARIANT3', N'LMA',       N'Land and Materials Administration', N'Administration',       N'AGENCY',   2)
, (N'VARIANT3', N'WSA',       N'Water and Science Administration',  N'Administration',       N'AGENCY',   2)
, (N'VARIANT3', N'ARA',       N'Air and Radiation Administration',  N'Administration',       N'AGENCY',   2)
, (N'VARIANT3', N'IT',        N'Information Technology',            N'Administration',       N'AGENCY',   2)
  -- EXTORG, not EXT_ORGS.  Section 17.3 of the design writes EXT_ORGS and this file used to copy it, which was wrong in
  -- a way that only became visible once the registration procedures existed.  config.ApplicationSetting holds ONE global
  -- key, Registration.ExternalBranchTenantCode, whose value 115_seed_reference_data.sql sets to 'EXTORG'.  That value is
  -- then resolved WITHIN the registering application (155_auth_registration_procedures.sql, around line 615).  So the
  -- setting is global while the tenant it names is per application: every application that accepts self-service
  -- registration must code its external-organizations branch with the SAME code, or auth.uspApproveOrganization raises
  -- E-50067 and calls it a configuration fault.  Spelled EXT_ORGS here, VARIANT3 could take a registration and never
  -- approve one.  Measured 2026-09-20; recorded as the functional half of gap G-34.  155's own closing report detects
  -- this for any application, so the check is not left to this comment.
, (N'VARIANT3', N'EXTORG',    N'External Organizations',            N'Division',             N'ROOT',     1)
, (N'VARIANT3', N'ORG_O1',    N'Partner Organization O1',           N'ExternalOrganization', N'EXTORG',   2)
, (N'VARIANT3', N'ORG_O2',    N'Partner Organization O2',           N'ExternalOrganization', N'EXTORG',   2)
, (N'VARIANT3', N'ORG_O3',    N'Partner Organization O3',           N'ExternalOrganization', N'EXTORG',   2);

-- The same actor on every row, and stated explicitly rather than left to the DEFAULT, because section 14.4 requires an
-- inserting statement to set auditCreatedBy itself (finding F-02).  A fixture is not exempt: the DEFAULT is
-- ORIGINAL_LOGIN (), and a row created by a fixture should say so.
DECLARE @Actor    NVARCHAR (255) = CONCAT (N'fixture@020_tenancy_variant_trees#', ORIGINAL_LOGIN ())
      , @Depth    INT            = 0
      , @MaxDepth INT            = (SELECT MAX (Depth) FROM @Tenants);


-- *** 3. The three applications ***
-- One transaction over sections 3 and 4.  A fixture interrupted halfway through is a tree with a missing level, and the
-- next thing to run is a closure rebuild that would faithfully record the broken shape.
BEGIN TRANSACTION;

-- ApplicationCode is the natural key and UX_auth_Application_Code enforces it.  A soft-deleted variant application is
-- resurrected, because the whole purpose of this file is to restore a declared state.
MERGE auth.Application AS tgt
USING (SELECT ApplicationCode, ApplicationName FROM @Applications) AS src
   ON tgt.ApplicationCode = src.ApplicationCode
WHEN MATCHED AND (tgt.ApplicationName <> src.ApplicationName OR tgt.IsDeleted = 1 OR tgt.IsActive = 0)
    THEN UPDATE SET tgt.ApplicationName      = src.ApplicationName
                  , tgt.IsActive             = 1
                  , tgt.IsDeleted            = 0
                  , tgt.auditDeletedBy       = NULL
                  , tgt.auditDeletedDateUtc  = NULL
                  , tgt.auditModifiedBy      = @Actor
                  , tgt.auditModifiedDateUtc = SYSUTCDATETIME ()
WHEN NOT MATCHED BY TARGET
    THEN INSERT (ApplicationCode, ApplicationName, auditCreatedBy, auditModifiedBy)
         VALUES (src.ApplicationCode, src.ApplicationName, @Actor, @Actor);
-- NO "WHEN NOT MATCHED BY SOURCE" BRANCH, DELIBERATELY.  The source is three variant applications; the target is every
-- application in the database.  That branch would soft-delete a real one.


-- *** 4. The tenants, one level at a time ***
-- Level by level because ParentTenantId is an IDENTITY that does not exist until its row does.  The alternative -- one
-- MERGE with a self-join onto the target -- reads the table it is writing, and the parent it needs may be in the same
-- statement's source.
WHILE @Depth <= @MaxDepth
BEGIN
    -- Resolved to ids here rather than in the MERGE, so the ON clause compares integers and a code that does not resolve
    -- is caught by the NOT NULL columns rather than silently matching nothing.
    MERGE auth.Tenant AS tgt
    USING (SELECT ApplicationId  = a.ApplicationId
                , f.TenantCode
                , f.TenantName
                , tt.TenantTypeId
                , f.TenantTypeCode
                  -- NULL for a root, which is what CK_auth_Tenant_RootHasNoParent requires of exactly the rows whose
                  -- TenantTypeCode is Root.
                , ParentTenantId = p.TenantId
             FROM @Tenants            AS f
             JOIN auth.Application    AS a  ON a.ApplicationCode = f.ApplicationCode
                                           AND a.IsDeleted       = 0
             JOIN auth.TenantType     AS tt ON tt.TenantTypeCode = f.TenantTypeCode
                                           AND tt.IsDeleted      = 0
             LEFT JOIN auth.Tenant    AS p  ON p.ApplicationId   = a.ApplicationId
                                           AND p.TenantCode      = f.ParentTenantCode
                                           AND p.IsDeleted       = 0
            WHERE f.Depth = @Depth
              -- A non-root whose parent did not resolve is excluded rather than inserted with a NULL parent, which would
              -- create a second root and violate INV-02.  The count assertion in section 6 is what notices.
              AND (f.ParentTenantCode IS NULL OR p.TenantId IS NOT NULL)) AS src
       ON tgt.ApplicationId = src.ApplicationId
      AND tgt.TenantCode    = src.TenantCode
    -- Restates the parent on every run, which is what puts a tenant moved by 030 back where it belongs.  IsDistinctFrom
    -- rather than <> because ParentTenantId is nullable on a root and NULL <> NULL is unknown.
    WHEN MATCHED AND (tgt.TenantName      <> src.TenantName
                   OR tgt.TenantTypeId    <> src.TenantTypeId
                   OR tgt.ParentTenantId  IS DISTINCT FROM src.ParentTenantId
                   OR tgt.IsActive         = 0
                   OR tgt.IsDeleted        = 1)
        THEN UPDATE SET tgt.TenantName           = src.TenantName
                      , tgt.TenantTypeId         = src.TenantTypeId
                      , tgt.TenantTypeCode       = src.TenantTypeCode
                      , tgt.ParentTenantId       = src.ParentTenantId
                      , tgt.IsActive             = 1
                      , tgt.IsDeleted            = 0
                      , tgt.auditDeletedBy       = NULL
                      , tgt.auditDeletedDateUtc  = NULL
                      , tgt.auditModifiedBy      = @Actor
                      , tgt.auditModifiedDateUtc = SYSUTCDATETIME ()
    WHEN NOT MATCHED BY TARGET
        THEN INSERT (ApplicationId, TenantCode, TenantName, TenantTypeId, TenantTypeCode, ParentTenantId
                   , auditCreatedBy, auditModifiedBy)
             VALUES (src.ApplicationId, src.TenantCode, src.TenantName, src.TenantTypeId, src.TenantTypeCode
                   , src.ParentTenantId, @Actor, @Actor);
    -- Again no "WHEN NOT MATCHED BY SOURCE": the source is one level of three variants and the target is every tenant in
    -- the database.  That branch would soft-delete every tenant at another depth, in every application, on every run.

    SET @Depth += 1;
END;

COMMIT TRANSACTION;
GO


-- *** 5. The closure ***
-- Called, not reimplemented.  A fixture that computed its own closure would be comparing the procedure's arithmetic with
-- a copy of the procedure's arithmetic, and section 6's assertions would pass on a broken rebuild.
EXEC auth.uspRebuildTenantClosure;
GO


-- *** 6. Verify what was built ***
DECLARE @Report TABLE
(
    RowNo    INT IDENTITY (1, 1) PRIMARY KEY,
    Severity INT             NOT NULL,
    Status   VARCHAR (10)    NOT NULL,
    Item     NVARCHAR (200)  NOT NULL,
    Detail   NVARCHAR (1000)     NULL
);

DECLARE @Expected TABLE
(
    ApplicationCode NVARCHAR (50) NOT NULL PRIMARY KEY,
    TenantCount     INT           NOT NULL,
    DeepestDepth    INT           NOT NULL
);

-- The expected shape, restated as counts.  These three numbers ARE hard-coded, and only these three: they are the claim
-- the file makes about what it built, and deriving them from the same VALUES list that built it would assert nothing.
-- The closure pair counts below are NOT hard-coded -- they are computed from auth.vwTenantHierarchy, which walks parent
-- edges, and compared with auth.TenantClosure, which the MERGE built. Two calculations, two objects, one answer.
INSERT @Expected (ApplicationCode, TenantCount, DeepestDepth)
VALUES (N'VARIANT1',  4, 1)
     , (N'VARIANT2',  9, 3)
     , (N'VARIANT3', 10, 2);

-- 6a. The three applications.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN a.ApplicationId IS NULL THEN 1 ELSE 4 END
     , CASE WHEN a.ApplicationId IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Application ' + e.ApplicationCode
     , CASE WHEN a.ApplicationId IS NULL
            THEN N'Not created. The MERGE in section 3 did not run or was rolled back.'
            ELSE CONCAT (N'ApplicationId=', a.ApplicationId, N', ', a.ApplicationName) END
  FROM @Expected         AS e
  LEFT JOIN auth.Application AS a ON a.ApplicationCode = e.ApplicationCode AND a.IsDeleted = 0;

-- 6b. Tenant counts and depth per variant, against the declared expectation.  A level the WHILE loop skipped, or a
-- parent code that failed to resolve, shows up here as a short count rather than as a puzzling closure total.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Actual = e.TenantCount AND x.Deepest = e.DeepestDepth THEN 4 ELSE 1 END
     , CASE WHEN x.Actual = e.TenantCount AND x.Deepest = e.DeepestDepth THEN 'OK' ELSE 'VIOLATED' END
     , N'Tree shape: ' + e.ApplicationCode
     , CONCAT (x.Actual, N' of ', e.TenantCount, N' expected live tenant(s), deepest depth ', x.Deepest, N' of '
             , e.DeepestDepth, N' expected. Depth is auth.vwTenantHierarchy''s, computed by walking parent edges.')
  FROM @Expected AS e
 CROSS APPLY (SELECT Actual  = COUNT (*)
                   , Deepest = COALESCE (MAX (v.Depth), -1)
                FROM auth.vwTenantHierarchy AS v
               WHERE v.ApplicationCode = e.ApplicationCode) AS x;

-- 6c. INV-02, both halves, per variant.  Three roots coexist, which is legal only because
-- UX_auth_Tenant_ApplicationRoot is filtered per application -- so three applications in one table is the test, and one
-- application would not have been.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Roots = 1 THEN 4 ELSE 1 END
     , CASE WHEN x.Roots = 1 THEN 'OK' ELSE 'VIOLATED' END
     , N'INV-02: exactly one root in ' + e.ApplicationCode
     , CONCAT (x.Roots, N' live tenant(s) with a NULL ParentTenantId, and ', x.RootTyped
             , N' typed Root. The two counts must agree and both must be 1: the first is '
             , N'UX_auth_Tenant_ApplicationRoot''s half, the second is CK_auth_Tenant_RootHasNoParent''s.')
  FROM @Expected AS e
  JOIN auth.Application AS a ON a.ApplicationCode = e.ApplicationCode AND a.IsDeleted = 0
              -- SUM (CASE ... ELSE 0) rather than COUNT (CASE ...): COUNT over an all-NULL expression raises
              -- "Null value is eliminated by an aggregate", and a warning in a test transcript reads as a finding.
 CROSS APPLY (SELECT Roots     = SUM (CASE WHEN t.ParentTenantId IS NULL   THEN 1 ELSE 0 END)
                   , RootTyped = SUM (CASE WHEN t.TenantTypeCode = N'Root' THEN 1 ELSE 0 END)
                FROM auth.Tenant AS t
               WHERE t.ApplicationId = a.ApplicationId
                 AND t.IsDeleted     = 0) AS x;

-- 6d. THE ASSERTION THIS FILE EXISTS FOR.  auth.vwTenantHierarchy computes each tenant's depth by walking parent edges;
-- auth.uspRebuildTenantClosure built a row per ancestor pair.  A tenant at depth d has exactly d + 1 ancestors including
-- itself, so SUM (Depth + 1) over the view must equal COUNT (*) over the closure.  Two independent calculations in two
-- different objects, and neither number is written in this file.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.FromView = x.FromClosure THEN 4 ELSE 1 END
     , CASE WHEN x.FromView = x.FromClosure THEN 'OK' ELSE 'VIOLATED' END
     , N'Closure agrees with the hierarchy: ' + e.ApplicationCode
     , CONCAT (N'SUM (Depth + 1) over auth.vwTenantHierarchy = ', x.FromView
             , N'; COUNT (*) over auth.TenantClosure = ', x.FromClosure
             , N'. Equal means every tenant has a row for itself and for each of its ancestors, and no others. '
             , N'Holds only while no tenant in the variant is soft-deleted -- the view excludes those and the closure '
             , N'deliberately does not.')
  FROM @Expected AS e
  JOIN auth.Application AS a ON a.ApplicationCode = e.ApplicationCode AND a.IsDeleted = 0
 CROSS APPLY (SELECT FromView    = (SELECT COALESCE (SUM (v.Depth + 1), 0)
                                      FROM auth.vwTenantHierarchy AS v
                                     WHERE v.ApplicationId = a.ApplicationId)
                   , FromClosure = (SELECT COUNT (*)
                                      FROM auth.TenantClosure AS c
                                      JOIN auth.Tenant        AS d ON d.TenantId = c.DescendantTenantId
                                     WHERE d.ApplicationId = a.ApplicationId
                                       AND c.IsDeleted     = 0)) AS x;

-- 6e. No closure pair may cross an application.  There is no declarative constraint for this -- the closure's two
-- foreign keys point at auth.Tenant and neither carries ApplicationId -- so it is asserted here and in 030's report.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 0 THEN 4 ELSE 1 END
     , CASE WHEN COUNT (*) = 0 THEN 'OK' ELSE 'VIOLATED' END
     , N'No closure pair crosses an application'
     , CONCAT (COUNT (*), N' live pair(s) whose ancestor and descendant belong to different applications. Anything but '
             , N'0 means a scope grant in one application reaches a tenant in another, which is the worst failure this '
             , N'schema can have.')
  FROM auth.TenantClosure AS c
  JOIN auth.Tenant        AS anc ON anc.TenantId = c.AncestorTenantId
  JOIN auth.Tenant        AS des ON des.TenantId = c.DescendantTenantId
 WHERE c.IsDeleted = 0
   AND anc.ApplicationId <> des.ApplicationId;

-- 6f. Every tenant in the three trees is usable, because every one of them is active.  This is the fail-closed function
-- reporting an open verdict, which is the half of auth.udfIsTenantUsable that 100_auth_functions.sql's report cannot
-- assert on an empty database.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Unusable = 0 THEN 4 ELSE 1 END
     , CASE WHEN x.Unusable = 0 THEN 'OK' ELSE 'VIOLATED' END
     , N'auth.udfIsTenantUsable returns 1 for every fixture tenant'
     , CONCAT (x.Unusable, N' of ', x.Total, N' live variant tenant(s) read as unusable. All are active and undeleted, '
             , N'so anything but 0 means the closure is incomplete -- the function needs a tenant''s depth-0 self row '
             , N'before it will return 1 for it.')
  FROM (SELECT Total    = COUNT (*)
             , Unusable = SUM (CASE WHEN auth.udfIsTenantUsable (t.TenantId) = 0 THEN 1 ELSE 0 END)
          FROM auth.Tenant      AS t
          JOIN auth.Application AS a ON a.ApplicationId = t.ApplicationId
         WHERE t.IsDeleted = 0
           AND a.ApplicationCode IN (N'VARIANT1', N'VARIANT2', N'VARIANT3')) AS x;

-- 6g. All seven seeded types are exercised.  A type no fixture builds a tenant of is a type whose place in the tree
-- nobody has tested, and the three variants were chosen between them to cover all of them.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 0 THEN 4 ELSE 2 END
     , CASE WHEN COUNT (*) = 0 THEN 'OK' ELSE 'INCOMPLETE' END
     , N'All seven tenant types are exercised by the three variants'
     , CONCAT (N'Unused: ', COALESCE (STRING_AGG (tt.TenantTypeCode, N', '), N'none')
             , N'. The three variants were chosen to cover every seeded type between them.')
  FROM auth.TenantType AS tt
 WHERE tt.IsDeleted = 0
   AND NOT EXISTS (SELECT 1
                     FROM auth.Tenant      AS t
                     JOIN auth.Application AS a ON a.ApplicationId = t.ApplicationId
                    WHERE t.TenantTypeId = tt.TenantTypeId
                      AND t.IsDeleted    = 0
                      AND a.ApplicationCode IN (N'VARIANT1', N'VARIANT2', N'VARIANT3'));

-- 6h. Totals, for the transcript.  Reported rather than asserted: the per-variant assertions above are the test, and a
-- total is what somebody reads to see whether the database has anything else in it.
INSERT @Report (Severity, Status, Item, Detail)
SELECT 4, 'OK'
     , N'Totals across the whole database'
     , CONCAT ((SELECT COUNT (*) FROM auth.Tenant        WHERE IsDeleted = 0), N' live tenant(s), '
             , (SELECT COUNT (*) FROM auth.TenantClosure WHERE IsDeleted = 0), N' live closure pair(s), '
             , (SELECT COUNT (*) FROM auth.TenantClosure WHERE IsDeleted = 1), N' retired pair(s) retained, '
             , (SELECT COUNT (*) FROM auth.Application    WHERE IsDeleted = 0), N' application(s). The three variants '
             , N'account for 23 tenants and 60 pairs; anything above that is other data in this database.');

IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
    PRINT N'Variant tenant trees: PROBLEMS found. Read the report below.';
ELSE
    PRINT N'Variant tenant trees: all three trees built and verified. Phase 1 exit criterion 1 satisfied.';

PRINT N'';

SELECT Severity, Status, Item, Detail
  FROM @Report
 ORDER BY Severity, RowNo;
GO


-- *** 7. The trees, for the transcript ***
-- Printed as a result set so a deployment log contains the shape that was built, not only the assertion that it was.
SELECT v.ApplicationCode
     , v.Depth
     , Tenant = REPLICATE (N'    ', v.Depth) + v.TenantCode
     , v.TenantTypeCode
     , v.TenantName
     , v.TenantPath
     , IsUsable = auth.udfIsTenantUsable (v.TenantId)
  FROM auth.vwTenantHierarchy AS v
 WHERE v.ApplicationCode IN (N'VARIANT1', N'VARIANT2', N'VARIANT3')
 ORDER BY v.ApplicationCode, v.TenantPath;
GO
