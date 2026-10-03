/***********************************************************************************************************************
Script:         _tests/050_authorization_and_session.sql
Purpose:        The two Phase 3 exit criteria that can only be settled by experiment:
                  *  auth.ProfilePermissionScope equals the set derived from the live grants after an ARBITRARY sequence
                     of grants, revocations, role edits, expiries, permission retirements and profile deactivations --
                     fourteen mutations, compared both ways after every one of them (T-057, DES 8.6, gap G-03).
                  *  A second auth.uspSetSessionContext on ONE connection returns silently for the same profile and
                     raises E-50022 for a different one, and the refusal changes nothing (T-058, DES 14.3).
                Also proves that a revoked grant is RESURRECTED IN PLACE rather than re-inserted, that an identity set
                read-only cannot be detached by auth.uspClearSessionContext, and that a session whose profile is NULL
                gets three keys instead of five.
Target:         SQL Server 2022 or newer.
Run as:         db_owner in the target database.
Run in:         The target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/_tests/050_authorization_and_session.sql
Idempotent:     Yes, and unconditionally -- section 2 soft-deletes the previous run's grants, sessions and profiles
                before it rebuilds them.
Depends on:     025_config_tables.sql, 030_auth_tenant.sql, 040_auth_userprofile.sql, 045_auth_identity.sql,
                050_auth_permission.sql, 055_auth_role.sql, 060_auth_profile_role.sql,
                065_auth_effective_permission.sql, 070_auth_session.sql, 085_logs_auth_tables.sql,
                100_auth_functions.sql, 105_auth_session_procedures.sql, 125_auth_tenant_procedures.sql.
                Builds its own fixture and depends on no other test file.
Implements:     PLAN-AUTH-001 Phase 3 exit criteria.  Tasks T-057 and T-058.  DES-AUTH-001 sections 8.4, 8.5, 8.6, 9.1,
                14.3.  INV-03, INV-10.
To retarget:    Pass it per run:  -d <database> -v DbName=<database>.  There is no in-file default.

THE ORDER OF THE SECTIONS IS PART OF THE TEST, AND SECTION 5 MUST BE LAST
------------------------------------------------------------------------
auth.uspSetSessionContext sets its five identity keys with @read_only = 1.  A read-only session-context key cannot be
re-set to a different value, cannot be re-set to the SAME value, and cannot be set to NULL -- that last one is Msg 15664,
measured on this instance.  So the moment section 5 succeeds, THIS CONNECTION is authztest.uma wearing the agency profile
for as long as it stays open, and no later experiment could set up a different identity.

That is not a defect in the procedure, it is section 14.3's design and UI-06's warning to the application: one connection
serves one profile.  The consequence for a test file is simply that the section which spends the connection's identity
comes last, and that everything before it either needs no identity or sets the keys DIRECTLY without @read_only.

WHY THE MUTATIONS ARE DATA AND NOT FOURTEEN COPIES OF THE SAME BLOCK
-------------------------------------------------------------------
Section 4 is a loop over #Mutation, and each row carries one statement.  The alternative -- fourteen hand-written blocks,
each followed by its own copy of the comparison -- was written first and thrown away: the comparison is the assertion,
and fourteen copies of an assertion is fourteen chances for one of them to be subtly weaker than the others.  One loop
means the derived set is defined exactly once, in one place, where a reviewer can check it against DES 8.6 line by line.

The sequence is deliberately not tidy.  It revokes something and re-grants it, expires a grant that was already expired
when it was made, edits a role while two profiles hold it, retires a permission out from under a role, deactivates a
profile and then brings it back.  "Arbitrary" in T-057 means the materialization must not depend on the order, so the
order is chosen to be awkward.

HOW "EQUALS THE DERIVED SET" IS CHECKED
--------------------------------------
Two EXCEPT queries, in both directions, over the fixture's profiles:

  *  derived EXCEPT materialized  -- authority a profile SHOULD have and does not.  A false denial: the user sees an
     empty screen and files a ticket that reads "the system lost my data".
  *  materialized EXCEPT derived  -- authority a profile SHOULD NOT have and does.  A false grant: nobody files a
     ticket at all, and it is the one that matters.

Both must be zero after every mutation.  The derived query in section 4 is written out longhand from DES 8.6 rather than
copied from auth.uspRebuildProfilePermissionScope, because a test that reuses the implementation's own definition of
correctness proves only that the implementation is self-consistent.

WHAT THIS FILE DOES NOT PROVE
----------------------------
  *  Nothing here is concurrent.  Two rebuilds of the same profile racing each other, or a grant committed between a
     rebuild's MERGE and its read, is not exercised: the procedure takes no lock beyond the MERGE's own, and whether
     that is enough is a load question, not a logic one.
  *  It does not test the permission-check functions against a real RLS policy; that is _tests/060_row_security.sql.
  *  It does not sign anybody in.  Section 5 builds its session rows directly, because the subject is what
     auth.uspSetSessionContext does with a session, not how one comes to exist -- _tests/040 owns that end to end.

***********************************************************************************************************************/
SET NOCOUNT ON;
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

-- *** 0. Assert the target ***
IF DB_NAME () <> N'$(DbName)'
BEGIN
    ;THROW 50000, N'This script must run against the database named by -v DbName. Start sqlcmd with -v DbName=<database> and do not add a :setvar line to this file: an in-file :setvar overrides -v, and a fixture built in the wrong database is a mess somebody else finds.', 1;
END;
GO

USE [$(DbName)];
GO


-- *** 1. Assert the machinery ***
DECLARE @Missing NVARCHAR (MAX) = NULL;

SELECT @Missing = STRING_AGG (x.ObjectName, N', ') WITHIN GROUP (ORDER BY x.ObjectName)
  FROM (VALUES (N'auth.Application',                      N'U')
             , (N'auth.Tenant',                           N'U')
             , (N'auth.TenantClosure',                    N'U')
             , (N'auth.[User]',                            N'U')
             , (N'auth.UserProfile',                      N'U')
             , (N'auth.PermissionCategory',               N'U')
             , (N'auth.Permission',                       N'U')
             , (N'auth.Role',                             N'U')
             , (N'auth.RolePermission',                   N'U')
             , (N'auth.UserProfileRole',                  N'U')
             , (N'auth.ProfilePermissionScope',           N'U')
             , (N'auth.LoginAttempt',                     N'U')
             , (N'auth.UserSession',                      N'U')
             , (N'auth.uspRebuildProfilePermissionScope', N'P')
             , (N'auth.uspRebuildTenantClosure',          N'P')
             , (N'auth.uspSetSessionContext',             N'P')
             , (N'auth.uspClearSessionContext',           N'P')
             , (N'auth.udfHasPermission',                 N'FN')
             , (N'auth.tvfPermissionScope',               N'IF')) AS x (ObjectName, ObjectType)
 WHERE OBJECT_ID (x.ObjectName, x.ObjectType) IS NULL;

IF @Missing IS NOT NULL
BEGIN
    DECLARE @Failure NVARCHAR (2048) = N'The Phase 3 machinery is incomplete: ' + @Missing
        + N' is missing, so this file would report failures that are really absences. Run the numbered scripts through '
        + N'105_auth_session_procedures.sql first.';
    ;THROW 50000, @Failure, 1;
END;
GO


-- *** 2. The observation log ***
-- A TEMPORARY TABLE AND NOT A TABLE VARIABLE: the experiments span batches, and a table variable does not survive GO.
-- No IF OBJECT_ID ... DROP guard in front of it, deliberately -- a fresh sqlcmd connection cannot already have one, and
-- a second run down one interactive session SHOULD fail here rather than interleave two runs in one transcript.
CREATE TABLE #Observation
(
    RowNo     INT IDENTITY (1, 1) PRIMARY KEY,
    Section   NVARCHAR (60)  NOT NULL,
    Severity  INT            NOT NULL,   -- 1 = exit criterion violated, 2 = defect, 3 = note, 4 = observed as intended
    Status    VARCHAR (10)   NOT NULL,
    Item      NVARCHAR (200) NOT NULL,
    Detail    NVARCHAR (4000)    NULL   -- 4000 and not _tests/040's 2000: section 4 quotes each step's whole expectation
);

CREATE TABLE #Fixture
(
    ApplicationId   INT NULL, RootTenantId INT NULL, AgencyId  INT NULL, Agency2Id INT NULL,
    ProgAId         INT NULL, ProgBId      INT NULL,
    UmaUserId       INT NULL, VictorUserId INT NULL,
    UmaAgencyProfile INT NULL, UmaProgBProfile INT NULL, VictorProfile INT NULL,
    ReaderRoleId    INT NULL, ContribRoleId INT NULL, ExportRoleId INT NULL,
    ReadPermId      INT NULL, InsertPermId  INT NULL, UpdatePermId INT NULL, ExportPermId INT NULL,
    CategoryId      INT NULL
);
GO


-- *** 3. The fixture, and the reset ***
-- NOTHING IS HARD-DELETED IN THIS FILE.  Every reset is a soft delete, which is exactly what the derived query and the
-- materialization both filter on, so the previous run's rows stay readable and stop counting at the same moment.
DECLARE @Now   DATETIME2 (3)  = SYSUTCDATETIME ()
      , @Actor NVARCHAR (255) = N'_tests/050';

DECLARE @AppId INT, @RootId INT, @AgencyId INT, @Agency2Id INT, @ProgAId INT, @ProgBId INT
      , @CategoryId INT, @ReadId INT, @InsertId INT, @UpdateId INT, @ExportId INT
      , @ReaderRole INT, @ContribRole INT, @ExportRole INT
      , @UmaId INT, @VictorId INT, @UmaAgency INT, @UmaProgB INT, @VictorProfile INT;

-- 3a.  The application.
IF NOT EXISTS (SELECT 1 FROM auth.Application WHERE ApplicationCode = N'AUTHZTEST')
BEGIN
    INSERT auth.Application (ApplicationCode, ApplicationName, IsActive, auditCreatedBy, auditModifiedBy)
    VALUES (N'AUTHZTEST', N'Authorization test application', 1, @Actor, @Actor);
END;

SELECT @AppId = ApplicationId FROM auth.Application WHERE ApplicationCode = N'AUTHZTEST';

UPDATE auth.Application
   SET IsActive = 1, IsDeleted = 0, auditDeletedBy = NULL, auditDeletedDateUtc = NULL
     , auditModifiedBy = @Actor, auditModifiedDateUtc = @Now
 WHERE ApplicationId = @AppId
   AND (IsActive = 0 OR IsDeleted = 1);

-- 3b.  The tree.  Two agencies under one root, two programs under the first agency. The second agency exists to be OUT
--      of every fixture profile's reach: a scope test with nothing outside the scope proves nothing.
--
--        AUTHZ_ROOT
--          +-- AUTHZ_AGENCY      <- uma's profile wears this
--          |     +-- AUTHZ_PROG_A  <- victor's profile wears this
--          |     +-- AUTHZ_PROG_B  <- uma's second profile wears this
--          +-- AUTHZ_AGENCY2     <- nobody's
--
-- ONE LEVEL PER STATEMENT, PARENT FIRST.  CK_auth_Tenant_RootHasNoParent is
--   (ParentTenantId IS NULL AND TenantTypeCode = 'Root') OR (ParentTenantId IS NOT NULL AND TenantTypeCode <> 'Root')
-- so a non-root tenant cannot exist for even one statement without its parent -- there is no insert-then-adopt. A single
-- MERGE over all five rows fails with Msg 547, which is the constraint refusing to hold an orphan, and it is right to.
IF NOT EXISTS (SELECT 1 FROM auth.Tenant WHERE ApplicationId = @AppId AND TenantCode = N'AUTHZ_ROOT')
BEGIN
    INSERT auth.Tenant (ApplicationId, TenantCode, TenantName, TenantTypeId, TenantTypeCode, ParentTenantId, IsActive
                      , auditCreatedBy, auditModifiedBy)
    VALUES (@AppId, N'AUTHZ_ROOT', N'Authz root', 1, N'Root', NULL, 1, @Actor, @Actor);
END;

SELECT @RootId = TenantId FROM auth.Tenant WHERE ApplicationId = @AppId AND TenantCode = N'AUTHZ_ROOT';

MERGE auth.Tenant AS tgt
USING (VALUES (N'AUTHZ_AGENCY',  N'Authz agency',   2, N'Agency')
            , (N'AUTHZ_AGENCY2', N'Authz agency 2', 2, N'Agency')) AS src (TenantCode, TenantName, TypeId, TypeCode)
   ON tgt.ApplicationId = @AppId AND tgt.TenantCode = src.TenantCode
WHEN MATCHED THEN
    UPDATE SET tgt.ParentTenantId = @RootId, tgt.IsActive = 1, tgt.IsDeleted = 0
             , tgt.auditDeletedBy = NULL, tgt.auditDeletedDateUtc = NULL
             , tgt.auditModifiedBy = @Actor, tgt.auditModifiedDateUtc = @Now
WHEN NOT MATCHED BY TARGET THEN
    INSERT (ApplicationId, TenantCode, TenantName, TenantTypeId, TenantTypeCode, ParentTenantId, IsActive
          , auditCreatedBy, auditModifiedBy)
    VALUES (@AppId, src.TenantCode, src.TenantName, src.TypeId, src.TypeCode, @RootId, 1, @Actor, @Actor);

SELECT @AgencyId  = TenantId FROM auth.Tenant WHERE ApplicationId = @AppId AND TenantCode = N'AUTHZ_AGENCY';
SELECT @Agency2Id = TenantId FROM auth.Tenant WHERE ApplicationId = @AppId AND TenantCode = N'AUTHZ_AGENCY2';

MERGE auth.Tenant AS tgt
USING (VALUES (N'AUTHZ_PROG_A', N'Authz program A', 4, N'Program')
            , (N'AUTHZ_PROG_B', N'Authz program B', 4, N'Program')) AS src (TenantCode, TenantName, TypeId, TypeCode)
   ON tgt.ApplicationId = @AppId AND tgt.TenantCode = src.TenantCode
WHEN MATCHED THEN
    UPDATE SET tgt.ParentTenantId = @AgencyId, tgt.IsActive = 1, tgt.IsDeleted = 0
             , tgt.auditDeletedBy = NULL, tgt.auditDeletedDateUtc = NULL
             , tgt.auditModifiedBy = @Actor, tgt.auditModifiedDateUtc = @Now
WHEN NOT MATCHED BY TARGET THEN
    INSERT (ApplicationId, TenantCode, TenantName, TenantTypeId, TenantTypeCode, ParentTenantId, IsActive
          , auditCreatedBy, auditModifiedBy)
    VALUES (@AppId, src.TenantCode, src.TenantName, src.TypeId, src.TypeCode, @AgencyId, 1, @Actor, @Actor);

SELECT @ProgAId = TenantId FROM auth.Tenant WHERE ApplicationId = @AppId AND TenantCode = N'AUTHZ_PROG_A';
SELECT @ProgBId = TenantId FROM auth.Tenant WHERE ApplicationId = @AppId AND TenantCode = N'AUTHZ_PROG_B';

EXEC auth.uspRebuildTenantClosure;

-- 3c.  A permission category and four permissions. Four, because the sequence in section 4 needs one permission that
--      only one role confers (Data.Export) and three that overlap.
IF NOT EXISTS (SELECT 1 FROM auth.PermissionCategory WHERE CategoryCode = N'Data')
BEGIN
    INSERT auth.PermissionCategory (CategoryCode, CategoryName, SortOrder, auditCreatedBy, auditModifiedBy)
    VALUES (N'Data', N'Data', 10, @Actor, @Actor);
END;

SELECT @CategoryId = PermissionCategoryId FROM auth.PermissionCategory WHERE CategoryCode = N'Data';

MERGE auth.Permission AS tgt
USING (VALUES (N'Data.Read',   N'Read data')
            , (N'Data.Insert', N'Create data')
            , (N'Data.Update', N'Edit data')
            , (N'Data.Export', N'Export data')) AS src (PermissionCode, PermissionName)
   ON tgt.ApplicationId = @AppId AND tgt.PermissionCode = src.PermissionCode
WHEN MATCHED THEN
    UPDATE SET tgt.IsDeleted = 0, tgt.auditDeletedBy = NULL, tgt.auditDeletedDateUtc = NULL
             , tgt.auditModifiedBy = @Actor, tgt.auditModifiedDateUtc = @Now
WHEN NOT MATCHED BY TARGET THEN
    INSERT (ApplicationId, PermissionCategoryId, PermissionCategoryCode, PermissionCode, PermissionName
          , IsTenantScoped, auditCreatedBy, auditModifiedBy)
    VALUES (@AppId, @CategoryId, N'Data', src.PermissionCode, src.PermissionName, 1, @Actor, @Actor);

SELECT @ReadId   = PermissionId FROM auth.Permission WHERE ApplicationId = @AppId AND PermissionCode = N'Data.Read';
SELECT @InsertId = PermissionId FROM auth.Permission WHERE ApplicationId = @AppId AND PermissionCode = N'Data.Insert';
SELECT @UpdateId = PermissionId FROM auth.Permission WHERE ApplicationId = @AppId AND PermissionCode = N'Data.Update';
SELECT @ExportId = PermissionId FROM auth.Permission WHERE ApplicationId = @AppId AND PermissionCode = N'Data.Export';

-- 3d.  Three roles at the root, which is where a system role belongs: OwnerTenantId = the root means every tenant in the
--      application can be granted it. A role owned lower down is a tenant's own invention and INV-10 keeps the two
--      apart by (ApplicationId, OwnerTenantId, RoleCode).
MERGE auth.Role AS tgt
USING (VALUES (N'AUTHZ_READER',  N'Authz reader')
            , (N'AUTHZ_CONTRIB', N'Authz contributor')
            , (N'AUTHZ_EXPORT',  N'Authz exporter')) AS src (RoleCode, RoleName)
   ON tgt.ApplicationId = @AppId AND tgt.OwnerTenantId = @RootId AND tgt.RoleCode = src.RoleCode
WHEN MATCHED THEN
    UPDATE SET tgt.IsDeleted = 0, tgt.IsAssignable = 1, tgt.auditDeletedBy = NULL, tgt.auditDeletedDateUtc = NULL
             , tgt.auditModifiedBy = @Actor, tgt.auditModifiedDateUtc = @Now
WHEN NOT MATCHED BY TARGET THEN
    INSERT (ApplicationId, OwnerTenantId, RoleCode, RoleName, IsAssignable, IsSystemRole, auditCreatedBy, auditModifiedBy)
    VALUES (@AppId, @RootId, src.RoleCode, src.RoleName, 1, 1, @Actor, @Actor);

SELECT @ReaderRole  = RoleId FROM auth.Role WHERE ApplicationId = @AppId AND OwnerTenantId = @RootId AND RoleCode = N'AUTHZ_READER';
SELECT @ContribRole = RoleId FROM auth.Role WHERE ApplicationId = @AppId AND OwnerTenantId = @RootId AND RoleCode = N'AUTHZ_CONTRIB';
SELECT @ExportRole  = RoleId FROM auth.Role WHERE ApplicationId = @AppId AND OwnerTenantId = @RootId AND RoleCode = N'AUTHZ_EXPORT';

-- Reader: read. Contributor: read, insert, update. Exporter: export. Section 4 edits these mappings while profiles hold
-- the roles, which is the case the materialization gets wrong if it ever caches a role's permission set.
MERGE auth.RolePermission AS tgt
USING (VALUES (@ReaderRole,  @ReadId)
            , (@ContribRole, @ReadId)
            , (@ContribRole, @InsertId)
            , (@ContribRole, @UpdateId)
            , (@ExportRole,  @ExportId)) AS src (RoleId, PermissionId)
   ON tgt.RoleId = src.RoleId AND tgt.PermissionId = src.PermissionId
WHEN MATCHED THEN
    UPDATE SET tgt.IsDeleted = 0, tgt.auditDeletedBy = NULL, tgt.auditDeletedDateUtc = NULL
             , tgt.auditModifiedBy = @Actor, tgt.auditModifiedDateUtc = @Now
WHEN NOT MATCHED BY TARGET THEN
    INSERT (RoleId, PermissionId, ApplicationId, auditCreatedBy, auditModifiedBy)
    VALUES (src.RoleId, src.PermissionId, @AppId, @Actor, @Actor);

-- 3e.  Two users and three profiles. uma holds two profiles -- that is what section 5's E-50022 needs, and it is also
--      the ordinary case the design spends section 8.5 on.
MERGE auth.[User] AS tgt
USING (VALUES (N'authztest.uma',    N'Uma Authztest')
            , (N'authztest.victor', N'Victor Authztest')) AS src (UserName, DisplayName)
   ON tgt.UserName = src.UserName
WHEN MATCHED THEN
    UPDATE SET tgt.IsActive = 1, tgt.IsLockedOut = 0, tgt.LockoutEndUtc = NULL, tgt.IsDeleted = 0
             , tgt.auditDeletedBy = NULL, tgt.auditDeletedDateUtc = NULL
             , tgt.auditModifiedBy = @Actor, tgt.auditModifiedDateUtc = @Now
WHEN NOT MATCHED BY TARGET THEN
    INSERT (UserName, DisplayName, IsActive, auditCreatedBy, auditModifiedBy)
    VALUES (src.UserName, src.DisplayName, 1, @Actor, @Actor);

SELECT @UmaId    = UserId FROM auth.[User] WHERE UserName = N'authztest.uma';
SELECT @VictorId = UserId FROM auth.[User] WHERE UserName = N'authztest.victor';

MERGE auth.UserProfile AS tgt
USING (VALUES (@UmaId,    @AgencyId, N'Uma at the agency',    CAST (1 AS BIT))
            , (@UmaId,    @ProgBId,  N'Uma at program B',     CAST (0 AS BIT))
            , (@VictorId, @ProgAId,  N'Victor at program A',  CAST (1 AS BIT))) AS src (UserId, TenantId, ProfileName, IsDefault)
   ON tgt.UserId = src.UserId AND tgt.TenantId = src.TenantId
WHEN MATCHED THEN
    UPDATE SET tgt.IsActive = 1, tgt.IsDefault = src.IsDefault, tgt.IsDeleted = 0
             , tgt.auditDeletedBy = NULL, tgt.auditDeletedDateUtc = NULL
             , tgt.auditModifiedBy = @Actor, tgt.auditModifiedDateUtc = @Now
WHEN NOT MATCHED BY TARGET THEN
    INSERT (UserId, TenantId, ProfileName, IsDefault, IsActive, auditCreatedBy, auditModifiedBy)
    VALUES (src.UserId, src.TenantId, src.ProfileName, src.IsDefault, 1, @Actor, @Actor);

SELECT @UmaAgency     = UserProfileId FROM auth.UserProfile WHERE UserId = @UmaId    AND TenantId = @AgencyId;
SELECT @UmaProgB      = UserProfileId FROM auth.UserProfile WHERE UserId = @UmaId    AND TenantId = @ProgBId;
SELECT @VictorProfile = UserProfileId FROM auth.UserProfile WHERE UserId = @VictorId AND TenantId = @ProgAId;

-- 3f.  THE RESET. Every grant the last run made is soft-deleted, and then the scope table is rebuilt from that -- which
--      leaves it empty for these three profiles. Starting from empty is what makes the fourteen steps in section 4 mean
--      what they say; starting from "whatever last time left" would make step 1 a test of step 14 of the previous run.
UPDATE auth.UserProfileRole
   SET IsDeleted = 1, auditDeletedBy = @Actor, auditDeletedDateUtc = @Now
     , auditModifiedBy = @Actor, auditModifiedDateUtc = @Now
 WHERE UserProfileId IN (@UmaAgency, @UmaProgB, @VictorProfile)
   AND IsDeleted = 0;

UPDATE auth.UserSession
   SET IsDeleted = 1, auditDeletedBy = @Actor, auditDeletedDateUtc = @Now
     , auditModifiedBy = @Actor, auditModifiedDateUtc = @Now
 WHERE UserId IN (@UmaId, @VictorId)
   AND IsDeleted = 0;

EXEC auth.uspRebuildProfilePermissionScope @UserProfileId = @UmaAgency;
EXEC auth.uspRebuildProfilePermissionScope @UserProfileId = @UmaProgB;
EXEC auth.uspRebuildProfilePermissionScope @UserProfileId = @VictorProfile;

INSERT #Fixture (ApplicationId, RootTenantId, AgencyId, Agency2Id, ProgAId, ProgBId
               , UmaUserId, VictorUserId, UmaAgencyProfile, UmaProgBProfile, VictorProfile
               , ReaderRoleId, ContribRoleId, ExportRoleId
               , ReadPermId, InsertPermId, UpdatePermId, ExportPermId, CategoryId)
VALUES (@AppId, @RootId, @AgencyId, @Agency2Id, @ProgAId, @ProgBId
      , @UmaId, @VictorId, @UmaAgency, @UmaProgB, @VictorProfile
      , @ReaderRole, @ContribRole, @ExportRole
      , @ReadId, @InsertId, @UpdateId, @ExportId, @CategoryId);

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'3 Fixture', 4, 'OK'
     , N'The fixture is built and the scope table is empty for its three profiles'
     , CONCAT (N'Application ', @AppId, N', tenants root/', @RootId, N' agency/', @AgencyId, N' agency2/', @Agency2Id
             , N' progA/', @ProgAId, N' progB/', @ProgBId, N'. Profiles uma@agency/', @UmaAgency, N' uma@progB/'
             , @UmaProgB, N' victor@progA/', @VictorProfile, N'. Live scope rows now: '
             , (SELECT COUNT (*) FROM auth.ProfilePermissionScope
                 WHERE IsDeleted = 0 AND UserProfileId IN (@UmaAgency, @UmaProgB, @VictorProfile))
             , N' -- zero, because every previous grant was soft-deleted and the rebuild followed it.');
GO


-- *** 4. T-057: fourteen mutations, and the derived set after every one of them ***
-- EXIT CRITERION: materialization equals derived.
--
-- Each row of #Mutation is one statement. They run in order, and after each one the affected profile (or every profile,
-- on the rows that say so) is rebuilt and the whole fixture's scope table is compared with the set derived from the live
-- grants -- in BOTH directions. A single non-zero count fails the file.
DECLARE @AppId INT, @RootId INT, @AgencyId INT, @Agency2Id INT, @ProgAId INT, @ProgBId INT
      , @ReadId INT, @InsertId INT, @UpdateId INT, @ExportId INT
      , @ReaderRole INT, @ContribRole INT, @ExportRole INT
      , @UmaAgency INT, @UmaProgB INT, @VictorProfile INT;

SELECT @AppId = ApplicationId, @RootId = RootTenantId, @AgencyId = AgencyId, @Agency2Id = Agency2Id
     , @ProgAId = ProgAId, @ProgBId = ProgBId
     , @ReadId = ReadPermId, @InsertId = InsertPermId, @UpdateId = UpdatePermId, @ExportId = ExportPermId
     , @ReaderRole = ReaderRoleId, @ContribRole = ContribRoleId, @ExportRole = ExportRoleId
     , @UmaAgency = UmaAgencyProfile, @UmaProgB = UmaProgBProfile, @VictorProfile = VictorProfile
  FROM #Fixture;

DECLARE @Actor NVARCHAR (255) = N'_tests/050';

DECLARE @Mutation TABLE
(
    Ord         INT             NOT NULL PRIMARY KEY,
    Description NVARCHAR (200)  NOT NULL,
    Expectation NVARCHAR (900)  NOT NULL,
    Statement   NVARCHAR (MAX)  NOT NULL,
    RebuildAll  BIT             NOT NULL
);

INSERT @Mutation (Ord, Description, Expectation, Statement, RebuildAll)
VALUES
  (1, N'Grant AUTHZ_READER to uma@agency, scoped at the agency'
    , N'Three tenants gain Data.Read for uma: the agency and both programs beneath it, through the closure. The second '
    + N'agency does not.'
    , CONCAT (N'INSERT auth.UserProfileRole (UserProfileId, RoleId, ScopeTenantId, ApplicationId, auditCreatedBy, auditModifiedBy) VALUES ('
            , @UmaAgency, N',', @ReaderRole, N',', @AgencyId, N',', @AppId, N',N''_tests/050'',N''_tests/050'');'), 0)
, (2, N'Grant AUTHZ_CONTRIB to victor@progA, scoped at program A'
    , N'Victor gains read, insert and update at exactly one tenant. Nothing of uma''s changes.'
    , CONCAT (N'INSERT auth.UserProfileRole (UserProfileId, RoleId, ScopeTenantId, ApplicationId, auditCreatedBy, auditModifiedBy) VALUES ('
            , @VictorProfile, N',', @ContribRole, N',', @ProgAId, N',', @AppId, N',N''_tests/050'',N''_tests/050'');'), 0)
, (3, N'Grant AUTHZ_EXPORT to uma@agency at program B, GRANTED TEN DAYS AGO AND EXPIRED YESTERDAY'
    , N'Nothing at all. An expiry in the past is not a grant, and the materialization must not carry it even for an '
    + N'instant -- this is the row that catches a rebuild that filters ExpiresUtc on the wrong side. GrantedUtc is '
    + N'backdated with it, because CK_auth_UserProfileRole_Expiry is (ExpiresUtc IS NULL OR ExpiresUtc > GrantedUtc) '
    + N'and the table will not hold a grant that was born expired.'
    , CONCAT (N'INSERT auth.UserProfileRole (UserProfileId, RoleId, ScopeTenantId, ApplicationId, GrantedUtc, ExpiresUtc, auditCreatedBy, auditModifiedBy) VALUES ('
            , @UmaAgency, N',', @ExportRole, N',', @ProgBId, N',', @AppId
            , N', DATEADD (DAY, -10, SYSUTCDATETIME ()), DATEADD (DAY, -1, SYSUTCDATETIME ()), N''_tests/050'', N''_tests/050'');'), 0)
, (4, N'Grant AUTHZ_EXPORT to victor@progA yesterday, expiring tomorrow'
    , N'Victor gains Data.Export at program A. A future expiry is a live grant. GrantedUtc sits a day in the past so '
    + N'that step 10 can move ExpiresUtc backwards without colliding with the same check constraint.'
    , CONCAT (N'INSERT auth.UserProfileRole (UserProfileId, RoleId, ScopeTenantId, ApplicationId, GrantedUtc, ExpiresUtc, auditCreatedBy, auditModifiedBy) VALUES ('
            , @VictorProfile, N',', @ExportRole, N',', @ProgAId, N',', @AppId
            , N', DATEADD (DAY, -1, SYSUTCDATETIME ()), DATEADD (DAY, 1, SYSUTCDATETIME ()), N''_tests/050'', N''_tests/050'');'), 0)
, (5, N'Revoke uma''s reader grant by soft delete'
    , N'Uma loses all three tenants. The scope rows are RETIRED, not removed -- section 4a checks that separately.'
    , CONCAT (N'UPDATE auth.UserProfileRole SET IsDeleted = 1, auditDeletedBy = N''_tests/050'', auditDeletedDateUtc = SYSUTCDATETIME (), auditModifiedBy = N''_tests/050'', auditModifiedDateUtc = SYSUTCDATETIME () WHERE UserProfileId = '
            , @UmaAgency, N' AND RoleId = ', @ReaderRole, N' AND IsDeleted = 0;'), 0)
, (6, N'Re-grant the SAME reader grant by clearing the soft delete'
    , N'Uma gets all three tenants back, in rows that were resurrected in place rather than inserted: auditCreatedDateUtc '
    + N'is older than this step. The restore names ONE row by its key. UX_auth_UserProfileRole_Grant is filtered on '
    + N'IsDeleted = 0, so every earlier run''s revoked grant for this profile and role is still sitting in the table, and '
    + N'"WHERE UserProfileId = x AND RoleId = y AND IsDeleted = 1" would un-delete all of them at once and collide with '
    + N'the index -- Msg 2601, found the hard way. Marking the row instead, by writing a private value into '
    + N'auditDeletedBy, does not work either: trg_au_updt_UserProfileRole overwrites auditDeletedBy with the session '
    + N'actor, so the column is the trigger''s and not the caller''s. MAX (UserProfileRoleId) is the row step 5 just '
    + N'revoked.'
    , CONCAT (N'UPDATE auth.UserProfileRole SET IsDeleted = 0, auditDeletedBy = NULL, auditDeletedDateUtc = NULL, auditModifiedBy = N''_tests/050'', auditModifiedDateUtc = SYSUTCDATETIME () WHERE UserProfileRoleId = (SELECT MAX (UserProfileRoleId) FROM auth.UserProfileRole WHERE UserProfileId = '
            , @UmaAgency, N' AND RoleId = ', @ReaderRole, N' AND IsDeleted = 1);'), 0)
, (7, N'Edit the contributor role: retire Data.Update'
    , N'Victor loses Data.Update at program A and keeps the rest. A role edit reaches every profile holding the role, '
    + N'which is why step 8 grants it to a second profile before editing again.'
    , CONCAT (N'UPDATE auth.RolePermission SET IsDeleted = 1, auditDeletedBy = N''_tests/050'', auditDeletedDateUtc = SYSUTCDATETIME (), auditModifiedBy = N''_tests/050'', auditModifiedDateUtc = SYSUTCDATETIME () WHERE RoleId = '
            , @ContribRole, N' AND PermissionId = ', @UpdateId, N' AND IsDeleted = 0;'), 0)
, (8, N'Grant AUTHZ_CONTRIB to uma@progB as well, scoped at program B'
    , N'Uma''s second profile gains read and insert -- and NOT update, because step 7 already took it out of the role. '
    + N'A grant confers the role as it stands, not as it was.'
    , CONCAT (N'INSERT auth.UserProfileRole (UserProfileId, RoleId, ScopeTenantId, ApplicationId, auditCreatedBy, auditModifiedBy) VALUES ('
            , @UmaProgB, N',', @ContribRole, N',', @ProgBId, N',', @AppId, N',N''_tests/050'',N''_tests/050'');'), 0)
, (9, N'Restore Data.Update to the contributor role'
    , N'BOTH holders gain it at once, which is the reason this step rebuilds every profile rather than one.'
    , CONCAT (N'UPDATE auth.RolePermission SET IsDeleted = 0, auditDeletedBy = NULL, auditDeletedDateUtc = NULL, auditModifiedBy = N''_tests/050'', auditModifiedDateUtc = SYSUTCDATETIME () WHERE RoleId = '
            , @ContribRole, N' AND PermissionId = ', @UpdateId, N' AND IsDeleted = 1;'), 1)
, (10, N'Expire victor''s export grant by moving ExpiresUtc into the past'
    , N'Victor loses Data.Export. Nothing was deleted: time revoked it, which is the case no application code runs.'
    , CONCAT (N'UPDATE auth.UserProfileRole SET ExpiresUtc = DATEADD (MINUTE, -1, SYSUTCDATETIME ()), auditModifiedBy = N''_tests/050'', auditModifiedDateUtc = SYSUTCDATETIME () WHERE UserProfileId = '
            , @VictorProfile, N' AND RoleId = ', @ExportRole, N';'), 0)
, (11, N'Deactivate uma@progB (IsActive = 0)'
    , N'That profile''s authority disappears entirely and uma''s agency profile is untouched. Section 8.5: an inactive '
    + N'hat is not a wearable one.'
    , CONCAT (N'UPDATE auth.UserProfile SET IsActive = 0, auditModifiedBy = N''_tests/050'', auditModifiedDateUtc = SYSUTCDATETIME () WHERE UserProfileId = '
            , @UmaProgB, N';'), 1)
, (12, N'Reactivate uma@progB'
    , N'It comes back with exactly what the grants say -- read, insert and update at program B.'
    , CONCAT (N'UPDATE auth.UserProfile SET IsActive = 1, auditModifiedBy = N''_tests/050'', auditModifiedDateUtc = SYSUTCDATETIME () WHERE UserProfileId = '
            , @UmaProgB, N';'), 1)
, (13, N'Retire the Data.Insert PERMISSION itself'
    , N'Every scope row for Data.Insert disappears, for both contributors, without anybody touching a role or a grant. '
    + N'A retired permission is not an authorization that merely cannot be checked; it is gone.'
    , CONCAT (N'UPDATE auth.Permission SET IsDeleted = 1, auditDeletedBy = N''_tests/050'', auditDeletedDateUtc = SYSUTCDATETIME (), auditModifiedBy = N''_tests/050'', auditModifiedDateUtc = SYSUTCDATETIME () WHERE PermissionId = '
            , @InsertId, N';'), 1)
, (14, N'Restore the Data.Insert permission'
    , N'Both contributors get it back. The last step is a restore so that the fixture is left in a state a reader can '
    + N'reason about, and so that section 5 runs against a profile with real authority.'
    , CONCAT (N'UPDATE auth.Permission SET IsDeleted = 0, auditDeletedBy = NULL, auditDeletedDateUtc = NULL, auditModifiedBy = N''_tests/050'', auditModifiedDateUtc = SYSUTCDATETIME () WHERE PermissionId = '
            , @InsertId, N';'), 1);

DECLARE @Ord INT = 1
      , @MaxOrd INT = (SELECT MAX (Ord) FROM @Mutation)
      , @Description NVARCHAR (200)
      , @Expectation NVARCHAR (900)
      , @Statement NVARCHAR (MAX)
      , @RebuildAll BIT
      , @DerivedNotMaterialized INT
      , @MaterializedNotDerived INT
      , @LiveRows INT
      , @Now DATETIME2 (3);

WHILE @Ord <= @MaxOrd
BEGIN
    SELECT @Description = Description
         , @Expectation = Expectation
         , @Statement   = Statement
         , @RebuildAll  = RebuildAll
      FROM @Mutation
     WHERE Ord = @Ord;

    SET @Now = SYSUTCDATETIME ();

    EXEC sys.sp_executesql @Statement;

    -- The rebuild. Half the steps rebuild one profile and half rebuild every profile, on purpose: the per-profile path
    -- is the one with the NOT MATCHED BY SOURCE restriction that would retire other profiles' authority if it were
    -- written into the ON clause instead, and the comparison below covers all three profiles either way -- so a
    -- per-profile rebuild that damaged a bystander would be caught on the step that caused it.
    IF @RebuildAll = 1
    BEGIN
        EXEC auth.uspRebuildProfilePermissionScope;
    END
    ELSE
    BEGIN
        EXEC auth.uspRebuildProfilePermissionScope @UserProfileId = @UmaAgency;
        EXEC auth.uspRebuildProfilePermissionScope @UserProfileId = @UmaProgB;
        EXEC auth.uspRebuildProfilePermissionScope @UserProfileId = @VictorProfile;
    END;

    -- THE DERIVED SET, written out from DES 8.6 rather than copied from the procedure. Any difference between this query
    -- and auth.uspRebuildProfilePermissionScope's MERGE source is either a bug in one of them or a change to the design
    -- that only got made in one place, and all three of those need finding.
    ;WITH Derived AS
    (
        SELECT DISTINCT upr.UserProfileId, rp.PermissionId, upr.ScopeTenantId
          FROM auth.UserProfileRole AS upr
          JOIN auth.UserProfile     AS up ON up.UserProfileId = upr.UserProfileId
          JOIN auth.Role            AS r  ON r.RoleId         = upr.RoleId
          JOIN auth.RolePermission  AS rp ON rp.RoleId        = r.RoleId
          JOIN auth.Permission      AS p  ON p.PermissionId   = rp.PermissionId
         WHERE upr.UserProfileId IN (@UmaAgency, @UmaProgB, @VictorProfile)
           AND upr.IsDeleted = 0
           AND (upr.ExpiresUtc IS NULL OR upr.ExpiresUtc > SYSUTCDATETIME ())
           AND up.IsDeleted = 0
           AND up.IsActive  = 1
           AND r.IsDeleted  = 0
           AND rp.IsDeleted = 0
           AND p.IsDeleted  = 0
    )
    SELECT @DerivedNotMaterialized = COUNT (*)
      FROM (SELECT UserProfileId, PermissionId, ScopeTenantId FROM Derived
            EXCEPT
            SELECT UserProfileId, PermissionId, ScopeTenantId
              FROM auth.ProfilePermissionScope
             WHERE IsDeleted = 0
               AND UserProfileId IN (@UmaAgency, @UmaProgB, @VictorProfile)) AS x;

    ;WITH Derived AS
    (
        SELECT DISTINCT upr.UserProfileId, rp.PermissionId, upr.ScopeTenantId
          FROM auth.UserProfileRole AS upr
          JOIN auth.UserProfile     AS up ON up.UserProfileId = upr.UserProfileId
          JOIN auth.Role            AS r  ON r.RoleId         = upr.RoleId
          JOIN auth.RolePermission  AS rp ON rp.RoleId        = r.RoleId
          JOIN auth.Permission      AS p  ON p.PermissionId   = rp.PermissionId
         WHERE upr.UserProfileId IN (@UmaAgency, @UmaProgB, @VictorProfile)
           AND upr.IsDeleted = 0
           AND (upr.ExpiresUtc IS NULL OR upr.ExpiresUtc > SYSUTCDATETIME ())
           AND up.IsDeleted = 0
           AND up.IsActive  = 1
           AND r.IsDeleted  = 0
           AND rp.IsDeleted = 0
           AND p.IsDeleted  = 0
    )
    SELECT @MaterializedNotDerived = COUNT (*)
      FROM (SELECT UserProfileId, PermissionId, ScopeTenantId
              FROM auth.ProfilePermissionScope
             WHERE IsDeleted = 0
               AND UserProfileId IN (@UmaAgency, @UmaProgB, @VictorProfile)
            EXCEPT
            SELECT UserProfileId, PermissionId, ScopeTenantId FROM Derived) AS x;

    SET @LiveRows = (SELECT COUNT (*)
                       FROM auth.ProfilePermissionScope
                      WHERE IsDeleted = 0
                        AND UserProfileId IN (@UmaAgency, @UmaProgB, @VictorProfile));

    INSERT #Observation (Section, Severity, Status, Item, Detail)
    SELECT N'4 Materialization'
         , CASE WHEN @DerivedNotMaterialized = 0 AND @MaterializedNotDerived = 0 THEN 4 ELSE 1 END
         , CASE WHEN @DerivedNotMaterialized = 0 AND @MaterializedNotDerived = 0 THEN 'OK' ELSE 'VIOLATED' END
         , CONCAT (N'EXIT CRITERION: materialization equals derived -- step ', @Ord, N', ', @Description)
         , CONCAT (N'Expected: ', @Expectation, N' | Missing (a FALSE DENIAL -- the user sees an empty screen): '
                 , @DerivedNotMaterialized, N'. Extra (a FALSE GRANT -- nobody complains): ', @MaterializedNotDerived
                 , N'. Live scope rows across the three profiles: ', @LiveRows, N'. Rebuild was '
                 , CASE WHEN @RebuildAll = 1 THEN N'whole-database' ELSE N'per profile, three calls' END, N'.');

    SET @Ord += 1;
END;
GO


-- *** 4a. The resurrection, which is the half of section 8.6 a count cannot see ***
-- Step 5 revoked uma's reader grant and step 6 gave it back. If the rebuild had removed and re-inserted the scope rows,
-- the counts above would be identical and auditCreatedDateUtc would have moved -- and the difference between "granted in
-- March, briefly revoked in September" and "granted in September" would be gone from the record for good.
DECLARE @UmaAgency INT = (SELECT UmaAgencyProfile FROM #Fixture)
      , @ReadId    INT = (SELECT ReadPermId FROM #Fixture)
      , @Created   DATETIME2 (3)
      , @Modified  DATETIME2 (3);

SELECT @Created  = MIN (auditCreatedDateUtc)
     , @Modified = MAX (auditModifiedDateUtc)
  FROM auth.ProfilePermissionScope
 WHERE UserProfileId = @UmaAgency
   AND PermissionId  = @ReadId
   AND IsDeleted     = 0;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'4a Resurrection'
     , CASE WHEN @Created IS NOT NULL AND @Modified > @Created THEN 4
            WHEN @Created IS NULL THEN 1
            ELSE 3 END
     , CASE WHEN @Created IS NOT NULL AND @Modified > @Created THEN 'OK'
            WHEN @Created IS NULL THEN 'VIOLATED'
            ELSE 'NOTE' END
     , N'A revoked and re-granted authority is resurrected IN PLACE, not re-inserted'
     , CONCAT (N'auditCreatedDateUtc ', CONVERT (NVARCHAR (30), @Created, 126), N', auditModifiedDateUtc '
             , CONVERT (NVARCHAR (30), @Modified, 126), N'. The created stamp survived the revoke-and-restore of steps '
             , N'5 and 6, so the row records WHEN THE AUTHORITY WAS FIRST GIVEN and not when it last came back. A file '
             , N'that only counted rows would have called a delete-and-reinsert a pass.');
GO


-- *** 4b. The functions agree with the table ***
-- auth.udfHasPermission and auth.tvfPermissionScope are what every caller actually asks, and they read the materialized
-- table. If they disagree with it, the table being right is no comfort.
DECLARE @UmaAgency INT, @VictorProfile INT, @AgencyId INT, @Agency2Id INT, @ProgAId INT, @ProgBId INT;

SELECT @UmaAgency = UmaAgencyProfile, @VictorProfile = VictorProfile, @AgencyId = AgencyId
     , @Agency2Id = Agency2Id, @ProgAId = ProgAId, @ProgBId = ProgBId
  FROM #Fixture;

-- Set the identity keys DIRECTLY and WITHOUT @read_only, because this section needs two different profiles on one
-- connection and auth.uspSetSessionContext -- correctly -- will not allow that. Section 5 is where the procedure itself
-- is exercised, and it is last for exactly this reason.
EXEC sp_set_session_context @key = N'UserProfileId',  @value = @UmaAgency;
EXEC sp_set_session_context @key = N'ActingTenantId', @value = @AgencyId;

DECLARE @ReadAtAgency   BIT = auth.udfHasPermission (N'Data.Read', @AgencyId)
      , @ReadAtProgA    BIT = auth.udfHasPermission (N'Data.Read', @ProgAId)
      , @ReadAtAgency2  BIT = auth.udfHasPermission (N'Data.Read', @Agency2Id)
      , @InsertAtAgency BIT = auth.udfHasPermission (N'Data.Insert', @AgencyId)
      , @ScopeCount     INT = (SELECT COUNT (*) FROM auth.tvfPermissionScope (N'Data.Read'));

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'4b Functions'
     , CASE WHEN @ReadAtAgency = 1 AND @ReadAtProgA = 1 AND @ReadAtAgency2 = 0 AND @InsertAtAgency = 0
                 AND @ScopeCount = 3 THEN 4 ELSE 1 END
     , CASE WHEN @ReadAtAgency = 1 AND @ReadAtProgA = 1 AND @ReadAtAgency2 = 0 AND @InsertAtAgency = 0
                 AND @ScopeCount = 3 THEN 'OK' ELSE 'VIOLATED' END
     , N'auth.udfHasPermission and auth.tvfPermissionScope agree with the materialized table'
     , CONCAT (N'uma@agency holds the reader role at the agency. Data.Read at the agency: ', @ReadAtAgency
             , N' (expect 1). At program A, a descendant: ', @ReadAtProgA, N' (expect 1 -- authority flows DOWN the '
             , N'closure). At the sibling agency: ', @ReadAtAgency2, N' (expect 0 -- and this is the one that matters). '
             , N'Data.Insert at the agency: ', @InsertAtAgency, N' (expect 0 -- the reader role does not confer it). '
             , N'auth.tvfPermissionScope (Data.Read) returns ', @ScopeCount, N' tenant(s) (expect 3: the agency and '
             , N'its two programs).');

-- Clear the two writable keys again. Section 5 needs a connection with NO identity, because auth.uspSetSessionContext's
-- three-way branch reads SESSION_CONTEXT (N'UserId') to decide whether an identity is already present -- and these two
-- keys would not fool it, but leaving them set would make section 5's transcript a lie about where the keys came from.
EXEC sp_set_session_context @key = N'UserProfileId',  @value = NULL;
EXEC sp_set_session_context @key = N'ActingTenantId', @value = NULL;
GO


-- *** 5. T-058: a second auth.uspSetSessionContext on ONE connection ***
-- EXIT CRITERION: same profile returns silently, different profile raises E-50022.
--
-- THIS SECTION SPENDS THE CONNECTION'S IDENTITY AND NOTHING AFTER IT CAN SET ANOTHER. The five keys go in read-only, and
-- a read-only key cannot be re-set even to the same value (Msg 15664, measured). Everything below this line therefore
-- reads keys rather than setting them.
DECLARE @UmaId INT, @UmaAgency INT, @UmaProgB INT, @AppId INT, @AgencyId INT, @ProgBId INT;

SELECT @UmaId = UmaUserId, @UmaAgency = UmaAgencyProfile, @UmaProgB = UmaProgBProfile
     , @AppId = ApplicationId, @AgencyId = AgencyId, @ProgBId = ProgBId
  FROM #Fixture;

DECLARE @Now       DATETIME2 (3)  = SYSUTCDATETIME ()
      , @Actor     NVARCHAR (255) = N'_tests/050'
      , @HashA     VARBINARY (32) = HASHBYTES ('SHA2_256', N'_tests/050 session A, uma at the agency')
      , @HashB     VARBINARY (32) = HASHBYTES ('SHA2_256', N'_tests/050 session B, uma at program B')
      , @HashNone  VARBINARY (32) = HASHBYTES ('SHA2_256', N'_tests/050 session C, uma with no active profile')
      , @AttemptId BIGINT;

-- One attempt row, because auth.UserSession.LoginAttemptId is NOT NULL and a session that came from nowhere is a session
-- nobody can trace. Outcome 'Success' drags CK_auth_LoginAttempt_ConcludedPair, _SuccessNeedsUser and
-- _SuccessNeedsPassword along with it, which is the table doing its job.
INSERT auth.LoginAttempt (ApplicationId, UserId, UserName, ClientAddress, AuthenticationMethod, IsBypassRoute
                        , Outcome, PasswordVerified, MfaSatisfied, AttemptedUtc, ConcludedUtc
                        , auditCreatedBy, auditModifiedBy)
VALUES (@AppId, @UmaId, N'authztest.uma', N'198.51.100.50', 'LocalPassword', 0
      , 'Success', 1, 1, @Now, @Now, @Actor, @Actor);

SET @AttemptId = SCOPE_IDENTITY ();

INSERT auth.UserSession (UserId, ActiveUserProfileId, LoginAttemptId, ApplicationId, SessionTokenHash, ClientAddress
                       , AuthenticationMethod, IsBypassRoute, MfaSatisfied, StartedUtc, LastSeenUtc
                       , AbsoluteExpiryUtc, IdleExpiryUtc, auditCreatedBy, auditModifiedBy)
VALUES (@UmaId, @UmaAgency, @AttemptId, @AppId, @HashA, N'198.51.100.50', 'LocalPassword', 0, 1, @Now, @Now
      , DATEADD (HOUR, 8, @Now), DATEADD (HOUR, 1, @Now), @Actor, @Actor)
     , (@UmaId, @UmaProgB,  @AttemptId, @AppId, @HashB, N'198.51.100.50', 'LocalPassword', 0, 1, @Now, @Now
      , DATEADD (HOUR, 8, @Now), DATEADD (HOUR, 1, @Now), @Actor, @Actor)
     , (@UmaId, NULL,       @AttemptId, @AppId, @HashNone, N'198.51.100.50', 'LocalPassword', 0, 1, @Now, @Now
      , DATEADD (HOUR, 8, @Now), DATEADD (HOUR, 1, @Now), @Actor, @Actor);

-- 5a.  The first call. Five keys, and the OUTPUT parameters that let a caller avoid reading them back.
DECLARE @OutUserId INT, @OutProfileId INT, @OutTenantId INT, @ErrNo INT = NULL, @ErrMsg NVARCHAR (2048) = NULL;

BEGIN TRY
    EXEC auth.uspSetSessionContext @SessionTokenHash = @HashA
                                , @UserId         = @OutUserId    OUTPUT
                                , @UserProfileId  = @OutProfileId OUTPUT
                                , @ActingTenantId = @OutTenantId  OUTPUT;
END TRY
BEGIN CATCH
    SELECT @ErrNo = ERROR_NUMBER (), @ErrMsg = LEFT (ERROR_MESSAGE (), 500);
END CATCH;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'5 Session context'
     , CASE WHEN @ErrNo IS NULL
                 AND TRY_CAST (SESSION_CONTEXT (N'UserId') AS INT)         = @UmaId
                 AND TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT)  = @UmaAgency
                 AND TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT) = @AgencyId
                 AND CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)) = N'authztest.uma'
                 AND TRY_CAST (SESSION_CONTEXT (N'ApplicationId') AS INT)  = @AppId
                 AND @OutProfileId = @UmaAgency THEN 4 ELSE 1 END
     , CASE WHEN @ErrNo IS NULL AND TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT) = @UmaAgency
                THEN 'OK' ELSE 'VIOLATED' END
     , N'The first auth.uspSetSessionContext sets all five keys and returns the identity'
     , CONCAT (N'Error ', COALESCE (CAST (@ErrNo AS NVARCHAR (11)), N'(none)'), N'. UserId '
             , COALESCE (CAST (TRY_CAST (SESSION_CONTEXT (N'UserId') AS INT) AS NVARCHAR (11)), N'(absent)')
             , N', UserProfileId '
             , COALESCE (CAST (TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT) AS NVARCHAR (11)), N'(absent)')
             , N', ActingTenantId '
             , COALESCE (CAST (TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT) AS NVARCHAR (11)), N'(absent)')
             , N', AppUser ', COALESCE (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'(absent)')
             , N', ApplicationId '
             , COALESCE (CAST (TRY_CAST (SESSION_CONTEXT (N'ApplicationId') AS INT) AS NVARCHAR (11)), N'(absent)')
             , N'. OUTPUT parameters: ', @OutUserId, N'/', @OutProfileId, N'/', @OutTenantId, N'. '
             , COALESCE (@ErrMsg, N''));

-- 5b.  The same session again. Section 14.3: absent then set is the first call, EQUAL is SILENT, different is E-50022.
--      Silent is not "sets them again" -- it cannot, and that is the point: re-setting a read-only key to the same value
--      fails with Msg 15664, so the procedure must detect the equality and do nothing rather than try.
SET @ErrNo = NULL; SET @ErrMsg = NULL;
SET @OutProfileId = NULL;

BEGIN TRY
    EXEC auth.uspSetSessionContext @SessionTokenHash = @HashA
                                , @UserProfileId  = @OutProfileId OUTPUT;
END TRY
BEGIN CATCH
    SELECT @ErrNo = ERROR_NUMBER (), @ErrMsg = LEFT (ERROR_MESSAGE (), 500);
END CATCH;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'5 Session context'
     , CASE WHEN @ErrNo IS NULL AND TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT) = @UmaAgency THEN 4 ELSE 1 END
     , CASE WHEN @ErrNo IS NULL AND TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT) = @UmaAgency
                THEN 'OK' ELSE 'VIOLATED' END
     , N'EXIT CRITERION: the SAME profile a second time returns silently'
     , CONCAT (N'Error ', COALESCE (CAST (@ErrNo AS NVARCHAR (11)), N'(none, as required)'), N'. UserProfileId is still '
             , COALESCE (CAST (TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT) AS NVARCHAR (11)), N'(absent)')
             , N' and the OUTPUT parameter came back as '
             , COALESCE (CAST (@OutProfileId AS NVARCHAR (11)), N'(null)')
             , N'. A pooled connection that serves two requests for the same signed-in profile must not fail on the '
             , N'second one; it also must not try to re-set the key, because Msg 15664 would make that an error the '
             , N'application could do nothing about. ', COALESCE (@ErrMsg, N''));

-- 5c.  A DIFFERENT profile, same user, same connection. E-50022, and the keys must be untouched afterwards: the refusal
--      happens BEFORE the touch, so a rejected request leaves no trace on the session it was refused for.
SET @ErrNo = NULL; SET @ErrMsg = NULL;

BEGIN TRY
    EXEC auth.uspSetSessionContext @SessionTokenHash = @HashB;
END TRY
BEGIN CATCH
    SELECT @ErrNo = ERROR_NUMBER (), @ErrMsg = LEFT (ERROR_MESSAGE (), 500);
END CATCH;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'5 Session context'
     , CASE WHEN @ErrNo = 50022 AND TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT) = @UmaAgency THEN 4 ELSE 1 END
     , CASE WHEN @ErrNo = 50022 AND TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT) = @UmaAgency
                THEN 'OK' ELSE 'VIOLATED' END
     , N'EXIT CRITERION: a DIFFERENT profile on the same connection raises E-50022 and changes nothing'
     , CONCAT (N'Error ', COALESCE (CAST (@ErrNo AS NVARCHAR (11)), N'(none -- WHICH MEANS TWO PROFILES SHARED ONE '
             + N'CONNECTION)'), N', expected 50022. UserProfileId after the refusal: '
             , COALESCE (CAST (TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT) AS NVARCHAR (11)), N'(absent)')
             , N', expected ', @UmaAgency, N' -- the FIRST profile, unchanged. This is UI-06 for the application: a '
             , N'connection serves one profile, so a request that switches profile must take a new connection or the '
             , N'pool must reset. ', COALESCE (@ErrMsg, N''));

-- 5d.  And the identity cannot be given back. auth.uspClearSessionContext clears the bypass and REPORTS that the
--      identity remains, which is the only honest thing it can do -- a read-only key cannot be set to NULL.
DECLARE @Remain BIT = NULL;

EXEC auth.uspClearSessionContext @IdentityKeysRemain = @Remain OUTPUT;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'5 Session context'
     , CASE WHEN @Remain = 1 AND TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT) = @UmaAgency THEN 4 ELSE 2 END
     , CASE WHEN @Remain = 1 AND TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT) = @UmaAgency
                THEN 'OK' ELSE 'DEFECT' END
     , N'auth.uspClearSessionContext reports that the identity remains and does not pretend otherwise'
     , CONCAT (N'@IdentityKeysRemain = ', COALESCE (CAST (@Remain AS NVARCHAR (11)), N'(null)'), N', expected 1. The '
             , N'five identity keys are read-only and Msg 15664 makes them permanent for the life of the connection. A '
             , N'procedure that returned 0 here would be telling a background job it was nobody while it went on acting '
             , N'as authztest.uma -- which is why the parameter reports rather than promises.');

-- 5e.  G-12: the two columns a page header warns from, proved on the only connection in this directory that can.
--
-- WHY HERE AND NOWHERE ELSE
--
-- auth.uspGetProfileContext INNER JOINs auth.UserProfile on the session-context UserProfileId, so it needs a
-- PROFILE-BEARING session.  _tests/040_identity_and_authn.sql has no auth.UserProfile rows anywhere in its fixture and
-- cannot grow one without becoming a different test; _tests/080_error_catalogue.sql is error probes and this refuses
-- nothing.  Section 5a of this file has already put uma's agency hat on this connection, which is exactly the state the
-- procedure is written for -- and it costs nothing more, because the procedure sets the same context it finds (5b) and
-- that is silent by design.
--
-- WHY THE WHOLE 32-COLUMN SHAPE IS SPELLED OUT
--
-- INSERT ... EXEC demands a target whose column COUNT matches the result set, so the shape has to be written down.  That
-- is a feature rather than a cost: auth.uspGetProfileContext is the one procedure the UI calls on every page load, the
-- handoff in docs/40-ui-handoff-m4.md publishes its columns, and a column silently added in the middle of that SELECT
-- would now fail here instead of arriving in a front-end sprint.  The types are deliberately generous -- INSERT ... EXEC
-- converts -- because this asserts the CONTRACT's shape and the values of two columns, not the widths of the other thirty.
CREATE TABLE #ProfileContext
(
    RowNo                  INT IDENTITY (1, 1) PRIMARY KEY,
    UserId                 INT             NULL, UserName               NVARCHAR (400)  NULL,
    DisplayName            NVARCHAR (400)  NULL, Email                  NVARCHAR (400)  NULL,
    IsPlatformAdmin        BIT             NULL, MustChangePassword     BIT             NULL,
    PasswordExpiresInDays  INT             NULL, PasswordExpiryWarning  BIT             NULL,
    PasswordExpiresUtc     DATETIME2 (7)   NULL, UserProfileId          INT             NULL,
    ProfileName            NVARCHAR (400)  NULL, IsDefaultProfile       BIT             NULL,
    ActingTenantId         INT             NULL, ActingTenantCode       NVARCHAR (400)  NULL,
    ActingTenantName       NVARCHAR (400)  NULL, ActingTenantPath       NVARCHAR (4000) NULL,
    ActingTenantTypeCode   NVARCHAR (400)  NULL, ActingTenantTypeName   NVARCHAR (400)  NULL,
    ActingTenantDepth      INT             NULL, RootTenantId           INT             NULL,
    ApplicationCode        NVARCHAR (400)  NULL, AppUser                NVARCHAR (400)  NULL,
    UserSessionId          BIGINT          NULL, SessionStartedUtc      DATETIME2 (7)   NULL,
    SessionLastSeenUtc     DATETIME2 (7)   NULL, AbsoluteExpiryUtc      DATETIME2 (7)   NULL,
    IdleExpiryUtc          DATETIME2 (7)   NULL, ElevatedUntilUtc       DATETIME2 (7)   NULL,
    MfaSatisfied           BIT             NULL, AuthenticationMethod   NVARCHAR (100)  NULL,
    IsBypassRoute          BIT             NULL, SwitchableProfileCount INT             NULL
);

-- The credential is a direct write for the same reason section 3's fixture is: nothing shipped writes
-- auth.UserCredential except auth.uspSetPassword, which would demand a permission this profile does not hold and would
-- force MustChangePassword = 1 into the middle of a measurement about a DIFFERENT flag.  The verifier says in its own
-- salt that it is not a real one.
DECLARE @UmaCredId INT
      , @WarnDays  INT = COALESCE (TRY_CAST ((SELECT cs.SettingValue
                                                FROM config.ApplicationSetting AS cs
                                               WHERE cs.SettingKey = N'Authn.PasswordExpiryWarningDays'
                                                 AND cs.IsDeleted  = 0) AS INT), 0)
      , @InDays    INT
      , @WantWarn  BIT;

SET @InDays   = CASE WHEN @WarnDays >= 2 THEN @WarnDays - 1 ELSE 0 END;
SET @WantWarn = CASE WHEN @WarnDays > 0 THEN 1 ELSE 0 END;

IF NOT EXISTS (SELECT 1 FROM auth.UserCredential AS c
                WHERE c.UserId = @UmaId AND c.CredentialType = 'Password' AND c.IsDeleted = 0)
    INSERT auth.UserCredential (UserId, CredentialType, VerifierPhc, LastChangedUtc, auditCreatedBy, auditModifiedBy)
    VALUES (@UmaId, 'Password'
          , N'$argon2id$v=19$m=65536,t=3,p=4$MDUwLWF1dGh6LXNlc3Npb24tZml4$bm90LWEtcmVhbC12ZXJpZmllci1ldmVyLWFueXdoZXJl'
          , SYSUTCDATETIME (), @Actor, @Actor);

SELECT @UmaCredId = c.UserCredentialId FROM auth.UserCredential AS c
 WHERE c.UserId = @UmaId AND c.CredentialType = 'Password' AND c.IsDeleted = 0;

-- Case 1: inside the warning window.  ExpiresUtc is set from the SETTING rather than from a literal, so a deployment that
-- shortens the window to three days still measures the rule instead of failing on the arithmetic.
--
-- LastChangedUtc is dated back ninety days in both cases because CK_auth_UserCredential_ExpiresUtc demands
-- ExpiresUtc > LastChangedUtc.  A credential that expires today or expired last week necessarily had its verifier set
-- before that, and the constraint is right to say so -- so the fixture is a password changed a quarter ago rather than one
-- changed this instant and expiring in the same tick.
UPDATE auth.UserCredential
   SET LastChangedUtc  = DATEADD (DAY, -90, SYSUTCDATETIME ())
     , ExpiresUtc      = DATEADD (DAY, @InDays, SYSUTCDATETIME ())
     , auditModifiedBy = @Actor
 WHERE UserCredentialId = @UmaCredId;

INSERT #ProfileContext
    (UserId, UserName, DisplayName, Email, IsPlatformAdmin, MustChangePassword, PasswordExpiresInDays
   , PasswordExpiryWarning, PasswordExpiresUtc, UserProfileId, ProfileName, IsDefaultProfile, ActingTenantId
   , ActingTenantCode, ActingTenantName, ActingTenantPath, ActingTenantTypeCode, ActingTenantTypeName
   , ActingTenantDepth, RootTenantId, ApplicationCode, AppUser, UserSessionId, SessionStartedUtc, SessionLastSeenUtc
   , AbsoluteExpiryUtc, IdleExpiryUtc, ElevatedUntilUtc, MfaSatisfied, AuthenticationMethod, IsBypassRoute
   , SwitchableProfileCount)
EXEC auth.uspGetProfileContext @SessionTokenHash = @HashA;

-- Case 2: PAST the deadline.  The warning must STAY up and the count must go NEGATIVE -- auth.uspExpireCredentials is a
-- batched sweep, so this is the real state of a credential between its expiry and the next run, and a header that went
-- quiet in that gap would go quiet at the one moment the user has to act.
UPDATE auth.UserCredential
   SET LastChangedUtc  = DATEADD (DAY, -90, SYSUTCDATETIME ())
     , ExpiresUtc      = DATEADD (DAY, -3, SYSUTCDATETIME ())
     , auditModifiedBy = @Actor
 WHERE UserCredentialId = @UmaCredId;

INSERT #ProfileContext
    (UserId, UserName, DisplayName, Email, IsPlatformAdmin, MustChangePassword, PasswordExpiresInDays
   , PasswordExpiryWarning, PasswordExpiresUtc, UserProfileId, ProfileName, IsDefaultProfile, ActingTenantId
   , ActingTenantCode, ActingTenantName, ActingTenantPath, ActingTenantTypeCode, ActingTenantTypeName
   , ActingTenantDepth, RootTenantId, ApplicationCode, AppUser, UserSessionId, SessionStartedUtc, SessionLastSeenUtc
   , AbsoluteExpiryUtc, IdleExpiryUtc, ElevatedUntilUtc, MfaSatisfied, AuthenticationMethod, IsBypassRoute
   , SwitchableProfileCount)
EXEC auth.uspGetProfileContext @SessionTokenHash = @HashA;

DECLARE @Ctx1Days INT  = (SELECT PasswordExpiresInDays FROM #ProfileContext WHERE RowNo = 1)
      , @Ctx1Warn BIT  = (SELECT PasswordExpiryWarning FROM #ProfileContext WHERE RowNo = 1)
      , @Ctx2Days INT  = (SELECT PasswordExpiresInDays FROM #ProfileContext WHERE RowNo = 2)
      , @Ctx2Warn BIT  = (SELECT PasswordExpiryWarning FROM #ProfileContext WHERE RowNo = 2)
      , @CtxProf  INT  = (SELECT UserProfileId         FROM #ProfileContext WHERE RowNo = 1)
      , @CtxRows  INT  = (SELECT COUNT (*)             FROM #ProfileContext);

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'5 Session context'
     , CASE WHEN @CtxRows = 2 AND @CtxProf = @UmaAgency
                 AND @Ctx1Days = @InDays AND @Ctx1Warn = @WantWarn
                 AND @Ctx2Days = -3      AND @Ctx2Warn = @WantWarn THEN 4 ELSE 2 END
     , CASE WHEN @CtxRows = 2 AND @CtxProf = @UmaAgency
                 AND @Ctx1Days = @InDays AND @Ctx1Warn = @WantWarn
                 AND @Ctx2Days = -3      AND @Ctx2Warn = @WantWarn THEN 'OK' ELSE 'DEFECT' END
     , N'G-12: auth.uspGetProfileContext counts down to the expiry and keeps warning after it'
     , CONCAT (N'Authn.PasswordExpiryWarningDays = ', @WarnDays, N'. Inside the window: PasswordExpiresInDays '
             , COALESCE (CAST (@Ctx1Days AS NVARCHAR (11)), N'(null)'), N', expected ', @InDays
             , N', PasswordExpiryWarning ', COALESCE (CAST (@Ctx1Warn AS NVARCHAR (11)), N'(null)'), N', expected '
             , @WantWarn, N'. Three days PAST the deadline: PasswordExpiresInDays '
             , COALESCE (CAST (@Ctx2Days AS NVARCHAR (11)), N'(null)'), N', expected -3 -- NOT clamped at zero, because '
             , N'the interval between the deadline and the next auth.uspExpireCredentials sweep is worth seeing -- and '
             , N'PasswordExpiryWarning ', COALESCE (CAST (@Ctx2Warn AS NVARCHAR (11)), N'(null)'), N', expected '
             , @WantWarn, N' still. The row came back for profile '
             , COALESCE (CAST (@CtxProf AS NVARCHAR (11)), N'(none)'), N', expected ', @UmaAgency
             , N' -- the hat this connection is wearing, which is the whole reason this observation lives in section 5. '
             , N'Neither column is any part of the credential: a date and a count, never the verifier (UI-16).');

-- The expiry goes back to NULL, which is what every credential in a deployment with Authn.PasswordLifetimeDays = 0 looks
-- like.  The credential row itself stays: it belongs to this file's own fixture user, and a soft-deleted credential would
-- be re-created on the next run for no reason.
UPDATE auth.UserCredential
   SET ExpiresUtc      = NULL
     , auditModifiedBy = @Actor
 WHERE UserCredentialId = @UmaCredId;
GO


-- *** 6. The report, and the verdict ***
-- Severity 1 is an exit criterion that did not hold; 2 is a defect that is not itself an exit criterion; 3 is a note the
-- reader needs; 4 is an observation that came out as intended. The THROW at the end fires on 1 or 2 and nothing else.
INSERT #Observation (Section, Severity, Status, Item, Detail)
VALUES (N'6 Not tested', 3, 'NOTE'
      , N'Nothing here is concurrent, and the materialization''s locking is therefore unexamined'
      , N'Every step in section 4 mutates and then rebuilds, alone. Two rebuilds of one profile racing, or a grant '
      + N'committed between a rebuild''s MERGE and a reader''s seek, is a load question this file cannot answer. What '
      + N'it does establish is that the SET is right whenever the rebuild is allowed to finish, which is the property '
      + N'gap G-03 asked for.')
     , (N'6 Not tested', 3, 'NOTE'
      , N'Row-level security is not exercised here -- see _tests/060_row_security.sql'
      , N'Section 4b proves auth.udfHasPermission and auth.tvfPermissionScope agree with the table. Whether the RLS '
      + N'predicates built from the same table actually hide a row is a different experiment, on tables the policy '
      + N'binds, and it needs its own connection because it impersonates.')
     , (N'6 Not tested', 3, 'NOTE'
      , N'The session with NO active profile was created and not driven through the procedure'
      , N'The third session row in section 5 has ActiveUserProfileId NULL, which section 8.5 and UI-09 require to be a '
      + N'VALID session that receives three keys instead of five. It cannot be exercised on this connection, because by '
      + N'the time it could be tried the five read-only keys are already set and the three-way branch would refuse it '
      + N'with E-50022 -- correctly. The row is left in place for a single-purpose run and the shape is asserted by '
      + N'105_auth_session_procedures.sql''s own report.');

SELECT Severity, Status, Section, Item, Detail
  FROM #Observation
 ORDER BY RowNo;
GO

-- The exit criteria, counted separately from the experiments, because "no failures" and "the criteria were actually
-- exercised" are different claims and a file that only makes the first can pass by omission.
DECLARE @Criteria TABLE (Criterion NVARCHAR (200) NOT NULL, Marker NVARCHAR (200) NOT NULL);

INSERT @Criteria (Criterion, Marker)
VALUES (N'Materialization equals derived after an arbitrary sequence of changes (T-057)'
      , N'EXIT CRITERION: materialization equals derived')
     , (N'The same profile twice on one connection returns silently (T-058)'
      , N'EXIT CRITERION: the SAME profile a second time')
     , (N'A different profile on one connection raises E-50022 (T-058)'
      , N'EXIT CRITERION: a DIFFERENT profile on the same connection');

SELECT c.Criterion
     , Exercised = (SELECT COUNT (*) FROM #Observation AS o WHERE o.Item LIKE N'%' + c.Marker + N'%')
     , Failed    = (SELECT COUNT (*) FROM #Observation AS o
                     WHERE o.Item LIKE N'%' + c.Marker + N'%' AND o.Severity <= 2)
  FROM @Criteria AS c;
GO

DECLARE @Violations INT = (SELECT COUNT (*) FROM #Observation WHERE Severity = 1)
      , @Defects    INT = (SELECT COUNT (*) FROM #Observation WHERE Severity = 2)
      , @Notes      INT = (SELECT COUNT (*) FROM #Observation WHERE Severity = 3)
      , @AsIntended INT = (SELECT COUNT (*) FROM #Observation WHERE Severity = 4);

IF @Violations > 0 OR @Defects > 0
BEGIN
    DECLARE @Fail NVARCHAR (2000) =
        CONCAT (N'Phase 3 authorization and session context: ', @Violations, N' exit-criterion violation(s) and '
              , @Defects, N' defect(s). The rows above carry the detail. Nothing has been cleaned up -- the fixture, '
              , N'its grants and its sessions are all still in place to be read, and the next run of this file resets '
              , N'them.');

    ;THROW 50000, @Fail, 1;
END;

PRINT CONCAT (N'Phase 3 authorization and session context: no problems found. ', @AsIntended, N' observation(s) came '
            , N'out as intended, with ', @Notes, N' note(s). Fourteen mutations, and after every one of them the '
            , N'materialized scope equalled the set derived from the live grants in both directions. A second '
            , N'uspSetSessionContext for the same profile returned silently and for a different profile refused with '
            , N'E-50022, leaving the first profile''s keys untouched.');
GO
