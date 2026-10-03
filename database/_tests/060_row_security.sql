/***********************************************************************************************************************
Script:         _tests/060_row_security.sql
Purpose:        The Phase 4 exit criteria, on live rows in two bound tables:
                  *  the whole DES 10.3 matrix -- read in scope and out of it, insert into the acting tenant and into
                     another one, update of a row that is readable but not writable, and an attempted tenant MOVE in
                     both directions (T-067);
                  *  the demonstration that a db_owner connection with no session context sees ZERO rows while four
                     rows sit in the table, and that the bypass key is what brings them back (T-068, UI-18);
                  *  the maintenance-bypass window end to end, under a real member of rlsBypassRole, including both
                     logs.AuthenticationEvent rows and the fact that ORIGINAL_LOGIN survives impersonation (T-066).
Target:         SQL Server 2022 or newer.
Run as:         db_owner in the target database.  The file creates and drops its own database user WITHOUT LOGIN.
Run in:         The target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/_tests/060_row_security.sql
Idempotent:     Yes.  Section 3 soft-deletes the previous run's case files and notes before it rebuilds them, and
                section 8 removes the bypass user it created.
Depends on:     025_config_tables.sql, 030_auth_tenant.sql, 040_auth_userprofile.sql, 050_auth_permission.sql,
                055_auth_role.sql, 060_auth_profile_role.sql, 065_auth_effective_permission.sql,
                085_logs_auth_tables.sql, 100_auth_functions.sql, 105_auth_session_procedures.sql,
                090_dbo_application.sql (the demo tables dbo.CaseFile and dbo.CaseNote), 120_rls_policy.sql,
                125_auth_tenant_procedures.sql.
                Builds its own fixture and depends on no other test file.
Implements:     PLAN-AUTH-001 Phase 4 exit criteria.  Tasks T-066, T-067 and T-068.  DES-AUTH-001 sections 10.1, 10.2,
                10.3, 10.5 and 21.3.  INV-04, INV-05.  UI-18.

WHY THIS FILE RE-BUILDS THE POLICY BEFORE IT TESTS ANYTHING
----------------------------------------------------------
The three predicate functions carry a LITERAL list of permission ids -- "pps.PermissionId IN (7, 19, 33)" -- because a
predicate must be schema-bound and cannot join auth.Permission by code (DES 10.2, BL-039).  auth.uspRebuildTenantAccessPolicy
resolves that list at build time.  So a fixture that invents its own Data.Read row and does NOT re-run the rebuild is
testing a policy that has never heard of its permissions, and every assertion below would "pass" by denying everything.

Section 4 therefore EXECs the rebuild after the fixture exists, and the observation it records prints the lists that ended
up in the functions.  This is the same hazard a real project meets on the day it adds a permission: the catalogue changed
and the policy did not, and nothing complains, because a stale list is a SILENT DENIAL (UI-35).

WHY THE SEEDING NEEDS THE BYPASS KEY
-----------------------------------
Once the policy is on, dbo cannot insert a row into a tenant it is not acting for -- that is the point of the block
predicate, and section 6 proves it.  Rows therefore have to be planted with SESSION_CONTEXT (N'BypassRowSecurity') set to
1, which is writable and clearable, and the key is cleared again before a single assertion runs.  If it were left set,
every count below would be the full count and the file would report a clean pass while proving nothing.  Section 5 checks
that the key really is off before the matrix starts.

WHAT 33504 MEANS BELOW
---------------------
Msg 33504 is "the attempted operation failed because the target object has a block predicate that conflicts with this
operation".  Every refusal in section 6 expects it by number.  A refusal that came back as some other error -- a check
constraint, a foreign key, a permission -- would be the right outcome for the wrong reason, and the matrix would be
worthless, so the number is asserted and not just the failure.

THE ONE THING RLS DOES NOT DO HERE
---------------------------------
The policy binds four predicates per table: the FILTER, BLOCK AFTER INSERT, BLOCK BEFORE UPDATE and BLOCK AFTER UPDATE.
There is no delete predicate, because this database has no hard deletes -- removal is an UPDATE that sets IsDeleted, and
BLOCK BEFORE UPDATE governs it (section 6h).  A hard DELETE aimed at an out-of-scope row would not be blocked; it would
match nothing, because the filter has already hidden the row.  That is protection by invisibility, and it is worth
knowing which of the two you are relying on.

***********************************************************************************************************************/
SET NOCOUNT ON;
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

-- *** 0. Assert the target ***
IF DB_NAME () <> N'$(DbName)'
BEGIN
    ;THROW 50000, N'This script must run against the database named by -v DbName. Start sqlcmd with -v DbName=<database> and do not add a :setvar line to this file: an in-file :setvar overrides -v, and a row-security test that plants rows in the wrong database leaves them there.', 1;
END;
GO

USE [$(DbName)];
GO


-- *** 1. Assert the machinery ***
DECLARE @Missing NVARCHAR (MAX) = NULL;

SELECT @Missing = STRING_AGG (x.ObjectName, N', ') WITHIN GROUP (ORDER BY x.ObjectName)
  FROM (VALUES (N'dbo.CaseFile',                        N'U')
             , (N'dbo.CaseNote',                        N'U')
             , (N'config.TenantScopedTable',            N'U')
             , (N'auth.ProfilePermissionScope',         N'U')
             , (N'auth.TenantClosure',                  N'U')
             , (N'logs.AuthenticationEvent',            N'U')
             , (N'auth.tvfTenantReadPredicate',         N'IF')
             , (N'auth.tvfTenantInsertPredicate',       N'IF')
             , (N'auth.tvfTenantUpdatePredicate',       N'IF')
             , (N'auth.uspRebuildTenantAccessPolicy',   N'P')
             , (N'auth.uspRebuildProfilePermissionScope', N'P')
             , (N'auth.uspRebuildTenantClosure',        N'P')
             , (N'auth.uspBeginMaintenanceSession',     N'P')
             , (N'auth.uspEndMaintenanceSession',       N'P')) AS x (ObjectName, ObjectType)
 WHERE OBJECT_ID (x.ObjectName, x.ObjectType) IS NULL;

IF @Missing IS NOT NULL
BEGIN
    DECLARE @Failure NVARCHAR (2048) = N'The Phase 4 machinery is incomplete: ' + @Missing
        + N' is missing. Run the numbered scripts through 120_rls_policy.sql first.';
    ;THROW 50000, @Failure, 1;
END;

IF DATABASE_PRINCIPAL_ID (N'rlsBypassRole') IS NULL
BEGIN
    ;THROW 50000, N'rlsBypassRole does not exist in this database, so the maintenance-bypass window in section 7 cannot be tested with a real member. Run 020_roles.sql.', 1;
END;
GO


-- *** 2. The observation log ***
CREATE TABLE #Observation
(
    RowNo     INT IDENTITY (1, 1) PRIMARY KEY,
    Section   NVARCHAR (60)  NOT NULL,
    Severity  INT            NOT NULL,   -- 1 = exit criterion violated, 2 = defect, 3 = note, 4 = observed as intended
    Status    VARCHAR (10)   NOT NULL,
    Item      NVARCHAR (200) NOT NULL,
    Detail    NVARCHAR (4000)    NULL
);

CREATE TABLE #Fixture
(
    ApplicationId INT NULL, RootTenantId INT NULL, AgencyId INT NULL, Agency2Id INT NULL,
    ProgAId       INT NULL, ProgBId      INT NULL,
    CarlaProfile  INT NULL, PatProfile   INT NULL, OliveProfile INT NULL,
    ReadPermId    INT NULL, InsertPermId INT NULL, UpdatePermId INT NULL
);
GO


-- *** 3. The fixture ***
-- Carla is the subject of the whole matrix. She contributes at program A and only READS at program B, which is what makes
-- "readable but not writable" a real state rather than a contrivance: it is the ordinary shape of a caseworker who can
-- see a neighbouring programme's files and must not touch them.
--
--   ROWSEC_ROOT
--     +-- ROWSEC_AGENCY
--     |     +-- ROWSEC_PROG_A   carla: read + insert + update      <- ActingTenantId for the matrix
--     |     +-- ROWSEC_PROG_B   carla: read only
--     +-- ROWSEC_AGENCY2        carla: nothing at all
DECLARE @Now   DATETIME2 (3)  = SYSUTCDATETIME ()
      , @Actor NVARCHAR (255) = N'_tests/060';

DECLARE @AppId INT, @RootId INT, @AgencyId INT, @Agency2Id INT, @ProgAId INT, @ProgBId INT
      , @CategoryId INT, @ReadId INT, @InsertId INT, @UpdateId INT
      , @ContribRole INT, @ReaderRole INT
      , @CarlaId INT, @PatId INT, @OliveId INT
      , @CarlaProfile INT, @PatProfile INT, @OliveProfile INT;

IF NOT EXISTS (SELECT 1 FROM auth.Application WHERE ApplicationCode = N'ROWSEC')
BEGIN
    INSERT auth.Application (ApplicationCode, ApplicationName, IsActive, auditCreatedBy, auditModifiedBy)
    VALUES (N'ROWSEC', N'Row security test application', 1, @Actor, @Actor);
END;

SELECT @AppId = ApplicationId FROM auth.Application WHERE ApplicationCode = N'ROWSEC';

-- One level per statement, parent first: CK_auth_Tenant_RootHasNoParent will not hold an orphan for the length of a
-- single MERGE, so there is no insert-then-adopt.
IF NOT EXISTS (SELECT 1 FROM auth.Tenant WHERE ApplicationId = @AppId AND TenantCode = N'ROWSEC_ROOT')
BEGIN
    INSERT auth.Tenant (ApplicationId, TenantCode, TenantName, TenantTypeId, TenantTypeCode, ParentTenantId, IsActive
                      , auditCreatedBy, auditModifiedBy)
    VALUES (@AppId, N'ROWSEC_ROOT', N'Rowsec root', 1, N'Root', NULL, 1, @Actor, @Actor);
END;

SELECT @RootId = TenantId FROM auth.Tenant WHERE ApplicationId = @AppId AND TenantCode = N'ROWSEC_ROOT';

MERGE auth.Tenant AS tgt
USING (VALUES (N'ROWSEC_AGENCY',  N'Rowsec agency',   2, N'Agency')
            , (N'ROWSEC_AGENCY2', N'Rowsec agency 2', 2, N'Agency')) AS src (TenantCode, TenantName, TypeId, TypeCode)
   ON tgt.ApplicationId = @AppId AND tgt.TenantCode = src.TenantCode
WHEN MATCHED THEN
    UPDATE SET tgt.ParentTenantId = @RootId, tgt.IsActive = 1, tgt.IsDeleted = 0
             , tgt.auditDeletedBy = NULL, tgt.auditDeletedDateUtc = NULL
             , tgt.auditModifiedBy = @Actor, tgt.auditModifiedDateUtc = @Now
WHEN NOT MATCHED BY TARGET THEN
    INSERT (ApplicationId, TenantCode, TenantName, TenantTypeId, TenantTypeCode, ParentTenantId, IsActive
          , auditCreatedBy, auditModifiedBy)
    VALUES (@AppId, src.TenantCode, src.TenantName, src.TypeId, src.TypeCode, @RootId, 1, @Actor, @Actor);

SELECT @AgencyId  = TenantId FROM auth.Tenant WHERE ApplicationId = @AppId AND TenantCode = N'ROWSEC_AGENCY';
SELECT @Agency2Id = TenantId FROM auth.Tenant WHERE ApplicationId = @AppId AND TenantCode = N'ROWSEC_AGENCY2';

MERGE auth.Tenant AS tgt
USING (VALUES (N'ROWSEC_PROG_A', N'Rowsec program A', 4, N'Program')
            , (N'ROWSEC_PROG_B', N'Rowsec program B', 4, N'Program')) AS src (TenantCode, TenantName, TypeId, TypeCode)
   ON tgt.ApplicationId = @AppId AND tgt.TenantCode = src.TenantCode
WHEN MATCHED THEN
    UPDATE SET tgt.ParentTenantId = @AgencyId, tgt.IsActive = 1, tgt.IsDeleted = 0
             , tgt.auditDeletedBy = NULL, tgt.auditDeletedDateUtc = NULL
             , tgt.auditModifiedBy = @Actor, tgt.auditModifiedDateUtc = @Now
WHEN NOT MATCHED BY TARGET THEN
    INSERT (ApplicationId, TenantCode, TenantName, TenantTypeId, TenantTypeCode, ParentTenantId, IsActive
          , auditCreatedBy, auditModifiedBy)
    VALUES (@AppId, src.TenantCode, src.TenantName, src.TypeId, src.TypeCode, @AgencyId, 1, @Actor, @Actor);

SELECT @ProgAId = TenantId FROM auth.Tenant WHERE ApplicationId = @AppId AND TenantCode = N'ROWSEC_PROG_A';
SELECT @ProgBId = TenantId FROM auth.Tenant WHERE ApplicationId = @AppId AND TenantCode = N'ROWSEC_PROG_B';

EXEC auth.uspRebuildTenantClosure;

IF NOT EXISTS (SELECT 1 FROM auth.PermissionCategory WHERE CategoryCode = N'Data')
BEGIN
    INSERT auth.PermissionCategory (CategoryCode, CategoryName, SortOrder, auditCreatedBy, auditModifiedBy)
    VALUES (N'Data', N'Data', 10, @Actor, @Actor);
END;

SELECT @CategoryId = PermissionCategoryId FROM auth.PermissionCategory WHERE CategoryCode = N'Data';

-- The three codes the predicates are built from, and no others: this fixture has nothing to say about Data.Export.
MERGE auth.Permission AS tgt
USING (VALUES (N'Data.Read', N'Read data'), (N'Data.Insert', N'Create data'), (N'Data.Update', N'Edit data'))
      AS src (PermissionCode, PermissionName)
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

MERGE auth.Role AS tgt
USING (VALUES (N'ROWSEC_CONTRIB', N'Rowsec contributor'), (N'ROWSEC_READER', N'Rowsec reader'))
      AS src (RoleCode, RoleName)
   ON tgt.ApplicationId = @AppId AND tgt.OwnerTenantId = @RootId AND tgt.RoleCode = src.RoleCode
WHEN MATCHED THEN
    UPDATE SET tgt.IsDeleted = 0, tgt.IsAssignable = 1, tgt.auditDeletedBy = NULL, tgt.auditDeletedDateUtc = NULL
             , tgt.auditModifiedBy = @Actor, tgt.auditModifiedDateUtc = @Now
WHEN NOT MATCHED BY TARGET THEN
    INSERT (ApplicationId, OwnerTenantId, RoleCode, RoleName, IsAssignable, IsSystemRole, auditCreatedBy, auditModifiedBy)
    VALUES (@AppId, @RootId, src.RoleCode, src.RoleName, 1, 1, @Actor, @Actor);

SELECT @ContribRole = RoleId FROM auth.Role WHERE ApplicationId = @AppId AND OwnerTenantId = @RootId AND RoleCode = N'ROWSEC_CONTRIB';
SELECT @ReaderRole  = RoleId FROM auth.Role WHERE ApplicationId = @AppId AND OwnerTenantId = @RootId AND RoleCode = N'ROWSEC_READER';

MERGE auth.RolePermission AS tgt
USING (VALUES (@ContribRole, @ReadId), (@ContribRole, @InsertId), (@ContribRole, @UpdateId)
            , (@ReaderRole,  @ReadId)) AS src (RoleId, PermissionId)
   ON tgt.RoleId = src.RoleId AND tgt.PermissionId = src.PermissionId
WHEN MATCHED THEN
    UPDATE SET tgt.IsDeleted = 0, tgt.auditDeletedBy = NULL, tgt.auditDeletedDateUtc = NULL
             , tgt.auditModifiedBy = @Actor, tgt.auditModifiedDateUtc = @Now
WHEN NOT MATCHED BY TARGET THEN
    INSERT (RoleId, PermissionId, ApplicationId, auditCreatedBy, auditModifiedBy)
    VALUES (src.RoleId, src.PermissionId, @AppId, @Actor, @Actor);

-- Three users, one profile each. Pat and Olive exist because dbo.CaseNote.AuthoredByProfileId is bound to the note's own
-- tenant by FK_dbo_CaseNote_AuthoredBy_Tenant -- a note in program B needs an author who lives in program B, and that
-- constraint is itself a small piece of tenant isolation that RLS never sees.
MERGE auth.[User] AS tgt
USING (VALUES (N'rowsec.carla', N'Carla Rowsec'), (N'rowsec.pat', N'Pat Rowsec'), (N'rowsec.olive', N'Olive Rowsec'))
      AS src (UserName, DisplayName)
   ON tgt.UserName = src.UserName
WHEN MATCHED THEN
    UPDATE SET tgt.IsActive = 1, tgt.IsLockedOut = 0, tgt.IsDeleted = 0
             , tgt.auditDeletedBy = NULL, tgt.auditDeletedDateUtc = NULL
             , tgt.auditModifiedBy = @Actor, tgt.auditModifiedDateUtc = @Now
WHEN NOT MATCHED BY TARGET THEN
    INSERT (UserName, DisplayName, IsActive, auditCreatedBy, auditModifiedBy)
    VALUES (src.UserName, src.DisplayName, 1, @Actor, @Actor);

SELECT @CarlaId = UserId FROM auth.[User] WHERE UserName = N'rowsec.carla';
SELECT @PatId   = UserId FROM auth.[User] WHERE UserName = N'rowsec.pat';
SELECT @OliveId = UserId FROM auth.[User] WHERE UserName = N'rowsec.olive';

MERGE auth.UserProfile AS tgt
USING (VALUES (@CarlaId, @ProgAId,   N'Carla at program A')
            , (@PatId,   @ProgBId,   N'Pat at program B')
            , (@OliveId, @Agency2Id, N'Olive at agency 2')) AS src (UserId, TenantId, ProfileName)
   ON tgt.UserId = src.UserId AND tgt.TenantId = src.TenantId
WHEN MATCHED THEN
    UPDATE SET tgt.IsActive = 1, tgt.IsDeleted = 0, tgt.auditDeletedBy = NULL, tgt.auditDeletedDateUtc = NULL
             , tgt.auditModifiedBy = @Actor, tgt.auditModifiedDateUtc = @Now
WHEN NOT MATCHED BY TARGET THEN
    INSERT (UserId, TenantId, ProfileName, IsDefault, IsActive, auditCreatedBy, auditModifiedBy)
    VALUES (src.UserId, src.TenantId, src.ProfileName, 1, 1, @Actor, @Actor);

SELECT @CarlaProfile = UserProfileId FROM auth.UserProfile WHERE UserId = @CarlaId AND TenantId = @ProgAId;
SELECT @PatProfile   = UserProfileId FROM auth.UserProfile WHERE UserId = @PatId   AND TenantId = @ProgBId;
SELECT @OliveProfile = UserProfileId FROM auth.UserProfile WHERE UserId = @OliveId AND TenantId = @Agency2Id;

-- Carla's two grants. Restore rather than re-insert, so that re-running the file does not pile up revoked rows behind the
-- filtered unique index.
MERGE auth.UserProfileRole AS tgt
USING (VALUES (@CarlaProfile, @ContribRole, @ProgAId)
            , (@CarlaProfile, @ReaderRole,  @ProgBId)) AS src (UserProfileId, RoleId, ScopeTenantId)
   ON tgt.UserProfileId = src.UserProfileId AND tgt.RoleId = src.RoleId AND tgt.ScopeTenantId = src.ScopeTenantId
WHEN MATCHED THEN
    UPDATE SET tgt.IsDeleted = 0, tgt.ExpiresUtc = NULL, tgt.auditDeletedBy = NULL, tgt.auditDeletedDateUtc = NULL
             , tgt.auditModifiedBy = @Actor, tgt.auditModifiedDateUtc = @Now
WHEN NOT MATCHED BY TARGET THEN
    INSERT (UserProfileId, RoleId, ScopeTenantId, ApplicationId, auditCreatedBy, auditModifiedBy)
    VALUES (src.UserProfileId, src.RoleId, src.ScopeTenantId, @AppId, @Actor, @Actor);

EXEC auth.uspRebuildProfilePermissionScope @UserProfileId = @CarlaProfile;

INSERT #Fixture (ApplicationId, RootTenantId, AgencyId, Agency2Id, ProgAId, ProgBId
               , CarlaProfile, PatProfile, OliveProfile, ReadPermId, InsertPermId, UpdatePermId)
VALUES (@AppId, @RootId, @AgencyId, @Agency2Id, @ProgAId, @ProgBId
      , @CarlaProfile, @PatProfile, @OliveProfile, @ReadId, @InsertId, @UpdateId);

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'3 Fixture'
     , CASE WHEN (SELECT COUNT (*) FROM auth.ProfilePermissionScope
                   WHERE UserProfileId = @CarlaProfile AND IsDeleted = 0) = 4 THEN 4 ELSE 2 END
     , CASE WHEN (SELECT COUNT (*) FROM auth.ProfilePermissionScope
                   WHERE UserProfileId = @CarlaProfile AND IsDeleted = 0) = 4 THEN 'OK' ELSE 'DEFECT' END
     , N'Carla contributes at program A and only reads at program B'
     , CONCAT (N'Tenants root/', @RootId, N' agency/', @AgencyId, N' agency2/', @Agency2Id, N' progA/', @ProgAId
             , N' progB/', @ProgBId, N'. Carla''s profile ', @CarlaProfile, N' holds '
             , (SELECT COUNT (*) FROM auth.ProfilePermissionScope WHERE UserProfileId = @CarlaProfile AND IsDeleted = 0)
             , N' scope row(s), expected 4: read+insert+update at program A and read at program B. Permission ids read/'
             , @ReadId, N' insert/', @InsertId, N' update/', @UpdateId, N'.');
GO


-- *** 4. Rebuild the policy so the predicates know about this fixture's permissions ***
-- WITHOUT THIS THE WHOLE FILE IS A LIE. The predicates carry literal permission ids; the fixture has just created three
-- permission rows the deployed predicates were built before. A rebuild resolves the lists again, and the observation
-- prints them so a reader can see WHICH ids the policy is now enforcing.
DECLARE @Bound INT, @Skipped INT;

EXEC auth.uspRebuildTenantAccessPolicy @Action = N'Rebuild', @TablesBound = @Bound OUTPUT, @TablesSkipped = @Skipped OUTPUT;

-- WITHIN GROUP (ORDER BY PermissionId), and the assertion below compares SETS rather than this string (T-121, BL-075).
-- Until 2026-09-21 this variable was aggregated in no stated order and the check was a CHARINDEX for the whole rendered
-- list inside the predicate's definition -- two STRING_AGG calls in two objects, asked to produce the same string, with
-- nothing anywhere requiring them to.  They stopped agreeing the moment the catalogue grew past a handful of Data.Read
-- rows: the predicate said IN (1, 5, 26, 61, 96, 131) and this file looked for IN (61, 131, 96, 1, 5, 26), so the file
-- reported the policy as STALE while printing the fixture's own id inside the very list it claimed was missing.  A
-- string comparison was the wrong instrument; the question was always "are these the same six permissions".
DECLARE @ReadIds   NVARCHAR (MAX) = (SELECT STRING_AGG (CAST (PermissionId AS NVARCHAR (11)), N', ')
                                                 WITHIN GROUP (ORDER BY PermissionId)
                                       FROM auth.Permission WHERE IsDeleted = 0 AND PermissionCode = N'Data.Read')
      , @PolicyOn  BIT = (SELECT CAST (is_enabled AS BIT) FROM sys.security_policies
                           WHERE name = N'TenantAccessPolicy')
      , @Predicates INT = (SELECT COUNT (*) FROM sys.security_predicates AS sp
                             JOIN sys.security_policies AS p ON p.object_id = sp.object_id
                            WHERE p.name = N'TenantAccessPolicy')
      , @ReadPermId INT = (SELECT ReadPermId FROM #Fixture);

-- The ids the DEPLOYED predicate is actually enforcing, lifted out of its own definition.  auth.tvfTenantReadPredicate is
-- generated with the list as literals -- that is the whole point of 120_rls_policy.sql -- so the text is the only place
-- the enforced set exists to be read back.
DECLARE @Marker NVARCHAR (30) = N'PermissionId IN (';

DECLARE @ReadPredicateList NVARCHAR (MAX) = NULL;

SELECT @ReadPredicateList =
           SUBSTRING (m.definition
                    , CHARINDEX (@Marker, m.definition) + LEN (@Marker)
                    , CHARINDEX (N')', m.definition, CHARINDEX (@Marker, m.definition))
                      - CHARINDEX (@Marker, m.definition) - LEN (@Marker))
  FROM sys.sql_modules AS m
 WHERE m.object_id = OBJECT_ID (N'auth.tvfTenantReadPredicate')
   AND CHARINDEX (@Marker, m.definition) > 0;

DECLARE @PredicateIds TABLE (PermissionId INT NOT NULL PRIMARY KEY);

INSERT @PredicateIds (PermissionId)
SELECT CAST (TRIM (s.value) AS INT)
  FROM STRING_SPLIT (COALESCE (@ReadPredicateList, N''), N',') AS s
 WHERE TRIM (s.value) <> N'';

-- Set equality in both directions.  An id in the predicate that is not a live Data.Read row is as wrong as a live
-- Data.Read row the predicate has never heard of, and only one of the two is what a stale rebuild looks like.
DECLARE @ReadListCurrent BIT =
    CASE WHEN @ReadPredicateList IS NOT NULL
          AND NOT EXISTS (SELECT p.PermissionId FROM @PredicateIds AS p
                          EXCEPT
                          SELECT x.PermissionId FROM auth.Permission AS x
                           WHERE x.IsDeleted = 0 AND x.PermissionCode = N'Data.Read')
          AND NOT EXISTS (SELECT x.PermissionId FROM auth.Permission AS x
                           WHERE x.IsDeleted = 0 AND x.PermissionCode = N'Data.Read'
                          EXCEPT
                          SELECT p.PermissionId FROM @PredicateIds AS p)
         THEN 1 ELSE 0 END;

-- Reported separately, because "the list is current" and "the list contains the row this file is about to depend on" are
-- different claims and the second one is the one the sections below rest on.
DECLARE @FixtureIdInPredicate BIT =
    CASE WHEN EXISTS (SELECT 1 FROM @PredicateIds AS p WHERE p.PermissionId = @ReadPermId) THEN 1 ELSE 0 END;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'4 Policy'
     , CASE WHEN @PolicyOn = 1 AND @Bound = 2 AND @Predicates = 8 AND @ReadListCurrent = 1
                 AND @FixtureIdInPredicate = 1 THEN 4 ELSE 1 END
     , CASE WHEN @PolicyOn = 1 AND @Bound = 2 AND @Predicates = 8 AND @ReadListCurrent = 1
                 AND @FixtureIdInPredicate = 1 THEN 'OK' ELSE 'VIOLATED' END
     , N'auth.TenantAccessPolicy was rebuilt and its predicates carry the fixture''s permission ids'
     , CONCAT (N'State ', CASE WHEN @PolicyOn = 1 THEN N'ON' ELSE N'OFF' END, N', ', @Bound
             , N' table(s) bound, ', @Skipped, N' registry row(s) skipped, ', @Predicates
             , N' predicate(s) (expect 8 -- filter, block after insert, block before update, block after update, on each '
             , N'of dbo.CaseFile and dbo.CaseNote). auth.tvfTenantReadPredicate enforces PermissionId IN ('
             , COALESCE (@ReadPredicateList, N'-- no list found in the definition --')
             , N'); the live Data.Read rows are ', @ReadIds, N'. Same set: ', @ReadListCurrent
             , N' (1 = current). This fixture''s own Data.Read id ', @ReadPermId, N' is in the enforced list: '
             , @FixtureIdInPredicate, N'. Compared as SETS and not as rendered text -- see the note above the check. '
             , N'Had this EXEC been left out, every assertion below would have passed by denying '
             , N'everything, which is exactly how a stale list behaves in production.');
GO


-- *** 5. The rows, planted with the bypass key, and T-068 ***
-- EXIT CRITERION (T-068): a db_owner connection with no session context sees ZERO rows while the rows are there.
DECLARE @Actor NVARCHAR (255) = N'_tests/060'
      , @Now   DATETIME2 (3)  = SYSUTCDATETIME ();

DECLARE @ProgAId INT, @ProgBId INT, @Agency2Id INT, @CarlaProfile INT, @PatProfile INT, @OliveProfile INT;

SELECT @ProgAId = ProgAId, @ProgBId = ProgBId, @Agency2Id = Agency2Id
     , @CarlaProfile = CarlaProfile, @PatProfile = PatProfile, @OliveProfile = OliveProfile
  FROM #Fixture;

-- The key is writable, so it can be set and cleared as often as this file likes. The five IDENTITY keys cannot -- which
-- is why nothing in this file calls auth.uspSetSessionContext (see _tests/050 section 5).
EXEC sp_set_session_context @key = N'BypassRowSecurity', @value = 1;

-- The reset. Soft delete, so the filtered unique index on (TenantId, CaseNumber) lets this run re-use the same numbers.
UPDATE dbo.CaseNote
   SET IsDeleted = 1, auditDeletedBy = @Actor, auditDeletedDateUtc = @Now
     , auditModifiedBy = @Actor, auditModifiedDateUtc = @Now
 WHERE IsDeleted = 0
   AND CaseFileId IN (SELECT CaseFileId FROM dbo.CaseFile WHERE CaseNumber LIKE N'ROWSEC-%');

UPDATE dbo.CaseFile
   SET IsDeleted = 1, auditDeletedBy = @Actor, auditDeletedDateUtc = @Now
     , auditModifiedBy = @Actor, auditModifiedDateUtc = @Now
 WHERE IsDeleted = 0
   AND CaseNumber LIKE N'ROWSEC-%';

INSERT dbo.CaseFile (TenantId, CaseNumber, Title, CaseStatus, AssignedToProfileId, auditCreatedBy, auditModifiedBy)
VALUES (@ProgAId,   N'ROWSEC-A1', N'Program A, carla''s own', 'open',  @CarlaProfile, @Actor, @Actor)
     , (@ProgAId,   N'ROWSEC-A2', N'Program A, to be retired', 'open', @CarlaProfile, @Actor, @Actor)
     , (@ProgBId,   N'ROWSEC-B1', N'Program B, readable only', 'open', @PatProfile,   @Actor, @Actor)
     , (@Agency2Id, N'ROWSEC-X1', N'Agency 2, out of reach',   'open', @OliveProfile, @Actor, @Actor);

INSERT dbo.CaseNote (TenantId, CaseFileId, NoteText, AuthoredByProfileId, auditCreatedBy, auditModifiedBy)
SELECT cf.TenantId, cf.CaseFileId
     , CASE cf.CaseNumber WHEN N'ROWSEC-A1' THEN N'A note carla wrote in her own programme.'
                          ELSE N'A note pat wrote in programme B.' END
     , CASE cf.CaseNumber WHEN N'ROWSEC-A1' THEN @CarlaProfile ELSE @PatProfile END
     , @Actor, @Actor
  FROM dbo.CaseFile AS cf
 WHERE cf.IsDeleted = 0
   AND cf.CaseNumber IN (N'ROWSEC-A1', N'ROWSEC-B1');

DECLARE @AllFiles INT = (SELECT COUNT (*) FROM dbo.CaseFile WHERE IsDeleted = 0 AND CaseNumber LIKE N'ROWSEC-%')
      , @AllNotes INT = (SELECT COUNT (*) FROM dbo.CaseNote WHERE IsDeleted = 0
                                                              AND CaseFileId IN (SELECT CaseFileId FROM dbo.CaseFile
                                                                                  WHERE CaseNumber LIKE N'ROWSEC-%'));

-- And now the key goes away. Everything after this line is the database as an ordinary connection meets it.
EXEC sp_set_session_context @key = N'BypassRowSecurity', @value = NULL;

DECLARE @BlindFiles INT = (SELECT COUNT (*) FROM dbo.CaseFile)
      , @BlindNotes INT = (SELECT COUNT (*) FROM dbo.CaseNote)
      , @IsOwner    INT = IS_ROLEMEMBER (N'db_owner')
      , @InBypass   INT = COALESCE (IS_ROLEMEMBER (N'rlsBypassRole'), -1);

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'5 Seeding'
     , CASE WHEN @AllFiles = 4 AND @AllNotes = 2 THEN 4 ELSE 2 END
     , CASE WHEN @AllFiles = 4 AND @AllNotes = 2 THEN 'OK' ELSE 'DEFECT' END
     , N'Four case files and two notes exist, planted with the bypass key set'
     , CONCAT (@AllFiles, N' case file(s) and ', @AllNotes, N' note(s), counted while BypassRowSecurity was 1. Two files '
             , N'in program A, one in program B, one in agency 2. The insert into agency 2 is only possible BECAUSE the '
             , N'bypass was on: section 6c and 6d show the same statement being refused without it. Seeding a '
             , N'tenant-scoped table is the one routine job that needs the bypass, which is why 120_rls_policy.sql says '
             , N'so in its closing report.');

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'5 T-068'
     , CASE WHEN @BlindFiles = 0 AND @BlindNotes = 0 AND @IsOwner = 1 THEN 4 ELSE 1 END
     , CASE WHEN @BlindFiles = 0 AND @BlindNotes = 0 AND @IsOwner = 1 THEN 'OK' ELSE 'VIOLATED' END
     , N'EXIT CRITERION: a db_owner connection with NO session context sees zero rows'
     , CONCAT (N'SELECT COUNT (*) FROM dbo.CaseFile returned ', @BlindFiles, N' and dbo.CaseNote returned '
             , @BlindNotes, N', with ', @AllFiles, N' and ', @AllNotes, N' rows actually present. IS_ROLEMEMBER '
             , N'(db_owner) = ', @IsOwner, N', IS_ROLEMEMBER (rlsBypassRole) = ', @InBypass
             , N'. THIS IS THE ONE EVERY NEW DEVELOPER MEETS COLD: the table is not empty, the query is not wrong, and '
             , N'being db_owner does not help -- there is no session context, so the filter predicate matches nothing. '
             , N'UI-18. The cure is to set the context (section 6) or, for genuine maintenance, to join rlsBypassRole '
             , N'and call auth.uspBeginMaintenanceSession (section 7), which leaves a logs.AuthenticationEvent row '
             , N'behind on purpose.');

-- And back again, twice, to make the point that the rows never moved: the key is the only variable in the experiment.
EXEC sp_set_session_context @key = N'BypassRowSecurity', @value = 1;

-- EVERY count in this file that names the fixture also says IsDeleted = 0. The reset soft-deletes the previous run's
-- rows rather than removing them, so a count without that filter climbs by four every time the file is run and the
-- assertions start failing for a reason that has nothing to do with row security.
DECLARE @Back INT = (SELECT COUNT (*) FROM dbo.CaseFile WHERE IsDeleted = 0 AND CaseNumber LIKE N'ROWSEC-%');

EXEC sp_set_session_context @key = N'BypassRowSecurity', @value = NULL;

DECLARE @Gone INT = (SELECT COUNT (*) FROM dbo.CaseFile WHERE IsDeleted = 0 AND CaseNumber LIKE N'ROWSEC-%');

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'5 T-068'
     , CASE WHEN @Back = 4 AND @Gone = 0 THEN 4 ELSE 1 END
     , CASE WHEN @Back = 4 AND @Gone = 0 THEN 'OK' ELSE 'VIOLATED' END
     , N'Setting BypassRowSecurity brings the same rows straight back, and clearing it hides them again'
     , CONCAT (N'With the key set the count is ', @Back, N' of ', @AllFiles, N'; cleared again it is ', @Gone
             , N'. Nothing else changed between the two counts -- same connection, same statement, same rows. One '
             , N'writable session-context key is the whole difference, which is why 170_permissions.sql grants EXECUTE on '
             , N'the maintenance procedures to rlsBypassRole alone and why DES 10.5 wants that role empty between jobs. '
             , N'It is also why a report tool that connects as db_owner and forgets the context will show an empty '
             , N'dataset rather than an error.');
GO


-- *** 6. T-067: the DES 10.3 matrix ***
-- EXIT CRITERION: read in and out of scope, insert into the acting tenant and another one, update of a readable but not
-- writable row, and an attempted tenant move.
--
-- The keys below are set DIRECTLY and are writable. In production auth.uspSetSessionContext sets them read-only from a
-- verified session; here the subject is the POLICY, and using the procedure would spend the connection's identity on the
-- first assertion (see _tests/050 section 5).
DECLARE @ProgAId INT, @ProgBId INT, @Agency2Id INT, @CarlaProfile INT, @PatProfile INT, @OliveProfile INT;

SELECT @ProgAId = ProgAId, @ProgBId = ProgBId, @Agency2Id = Agency2Id
     , @CarlaProfile = CarlaProfile, @PatProfile = PatProfile, @OliveProfile = OliveProfile
  FROM #Fixture;

DECLARE @Actor NVARCHAR (255) = N'_tests/060';

EXEC sp_set_session_context @key = N'UserProfileId',  @value = @CarlaProfile;
EXEC sp_set_session_context @key = N'ActingTenantId', @value = @ProgAId;

DECLARE @ErrNo INT, @ErrMsg NVARCHAR (500), @Rows INT;

-- 6a.  Read, in scope and out of it.
DECLARE @VisibleFiles INT = (SELECT COUNT (*) FROM dbo.CaseFile WHERE IsDeleted = 0 AND CaseNumber LIKE N'ROWSEC-%')
      , @VisibleInA    INT = (SELECT COUNT (*) FROM dbo.CaseFile WHERE IsDeleted = 0 AND TenantId = @ProgAId   AND CaseNumber LIKE N'ROWSEC-%')
      , @VisibleInB    INT = (SELECT COUNT (*) FROM dbo.CaseFile WHERE IsDeleted = 0 AND TenantId = @ProgBId   AND CaseNumber LIKE N'ROWSEC-%')
      , @VisibleInX    INT = (SELECT COUNT (*) FROM dbo.CaseFile WHERE IsDeleted = 0 AND TenantId = @Agency2Id AND CaseNumber LIKE N'ROWSEC-%')
      , @VisibleNotes  INT = (SELECT COUNT (*) FROM dbo.CaseNote AS cn
                               WHERE cn.IsDeleted = 0
                                 AND EXISTS (SELECT 1 FROM dbo.CaseFile AS cf
                                              WHERE cf.CaseFileId = cn.CaseFileId
                                                AND cf.CaseNumber LIKE N'ROWSEC-%'));

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'6a Read'
     , CASE WHEN @VisibleFiles = 3 AND @VisibleInA = 2 AND @VisibleInB = 1 AND @VisibleInX = 0 AND @VisibleNotes = 2
            THEN 4 ELSE 1 END
     , CASE WHEN @VisibleFiles = 3 AND @VisibleInA = 2 AND @VisibleInB = 1 AND @VisibleInX = 0 AND @VisibleNotes = 2
            THEN 'OK' ELSE 'VIOLATED' END
     , N'EXIT CRITERION (10.3 read): rows in scope are visible, rows out of scope do not exist'
     , CONCAT (N'Carla sees ', @VisibleFiles, N' of 4 case files: ', @VisibleInA, N' in program A (expect 2), '
             , @VisibleInB, N' in program B, which she may read but not write (expect 1), and ', @VisibleInX
             , N' in agency 2 (expect 0). She sees ', @VisibleNotes, N' note(s) (expect 2 -- dbo.CaseNote is bound by the '
             , N'same policy through config.TenantScopedTable, and nobody had to write a second predicate). The agency 2 '
             , N'row is not hidden behind an error: it is ABSENT, and a COUNT over it is 0 rather than a refusal.');

-- 6b.  Insert into the acting tenant.
--      AssignedToProfileId is left NULL on this one, and the row is the subject of the tenant-move attempt in 6g.
--      FK_dbo_CaseFile_AssignedTo_Tenant is on (AssignedToProfileId, TenantId), so an ASSIGNED case file cannot change
--      tenant at all: the foreign key fails with Msg 547 before the block predicate is ever consulted. The same is true
--      of a case file with notes, through FK_dbo_CaseNote_CaseFile_Tenant. Both refusals are welcome, and both would
--      make 6g a test of referential integrity rather than of row security -- so 6g needs a row that nothing points at.
SET @ErrNo = NULL; SET @ErrMsg = NULL; SET @Rows = 0;

BEGIN TRY
    INSERT dbo.CaseFile (TenantId, CaseNumber, Title, CaseStatus, AssignedToProfileId, auditCreatedBy, auditModifiedBy)
    VALUES (@ProgAId, N'ROWSEC-A3', N'Program A, inserted by carla, assigned to nobody', 'open', NULL, @Actor, @Actor);

    SET @Rows = @@ROWCOUNT;
END TRY
BEGIN CATCH
    SELECT @ErrNo = ERROR_NUMBER (), @ErrMsg = LEFT (ERROR_MESSAGE (), 400);
END CATCH;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'6b Insert here'
     , CASE WHEN @ErrNo IS NULL AND @Rows = 1 THEN 4 ELSE 1 END
     , CASE WHEN @ErrNo IS NULL AND @Rows = 1 THEN 'OK' ELSE 'VIOLATED' END
     , N'EXIT CRITERION (10.3 insert): a row into the ACTING tenant is accepted'
     , CONCAT (N'Rows inserted: ', @Rows, N', error ', COALESCE (CAST (@ErrNo AS NVARCHAR (11)), N'(none)'), N'. '
             , COALESCE (@ErrMsg, N'The insert predicate is anchored to ActingTenantId and program A is it.'));

-- 6c.  Insert into a tenant she can READ but is not acting for. This is the asymmetry P-06 chose deliberately: read is
--      covering, write is anchored, so nobody can file paperwork into a neighbouring programme by changing one column.
SET @ErrNo = NULL; SET @ErrMsg = NULL; SET @Rows = 0;

BEGIN TRY
    INSERT dbo.CaseFile (TenantId, CaseNumber, Title, CaseStatus, AssignedToProfileId, auditCreatedBy, auditModifiedBy)
    VALUES (@ProgBId, N'ROWSEC-B9', N'Program B, should never exist', 'open', @PatProfile, @Actor, @Actor);

    SET @Rows = @@ROWCOUNT;
END TRY
BEGIN CATCH
    SELECT @ErrNo = ERROR_NUMBER (), @ErrMsg = LEFT (ERROR_MESSAGE (), 400);
END CATCH;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'6c Insert there'
     , CASE WHEN @ErrNo = 33504 AND @Rows = 0 THEN 4 ELSE 1 END
     , CASE WHEN @ErrNo = 33504 AND @Rows = 0 THEN 'OK' ELSE 'VIOLATED' END
     , N'EXIT CRITERION (10.3 insert): a row into a READABLE but non-acting tenant is BLOCKED'
     , CONCAT (N'Error ', COALESCE (CAST (@ErrNo AS NVARCHAR (11)), N'(none -- THE ROW WENT IN)'), N', expected 33504, '
             , @Rows, N' row(s) written. Carla can read program B, so a covering predicate would have allowed this. The '
             , N'insert predicate also demands @TenantId = ActingTenantId, which is the whole of P-06: reading across a '
             , N'subtree is useful, writing across one is how data ends up in the wrong agency. ', COALESCE (@ErrMsg, N''));

-- 6d.  Insert into a tenant she cannot even see.
SET @ErrNo = NULL; SET @ErrMsg = NULL; SET @Rows = 0;

BEGIN TRY
    INSERT dbo.CaseFile (TenantId, CaseNumber, Title, CaseStatus, AssignedToProfileId, auditCreatedBy, auditModifiedBy)
    VALUES (@Agency2Id, N'ROWSEC-X9', N'Agency 2, should never exist', 'open', @OliveProfile, @Actor, @Actor);

    SET @Rows = @@ROWCOUNT;
END TRY
BEGIN CATCH
    SELECT @ErrNo = ERROR_NUMBER (), @ErrMsg = LEFT (ERROR_MESSAGE (), 400);
END CATCH;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'6d Insert outside'
     , CASE WHEN @ErrNo = 33504 AND @Rows = 0 THEN 4 ELSE 1 END
     , CASE WHEN @ErrNo = 33504 AND @Rows = 0 THEN 'OK' ELSE 'VIOLATED' END
     , N'EXIT CRITERION (10.3 insert): a row into an UNREACHABLE tenant is BLOCKED'
     , CONCAT (N'Error ', COALESCE (CAST (@ErrNo AS NVARCHAR (11)), N'(none -- THE ROW WENT IN)'), N', expected 33504, '
             , @Rows, N' row(s) written. ', COALESCE (@ErrMsg, N''));

-- 6e.  Update a row she can read and must not write.
SET @ErrNo = NULL; SET @ErrMsg = NULL; SET @Rows = 0;

BEGIN TRY
    UPDATE dbo.CaseFile
       SET Title = N'Program B, edited by somebody who may only look'
         , auditModifiedBy = @Actor, auditModifiedDateUtc = SYSUTCDATETIME ()
     WHERE CaseNumber = N'ROWSEC-B1' AND IsDeleted = 0;

    SET @Rows = @@ROWCOUNT;
END TRY
BEGIN CATCH
    SELECT @ErrNo = ERROR_NUMBER (), @ErrMsg = LEFT (ERROR_MESSAGE (), 400);
END CATCH;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'6e Update read-only'
     , CASE WHEN @ErrNo = 33504 AND @Rows = 0 THEN 4 ELSE 1 END
     , CASE WHEN @ErrNo = 33504 AND @Rows = 0 THEN 'OK' ELSE 'VIOLATED' END
     , N'EXIT CRITERION (10.3 update): a READABLE BUT NOT WRITABLE row cannot be edited'
     , CONCAT (N'Error ', COALESCE (CAST (@ErrNo AS NVARCHAR (11)), N'(none -- THE EDIT LANDED)'), N', expected 33504, '
             , @Rows, N' row(s) changed. The row passed the FILTER -- section 6a counted it -- and then failed BLOCK '
             , N'BEFORE UPDATE, because carla holds Data.Read at program B and not Data.Update. Read and write scope are '
             , N'separate sets over the same table, and this is the case that shows it: the refusal is loud, not silent, '
             , N'because the row was visible. ', COALESCE (@ErrMsg, N''));

-- 6f.  Update a row she may write.
SET @ErrNo = NULL; SET @ErrMsg = NULL; SET @Rows = 0;

BEGIN TRY
    UPDATE dbo.CaseFile
       SET Title = N'Program A, carla''s own, edited at ' + CONVERT (NVARCHAR (30), SYSUTCDATETIME (), 126)
         , auditModifiedBy = @Actor, auditModifiedDateUtc = SYSUTCDATETIME ()
     WHERE CaseNumber = N'ROWSEC-A1' AND IsDeleted = 0;

    SET @Rows = @@ROWCOUNT;
END TRY
BEGIN CATCH
    SELECT @ErrNo = ERROR_NUMBER (), @ErrMsg = LEFT (ERROR_MESSAGE (), 400);
END CATCH;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'6f Update writable'
     , CASE WHEN @ErrNo IS NULL AND @Rows = 1 THEN 4 ELSE 1 END
     , CASE WHEN @ErrNo IS NULL AND @Rows = 1 THEN 'OK' ELSE 'VIOLATED' END
     , N'EXIT CRITERION (10.3 update): a row inside the write scope is edited normally'
     , CONCAT (@Rows, N' row(s) changed, error ', COALESCE (CAST (@ErrNo AS NVARCHAR (11)), N'(none)')
             , N'. Without this row the file would only prove that the policy says no. ', COALESCE (@ErrMsg, N''));

-- 6g.  The tenant move: the same edit that a naive policy allows. BLOCK AFTER UPDATE is bound separately from BLOCK
--      BEFORE UPDATE for exactly this -- the pre-image is legal and the post-image is not. The subject is ROWSEC-A3,
--      unassigned and unreferenced, so that the composite foreign keys do not refuse it first (see 6b).
SET @ErrNo = NULL; SET @ErrMsg = NULL; SET @Rows = 0;

BEGIN TRY
    UPDATE dbo.CaseFile
       SET TenantId = @ProgBId
         , auditModifiedBy = @Actor, auditModifiedDateUtc = SYSUTCDATETIME ()
     WHERE CaseNumber = N'ROWSEC-A3' AND IsDeleted = 0;

    SET @Rows = @@ROWCOUNT;
END TRY
BEGIN CATCH
    SELECT @ErrNo = ERROR_NUMBER (), @ErrMsg = LEFT (ERROR_MESSAGE (), 400);
END CATCH;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'6g Tenant move'
     , CASE WHEN @ErrNo = 33504 AND @Rows = 0 THEN 4 ELSE 1 END
     , CASE WHEN @ErrNo = 33504 AND @Rows = 0 THEN 'OK' ELSE 'VIOLATED' END
     , N'EXIT CRITERION (10.3 update): a row cannot be MOVED to a tenant outside the write scope'
     , CONCAT (N'Error ', COALESCE (CAST (@ErrNo AS NVARCHAR (11)), N'(none -- THE CASE FILE CHANGED TENANT)')
             , N', expected 33504, ', @Rows, N' row(s) moved. Carla owns this row and may edit it (6b inserted it), and program B is '
             , N'a tenant she can read -- so the pre-image passes and only the POST-image fails. A policy that bound the '
             , N'update predicate once, before the update only, would have let a caseworker hand a case file to another '
             , N'programme and then lose sight of it. ', COALESCE (@ErrMsg, N''));

-- 6h.  Retirement is an UPDATE in this database, so the update predicate governs deletion too.
SET @ErrNo = NULL; SET @ErrMsg = NULL; SET @Rows = 0;

BEGIN TRY
    UPDATE dbo.CaseFile
       SET IsDeleted = 1, auditDeletedBy = @Actor, auditDeletedDateUtc = SYSUTCDATETIME ()
         , auditModifiedBy = @Actor, auditModifiedDateUtc = SYSUTCDATETIME ()
     WHERE CaseNumber = N'ROWSEC-A2' AND IsDeleted = 0;

    SET @Rows = @@ROWCOUNT;
END TRY
BEGIN CATCH
    SELECT @ErrNo = ERROR_NUMBER (), @ErrMsg = LEFT (ERROR_MESSAGE (), 400);
END CATCH;

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'6h Retire'
     , CASE WHEN @ErrNo IS NULL AND @Rows = 1 THEN 4 ELSE 2 END
     , CASE WHEN @ErrNo IS NULL AND @Rows = 1 THEN 'OK' ELSE 'DEFECT' END
     , N'Retiring an in-scope row is an ordinary UPDATE and the update predicate is what governs it'
     , CONCAT (@Rows, N' row(s) retired, error ', COALESCE (CAST (@ErrNo AS NVARCHAR (11)), N'(none)')
             , N'. There is no delete predicate in auth.TenantAccessPolicy because there are no hard deletes in this '
             , N'database. A hard DELETE aimed at agency 2 would not be BLOCKED either -- it would simply match nothing, '
             , N'because the filter has already hidden the row. Knowing which of the two protects you matters on the day '
             , N'somebody proposes a purge job. ', COALESCE (@ErrMsg, N''));

-- Hand the connection back with no acting identity, so section 7 starts from nothing.
EXEC sp_set_session_context @key = N'UserProfileId',  @value = NULL;
EXEC sp_set_session_context @key = N'ActingTenantId', @value = NULL;
GO


-- *** 7. T-066: the maintenance-bypass window, under a real member of rlsBypassRole ***
-- auth.uspBeginMaintenanceSession refuses anybody who is not in the role (E-50070), and dbo is deliberately not a member
-- -- 105_auth_session_procedures.sql proves the refusal at deployment time and leaves the ACCEPTED path here, because
-- proving it needs a principal that a deployment must not create and leave behind.
IF DATABASE_PRINCIPAL_ID (N'rowsecMaintenanceUser') IS NULL
BEGIN
    CREATE USER rowsecMaintenanceUser WITHOUT LOGIN;
END;

ALTER ROLE rlsBypassRole ADD MEMBER rowsecMaintenanceUser;
GRANT SELECT ON dbo.CaseFile TO rowsecMaintenanceUser;
GO

DECLARE @Actor    NVARCHAR (255) = N'_tests/060'
      , @ErrNo    INT = NULL
      , @ErrMsg   NVARCHAR (500) = NULL
      , @WithBypass INT = -1
      , @AfterEnd   INT = -1
      , @Cleared  BIT = NULL
      , @Started  DATETIME2 (3) = SYSUTCDATETIME ();

BEGIN TRY
    EXECUTE AS USER = N'rowsecMaintenanceUser';

    EXEC auth.uspBeginMaintenanceSession @Reason = N'_tests/060 proves the accepted maintenance path end to end.'
                                       , @TicketReference = N'TEST-060';

    SET @WithBypass = (SELECT COUNT (*) FROM dbo.CaseFile WHERE IsDeleted = 0 AND CaseNumber LIKE N'ROWSEC-%');

    EXEC auth.uspEndMaintenanceSession @BypassCleared = @Cleared OUTPUT;

    SET @AfterEnd = (SELECT COUNT (*) FROM dbo.CaseFile WHERE IsDeleted = 0 AND CaseNumber LIKE N'ROWSEC-%');

    REVERT;
END TRY
BEGIN CATCH
    SELECT @ErrNo = ERROR_NUMBER (), @ErrMsg = LEFT (ERROR_MESSAGE (), 400);

    IF USER_NAME () = N'rowsecMaintenanceUser'
    BEGIN
        REVERT;
    END;

    -- If the procedure failed midway the key may still be set, and leaving it set would poison every count below.
    EXEC sp_set_session_context @key = N'BypassRowSecurity', @value = NULL;
END CATCH;

DECLARE @BeginEvents INT = (SELECT COUNT (*) FROM logs.AuthenticationEvent
                             WHERE EventType = N'MaintenanceBypass' AND EventUtc >= @Started)
      , @EndEvents   INT = (SELECT COUNT (*) FROM logs.AuthenticationEvent
                             WHERE EventType = N'MaintenanceBypassEnded' AND EventUtc >= @Started)
      , @EventActor  NVARCHAR (255) = (SELECT TOP (1) Actor FROM logs.AuthenticationEvent
                                        WHERE EventType = N'MaintenanceBypass' AND EventUtc >= @Started
                                        ORDER BY AuthenticationEventId DESC);

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'7 Maintenance'
     , CASE WHEN @ErrNo IS NULL AND @WithBypass = 4 AND @AfterEnd = 0 AND @Cleared = 1 THEN 4 ELSE 1 END
     , CASE WHEN @ErrNo IS NULL AND @WithBypass = 4 AND @AfterEnd = 0 AND @Cleared = 1 THEN 'OK' ELSE 'VIOLATED' END
     , N'A member of rlsBypassRole opens a bypass window, sees every tenant, and closes it again'
     , CONCAT (N'Error ', COALESCE (CAST (@ErrNo AS NVARCHAR (11)), N'(none)'), N'. Inside the window the user saw '
             , @WithBypass, N' case file(s) across all four tenants (expect 4); after '
             , N'auth.uspEndMaintenanceSession it saw ', @AfterEnd, N' (expect 0, because the impersonated user has no '
             , N'profile and no context). @BypassCleared = ', COALESCE (CAST (@Cleared AS NVARCHAR (11)), N'(null)')
             , N'. This is the path 105_auth_session_procedures.sql could not run at deployment time without creating a '
             , N'principal and leaving it behind -- section 8 removes it. ', COALESCE (@ErrMsg, N''));

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'7 Maintenance'
     , CASE WHEN @BeginEvents >= 1 AND @EndEvents >= 1 THEN 4 ELSE 1 END
     , CASE WHEN @BeginEvents >= 1 AND @EndEvents >= 1 THEN 'OK' ELSE 'VIOLATED' END
     , N'The window left BOTH logs.AuthenticationEvent rows, and the actor is the real login'
     , CONCAT (@BeginEvents, N' MaintenanceBypass row(s) and ', @EndEvents, N' MaintenanceBypassEnded row(s) since this '
             , N'section started (expect at least one of each). Actor on the opening row: '
             , COALESCE (@EventActor, N'(none)'), N' -- ORIGINAL_LOGIN, NOT rowsecMaintenanceUser, because EXECUTE AS '
             , N'changes who you are for permission checks and not who the server knows signed in. Somebody who '
             , N'impersonates their way into the bypass is recorded under their own name, which is the only reason the '
             , N'trail is worth keeping. DES 10.5 makes this pair the price of admission: the bypass is allowed, and it '
             , N'is never quiet.');
GO


-- *** 8. Take the bypass principal away again ***
-- A template database that has been TESTED must not be left with an extra member of rlsBypassRole. The role is meant to
-- be empty between maintenance jobs (DES 10.5), and a user WITHOUT LOGIN that nobody remembers creating is exactly the
-- kind of thing an audit finds and nobody can explain.
IF DATABASE_PRINCIPAL_ID (N'rowsecMaintenanceUser') IS NOT NULL
BEGIN
    ALTER ROLE rlsBypassRole DROP MEMBER rowsecMaintenanceUser;
    REVOKE SELECT ON dbo.CaseFile FROM rowsecMaintenanceUser;
    DROP USER rowsecMaintenanceUser;
END;

DECLARE @BypassMembers INT = (SELECT COUNT (*)
                                FROM sys.database_role_members AS drm
                                JOIN sys.database_principals   AS r ON r.principal_id = drm.role_principal_id
                               WHERE r.name = N'rlsBypassRole');

INSERT #Observation (Section, Severity, Status, Item, Detail)
SELECT N'8 Cleanup'
     , CASE WHEN DATABASE_PRINCIPAL_ID (N'rowsecMaintenanceUser') IS NULL THEN 4 ELSE 2 END
     , CASE WHEN DATABASE_PRINCIPAL_ID (N'rowsecMaintenanceUser') IS NULL THEN 'OK' ELSE 'DEFECT' END
     , N'The test''s bypass user is gone and rlsBypassRole is back to its intended state'
     , CONCAT (N'rowsecMaintenanceUser exists: '
             , CASE WHEN DATABASE_PRINCIPAL_ID (N'rowsecMaintenanceUser') IS NULL THEN N'no' ELSE N'YES' END
             , N'. rlsBypassRole now has ', @BypassMembers, N' member(s) -- zero is the resting state DES 10.5 asks for. '
             , N'The fixture rows are left in place on purpose: they are what makes the next run''s T-068 demonstration '
             , N'meaningful, and they are the rows a new developer should be shown disappearing.');
GO


-- *** 9. The report, and the verdict ***
INSERT #Observation (Section, Severity, Status, Item, Detail)
VALUES (N'9 Not tested', 3, 'NOTE'
      , N'The policy was rebuilt by this file, and the permission ids it now carries include the test fixtures'''
      , N'auth.uspRebuildTenantAccessPolicy resolves Data.Read, Data.Insert and Data.Update across EVERY application, so '
      + N'after this run the predicates name the ROWSEC and AUTHZTEST permission ids alongside any real ones. That is '
      + N'correct -- the codes are the contract, not the ids -- but it means the deployed policy in a development '
      + N'database reflects whatever the tests last created. Re-run 120_rls_policy.sql to rebuild from the real '
      + N'catalogue, and remember that 100_auth_functions.sql, 065_auth_effective_permission.sql and 030_auth_tenant.sql '
      + N'cannot be re-run at all while the policy is bound (error 3729): drop it first with '
      + N'EXEC auth.uspRebuildTenantAccessPolicy @Action = N''Drop''.')
     , (N'9 Not tested', 3, 'NOTE'
      , N'Nothing here was read through a stored procedure, so ownership chaining past the policy is unexamined'
      , N'Every statement in section 6 touched the tables directly. A security policy evaluates its predicates in the '
      + N'POLICY''s context, so a caller needs no permission on auth.ProfilePermissionScope or auth.TenantClosure to be '
      + N'filtered by them -- measured while building 120_rls_policy.sql -- but whether a procedure that reads '
      + N'dbo.CaseFile on an application user''s behalf behaves identically is a Phase 6 question, when there are '
      + N'procedures to ask it of.')
     , (N'9 Not tested', 3, 'NOTE'
      , N'The hot path was not measured, only made correct'
      , N'Each predicate is an EXISTS over auth.ProfilePermissionScope joined to auth.TenantClosure, evaluated once per '
      + N'row per statement. Whether that is acceptable at ten million case files is gap G-14''s question and needs a '
      + N'volume fixture, not a matrix.');

SELECT Severity, Status, Section, Item, Detail
  FROM #Observation
 ORDER BY RowNo;
GO

DECLARE @Criteria TABLE (Criterion NVARCHAR (200) NOT NULL, Marker NVARCHAR (200) NOT NULL);

INSERT @Criteria (Criterion, Marker)
VALUES (N'Read in scope and out of scope (T-067)',            N'EXIT CRITERION (10.3 read)')
     , (N'Insert into the acting tenant and others (T-067)',  N'EXIT CRITERION (10.3 insert)')
     , (N'Update, read-only row, and tenant move (T-067)',    N'EXIT CRITERION (10.3 update)')
     , (N'db_owner with no context sees zero rows (T-068)',   N'EXIT CRITERION: a db_owner connection');

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
        CONCAT (N'Phase 4 row security: ', @Violations, N' exit-criterion violation(s) and ', @Defects
              , N' defect(s). The rows above carry the detail. The fixture rows are still in place; the bypass key and '
              , N'the context keys have been cleared, and the test''s bypass user has been dropped.');

    ;THROW 50000, @Fail, 1;
END;

PRINT CONCAT (N'Phase 4 row security: no problems found. ', @AsIntended, N' observation(s) came out as intended, with '
            , @Notes, N' note(s). Four case files and two notes sit in four tenants; a db_owner connection with no '
            , N'session context sees none of them, carla sees three, she may write only in the tenant she is acting for, '
            , N'she cannot edit the programme B file she can read, and she cannot move her own file out of reach. A '
            , N'member of rlsBypassRole opened a window, saw all four, closed it, and left two events behind.');
GO
