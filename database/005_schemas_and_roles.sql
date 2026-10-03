/***********************************************************************************************************************
Script:         005_schemas_and_roles.sql
Purpose:        The four consumer schemas and the four database roles everything else in the deployment grants to.
Target:         SQL Server 2022.
Run as:         db_owner in the target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -i database/005_schemas_and_roles.sql
Idempotent:     Yes.  Every CREATE is guarded and every ALTER AUTHORIZATION is conditional, so a second run reports and
                changes nothing.  Nothing is ever dropped.
Depends on:     database/000_prerequisites.sql.
Implements:     DES-AUTH-001 sections 10.5, 19.3 and 21.1.  PLAN-AUTH-001 tasks T-008 and T-010.
To retarget:    Pass it per run:  sqlcmd -d <database> -v DbName=<database>.  There is no in-file default.

WHY THE ROLES COME THIS EARLY, AND WHAT HAPPENS IF THEY DO NOT
--------------------------------------------------------------
Every GRANT in this project is guarded on the principal existing:

    IF DATABASE_PRINCIPAL_ID (N'applicationRole') IS NOT NULL GRANT ... TO applicationRole;

That guard is what lets the conventions ship into an estate that names its principals differently, and it has a cost
that is worth stating in the file that creates them: A NAME YOU HAVE NOT CREATED IS A SILENTLY SKIPPED GRANT.  The
object deploys, the script reports success, and nobody can execute it.  There is no error, because a guard that did not
fire is not a failure.

So the roles are created here, in script 005, before anything that grants to them -- and the closing report below names
every one of them so a typo is visible on the first run rather than on the first support call.

WHY THESE FOUR SCHEMAS AND NOT MORE
-----------------------------------
  auth    authentication and authorization
  logs    logging
  config  application configuration
  util    utility objects
  dbo     user data -- exists already, created with the database

Two more schemas exist in a fully deployed database and are deliberately NOT created here:

  logsData and history are created by scripts/logdBChanges.sql, because they are structural to the DDL change-logging
  subsystem rather than to this design.  Creating them here would mean two scripts owning the same objects.

  dboData is created only if a table opts into row history, which no table in this design does -- the authorization
  trail is an event stream in logs.AuthorizationChange, which answers "who granted what, when, under what authority"
  better than a row-version history of the grant table would.

ALL SCHEMAS MUST SHARE ONE OWNER, AND THAT OWNER IS dbo
-------------------------------------------------------
Section 2 asserts it and fixes it.  Ownership chaining is what lets a procedure in auth read logs.ExecutionLog without
a table-level grant, and it is the whole mechanism behind INV-11: applicationRole holds EXECUTE on named procedures and
NO table permission on SCHEMA::auth at all.  Break the ownership chain and either every instrumented procedure starts
failing inside its own logging block on logic that is fine, or somebody "fixes" it by granting table access and quietly
removes the barrier.
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


-- *** 1. Schemas ***
-- CREATE SCHEMA must be the first statement in its batch, which is why each one is wrapped in EXEC rather than written
-- inside the IF.  This is the form the conventions require; it is not a stylistic preference.
IF SCHEMA_ID (N'auth')   IS NULL EXEC (N'CREATE SCHEMA auth');
GO
IF SCHEMA_ID (N'logs')   IS NULL EXEC (N'CREATE SCHEMA logs');
GO
IF SCHEMA_ID (N'config') IS NULL EXEC (N'CREATE SCHEMA config');
GO
IF SCHEMA_ID (N'util')   IS NULL EXEC (N'CREATE SCHEMA util');
GO


-- *** 2. One owner across every schema ***
-- See the header.  A schema created by a login other than dbo is owned by that login, which breaks ownership chaining
-- in a way that surfaces much later as a permission error inside a procedure whose logic is correct.
DECLARE @Schema SYSNAME
      , @Sql    NVARCHAR (400);

DECLARE SchemaCursor CURSOR LOCAL FAST_FORWARD FOR
    SELECT s.name
      FROM sys.schemas AS s
      JOIN sys.database_principals AS p ON p.principal_id = s.principal_id
     WHERE s.name IN (N'auth', N'logs', N'config', N'util', N'dbo')
       AND p.name <> N'dbo';

OPEN SchemaCursor;
FETCH NEXT FROM SchemaCursor INTO @Schema;

WHILE @@FETCH_STATUS = 0
BEGIN
    SET @Sql = N'ALTER AUTHORIZATION ON SCHEMA::' + QUOTENAME (@Schema) + N' TO dbo;';
    PRINT N'Schema ' + QUOTENAME (@Schema) + N' was not owned by dbo. Transferring ownership.';
    EXEC sys.sp_executesql @Sql;

    FETCH NEXT FROM SchemaCursor INTO @Schema;
END;

CLOSE SchemaCursor;
DEALLOCATE SchemaCursor;
GO


-- *** 3. Database roles ***
--
-- applicationRole   The web application connects as a member of this role.  It holds SELECT, INSERT and UPDATE on
--                   SCHEMA::dbo and EXECUTE on named procedures -- and NO table permission on SCHEMA::auth.
--                   DELETE is never granted on SCHEMA::dbo: a plain table has no INSTEAD OF DELETE trigger, so a
--                   DELETE there would be a real hard delete.  Soft-deleting is an UPDATE, which the UPDATE grant
--                   already covers.
--
-- readOnlyRole      The monitoring and reporting path.  SELECT only, and writes to logs explicitly denied.
--
-- logsAuditReader   Auditors.  SELECT on the DDL change trail in logsData, which neither of the two roles above can
--                   reach.
--
-- rlsBypassRole     The controlled row-level-security bypass, and the one role whose membership is a security
--                   decision rather than a deployment step.  See section 4.
--
IF DATABASE_PRINCIPAL_ID (N'applicationRole') IS NULL
BEGIN
    PRINT N'Creating role applicationRole.';
    CREATE ROLE applicationRole;
END
GO

IF DATABASE_PRINCIPAL_ID (N'readOnlyRole') IS NULL
BEGIN
    PRINT N'Creating role readOnlyRole.';
    CREATE ROLE readOnlyRole;
END
GO

IF DATABASE_PRINCIPAL_ID (N'logsAuditReader') IS NULL
BEGIN
    PRINT N'Creating role logsAuditReader.';
    CREATE ROLE logsAuditReader;
END
GO

IF DATABASE_PRINCIPAL_ID (N'rlsBypassRole') IS NULL
BEGIN
    PRINT N'Creating role rlsBypassRole.';
    CREATE ROLE rlsBypassRole;
END
GO


/***********************************************************************************************************************
    4. rlsBypassRole -- membership policy

    This role exists because row-level security in SQL Server applies to db_owner and to sysadmin.  A DBA who connects
    and selects from a protected table with no session context sees ZERO ROWS -- no error, no warning, an empty grid.
    Everyone who touches this database meets that once, and several will conclude the data has been lost.

    Pretending the need does not exist produces the worst available outcome, which is somebody disabling the security
    policy at three in the morning and not re-enabling it.  So there is a supported door, and these are its rules:

      1.  NO APPLICATION LOGIN IS EVER A MEMBER.  Not the web application, not a service account that runs a nightly
          job, not "temporarily".  A member of this role can read every tenant's rows unfiltered.

      2.  MEMBERSHIP IS FOR NAMED HUMAN ACCOUNTS ONLY, granted for a reason that is written down, and reviewed on
          whatever cycle the estate reviews privileged access on.

      3.  THE ROLE IS NOT THE PERMISSION.  Membership only allows auth.uspBeginMaintenanceSession to succeed; that
          procedure writes a logs.AuthenticationEvent row of type MaintenanceBypass BEFORE it sets the session key, so
          the record exists even if the session then fails.  Reading the data without calling it still returns nothing.

      4.  REPORTING IS NOT A REASON TO JOIN THIS ROLE.  A report that needs to read across tenants gets a profile with
          read scoped at the root and Data.Export, and goes through the ordinary predicate -- so its scope is visible
          in auth.vwProfilePermission like anyone else's and its extracts are attributable.  Using the bypass for
          reporting hands a service account unrestricted read with no tenant attribution, which is gap G-16.

    database/950_verify_deployment.sql lists every member of this role by name in its report, every run.  That is
    deliberate: a privileged group nobody enumerates is a privileged group that grows.
***********************************************************************************************************************/


-- *** 5. Closing report ***
DECLARE @Report TABLE
(
    RowNo    INT IDENTITY (1, 1) PRIMARY KEY,
    Severity INT             NOT NULL,
    Status   VARCHAR (10)    NOT NULL,
    Item     NVARCHAR (200)  NOT NULL,
    Detail   NVARCHAR (1000)     NULL
);

-- Schemas, and who owns them.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN SCHEMA_ID (x.SchemaName) IS NULL THEN 1
            WHEN USER_NAME (s.principal_id) <> N'dbo' THEN 2
            ELSE 4 END
     , CASE WHEN SCHEMA_ID (x.SchemaName) IS NULL THEN 'MISSING'
            WHEN USER_NAME (s.principal_id) <> N'dbo' THEN 'BAD OWNER'
            ELSE 'OK' END
     , N'Schema ' + x.SchemaName
     , x.Purpose + N' Owner: ' + COALESCE (USER_NAME (s.principal_id), N'(absent)') + N'.'
  FROM (VALUES (N'auth',   N'Authentication and authorization.')
             , (N'logs',   N'Logging.')
             , (N'config', N'Application configuration.')
             , (N'util',   N'Utility objects.')
             , (N'dbo',    N'User data.')) AS x (SchemaName, Purpose)
  LEFT JOIN sys.schemas AS s ON s.name = x.SchemaName;

-- Roles, and whether anyone is in them.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN DATABASE_PRINCIPAL_ID (x.RoleName) IS NULL THEN 1 ELSE 4 END
     , CASE WHEN DATABASE_PRINCIPAL_ID (x.RoleName) IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Role ' + x.RoleName
     , x.Purpose
  FROM (VALUES (N'applicationRole', N'The web application. SELECT, INSERT, UPDATE on SCHEMA::dbo and EXECUTE on named procedures. No table access to SCHEMA::auth.')
             , (N'readOnlyRole',    N'Monitoring and reporting. SELECT only; writes to logs denied.')
             , (N'logsAuditReader', N'Auditors. SELECT on the DDL change trail in logsData.')
             , (N'rlsBypassRole',   N'The controlled row-level-security bypass. Named human accounts only -- see section 4.')) AS x (RoleName, Purpose);

-- An empty role is not an error, but it is the reason "the permissions look right and the user sees nothing".
--
-- THE COUNT IS A CORRELATED COUNT (*), NOT COUNT (m.member_principal_id) OVER A LEFT JOIN.  The earlier shape was
-- measured to print  "Warning: Null value is eliminated by an aggregate or other SET operation."  on every run of a
-- fresh database, because an empty role produces one outer row whose member_principal_id is NULL and COUNT over an
-- all-NULL expression warns.  The count was right; the transcript was not.  A warning in a deployment transcript reads
-- as a finding, and a reader who learns to scroll past this one will scroll past the next.  COUNT (*) over zero rows
-- returns 0 silently, which is what was wanted all along.
INSERT @Report (Severity, Status, Item, Detail)
SELECT 3, 'INFO', N'Members of ' + r.RoleName
     , CASE WHEN r.MemberCount = 0
            THEN N'None. The grants will apply to nobody until somebody is added: ALTER ROLE ' + r.RoleName + N' ADD MEMBER <user>;'
            ELSE CAST (r.MemberCount AS NVARCHAR (10)) + N' member(s).'
       END
  FROM (SELECT RoleName    = p.name
             , MemberCount = (SELECT COUNT (*)
                                FROM sys.database_role_members AS m
                               WHERE m.role_principal_id = p.principal_id)
          FROM sys.database_principals AS p
         WHERE p.name IN (N'applicationRole', N'readOnlyRole', N'logsAuditReader', N'rlsBypassRole')
           AND p.type = 'R') AS r;

-- rlsBypassRole is called out separately because a member here is a member with unfiltered read.
INSERT @Report (Severity, Status, Item, Detail)
SELECT 2, 'REVIEW', N'rlsBypassRole member: ' + mp.name
     , N'This principal can open a maintenance session and read every tenant''s rows unfiltered. Confirm it is a named '
     + N'human account and not an application login -- see section 4, rule 1.'
  FROM sys.database_role_members AS m
  JOIN sys.database_principals  AS rp ON rp.principal_id = m.role_principal_id
  JOIN sys.database_principals  AS mp ON mp.principal_id = m.member_principal_id
 WHERE rp.name = N'rlsBypassRole';

INSERT @Report (Severity, Status, Item, Detail)
SELECT 3, 'NEXT', N'Run the conventions installers'
     , N'templates/extended-properties.sql, then scripts/logdBChanges.sql, then scripts/logExecutionLogging.sql, then '
     + N'scripts/permissions.sql. database/Install-TemplateDatabase.ps1 runs the whole sequence in order.';

IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
    PRINT N'Schemas and roles: ATTENTION needed. Read the report below before running the next script.';
ELSE
    PRINT N'Schemas and roles: no problems found.';

PRINT N'';

SELECT Severity, Status, Item, Detail
  FROM @Report
 ORDER BY Severity, RowNo;
GO
