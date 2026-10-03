/***********************************************************************************************************************
Script:         000_prerequisites.sql
Purpose:        The first script of a deployment.  Asserts the server is a version these conventions can run on,
                creates the target database if it does not exist, reuses it if it does, and sets the database-level
                options the rest of the deployment assumes.
Target:         SQL Server 2022.
Run as:         A login with CREATE DATABASE on the server, and db_owner on the database once it exists.
Run in:         master.  This is the ONE script in the deployment that does not run in the target database -- it is the
                script that creates it.
Run with:       sqlcmd -S <server> -d master -v DbName=<database> -I -C -i database/000_prerequisites.sql
Idempotent:     Yes.  The database is created only if absent; every option is set only if it is not already set, so a
                second run prints its report and changes nothing.
Depends on:     Nothing.  This is the first script.
Implements:     DES-AUTH-001 section 21.1.  PLAN-AUTH-001 task T-009.
To retarget:    Pass it per run:  -v DbName=<database>.  There is no in-file default and there must never be one --
                an in-file :setvar OVERRIDES -v rather than yielding to it, so a "harmless default" would silently
                decide the target on every documented run.

WHY THIS SCRIPT RUNS IN master AND EVERY OTHER SCRIPT DOES NOT
-------------------------------------------------------------
Every other script in this deployment opens by asserting  DB_NAME () = N'$(DbName)'  and stops if it is not, which is
the guard that stops a deployment landing in the wrong database.  This script cannot do that, because at the moment it
starts the target database may not exist yet.  So the assertion here is inverted: it refuses to run if it is NOT in
master, which is the only place the create can legitimately happen.

That asymmetry is deliberate and it is the reason this file is numbered 000 and is the only one of its kind.  After it,
every script asserts its target the normal way.

WHAT "SQL SERVER 2022 IS THE FLOOR AND THE CEILING" MEANS FOR THIS CHECK
-----------------------------------------------------------------------
The floor is enforced hard: below major version 16 the deployment stops, because the procedure template uses LEAST ()
and several other 2022 constructs that do not parse on 2017 or 2019.  There is no degraded mode.

The ceiling is a rule about what you WRITE, not about where you run.  These scripts run perfectly well on a newer
server; what must not happen is somebody authoring a 2025-only construct on a newer developer instance and shipping it
to a 2022 server, where it fails at CREATE time.  So a newer server gets a warning rather than a refusal, and the
warning names the real risk.
***********************************************************************************************************************/

:on error exit

-- THE TARGET DATABASE IS SUPPLIED ON THE COMMAND LINE AND HAS NO DEFAULT.  There is deliberately no `:setvar DbName`
-- line: measured on sqlcmd 17, a :setvar in the file OVERRIDES -v rather than acting as a fallback for its absence.

SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;
GO


-- *** 0. Assert we are in master ***
-- The inverse of every other script's guard, for the reason in the header.
IF DB_NAME () <> N'master'
BEGIN
    DECLARE @WrongDb NVARCHAR (2000) =
        N'000_prerequisites.sql must run in master, because it may need to CREATE the target database. '
      + N'Connected to [' + DB_NAME () + N']. Re-run with  -d master -v DbName=$(DbName). Nothing has been changed.';

    THROW 50000, @WrongDb, 1;
END
GO


-- *** 1. Assert the server version ***
DECLARE @Major INT = CAST (SERVERPROPERTY ('ProductMajorVersion') AS INT);

IF @Major IS NULL
BEGIN
    THROW 50000, N'Could not read ProductMajorVersion from SERVERPROPERTY. This is not a SQL Server instance these conventions support.', 1;
END;

IF @Major < 16
BEGIN
    DECLARE @TooOld NVARCHAR (2000) =
        N'SQL Server 2022 (major version 16) is the floor. This instance reports major version '
      + CAST (@Major AS NVARCHAR (10)) + N' (' + CAST (SERVERPROPERTY ('ProductVersion') AS NVARCHAR (50))
      + N'). The procedure template uses LEAST (), which does not exist before 2022, so a deployment here would fail '
      + N'part way through rather than cleanly. Nothing has been changed.';

    THROW 50000, @TooOld, 1;
END;

IF @Major > 16
BEGIN
    PRINT N'WARNING: this instance is newer than SQL Server 2022 (major version '
        + CAST (@Major AS NVARCHAR (10)) + N').';
    PRINT N'         The scripts will run. The risk is the other direction: a 2025-only construct authored here';
    PRINT N'         deploys cleanly on this instance and fails at CREATE time on every 2022 server in the estate.';
    PRINT N'         The convention gate (.claude/hooks/validate-sql.py) is what catches that -- keep it enabled.';
    PRINT N'';
END;
GO


-- *** 2. Create the database if it does not exist; reuse it if it does ***
-- Guarded rather than DROP ... CREATE.  Re-running a deployment against a populated database is the normal case, and
-- a script that drops it to make itself repeatable is a hard delete of real data.
IF DB_ID (N'$(DbName)') IS NULL
BEGIN
    PRINT N'Database [$(DbName)] does not exist. Creating it.';
    -- Not inside a transaction: CREATE DATABASE cannot run in one, which is also why this script opens no explicit
    -- transaction anywhere. XACT_ABORT still applies to the statements that can participate in one.
    CREATE DATABASE [$(DbName)];
END
ELSE
BEGIN
    PRINT N'Database [$(DbName)] already exists. Reusing it; nothing dropped, nothing recreated.';
END
GO


-- *** 3. Database options ***
-- Each guarded on its current value, so a second run reports and changes nothing.

-- 3a. Compatibility level 160 (SQL Server 2022).
-- A database restored from an older server keeps its old compatibility level even on a 2022 instance, which is the
-- quiet way LEAST () and the other 2022 constructs stop parsing on a server that is unambiguously 2022.
IF EXISTS (SELECT 1 FROM sys.databases WHERE name = N'$(DbName)' AND compatibility_level <> 160)
BEGIN
    PRINT N'Setting compatibility level to 160.';
    ALTER DATABASE [$(DbName)] SET COMPATIBILITY_LEVEL = 160;
END
GO

-- 3b. READ_COMMITTED_SNAPSHOT.
-- Readers do not block writers and writers do not block readers.  It matters more here than in an ordinary database:
-- every read passes through a row-level security predicate that touches auth.ProfilePermissionScope and
-- auth.TenantClosure, so those two small tables are in the path of every query in the system.  Under locking read
-- committed, one administrator editing a role grant would block every reader in every tenant.
--
-- WITH ROLLBACK IMMEDIATE terminates other connections to the database.  That is safe on a deployment target and is
-- NOT safe on a live one, which is why this prints what it is about to do.  On a database with no other sessions it
-- is a no-op with a scary name.
IF EXISTS (SELECT 1 FROM sys.databases WHERE name = N'$(DbName)' AND is_read_committed_snapshot_on = 0)
BEGIN
    PRINT N'Setting READ_COMMITTED_SNAPSHOT ON. This terminates other connections to [$(DbName)].';
    ALTER DATABASE [$(DbName)] SET READ_COMMITTED_SNAPSHOT ON WITH ROLLBACK IMMEDIATE;
END
GO

-- 3c. Page verify CHECKSUM, and auto-close off.
-- AUTO_CLOSE on a database that a web application connects to is a measurable per-connection cost and is occasionally
-- still the default on a developer instance.
IF EXISTS (SELECT 1 FROM sys.databases WHERE name = N'$(DbName)' AND page_verify_option_desc <> N'CHECKSUM')
BEGIN
    PRINT N'Setting PAGE_VERIFY CHECKSUM.';
    ALTER DATABASE [$(DbName)] SET PAGE_VERIFY CHECKSUM;
END
GO

IF EXISTS (SELECT 1 FROM sys.databases WHERE name = N'$(DbName)' AND is_auto_close_on = 1)
BEGIN
    PRINT N'Setting AUTO_CLOSE OFF.';
    ALTER DATABASE [$(DbName)] SET AUTO_CLOSE OFF;
END
GO


-- *** 4. Closing report ***
DECLARE @Report TABLE
(
    RowNo    INT IDENTITY (1, 1) PRIMARY KEY,
    Severity INT             NOT NULL,
    Status   VARCHAR (10)    NOT NULL,
    Item     NVARCHAR (200)  NOT NULL,
    Detail   NVARCHAR (1000)     NULL
);

INSERT @Report (Severity, Status, Item, Detail)
SELECT 4, 'OK', N'Server version'
     , N'Major ' + CAST (SERVERPROPERTY ('ProductMajorVersion') AS NVARCHAR (10))
     + N' (' + CAST (SERVERPROPERTY ('ProductVersion') AS NVARCHAR (50)) + N'), edition '
     + CAST (SERVERPROPERTY ('Edition') AS NVARCHAR (100));

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN DB_ID (N'$(DbName)') IS NULL THEN 1 ELSE 4 END
     , CASE WHEN DB_ID (N'$(DbName)') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Database [$(DbName)]'
     , N'The deployment target. Created by this script if it was absent, reused if it was present.';

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN d.compatibility_level = 160 THEN 4 ELSE 2 END
     , CASE WHEN d.compatibility_level = 160 THEN 'OK' ELSE 'STALE' END
     , N'Compatibility level'
     , N'Is ' + CAST (d.compatibility_level AS NVARCHAR (10))
     + N'; 160 expected. A lower level stops the 2022 constructs parsing on a server that is otherwise 2022.'
  FROM sys.databases AS d WHERE d.name = N'$(DbName)';

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN d.is_read_committed_snapshot_on = 1 THEN 4 ELSE 2 END
     , CASE WHEN d.is_read_committed_snapshot_on = 1 THEN 'OK' ELSE 'OFF' END
     , N'READ_COMMITTED_SNAPSHOT'
     , N'Every read passes through a security predicate that touches two small shared tables, so under locking read '
     + N'committed one administrator editing a grant blocks every reader in every tenant.'
  FROM sys.databases AS d WHERE d.name = N'$(DbName)';

INSERT @Report (Severity, Status, Item, Detail)
SELECT 4, 'INFO', N'Collation'
     , CAST (DATABASEPROPERTYEX (N'$(DbName)', 'Collation') AS NVARCHAR (128))
     + N'. Reported rather than asserted: these conventions do not require a particular collation, but a database '
     + N'whose collation differs from the server''s will surprise somebody joining to a temp table.';

INSERT @Report (Severity, Status, Item, Detail)
SELECT 3, 'NEXT', N'Run database/005_schemas_and_roles.sql'
     , N'It creates the auth, logs, config and util schemas and the four database roles. Until the roles exist, every '
     + N'grant in every later script is guarded on a principal that is absent and is therefore silently skipped.';

IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
    PRINT N'Prerequisites: PROBLEMS found. Read the report below before running the next script.';
ELSE
    PRINT N'Prerequisites: no problems found.';

PRINT N'';

SELECT Severity, Status, Item, Detail
  FROM @Report
 ORDER BY Severity, RowNo;
GO
