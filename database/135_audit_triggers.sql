/***********************************************************************************************************************
Script:         135_audit_triggers.sql
Purpose:        Prove that every plain table in this database carries its AFTER UPDATE audit trigger, and FAIL THE
                DEPLOYMENT if one is missing, misnamed, disabled, or not maintaining the audit block.  This script
                creates nothing.
Target:         SQL Server 2022.
Run as:         db_owner in the target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/135_audit_triggers.sql
Idempotent:     Yes, trivially.  It writes nothing at all.
Depends on:     Every table script in the manifest, which is why it runs near the end.
Implements:     DES-AUTH-001 section 3, gap G-23, error E-50210 and E-50211.
Tasks:          T-101.
To retarget:    Pass it per run:  sqlcmd -d <database> -v DbName=<database>.  There is no in-file default.

THIS SCRIPT IS INVERTED, AND THE INVERSION IS THE WHOLE POINT
------------------------------------------------------------
The project plan asked for a script that CREATES the AFTER UPDATE audit triggers for every auth, logs and config table.
It does the opposite: it asserts they already exist.  That is not a shortcut and it is worth setting out why, because a
reader who expected a generator will otherwise think something is missing.

Every table's trigger ships in the same file as the table -- BL-022 -- and it ships there for a reason that a generator
cannot work around: THE TRIGGERS ARE NOT INTERCHANGEABLE.  They share a shape, but each one also enforces that table's
own immutability rules, and those rules are facts about the table rather than facts about the convention:

    dbo.trg_au_updt_CaseFile      refuses a change to TenantId (E-50011) and to ApprovedByProfileId once set (E-50010)
    dbo.trg_au_updt_CaseNote      refuses a change to TenantId or CaseFileId (E-50011)
    auth.trg_au_updt_Role         refuses any change INV-10 forbids on a system role (E-50012)

A generator that produced a uniform trigger from sys.columns would either omit those rules or invent them, and in both
cases the generated trigger would be WRONG while looking right.  Worse, it would have to CREATE OR ALTER over the
hand-written triggers on every deployment, so the rules above would survive exactly until the next build.

So the convention is: the trigger belongs to the table, and this file's job is to make the convention enforceable.  A
missing trigger is otherwise invisible -- the table works, no error is raised, and its audit columns quietly stop being
maintained on UPDATE while every soft delete records neither who nor when.  That is the single most expensive kind of
defect this database can have, because it is discovered by somebody asking who changed a row and finding out that
nothing knows.

WHAT IS ASSERTED, PRECISELY
---------------------------
For every user table in auth, config, dbo, logs and util, minus the exemptions below:

  1. a trigger named  trg_au_updt_<TableName>  exists on that table                        -- E-50210
  2. it is an AFTER trigger and not an INSTEAD OF trigger                                  -- E-50210
  3. it is enabled                                                                         -- E-50210
  4. its definition stamps auditModifiedDateUtc and reads SESSION_CONTEXT (N'AppUser')     -- E-50211
  5. its definition stamps auditDeletedBy on the 0 -> 1 transition of IsDeleted, BUT ONLY
     on a table whose IsDeleted is not already paired with auditDeletedBy by a CHECK
     constraint -- see the next essay, which is the reason for the qualification          -- E-50211

Checks 4 and 5 are the difference between "a trigger exists" and "the audit block is maintained".  They are text tests
against sys.sql_modules, which is a blunt instrument and is stated as such: a trigger can satisfy them and still be
wrong.  They are here because the failure they catch -- somebody copies the trigger shape and drops the soft-delete
branch -- is common, silent and otherwise unreportable.

Checks 1 to 3 raise E-50210; checks 4 and 5 raise E-50211.  The two numbers are separate because they mean different
things to whoever reads the failure: E-50210 says a table has no audit trigger, E-50211 says a table has one that does
not do the job.

WHY CHECK 5 IS CONDITIONAL: CHECK CONSTRAINTS ARE EVALUATED BEFORE AFTER TRIGGERS FIRE
-------------------------------------------------------------------------------------
Check 5 was unconditional in the first version of this script, and on its first run it failed the deployment on
auth.trg_au_updt_ProfilePermissionScope -- correctly identifying the one trigger in the database that does NOT carry an
auditDeletedBy branch.  The trigger turned out to be right and the check turned out to be wrong, and the reason is worth
writing down at length because it governs every soft delete in this database and is not visible in any one table.

Almost every table here carries a constraint of the shape

    CONSTRAINT CK_<schema>_<Table>_DeletedPair CHECK (   (IsDeleted = 0 AND auditDeletedBy IS NULL)
                                                      OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL))

SQL Server evaluates CHECK constraints as part of the statement, BEFORE any AFTER trigger on the table fires.  So on a
table with that constraint, the classic soft delete

    UPDATE dbo.CaseFile SET IsDeleted = 1 WHERE CaseFileId = @Id;

does not reach the trigger at all.  It is rejected outright:

    Msg 547, Level 16, State 0 -- The UPDATE statement conflicted with the CHECK constraint
    "CK_dbo_CaseFile_DeletedPair".

That was confirmed by running it, not reasoned about.  The consequence is unavoidable: a trigger can NEVER be the thing
that stamps auditDeletedBy on a table that pairs the two columns in a CHECK constraint, because the constraint has
already rejected the only statement that would have invoked the trigger.  The soft-delete branch present in most of this
database's audit triggers is therefore UNREACHABLE on those tables.  It is retained -- it is harmless, and it becomes
live again the moment somebody drops the constraint -- but it is not what makes soft delete work, and nobody should
believe it is.

What makes soft delete work is the CALLER setting all three columns in one statement:

    UPDATE dbo.CaseFile
       SET IsDeleted = 1, auditDeletedBy = @Actor, auditDeletedDateUtc = SYSUTCDATETIME ()
     WHERE CaseFileId = @Id AND IsDeleted = 0;

auth.uspRebuildProfilePermissionScope already does exactly this, and 065_auth_effective_permission.sql says so in
terms -- "IT SETS auditDeletedBy AND auditDeletedDateUtc ITSELF rather than leaving them to the trigger" -- which is why
its trigger has no such branch and why the first version of check 5 flagged the one honest case in the database.

So the check is inverted for those tables.  Where the paired CHECK constraint exists, the report says CALLER and no
assertion is made about the trigger's soft-delete branch.  Where it does NOT exist, nothing but the trigger can stamp
the soft delete, a missing branch means a soft delete that records neither who nor when, and check 5 is enforced as
before.  The split is summarised once in the report as 'Soft-delete stamp ownership' with both counts, so that a reader
learns the rule from the report rather than from this comment.

The residual risk this leaves is real and is stated rather than papered over: on a paired table, a caller that forgets
the two audit columns gets Msg 547 and fails loudly, which is the good failure; but a caller that sets auditDeletedBy
to something untrue gets no complaint from anything.  The constraint proves a value is PRESENT, never that it is
CORRECT.  That is why section 14's calling contract routes every write through a procedure.

THE ONE EXEMPTION, AND THE TEST THAT JUSTIFIES IT
-------------------------------------------------
logs.ExecutionLog carries no AFTER UPDATE trigger, deliberately, and it is the only table in the database that does.

The conventions' test for an exemption is whether the table has a SINGLE WRITER that can be trusted to maintain the
audit columns itself.  logs.ExecutionLog passes that test in the strongest possible form: its only writers are
logs.uspStartExecutionLogging, logs.uspEndExecutionLogging, logs.uspRecordExecutionError and logs.uspLogExecutionStep,
they are generated by the conventions skill rather than by this project, and nothing else in the database is permitted
to write to it.

There is also a second reason, which is the one that makes the exemption necessary rather than merely defensible.  A
trigger on logs.ExecutionLog would fire inside the Rule 8 instrumentation of every procedure in this database -- on the
hottest write path there is, twice per call.  And it would fire inside the CATCH block: logs.uspRecordExecutionError
updates the row it is reporting a failure on, so an error raised by a trigger there would REPLACE the error being
reported, and the original failure would be lost.  An audit trigger that can hide the error it is auditing is worse than
no audit trigger.

The exemption is a row in a table below rather than a predicate in a WHERE clause, so that it appears in the report, can
be counted, and cannot be added to by accident.  A stale exemption -- one naming a table that no longer exists -- is
itself reported, because an exemption list nobody prunes is an exemption list nobody can trust.

WHY NOT THE CONVENTION VALIDATOR
--------------------------------
.claude/hooks/validate-sql.py already requires an audit trigger beside every CREATE TABLE it sees, and it blocks the
write when one is absent.  That catches the defect at authoring time in this repository, and it is the better place to
catch it.  It cannot catch the two cases this script exists for: a table created by a script the validator never saw,
and a trigger dropped or disabled in the deployed database after the build.  Both are the deployed state, and only the
deployed database can be asked about the deployed state.
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


-- *** 1. The exemption list ***
-- One row per table that is permitted to have no AFTER UPDATE audit trigger, with the reason it is permitted, so that
-- the reason is read every time somebody reads the report.  Adding a row here is a design decision and should be
-- accompanied by an entry in the build log.

DECLARE @Exempt TABLE
(
    SchemaName SYSNAME         NOT NULL
  , TableName  SYSNAME         NOT NULL
  , Reason     NVARCHAR (1000) NOT NULL
  , PRIMARY KEY (SchemaName, TableName)
);

INSERT @Exempt (SchemaName, TableName, Reason)
VALUES (N'logs', N'ExecutionLog'
      , N'Single-writer: logs.uspStartExecutionLogging, logs.uspEndExecutionLogging, logs.uspRecordExecutionError and '
      + N'logs.uspLogExecutionStep are its only writers and maintain the audit columns themselves. A trigger here would '
      + N'also fire inside every procedure''s own instrumentation, including inside the CATCH block, where an error it '
      + N'raised would REPLACE the error being reported and lose the original failure. See the file header.');


-- *** 2. The assertion ***
DECLARE @Report TABLE
(
    RowNo    INT IDENTITY (1, 1) PRIMARY KEY
  , Severity INT             NOT NULL
  , Status   VARCHAR (10)    NOT NULL
  , Item     NVARCHAR (200)  NOT NULL
  , Detail   NVARCHAR (1000)     NULL
);

-- Every table that must carry a trigger, with the trigger it should have and the one it does have.
DECLARE @Checked TABLE
(
    SchemaName    SYSNAME         NOT NULL
  , TableName     SYSNAME         NOT NULL
  , ExpectedName  SYSNAME         NOT NULL
  , ActualName    SYSNAME             NULL
  , IsDisabled    BIT                 NULL
  , IsInsteadOf   BIT                 NULL
  , Definition    NVARCHAR (MAX)      NULL
  , HasPairCheck  BIT             NOT NULL
  , PRIMARY KEY (SchemaName, TableName)
);

INSERT @Checked (SchemaName, TableName, ExpectedName, ActualName, IsDisabled, IsInsteadOf, Definition, HasPairCheck)
SELECT s.name
     , t.name
     , N'trg_au_updt_' + t.name
     , tr.name
     , tr.is_disabled
     , tr.is_instead_of_trigger
     , m.definition
       -- Does the table pair IsDeleted with auditDeletedBy in a CHECK constraint?  This decides whether the trigger is
       -- ALLOWED to be the thing that stamps the soft delete -- see check 5 in the file header.
     , CAST (CASE WHEN EXISTS (SELECT 1
                                 FROM sys.check_constraints AS cc
                                WHERE cc.parent_object_id = t.object_id
                                  AND cc.definition LIKE N'%auditDeletedBy%')
                  THEN 1 ELSE 0 END AS BIT)
  FROM sys.tables  AS t
  JOIN sys.schemas AS s ON s.schema_id = t.schema_id
  LEFT JOIN sys.triggers    AS tr ON tr.parent_id  = t.object_id
                                 AND tr.name       = N'trg_au_updt_' + t.name
  LEFT JOIN sys.sql_modules AS m  ON m.object_id   = tr.object_id
 WHERE s.name IN (N'auth', N'config', N'dbo', N'logs', N'util')
   AND t.is_ms_shipped = 0
   AND NOT EXISTS (SELECT 1 FROM @Exempt AS e
                    WHERE e.SchemaName = s.name AND e.TableName = t.name);

-- 2a. Checks 1 to 3: the trigger exists, is an AFTER trigger, and is enabled.  E-50210.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN c.ActualName  IS NULL THEN 1
            WHEN c.IsInsteadOf = 1     THEN 1
            WHEN c.IsDisabled  = 1     THEN 1
            ELSE 4 END
     , CASE WHEN c.ActualName  IS NULL THEN 'MISSING'
            WHEN c.IsInsteadOf = 1     THEN 'WRONGKIND'
            WHEN c.IsDisabled  = 1     THEN 'DISABLED'
            ELSE 'OK' END
     , N'Audit trigger ' + QUOTENAME (c.SchemaName) + N'.' + QUOTENAME (c.ExpectedName)
     , CASE WHEN c.ActualName IS NULL
            THEN N'No such trigger on ' + QUOTENAME (c.SchemaName) + N'.' + QUOTENAME (c.TableName)
               + N'. Every UPDATE on this table leaves auditModifiedBy and auditModifiedDateUtc at their insert-time '
               + N'values, and every soft delete records neither who nor when. The trigger belongs in the script that '
               + N'creates the table -- BL-022 -- not here. E-50210.'
            WHEN c.IsInsteadOf = 1
            THEN N'This is an INSTEAD OF trigger. The audit stamp must be applied to the row as it lands, which means '
               + N'AFTER UPDATE; an INSTEAD OF trigger replaces the statement and would have to reimplement it. E-50210.'
            WHEN c.IsDisabled = 1
            THEN N'The trigger exists and is DISABLED, which is indistinguishable from absent at run time and harder to '
               + N'notice. ALTER TABLE ... ENABLE TRIGGER, and find out who disabled it and why. E-50210.'
            ELSE N'Present, AFTER UPDATE, enabled.' END
  FROM @Checked AS c;

-- 2b. Checks 4 and 5: the trigger actually maintains the audit block.  E-50211.  Only tables that passed 2a are
--     examined, because reporting "the missing trigger does not stamp auditModifiedDateUtc" twice helps nobody.
--
--     CHECK 5 IS CONDITIONAL ON HasPairCheck, AND THAT CONDITION IS THE INTERESTING PART OF THIS SCRIPT.  A table that
--     pairs IsDeleted with auditDeletedBy in a CHECK constraint CANNOT have its soft-delete stamp applied by an AFTER
--     trigger, because SQL Server evaluates CHECK constraints BEFORE AFTER triggers fire.  On such a table
--     `UPDATE ... SET IsDeleted = 1` is rejected with Msg 547 and the trigger never runs at all, so demanding that its
--     definition mention auditDeletedBy is demanding a branch that can never execute.  Asserting that would be asserting
--     something false, which is worse than asserting nothing.  See the file header.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN c.Definition NOT LIKE N'%auditModifiedDateUtc%'                  THEN 2
            WHEN c.Definition NOT LIKE N'%SESSION_CONTEXT%'                       THEN 2
            WHEN c.HasPairCheck = 0 AND c.Definition NOT LIKE N'%auditDeletedBy%' THEN 2
            ELSE 4 END
     , CASE WHEN c.Definition NOT LIKE N'%auditModifiedDateUtc%'                  THEN 'NOSTAMP'
            WHEN c.Definition NOT LIKE N'%SESSION_CONTEXT%'                       THEN 'NOACTOR'
            WHEN c.HasPairCheck = 0 AND c.Definition NOT LIKE N'%auditDeletedBy%' THEN 'NODELETE'
            WHEN c.HasPairCheck = 1                                               THEN 'CALLER'
            ELSE 'OK' END
     , N'Maintains the block ' + QUOTENAME (c.SchemaName) + N'.' + QUOTENAME (c.ExpectedName)
     , CASE WHEN c.Definition NOT LIKE N'%auditModifiedDateUtc%'
            THEN N'The trigger never mentions auditModifiedDateUtc, so it is not stamping the modification time, which '
               + N'is the one thing it exists to do. E-50211.'
            WHEN c.Definition NOT LIKE N'%SESSION_CONTEXT%'
            THEN N'The trigger never reads SESSION_CONTEXT, so auditModifiedBy will record the pooled application '
               + N'login rather than the acting user -- identical on every row and therefore worthless. DES section '
               + N'14.4. E-50211.'
            WHEN c.HasPairCheck = 0 AND c.Definition NOT LIKE N'%auditDeletedBy%'
            THEN N'The trigger never mentions auditDeletedBy, and this table has no CHECK constraint pairing IsDeleted '
               + N'with auditDeletedBy, so nothing at all stamps a soft delete here: it records neither who nor when '
               + N'and raises no error. This is the branch most often lost when the trigger shape is copied from '
               + N'another table. E-50211.'
            WHEN c.HasPairCheck = 1
            THEN N'Stamps the modified pair and reads the session context. The SOFT-DELETE stamp is the CALLER''S, not '
               + N'this trigger''s: a CHECK constraint on this table pairs IsDeleted with auditDeletedBy, and SQL '
               + N'Server evaluates CHECK constraints BEFORE AFTER triggers, so UPDATE ... SET IsDeleted = 1 on its '
               + N'own is rejected with Msg 547 and the trigger never fires. Every soft delete must set IsDeleted, '
               + N'auditDeletedBy and auditDeletedDateUtc in ONE statement. Any auditDeletedBy branch in the trigger '
               + N'is unreachable and is retained only as a backstop should the constraint ever be dropped.'
            ELSE N'Stamps the modified pair, reads the session context, and handles the soft-delete transition.' END
  FROM @Checked AS c
 WHERE c.ActualName IS NOT NULL
   AND c.IsDisabled = 0
   AND c.IsInsteadOf = 0
   -- ONLY THE FAILURES GET A ROW.  A passing table is counted in 2f instead of listed here, and that is not tidiness for
   -- its own sake: 33 of 34 tables pass as CALLER, and emitting 33 rows of near-identical Severity-4 prose on every
   -- deployment is how a report teaches people to scroll past it.  The CASE arms above still spell out all four verdicts,
   -- because the arm a table WOULD have taken is the documentation of what is being asserted.  2f states the split.
   AND (   c.Definition NOT LIKE N'%auditModifiedDateUtc%'
        OR c.Definition NOT LIKE N'%SESSION_CONTEXT%'
        OR (c.HasPairCheck = 0 AND c.Definition NOT LIKE N'%auditDeletedBy%'));

-- 2c. The exemptions themselves, reported rather than hidden.  Severity 3: an exemption is a decision, not a fault, and
--     it should be re-read on every deployment rather than forgotten.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (QUOTENAME (e.SchemaName) + N'.' + QUOTENAME (e.TableName), N'U') IS NULL THEN 2 ELSE 3 END
     , CASE WHEN OBJECT_ID (QUOTENAME (e.SchemaName) + N'.' + QUOTENAME (e.TableName), N'U') IS NULL THEN 'STALE'
            ELSE 'EXEMPT' END
     , N'Exemption ' + QUOTENAME (e.SchemaName) + N'.' + QUOTENAME (e.TableName)
     , CASE WHEN OBJECT_ID (QUOTENAME (e.SchemaName) + N'.' + QUOTENAME (e.TableName), N'U') IS NULL
            THEN N'This exemption names a table that does not exist in this database. A stale exemption is how an '
               + N'exemption list stops being trustworthy: the next table to take that name inherits the exemption '
               + N'silently. Remove the row. Original reason: ' + e.Reason
            ELSE e.Reason END
  FROM @Exempt AS e;

-- 2d. An exempt table that has acquired a trigger anyway.  Not a fault -- the trigger is doing no harm and may be an
--     improvement -- but the exemption is then a lie, and the two should be reconciled.
INSERT @Report (Severity, Status, Item, Detail)
SELECT 3
     , 'REVIEW'
     , N'Exemption contradicted ' + QUOTENAME (e.SchemaName) + N'.' + QUOTENAME (e.TableName)
     , N'This table is exempt from the audit-trigger rule and nonetheless carries ' + tr.name + N'. Somebody has '
     + N'decided the exemption is unnecessary without removing it. Either drop the trigger or remove the exemption '
     + N'row from section 1 of this script, so that the list and the database agree.'
  FROM @Exempt AS e
  JOIN sys.tables   AS t  ON t.name      = e.TableName
  JOIN sys.schemas  AS s  ON s.schema_id = t.schema_id AND s.name = e.SchemaName
  JOIN sys.triggers AS tr ON tr.parent_id = t.object_id
 WHERE tr.is_instead_of_trigger = 0;

-- 2e. The count, so a reader can see at a glance how much was checked rather than trusting that anything was.
DECLARE @Tables INT = (SELECT COUNT (*) FROM @Checked)
      , @Exempts INT = (SELECT COUNT (*) FROM @Exempt)
      , @Bad INT;

INSERT @Report (Severity, Status, Item, Detail)
VALUES (4, 'INFO', N'Tables examined'
      , CONCAT (N'', @Tables, N' table(s) in auth, config, dbo, logs and util required an AFTER UPDATE audit trigger; '
              , @Exempts, N' exempt table(s) were skipped. A count of 0 here would mean the schema filter matched '
              , N'nothing and the assertion proved nothing -- which is why it is reported.'));

IF @Tables = 0
BEGIN
    UPDATE @Report SET Severity = 1, Status = 'EMPTY' WHERE Item = N'Tables examined';
END;

-- 2f. The soft-delete ownership split, stated once rather than once per table.  Section 2b lists only the tables that
--     FAIL, so on a healthy database this row is the only evidence that check 5 ran at all -- which is why it also states
--     how many tables it passed over.  The rule behind it is the single easiest thing in this database to get wrong and it
--     is invisible in any individual table's definition.
DECLARE @Paired INT = (SELECT COUNT (*) FROM @Checked WHERE HasPairCheck = 1)
      , @Passed INT = (SELECT COUNT (*)
                         FROM @Checked AS c
                        WHERE c.ActualName IS NOT NULL
                          AND c.IsDisabled  = 0
                          AND c.IsInsteadOf = 0
                          AND c.Definition LIKE N'%auditModifiedDateUtc%'
                          AND c.Definition LIKE N'%SESSION_CONTEXT%'
                          AND (c.HasPairCheck = 1 OR c.Definition LIKE N'%auditDeletedBy%'));

INSERT @Report (Severity, Status, Item, Detail)
VALUES (4, 'INFO', N'Soft-delete stamp ownership'
      , CONCAT (N'', @Passed, N' trigger(s) passed checks 4 and 5 and are therefore not listed individually above. '
              , @Paired, N' of ', @Tables, N' examined table(s) pair IsDeleted with auditDeletedBy in a CHECK '
              , N'constraint, so on those tables the CALLER owns the soft-delete stamp and check 5 is not applied: SQL '
              , N'Server evaluates CHECK constraints BEFORE AFTER triggers, so UPDATE ... SET IsDeleted = 1 alone is '
              , N'rejected with Msg 547 and the trigger never fires. Set IsDeleted, auditDeletedBy and '
              , N'auditDeletedDateUtc in ONE statement. On the remaining ', @Tables - @Paired, N' table(s) nothing but '
              , N'the trigger can stamp the soft delete, so check 5 is enforced there. DES section 14.4.'));


-- *** 3. The report, and then the failure ***
IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
    PRINT N'Audit triggers: PROBLEMS found. The deployment will stop after the report below.';
ELSE
    PRINT N'Audit triggers: no problems found.';

PRINT N'';

SELECT Severity, Status, Item, Detail
  FROM @Report
 ORDER BY Severity, RowNo;

-- The throw comes last, so the report is always readable before the deployment stops.  Two numbers, checked in order of
-- seriousness: a table with no trigger at all is worse than a table with a trigger that does half the job.
DECLARE @Failure NVARCHAR (2000) = NULL
      , @Names   NVARCHAR (1000) = NULL;

SELECT @Bad = COUNT (*) FROM @Report WHERE Severity = 1;

IF @Bad > 0
BEGIN
    SELECT @Names = STRING_AGG (CAST (r.Item AS NVARCHAR (MAX)), N', ') WITHIN GROUP (ORDER BY r.RowNo)
      FROM (SELECT TOP (20) Item, RowNo FROM @Report WHERE Severity = 1 ORDER BY RowNo) AS r;

    SET @Failure = CONCAT (N'', @Bad, N' plain table(s) carry no usable AFTER UPDATE audit trigger: ', @Names
                         , N'. Every UPDATE on such a table leaves the audit columns at their insert-time values and '
                         , N'every soft delete records neither who nor when, with no error and nothing in any log -- '
                         , N'which is why this is a deployment failure and not a warning. The trigger ships in the '
                         , N'script that creates the table (BL-022); this script only asserts it. G-23.');

    THROW 50210, @Failure, 1;
END;

SELECT @Bad = COUNT (*) FROM @Report WHERE Severity = 2;

IF @Bad > 0
BEGIN
    SELECT @Names = STRING_AGG (CAST (r.Item AS NVARCHAR (MAX)), N', ') WITHIN GROUP (ORDER BY r.RowNo)
      FROM (SELECT TOP (20) Item, RowNo FROM @Report WHERE Severity = 2 ORDER BY RowNo) AS r;

    SET @Failure = CONCAT (N'', @Bad, N' audit trigger(s) or exemption(s) are present but not doing their job: ', @Names
                         , N'. A trigger that exists and does not stamp the audit block is worse than one that is '
                         , N'missing, because the report above is the only thing that distinguishes them. Read the '
                         , N'Detail column for which of the three checks failed.');

    THROW 50211, @Failure, 1;
END;
GO
