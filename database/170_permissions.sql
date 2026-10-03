/***********************************************************************************************************************
Script:         170_permissions.sql
Purpose:        The one place that states, for every schema in this database, what each role may do in it -- including
                the schemas the answer is "nothing" for.  Closes gap G-19.
Target:         SQL Server 2022 or newer.
Run as:         db_owner in the target database.
Run in:         The target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/170_permissions.sql
Idempotent:     Yes.  GRANT and DENY are declarative; running this twice leaves the same catalog rows.
Depends on:     005_schemas_and_roles.sql (the four roles), and every script that creates an object it names.
Implements:     DES-AUTH-001 section 13.  INV-11.  Gap G-19.  BL-015.  BL-047 (the rlsBypassRole assertion, rewritten
                after Phase 4 gave that role its first two permissions).
To retarget:    Pass it per run:  -d <database> -v DbName=<database>.  There is no in-file default.

WHY THIS FILE EXISTS, WHICH IS NOT THE SAME AS WHY PERMISSIONS EXIST
-------------------------------------------------------------------
Most of the grants in this database are already in place, made by the script that created the object they apply to --
085_logs_auth_tables.sql grants on SCHEMA::logs, 110_auth_authn_procedures.sql grants EXECUTE on its seven procedures,
112_auth_mfa_procedures.sql on its four, and so on.  That is the right default: a grant next to the thing it grants on
cannot be forgotten when the thing moves.

What it cannot do is notice an ABSENCE.  SCHEMA::config was created in 005, filled in 025, and read by every procedure
in 110 -- and until this file, no role had been granted or denied anything in it, ever.  Nobody noticed because nothing
broke: every procedure that reads a setting reaches it by ownership chaining, so the missing grant cost nothing and
announced nothing.  That was found by a catalog query during the first real Phase 0 deployment, not by reading the
scripts, and it is gap G-19 and build-log entry BL-015.

So this file's job is the complement of the others': it states the permissions that belong to no single object, and its
closing report asserts that EVERY user schema in the database now appears with either a grant or a stated deny.  The next
schema somebody adds cannot repeat G-19 silently -- it will fail this script.

THREE THINGS WERE MEASURED BEFORE THIS FILE WAS WRITTEN, BECAUSE ASSUMING THEM WOULD HAVE BEEN WRONG TWICE
---------------------------------------------------------------------------------------------------------
Each of these was run against a throwaway user in applicationRole and the answer is recorded here because the answer
changes the design, not merely the commentary.  BL-028.

  1.  A DENY on a table does NOT stop a procedure that reads it.  With DENY SELECT ON config.ApplicationSetting in
      place, auth.uspGetLoginVerifier -- which reads four settings out of that table -- ran normally, while a direct
      SELECT of the same row failed with error 229.  Ownership chaining is not "a grant you did not have to write"; the
      permission is not evaluated at all when the calling procedure and the table share an owner.  This is what makes
      the section 1 and section 3 denies affordable.

  2.  A DENY at schema level BEATS a GRANT at object level.  DENY EXECUTE ON SCHEMA::util made util.uspPhase0Probe
      unexecutable even though applicationRole holds an explicit object-level GRANT on it, measured both by
      HAS_PERMS_BY_NAME (0) and by calling it (error 229).  The column-level exception people remember from the
      documentation does not generalise: at every other pair of scopes, DENY wins.  Section 2 is written the way it is
      BECAUSE of this result -- a blanket DENY EXECUTE on util would have silently broken the Phase 0 probe.

  3.  A DENY on the four table verbs on SCHEMA::auth does not break the auth procedures either, and does stop a direct
      read.  That is what lets INV-11 stop being an absence and become a catalog row -- see section 3.

WHY THE ROLES ARE ASSERTED HERE AND NOT GUARDED
-----------------------------------------------
005_schemas_and_roles.sql sets the house convention of guarding every grant on the principal existing, and says why:
a name you have not created is a silently skipped grant.  This file inverts that, deliberately.  Everywhere else a
guard is the lesser evil, because the alternative is a script that cannot run at all on a partial deployment.  Here the
entire deliverable IS the permission state, so a run that skipped half of it and reported success would be the exact
failure G-19 describes.  Section 0 therefore asserts all four roles and throws if one is missing -- finding F-07's
shape, refused in the file whose subject is F-07's cousin.

WHAT IS DELIBERATELY NOT HERE
-----------------------------
  *  The other half of G-19 -- the same "every schema is stated" assertion inside 950_verify_deployment.sql -- is
     Phase 8's work, because 950 does not exist yet.  The assertion in section 6 below is the same query and will be
     lifted into it; until then the check runs at deployment time rather than at verification time, which is weaker
     only in that a later ad-hoc REVOKE would not be caught.  BL-029 records the debt rather than leaving it implied.
  *  No grant on any Phase 3 or Phase 4 object.  Every one of them is stated next to itself, which is the default this
     file's opening paragraph argues for: 105_auth_session_procedures.sql grants EXECUTE on the two session-context
     procedures to applicationRole and on the two maintenance-bypass procedures to rlsBypassRole, and the rest of Phase
     3 and Phase 4 -- the six functions, the three RLS predicates, auth.uspDemandPermission, the two rebuild
     procedures, the three trail recorders in logs -- is granted to NOBODY, on purpose.  What this file adds for them is
     section 6: those absences are asserted, so that the next convenience grant fails a deployment instead of passing
     one.

WHAT PHASE 4 CHANGED ABOUT THIS FILE, AND HOW IT WAS FOUND
---------------------------------------------------------
Until Phase 4 this file asserted that rlsBypassRole held NO permission anywhere, and section 6d said so in those words.
That stopped being true the moment 105_auth_session_procedures.sql shipped: the two maintenance-bypass procedures are
role-gated by IS_ROLEMEMBER, and a role-gated procedure that the role cannot execute is a locked door with no handle, so
105 grants EXECUTE on both to rlsBypassRole -- next to the objects, where the grant belongs.

Running this file after Phase 4 therefore failed: 2 permissions found, expected 0, severity 2, THROW.  That is the
assertion doing its job, and it is worth recording how cheap the alternative would have been to get wrong -- a report
that had merely LISTED rlsBypassRole's permissions would have printed two new rows and nobody would have looked.
Section 6d now asserts the shape that is actually intended, which is narrower than either "none" or "some": EXECUTE on
exactly those two procedures, and nothing else of any kind, anywhere.  BL-047.
***********************************************************************************************************************/

:on error exit

-- THE TARGET DATABASE IS SUPPLIED ON THE COMMAND LINE AND HAS NO DEFAULT.  There is deliberately no `:setvar DbName`
-- line: measured on sqlcmd 17, a :setvar in the file OVERRIDES -v rather than acting as a fallback for its absence.

SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;
GO


-- *** 0. Assert the target and the four roles ***
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

-- Asserted, not guarded -- the banner argues why this one file inverts the house convention.
IF DATABASE_PRINCIPAL_ID (N'applicationRole') IS NULL
   OR DATABASE_PRINCIPAL_ID (N'readOnlyRole') IS NULL
   OR DATABASE_PRINCIPAL_ID (N'logsAuditReader') IS NULL
   OR DATABASE_PRINCIPAL_ID (N'rlsBypassRole') IS NULL
BEGIN
    DECLARE @MsgRoles NVARCHAR (2000) =
        N'One or more of the four database roles is missing: applicationRole, readOnlyRole, logsAuditReader, '
      + N'rlsBypassRole. Run database/005_schemas_and_roles.sql first. This file grants and denies unguarded on '
      + N'purpose -- a half-applied permission model that reported success is the failure gap G-19 describes -- so it '
      + N'refuses to start. Nothing has been changed.';

    THROW 50000, @MsgRoles, 1;
END
GO

IF SCHEMA_ID (N'config') IS NULL OR SCHEMA_ID (N'util') IS NULL OR SCHEMA_ID (N'auth') IS NULL
BEGIN
    DECLARE @MsgSchemas NVARCHAR (2000) =
        N'One of the schemas this file states permissions for is missing: config, util or auth. Run '
      + N'database/005_schemas_and_roles.sql first. Nothing has been changed.';

    THROW 50000, @MsgSchemas, 1;
END
GO


-- *** 1. SCHEMA::config -- the gap itself ***
-- config holds operational settings: thresholds, timeouts, window lengths, the PHC template.  None of that is secret,
-- and a monitoring query that can report "the lockout threshold is 5" is a legitimate thing to be able to write.  So
-- SELECT is granted at the schema level, to both reading roles, which also means the next table added to config is
-- readable by default rather than invisible for a release and a half.
GRANT SELECT ON SCHEMA::config TO applicationRole;
GRANT SELECT ON SCHEMA::config TO readOnlyRole;
GO

-- AND THEN ONE TABLE IS TAKEN BACK OUT, because config.ApplicationSetting is not uniformly non-secret.  One row in it is
-- Authn.DummyVerifierPepper, and that row is the entire basis of section 19.2: the dummy verifier issued for a user name
-- nobody holds is HMAC-derived from the pepper, so a caller who can read the pepper can compute the dummy for any name
-- and compare it with what round trip 1 returned.  That caller can then enumerate every account in the database with no
-- extra requests at all -- the defence does not degrade, it disappears.  The application is the internet-facing
-- principal and is therefore exactly the principal that must not hold it.
--
-- SQL Server permissions cannot say "every row but that one", and the IsSensitive column that 025_config_tables.sql
-- already carries is the seam for saying it properly: a view filtered to IsSensitive = 0, granted to both roles, with
-- the table denied underneath it.  That view is NOT built here, because nothing has yet asked to read a setting
-- directly -- every procedure that needs one reaches it through ownership chaining, measured, finding 1 in the banner.
-- When something does ask, the answer is that view and not a REVOKE of these two lines.
DENY SELECT ON config.ApplicationSetting TO applicationRole;
DENY SELECT ON config.ApplicationSetting TO readOnlyRole;
GO

-- No write permission is granted in config to anybody.  Settings are changed by a deployment or by a db_owner at a
-- console, and an application that can rewrite its own lockout threshold has no lockout threshold.
GO


-- *** 2. SCHEMA::util -- the decision G-19 asked to see stated, whichever way it went ***
-- It went this way: the four TABLE verbs are denied at schema level, and EXECUTE is NOT.
--
-- The tempting version of this section was DENY EXECUTE ON SCHEMA::util, on the argument that util holds deployment
-- helpers no application should call.  Measuring it (finding 2 in the banner) showed that would have revoked
-- util.uspPhase0Probe from applicationRole even though 000_prerequisites.sql grants it explicitly at object level: a
-- schema DENY beats an object GRANT.  The Phase 0 connectivity probe would have started failing, at some later date,
-- for a reason nobody would have connected to this file.
--
-- So EXECUTE in util stays ungranted-by-default and granted one procedure at a time by the script that creates it,
-- which is a weaker statement than a DENY but an honest one -- and the section 6 report lists every util procedure with
-- its grant state, so "ungranted by default" is visible rather than assumed.  The table verbs cost nothing to deny:
-- util holds no tables today, and a DENY that is currently vacuous is precisely how the next one gets caught.
DENY SELECT, INSERT, UPDATE, DELETE ON SCHEMA::util TO applicationRole;
DENY SELECT, INSERT, UPDATE, DELETE ON SCHEMA::util TO readOnlyRole;
GO


-- *** 3. SCHEMA::auth -- turning INV-11 from an absence into a catalog row ***
-- INV-11 says applicationRole holds no table access to SCHEMA::auth.  Until now that was true the way G-19's config
-- hole was true: nobody had granted any, so nobody could use any.  An invariant that holds because of what is missing
-- cannot be verified, cannot be reported on, and stops holding the first time somebody grants a convenience SELECT to
-- get a page working on a Friday.
--
-- Measured, finding 3: this DENY does not affect the fifteen auth procedures applicationRole holds EXECUTE on.  They
-- read and write these tables through ownership chaining, where the permission is not consulted.
--
-- THE COST, STATED PLAINLY: because a schema DENY beats an object GRANT (finding 2), this forecloses ever granting
-- applicationRole SELECT on an individual auth table or view -- including the views in 095_auth_views.sql.  That is
-- intended.  It means every read the application makes of identity data must go through a procedure, which is where the
-- tenant filtering and the audit trail live.  A future requirement for a cheap read is a requirement for a procedure,
-- or for a view in another schema; it is not a requirement to revoke this.
DENY SELECT, INSERT, UPDATE, DELETE ON SCHEMA::auth TO applicationRole;
GO

-- readOnlyRole is NOT denied the whole of auth: it is a named reporting principal, and a Phase 6 reporting requirement
-- for "how many users per tenant" is reasonable and will be met by granting SELECT on a view.  What it is denied is the
-- five tables that hold credentials and second-factor material, one table at a time so that a later view grant is still
-- possible.  A reporting role that can read verifier strings and MFA ciphertext is a reporting role that is worth
-- attacking for the same reasons the application is.
DENY SELECT, INSERT, UPDATE, DELETE ON auth.UserCredential        TO readOnlyRole;
DENY SELECT, INSERT, UPDATE, DELETE ON auth.PasswordHistory       TO readOnlyRole;
DENY SELECT, INSERT, UPDATE, DELETE ON auth.UserMfaFactor         TO readOnlyRole;
DENY SELECT, INSERT, UPDATE, DELETE ON auth.UserMfaRecoveryCode   TO readOnlyRole;
DENY SELECT, INSERT, UPDATE, DELETE ON auth.UserFederatedIdentity TO readOnlyRole;
GO

-- The same five tables, denied to logsAuditReader for the same reason.  An auditor's remit is the change trail in
-- logsData and history, both of which they hold SELECT on; it has never been the credential store.
DENY SELECT, INSERT, UPDATE, DELETE ON auth.UserCredential        TO logsAuditReader;
DENY SELECT, INSERT, UPDATE, DELETE ON auth.PasswordHistory       TO logsAuditReader;
DENY SELECT, INSERT, UPDATE, DELETE ON auth.UserMfaFactor         TO logsAuditReader;
DENY SELECT, INSERT, UPDATE, DELETE ON auth.UserMfaRecoveryCode   TO logsAuditReader;
DENY SELECT, INSERT, UPDATE, DELETE ON auth.UserFederatedIdentity TO logsAuditReader;
GO


-- *** 4. SCHEMA::logs -- every table in it the application must not write, found by enumeration ***
-- THIS SECTION EXISTS BECAUSE THE INTENT AND THE CATALOG DISAGREED, and the catalog was winning quietly.
--
-- Section 8 of 085_logs_auth_tables.sql states it plainly: "applicationRole gets INSERT here through ownership chaining
-- only ... An INSERT grant would let a compromised application login forge the narrative of its own compromise -- and on
-- logs.AuthorizationChange, forge the authority it acted under."  165_logs_procedures.sql makes the same argument about
-- the three recorders and asserts in its own report that no EXECUTE was granted on them.
--
-- Both are true and neither was sufficient.  The conventions skill's own scripts/permissions.sql -- which every database
-- built to this house standard runs -- contains
--
--     GRANT SELECT, INSERT, UPDATE, DELETE ON SCHEMA::logs TO applicationRole;
--
-- because the logging framework expects the application to write logs.ExecutionLog directly.  That grant predates these
-- four tables and covered them the moment they were put in that schema.  So the application login could have inserted a
-- forged logs.AuthorizationChange row, UPDATEd a denial it had provoked, or DELETEd one -- no procedure, no permission
-- consulted, nothing to find afterwards.  Withholding EXECUTE on the recorders never closed that door; it closed the
-- polite way in.  Found by a catalog query during the Phase 3/4 closeout, for exactly the reason G-19 was found that
-- way: the grant nobody wrote is the grant nobody reviews.  BL-048.
--
-- THE FIRST VERSION OF THIS SECTION NAMED FOUR TABLES, AND G-23 SAID THAT WOULD NOT HOLD.  IT DID NOT HOLD.
-- G-23, filed at the Phase 4 closeout, made a prediction in writing: the schema grant is INHERITED and the denies were
-- ENUMERATED, so the fifth table anybody put in this schema would repeat the hole and this file's own report would still
-- say 12 of 12 OK.  Phase 5 added logs.PermissionProbe (175_perf_instrumentation.sql), whose banner says in so many
-- words "not granted to applicationRole; reached by ownership chaining" -- and measured as deployed,
-- HAS_PERMS_BY_NAME returned 1 for INSERT, UPDATE and DELETE on it to an applicationRole member, while the four trails
-- correctly returned 0.  Nine months of argument in this file's banner did not stop it, because a list is not a rule.
-- D-07 is taken on the contents of that table, so a table the application can insert rows into is a decision nobody can
-- audit -- and that is the same sentence BL-048 wrote about the trails.
--
-- So this section is now INVERTED, which is what G-23's proposed resolution asked for: enumerate sys.tables in logs,
-- subtract the ONE documented exception, and deny the write verbs on everything else -- including tables this file has
-- never heard of.  A table added in Phase 9 by somebody who never reads this comment is governed by it anyway.  The
-- exception list is data, with its reason attached, for the same reason 135_audit_triggers.sql holds its trigger
-- exemption as a row: an exemption with a stated reason is auditable, an exemption by omission is a hole.  BL-066.
-- IT IS A #TEMP TABLE AND NOT A @TABLE VARIABLE FOR ONE REASON: section 6e has to read the same list, and a table
-- variable does not survive the GO between them.  Declaring it twice would put the exemption in two places, which is the
-- defect this whole section is a repair of.  It is dropped at the end of section 6e.
DROP TABLE IF EXISTS #LogsWriteExempt;

CREATE TABLE #LogsWriteExempt
(
    TableName NVARCHAR (300) NOT NULL PRIMARY KEY,
    Reason    NVARCHAR (900) NOT NULL
);

INSERT #LogsWriteExempt (TableName, Reason)
VALUES (N'logs.ExecutionLog'
      , N'The house logging framework writes it from the APPLICATION side by design -- scripts/logExecutionLogging.sql '
      + N'and every procedure''s Rule 8 block. Narrowing it would be a change to the house convention rather than to '
      + N'this design, and it is the one table in this schema whose direct writability is the intended arrangement.');

DECLARE @Denied NVARCHAR (MAX) = N''
      , @Exempted NVARCHAR (MAX) = N''
      , @Stmt NVARCHAR (MAX) = N'';

-- The statement is built per table rather than issued once, because DENY takes one securable.  QUOTENAME on both parts:
-- a table name arriving from sys.tables is not a literal this file chose, which is exactly why it must be quoted.
SELECT @Stmt = @Stmt + N'DENY INSERT, UPDATE, DELETE ON '
                     + QUOTENAME (s.name) + N'.' + QUOTENAME (t.name) + N' TO applicationRole;' + NCHAR (10)
     , @Denied = @Denied + s.name + N'.' + t.name + N', '
  FROM sys.tables  AS t
  JOIN sys.schemas AS s ON s.schema_id = t.schema_id
 WHERE s.name = N'logs'
   AND t.is_ms_shipped = 0
   AND NOT EXISTS (SELECT 1 FROM #LogsWriteExempt AS e WHERE e.TableName = s.name + N'.' + t.name)
 ORDER BY t.name;

SELECT @Exempted = @Exempted + e.TableName + N', '
  FROM #LogsWriteExempt AS e
 WHERE OBJECT_ID (e.TableName, N'U') IS NOT NULL;

IF LEN (@Stmt) = 0
BEGIN
    PRINT N'No tables in SCHEMA::logs outside the exemption list, so no write denies were applied. That means '
        + N'database/085_logs_auth_tables.sql has not run. Section 6e reports the shortfall.';
END
ELSE
BEGIN
    EXEC sys.sp_executesql @Stmt;

    PRINT N'DENY INSERT, UPDATE, DELETE TO applicationRole on every table in SCHEMA::logs except the documented '
        + N'exemptions. The procedures still write them through ownership chaining -- measured, finding 1 in this '
        + N'file''s banner. Denied: ' + LEFT (@Denied, LEN (@Denied) - 1) + N'.';

    IF LEN (@Exempted) > 0
        PRINT N'Exempt by design, and the reason travels with the name in section 6e: '
            + LEFT (@Exempted, LEN (@Exempted) - 1) + N'.';
END
GO

-- SELECT IS LEFT ALONE, DELIBERATELY.  These tables are written so that nothing in them is dangerous to read -- 085's
-- banner makes that a rule about DetailJson -- and a read is not a forgery.  What governs the application's reading of a
-- trail is an application-level permission checked inside a procedure (Audit.ReadAuthorization and Audit.ReadDataChange,
-- appendix A); that is a different question from what a raw login may do with a SELECT, and answering it with a REVOKE
-- here would break the Phase 6 procedures that surface a trail on a screen.
--
-- logs.ExecutionLog is the one exemption, and it is now a ROW rather than a sentence -- see #LogsWriteExempt above.
-- The difference matters: a sentence explaining why a table is missing from a list cannot be read by section 6e, so the
-- report had to know the exception separately from the comment that justified it.  Two places, one fact, and the usual
-- outcome.  Now the report enumerates the same table variable the denies came from, so the exemption cannot drift from
-- the assertion that honours it.
GO


-- *** 5. Descriptions ***
-- This file creates no objects, so there is nothing for util.uspSetObjectDescription to attach a description to.  The
-- permission state describes itself: sys.database_permissions is the record, and section 6 prints it.
GO


-- *** 6. The closing report, and the assertion that closes G-19 ***
DECLARE @Report TABLE
(
    RowNo    INT IDENTITY (1, 1) PRIMARY KEY,
    Severity INT             NOT NULL,
    Status   VARCHAR (10)    NOT NULL,
    Item     NVARCHAR (200)  NOT NULL,
    Detail   NVARCHAR (1000)     NULL
);

-- 6a.  Every user schema, and what is stated about it.  This is the query G-19 asks for and the one that will be lifted
--      into 950_verify_deployment.sql in Phase 8 (BL-029).
DECLARE @SchemaState TABLE
(
    SchemaName NVARCHAR (128) NOT NULL PRIMARY KEY,
    Grants     INT            NOT NULL,
    Denies     INT            NOT NULL,
    Roles      NVARCHAR (400)     NULL
);

INSERT @SchemaState (SchemaName, Grants, Denies, Roles)
SELECT s.name
     , Grants = (SELECT COUNT (*)
                   FROM sys.database_permissions AS p
                   JOIN sys.database_principals  AS dp ON dp.principal_id = p.grantee_principal_id
                  WHERE dp.name IN (N'applicationRole', N'readOnlyRole', N'logsAuditReader', N'rlsBypassRole')
                    AND p.state_desc = 'GRANT'
                    AND ((p.class = 3 AND p.major_id = s.schema_id)
                      OR (p.class = 1 AND OBJECT_SCHEMA_NAME (p.major_id) = s.name)))
     , Denies = (SELECT COUNT (*)
                   FROM sys.database_permissions AS p
                   JOIN sys.database_principals  AS dp ON dp.principal_id = p.grantee_principal_id
                  WHERE dp.name IN (N'applicationRole', N'readOnlyRole', N'logsAuditReader', N'rlsBypassRole')
                    AND p.state_desc LIKE 'DENY%'
                    AND ((p.class = 3 AND p.major_id = s.schema_id)
                      OR (p.class = 1 AND OBJECT_SCHEMA_NAME (p.major_id) = s.name)))
     , Roles  = STUFF ((SELECT DISTINCT N', ' + dp.name
                          FROM sys.database_permissions AS p
                          JOIN sys.database_principals  AS dp ON dp.principal_id = p.grantee_principal_id
                         WHERE dp.name IN (N'applicationRole', N'readOnlyRole', N'logsAuditReader', N'rlsBypassRole')
                           AND ((p.class = 3 AND p.major_id = s.schema_id)
                             OR (p.class = 1 AND OBJECT_SCHEMA_NAME (p.major_id) = s.name))
                         FOR XML PATH (N''), TYPE).value (N'.', N'NVARCHAR (400)'), 1, 2, N'')
  FROM sys.schemas AS s
 WHERE s.name NOT IN (N'sys', N'INFORMATION_SCHEMA', N'guest')
   AND s.name NOT LIKE N'db[_]%'
   AND s.principal_id = DATABASE_PRINCIPAL_ID (N'dbo');

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN st.Grants + st.Denies = 0 THEN 1 ELSE 4 END
     , CASE WHEN st.Grants + st.Denies = 0 THEN 'UNSTATED' ELSE 'OK' END
     , CONCAT (N'SCHEMA::', st.SchemaName, N' is ', CASE WHEN st.Grants + st.Denies = 0
                                                         THEN N'NOT stated for any role' ELSE N'stated' END)
     , CONCAT (st.Grants, N' grant(s) and ', st.Denies, N' deny/denies across '
             , COALESCE (st.Roles, N'no role at all')
             , N'. A schema with neither is gap G-19 repeating itself: nothing breaks, nothing is announced, and the '
             , N'first person to notice is whoever runs a catalog query years later.')
  FROM @SchemaState AS st;

-- 6b.  The three things this file decided, restated as checks rather than as comments, so that a later REVOKE shows up.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 2 THEN 4 ELSE 2 END
     , CASE WHEN COUNT (*) = 2 THEN 'OK' ELSE 'DEFECT' END
     , N'SCHEMA::config carries SELECT for both reading roles'
     , CONCAT (COUNT (*), N' of 2 expected schema-level SELECT grants. This is the hole G-19 was filed for: config was '
             , N'created in 005, filled in 025 and read by every procedure in 110 without one role being granted or '
             , N'denied anything in it.')
  FROM sys.database_permissions AS p
  JOIN sys.database_principals  AS dp ON dp.principal_id = p.grantee_principal_id
 WHERE p.class          = 3
   AND p.major_id       = SCHEMA_ID (N'config')
   AND p.permission_name = 'SELECT'
   AND p.state_desc     = 'GRANT'
   AND dp.name IN (N'applicationRole', N'readOnlyRole');

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 2 THEN 4 ELSE 1 END
     , CASE WHEN COUNT (*) = 2 THEN 'OK' ELSE 'VIOLATED' END
     , N'config.ApplicationSetting is denied to both reading roles, so the pepper is unreadable'
     , CONCAT (COUNT (*), N' of 2 expected object-level DENYs. Authn.DummyVerifierPepper is the whole basis of section '
             , N'19.2: a caller who can read it can compute the dummy verifier for any name and enumerate every '
             , N'account with no extra requests. The procedures still read the table, by ownership chaining, which is '
             , N'measured in this file''s banner rather than assumed.')
  FROM sys.database_permissions AS p
  JOIN sys.database_principals  AS dp ON dp.principal_id = p.grantee_principal_id
 WHERE p.class           = 1
   AND p.major_id        = OBJECT_ID (N'config.ApplicationSetting')
   AND p.permission_name = 'SELECT'
   AND p.state_desc      = 'DENY'
   AND dp.name IN (N'applicationRole', N'readOnlyRole');

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 4 THEN 4 ELSE 1 END
     , CASE WHEN COUNT (*) = 4 THEN 'OK' ELSE 'VIOLATED' END
     , N'INV-11 is now a catalog row: applicationRole is denied all four table verbs on SCHEMA::auth'
     , CONCAT (COUNT (*), N' of 4 expected verbs denied. The invariant used to hold because nothing had been granted, '
             , N'which is not the same as holding -- it would have stopped holding the first time somebody added a '
             , N'convenience SELECT. The fifteen EXECUTE grants are unaffected: ownership chaining does not consult '
             , N'this deny.')
  FROM sys.database_permissions AS p
  JOIN sys.database_principals  AS dp ON dp.principal_id = p.grantee_principal_id
 WHERE p.class       = 3
   AND p.major_id    = SCHEMA_ID (N'auth')
   AND p.state_desc  = 'DENY'
   AND dp.name       = N'applicationRole'
   AND p.permission_name IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE');

-- 6c.  util, listed rather than asserted -- the decision was to leave EXECUTE ungranted by default, and a list is the
--      only way to make "ungranted by default" visible.
INSERT @Report (Severity, Status, Item, Detail)
SELECT 3, 'INFO'
     , CONCAT (N'util.', o.name, N': EXECUTE is ', CASE WHEN EXISTS (SELECT 1
                                                                       FROM sys.database_permissions AS p
                                                                       JOIN sys.database_principals AS dp
                                                                         ON dp.principal_id = p.grantee_principal_id
                                                                      WHERE p.class = 1
                                                                        AND p.major_id = o.object_id
                                                                        AND p.permission_name = 'EXECUTE'
                                                                        AND p.state_desc = 'GRANT'
                                                                        AND dp.name = N'applicationRole')
                                                        THEN N'GRANTED to applicationRole'
                                                        ELSE N'not granted to any role' END)
     , N'EXECUTE on SCHEMA::util is deliberately not denied at schema level: measured, a schema DENY beats the '
     + N'object-level GRANT that 000_prerequisites.sql makes on util.uspPhase0Probe, and the Phase 0 connectivity probe '
     + N'would have started failing for a reason nobody would trace back here. The table verbs ARE denied.'
  FROM sys.objects AS o
 WHERE o.schema_id = SCHEMA_ID (N'util')
   AND o.type      = 'P';

-- 6d.  rlsBypassRole holds EXECUTE on exactly the two maintenance-bypass procedures and nothing else.  Until Phase 4
--      this row asserted zero permissions; the banner records why that changed and why the replacement is narrower than
--      "none" rather than looser.  BL-047.
DECLARE @BypassExpected INT =
(
    SELECT COUNT (*)
      FROM sys.database_permissions AS p
      JOIN sys.database_principals  AS dp ON dp.principal_id = p.grantee_principal_id
     WHERE dp.name             = N'rlsBypassRole'
       AND p.class             = 1
       AND p.permission_name   = 'EXECUTE'
       AND p.state_desc        = 'GRANT'
       AND p.major_id IN (COALESCE (OBJECT_ID (N'auth.uspBeginMaintenanceSession'), -1)
                        , COALESCE (OBJECT_ID (N'auth.uspEndMaintenanceSession'),   -1))
);

-- Everything that is NOT one of those two grants, counted separately, because "two permissions" and "the two intended
-- permissions" are different facts and only the second one is the invariant.
DECLARE @BypassOther INT =
(
    SELECT COUNT (*)
      FROM sys.database_permissions AS p
      JOIN sys.database_principals  AS dp ON dp.principal_id = p.grantee_principal_id
     WHERE dp.name = N'rlsBypassRole'
       AND NOT (p.class           = 1
            AND p.permission_name = 'EXECUTE'
            AND p.state_desc      = 'GRANT'
            AND p.major_id IN (COALESCE (OBJECT_ID (N'auth.uspBeginMaintenanceSession'), -1)
                             , COALESCE (OBJECT_ID (N'auth.uspEndMaintenanceSession'),   -1)))
);

INSERT @Report (Severity, Status, Item, Detail)
VALUES (CASE WHEN @BypassExpected = 2 AND @BypassOther = 0 THEN 4 ELSE 2 END
      , CASE WHEN @BypassExpected = 2 AND @BypassOther = 0 THEN 'OK' ELSE 'REVIEW' END
      , N'rlsBypassRole holds EXECUTE on the two maintenance-bypass procedures and nothing else'
      , CONCAT (@BypassExpected, N' of 2 expected EXECUTE grants, and ', @BypassOther, N' other permission(s) where 0 '
              , N'is correct. The two grants are made by 105_auth_session_procedures.sql, next to the objects: the '
              , N'procedures gate themselves on IS_ROLEMEMBER, and a role-gated procedure the role cannot execute is a '
              , N'locked door with no handle. Anything BEYOND those two would be a permission that follows a named '
              , N'human around outside the role''s stated purpose -- section 4 of 005_schemas_and_roles.sql argues it, '
              , N'and the membership, not the permission set, is what that role is for.'));

-- 6e.  EVERY table in SCHEMA::logs, enumerated from sys.tables rather than listed here, and the write denies section 4
--      applies to each.  This check is INVERTED on purpose and it is the whole of G-23's resolution: the previous
--      version named the same four tables the denies named, so the two agreed with each other and neither agreed with
--      the database.  logs.PermissionProbe arrived in Phase 5 and the report went on saying 12 of 12 OK.  A report that
--      can only find the holes it was told about is not a control, it is a restatement of section 4.  BL-048, BL-066.
--
--      The exemptions come from the SAME table variable section 4 denied from, so an exemption cannot be honoured by the
--      grants and forgotten by the report, or the reverse.  An exempt table is reported as EXEMPT with its reason
--      printed, at severity 4, because the reason is the thing a reviewer needs and "absent from a list" is not a reason.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Reason IS NOT NULL THEN 4 WHEN x.Denied = 3 THEN 4 ELSE 1 END
     , CASE WHEN x.Reason IS NOT NULL THEN 'EXEMPT' WHEN x.Denied = 3 THEN 'OK' ELSE 'VIOLATED' END
     , CONCAT (x.TableName, N' is unwritable by applicationRole outside a procedure')
     , CASE WHEN x.Reason IS NOT NULL
            THEN CONCAT (N'Exempt from the write denies, by a row in section 4''s #LogsWriteExempt. ', x.Reason)
            ELSE CONCAT (x.Denied, N' of 3 expected write verbs denied (INSERT, UPDATE, DELETE). The conventions'' own '
                       , N'scripts/permissions.sql grants all four verbs on SCHEMA::logs to applicationRole so the '
                       , N'framework can write logs.ExecutionLog, and that grant covers every table put in this schema '
                       , N'from the moment it is created -- which is not what section 8 of 085_logs_auth_tables.sql '
                       , N'says is intended. Without these denies a compromised application login could forge or erase '
                       , N'the record of its own compromise directly, with no procedure and no permission consulted. '
                       , N'The procedures still write it by ownership chaining. BL-048, BL-066.') END
  FROM (SELECT TableName = s.name + N'.' + t.name
             , Reason    = (SELECT e.Reason FROM #LogsWriteExempt AS e WHERE e.TableName = s.name + N'.' + t.name)
             , Denied    = (SELECT COUNT (DISTINCT p.permission_name)
                              FROM sys.database_permissions AS p
                              JOIN sys.database_principals  AS dp ON dp.principal_id = p.grantee_principal_id
                             WHERE p.class       = 1
                               AND p.major_id    = t.object_id
                               AND p.minor_id    = 0
                               AND p.state_desc  = 'DENY'
                               AND dp.name       = N'applicationRole'
                               AND p.permission_name IN ('INSERT', 'UPDATE', 'DELETE'))
          FROM sys.tables  AS t
          JOIN sys.schemas AS s ON s.schema_id = t.schema_id
         WHERE s.name = N'logs'
           AND t.is_ms_shipped = 0) AS x;

-- And the count itself, because "every row says OK" is only reassuring if the number of rows is right.  A logs schema
-- with no tables in it would produce no rows above and an entirely silent report -- the failure mode BL-064 is named for.
DECLARE @LogsTableCount INT = (SELECT COUNT (*) FROM sys.tables AS t JOIN sys.schemas AS s
                                 ON s.schema_id = t.schema_id WHERE s.name = N'logs' AND t.is_ms_shipped = 0);

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN @LogsTableCount >= 4 THEN 4 ELSE 3 END
     , CASE WHEN @LogsTableCount >= 4 THEN 'OK' ELSE 'ABSENT' END
     , N'SCHEMA::logs holds the tables 085_logs_auth_tables.sql creates'
     , CONCAT (@LogsTableCount, N' table(s) found, and the four trails are the minimum a deployed database has. Fewer '
             , N'means 085_logs_auth_tables.sql has not run, so the rows above are a report on an empty schema rather '
             , N'than a clean one. This row exists because the enumeration above cannot distinguish those two states.');

DROP TABLE IF EXISTS #LogsWriteExempt;

-- 6f.  The Phase 3 and Phase 4 objects that are granted to NOBODY, asserted one at a time.  Each of these is reached by
--      ownership chaining from something that IS granted, or by the engine itself, or by a db_owner at a console -- and
--      a grant appearing on any of them is a hole of a different shape in each case, which is why the reason travels
--      with the name rather than being written once above the list.
DECLARE @Ungranted TABLE
(
    ObjectName NVARCHAR (300)  NOT NULL PRIMARY KEY,
    Reason     NVARCHAR (900)  NOT NULL
);

INSERT @Ungranted (ObjectName, Reason)
VALUES (N'logs.uspRecordAuthorizationChange'
      , N'A grant here lets the application write the authority trail directly, which means writing that it held '
      + N'authority it never held. 165_logs_procedures.sql asserts the same absence; this file asserts it again '
      + N'because this file runs last and is where somebody who has just seen a 229 will come to add the grant.')
     , (N'logs.uspRecordAuthorizationDenial'
      , N'A grant here lets a caller manufacture denials for a user it wants investigated, or -- with the section 4 '
      + N'denies in place -- flood the one table an investigation starts from.')
     , (N'logs.uspRecordDataChange'
      , N'A grant here lets a caller write a data-change narrative that no data change produced. The domain '
      + N'procedures call it by ownership chaining, measured on this instance.')
     , (N'auth.uspDemandPermission'
      , N'THE AUTHORIZATION GATE ITSELF. It is called from inside the procedures that need it, at step 5 of section 9, '
      + N'before any transaction opens. A caller that can execute it directly learns whether it holds a permission '
      + N'without doing the thing the permission governs -- an oracle for probing authority -- and gains nothing it '
      + N'needs, because a grant it holds is already implied by the procedure it is allowed to call.')
     , (N'auth.uspRebuildProfilePermissionScope'
      , N'Materializing the scope is an administrative act with a transaction over every row of one profile. It runs '
      + N'from the grant procedures by ownership chaining and from a console. An application that can call it at will '
      + N'can make the materialized scope disagree with the grants at a moment of its choosing.')
     , (N'auth.uspRebuildTenantAccessPolicy'
      , N'It DROPS AND RE-CREATES the row-level security policy. Every protected table in this database is unprotected '
      + N'for the length of that transaction, and @Action = N''Drop'' leaves it unprotected until somebody rebuilds. '
      + N'This is a deployment step and a db_owner step, and nothing else.')
     , (N'auth.tvfPermissionScope'
      , N'The scope reader. Granting SELECT would let a caller enumerate the tenants and permissions of ANY profile id '
      + N'it can guess, because the function takes the profile as a parameter rather than reading the session.')
     , (N'auth.tvfTenantReadPredicate'
      , N'A bound predicate is evaluated by the ENGINE, not by the caller, so SELECT permission on it is never checked '
      + N'and granting it adds exactly one capability: running the predicate directly to enumerate which tenants the '
      + N'current session may read, without touching the protected table.')
     , (N'auth.tvfTenantInsertPredicate'
      , N'Same reason as the read predicate. The engine consults it on INSERT; a caller has no use for it except '
      + N'reconnaissance.')
     , (N'auth.tvfTenantUpdatePredicate'
      , N'Same reason again, on UPDATE -- and this is the predicate that governs the soft delete, so "which rows can I '
      + N'retire" is the question a direct call answers.');

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (u.ObjectName) IS NULL THEN 3 WHEN g.Grants = 0 THEN 4 ELSE 1 END
     , CASE WHEN OBJECT_ID (u.ObjectName) IS NULL THEN 'ABSENT' WHEN g.Grants = 0 THEN 'OK' ELSE 'VIOLATED' END
     , CONCAT (u.ObjectName, N': granted to no role, deliberately')
     , CONCAT (g.Grants, N' grant(s) to applicationRole, readOnlyRole, logsAuditReader or rlsBypassRole; 0 is correct. '
             , u.Reason)
  FROM @Ungranted AS u
 CROSS APPLY (SELECT Grants = (SELECT COUNT (*)
                                 FROM sys.database_permissions AS p
                                 JOIN sys.database_principals  AS dp ON dp.principal_id = p.grantee_principal_id
                                WHERE p.class      = 1
                                  AND p.major_id   = COALESCE (OBJECT_ID (u.ObjectName), -1)
                                  AND p.state_desc = 'GRANT'
                                  AND dp.name IN (N'applicationRole', N'readOnlyRole', N'logsAuditReader'
                                                , N'rlsBypassRole'))) AS g;

-- 6g.  The one Phase 3 grant that MUST be present, asserted positively.  Everything above is an absence; this is the
--      opposite failure and it is worth its own row, because without it the application cannot set a session context at
--      all, every predicate in section 10 sees five NULL keys, and the whole database answers every query with nothing.
--      That failure looks exactly like empty data (UI-18), which is the most expensive way to spend an afternoon.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 2 THEN 4 ELSE 1 END
     , CASE WHEN COUNT (*) = 2 THEN 'OK' ELSE 'VIOLATED' END
     , N'applicationRole holds EXECUTE on the two session-context procedures'
     , CONCAT (COUNT (*), N' of 2 expected EXECUTE grants on auth.uspSetSessionContext and '
             , N'auth.uspClearSessionContext, made by 105_auth_session_procedures.sql next to the objects. These are '
             , N'the application''s only way in: the five identity keys are read-only once set (Msg 15664) and no '
             , N'predicate reads anything else.')
  FROM sys.database_permissions AS p
  JOIN sys.database_principals  AS dp ON dp.principal_id = p.grantee_principal_id
 WHERE p.class           = 1
   AND p.permission_name = 'EXECUTE'
   AND p.state_desc      = 'GRANT'
   AND dp.name           = N'applicationRole'
   AND p.major_id IN (COALESCE (OBJECT_ID (N'auth.uspSetSessionContext'),   -1)
                    , COALESCE (OBJECT_ID (N'auth.uspClearSessionContext'), -1));

-- 6h.  The debt, stated in the transcript rather than left in a comment.
INSERT @Report (Severity, Status, Item, Detail)
VALUES (3, 'DEFERRED'
      , N'G-19''s other half -- the same assertion inside 950_verify_deployment.sql -- is Phase 8'
      , N'950_verify_deployment.sql does not exist yet. Section 6a is the query it will carry, so the check runs at '
      + N'deployment time today and at verification time later. The difference matters: an ad-hoc REVOKE after '
      + N'deployment is not caught until 950 exists. BL-029.')
     , (3, 'NOTE'
      , N'A view over config.ApplicationSetting filtered to IsSensitive = 0 is the named extension point'
      , N'Nothing needs it yet, because every procedure that reads a setting reaches it by ownership chaining. When '
      + N'something does need to read a setting directly, the answer is that view -- not a REVOKE of the two DENYs in '
      + N'section 1. 025_config_tables.sql already carries the IsSensitive column that makes it a one-line filter.')
     , (4, 'NOTE'
      , N'The conventions'' SCHEMA::logs grant is narrowed here, not revoked, and section 4 now finds the tables itself'
      , N'scripts/permissions.sql in the conventions skill grants all four table verbs on SCHEMA::logs to '
      + N'applicationRole, and that grant covers every table put in that schema from the moment it is created. This row '
      + N'used to be a WARNING at severity 3, saying that section 4 denied the write verbs on four NAMED tables and that '
      + N'a fifth would be writable on the day it was created. It was right: logs.PermissionProbe arrived in Phase 5 and '
      + N'was writable by applicationRole for the whole of Phases 5 to 7 while this report went on saying 12 of 12 OK. '
      + N'Section 4 and section 6e are now both driven by sys.tables minus one documented exemption, so a table nobody '
      + N'thought about is denied and asserted without anybody editing this file. G-23 is closed by that inversion and '
      + N'not by adding a fifth name. BL-048, BL-066.')
     , (5, 'NEXT'
      , N'Phase 8 Verification: this file''s section 6a is what 950_verify_deployment.sql lifts'
      , N'The schema-state query in 6a is the deployment-time half of G-19; the verification-time half is 950, which is '
      + N'T-104 and unwritten, so an ad-hoc REVOKE after deployment is still caught by nothing. BL-029. One thing about '
      + N'SCHEMA::dbo is worth reading here rather than there: applicationRole holds SELECT, INSERT and UPDATE on it -- '
      + N'deliberately, because the demo domain is the one place a project reaches tables directly, with row-level '
      + N'security rather than INV-11 doing the containment. Note what is NOT granted: DELETE. Deletion in this design '
      + N'is a soft-delete UPDATE, and the absence of that verb is what makes it one.');

SELECT Severity, Status, Item, Detail FROM @Report ORDER BY RowNo;

IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
BEGIN
    DECLARE @Fail NVARCHAR (2000) =
        CONCAT (N'Permissions: ', (SELECT COUNT (*) FROM @Report WHERE Severity = 1), N' violation(s) and '
              , (SELECT COUNT (*) FROM @Report WHERE Severity = 2), N' defect(s). A row marked UNSTATED is gap G-19 '
              , N'repeating itself for a schema added since: state what every role may do in it, here, even if the '
              , N'answer is nothing.');

    THROW 50000, @Fail, 1;
END;

PRINT N'Permissions: no problems found. Every user schema is now stated for at least one role, SCHEMA::config is '
    + N'closed -- gap G-19 -- the pepper is unreadable outside a procedure, and INV-11 is a catalog row rather than an '
    + N'absence. Every table in SCHEMA::logs except the one documented exemption is unwritable by the application login '
    + N'outside a procedure, found by enumeration rather than by a list (BL-048, BL-066), the '
    + N'ten Phase 3 and Phase 4 objects that must be granted to nobody are asserted one at a time, rlsBypassRole holds '
    + N'the two maintenance grants and nothing else (BL-047), and the two session-context grants the application cannot '
    + N'work without are asserted positively. The util EXECUTE decision and the deferred 950 half are in the report '
    + N'above.';
GO
