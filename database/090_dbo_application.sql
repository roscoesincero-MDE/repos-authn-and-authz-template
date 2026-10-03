/***********************************************************************************************************************
Script:         090_dbo_application.sql
Purpose:        The application's own domain tables: dbo.CaseFile and dbo.CaseNote.  Two tables, chosen to be the
                smallest pair that exercises every pattern a real domain table in this database has to follow -- tenant
                scoping, a per-tenant natural key, a denormalised TenantId constrained by a composite foreign key, soft
                delete, the audit block, and the AFTER UPDATE trigger that maintains it.
Target:         SQL Server 2022.
Run as:         db_owner in the target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -i database/090_dbo_application.sql
Idempotent:     Yes.  Guarded CREATE TABLE and CREATE INDEX, additive ALTERs, CREATE OR ALTER triggers, MERGE for the
                registry rows.  No rows deleted, ever.
Depends on:     database/025_config_tables.sql, database/030_auth_tenant.sql, database/040_auth_userprofile.sql,
                templates/extended-properties.sql.
Depended on by: database/120_rls_policy.sql (reads the registry row written in section 4),
                database/135_audit_triggers.sql (asserts the triggers in section 3 exist),
                database/180_dbo_application_procedures.sql (the only sanctioned way to read or write these tables),
                database/950_verify_deployment.sql.
Implements:     DES-AUTH-001 sections 10.1, 10.3, 10.6, 14.4 and 15.  See docs/10-database-authn-authz-design.md.
Tasks:          T-096, T-097, T-098, T-099, T-100.
To retarget:    Pass it per run:  sqlcmd -d <database> -v DbName=<database>.  There is no in-file default.

THESE TWO TABLES ARE A PATTERN, NOT A REQUIREMENTS DOCUMENT
----------------------------------------------------------
docs/10-database-authn-authz-design.md describes the security architecture in full and the business domain barely at all
-- it names case data as the thing being protected without saying what a case is.  So the domain here is deliberately
thin: a case file with a status, and notes attached to it.  Nothing in the security machinery depends on these columns,
and a real project should expect to replace them.

What a real project should NOT replace is the shape.  Every pattern below is load-bearing, and each one exists because
getting it wrong in a multi-tenant database fails quietly:

  TenantId ON EVERY TABLE, NOT NULL.  The row-level security predicate compares one column on the table being queried.
  A table without its own TenantId cannot be filtered, so it has to be reached through a join to one that can -- and a
  predicate that joins is a join executed for every row of every query against the table.  Denormalising the tenant onto
  the child is the cheaper half of the trade, and the composite foreign key below is what makes it safe.

  A COMPOSITE FOREIGN KEY, NOT JUST A PARENT REFERENCE.  dbo.CaseNote.CaseFileId alone would let a note in tenant 3 point
  at a case in tenant 8.  Row-level security would not catch it: the predicate trusts CaseNote.TenantId, sees 3, and
  shows the note to tenant 3 -- along with whatever the application then joins in from the case.  FK (CaseFileId,
  TenantId) against UX_dbo_CaseFile_Id_Tenant makes the pair exist together or not at all.  This is the table where that
  is easiest to see; DES section 15.4 applies the same rule to every profile reference in the database.

  A PER-TENANT NATURAL KEY, FILTERED.  Case numbers are unique within a tenant and must be allowed to collide across
  tenants -- two organizations both having a case 2026-0001 is normal.  So the unique index leads with TenantId, and it
  is filtered WHERE IsDeleted = 0 so a withdrawn case number can be reissued.

  AN AFTER UPDATE TRIGGER ON EVERY PLAIN TABLE.  Section 3.  The audit column DEFAULTs fire on INSERT only, so without
  it every UPDATE leaves auditModifiedBy and auditModifiedDateUtc at their insert-time values and a soft delete records
  neither who nor when.  The trigger also enforces the two immutability rules this domain has.

  REGISTRATION FOR ROW-LEVEL SECURITY.  Section 4.  A tenant-scoped table that is not registered is not protected, and
  it fails OPEN: every tenant's rows are returned to every tenant, with no error and nothing in any log.  The row goes in
  the same script as the table, deliberately, so the two cannot drift apart.

  NO DELETE PATH AT ALL.  Soft delete only, which the convention gate enforces and which matters more here than
  anywhere: a case file is a record of a decision about a person, and the audit trail in logs.DataChangeLog references
  rows by key.  Hard-delete the row and the audit trail describes something that no longer exists.

  AND A SOFT DELETE IS ONE STATEMENT, NOT A FLAG FLIP.  This is the single easiest thing on these two tables to get
  wrong, so it is stated here and again beside the trigger that looks like it handles it.  CK_dbo_CaseFile_DeletedPair
  requires auditDeletedBy to be non-NULL whenever IsDeleted = 1, and SQL Server evaluates CHECK constraints BEFORE an
  AFTER trigger fires.  So  UPDATE dbo.CaseFile SET IsDeleted = 1  does not soft-delete the row and does not reach the
  trigger: it fails with Msg 547, measured rather than assumed.  The caller sets all three columns together --
       SET IsDeleted = 1, auditDeletedBy = @Actor, auditDeletedDateUtc = SYSUTCDATETIME ()
  -- which is what dbo.uspSoftDeleteCaseFile in 180_dbo_application_procedures.sql does.  The consequence for the
  triggers in section 3 is that their auditDeletedBy branch is unreachable on these tables; it is kept as a backstop and
  labelled as one, and 135_audit_triggers.sql knows not to demand it where the paired CHECK constraint exists.

WHAT ACTUALLY PROTECTS THESE TWO TABLES, BY NAME
------------------------------------------------
This file was written before the security model around it existed, and the header it shipped with described the patterns
without naming the objects that make them work.  They exist now, so here they are:

  THE REGISTRY ROW IN SECTION 4 is read by database/120_rls_policy.sql, which generates auth.TenantAccessPolicy with
  FOUR predicates per registered table -- a FILTER, plus BLOCK AFTER INSERT, BLOCK AFTER UPDATE and BLOCK BEFORE UPDATE.
  Eight predicates in total for these two tables.  The functions are auth.tvfTenantReadPredicate,
  auth.tvfTenantInsertPredicate and auth.tvfTenantUpdatePredicate; all three read SESSION_CONTEXT (N'UserProfileId') and
  join auth.ProfilePermissionScope to auth.TenantClosure, and the insert predicate additionally requires the row's
  TenantId to equal SESSION_CONTEXT (N'ActingTenantId').

  THAT IS THE TENANCY HALF AND IT IS NOT THE PERMISSION HALF.  Row-level security answers "may this session see this
  row"; it says nothing about whether the session may approve a case or write an internal note.  That is
  auth.uspDemandPermission, called by the procedures in database/180_dbo_application_procedures.sql.  The two questions
  are separate on purpose and both have to be asked -- DES section 10.4.

  THE APPLICATION LOGIN HAS TABLE PERMISSIONS ON THIS SCHEMA (section 6), so the predicate is the only thing standing
  between one tenant's session and another tenant's rows.  That is deliberate and it is what makes section 4 a security
  control rather than a configuration nicety.

HOW THEY ARE REACHED: THROUGH PROCEDURES, ONLY
----------------------------------------------
database/180_dbo_application_procedures.sql is the reference implementation of DES section 14's calling contract and is
the only sanctioned path to these tables.  Its numbers are E-50200 to E-50206, and E-50201 is the one worth reading
twice: "no such case file" and "that case file is not yours" are deliberately the SAME number, because the predicate has
already removed the other tenant's rows before the procedure looks.  The procedure genuinely cannot tell the difference,
and a design that could tell would be one that read around its own security.

WHAT PHASE 5 MEASURED, ON THIS TABLE, AND THE RULE IT PRODUCED
-------------------------------------------------------------
DES section 10.6 records the numbers.  They were taken against 200,000 rows in dbo.CaseFile with 1,050 tenants and 5,000
profiles, so they describe this table and not a model of it:

  a point read by CaseFileId costs 8 logical reads protected against 3 unprotected -- fine, and it is what the
  procedures issue;
  a range scan by (TenantId, CaseStatus) costs 1,007 reads per call against 6 -- acceptable, and the index above is why;
  SELECT COUNT (*) FROM dbo.CaseFile with no filter but the policy reads a MILLION pages to return a thousand rows.

The plan shape was confirmed optimal -- a semi-join with seeks on both inner tables, never a scan -- so that last figure
is not a missing index and cannot be tuned away.  It is the row count.  Hence the rule, which belongs to every query
written against a table in this schema:

  ANY QUERY AGAINST A PROTECTED TABLE MUST CARRY A FILTER AN INDEX CAN SEEK.  A key, a tenant, a status, a date range.
  A statement whose only filter is the security policy will read the whole table.  Cross-tenant totals belong in a
  procedure that takes the scope as an argument.

THE TRIGGERS IN SECTION 3 ARE ALSO AN ASSERTION SOMEWHERE ELSE
--------------------------------------------------------------
database/135_audit_triggers.sql creates nothing.  Every table's AFTER UPDATE trigger ships beside the table -- these two
ship here -- so 135's whole job is to prove the set is complete and fail the deployment with E-50210 if it is not.
Deleting either trigger below therefore fails the build rather than quietly stopping the audit columns from being
maintained, which is what it used to do.
***********************************************************************************************************************/

:on error exit

-- THE TARGET DATABASE IS SUPPLIED ON THE COMMAND LINE AND HAS NO DEFAULT.  There is deliberately no `:setvar DbName`
-- line: measured on sqlcmd 17, a :setvar in the file OVERRIDES -v rather than acting as a fallback for its absence.

SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;
GO


-- *** 0. Assert the target and the parents ***
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

IF OBJECT_ID (N'auth.Tenant', N'U') IS NULL OR OBJECT_ID (N'auth.UserProfile', N'U') IS NULL
BEGIN
    -- Built into a variable because THROW takes a constant or a variable, never an expression: a concatenation in the
    -- message position is a parse error (102, near '+').
    DECLARE @Msg NVARCHAR (2000) =
        N'auth.Tenant or auth.UserProfile is missing. Run database/030_auth_tenant.sql and '
      + N'database/040_auth_userprofile.sql first.';

    THROW 50000, @Msg, 1;
END
GO


-- *** 1. dbo.CaseFile ***
IF OBJECT_ID (N'dbo.CaseFile', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.CaseFile
    (
        CaseFileId           INT            IDENTITY (1, 1) NOT NULL
        -- NOT NULL, always, on every table in dbo.  See the file header.  Immutable after insert -- section 3 raises
        -- 50011 on an attempt to change it, and the BLOCK AFTER UPDATE predicate is the second line of defence.
      , TenantId             INT                            NOT NULL

        -- The per-tenant natural key: what the case is called on paper and in a telephone conversation.  Unique within
        -- the tenant, free to collide across tenants.
      , CaseNumber           NVARCHAR (50)                  NOT NULL
      , Title                NVARCHAR (400)                 NOT NULL

        -- A closed set, checked rather than looked up.  A status drives behaviour in code, so it is a value the code
        -- knows; a lookup table would add a join to every read and let somebody insert a status nothing handles.
      , CaseStatus           VARCHAR (20)                   NOT NULL
            CONSTRAINT DF_dbo_CaseFile_CaseStatus DEFAULT ('draft')

        -- Who is working on it.  Composite foreign key, like every profile reference in a tenant-scoped table: without
        -- the TenantId half, a case in tenant 3 could be assigned to a person in tenant 8, and the application would
        -- then display that person's name to tenant 3 -- a cross-tenant disclosure through a legitimate query.
      , AssignedToProfileId  INT                                NULL

        -- Decision dates, which is what makes this table interesting to audit: a case that was approved and by whom.
      , OpenedUtc            DATETIME2 (3)                  NOT NULL
            CONSTRAINT DF_dbo_CaseFile_OpenedUtc DEFAULT (SYSUTCDATETIME ())
      , ClosedUtc            DATETIME2 (3)                      NULL
      , ApprovedUtc          DATETIME2 (3)                      NULL
        -- Recorded as a profile id AND kept immutable: an approval that can be reattributed is not an approval.
        -- Section 3 raises 50010 on an attempt to change it once set.
      , ApprovedByProfileId  INT                                NULL

      , IsDeleted            BIT                            NOT NULL
            CONSTRAINT DF_dbo_CaseFile_IsDeleted DEFAULT (0)
      , auditDeletedBy       NVARCHAR (255)                     NULL
      , auditDeletedDateUtc  DATETIME2 (3)                      NULL
        -- THE DEFAULT READS THE SESSION CONTEXT FIRST AND ORIGINAL_LOGIN () ONLY AS A FALLBACK, which is the same
        -- expression the AFTER UPDATE trigger uses for auditModifiedBy -- see section 3 and T-097.  Under the pooled
        -- application login ORIGINAL_LOGIN () is the APPLICATION's name, identical on every row, so a DEFAULT of
        -- ORIGINAL_LOGIN () alone makes auditCreatedBy worthless on exactly the path that writes every row.  A procedure
        -- may still name the column explicitly and that wins; this is what happens when it does not.  DES section 14.4.
      , auditCreatedBy       NVARCHAR (255)                 NOT NULL
            CONSTRAINT DF_dbo_CaseFile_auditCreatedBy
                DEFAULT (COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N''), ORIGINAL_LOGIN ()))
      , auditCreatedDateUtc  DATETIME2 (3)                  NOT NULL
            CONSTRAINT DF_dbo_CaseFile_auditCreatedDateUtc DEFAULT (SYSUTCDATETIME ())
      , auditModifiedBy      NVARCHAR (255)                     NULL
      , auditModifiedDateUtc DATETIME2 (3)                      NULL

      , CONSTRAINT PK_dbo_CaseFile PRIMARY KEY CLUSTERED (CaseFileId)

        -- The composite foreign-key target for dbo.CaseNote.  Unfiltered UNIQUE constraint because a FOREIGN KEY cannot
        -- reference a filtered index, and safe because the pair contains the primary key.
      , CONSTRAINT UX_dbo_CaseFile_Id_Tenant UNIQUE (CaseFileId, TenantId)

      , CONSTRAINT FK_dbo_CaseFile_Tenant FOREIGN KEY (TenantId) REFERENCES auth.Tenant (TenantId)

      , CONSTRAINT FK_dbo_CaseFile_AssignedTo_Tenant
            FOREIGN KEY (AssignedToProfileId, TenantId) REFERENCES auth.UserProfile (UserProfileId, TenantId)

      , CONSTRAINT FK_dbo_CaseFile_ApprovedBy_Tenant
            FOREIGN KEY (ApprovedByProfileId, TenantId) REFERENCES auth.UserProfile (UserProfileId, TenantId)

      , CONSTRAINT CK_dbo_CaseFile_CaseStatus
            CHECK (CaseStatus IN ('draft', 'open', 'pending', 'approved', 'rejected', 'closed', 'withdrawn'))

      , CONSTRAINT CK_dbo_CaseFile_CaseNumber
            CHECK (LEN (LTRIM (RTRIM (CaseNumber))) > 0 AND CaseNumber = LTRIM (RTRIM (CaseNumber)))

      , CONSTRAINT CK_dbo_CaseFile_Title CHECK (LEN (LTRIM (RTRIM (Title))) > 0)

        -- An approval is a timestamp AND a person, or neither.  Half an approval is a row nobody can act on and nobody
        -- can explain, and it is the shape a partially-written update leaves behind.
      , CONSTRAINT CK_dbo_CaseFile_ApprovalPair
            CHECK ((ApprovedUtc IS NULL AND ApprovedByProfileId IS NULL)
                OR (ApprovedUtc IS NOT NULL AND ApprovedByProfileId IS NOT NULL))

      , CONSTRAINT CK_dbo_CaseFile_DateOrder
            CHECK ((ClosedUtc IS NULL OR ClosedUtc >= OpenedUtc)
               AND (ApprovedUtc IS NULL OR ApprovedUtc >= OpenedUtc))

      , CONSTRAINT CK_dbo_CaseFile_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS NULL AND auditDeletedDateUtc IS NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL))
    );
END
GO

-- Additive column pattern for a later revision:
--   IF COL_LENGTH (N'dbo.CaseFile', N'NewColumn') IS NULL ALTER TABLE dbo.CaseFile ADD NewColumn INT NULL;

-- One live case number per tenant.  TenantId leads for two reasons at once: it makes the key per-tenant, and the security
-- predicate adds TenantId = <session value> to every query here, so an index that does not start with TenantId cannot
-- serve one.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'UX_dbo_CaseFile_Tenant_CaseNumber' AND object_id = OBJECT_ID (N'dbo.CaseFile'))
BEGIN
    CREATE UNIQUE NONCLUSTERED INDEX UX_dbo_CaseFile_Tenant_CaseNumber
        ON dbo.CaseFile (TenantId, CaseNumber)
        INCLUDE (CaseFileId, Title, CaseStatus)
     WHERE IsDeleted = 0;
END
GO

-- The work list: this tenant's cases by status, newest first.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_dbo_CaseFile_Tenant_Status' AND object_id = OBJECT_ID (N'dbo.CaseFile'))
BEGIN
    CREATE NONCLUSTERED INDEX IX_dbo_CaseFile_Tenant_Status
        ON dbo.CaseFile (TenantId, CaseStatus, OpenedUtc)
        INCLUDE (CaseNumber, Title, AssignedToProfileId)
     WHERE IsDeleted = 0;
END
GO

-- "My cases", which is the first screen most users see.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_dbo_CaseFile_Tenant_AssignedTo' AND object_id = OBJECT_ID (N'dbo.CaseFile'))
BEGIN
    CREATE NONCLUSTERED INDEX IX_dbo_CaseFile_Tenant_AssignedTo
        ON dbo.CaseFile (TenantId, AssignedToProfileId, CaseStatus)
        INCLUDE (CaseNumber, Title, OpenedUtc)
     WHERE IsDeleted = 0;
END
GO


-- *** 1b. Bring an already-deployed dbo.CaseFile up to the current auditCreatedBy DEFAULT ***
--
-- The guarded CREATE TABLE above only runs on a database that does not have the table, so a database deployed before
-- T-097 still carries DEFAULT (ORIGINAL_LOGIN ()) and would keep recording the pooled application login as the creator
-- of every row.  A DEFAULT cannot be altered in place, so it is dropped and re-added -- which is safe in a way that
-- almost no other schema change is, because a DEFAULT is metadata: no row is read, no row is written, no lock is held
-- beyond the metadata change, and nothing already inserted is touched.
--
-- Guarded on the definition text rather than on a version row, so it is idempotent and so it also repairs a database
-- where somebody put the old expression back.  sys.default_constraints.definition holds the parsed form SQL Server
-- stores, which is why the test is a LIKE for the function name and not an equality against the text written above.

IF EXISTS (SELECT 1
             FROM sys.default_constraints AS dc
            WHERE dc.name = N'DF_dbo_CaseFile_auditCreatedBy'
              AND dc.definition NOT LIKE N'%SESSION_CONTEXT%')
BEGIN
    PRINT N'Replacing DF_dbo_CaseFile_auditCreatedBy: the old DEFAULT recorded the pooled application login.';
    ALTER TABLE dbo.CaseFile DROP CONSTRAINT DF_dbo_CaseFile_auditCreatedBy;
    ALTER TABLE dbo.CaseFile ADD CONSTRAINT DF_dbo_CaseFile_auditCreatedBy
        DEFAULT (COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N''), ORIGINAL_LOGIN ()))
        FOR auditCreatedBy;
END
GO


-- *** 2. dbo.CaseNote ***
-- The child table, and the one that demonstrates the composite foreign key doing real work.
IF OBJECT_ID (N'dbo.CaseNote', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.CaseNote
    (
        CaseNoteId           BIGINT         IDENTITY (1, 1) NOT NULL
        -- Denormalised from dbo.CaseFile, and constrained by FK_dbo_CaseNote_CaseFile_Tenant below.  Both columns are
        -- NOT NULL on both sides, so the constraint is fully enforced -- a note cannot point at a case in another
        -- tenant, and the predicate's trust in this column is therefore earned rather than assumed.  Immutable after
        -- insert; section 3 raises 50011.
      , TenantId             INT                            NOT NULL
      , CaseFileId           INT                            NOT NULL

      , NoteText             NVARCHAR (MAX)                 NOT NULL
        -- 'internal' notes are not shown to the subject of the case.  A boolean rather than a note type, because the
        -- distinction that matters is a disclosure decision and it should not be buried in a category list.
      , IsInternal           BIT                            NOT NULL
            CONSTRAINT DF_dbo_CaseNote_IsInternal DEFAULT (0)

      , AuthoredByProfileId  INT                            NOT NULL
      , AuthoredUtc          DATETIME2 (3)                  NOT NULL
            CONSTRAINT DF_dbo_CaseNote_AuthoredUtc DEFAULT (SYSUTCDATETIME ())

      , IsDeleted            BIT                            NOT NULL
            CONSTRAINT DF_dbo_CaseNote_IsDeleted DEFAULT (0)
      , auditDeletedBy       NVARCHAR (255)                     NULL
      , auditDeletedDateUtc  DATETIME2 (3)                      NULL
        -- See the note on dbo.CaseFile.auditCreatedBy: the session context first, ORIGINAL_LOGIN () only as a fallback.
      , auditCreatedBy       NVARCHAR (255)                 NOT NULL
            CONSTRAINT DF_dbo_CaseNote_auditCreatedBy
                DEFAULT (COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N''), ORIGINAL_LOGIN ()))
      , auditCreatedDateUtc  DATETIME2 (3)                  NOT NULL
            CONSTRAINT DF_dbo_CaseNote_auditCreatedDateUtc DEFAULT (SYSUTCDATETIME ())
      , auditModifiedBy      NVARCHAR (255)                     NULL
      , auditModifiedDateUtc DATETIME2 (3)                      NULL

      , CONSTRAINT PK_dbo_CaseNote PRIMARY KEY CLUSTERED (CaseNoteId)

      , CONSTRAINT FK_dbo_CaseNote_Tenant FOREIGN KEY (TenantId) REFERENCES auth.Tenant (TenantId)

        -- The one that matters. Without it, a note in tenant 3 could reference a case in tenant 8 and the predicate --
        -- which reads CaseNote.TenantId and sees 3 -- would show it to tenant 3.
      , CONSTRAINT FK_dbo_CaseNote_CaseFile_Tenant
            FOREIGN KEY (CaseFileId, TenantId) REFERENCES dbo.CaseFile (CaseFileId, TenantId)

      , CONSTRAINT FK_dbo_CaseNote_AuthoredBy_Tenant
            FOREIGN KEY (AuthoredByProfileId, TenantId) REFERENCES auth.UserProfile (UserProfileId, TenantId)

        -- An empty note is a mistake, and an empty note that somebody later reads as "no concerns" is worse than a
        -- mistake.  DATALENGTH rather than LEN because NoteText is MAX and LEN on a large value is needlessly expensive.
      , CONSTRAINT CK_dbo_CaseNote_NoteText CHECK (DATALENGTH (NoteText) > 0)

      , CONSTRAINT CK_dbo_CaseNote_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS NULL AND auditDeletedDateUtc IS NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL))
    );
END
GO

-- The read that matters: this case's notes, oldest first.  NoteText is not INCLUDEd -- it is MAX, and an INCLUDE would
-- put the whole note into the index leaf, doubling the storage of the table's busiest read for no gain over the key
-- lookup that follows.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_dbo_CaseNote_Tenant_CaseFile' AND object_id = OBJECT_ID (N'dbo.CaseNote'))
BEGIN
    CREATE NONCLUSTERED INDEX IX_dbo_CaseNote_Tenant_CaseFile
        ON dbo.CaseNote (TenantId, CaseFileId, AuthoredUtc)
        INCLUDE (IsInternal, AuthoredByProfileId)
     WHERE IsDeleted = 0;
END
GO


-- *** 2b. Bring an already-deployed dbo.CaseNote up to the current auditCreatedBy DEFAULT ***
-- See the identical block under dbo.CaseFile in section 1b for the reasoning.  Each table's repair sits beside that
-- table, in that table's part of the file, rather than both being collected into one section at the end.

IF EXISTS (SELECT 1
             FROM sys.default_constraints AS dc
            WHERE dc.name = N'DF_dbo_CaseNote_auditCreatedBy'
              AND dc.definition NOT LIKE N'%SESSION_CONTEXT%')
BEGIN
    PRINT N'Replacing DF_dbo_CaseNote_auditCreatedBy: the old DEFAULT recorded the pooled application login.';
    ALTER TABLE dbo.CaseNote DROP CONSTRAINT DF_dbo_CaseNote_auditCreatedBy;
    ALTER TABLE dbo.CaseNote ADD CONSTRAINT DF_dbo_CaseNote_auditCreatedBy
        DEFAULT (COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N''), ORIGINAL_LOGIN ()))
        FOR auditCreatedBy;
END
GO


-- *** 3. Audit triggers ***
-- One AFTER UPDATE trigger per plain table, which is the arrangement the conventions require and which this script
-- shipped without.  The audit column DEFAULTs fire on INSERT only; without the trigger, an UPDATE leaves
-- auditModifiedBy and auditModifiedDateUtc at their insert-time values and a soft delete records neither who nor when.

/***********************************************************************************************************************
ObjectName:   dbo.trg_au_updt_CaseFile
Author:       rsincero
CreateDate:   2026-09-19
========================================================================================================================
Description:

Maintains the audit columns on dbo.CaseFile and enforces this table's two immutability rules.  Every plain table in this
database carries exactly one trigger of this shape; a table with none has an audit trail that holds only while every
caller maintains it by hand.

========================================================================================================================
Requirements and Key Dependencies:

SESSION_CONTEXT (N'AppUser'), set by auth.uspSetSessionContext at the top of every procedure call.  Falls back to
ORIGINAL_LOGIN () when absent, which is the maintenance case.

========================================================================================================================
Notes:

WHY THE 0 -> 1 TEST IS EXPLICIT.  There is no filter in front of a plain table: an already-deleted row can be updated
again, and testing only the after-image would re-stamp auditDeletedBy and auditDeletedDateUtc on every later touch of a
row deleted months ago, quietly moving the delete forward in time.  Hence  d.IsDeleted = 0 AND i.IsDeleted = 1.

AN UNDELETE LEAVES auditDeleted* ALONE, on purpose.  Clearing them on a 1 -> 0 transition would destroy the record of a
delete that really happened; leaving them makes a restored row's history readable.

UPDATE (auditModifiedBy) is what distinguishes "the caller named this column" from "the caller's UPDATE happened to
carry the value already in the row".  Without it the two are indistinguishable and every update would look deliberate.

TWO IMMUTABILITY RULES, AND WHY THEY ARE HERE RATHER THAN IN A CHECK CONSTRAINT.  A CHECK sees one row and cannot
compare it to its own previous value.  TenantId (50011) must never change because row-level security reads it and the
audit trail references rows by key: move a row between tenants and every earlier log entry describes a row that is now
somewhere else.  ApprovedByProfileId (50010) must never change once set because an approval that can be reattributed is
not an approval.  Both use THROW with a branchable number rather than RAISERROR followed by RETURN -- RETURN ends the
module and nothing else, so the statement is silently not applied and the caller's batch continues believing it was.

RECURSION.  This trigger updates the table it is defined on.  RECURSIVE_TRIGGERS is OFF by default, but that is a
DATABASE option someone else can turn on, and the failure if they do is an infinite loop rather than a wrong value.

JOINING ON THE PRIMARY KEY is sound here because CaseFileId is an IDENTITY column and SQL Server rejects an UPDATE
against one outright.

========================================================================================================================
Example Usage and Performance:

update dbo.CaseFile set Title = N'Revised title' where CaseFileId = 1;   -- audit columns follow automatically

Set-based; one extra UPDATE per statement regardless of row count, touching four columns.

========================================================================================================================
Modification History:

Date:		2026-09-19
Author:		rsincero
Ticket:		DES-AUTH-001
Description:
Created.  The table shipped without an audit trigger, which left every UPDATE with stale audit columns and every soft
delete recording neither who nor when.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER TRIGGER dbo.trg_au_updt_CaseFile
ON dbo.CaseFile
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    -- An UPDATE that matched nothing still fires the trigger, with inserted and deleted both empty.
    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;

    -- See RECURSION in the notes.  Guarding on this trigger's own depth rather than on the database option, so the
    -- trigger cannot be made to loop by a setting changed elsewhere.
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    -- Immutability, before anything is stamped.  A rejected statement must leave no trace of having been attempted.
    IF UPDATE (TenantId)
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.CaseFileId = i.CaseFileId
                    WHERE i.TenantId <> d.TenantId)
    BEGIN
        ;THROW 50011, N'dbo.CaseFile.TenantId is immutable. A case cannot be moved between tenants: row-level security reads this column and the audit trail references the row by key.', 1;
    END;

    IF UPDATE (ApprovedByProfileId)
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.CaseFileId = i.CaseFileId
                    WHERE d.ApprovedByProfileId IS NOT NULL
                      AND i.ApprovedByProfileId IS DISTINCT FROM d.ApprovedByProfileId)
    BEGIN
        ;THROW 50010, N'dbo.CaseFile.ApprovedByProfileId is immutable once set. An approval that can be reattributed is not an approval.', 1;
    END;

    -- One value per fact, hoisted: a soft delete arriving here must stamp auditDeletedDateUtc and auditModifiedDateUtc
    -- with the SAME instant, not two SYSUTCDATETIME () calls that a millisecond boundary can separate.
    DECLARE @Now   DATETIME2 (3)  = SYSUTCDATETIME (),
            @Actor NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N''), ORIGINAL_LOGIN ());

    UPDATE t
       SET t.auditModifiedDateUtc = @Now,

           -- Caller-overridable, and the only one that is.
           t.auditModifiedBy = CASE WHEN UPDATE (auditModifiedBy)
                                    THEN COALESCE (NULLIF (i.auditModifiedBy, N''), @Actor)
                                    ELSE @Actor
                               END,

           -- THIS BRANCH IS UNREACHABLE ON THIS TABLE, AND THAT IS NOT A DEFECT -- IT IS A BACKSTOP.  It looks like the
           -- soft-delete path and it is not, because CK_dbo_CaseFile_DeletedPair requires auditDeletedBy to be non-NULL
           -- whenever IsDeleted = 1, and SQL Server evaluates CHECK constraints BEFORE an AFTER trigger fires.  So the
           -- bare  UPDATE dbo.CaseFile SET IsDeleted = 1  never gets here; it is rejected first, measured:
           --     Msg 547 -- The UPDATE statement conflicted with the CHECK constraint "CK_dbo_CaseFile_DeletedPair".
           -- Every soft delete must therefore set IsDeleted, auditDeletedBy and auditDeletedDateUtc in ONE statement,
           -- which is what dbo.uspSoftDeleteCaseFile in 180_dbo_application_procedures.sql does, and what
           -- auth.uspRebuildProfilePermissionScope does for its own table for exactly this reason.  135_audit_triggers
           -- .sql knows about the split and reports it as CALLER rather than demanding this branch.  The branch stays
           -- because it costs nothing, it documents the intended stamp, and it becomes live the moment the paired CHECK
           -- constraint is dropped -- but nobody should believe it is what makes soft delete work here.
           t.auditDeletedBy      = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Actor ELSE t.auditDeletedBy      END,
           t.auditDeletedDateUtc = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Now   ELSE t.auditDeletedDateUtc END
      FROM dbo.CaseFile AS t
      JOIN inserted     AS i ON i.CaseFileId = t.CaseFileId
      JOIN deleted      AS d ON d.CaseFileId = t.CaseFileId;
END;
GO


/***********************************************************************************************************************
ObjectName:   dbo.trg_au_updt_CaseNote
Author:       rsincero
CreateDate:   2026-09-19
========================================================================================================================
Description:

Maintains the audit columns on dbo.CaseNote and enforces TenantId immutability.  Identical in shape to
dbo.trg_au_updt_CaseFile; see that trigger's notes for the reasoning behind every clause.

========================================================================================================================
Requirements and Key Dependencies:

SESSION_CONTEXT (N'AppUser'), set by auth.uspSetSessionContext.

========================================================================================================================
Notes:

CaseFileId is immutable too, and for a sharper reason than TenantId: re-pointing a note at a different case rewrites the
history of both cases at once.  It is enforced here rather than by a constraint for the same reason as TenantId -- a
CHECK cannot see the row's previous value.

========================================================================================================================
Example Usage and Performance:

update dbo.CaseNote set IsInternal = 1 where CaseNoteId = 1;

========================================================================================================================
Modification History:

Date:		2026-09-19
Author:		rsincero
Ticket:		DES-AUTH-001
Description:
Created alongside dbo.trg_au_updt_CaseFile.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER TRIGGER dbo.trg_au_updt_CaseNote
ON dbo.CaseNote
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    IF (UPDATE (TenantId) OR UPDATE (CaseFileId))
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.CaseNoteId = i.CaseNoteId
                    WHERE i.TenantId   <> d.TenantId
                       OR i.CaseFileId <> d.CaseFileId)
    BEGIN
        ;THROW 50011, N'dbo.CaseNote.TenantId and dbo.CaseNote.CaseFileId are immutable. Re-pointing a note rewrites the history of two cases at once.', 1;
    END;

    DECLARE @Now   DATETIME2 (3)  = SYSUTCDATETIME (),
            @Actor NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N''), ORIGINAL_LOGIN ());

    UPDATE t
       SET t.auditModifiedDateUtc = @Now,
           t.auditModifiedBy = CASE WHEN UPDATE (auditModifiedBy)
                                    THEN COALESCE (NULLIF (i.auditModifiedBy, N''), @Actor)
                                    ELSE @Actor
                               END,
           t.auditDeletedBy      = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Actor ELSE t.auditDeletedBy      END,
           t.auditDeletedDateUtc = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Now   ELSE t.auditDeletedDateUtc END
      FROM dbo.CaseNote AS t
      JOIN inserted     AS i ON i.CaseNoteId = t.CaseNoteId
      JOIN deleted      AS d ON d.CaseNoteId = t.CaseNoteId;
END;
GO


-- *** 4. Row-level security registration ***
--
-- The registry row goes in the same script as the table, deliberately.  An unregistered tenant-scoped table is not
-- protected and it fails OPEN -- every tenant's rows returned to every tenant, no error, nothing in any log.  Keeping
-- the registration here means the two cannot drift apart in the one direction that matters.
--
-- database/120_rls_policy.sql reads this registry and adds a FILTER predicate plus three BLOCK predicates per row.
-- database/950_verify_deployment.sql fails the build if any table with a TenantId column is missing from it.
--
-- MERGE rather than a bare INSERT, per the re-runnable rule: a second run must change nothing and report nothing.  The
-- UPDATE branch deliberately does not touch IsActive -- an operator who deactivated a row had a reason, and a
-- redeployment that silently reactivated it would be the worst possible behaviour for this particular table.

IF OBJECT_ID (N'config.TenantScopedTable', N'U') IS NOT NULL
BEGIN
    WITH src (SchemaName, TableName, TenantColumnName) AS
    (
        SELECT * FROM (VALUES (N'dbo', N'CaseFile', N'TenantId')
                            , (N'dbo', N'CaseNote', N'TenantId')) AS v (SchemaName, TableName, TenantColumnName)
    )
    MERGE config.TenantScopedTable AS tgt
    USING src
       ON tgt.SchemaName = src.SchemaName
      AND tgt.TableName  = src.TableName
    WHEN MATCHED AND tgt.TenantColumnName <> src.TenantColumnName
        THEN UPDATE SET tgt.TenantColumnName = src.TenantColumnName
    WHEN NOT MATCHED BY TARGET
        THEN INSERT (SchemaName, TableName, TenantColumnName, IsActive, auditCreatedBy)
             VALUES (src.SchemaName, src.TableName, src.TenantColumnName, 1, ORIGINAL_LOGIN ());
END
ELSE
BEGIN
    PRINT N'config.TenantScopedTable is absent, so dbo.CaseFile and dbo.CaseNote were NOT registered for row-level '
        + N'security. Run database/025_config_tables.sql and then re-run this file. Until then both tables return '
        + N'every tenant''s rows to every tenant.';
END
GO


-- *** 5. Descriptions ***
IF OBJECT_ID (N'util.uspSetObjectDescription', N'P') IS NOT NULL
BEGIN
    DECLARE @Descriptions TABLE
    (
        RowNo       INT IDENTITY (1, 1) PRIMARY KEY,
        SchemaName  SYSNAME         NOT NULL,
        ObjectType  SYSNAME         NOT NULL,
        ObjectName  SYSNAME         NOT NULL,
        ColumnName  SYSNAME             NULL,
        Description NVARCHAR (3750) NOT NULL
    );

    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    VALUES
      (N'dbo', N'TABLE', N'CaseFile', NULL
     , N'The application''s primary domain table, and the pattern every tenant-scoped table in dbo follows: TenantId NOT '
     + N'NULL and immutable, a per-tenant natural key filtered on IsDeleted = 0, composite foreign keys for every '
     + N'profile reference, an AFTER UPDATE trigger maintaining the audit block, a config.TenantScopedTable '
     + N'registration, and soft delete only. The columns are deliberately thin -- the design specifies the security '
     + N'architecture, not the domain -- but the shape is load-bearing.')
    , (N'dbo', N'TABLE', N'CaseFile', N'TenantId'
     , N'The owning tenant. NOT NULL because the RLS predicate compares one column on the table being queried: a table '
     + N'without its own TenantId can only be filtered through a join, and a predicate that joins runs that join for '
     + N'every row of every query. Immutable after insert; dbo.trg_au_updt_CaseFile raises 50011.')
    , (N'dbo', N'TABLE', N'CaseFile', N'AssignedToProfileId'
     , N'Composite FK with TenantId. Without the TenantId half, a case in one tenant could be assigned to a person in '
     + N'another and the application would display that person''s name -- a cross-tenant disclosure through an '
     + N'entirely legitimate query.')
    , (N'dbo', N'TABLE', N'CaseFile', N'ApprovedByProfileId'
     , N'Immutable once set: dbo.trg_au_updt_CaseFile raises 50010 on an attempt to change it. An approval that can be '
     + N'reattributed is not an approval.')
    , (N'dbo', N'TABLE', N'CaseFile', N'auditCreatedBy'
     , N'Who created the row. The DEFAULT reads SESSION_CONTEXT(''AppUser'') first and falls back to ORIGINAL_LOGIN () '
     + N'only when there is no session context -- the same expression dbo.trg_au_updt_CaseFile uses for '
     + N'auditModifiedBy, so creation and modification are attributed the same way. Under the pooled application login '
     + N'ORIGINAL_LOGIN () is the application''s own name and identical on every row, which is why it is the fallback '
     + N'and not the default. A procedure may still name the column explicitly and that wins. See DES-AUTH-001 '
     + N'section 14.4.')

    , (N'dbo', N'TABLE', N'CaseNote', NULL
     , N'Notes attached to a case, and the clearest example of why the denormalised TenantId needs a composite foreign '
     + N'key: FK_dbo_CaseNote_CaseFile_Tenant is what stops a note in one tenant referencing a case in another, which '
     + N'row-level security would not catch because the predicate trusts this row''s own TenantId.')
    , (N'dbo', N'TABLE', N'CaseNote', N'TenantId'
     , N'The owning tenant, denormalised from dbo.CaseFile and constrained by FK_dbo_CaseNote_CaseFile_Tenant. '
     + N'Immutable after insert; dbo.trg_au_updt_CaseNote raises 50011.')
    , (N'dbo', N'TABLE', N'CaseNote', N'CaseFileId'
     , N'The case this note belongs to. Immutable after insert: re-pointing a note rewrites the history of two cases '
     + N'at once.')
    , (N'dbo', N'TABLE', N'CaseNote', N'IsInternal'
     , N'1 = not shown to the subject of the case. A boolean rather than a note type, because the distinction is a '
     + N'disclosure decision and should not be buried in a category list.');

    DECLARE @RowNo       INT = 1
          , @MaxRowNo    INT = (SELECT MAX (RowNo) FROM @Descriptions)
          , @SchemaName  SYSNAME
          , @ObjectType  SYSNAME
          , @ObjectName  SYSNAME
          , @ColumnName  SYSNAME
          , @Description NVARCHAR (3750);

    WHILE @RowNo <= @MaxRowNo
    BEGIN
        SELECT @SchemaName  = SchemaName
             , @ObjectType  = ObjectType
             , @ObjectName  = ObjectName
             , @ColumnName  = ColumnName
             , @Description = Description
          FROM @Descriptions
         WHERE RowNo = @RowNo;

        EXEC util.uspSetObjectDescription @SchemaName  = @SchemaName
                                        , @ObjectType  = @ObjectType
                                        , @ObjectName  = @ObjectName
                                        , @Description = @Description
                                        , @ColumnName  = @ColumnName;

        SET @RowNo += 1;
    END;
END
ELSE
BEGIN
    PRINT N'util.uspSetObjectDescription is absent, so no descriptions were set. Run templates/extended-properties.sql '
        + N'and then re-run this file to add them.';
END
GO


-- *** 6. Grants ***
-- Nothing here.  scripts/permissions.sql grants SELECT, INSERT, UPDATE on SCHEMA::dbo to applicationRole and SELECT to
-- readOnlyRole, which covers these tables and every domain table added later -- that is the point of granting at schema
-- level.  Repeating it per table would create two places to keep in step, and the object-level grant would survive a
-- future decision to narrow the schema-level one.
--
-- DELETE is not granted, there and here: a plain table has no INSTEAD OF DELETE trigger, so a DELETE would be a real
-- hard delete. Soft-deleting is UPDATE ... SET IsDeleted = 1, which the UPDATE grant already covers.
--
-- The schema grant is what makes row-level security load-bearing rather than decorative: applicationRole can read and write
-- every table in dbo, so the predicate is the only thing standing between one tenant's session and another tenant's
-- rows.  DES-AUTH-001 section 19.3.


-- *** 7. Closing report ***
DECLARE @Report TABLE
(
    RowNo    INT IDENTITY (1, 1) PRIMARY KEY,
    Severity INT             NOT NULL,
    Status   VARCHAR (10)    NOT NULL,
    Item     NVARCHAR (200)  NOT NULL,
    Detail   NVARCHAR (1000)     NULL
);

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (x.FullName, N'U') IS NULL THEN 1 ELSE 4 END
     , CASE WHEN OBJECT_ID (x.FullName, N'U') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Table ' + x.FullName
     , x.Purpose
  FROM (VALUES (N'dbo.CaseFile', N'The domain table, and the pattern for every tenant-scoped table in dbo.')
             , (N'dbo.CaseNote', N'The child table, demonstrating the composite foreign key.')) AS x (FullName, Purpose);

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (x.ConstraintName, N'F') IS NULL THEN 1 ELSE 4 END
     , CASE WHEN OBJECT_ID (x.ConstraintName, N'F') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Composite FK ' + x.ConstraintName
     , x.Purpose
  FROM (VALUES (N'dbo.FK_dbo_CaseNote_CaseFile_Tenant'
              , N'Stops a note referencing a case in another tenant. RLS would not catch that: the predicate reads the '
              + N'note''s own TenantId and believes it.')
             , (N'dbo.FK_dbo_CaseFile_AssignedTo_Tenant'
              , N'Stops a case being assigned to a person in another tenant.')
             , (N'dbo.FK_dbo_CaseFile_ApprovedBy_Tenant'
              , N'Stops an approval being attributed to a person in another tenant.')) AS x (ConstraintName, Purpose);

-- The audit trigger check.  A missing trigger raises no error and breaks nothing visibly: the table works, and its
-- audit columns quietly stop being maintained on UPDATE.  That is precisely why it is reported here as a problem rather
-- than left to be noticed.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN tr.object_id IS NULL THEN 1
            WHEN tr.is_disabled = 1   THEN 2
            ELSE 4 END
     , CASE WHEN tr.object_id IS NULL THEN 'MISSING'
            WHEN tr.is_disabled = 1   THEN 'DISABLED'
            ELSE 'OK' END
     , N'Audit trigger ' + x.TriggerName
     , N'Maintains auditModifiedBy, auditModifiedDateUtc and the soft-delete stamp, and enforces immutability. Without '
     + N'it every UPDATE leaves the audit columns at their insert-time values and a soft delete records neither who nor '
     + N'when.'
  FROM (VALUES (N'dbo.trg_au_updt_CaseFile'), (N'dbo.trg_au_updt_CaseNote')) AS x (TriggerName)
  LEFT JOIN sys.triggers AS tr ON tr.object_id = OBJECT_ID (x.TriggerName);

-- Insert-side audit attribution -- T-097.  Severity 2 rather than 1: the row is still written and the column is still
-- NOT NULL, so nothing breaks; what is lost is the ability to say who created a row, on the one path that creates
-- every row.  That is a defect of the audit trail rather than of the table, and it is invisible until somebody asks.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN dc.definition IS NULL THEN 1
            WHEN dc.definition NOT LIKE N'%SESSION_CONTEXT%' THEN 2
            ELSE 4 END
     , CASE WHEN dc.definition IS NULL THEN 'MISSING'
            WHEN dc.definition NOT LIKE N'%SESSION_CONTEXT%' THEN 'STALE'
            ELSE 'OK' END
     , N'Insert attribution ' + x.ConstraintName
     , N'The auditCreatedBy DEFAULT must read SESSION_CONTEXT(''AppUser'') and fall back to ORIGINAL_LOGIN (), not the '
     + N'other way round: under the pooled application login ORIGINAL_LOGIN () is the application''s own name and is '
     + N'identical on every row. STALE means this database predates T-097 and section 1b or 2b did not run.'
  FROM (VALUES (N'DF_dbo_CaseFile_auditCreatedBy')
             , (N'DF_dbo_CaseNote_auditCreatedBy')) AS x (ConstraintName)
  LEFT JOIN sys.default_constraints AS dc ON dc.name = x.ConstraintName;

-- Registration.  Severity 1, not 3: an unregistered tenant-scoped table returns every tenant's rows to every tenant.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN EXISTS (SELECT 1 FROM config.TenantScopedTable
                          WHERE SchemaName = N'dbo' AND TableName = x.TableName
                            AND IsDeleted = 0 AND IsActive = 1) THEN 4 ELSE 1 END
     , CASE WHEN EXISTS (SELECT 1 FROM config.TenantScopedTable
                          WHERE SchemaName = N'dbo' AND TableName = x.TableName
                            AND IsDeleted = 0 AND IsActive = 1) THEN 'OK' ELSE 'MISSING' END
     , N'Tenant-scope registration for dbo.' + x.TableName
     , N'Registered by section 4 of this script, applied by database/120_rls_policy.sql. An unregistered tenant-scoped '
     + N'table is not protected and fails OPEN. database/950_verify_deployment.sql fails the build if this is still '
     + N'missing at the end of a deployment.'
  FROM (VALUES (N'CaseFile'), (N'CaseNote')) AS x (TableName)
 WHERE OBJECT_ID (N'config.TenantScopedTable', N'U') IS NOT NULL;

-- Policy coverage.  Registration alone is not protection -- 120_rls_policy.sql has to have run since the row appeared.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN sp.object_id IS NULL THEN 3 WHEN sp.is_enabled = 0 THEN 1 ELSE 4 END
     , CASE WHEN sp.object_id IS NULL THEN 'PENDING' WHEN sp.is_enabled = 0 THEN 'DISABLED' ELSE 'OK' END
     , N'Row-level security policy auth.TenantAccessPolicy'
     , N'PENDING here is expected on a first deployment: database/120_rls_policy.sql runs after this file. DISABLED is '
     + N'not expected and means the database is currently serving every tenant''s rows to every session.'
  FROM (SELECT 1 AS x) AS one
  LEFT JOIN sys.security_policies AS sp ON sp.object_id = OBJECT_ID (N'auth.TenantAccessPolicy');

IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
    PRINT N'Domain tables: PROBLEMS found. Read the report below before running the next script.';
ELSE
    PRINT N'Domain tables: no problems found.';

PRINT N'';

SELECT Severity, Status, Item, Detail
  FROM @Report
 ORDER BY Severity, RowNo;
GO
