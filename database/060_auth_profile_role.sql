/***********************************************************************************************************************
Script:         060_auth_profile_role.sql
Purpose:        auth.UserProfileRole -- the grant.  One row per (profile, role, scope): who holds what authority, where,
                from whom, and until when.
Target:         SQL Server 2022.
Run as:         db_owner in the target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/060_auth_profile_role.sql
Idempotent:     Yes.  Guarded CREATE TABLE and CREATE INDEX, CREATE OR ALTER trigger, no seed data.
Depends on:     database/030_auth_tenant.sql (auth.Tenant, auth.TenantClosure, UX_auth_Tenant_Id_Application),
                database/040_auth_userprofile.sql (auth.UserProfile), database/055_auth_role.sql (auth.Role and
                UX_auth_Role_Id_Application), templates/extended-properties.sql.
Implements:     DES-AUTH-001 sections 8.4, 11, 15.4 and Appendix B.  PLAN-AUTH-001 task T-047.
To retarget:    Pass it per run:  sqlcmd -d <database> -v DbName=<database>.  There is no in-file default.

THIS IS THE TABLE THE WHOLE DESIGN IS ABOUT
-------------------------------------------
Everything before it is vocabulary.  auth.UserProfileRole is the only place a human decision is recorded: this person, in
this organization, may do these things, over this part of the tree, granted by that person, until then.  Four
consequences follow and each one is a column.

SCOPE IS NOT THE PROFILE'S TENANT
--------------------------------
Section 8.4.  ScopeTenantId defaults to the profile's own tenant -- the common case, and the one an administrator never
has to think about.  Setting it elsewhere is what Variant 2 needs:

    A program officer's profile is bound to their program.  It carries Editor scoped at the program, so their inserts
    land there, and Read-only scoped at the agency, so they can see every other program's records without switching
    profile.  One profile, two grants, exactly the authority the requirement describes.

That is why the natural key is the TRIPLE (UserProfileId, RoleId, ScopeTenantId) and not the pair: the same role twice at
two scopes is not a duplicate, it is the feature.

REVOCATION IS A SOFT DELETE AND EXPIRY IS NOT
---------------------------------------------
P-07.  Revoking sets IsDeleted = 1 and the row stays, because "who could approve this last March" is a question an
auditor will ask about a grant that no longer exists.  ExpiresUtc is a different mechanism for a different need -- the
backup role-assigner who covers for two weeks -- and an expired grant is filtered out at MATERIALIZATION time, in
auth.uspRebuildProfilePermissionScope, not by anything that writes to this table.  Nothing expires a row; time does.

The consequence to keep in mind is that this table is NOT the effective permission set and must never be read as one.  A
live row here can be expired, can belong to a soft-deleted role, can point at a deactivated profile, and can name a role
whose permissions were emptied yesterday.  auth.ProfilePermissionScope is the resolved answer; this is the input.

WHAT IS ENFORCED HERE AND WHAT IS NOT
-------------------------------------
Two of the three cross-application edges are structural.  ApplicationId is denormalised onto this table and pinned by two
composite foreign keys -- one to auth.Role, one to auth.Tenant -- so a grant cannot name a role from one application and
a scope tenant from another.  That is INV-04's precondition: "ancestor-or-self" is only a meaningful question inside one
tree.

The third edge is not structural and cannot cheaply be made so.  Whether the TARGET PROFILE belongs to the same
application reaches through auth.UserProfile to auth.Tenant to auth.Application, and pinning it would mean denormalising
ApplicationId onto auth.UserProfile -- a column section 15.4 does not have, on the table every sign-in touches.  So it is
checked in auth.uspAssignRoleToProfile and refused with E-50043.  The registry entry for that number is the record of a
deliberate choice, not of an oversight.

INV-04 itself -- the owner tenant covers the scope -- is likewise procedural, E-50042, because it is a question about
auth.TenantClosure and a CHECK constraint cannot read another table.  The closing report of this script asks it of every
live grant, so a violation introduced by a direct UPDATE or by a re-parenting that outran its closure rebuild is visible
on the next deployment rather than at the next audit.

WHY GrantedByProfileId IS NULLABLE
----------------------------------
Section 16.3.  On an empty database INV-05 has nobody to satisfy it: 900_bootstrap_first_admin.sql is the only script
that writes authorization rows without a granting profile, and it writes NULL here rather than pointing the row at
itself.  A self-reference would be indistinguishable from the self-grant INV-06 exists to refuse, and it would put a
fiction in the one column section 11 relies on for "under whose authority".  NULL says "no granting profile existed",
which is true exactly once per deployment, and the closing report counts them.
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

IF OBJECT_ID (N'auth.UserProfile', N'U') IS NULL OR OBJECT_ID (N'auth.Role', N'U') IS NULL
BEGIN
    DECLARE @MsgParents NVARCHAR (2000) =
        N'auth.UserProfile or auth.Role is missing. Run database/040_auth_userprofile.sql and '
      + N'database/055_auth_role.sql first. Nothing has been changed.';

    THROW 50000, @MsgParents, 1;
END
GO


-- *** 1. auth.UserProfileRole ***
IF OBJECT_ID (N'auth.UserProfileRole', N'U') IS NULL
BEGIN
    CREATE TABLE auth.UserProfileRole
    (
        UserProfileRoleId    INT             IDENTITY (1, 1) NOT NULL

        -- WHO.  The profile, not the user: a person's authority is per hat, which is the whole of section 6.3.
      , UserProfileId        INT                             NOT NULL

        -- WHAT.
      , RoleId               INT                             NOT NULL

        -- WHERE.  Defaults to the profile's own tenant in auth.uspAssignRoleToProfile -- not by a DEFAULT constraint,
        -- because the default is another row's column and a constraint cannot read one.
      , ScopeTenantId        INT                             NOT NULL

        -- Denormalised from the role and pinned by the two composite foreign keys below, so the role and the scope
        -- cannot come from different applications.  A caller never supplies it; the trigger refuses to let it change.
      , ApplicationId        INT                             NOT NULL

        -- FROM WHOM.  Section 11's audit anchor.  NULL only for 900_bootstrap_first_admin.sql; see the header.
      , GrantedByProfileId   INT                                 NULL

      , GrantedUtc           DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_UserProfileRole_GrantedUtc DEFAULT (SYSUTCDATETIME ())

        -- UNTIL WHEN.  Normally NULL.  An expired grant is filtered out at materialization time and the row remains --
        -- nothing expires it, time does.
      , ExpiresUtc           DATETIME2 (3)                       NULL

      , IsDeleted            BIT                             NOT NULL
            CONSTRAINT DF_auth_UserProfileRole_IsDeleted DEFAULT (0)
      , auditDeletedBy       NVARCHAR (255)                      NULL
      , auditDeletedDateUtc  DATETIME2 (3)                       NULL
      , auditCreatedBy       NVARCHAR (255)                  NOT NULL
            CONSTRAINT DF_auth_UserProfileRole_auditCreatedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditCreatedDateUtc  DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_UserProfileRole_auditCreatedDateUtc DEFAULT (SYSUTCDATETIME ())
      , auditModifiedBy      NVARCHAR (255)                  NOT NULL
            CONSTRAINT DF_auth_UserProfileRole_auditModifiedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditModifiedDateUtc DATETIME2 (3)                   NOT NULL
            CONSTRAINT DF_auth_UserProfileRole_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ())

        -- A surrogate key, for the reason auth.RolePermission gives: the natural key's uniqueness has to be filtered on
        -- IsDeleted = 0, because revoking a grant and later re-granting it is the ordinary course of events.
      , CONSTRAINT PK_auth_UserProfileRole PRIMARY KEY CLUSTERED (UserProfileRoleId)

      , CONSTRAINT FK_auth_UserProfileRole_UserProfile
            FOREIGN KEY (UserProfileId) REFERENCES auth.UserProfile (UserProfileId)

        -- The audit anchor is a foreign key too: "granted by profile 412" must name a profile that exists, or section
        -- 11's trail has a hole in it that nothing would report.
      , CONSTRAINT FK_auth_UserProfileRole_GrantedByProfile
            FOREIGN KEY (GrantedByProfileId) REFERENCES auth.UserProfile (UserProfileId)

      , CONSTRAINT FK_auth_UserProfileRole_Role
            FOREIGN KEY (RoleId, ApplicationId)
            REFERENCES auth.Role (RoleId, ApplicationId)

      , CONSTRAINT FK_auth_UserProfileRole_ScopeTenant
            FOREIGN KEY (ScopeTenantId, ApplicationId)
            REFERENCES auth.Tenant (TenantId, ApplicationId)

        -- A grant that expires before it is made is not a time-boxed grant, it is a typo -- and one that would be
        -- invisible, because materialization would simply never return it and the screen would say "no permission".
      , CONSTRAINT CK_auth_UserProfileRole_Expiry
            CHECK (ExpiresUtc IS NULL OR ExpiresUtc > GrantedUtc)

      , CONSTRAINT CK_auth_UserProfileRole_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS     NULL AND auditDeletedDateUtc IS     NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL))
    );
END
GO

-- The natural key of section 15.4: the TRIPLE, filtered.  The same role at two scopes is not a duplicate -- see the
-- header -- and re-granting after a revocation must not be refused by an index.
--
-- ExpiresUtc is INCLUDEd rather than given its own index: auth.uspRebuildProfilePermissionScope reads exactly these four
-- columns for one profile, so this index alone answers it.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'UX_auth_UserProfileRole_Grant' AND object_id = OBJECT_ID (N'auth.UserProfileRole'))
BEGIN
    CREATE UNIQUE INDEX UX_auth_UserProfileRole_Grant
        ON auth.UserProfileRole (UserProfileId, RoleId, ScopeTenantId)
        INCLUDE (ExpiresUtc, ApplicationId) WHERE IsDeleted = 0;
END
GO

-- "Who holds this role?"  Asked by the role editor before anyone changes what a role means, and asked by
-- auth.uspSetRolePermissions to find the profiles whose materialized scope must be rebuilt afterwards -- which is the
-- reader that makes this index load-bearing rather than merely convenient.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_auth_UserProfileRole_Role' AND object_id = OBJECT_ID (N'auth.UserProfileRole'))
BEGIN
    CREATE INDEX IX_auth_UserProfileRole_Role
        ON auth.UserProfileRole (RoleId)
        INCLUDE (UserProfileId, ScopeTenantId, ExpiresUtc) WHERE IsDeleted = 0;
END
GO

-- "Who has authority here?" -- the tenant administrator's own screen, and the query a re-parenting has to run to find
-- out whose reach just changed.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_auth_UserProfileRole_Scope' AND object_id = OBJECT_ID (N'auth.UserProfileRole'))
BEGIN
    CREATE INDEX IX_auth_UserProfileRole_Scope
        ON auth.UserProfileRole (ScopeTenantId)
        INCLUDE (UserProfileId, RoleId, ExpiresUtc) WHERE IsDeleted = 0;
END
GO

-- "What did this administrator grant?" -- the only index that reads the audit anchor, and the one a disputed grant is
-- investigated with.  Section 11.  Filtered on IsDeleted = 0 like the others, which is a limitation worth naming: a
-- revoked grant is found through logs.AuthorizationChange, which records the revocation as an event and is the trail
-- built for this question.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'IX_auth_UserProfileRole_GrantedBy' AND object_id = OBJECT_ID (N'auth.UserProfileRole'))
BEGIN
    CREATE INDEX IX_auth_UserProfileRole_GrantedBy
        ON auth.UserProfileRole (GrantedByProfileId)
        INCLUDE (UserProfileId, RoleId, ScopeTenantId, GrantedUtc) WHERE IsDeleted = 0;
END
GO


-- *** 2. Audit trigger ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.trg_au_updt_UserProfileRole
Author:       rsincero
CreateDate:   2026-09-20
Description:
AFTER UPDATE audit stamp for auth.UserProfileRole, and the guard that makes everything except ExpiresUtc immutable --
E-50010.

UserProfileId, RoleId, ScopeTenantId, ApplicationId, GrantedByProfileId and GrantedUtc are all immutable, and the reason
is the same for all six: this row is a RECORD OF A DECISION, and a decision cannot be edited.  Re-pointing any of the
first four moves authority somebody else authorised; re-pointing GrantedByProfileId attributes a decision to a person who
did not make it, which is worse than having no trail at all; moving GrantedUtc changes when authority began, and
therefore which of two conflicting grants an auditor believes.  Revoke the grant -- a soft delete, P-07 -- and make the
one you meant.

ExpiresUtc is the exception, and deliberately: extending the cover of a backup role-assigner by a week is an ordinary
administrative act, not a new decision, and forcing a revoke-and-regrant for it would leave two rows where the trail
reads as if authority lapsed and was re-granted.  The change is recorded in logs.AuthorizationChange by the procedure
that makes it.

Modification History:
2026-09-20  rsincero  Created.  PLAN-AUTH-001 T-047.
2026-09-25  rsincero  G-55, BL-086.  A resurrection -- IsDeleted 1 to 0 in one statement -- may re-stamp GrantedUtc and
                      GrantedByProfileId: it is a new decision by a new person, and auth.uspAssignRoleToProfile has always
                      re-stamped both on that path, so every re-grant after a revoke through the procedure failed with
                      E-50010.  _tests/050 resurrects by a direct UPDATE that leaves both alone, which is why it did not
                      show; _tests/080 8b'' now asserts the round trip.  The other four columns stay immutable on every row.
***********************************************************************************************************************/
CREATE OR ALTER TRIGGER auth.trg_au_updt_UserProfileRole
    ON auth.UserProfileRole
    AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    IF (UPDATE (UserProfileId) OR UPDATE (RoleId) OR UPDATE (ScopeTenantId) OR UPDATE (ApplicationId)
        OR UPDATE (GrantedByProfileId) OR UPDATE (GrantedUtc))
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.UserProfileRoleId = i.UserProfileRoleId
                    WHERE i.UserProfileId <> d.UserProfileId
                       OR i.RoleId        <> d.RoleId
                       OR i.ScopeTenantId <> d.ScopeTenantId
                       OR i.ApplicationId <> d.ApplicationId
                       -- A resurrection is a new grant, so who and when are re-stamped. See the history.
                       OR (NOT (d.IsDeleted = 1 AND i.IsDeleted = 0)
                           AND (i.GrantedUtc <> d.GrantedUtc
                                OR EXISTS (SELECT i.GrantedByProfileId EXCEPT SELECT d.GrantedByProfileId))))
    BEGIN
        ;THROW 50010, N'auth.UserProfileRole: every column except ExpiresUtc is immutable. This row records a decision somebody made, and a decision cannot be edited -- re-pointing the profile, role or scope moves authority another person authorised, and re-pointing GrantedByProfileId or GrantedUtc attributes a decision to the wrong person or the wrong moment. Revoke the grant and make the one you meant.', 1;
    END;

    DECLARE @Now   DATETIME2 (3)  = SYSUTCDATETIME ()
          , @Actor NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                            , ORIGINAL_LOGIN ());

    UPDATE upr
       SET upr.auditModifiedDateUtc = @Now
         , upr.auditModifiedBy      = CASE WHEN UPDATE (auditModifiedBy)
                                           THEN COALESCE (NULLIF (i.auditModifiedBy, N''), @Actor)
                                           ELSE @Actor END
         , upr.auditDeletedBy       = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Actor ELSE upr.auditDeletedBy      END
         , upr.auditDeletedDateUtc  = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Now   ELSE upr.auditDeletedDateUtc END
      FROM auth.UserProfileRole AS upr
      JOIN inserted             AS i ON i.UserProfileRoleId = upr.UserProfileRoleId
      JOIN deleted              AS d ON d.UserProfileRoleId = upr.UserProfileRoleId;
END;
GO


-- *** 3. Descriptions ***
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
      (N'auth', N'TABLE', N'UserProfileRole', NULL
     , N'THE GRANT -- the only table in this database that records a human decision: this profile holds this role over '
     + N'this part of the tree, granted by that profile, until then. Sections 8.4 and 11. NOT the effective permission '
     + N'set and must never be read as one: a live row here can be expired, can name a soft-deleted role, or can name a '
     + N'role whose permissions were emptied yesterday. auth.ProfilePermissionScope is the resolved answer; this is the '
     + N'input to it.')
    , (N'auth', N'TABLE', N'UserProfileRole', N'UserProfileRoleId'
     , N'Surrogate key, used because the natural key''s uniqueness must be FILTERED on IsDeleted = 0 -- revoking a '
     + N'grant and later re-granting it is the ordinary course of events.')
    , (N'auth', N'TABLE', N'UserProfileRole', N'UserProfileId'
     , N'WHO. The profile, not the user: authority is per hat, which is the whole of section 6.3. IMMUTABLE (E-50010).')
    , (N'auth', N'TABLE', N'UserProfileRole', N'RoleId'
     , N'WHAT. IMMUTABLE (E-50010). Pinned to ApplicationId by FK_auth_UserProfileRole_Role.')
    , (N'auth', N'TABLE', N'UserProfileRole', N'ScopeTenantId'
     , N'WHERE the grant reaches -- any tenant the role''s owner covers (INV-04, enforced in '
     + N'auth.uspAssignRoleToProfile with E-50042, because it is a question about auth.TenantClosure and a CHECK cannot '
     + N'read another table). Defaults to the profile''s own tenant, set by the procedure rather than by a DEFAULT '
     + N'constraint, because the default is another row''s column. Section 8.4''s Variant 2 case -- Editor at the '
     + N'program, Read-only at the agency, one profile -- is why the natural key is the triple and not the pair. '
     + N'IMMUTABLE (E-50010).')
    , (N'auth', N'TABLE', N'UserProfileRole', N'ApplicationId'
     , N'Denormalised from the role and pinned by two composite foreign keys, one to auth.Role and one to auth.Tenant, '
     + N'so a grant cannot name a role from one application and a scope from another -- INV-04 is only a meaningful '
     + N'question inside one tree. Whether the TARGET PROFILE is in the same application is checked procedurally '
     + N'instead (E-50043): pinning it would mean denormalising ApplicationId onto auth.UserProfile, a column section '
     + N'15.4 does not have on the table every sign-in touches. IMMUTABLE (E-50010).')
    , (N'auth', N'TABLE', N'UserProfileRole', N'GrantedByProfileId'
     , N'FROM WHOM -- section 11''s audit anchor, and a foreign key so the trail cannot name a profile that does not '
     + N'exist. NULL means no granting profile existed, which is true exactly once per deployment: '
     + N'900_bootstrap_first_admin.sql. It writes NULL rather than pointing the row at itself, because a self-reference '
     + N'would be indistinguishable from the self-grant INV-06 refuses. IMMUTABLE (E-50010): attributing a decision to '
     + N'someone who did not make it is worse than having no trail.')
    , (N'auth', N'TABLE', N'UserProfileRole', N'GrantedUtc'
     , N'When authority began, UTC. IMMUTABLE (E-50010) -- moving it changes which of two conflicting grants an auditor '
     + N'believes.')
    , (N'auth', N'TABLE', N'UserProfileRole', N'ExpiresUtc'
     , N'Time-boxed authority -- the backup role-assigner who covers for two weeks. Normally NULL. The ONE editable '
     + N'column: extending cover by a week is an administrative act, not a new decision, and forcing a '
     + N'revoke-and-regrant would leave a trail reading as if authority had lapsed. An expired grant is filtered out at '
     + N'materialization time by auth.uspRebuildProfilePermissionScope; nothing expires the row, time does.');

    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    SELECT N'auth', N'TABLE', N'UserProfileRole', c.ColumnName, c.Description
      FROM (VALUES
          (N'IsDeleted',            N'Soft-delete flag, and the way a grant is REVOKED -- P-07. The row stays, because "who could approve this last March" is asked about grants that no longer exist.')
        , (N'auditDeletedBy',       N'Who revoked the grant. NULL unless IsDeleted = 1 -- the pair is enforced by CK_auth_UserProfileRole_DeletedPair.')
        , (N'auditDeletedDateUtc',  N'When the grant was revoked, UTC. NULL unless IsDeleted = 1.')
        , (N'auditCreatedBy',       N'Who inserted the row. Defaults to ORIGINAL_LOGIN (); auth.uspAssignRoleToProfile sets it to the acting profile. GrantedByProfileId is the column an audit reads -- this one records the database principal.')
        , (N'auditCreatedDateUtc',  N'When the row was inserted, UTC. Normally equal to GrantedUtc.')
        , (N'auditModifiedBy',      N'Who last updated the row, set by the AFTER UPDATE trigger from SESSION_CONTEXT (''AppUser'') or ORIGINAL_LOGIN ().')
        , (N'auditModifiedDateUtc', N'When the row was last updated, UTC, set by the AFTER UPDATE trigger.')
       ) AS c (ColumnName, Description);

    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    VALUES (N'auth', N'TRIGGER', N'trg_au_updt_UserProfileRole', NULL
          , N'AFTER UPDATE audit stamp for auth.UserProfileRole, and the guard that makes every column except '
          + N'ExpiresUtc immutable -- E-50010. This row records a decision, and a decision cannot be edited.');

    DECLARE @RowNo    INT = 1
          , @MaxRowNo INT = (SELECT MAX (RowNo) FROM @Descriptions)
          , @dSchema  SYSNAME
          , @dType    SYSNAME
          , @dObject  SYSNAME
          , @dColumn  SYSNAME
          , @dText    NVARCHAR (3750);

    WHILE @RowNo <= @MaxRowNo
    BEGIN
        SELECT @dSchema = SchemaName
             , @dType   = ObjectType
             , @dObject = ObjectName
             , @dColumn = ColumnName
             , @dText   = Description
          FROM @Descriptions
         WHERE RowNo = @RowNo;

        EXEC util.uspSetObjectDescription
              @SchemaName  = @dSchema
            , @ObjectType  = @dType
            , @ObjectName  = @dObject
            , @Description = @dText
            , @ColumnName  = @dColumn;

        SET @RowNo = @RowNo + 1;
    END;
END
ELSE
BEGIN
    PRINT N'util.uspSetObjectDescription is absent. Descriptions were NOT applied. Run '
        + N'.claude/skills/ponytail-sql-objects/templates/extended-properties.sql and then re-run this script.';
END
GO


-- *** 4. Grants ***
--
-- DELIBERATELY EMPTY.  INV-11 and 170_permissions.sql.  A SELECT grant on this table would hand a client the complete
-- authority map of every organization in the deployment, which is more than any screen needs and exactly what an
-- attacker choosing a target would want.
GO


-- *** 5. Closing report ***
DECLARE @Report TABLE
(
    RowNo    INT IDENTITY (1, 1) PRIMARY KEY,
    Severity INT             NOT NULL,
    Status   VARCHAR (10)    NOT NULL,
    Item     NVARCHAR (200)  NOT NULL,
    Detail   NVARCHAR (1000)     NULL
);

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (N'auth.UserProfileRole', N'U') IS NULL THEN 1 ELSE 4 END
     , CASE WHEN OBJECT_ID (N'auth.UserProfileRole', N'U') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Table auth.UserProfileRole'
     , N'The grant. Natural key is the TRIPLE (UserProfileId, RoleId, ScopeTenantId), filtered -- sections 8.4 and 15.4.';

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN i.name IS NULL THEN 2 WHEN i.is_disabled = 1 THEN 2 ELSE 4 END
     , CASE WHEN i.name IS NULL THEN 'MISSING' WHEN i.is_disabled = 1 THEN 'DISABLED' ELSE 'OK' END
     , N'Index ' + x.IndexName
     , x.Purpose
  FROM (VALUES (N'UX_auth_UserProfileRole_Grant',     N'UNIQUE on the triple where live, INCLUDE (ExpiresUtc, ApplicationId) so auth.uspRebuildProfilePermissionScope reads one profile from this index alone.')
             , (N'IX_auth_UserProfileRole_Role',      N'"Who holds this role?" -- and the index auth.uspSetRolePermissions uses to find the profiles whose materialized scope must be rebuilt.')
             , (N'IX_auth_UserProfileRole_Scope',     N'"Who has authority here?" -- the tenant administrator''s screen, and the re-parenting impact query.')
             , (N'IX_auth_UserProfileRole_GrantedBy', N'"What did this administrator grant?" -- section 11, the disputed-grant investigation.'))
       AS x (IndexName, Purpose)
  LEFT JOIN sys.indexes AS i ON i.name = x.IndexName AND i.object_id = OBJECT_ID (N'auth.UserProfileRole');

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN fk.name IS NULL THEN 1 WHEN fk.is_disabled = 1 THEN 1 ELSE 4 END
     , CASE WHEN fk.name IS NULL THEN 'MISSING' WHEN fk.is_disabled = 1 THEN 'DISABLED' ELSE 'OK' END
     , N'Foreign key ' + x.ConstraintName
     , x.Purpose
  FROM (VALUES (N'FK_auth_UserProfileRole_UserProfile',       N'The profile exists.')
             , (N'FK_auth_UserProfileRole_GrantedByProfile',  N'The audit anchor names a profile that exists -- otherwise section 11''s trail has a hole nothing would report.')
             , (N'FK_auth_UserProfileRole_Role',              N'(RoleId, ApplicationId) -> auth.Role. Pins the grant''s application to the role''s.')
             , (N'FK_auth_UserProfileRole_ScopeTenant',       N'(ScopeTenantId, ApplicationId) -> auth.Tenant. Pins the same column to the scope''s, so role and scope must share an application -- INV-04''s precondition.'))
       AS x (ConstraintName, Purpose)
  LEFT JOIN sys.foreign_keys AS fk ON fk.name = x.ConstraintName;

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN tr.object_id IS NULL THEN 1 WHEN tr.is_disabled = 1 THEN 1 ELSE 4 END
     , CASE WHEN tr.object_id IS NULL THEN 'MISSING' WHEN tr.is_disabled = 1 THEN 'DISABLED' ELSE 'OK' END
     , N'Trigger auth.trg_au_updt_UserProfileRole'
     , N'Audit stamp, and E-50010 on every column except ExpiresUtc. DISABLED here means a grant can be silently '
     + N're-pointed at another person with the original''s audit trail attached, which is a security finding.'
  FROM (SELECT 1 AS one) AS o
  LEFT JOIN sys.triggers AS tr ON tr.object_id = OBJECT_ID (N'auth.trg_au_updt_UserProfileRole');

-- INV-04, asked of every live grant.  Not preventable declaratively -- it is a question about auth.TenantClosure -- so
-- E-50042 in auth.uspAssignRoleToProfile is the gate and this is the audit.  A violation here means either a direct
-- UPDATE went round the procedure, or a re-parenting changed the tree and auth.uspRebuildTenantClosure has not run.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Violations = 0 THEN 4 ELSE 1 END
     , CASE WHEN x.Violations = 0 THEN 'OK' ELSE 'VIOLATION' END
     , N'INV-04: every live grant''s role is owned at or above its scope'
     , CASE WHEN x.Violations = 0
            THEN N'Yes, over ' + CAST (x.LiveGrants AS NVARCHAR (11)) + N' live grant(s). Enforced at write time by '
               + N'auth.uspAssignRoleToProfile (E-50042) and audited here, because a CHECK constraint cannot read '
               + N'auth.TenantClosure.'
            ELSE CAST (x.Violations AS NVARCHAR (11)) + N' live grant(s) name a role whose owner tenant does not cover '
               + N'the scope. Either a direct UPDATE went round auth.uspAssignRoleToProfile, or the tree was '
               + N're-parented and auth.uspRebuildTenantClosure has not run since. Each such grant confers authority '
               + N'nobody was entitled to delegate.'
       END
  FROM (SELECT LiveGrants = (SELECT COUNT (*) FROM auth.UserProfileRole WHERE IsDeleted = 0)
             , Violations = (SELECT COUNT (*)
                               FROM auth.UserProfileRole AS upr
                               JOIN auth.Role            AS r  ON r.RoleId = upr.RoleId
                              WHERE upr.IsDeleted = 0
                                AND NOT EXISTS (SELECT 1
                                                  FROM auth.TenantClosure AS tc
                                                 WHERE tc.AncestorTenantId   = r.OwnerTenantId
                                                   AND tc.DescendantTenantId = upr.ScopeTenantId
                                                   AND tc.IsDeleted = 0))) AS x;

-- The bootstrap's fingerprint.  More than a handful of these means something other than 900_bootstrap_first_admin.sql
-- is writing grants with no granting profile, which is the one thing INV-05 exists to prevent.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Anonymous = 0 THEN 4 ELSE 3 END
     , CASE WHEN x.Anonymous = 0 THEN 'OK' ELSE 'REVIEW' END
     , N'Grants with no granting profile'
     , CASE WHEN x.Anonymous = 0
            THEN N'None. Every grant names the profile that made it -- section 11''s audit anchor.'
            ELSE CAST (x.Anonymous AS NVARCHAR (11)) + N' live grant(s) have GrantedByProfileId = NULL. Expected from '
               + N'900_bootstrap_first_admin.sql, which is the only script permitted to write authorization rows '
               + N'without a granting profile (section 16.3) -- it should be a handful, all at the root tenant, all on '
               + N'the same profile. Anything else means something is going round INV-05.'
       END
  FROM (SELECT Anonymous = (SELECT COUNT (*) FROM auth.UserProfileRole
                             WHERE IsDeleted = 0 AND GrantedByProfileId IS NULL)) AS x;

INSERT @Report (Severity, Status, Item, Detail)
SELECT 3, 'INFO', N'Grants'
     , CAST (x.LiveGrants AS NVARCHAR (11)) + N' live, of which ' + CAST (x.TimeBoxed AS NVARCHAR (11))
     + N' time-boxed and ' + CAST (x.Expired AS NVARCHAR (11)) + N' already expired, plus '
     + CAST (x.Revoked AS NVARCHAR (11)) + N' revoked and retained (P-07). An expired grant is filtered out at '
     + N'materialization time and keeps its row on purpose -- nothing expires it, time does.'
  FROM (SELECT LiveGrants = (SELECT COUNT (*) FROM auth.UserProfileRole WHERE IsDeleted = 0)
             , TimeBoxed  = (SELECT COUNT (*) FROM auth.UserProfileRole WHERE IsDeleted = 0 AND ExpiresUtc IS NOT NULL)
             , Expired    = (SELECT COUNT (*) FROM auth.UserProfileRole
                              WHERE IsDeleted = 0 AND ExpiresUtc IS NOT NULL AND ExpiresUtc <= SYSUTCDATETIME ())
             , Revoked    = (SELECT COUNT (*) FROM auth.UserProfileRole WHERE IsDeleted = 1)) AS x;

INSERT @Report (Severity, Status, Item, Detail)
VALUES (3, 'NEXT', N'Next script'
      , N'065_auth_effective_permission.sql -- auth.ProfilePermissionScope, the flattening of this table through roles '
      + N'to permissions, and auth.uspRebuildProfilePermissionScope which builds it. D-07.');

IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
    PRINT N'Role grants: PROBLEMS found. Read the report below before running the next script.';
ELSE
    PRINT N'Role grants: no problems found.';

PRINT N'';

SELECT Severity, Status, Item, Detail
  FROM @Report
 ORDER BY Severity, RowNo;
GO
