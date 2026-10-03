/***********************************************************************************************************************
Script:         035_auth_tenant_policy.sql
Purpose:        auth.TenantAuthenticationPolicy, auth.TenantTrustedIssuer and auth.TenantDefaultRole -- the per-tenant
                authentication settings that make the three application variants one design, the identity providers a
                subtree will accept an assertion from, and the roles a new profile gets automatically.
Target:         SQL Server 2022.
Run as:         db_owner in the target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/035_auth_tenant_policy.sql
Idempotent:     Yes.  Every CREATE is guarded, every trigger is CREATE OR ALTER, nothing is dropped, nothing is seeded.
Depends on:     database/030_auth_tenant.sql (auth.Tenant), database/005_schemas_and_roles.sql (schema auth),
                templates/extended-properties.sql (util.uspSetObjectDescription).
Implements:     DES-AUTH-001 sections 7.2, 7.3, 11.5 and 15.2.  PLAN-AUTH-001 task T-031.
                auth.TenantTrustedIssuer arrives in section 3 with gap G-21: AllowFederated is a boolean, and a boolean
                cannot say WHICH identity provider a subtree federates with.  The table is the list; the refusal
                (E-50124) is in auth.uspBeginSsoLogin, because that is where an issuer is first presented.
To retarget:    Pass it per run:  sqlcmd -d <database> -v DbName=<database>.  There is no in-file default.

WHAT IS LOAD-BEARING HERE
-------------------------
ONE POLICY ROW PER TENANT, AND MOST TENANTS HAVE NONE.  The unique index on TenantId is filtered on IsDeleted = 0, so
a tenant has at most one live policy.  The normal state of a deployed database is that the ROOT has a policy row and
nothing else does: section 7.2 inherits down the tree, and auth.udfResolveAuthPolicy (100_auth_functions.sql) walks
auth.TenantClosure upward and takes the lowest-depth match.  A hundred-tenant Variant 2 deployment has two or three
rows in this table.

That is why there is no NOT NULL default policy and no row created for a tenant when the tenant is created.  A row
here means "this subtree is different", and a table where every tenant has a row is a table where nobody can see which
tenants were deliberately overridden.

PreferredMethod MUST BE A METHOD THIS ROW PERMITS, AND THAT IS A CONSTRAINT, NOT A CONVENTION.
CK_auth_TenantAuthenticationPolicy_PreferredIsAllowed ties the two together row-locally.  Without it the reachable bad
state is a policy that prefers federated sign-in and does not allow it, which presents the user with an SSO button
that raises E-50104 when pressed -- a configuration error that looks like an outage.

RequireMfaForLocal IS NOT THE WHOLE MFA RULE, AND MUST NOT BE READ AS IF IT WERE.  It governs ORDINARY local sign-in.
The platform-administrator bypass route requires a second factor unconditionally, whatever this column says: INV-08,
enforced in auth.uspCompleteLogin by E-50107, not here.  A reader who sets RequireMfaForLocal = 0 and concludes the
bypass route is now single-factor has misread the design, so the column's own description says so.

AN EMPTY auth.TenantTrustedIssuer IS "NOT CONFIGURED", NOT "TRUST NOTHING", AND THAT IS THE ONE JUDGEMENT IN G-21.
The list inherits the way a policy row inherits: auth.uspBeginSsoLogin walks auth.TenantClosure upward and the NEAREST
ancestor holding at least one live row owns the list WHOLE.  If no ancestor holds one, no list resolved, and the issuer
is not checked -- the procedure behaves as it did before G-21.  Refusing everything instead would mean that installing
this template's next version turns off federated sign-in for every deployment that already had it working, which is an
outage delivered by an upgrade.  So the control is opt-in, and the closing report of this script and of
110_auth_authn_procedures.sql both name the deployments that have not opted in, rather than letting the absence be
silent -- which is the mistake G-30 records about RequireStepUpForPrivileged.

Once a list DOES resolve, it is strict in both directions: an issuer that is not on it is refused, and so is a call that
supplies no issuer at all.  A tenant that has named its providers has said the question is now answerable, and a caller
that declines to answer it cannot be given the benefit of the doubt -- E-50124 covers both.

Issuer is NVARCHAR (512), matching auth.UserFederatedIdentity.Issuer exactly, because the value compared at the
callback and the value permitted here MUST be the same string.  A shorter column here would silently truncate a long
directory URL into an entry that never matches, which presents as "SSO stopped working" with nothing in the transcript.

auth.TenantDefaultRole.RoleId IS CONSTRAINED BY A GUARDED ALTER, NOT BY ITS CREATE TABLE
---------------------------------------------------------------------------------------
auth.Role is created by 055_auth_role.sql, which installs at manifest step 13; this script installs at step 9, so the
constraint cannot be declared in the column list.  Section 2 therefore adds it separately, guarded on the PARENT TABLE
rather than on the phase:

    IF OBJECT_ID (N'auth.Role', N'U') IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = N'FK_auth_TenantDefaultRole_Role')
    BEGIN
        ALTER TABLE auth.TenantDefaultRole WITH CHECK
            ADD CONSTRAINT FK_auth_TenantDefaultRole_Role FOREIGN KEY (RoleId) REFERENCES auth.Role (RoleId);
    END

WITH CHECK, not WITH NOCHECK, and it succeeds because nothing wrote this table before auth.Role existed either -- the
only writer is auth.uspCreateProfile.  An unvalidated constraint is one the optimizer ignores and the catalog reports as
untrusted, which is worse than none because it looks like one.

THE GUARD REPLACED A SENTENCE, AND THE SENTENCE IS WHY THE CONSTRAINT WAS MISSING FOR TWO PHASES.  This header used to
say "Phase 3 task T-047 adds exactly this", followed by the ALTER, and section 7 reported the constraint ABSENT on every
run.  Phase 3 came and went; T-047 built auth.UserProfileRole and nobody ran the deferred statement, because a statement
that belongs to no script belongs to nobody -- there is no manifest step to execute it and no assertion that fails
without it, only a sentence addressed to a reader and an advisory line in a transcript identical to the run before.
auth.UserSession.ActiveUserProfileId had the same thing happen for the same reason.  Both are BL-049, and the fix is
structural in both places: the ALTER is in the install path, guarded on the condition that unblocks it, so the next
deployment applies it whether or not anybody remembers.  Section 7 now reports VIOLATION rather than PENDING once
auth.Role exists, because a report that cannot fail is not a control.

The alternative was to create this table in Phase 3 with the rest of the authorization tables.  It was rejected
because the table is a TENANT property -- section 11.5 puts it with the tenant, and the tenant is what its natural key
leads with -- and splitting the two tenant-policy tables across two phases to avoid one deferred constraint would put
them in two scripts for ever.
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

IF SCHEMA_ID (N'auth') IS NULL
BEGIN
    DECLARE @MsgSchema NVARCHAR (2000) =
        N'Schema [auth] does not exist. Run database/005_schemas_and_roles.sql first. Nothing has been changed.';

    THROW 50000, @MsgSchema, 1;
END
GO

IF OBJECT_ID (N'auth.Tenant', N'U') IS NULL
BEGIN
    DECLARE @MsgParent NVARCHAR (2000) =
        N'auth.Tenant does not exist. Run database/030_auth_tenant.sql first: both tables in this script take a '
      + N'foreign key to it. Nothing has been changed.';

    THROW 50000, @MsgParent, 1;
END
GO


-- *** 1. auth.TenantAuthenticationPolicy ***
-- SessionLifetimeMinutes and IdleTimeoutMinutes are NOT NULL here and have config.ApplicationSetting fallbacks
-- (Authn.SessionLifetimeMinutes, Authn.IdleTimeoutMinutes) used when NO policy row applies anywhere above the tenant.
-- Nullable columns meaning "inherit this one field from the ancestor" were rejected: per-column inheritance means
-- resolving eight columns from up to eight different rows, and the resolution rule then lives in every caller.  A
-- policy row is inherited WHOLE.
IF OBJECT_ID (N'auth.TenantAuthenticationPolicy', N'U') IS NULL
BEGIN
    CREATE TABLE auth.TenantAuthenticationPolicy
    (
        TenantAuthenticationPolicyId INT            IDENTITY (1, 1) NOT NULL
      , TenantId                     INT                            NOT NULL
      , AllowFederated               BIT                            NOT NULL
            CONSTRAINT DF_auth_TenantAuthenticationPolicy_AllowFederated DEFAULT (0)
      , AllowLocalPassword           BIT                            NOT NULL
            CONSTRAINT DF_auth_TenantAuthenticationPolicy_AllowLocalPassword DEFAULT (1)
      , RequireMfaForLocal           BIT                            NOT NULL
            CONSTRAINT DF_auth_TenantAuthenticationPolicy_RequireMfaForLocal DEFAULT (1)
      , PreferredMethod              VARCHAR (20)                   NOT NULL
            CONSTRAINT DF_auth_TenantAuthenticationPolicy_PreferredMethod DEFAULT ('LocalPassword')
      , SessionLifetimeMinutes       INT                            NOT NULL
            CONSTRAINT DF_auth_TenantAuthenticationPolicy_SessionLifetimeMinutes DEFAULT (480)
      , IdleTimeoutMinutes           INT                            NOT NULL
            CONSTRAINT DF_auth_TenantAuthenticationPolicy_IdleTimeoutMinutes DEFAULT (60)
      , RequireStepUpForPrivileged   BIT                            NOT NULL
            CONSTRAINT DF_auth_TenantAuthenticationPolicy_RequireStepUpForPrivileged DEFAULT (0)
      , PolicyNote                   NVARCHAR (1000)                    NULL
      , IsDeleted                    BIT                            NOT NULL
            CONSTRAINT DF_auth_TenantAuthenticationPolicy_IsDeleted DEFAULT (0)
      , auditDeletedBy               NVARCHAR (255)                     NULL
      , auditDeletedDateUtc          DATETIME2 (3)                      NULL
      , auditCreatedBy               NVARCHAR (255)                 NOT NULL
            CONSTRAINT DF_auth_TenantAuthenticationPolicy_auditCreatedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditCreatedDateUtc          DATETIME2 (3)                  NOT NULL
            CONSTRAINT DF_auth_TenantAuthenticationPolicy_auditCreatedDateUtc DEFAULT (SYSUTCDATETIME ())
      , auditModifiedBy              NVARCHAR (255)                 NOT NULL
            CONSTRAINT DF_auth_TenantAuthenticationPolicy_auditModifiedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditModifiedDateUtc         DATETIME2 (3)                  NOT NULL
            CONSTRAINT DF_auth_TenantAuthenticationPolicy_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ())
      , CONSTRAINT PK_auth_TenantAuthenticationPolicy PRIMARY KEY CLUSTERED (TenantAuthenticationPolicyId)
      , CONSTRAINT FK_auth_TenantAuthenticationPolicy_Tenant
            FOREIGN KEY (TenantId) REFERENCES auth.Tenant (TenantId)
      , CONSTRAINT CK_auth_TenantAuthenticationPolicy_PreferredMethod
            CHECK (PreferredMethod IN ('Federated', 'LocalPassword'))
      -- Row-local, and the reason is in the header: a policy that prefers a method it forbids is an SSO button that
      -- raises E-50104 when pressed.
      , CONSTRAINT CK_auth_TenantAuthenticationPolicy_PreferredIsAllowed
            CHECK ((PreferredMethod = 'Federated'     AND AllowFederated     = 1)
                OR (PreferredMethod = 'LocalPassword' AND AllowLocalPassword = 1))
      , CONSTRAINT CK_auth_TenantAuthenticationPolicy_Lifetimes
            CHECK (SessionLifetimeMinutes BETWEEN 1 AND 43200 AND IdleTimeoutMinutes BETWEEN 1 AND 43200
                   AND IdleTimeoutMinutes <= SessionLifetimeMinutes)
      , CONSTRAINT CK_auth_TenantAuthenticationPolicy_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS     NULL AND auditDeletedDateUtc IS     NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL))
    );
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'UX_auth_TenantAuthenticationPolicy_Tenant'
                  AND object_id = OBJECT_ID (N'auth.TenantAuthenticationPolicy'))
BEGIN
    CREATE UNIQUE INDEX UX_auth_TenantAuthenticationPolicy_Tenant
        ON auth.TenantAuthenticationPolicy (TenantId) WHERE IsDeleted = 0;
END
GO


-- *** 2. auth.TenantDefaultRole ***
-- RoleId's foreign key is NOT in the column list: auth.Role installs four manifest steps after this file, and a CREATE
-- TABLE cannot be conditional in its own column list.  The guarded ALTER at the end of this section adds it as soon as
-- auth.Role is present.  See the header -- it was a sentence addressed to a reader for two phases, which is BL-049.
IF OBJECT_ID (N'auth.TenantDefaultRole', N'U') IS NULL
BEGIN
    CREATE TABLE auth.TenantDefaultRole
    (
        TenantDefaultRoleId  INT            IDENTITY (1, 1) NOT NULL
      , TenantId             INT                            NOT NULL
      , RoleId               INT                            NOT NULL
      , GrantNote            NVARCHAR (1000)                    NULL
      , IsDeleted            BIT                            NOT NULL
            CONSTRAINT DF_auth_TenantDefaultRole_IsDeleted DEFAULT (0)
      , auditDeletedBy       NVARCHAR (255)                     NULL
      , auditDeletedDateUtc  DATETIME2 (3)                      NULL
      , auditCreatedBy       NVARCHAR (255)                 NOT NULL
            CONSTRAINT DF_auth_TenantDefaultRole_auditCreatedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditCreatedDateUtc  DATETIME2 (3)                  NOT NULL
            CONSTRAINT DF_auth_TenantDefaultRole_auditCreatedDateUtc DEFAULT (SYSUTCDATETIME ())
      , auditModifiedBy      NVARCHAR (255)                 NOT NULL
            CONSTRAINT DF_auth_TenantDefaultRole_auditModifiedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditModifiedDateUtc DATETIME2 (3)                  NOT NULL
            CONSTRAINT DF_auth_TenantDefaultRole_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ())
      , CONSTRAINT PK_auth_TenantDefaultRole PRIMARY KEY CLUSTERED (TenantDefaultRoleId)
      , CONSTRAINT FK_auth_TenantDefaultRole_Tenant
            FOREIGN KEY (TenantId) REFERENCES auth.Tenant (TenantId)
      , CONSTRAINT CK_auth_TenantDefaultRole_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS     NULL AND auditDeletedDateUtc IS     NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL))
    );
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'UX_auth_TenantDefaultRole_TenantRole'
                  AND object_id = OBJECT_ID (N'auth.TenantDefaultRole'))
BEGIN
    CREATE UNIQUE INDEX UX_auth_TenantDefaultRole_TenantRole
        ON auth.TenantDefaultRole (TenantId, RoleId) WHERE IsDeleted = 0;
END
GO

-- The deferred foreign key.  auth.Role is created by 055_auth_role.sql at manifest step 13, four steps after this one,
-- so on a first-ever deployment the branch below does nothing and the closing report says PENDING.  On the pass that
-- follows -- and on every pass once Phase 3 is installed -- auth.Role is present and the constraint is added WITH CHECK,
-- so any rows a project has already inserted are validated rather than trusted.  This is idempotent: the NOT EXISTS on
-- sys.foreign_keys means a re-run adds nothing.
IF OBJECT_ID (N'auth.Role', N'U') IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = N'FK_auth_TenantDefaultRole_Role')
BEGIN
    ALTER TABLE auth.TenantDefaultRole WITH CHECK
        ADD CONSTRAINT FK_auth_TenantDefaultRole_Role FOREIGN KEY (RoleId)
            REFERENCES auth.Role (RoleId);

    PRINT N'  FK_auth_TenantDefaultRole_Role added -- auth.Role is present, so the Phase 3 key is now enforced.';
END
GO

IF OBJECT_ID (N'auth.Role', N'U') IS NULL
BEGIN
    PRINT N'  WARNING: FK_auth_TenantDefaultRole_Role NOT added -- auth.Role does not exist yet.  Re-run this file after';
    PRINT N'           055_auth_role.sql, which adds it as soon as auth.Role exists (a single pass is enough).';
END
GO


-- *** 3. auth.TenantTrustedIssuer ***
-- G-21.  The list of identity providers a subtree will accept a federated assertion from.  There is no ProviderName or
-- MetadataUrl or SigningCertificate column: the template does not perform the federation, the application does, and a
-- column the database can neither validate nor use is a column that goes stale without anybody noticing.  What the
-- database can do is answer one question -- "is this issuer permitted for this tenant" -- and that needs (TenantId,
-- Issuer) and nothing else.
IF OBJECT_ID (N'auth.TenantTrustedIssuer', N'U') IS NULL
BEGIN
    CREATE TABLE auth.TenantTrustedIssuer
    (
        TenantTrustedIssuerId INT            IDENTITY (1, 1) NOT NULL
      , TenantId              INT                            NOT NULL
      , Issuer                NVARCHAR (512)                 NOT NULL
      , IssuerNote            NVARCHAR (1000)                    NULL
      , IsDeleted             BIT                            NOT NULL
            CONSTRAINT DF_auth_TenantTrustedIssuer_IsDeleted DEFAULT (0)
      , auditDeletedBy        NVARCHAR (255)                     NULL
      , auditDeletedDateUtc   DATETIME2 (3)                      NULL
      , auditCreatedBy        NVARCHAR (255)                 NOT NULL
            CONSTRAINT DF_auth_TenantTrustedIssuer_auditCreatedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditCreatedDateUtc   DATETIME2 (3)                  NOT NULL
            CONSTRAINT DF_auth_TenantTrustedIssuer_auditCreatedDateUtc DEFAULT (SYSUTCDATETIME ())
      , auditModifiedBy       NVARCHAR (255)                 NOT NULL
            CONSTRAINT DF_auth_TenantTrustedIssuer_auditModifiedBy DEFAULT (ORIGINAL_LOGIN ())
      , auditModifiedDateUtc  DATETIME2 (3)                  NOT NULL
            CONSTRAINT DF_auth_TenantTrustedIssuer_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ())
      , CONSTRAINT PK_auth_TenantTrustedIssuer PRIMARY KEY CLUSTERED (TenantTrustedIssuerId)
      , CONSTRAINT FK_auth_TenantTrustedIssuer_Tenant
            FOREIGN KEY (TenantId) REFERENCES auth.Tenant (TenantId)
      -- The same check auth.UserFederatedIdentity.Issuer carries, for the same reason: the two values are compared as
      -- strings, so one of them arriving with a trailing space is an entry that can never match.
      , CONSTRAINT CK_auth_TenantTrustedIssuer_Issuer
            CHECK (LEN (Issuer) > 0 AND Issuer = LTRIM (RTRIM (Issuer)))
      , CONSTRAINT CK_auth_TenantTrustedIssuer_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS     NULL AND auditDeletedDateUtc IS     NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL))
    );
END
GO

-- (TenantId, Issuer) leading with TenantId, because the question asked of this table is always "what does THIS tenant
-- trust" -- auth.uspBeginSsoLogin probes one ancestor at a time.  Filtered on IsDeleted = 0 so that revoking an issuer
-- and later re-trusting it is two rows rather than a constraint violation.
IF NOT EXISTS (SELECT 1 FROM sys.indexes
                WHERE name = N'UX_auth_TenantTrustedIssuer_TenantIssuer'
                  AND object_id = OBJECT_ID (N'auth.TenantTrustedIssuer'))
BEGIN
    CREATE UNIQUE INDEX UX_auth_TenantTrustedIssuer_TenantIssuer
        ON auth.TenantTrustedIssuer (TenantId, Issuer) WHERE IsDeleted = 0;
END
GO


-- *** 4. Audit triggers ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.trg_au_updt_TenantAuthenticationPolicy
Author:       rsincero
CreateDate:   2026-09-19
Description:
AFTER UPDATE audit stamp for auth.TenantAuthenticationPolicy.  TenantId is immutable: a policy row IS the statement
"this tenant is different", and moving it to another tenant changes the authentication rules of two subtrees in one
UPDATE with one audit stamp.  Soft-delete the row and insert one against the other tenant instead -- E-50010.

Modification History:
2026-09-19  rsincero  Created.  PLAN-AUTH-001 T-031.
***********************************************************************************************************************/
CREATE OR ALTER TRIGGER auth.trg_au_updt_TenantAuthenticationPolicy
    ON auth.TenantAuthenticationPolicy
    AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    IF UPDATE (TenantId)
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.TenantAuthenticationPolicyId = i.TenantAuthenticationPolicyId
                    WHERE i.TenantId <> d.TenantId)
    BEGIN
        ;THROW 50010, N'auth.TenantAuthenticationPolicy.TenantId is immutable. Soft-delete this row and insert a policy against the other tenant: re-pointing it changes two subtrees at once.', 1;
    END;

    DECLARE @Now   DATETIME2 (3)  = SYSUTCDATETIME ()
          , @Actor NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                            , ORIGINAL_LOGIN ());

    UPDATE p
       SET p.auditModifiedDateUtc = @Now
         , p.auditModifiedBy      = CASE WHEN UPDATE (auditModifiedBy)
                                         THEN COALESCE (NULLIF (i.auditModifiedBy, N''), @Actor)
                                         ELSE @Actor END
         , p.auditDeletedBy       = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Actor ELSE p.auditDeletedBy      END
         , p.auditDeletedDateUtc  = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Now   ELSE p.auditDeletedDateUtc END
      FROM auth.TenantAuthenticationPolicy AS p
      JOIN inserted AS i ON i.TenantAuthenticationPolicyId = p.TenantAuthenticationPolicyId
      JOIN deleted  AS d ON d.TenantAuthenticationPolicyId = p.TenantAuthenticationPolicyId;
END;
GO

SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.trg_au_updt_TenantDefaultRole
Author:       rsincero
CreateDate:   2026-09-19
Description:
AFTER UPDATE audit stamp for auth.TenantDefaultRole.  Both TenantId and RoleId are immutable: the row is a pair, and
there is nothing to update on it except IsDeleted.  Changing either half silently rewrites what every profile created
at that tenant since has been given, with one audit stamp covering both meanings -- E-50010.

Modification History:
2026-09-19  rsincero  Created.  PLAN-AUTH-001 T-031.
***********************************************************************************************************************/
CREATE OR ALTER TRIGGER auth.trg_au_updt_TenantDefaultRole
    ON auth.TenantDefaultRole
    AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    IF (UPDATE (TenantId) OR UPDATE (RoleId))
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.TenantDefaultRoleId = i.TenantDefaultRoleId
                    WHERE i.TenantId <> d.TenantId
                       OR i.RoleId   <> d.RoleId)
    BEGIN
        ;THROW 50010, N'auth.TenantDefaultRole is a (TenantId, RoleId) pair and neither half may be changed. Soft-delete the row and insert the pair you want.', 1;
    END;

    DECLARE @Now   DATETIME2 (3)  = SYSUTCDATETIME ()
          , @Actor NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                            , ORIGINAL_LOGIN ());

    UPDATE r
       SET r.auditModifiedDateUtc = @Now
         , r.auditModifiedBy      = CASE WHEN UPDATE (auditModifiedBy)
                                         THEN COALESCE (NULLIF (i.auditModifiedBy, N''), @Actor)
                                         ELSE @Actor END
         , r.auditDeletedBy       = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Actor ELSE r.auditDeletedBy      END
         , r.auditDeletedDateUtc  = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Now   ELSE r.auditDeletedDateUtc END
      FROM auth.TenantDefaultRole AS r
      JOIN inserted AS i ON i.TenantDefaultRoleId = r.TenantDefaultRoleId
      JOIN deleted  AS d ON d.TenantDefaultRoleId = r.TenantDefaultRoleId;
END;
GO

SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.trg_au_updt_TenantTrustedIssuer
Author:       rsincero
CreateDate:   2026-09-21
Description:
AFTER UPDATE audit stamp for auth.TenantTrustedIssuer.  Both TenantId and Issuer are immutable, and for the reason
auth.UserFederatedIdentity gives about the same two words: the row is the sentence "this subtree trusts this provider",
and editing either half retargets the trust rather than amending it, under one audit stamp that says the row was
modified.  An operator re-pointing a trusted issuer is the one change here worth being able to see afterwards.
Soft-delete the row and insert the pair you want -- E-50010.

Modification History:
2026-09-21  rsincero  Created.  Gap G-21.
***********************************************************************************************************************/
CREATE OR ALTER TRIGGER auth.trg_au_updt_TenantTrustedIssuer
    ON auth.TenantTrustedIssuer
    AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    IF (UPDATE (TenantId) OR UPDATE (Issuer))
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.TenantTrustedIssuerId = i.TenantTrustedIssuerId
                    WHERE i.TenantId <> d.TenantId
                       OR i.Issuer   <> d.Issuer)
    BEGIN
        ;THROW 50010, N'auth.TenantTrustedIssuer is a (TenantId, Issuer) pair and neither half may be changed: editing one retargets which provider a subtree trusts, which is a grant of authority rather than a correction. Soft-delete the row and insert the pair you want.', 1;
    END;

    DECLARE @Now   DATETIME2 (3)  = SYSUTCDATETIME ()
          , @Actor NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                            , ORIGINAL_LOGIN ());

    UPDATE ti
       SET ti.auditModifiedDateUtc = @Now
         , ti.auditModifiedBy      = CASE WHEN UPDATE (auditModifiedBy)
                                          THEN COALESCE (NULLIF (i.auditModifiedBy, N''), @Actor)
                                          ELSE @Actor END
         , ti.auditDeletedBy       = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Actor ELSE ti.auditDeletedBy      END
         , ti.auditDeletedDateUtc  = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @Now   ELSE ti.auditDeletedDateUtc END
      FROM auth.TenantTrustedIssuer AS ti
      JOIN inserted AS i ON i.TenantTrustedIssuerId = ti.TenantTrustedIssuerId
      JOIN deleted  AS d ON d.TenantTrustedIssuerId = ti.TenantTrustedIssuerId;
END;
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
      (N'auth', N'TABLE', N'TenantAuthenticationPolicy', NULL, N'Which authentication methods a subtree permits, which it prefers, and its session timings. Section 7.2. At most one live row per tenant, and MOST TENANTS HAVE NONE: policy inherits down the tree and auth.udfResolveAuthPolicy takes the nearest live ancestor. A row here means "this subtree is different".')
    , (N'auth', N'TABLE', N'TenantAuthenticationPolicy', N'TenantId',                   N'The tenant this policy is stated at. Immutable -- re-pointing it changes two subtrees in one UPDATE. Unique where IsDeleted = 0.')
    , (N'auth', N'TABLE', N'TenantAuthenticationPolicy', N'AllowFederated',             N'1 permits Entra SSO for users in this subtree who have an auth.UserFederatedIdentity row. auth.uspBeginSsoLogin raises E-50104 when 0.')
    , (N'auth', N'TABLE', N'TenantAuthenticationPolicy', N'AllowLocalPassword',         N'1 permits local password sign-in in this subtree. auth.uspGetLoginVerifier raises E-50103 when 0.')
    , (N'auth', N'TABLE', N'TenantAuthenticationPolicy', N'RequireMfaForLocal',         N'1 demands a satisfied second factor for ORDINARY local sign-in -- E-50109. It does NOT govern the platform-administrator bypass route, which requires a second factor unconditionally whatever this column says: INV-08, enforced by E-50107 in auth.uspCompleteLogin.')
    , (N'auth', N'TABLE', N'TenantAuthenticationPolicy', N'PreferredMethod',            N'Federated or LocalPassword. Which button the sign-in page leads with. Constrained to a method this row also permits -- CK_auth_TenantAuthenticationPolicy_PreferredIsAllowed.')
    , (N'auth', N'TABLE', N'TenantAuthenticationPolicy', N'SessionLifetimeMinutes',     N'Absolute session lifetime. auth.uspCompleteLogin sets auth.UserSession.ExpiresUtc from it. When no policy applies anywhere above the tenant, config.ApplicationSetting key Authn.SessionLifetimeMinutes is used instead.')
    , (N'auth', N'TABLE', N'TenantAuthenticationPolicy', N'IdleTimeoutMinutes',         N'How long a session may sit idle. Constrained not to exceed SessionLifetimeMinutes, because an idle timeout longer than the lifetime is a column nobody reads. Fallback: Authn.IdleTimeoutMinutes.')
    , (N'auth', N'TABLE', N'TenantAuthenticationPolicy', N'RequireStepUpForPrivileged', N'1 demands a fresh second factor when switching INTO a privileged profile in this subtree. Read by auth.uspSwitchProfile in Phase 3 -- E-50052. Section 12.3.')
    , (N'auth', N'TABLE', N'TenantAuthenticationPolicy', N'PolicyNote',                 N'Why this subtree is different. Read by whoever next wonders why one county does not use SSO.')

    , (N'auth', N'TABLE', N'TenantTrustedIssuer', NULL, N'The identity providers a subtree will accept a federated assertion from. Section 7.3, gap G-21. AllowFederated on auth.TenantAuthenticationPolicy says WHETHER; this says WHICH. Read by auth.uspBeginSsoLogin, which walks auth.TenantClosure upward and takes the list of the NEAREST ancestor holding one -- inherited WHOLE, like a policy row. An EMPTY list anywhere above the tenant means NOT CONFIGURED and the issuer is not checked; once a list resolves, an issuer off it and a call supplying none are both refused with E-50124.')
    , (N'auth', N'TABLE', N'TenantTrustedIssuer', N'TenantId',   N'The tenant the list is stated at. Immutable. Unique with Issuer where IsDeleted = 0. Every tenant below it inherits this list unless a nearer ancestor states one of its own.')
    , (N'auth', N'TABLE', N'TenantTrustedIssuer', N'Issuer',     N'The issuer value as it appears in the token, compared as a string. NVARCHAR (512) to match auth.UserFederatedIdentity.Issuer exactly -- the value permitted here and the value joined on at the callback must be the same string, so a shorter column would truncate a long directory URL into an entry that never matches. Immutable; no leading or trailing space -- CK_auth_TenantTrustedIssuer_Issuer.')
    , (N'auth', N'TABLE', N'TenantTrustedIssuer', N'IssuerNote', N'Which directory this is, in the words of whoever added it. The issuer URL of an Entra directory is a GUID; six months later nobody can tell which customer it belongs to.')

    , (N'auth', N'TABLE', N'TenantDefaultRole', NULL, N'Roles granted automatically when a profile is created at this tenant. Section 11.5. Read by auth.uspCreateProfile in 140_auth_profile_procedures.sql; nothing written so far writes it.')
    , (N'auth', N'TABLE', N'TenantDefaultRole', N'TenantId',  N'The tenant whose new profiles get this role. Immutable; unique with RoleId where IsDeleted = 0.')
    , (N'auth', N'TABLE', N'TenantDefaultRole', N'RoleId',    N'The role granted. Its foreign key FK_auth_TenantDefaultRole_Role is NOT in the CREATE TABLE: auth.Role arrives at manifest step 13 and this table is built at step 9, so a guarded ALTER at the end of section 2 adds it WITH CHECK as soon as auth.Role exists. The closing report of 035_auth_tenant_policy.sql reports OK, PENDING (only while auth.Role is absent) or VIOLATION. BL-049.')
    , (N'auth', N'TABLE', N'TenantDefaultRole', N'GrantNote', N'Why this role is a default here. An unexplained automatic grant is the hardest kind of authority to review.');

    -- The seven audit columns carry the same description on every table, so they are generated rather than typed out.
    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    SELECT N'auth', N'TABLE', t.TableName, c.ColumnName, c.Description
      FROM (VALUES (N'TenantAuthenticationPolicy'), (N'TenantTrustedIssuer'), (N'TenantDefaultRole')) AS t (TableName)
     CROSS JOIN (VALUES
          (N'IsDeleted',            N'Soft-delete flag. 1 means the row is gone as far as the application is concerned; nothing in this database hard-deletes.')
        , (N'auditDeletedBy',       N'Who soft-deleted the row. NULL unless IsDeleted = 1 -- the pair is enforced by CK_<table>_DeletedPair.')
        , (N'auditDeletedDateUtc',  N'When the row was soft-deleted, UTC. NULL unless IsDeleted = 1.')
        , (N'auditCreatedBy',       N'Who inserted the row. Defaults to ORIGINAL_LOGIN (); a procedure sets it to the acting profile instead.')
        , (N'auditCreatedDateUtc',  N'When the row was inserted, UTC.')
        , (N'auditModifiedBy',      N'Who last updated the row, set by the AFTER UPDATE trigger from SESSION_CONTEXT (''AppUser'') or ORIGINAL_LOGIN ().')
        , (N'auditModifiedDateUtc', N'When the row was last updated, UTC, set by the AFTER UPDATE trigger.')
       ) AS c (ColumnName, Description);

    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    VALUES
      (N'auth', N'TRIGGER', N'trg_au_updt_TenantAuthenticationPolicy', NULL, N'AFTER UPDATE audit stamp, and the guard that makes TenantId immutable -- E-50010.')
    , (N'auth', N'TRIGGER', N'trg_au_updt_TenantTrustedIssuer',        NULL, N'AFTER UPDATE audit stamp, and the guard that makes both halves of the (TenantId, Issuer) pair immutable: editing either retargets which provider a subtree trusts -- E-50010.')
    , (N'auth', N'TRIGGER', N'trg_au_updt_TenantDefaultRole',          NULL, N'AFTER UPDATE audit stamp, and the guard that makes both halves of the (TenantId, RoleId) pair immutable -- E-50010.');

    -- Assertion 11: the key and audit columns the list above left undescribed, found by 950_verify_deployment.sql,
    -- which fails a column without an MS_Description.
    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    VALUES
      (N'auth', N'TABLE', N'TenantAuthenticationPolicy', N'TenantAuthenticationPolicyId', N'Surrogate key.')
    , (N'auth', N'TABLE', N'TenantTrustedIssuer', N'TenantTrustedIssuerId', N'Surrogate key.')
    , (N'auth', N'TABLE', N'TenantDefaultRole', N'TenantDefaultRoleId', N'Surrogate key.');

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


-- *** 6. Grants ***
--
-- DELIBERATELY EMPTY.  INV-11: applicationRole holds NO table-level permission on SCHEMA::auth, and reaches all three of
-- these tables only through ownership chaining inside auth.uspGetLoginVerifier, auth.uspBeginSsoLogin,
-- auth.uspSetTenantAuthenticationPolicy, auth.uspSetTenantDefaultRoles and auth.uspCreateProfile.  170_permissions.sql
-- and each procedure's own script grant EXECUTE on those procedures and nothing here.
GO


-- *** 7. Closing report ***
DECLARE @Report TABLE
(
    RowNo    INT IDENTITY (1, 1) PRIMARY KEY,
    Severity INT             NOT NULL,
    Status   VARCHAR (10)    NOT NULL,
    Item     NVARCHAR (200)  NOT NULL,
    Detail   NVARCHAR (1000)     NULL
);

DECLARE @TrustedIssuers      INT = 0
      , @TrustedIssuerTenants INT = 0
      , @FederatingPolicies   INT = 0;

IF OBJECT_ID (N'auth.TenantTrustedIssuer', N'U') IS NOT NULL
BEGIN
    SELECT @TrustedIssuers       = COUNT (*)
         , @TrustedIssuerTenants = COUNT (DISTINCT TenantId)
      FROM auth.TenantTrustedIssuer
     WHERE IsDeleted = 0;
END;

SELECT @FederatingPolicies = COUNT (*)
  FROM auth.TenantAuthenticationPolicy
 WHERE AllowFederated = 1
   AND IsDeleted      = 0;

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (x.QualifiedName, N'U') IS NULL THEN 1 ELSE 4 END
     , CASE WHEN OBJECT_ID (x.QualifiedName, N'U') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Table ' + x.QualifiedName
     , x.Purpose
  FROM (VALUES (N'auth.TenantAuthenticationPolicy', N'Per-subtree authentication policy. Section 7.2.')
             , (N'auth.TenantTrustedIssuer',        N'Which identity providers a subtree trusts. Section 7.3, gap G-21.')
             , (N'auth.TenantDefaultRole',          N'Roles granted automatically on profile creation. Section 11.5.'))
       AS x (QualifiedName, Purpose);

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN i.name IS NULL THEN 2 ELSE 4 END
     , CASE WHEN i.name IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Unique index ' + x.IndexName
     , x.Purpose
  FROM (VALUES (N'UX_auth_TenantAuthenticationPolicy_Tenant', N'auth.TenantAuthenticationPolicy'
              , N'At most one live policy per tenant. Filtered WHERE IsDeleted = 0, so a retired policy does not block a new one.')
             , (N'UX_auth_TenantTrustedIssuer_TenantIssuer',   N'auth.TenantTrustedIssuer'
              , N'One live row per (TenantId, Issuer). Filtered WHERE IsDeleted = 0, so revoking an issuer and later re-trusting it is two rows.')
             , (N'UX_auth_TenantDefaultRole_TenantRole',       N'auth.TenantDefaultRole'
              , N'One live row per (TenantId, RoleId). Filtered WHERE IsDeleted = 0.'))
       AS x (IndexName, QualifiedName, Purpose)
  LEFT JOIN sys.indexes AS i
         ON i.name = x.IndexName AND i.object_id = OBJECT_ID (x.QualifiedName);

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (x.QualifiedName, N'TR') IS NULL THEN 2 ELSE 4 END
     , CASE WHEN OBJECT_ID (x.QualifiedName, N'TR') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Trigger ' + x.QualifiedName
     , N'AFTER UPDATE audit stamp, and the immutability guard described in its header.'
  FROM (VALUES (N'auth.trg_au_updt_TenantAuthenticationPolicy')
             , (N'auth.trg_au_updt_TenantTrustedIssuer')
             , (N'auth.trg_au_updt_TenantDefaultRole')) AS x (QualifiedName);

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN fk.name IS NULL THEN 2 ELSE 4 END
     , CASE WHEN fk.name IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Foreign key ' + x.ConstraintName
     , x.Purpose
  FROM (VALUES (N'FK_auth_TenantAuthenticationPolicy_Tenant', N'A policy without a tenant is a policy nobody inherits.')
             , (N'FK_auth_TenantTrustedIssuer_Tenant',        N'A trusted issuer without a tenant is trusted by nobody -- and would be invisible to the upward walk.')
             , (N'FK_auth_TenantDefaultRole_Tenant',          N'A default role without a tenant is granted to nobody.'))
       AS x (ConstraintName, Purpose)
  LEFT JOIN sys.foreign_keys AS fk ON fk.name = x.ConstraintName;

-- Three states, not two.  PENDING is only legitimate while auth.Role is absent; once it exists, a missing key is a
-- VIOLATION, because the guarded ALTER at the end of section 2 should have added it on this very run.  The old version of
-- this row read the key's absence as a phase boundary unconditionally, so it reported PENDING on a Phase 4 database and
-- nobody acted -- BL-049.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = N'FK_auth_TenantDefaultRole_Role') THEN 4
            WHEN OBJECT_ID (N'auth.Role', N'U') IS NULL                                                 THEN 3
            ELSE 1 END
     , CASE WHEN EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = N'FK_auth_TenantDefaultRole_Role') THEN 'OK'
            WHEN OBJECT_ID (N'auth.Role', N'U') IS NULL                                                 THEN 'PENDING'
            ELSE 'VIOLATION' END
     , N'Foreign key FK_auth_TenantDefaultRole_Role'
     , CASE WHEN EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = N'FK_auth_TenantDefaultRole_Role')
            THEN N'Present and trusted. auth.Role exists and RoleId is constrained.'
            WHEN OBJECT_ID (N'auth.Role', N'U') IS NULL
            THEN N'NOT CREATED, and not expected yet: auth.Role is built by 055_auth_role.sql at manifest step 13 and '
               + N'this file runs at step 9. Until then RoleId is unconstrained, but nothing reads this table either. '
               + N'Section 2 adds the key -- WITH CHECK, deliberately -- as soon as the parent exists.'
            ELSE N'MISSING ON A DATABASE THAT HAS auth.Role. RoleId is unconstrained, so a default-role row can name a '
               + N'role that does not exist, and auth.uspCreateProfile would grant a dangling RoleId to every new '
               + N'profile at that tenant. Section 2 of this file adds the key; if this row is showing, that ALTER did '
               + N'not apply and the transcript above says why.'
       END;

INSERT @Report (Severity, Status, Item, Detail)
SELECT 3, 'INFO', N'Policy rows'
     , CASE WHEN COUNT (*) = 0
            THEN N'None. Expected on a fresh deployment: this script seeds nothing, because a policy row is a '
               + N'statement about a particular deployment. Until one exists, auth.udfResolveAuthPolicy returns NULL '
               + N'and the sign-in procedures fall back to config.ApplicationSetting.'
            ELSE CAST (COUNT (*) AS NVARCHAR (10)) + N' live policy row(s). auth.udfResolveAuthPolicy resolves the '
               + N'rest of the tree from them.'
       END
  FROM auth.TenantAuthenticationPolicy
 WHERE IsDeleted = 0;

-- G-21's report, and the reason the control can be opt-in without being silent.  Three states: no federation permitted
-- anywhere (nothing to constrain), federation permitted with a list (constrained), federation permitted with NO list --
-- which is the state G-21 describes, so it is severity 2 and says PROBLEMS found.  Adding one row is a one-time act by
-- somebody who already knows their directory's issuer URL, unlike scheduling a job, so a report that keeps asking until
-- it is done is proportionate.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN @TrustedIssuers > 0 THEN 4 WHEN @FederatingPolicies = 0 THEN 3 ELSE 2 END
     , CASE WHEN @TrustedIssuers > 0 THEN 'OK' WHEN @FederatingPolicies = 0 THEN 'INFO' ELSE 'ACTION' END
     , N'Trusted issuers (G-21)'
     , CASE WHEN @TrustedIssuers > 0
            THEN CAST (@TrustedIssuers AS NVARCHAR (10)) + N' live trusted-issuer row(s) across '
               + CAST (@TrustedIssuerTenants AS NVARCHAR (10)) + N' tenant(s). auth.uspBeginSsoLogin refuses an issuer '
               + N'that is not on the nearest ancestor''s list, and refuses a call that names none -- E-50124.'
            WHEN @FederatingPolicies = 0
            THEN N'None, and none needed yet: no live policy row sets AllowFederated = 1, so no tenant permits '
               + N'federated sign-in and there is no issuer to constrain. Add rows here at the same time as the policy '
               + N'row that turns federation on.'
            ELSE N'NONE, on a deployment where ' + CAST (@FederatingPolicies AS NVARCHAR (10)) + N' policy row(s) set '
               + N'AllowFederated = 1. Federated sign-in is permitted and UNCONSTRAINED: auth.uspBeginSsoLogin will '
               + N'open an exchange whatever issuer the application later attributes the assertion to, because the '
               + N'database has no list to check it against. Insert one row per directory you actually federate with '
               + N'-- Issuer exactly as it appears in the token, matching auth.UserFederatedIdentity.Issuer -- and the '
               + N'check switches itself on. Gap G-21, section 7.3.'
       END;

INSERT @Report (Severity, Status, Item, Detail)
VALUES (3, 'NEXT', N'Next scripts'
      , N'040_auth_userprofile.sql (auth.User), then 045_auth_identity.sql, 070_auth_session.sql, '
      + N'085_logs_auth_tables.sql, 100_auth_functions.sql and 110_auth_authn_procedures.sql.');

IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
    PRINT N'Tenant authentication policy: PROBLEMS found. Read the report below before running the next script.';
ELSE
    PRINT N'Tenant authentication policy: no problems found.';

PRINT N'';

SELECT Severity, Status, Item, Detail
  FROM @Report
 ORDER BY Severity, RowNo;
GO
