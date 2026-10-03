/***********************************************************************************************************************
Script:         080_auth_registration.sql
Purpose:        auth.OrganizationRegistration -- the Variant 3 self-service onboarding queue.  An external organization
                asks for a tenant; an agency user holding Tenant.Create decides.  And auth.RegistrationAttempt, the
                per-address arrival log the queue's throttle counts (G-24).
Target:         SQL Server 2022.
Run as:         db_owner in the target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/080_auth_registration.sql
Idempotent:     Yes.  Guarded CREATEs, CREATE OR ALTER on the trigger, descriptions through util.uspSetObjectDescription.
Depends on:     database/030_auth_tenant.sql (auth.Application, auth.Tenant), database/040_auth_userprofile.sql
                (auth.UserProfile), templates/extended-properties.sql.
Implements:     T-086.  DES-AUTH-001 sections 15.4, 16.4, 17.3.  Gap G-24 -- auth.RegistrationAttempt and the
                E-50068 throttle it feeds.
                See docs/10-database-authn-authz-design.md.
To retarget:    Pass it per run:  sqlcmd -d <database> -v DbName=<database>.  There is no in-file default.

THIS TABLE IS WRITTEN BY AN UNAUTHENTICATED CALLER, AND IT IS THE ONLY ONE IN THE DESIGN THAT IS
-----------------------------------------------------------------------------------------------
auth.uspRegisterOrganization takes no session token: section 16.4 step 1 is a public-facing form.  Everything about the
shape of this table follows from that one fact.

  *  NO TENANT IS CREATED BY A REGISTRATION.  TenantId is NULL until an agency user approves, and the CHECK constraint
     below ties it to Status rather than leaving it to the procedure.  Section 16.4: "Self-service tenant creation in a
     public-facing application is how an attacker gets a tenant of their own and an approved-looking identity."
  *  NOTHING HERE IS A CREDENTIAL.  The registration carries a contact email and an organization name, and no verifier,
     no token and no secret.  The external USER's credential arrives later, through auth.uspRegisterExternalUser.
  *  THE CONCLUSION IS WRITE-ONCE.  The trigger refuses any Status change out of Approved or Rejected (E-50010), which
     is the structural backstop behind auth.uspApproveOrganization's E-50060 "already processed".  One is a friendly
     error for a double-clicked button; the other holds for somebody with SSMS.
  *  ClientAddress IS RECORDED.  It is the only attribution an anonymous submission has, and a burst of registrations
     from one address is the thing an operator wants to see.  It is not, by itself, a rate limit: the count that
     refuses a burst is taken over auth.RegistrationAttempt in section 2 and NOT over this table, for the reason that
     section explains.  This column remains what it always was -- the address on the record of what was asked for.

WHY THE TENANT FOREIGN KEY IS COMPOSITE
---------------------------------------
FK_auth_OrganizationRegistration_auth_Tenant is on (TenantId, ApplicationId) against UX_auth_Tenant_Id_Application, so an
approval cannot point a registration at a tenant in a different application.  D-09, and the same reasoning as
auth.RolePermission (BL-040) and auth.UiElementPermission.

WHY "PENDING" UNIQUENESS IS ON THE PROPOSED CODE AND NOT ON THE EMAIL
--------------------------------------------------------------------
UX_auth_OrganizationRegistration_Pending is filtered on  IsDeleted = 0 AND Status = N'Pending'.  Two organizations may
share an agent, and one organization may correct its contact address mid-review, so the email is not a key.  The proposed
tenant code is: two live requests for the same code cannot both be approved, and refusing the second at submission time
is kinder than refusing it at approval time when somebody has already been told to expect it.  A rejected or approved
registration falls out of the filter, so the same code may be requested again after a rejection.
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

IF OBJECT_ID (N'auth.Application', N'U') IS NULL OR OBJECT_ID (N'auth.Tenant', N'U') IS NULL
BEGIN
    DECLARE @MsgTen NVARCHAR (2000) =
        N'auth.Application or auth.Tenant is missing. Run database/030_auth_tenant.sql first.';

    THROW 50000, @MsgTen, 1;
END
GO

IF OBJECT_ID (N'auth.UserProfile', N'U') IS NULL
BEGIN
    DECLARE @MsgProf NVARCHAR (2000) =
        N'auth.UserProfile is missing. Run database/040_auth_userprofile.sql first: ReviewedByProfileId records WHICH '
      + N'agency profile approved a registration, and a nullable foreign key to a table that does not exist is not '
      + N'something to defer.';

    THROW 50000, @MsgProf, 1;
END
GO


-- *** 1. auth.OrganizationRegistration ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

IF OBJECT_ID (N'auth.OrganizationRegistration', N'U') IS NULL
BEGIN
    CREATE TABLE auth.OrganizationRegistration
    (
        OrganizationRegistrationId INT            IDENTITY (1, 1) NOT NULL,

        -- D-09.  Which application this organization is asking to join.
        ApplicationId              INT            NOT NULL,

        -- The tenant code the organization is asking for.  Matches auth.Tenant.TenantCode's width exactly, because
        -- auth.uspApproveOrganization passes it straight through to auth.uspCreateTenant -- a narrower column here
        -- would refuse codes the tenant table accepts, and a wider one would truncate at approval.
        ProposedTenantCode         NVARCHAR (50)  NOT NULL,
        OrganizationName           NVARCHAR (200) NOT NULL,

        -- Matches auth.User.Email's width, for the same pass-through reason.
        ContactEmail               NVARCHAR (320) NOT NULL,
        ContactName                NVARCHAR (256)     NULL,

        -- The only attribution an anonymous submission has.  Same width as auth.LoginAttempt.ClientAddress.
        ClientAddress              NVARCHAR (45)      NULL,

        -- Pending | Approved | Rejected.  A closed set, and the conclusion is write-once -- see the trigger.
        Status                     NVARCHAR (20)  NOT NULL,

        SubmittedUtc               DATETIME2 (3)  NOT NULL,

        -- The three conclusion columns.  All NULL while Pending, and tied to Status by
        -- CK_auth_OrganizationRegistration_Concluded rather than left to the procedure -- a registration that says
        -- Approved and names no tenant is the shape of a bug that only shows up when somebody tries to sign in.
        ReviewedUtc                DATETIME2 (3)      NULL,
        ReviewedByProfileId        INT                NULL,
        ReviewNote                 NVARCHAR (2000)    NULL,

        -- The tenant this registration became.  NULL until approval.  COMPOSITE foreign key -- see the file header.
        TenantId                   INT                NULL,

        -- ---------------------------------------------------------------------------------
        -- Standard audit columns.  auditDeleted* are nullable and without defaults, paired to the flag by
        -- CK_auth_OrganizationRegistration_DeletedPair; an undelete must clear them in the same statement, because a
        -- CHECK is evaluated before the AFTER trigger.
        -- ---------------------------------------------------------------------------------
        IsDeleted            BIT             NOT NULL CONSTRAINT DF_auth_OrganizationRegistration_IsDeleted            DEFAULT (0),
        auditDeletedBy       NVARCHAR (255)      NULL,
        auditDeletedDateUtc  DATETIME2 (3)       NULL,
        auditCreatedBy       NVARCHAR (255)  NOT NULL CONSTRAINT DF_auth_OrganizationRegistration_auditCreatedBy       DEFAULT (ORIGINAL_LOGIN ()),
        auditCreatedDateUtc  DATETIME2 (3)   NOT NULL CONSTRAINT DF_auth_OrganizationRegistration_auditCreatedDateUtc  DEFAULT (SYSUTCDATETIME ()),
        auditModifiedBy      NVARCHAR (255)  NOT NULL CONSTRAINT DF_auth_OrganizationRegistration_auditModifiedBy      DEFAULT (ORIGINAL_LOGIN ()),
        auditModifiedDateUtc DATETIME2 (3)   NOT NULL CONSTRAINT DF_auth_OrganizationRegistration_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ()),

        CONSTRAINT PK_auth_OrganizationRegistration PRIMARY KEY CLUSTERED (OrganizationRegistrationId),

        CONSTRAINT CK_auth_OrganizationRegistration_Status
            CHECK (Status IN (N'Pending', N'Approved', N'Rejected')),

        -- Status and the conclusion columns are one fact expressed in four places, so they are constrained together.
        CONSTRAINT CK_auth_OrganizationRegistration_Concluded
            CHECK ((Status = N'Pending'
                    AND ReviewedUtc IS NULL AND ReviewedByProfileId IS NULL AND TenantId IS NULL)
                OR (Status = N'Approved'
                    AND ReviewedUtc IS NOT NULL AND ReviewedByProfileId IS NOT NULL AND TenantId IS NOT NULL)
                OR (Status = N'Rejected'
                    AND ReviewedUtc IS NOT NULL AND ReviewedByProfileId IS NOT NULL AND TenantId IS NULL)),

        -- Public-facing input, so the shape of it is checked here as well as in the procedure.  E-50062 is the
        -- friendly error; this is what holds when somebody writes the row by hand.
        CONSTRAINT CK_auth_OrganizationRegistration_Named
            CHECK (LEN (LTRIM (RTRIM (OrganizationName)))   > 0
               AND LEN (LTRIM (RTRIM (ProposedTenantCode))) > 0
               AND LEN (LTRIM (RTRIM (ContactEmail)))       > 0),

        CONSTRAINT CK_auth_OrganizationRegistration_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS NULL     AND auditDeletedDateUtc IS NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL)),

        CONSTRAINT FK_auth_OrganizationRegistration_auth_Application
            FOREIGN KEY (ApplicationId) REFERENCES auth.Application (ApplicationId),

        CONSTRAINT FK_auth_OrganizationRegistration_auth_Tenant
            FOREIGN KEY (TenantId, ApplicationId)
            REFERENCES auth.Tenant (TenantId, ApplicationId),

        CONSTRAINT FK_auth_OrganizationRegistration_auth_UserProfile
            FOREIGN KEY (ReviewedByProfileId) REFERENCES auth.UserProfile (UserProfileId)
    );
END;
GO

IF NOT EXISTS (SELECT 1
                 FROM sys.default_constraints
                WHERE name = N'DF_auth_OrganizationRegistration_Status')
BEGIN
    ALTER TABLE auth.OrganizationRegistration
        ADD CONSTRAINT DF_auth_OrganizationRegistration_Status DEFAULT (N'Pending') FOR Status;
END;
GO

IF NOT EXISTS (SELECT 1
                 FROM sys.default_constraints
                WHERE name = N'DF_auth_OrganizationRegistration_SubmittedUtc')
BEGIN
    ALTER TABLE auth.OrganizationRegistration
        ADD CONSTRAINT DF_auth_OrganizationRegistration_SubmittedUtc DEFAULT (SYSUTCDATETIME ()) FOR SubmittedUtc;
END;
GO

-- At most one PENDING request per proposed code per application.  See the file header for why the filter names Status
-- as well as IsDeleted, and why the email is not part of the key.
IF NOT EXISTS (SELECT 1
                 FROM sys.indexes
                WHERE name      = N'UX_auth_OrganizationRegistration_Pending'
                  AND object_id = OBJECT_ID (N'auth.OrganizationRegistration'))
BEGIN
    CREATE UNIQUE INDEX UX_auth_OrganizationRegistration_Pending
        ON auth.OrganizationRegistration (ApplicationId, ProposedTenantCode)
        WHERE IsDeleted = 0 AND Status = N'Pending';
END;
GO

-- The review queue: "what is waiting for me, oldest first".  The one read an agency user actually performs.
IF NOT EXISTS (SELECT 1
                 FROM sys.indexes
                WHERE name      = N'IX_auth_OrganizationRegistration_Queue'
                  AND object_id = OBJECT_ID (N'auth.OrganizationRegistration'))
BEGIN
    CREATE INDEX IX_auth_OrganizationRegistration_Queue
        ON auth.OrganizationRegistration (ApplicationId, Status, SubmittedUtc)
        INCLUDE (ProposedTenantCode, OrganizationName, ContactEmail, TenantId)
        WHERE IsDeleted = 0;
END;
GO


-- *** 2. auth.RegistrationAttempt ***
--
-- G-24.  ONE ROW PER CALL OF A PUBLIC REGISTRATION ENTRY POINT, WHATEVER THE CALL'S OUTCOME.
--
-- WHY THIS IS A SECOND TABLE AND NOT A COUNT OVER THE FIRST ONE.  The obvious throttle is  SELECT COUNT (*) FROM
-- auth.OrganizationRegistration WHERE ClientAddress = @Addr AND SubmittedUtc >= ...  and it does not work, because a
-- REFUSED submission writes no registration row at all: E-50062 (a blank or unrecognised argument) and E-50063 (the
-- proposed code is already queued) are both raised before the INSERT.  So that count sees only the submissions
-- well-formed enough to reach the queue, and an attacker who varies the payload until it fails validation is invisible
-- to it while still costing the same work.  A control that can be avoided by being wrong on purpose is not a control.
--
-- THE COUNT IS ON ARRIVALS AND IGNORES THE OUTCOME, WHICH IS THE OPPOSITE OF THE SIGN-IN THROTTLE.  Section 7.4 counts
-- FAILED sign-ins, because a successful sign-in is proof that the caller is who they say they are and there is no reason
-- to hold it against them.  Registration has no such proof: anybody can fill a form in correctly, and a thousand
-- perfectly valid registrations from one address is the flood, not the good case.  So IX_auth_RegistrationAttempt_Address
-- is deliberately NOT filtered on Outcome, and a successful submission counts against the next one from the same place.
--
-- THE ROW IS WRITTEN BEFORE THE CALL IS VALIDATED, AND THAT IS THE WHOLE POINT.  auth.uspRecordRegistrationAttempt is
-- called first, outside any transaction, with Outcome 'Received'; the caller updates it to 'Accepted', 'Refused' or
-- 'Throttled' when it knows.  A row that is never updated stays 'Received' and STILL COUNTS, so an input that trips an
-- error nobody anticipated -- a constraint violation, a deadlock, anything at all -- does not buy a free call.
--
-- WHAT IT DOES NOT HOLD.  No credential, no verifier, no password and no token: the public forms this records do not
-- carry one (a registration has none, and an enrolment writes none).  ApplicationCode and ProposedTenantCode are
-- recorded as the strings that were SUPPLIED, not as resolved ids, for the same reason auth.LoginAttempt records
-- UserName as a string -- the attempts worth investigating are the ones that named nothing that exists.
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

IF OBJECT_ID (N'auth.RegistrationAttempt', N'U') IS NULL
BEGIN
    CREATE TABLE auth.RegistrationAttempt
    (
        RegistrationAttemptId      BIGINT         IDENTITY (1, 1) NOT NULL,

        -- WHICH public form.  Both of section 16.4's unauthenticated entry points land here and both are throttled on
        -- the SAME per-address count: a throttle on one door beside an untouched one is a throttle nobody pays.
        -- 'Organization' is step 1, 'ExternalUser' is step 3.
        AttemptKind                VARCHAR (20)   NOT NULL,

        -- NULLABLE, and for the reason auth.LoginAttempt.UserId is: an attempt that named an application code matching
        -- nothing live has no ApplicationId, and those are exactly the attempts an operator wants to see.
        ApplicationId              INT                NULL,
        ApplicationCode            NVARCHAR (50)      NULL,
        ProposedTenantCode         NVARCHAR (50)      NULL,

        -- The reason this table exists.  NOT NULL, which is what makes the throttle unbypassable -- see
        -- auth.uspRegisterOrganization's header on why @ClientAddress stopped being optional.  Same width as
        -- auth.LoginAttempt.ClientAddress and auth.OrganizationRegistration.ClientAddress: the longest textual IPv6
        -- address including an IPv4-mapped tail.
        ClientAddress              NVARCHAR (45)  NOT NULL,
        UserAgent                  NVARCHAR (512)     NULL,

        -- Received | Accepted | Refused | Throttled.  'Received' is written first and means "the outcome is not known
        -- yet"; every one of the four counts toward the throttle.
        Outcome                    VARCHAR (20)   NOT NULL,

        -- A short token, never shown to the caller -- section 14.5, UI-26.  Present exactly on the two refusing
        -- outcomes, by CK_auth_RegistrationAttempt_FailureReason.
        FailureReason              VARCHAR (40)       NULL,

        -- For an 'Organization' attempt: the registration this call created.  For an 'ExternalUser' attempt: the
        -- approved registration it enrolled into, which is known before the call is validated.  Either way an accepted
        -- attempt names one -- CK_auth_RegistrationAttempt_Registration.
        OrganizationRegistrationId INT                NULL,

        AttemptedUtc               DATETIME2 (3)  NOT NULL,
        ConcludedUtc               DATETIME2 (3)      NULL,

        -- ---------------------------------------------------------------------------------
        -- Standard audit columns.  auditDeleted* are nullable and without defaults, paired to the flag by
        -- CK_auth_RegistrationAttempt_DeletedPair.
        -- ---------------------------------------------------------------------------------
        IsDeleted            BIT             NOT NULL CONSTRAINT DF_auth_RegistrationAttempt_IsDeleted            DEFAULT (0),
        auditDeletedBy       NVARCHAR (255)      NULL,
        auditDeletedDateUtc  DATETIME2 (3)       NULL,
        auditCreatedBy       NVARCHAR (255)  NOT NULL CONSTRAINT DF_auth_RegistrationAttempt_auditCreatedBy       DEFAULT (ORIGINAL_LOGIN ()),
        auditCreatedDateUtc  DATETIME2 (3)   NOT NULL CONSTRAINT DF_auth_RegistrationAttempt_auditCreatedDateUtc  DEFAULT (SYSUTCDATETIME ()),
        auditModifiedBy      NVARCHAR (255)  NOT NULL CONSTRAINT DF_auth_RegistrationAttempt_auditModifiedBy      DEFAULT (ORIGINAL_LOGIN ()),
        auditModifiedDateUtc DATETIME2 (3)   NOT NULL CONSTRAINT DF_auth_RegistrationAttempt_auditModifiedDateUtc DEFAULT (SYSUTCDATETIME ()),

        CONSTRAINT PK_auth_RegistrationAttempt PRIMARY KEY CLUSTERED (RegistrationAttemptId),

        CONSTRAINT CK_auth_RegistrationAttempt_AttemptKind
            CHECK (AttemptKind IN ('Organization', 'ExternalUser')),

        -- Trimmed and non-empty, because the throttle groups on this string and '203.0.113.9 ' would be a second
        -- address with its own allowance.  The procedure trims before it records; this is what holds regardless.
        CONSTRAINT CK_auth_RegistrationAttempt_ClientAddress
            CHECK (LEN (ClientAddress) > 0 AND ClientAddress = LTRIM (RTRIM (ClientAddress))),

        CONSTRAINT CK_auth_RegistrationAttempt_Outcome
            CHECK (Outcome IN ('Received', 'Accepted', 'Refused', 'Throttled')),

        -- Concluded exactly when the outcome is known.  A 'Received' row with a conclusion time, or a finished row
        -- without one, is a row nobody can age or explain.
        CONSTRAINT CK_auth_RegistrationAttempt_ConcludedPair
            CHECK ((Outcome = 'Received' AND ConcludedUtc IS NULL)
                OR (Outcome <> 'Received' AND ConcludedUtc IS NOT NULL AND ConcludedUtc >= AttemptedUtc)),

        -- A reason on an accepted attempt is a contradiction; a refusal with no reason is a row nobody can act on.
        CONSTRAINT CK_auth_RegistrationAttempt_FailureReason
            CHECK ((Outcome IN ('Refused', 'Throttled')
                    AND FailureReason IS NOT NULL AND LEN (FailureReason) > 0)
                OR (Outcome IN ('Received', 'Accepted') AND FailureReason IS NULL)),

        -- An accepted attempt produced or used a registration, and naming it is what turns this table from a counter
        -- into evidence: it is how "which address enrolled these nine users" is answerable at all.
        CONSTRAINT CK_auth_RegistrationAttempt_Registration
            CHECK (Outcome <> 'Accepted' OR OrganizationRegistrationId IS NOT NULL),

        CONSTRAINT CK_auth_RegistrationAttempt_DeletedPair
            CHECK ((IsDeleted = 0 AND auditDeletedBy IS NULL     AND auditDeletedDateUtc IS NULL)
                OR (IsDeleted = 1 AND auditDeletedBy IS NOT NULL AND auditDeletedDateUtc IS NOT NULL)),

        CONSTRAINT FK_auth_RegistrationAttempt_auth_Application
            FOREIGN KEY (ApplicationId) REFERENCES auth.Application (ApplicationId),

        CONSTRAINT FK_auth_RegistrationAttempt_auth_OrganizationRegistration
            FOREIGN KEY (OrganizationRegistrationId)
            REFERENCES auth.OrganizationRegistration (OrganizationRegistrationId)
    );
END;
GO

IF NOT EXISTS (SELECT 1
                 FROM sys.default_constraints
                WHERE name = N'DF_auth_RegistrationAttempt_AttemptedUtc')
BEGIN
    ALTER TABLE auth.RegistrationAttempt
        ADD CONSTRAINT DF_auth_RegistrationAttempt_AttemptedUtc DEFAULT (SYSUTCDATETIME ()) FOR AttemptedUtc;
END;
GO

IF NOT EXISTS (SELECT 1
                 FROM sys.default_constraints
                WHERE name = N'DF_auth_RegistrationAttempt_Outcome')
BEGIN
    ALTER TABLE auth.RegistrationAttempt
        ADD CONSTRAINT DF_auth_RegistrationAttempt_Outcome DEFAULT ('Received') FOR Outcome;
END;
GO

-- THE THROTTLE'S ONE INDEX.  Deliberately NOT filtered on Outcome, unlike IX_auth_LoginAttempt_Address: the
-- registration count is on ARRIVALS and a valid submission counts too.  See the section header.
IF NOT EXISTS (SELECT 1
                 FROM sys.indexes
                WHERE name      = N'IX_auth_RegistrationAttempt_Address'
                  AND object_id = OBJECT_ID (N'auth.RegistrationAttempt'))
BEGIN
    CREATE INDEX IX_auth_RegistrationAttempt_Address
        ON auth.RegistrationAttempt (ClientAddress, AttemptedUtc)
        INCLUDE (AttemptKind, Outcome)
        WHERE IsDeleted = 0;
END;
GO

-- "Who has been knocking at this registration" -- the forensic read, and the one that makes an enrolment flood into a
-- named organization visible rather than merely counted.
IF NOT EXISTS (SELECT 1
                 FROM sys.indexes
                WHERE name      = N'IX_auth_RegistrationAttempt_Registration'
                  AND object_id = OBJECT_ID (N'auth.RegistrationAttempt'))
BEGIN
    CREATE INDEX IX_auth_RegistrationAttempt_Registration
        ON auth.RegistrationAttempt (OrganizationRegistrationId, AttemptedUtc)
        WHERE OrganizationRegistrationId IS NOT NULL AND IsDeleted = 0;
END;
GO


-- *** 3. Audit triggers ***
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
GO

/***********************************************************************************************************************
ObjectName:   auth.trg_au_updt_OrganizationRegistration
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

AFTER UPDATE audit stamp for auth.OrganizationRegistration, and two guards: the submission is immutable, and the
conclusion is write-once.  Both raise E-50010.

========================================================================================================================
Requirements and Key Dependencies:

auth.OrganizationRegistration and its PRIMARY KEY.  No grant of its own: a trigger runs in the caller's security
context.

========================================================================================================================
Notes:

WHAT "THE SUBMISSION IS IMMUTABLE" COVERS, AND WHY EACH ONE.  ApplicationId, ProposedTenantCode, OrganizationName,
ContactEmail and SubmittedUtc are all write-once.  This is stricter than most tables here and the reason is that the
submission is EVIDENCE: it is the record of what an anonymous caller asked for, and an approval means "I, this profile,
agreed to that request".  If the request can be edited after the fact then the approval attests to nothing.  ContactName
and ClientAddress are deliberately NOT in the list -- the first is a courtesy field somebody will want to correct, and
the second is metadata the submitter did not supply.

WHY THE CONCLUSION IS WRITE-ONCE RATHER THAN A STATE MACHINE.  Pending -> Approved and Pending -> Rejected are the only
transitions.  Not Approved -> Rejected, and not Rejected -> Pending: an approval has already created a tenant and granted
default roles to whoever registered under it, so "un-approving" is a deactivation of that tenant (auth.uspDeactivateTenant)
and not an edit of this row.  A rejected organization that wants to try again submits again -- which the filtered unique
index permits, because it names Status.

E-50060 FROM auth.uspApproveOrganization SAYS THE SAME THING MORE POLITELY.  Both exist on purpose: the procedure's
number is what the UI shows when a reviewer double-clicks, and this one is what holds when the row is touched from SSMS
or by a later procedure that forgot to check.  The pattern is auth.trg_au_updt_Role's E-50012 and INV-10.

========================================================================================================================
Example Usage and Performance:

update auth.OrganizationRegistration set ContactName = N'A Patel' where OrganizationRegistrationId = 1;   -- permitted

Set-based; one extra UPDATE per statement touching four columns.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-086
Description:
Created.  Phase 6.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER TRIGGER auth.trg_au_updt_OrganizationRegistration
    ON auth.OrganizationRegistration
    AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    IF (UPDATE (ApplicationId) OR UPDATE (ProposedTenantCode) OR UPDATE (OrganizationName)
        OR UPDATE (ContactEmail) OR UPDATE (SubmittedUtc))
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.OrganizationRegistrationId = i.OrganizationRegistrationId
                    WHERE i.ApplicationId      <> d.ApplicationId
                       OR i.ProposedTenantCode <> d.ProposedTenantCode
                       OR i.OrganizationName    <> d.OrganizationName
                       OR i.ContactEmail        <> d.ContactEmail
                       OR i.SubmittedUtc        <> d.SubmittedUtc)
    BEGIN
        ;THROW 50010, N'The submission half of auth.OrganizationRegistration is immutable: ApplicationId, ProposedTenantCode, OrganizationName, ContactEmail and SubmittedUtc. The row is the evidence of what an anonymous caller asked for, and an approval attests to that request -- if the request can be edited afterwards the approval attests to nothing. ContactName, ClientAddress and ReviewNote remain editable.', 1;
    END;

    -- The conclusion is write-once.  Pending -> Approved and Pending -> Rejected only.
    IF UPDATE (Status)
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.OrganizationRegistrationId = i.OrganizationRegistrationId
                    WHERE i.Status <> d.Status
                      AND d.Status <> N'Pending')
    BEGIN
        ;THROW 50010, N'auth.OrganizationRegistration.Status is write-once out of Pending: only Pending -> Approved and Pending -> Rejected are permitted. An approval has already created a tenant and granted its default roles, so reversing it is auth.uspDeactivateTenant and not an edit of this row; a rejected organization submits again, which UX_auth_OrganizationRegistration_Pending permits because its filter names Status.', 1;
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
      FROM auth.OrganizationRegistration AS r
      JOIN inserted                      AS i ON i.OrganizationRegistrationId = r.OrganizationRegistrationId
      JOIN deleted                       AS d ON d.OrganizationRegistrationId = r.OrganizationRegistrationId;
END;
GO

/***********************************************************************************************************************
ObjectName:   auth.trg_au_updt_RegistrationAttempt
Author:       rsincero
CreateDate:   2026-09-21
========================================================================================================================
Description:

AFTER UPDATE audit stamp for auth.RegistrationAttempt, and the two guards that make the throttle count mean something:
the identifying half of the row is immutable, and the outcome is terminal once it leaves 'Received'.  Both raise
E-50010.

========================================================================================================================
Requirements and Key Dependencies:

auth.RegistrationAttempt and its PRIMARY KEY.  No grant of its own: a trigger runs in the caller's security context.

========================================================================================================================
Notes:

WHY AttemptKind, ClientAddress, ApplicationCode AND AttemptedUtc ARE IMMUTABLE.  Each one is an INPUT TO THE COUNT, and
the reasoning is auth.trg_au_updt_LoginAttempt's exactly: changing one moves an arrival from one address's tally to
another's, or out of the window entirely.  A throttle whose history can be edited is a throttle that can be cleared
without deleting anything, which is worse than no throttle because the queue still looks defended.

ProposedTenantCode, UserAgent AND OrganizationRegistrationId ARE DELIBERATELY NOT IN THE LIST.  None of the three is
counted, and the third is written LATE on purpose: an 'Organization' attempt does not know the registration id until the
INSERT that produces it has run, so the recorder writes the row first and names the registration when it exists.  An
immutability guard over that column would refuse the very update the design depends on.

WHY THE OUTCOME IS TERMINAL.  'Received' -> anything is permitted once.  Nothing else moves, for the reason
auth.LoginAttempt's Outcome is terminal (D-14): re-opening a concluded attempt makes it re-usable, and editing a
'Throttled' into an 'Accepted' rewrites the record of a refusal that really happened.  Note what this does NOT protect
-- an attempt cannot be un-counted by changing its Outcome anyway, because the count ignores Outcome entirely.  That is
the belt beside the braces, and it is the braces that carry the load here.

========================================================================================================================
Example Usage and Performance:

update auth.RegistrationAttempt set Outcome = 'Refused', FailureReason = 'BlankArgument', ConcludedUtc = SYSUTCDATETIME ()
 where RegistrationAttemptId = 1;   -- permitted once

Set-based; one extra UPDATE per statement touching four columns.

========================================================================================================================
Modification History:

Date:		2026-09-21
Author:		rsincero
Ticket:		G-24
Description:
Created with auth.RegistrationAttempt.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER TRIGGER auth.trg_au_updt_RegistrationAttempt
    ON auth.RegistrationAttempt
    AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM inserted) RETURN;
    IF TRIGGER_NESTLEVEL (@@PROCID, 'AFTER', 'DML') > 1 RETURN;

    IF (UPDATE (AttemptKind) OR UPDATE (ClientAddress) OR UPDATE (ApplicationCode) OR UPDATE (AttemptedUtc))
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.RegistrationAttemptId = i.RegistrationAttemptId
                    WHERE i.AttemptKind   <> d.AttemptKind
                       OR i.ClientAddress <> d.ClientAddress
                       OR i.AttemptedUtc  <> d.AttemptedUtc
                       OR COALESCE (i.ApplicationCode, N'') <> COALESCE (d.ApplicationCode, N''))
    BEGIN
        ;THROW 50010, N'auth.RegistrationAttempt.AttemptKind, ClientAddress, ApplicationCode and AttemptedUtc are immutable: each is an input to the per-address registration count, and changing one moves an arrival from one address''s tally to another''s or out of the window entirely -- gap G-24, E-50068. ProposedTenantCode, UserAgent and OrganizationRegistrationId stay editable, the last because an Organization attempt does not know the registration id until the INSERT that creates it has run.', 1;
    END;

    IF UPDATE (Outcome)
       AND EXISTS (SELECT 1
                     FROM inserted AS i
                     JOIN deleted  AS d ON d.RegistrationAttemptId = i.RegistrationAttemptId
                    WHERE i.Outcome <> d.Outcome
                      AND d.Outcome <> 'Received')
    BEGIN
        ;THROW 50010, N'auth.RegistrationAttempt.Outcome is terminal once it leaves ''Received'': Received -> Accepted, Refused or Throttled, and nothing else. Editing a Throttled row into an Accepted one rewrites the record of a refusal that really happened. The count behind E-50068 ignores Outcome entirely, so this guard protects the evidence rather than the throttle.', 1;
    END;

    DECLARE @NowRa   DATETIME2 (3)  = SYSUTCDATETIME ()
          , @ActorRa NVARCHAR (255) = COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N'')
                                              , ORIGINAL_LOGIN ());

    UPDATE a
       SET a.auditModifiedDateUtc = @NowRa
         , a.auditModifiedBy      = CASE WHEN UPDATE (auditModifiedBy)
                                         THEN COALESCE (NULLIF (i.auditModifiedBy, N''), @ActorRa)
                                         ELSE @ActorRa END
         , a.auditDeletedBy       = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @ActorRa ELSE a.auditDeletedBy      END
         , a.auditDeletedDateUtc  = CASE WHEN d.IsDeleted = 0 AND i.IsDeleted = 1 THEN @NowRa   ELSE a.auditDeletedDateUtc END
      FROM auth.RegistrationAttempt AS a
      JOIN inserted                 AS i ON i.RegistrationAttemptId = a.RegistrationAttemptId
      JOIN deleted                  AS d ON d.RegistrationAttemptId = a.RegistrationAttemptId;
END;
GO


-- *** 4. Descriptions ***
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
      (N'auth', N'TABLE', N'OrganizationRegistration', NULL
     , N'The Variant 3 self-service onboarding queue -- section 16.4. An external organization asks for a tenant; an '
     + N'agency user holding Tenant.Create decides. THE ONLY TABLE IN THIS DESIGN WRITTEN BY AN UNAUTHENTICATED '
     + N'CALLER: auth.uspRegisterOrganization takes no session token. NO TENANT IS CREATED BY A REGISTRATION -- '
     + N'step 2 of section 16.4 is a deliberate human gate, because self-service tenant creation in a public-facing '
     + N'application is how an attacker gets a tenant of their own and an approved-looking identity. Carries no '
     + N'credential of any kind; the external user''s verifier arrives later through auth.uspRegisterExternalUser.')
    , (N'auth', N'TABLE', N'OrganizationRegistration', N'OrganizationRegistrationId'
     , N'Surrogate key. There is no natural key: a rejected organization may submit the same request again, so only '
     + N'the PENDING rows are unique on (ApplicationId, ProposedTenantCode).')
    , (N'auth', N'TABLE', N'OrganizationRegistration', N'ApplicationId'
     , N'Which application the organization is asking to join -- D-09. IMMUTABLE (E-50010) with the rest of the '
     + N'submission.')
    , (N'auth', N'TABLE', N'OrganizationRegistration', N'ProposedTenantCode'
     , N'The tenant code asked for, passed straight through to auth.uspCreateTenant on approval. Same width as '
     + N'auth.Tenant.TenantCode deliberately -- narrower would refuse codes the tenant table accepts, wider would '
     + N'truncate at approval. Unique among PENDING rows per application (E-50063); a rejected request frees the '
     + N'code again. IMMUTABLE (E-50010).')
    , (N'auth', N'TABLE', N'OrganizationRegistration', N'OrganizationName'
     , N'The organization''s own name for itself, which becomes auth.Tenant.TenantName on approval. IMMUTABLE '
     + N'(E-50010): the row is the evidence of what was asked for.')
    , (N'auth', N'TABLE', N'OrganizationRegistration', N'ContactEmail'
     , N'Where the decision is sent. Same width as auth.User.Email. Deliberately NOT part of any unique key: two '
     + N'organizations may share an agent, and one organization may correct its contact mid-review. IMMUTABLE '
     + N'(E-50010).')
    , (N'auth', N'TABLE', N'OrganizationRegistration', N'ContactName'
     , N'Who to address. A courtesy field, and one of the two columns the immutability guard deliberately leaves '
     + N'editable -- somebody will want to correct a misspelt name and nothing depends on it.')
    , (N'auth', N'TABLE', N'OrganizationRegistration', N'ClientAddress'
     , N'The address the submission arrived from -- the only attribution an anonymous caller has, and a burst from '
     + N'one address is the thing an operator wants to see. NOT the column the throttle counts: G-24''s per-address '
     + N'count is taken over auth.RegistrationAttempt instead, because a submission REFUSED by E-50062 or E-50063 '
     + N'writes no row here at all, so counting this table would count only the attempts that were well formed enough '
     + N'to reach the queue. Same width as auth.LoginAttempt.ClientAddress.')
    , (N'auth', N'TABLE', N'OrganizationRegistration', N'Status'
     , N'Pending, Approved or Rejected. WRITE-ONCE out of Pending (E-50010 from the trigger, E-50060 from '
     + N'auth.uspApproveOrganization): an approval has already created a tenant and granted its default roles, so '
     + N'reversing it is auth.uspDeactivateTenant, not an edit here. Tied to the three conclusion columns by '
     + N'CK_auth_OrganizationRegistration_Concluded.')
    , (N'auth', N'TABLE', N'OrganizationRegistration', N'SubmittedUtc'
     , N'When the organization asked. IMMUTABLE (E-50010). Drives the review queue''s ordering, oldest first.')
    , (N'auth', N'TABLE', N'OrganizationRegistration', N'ReviewedUtc'
     , N'When the decision was made. NULL while Pending, NOT NULL once concluded -- '
     + N'CK_auth_OrganizationRegistration_Concluded.')
    , (N'auth', N'TABLE', N'OrganizationRegistration', N'ReviewedByProfileId'
     , N'WHICH agency profile decided. Required on both Approved and Rejected: a refusal nobody is accountable for '
     + N'is the one an applicant cannot appeal. The acting profile, not the login -- P-08, the same anchor '
     + N'logs.AuthorizationChange.ActorUserProfileId uses.')
    , (N'auth', N'TABLE', N'OrganizationRegistration', N'ReviewNote'
     , N'Free text from the reviewer. Editable after the conclusion, deliberately: a rejection reason improved after '
     + N'a telephone call is worth more than an immutable one. Holds no credential and no personal data beyond what '
     + N'the reviewer types.')
    , (N'auth', N'TABLE', N'OrganizationRegistration', N'TenantId'
     , N'The tenant this registration became. NULL until approval, NOT NULL on Approved, and NULL again on Rejected '
     + N'-- CK_auth_OrganizationRegistration_Concluded. The foreign key is COMPOSITE on (TenantId, ApplicationId) '
     + N'against UX_auth_Tenant_Id_Application, so an approval cannot point at a tenant in a different application.')
    , (N'auth', N'TRIGGER', N'trg_au_updt_OrganizationRegistration', NULL
     , N'Audit stamp for auth.OrganizationRegistration, plus two E-50010 guards: the submission half is immutable '
     + N'(ApplicationId, ProposedTenantCode, OrganizationName, ContactEmail, SubmittedUtc) and Status is write-once '
     + N'out of Pending. ContactName, ClientAddress and ReviewNote stay editable on purpose.')

    -- ---------------------------------------------------------------------------- auth.RegistrationAttempt (G-24)
    , (N'auth', N'TABLE', N'RegistrationAttempt', NULL
     , N'One row per CALL of a public registration entry point, whatever the outcome -- gap G-24, section 16.4. The '
     + N'source of the per-address count behind E-50068. A SECOND table rather than a count over '
     + N'auth.OrganizationRegistration because a submission refused by E-50062 or E-50063 writes no registration row, '
     + N'so that count would see only the well-formed attempts and an attacker who varies the payload until it fails '
     + N'validation would be invisible to it. The count is on ARRIVALS and ignores Outcome, which is the opposite of '
     + N'the sign-in throttle (section 7.4 counts failures, because a successful sign-in is proof of identity; anybody '
     + N'can fill a form in correctly). The row is written BEFORE the call is validated, so an input that trips an '
     + N'unanticipated error still costs the caller its allowance. Holds no credential: neither public form carries '
     + N'one.')
    , (N'auth', N'TABLE', N'RegistrationAttempt', N'RegistrationAttemptId'
     , N'Surrogate key, BIGINT: one row per public call including the refused ones, so this grows faster than the '
     + N'queue it protects and is the table a retention policy will want first.')
    , (N'auth', N'TABLE', N'RegistrationAttempt', N'AttemptKind'
     , N'Which public form: Organization (section 16.4 step 1) or ExternalUser (step 3). Both are throttled on the '
     + N'SAME per-address count, because a throttle on one door beside an untouched one is a throttle nobody pays. '
     + N'IMMUTABLE (E-50010).')
    , (N'auth', N'TABLE', N'RegistrationAttempt', N'ApplicationId'
     , N'The application the attempt resolved to, or NULL. Nullable for the reason auth.LoginAttempt.UserId is: an '
     + N'attempt naming an application code that matches nothing live has no id, and those are exactly the attempts '
     + N'worth looking at.')
    , (N'auth', N'TABLE', N'RegistrationAttempt', N'ApplicationCode'
     , N'The application code as SUPPLIED, recorded as a string rather than only as a resolved id -- the same decision '
     + N'auth.LoginAttempt makes for UserName, and for the same reason. IMMUTABLE (E-50010), because it is part of what '
     + N'was asked for.')
    , (N'auth', N'TABLE', N'RegistrationAttempt', N'ProposedTenantCode'
     , N'The tenant code asked for, upper-cased and trimmed as the procedure normalises it, or NULL on an ExternalUser '
     + N'attempt. Deliberately NOT immutable and deliberately not counted: it is context for an investigator, and an '
     + N'attacker varying it is the behaviour the address count exists to catch.')
    , (N'auth', N'TABLE', N'RegistrationAttempt', N'ClientAddress'
     , N'The address the call arrived from, as the application reported it. NOT NULL, and that is what makes the '
     + N'throttle unbypassable: @ClientAddress stopped being optional on both public procedures when this table was '
     + N'built, because an optional identifier on a throttled endpoint is the bypass. Trimmed and non-empty '
     + N'(CK_auth_RegistrationAttempt_ClientAddress), because the count groups on this string and a trailing space '
     + N'would be a second address with its own allowance. IMMUTABLE (E-50010).')
    , (N'auth', N'TABLE', N'RegistrationAttempt', N'UserAgent'
     , N'What the client said it was, unverified and unparsed. Evidence, not a control -- a header an attacker sets '
     + N'freely is worth recording and worth nothing to count.')
    , (N'auth', N'TABLE', N'RegistrationAttempt', N'Outcome'
     , N'Received, Accepted, Refused or Throttled. Received is written FIRST and means the outcome is not known yet; a '
     + N'row that is never updated stays Received and STILL COUNTS. Terminal once it leaves Received (E-50010). Every '
     + N'one of the four counts toward E-50068, so this column is evidence rather than an input to the throttle.')
    , (N'auth', N'TABLE', N'RegistrationAttempt', N'FailureReason'
     , N'A short token -- BlankArgument, UnknownApplication, DuplicatePending, AddressThrottled and the rest -- present '
     + N'exactly on Refused and Throttled (CK_auth_RegistrationAttempt_FailureReason). NEVER shown to the caller: '
     + N'section 14.5 and UI-26, the same rule auth.LoginAttempt.FailureReason follows.')
    , (N'auth', N'TABLE', N'RegistrationAttempt', N'OrganizationRegistrationId'
     , N'On an Organization attempt, the registration this call created; on an ExternalUser attempt, the approved '
     + N'registration it enrolled into. An Accepted attempt always names one '
     + N'(CK_auth_RegistrationAttempt_Registration), which is what makes "which address enrolled these nine users" '
     + N'answerable. Editable, because an Organization attempt cannot know the id until the INSERT that produces it '
     + N'has run.')
    , (N'auth', N'TABLE', N'RegistrationAttempt', N'AttemptedUtc'
     , N'When the call arrived. The window boundary for the count, and IMMUTABLE (E-50010) for that reason: a '
     + N'back-dated arrival is an arrival moved out of the window.')
    , (N'auth', N'TABLE', N'RegistrationAttempt', N'ConcludedUtc'
     , N'When the outcome became known. NULL exactly while Outcome is Received '
     + N'(CK_auth_RegistrationAttempt_ConcludedPair). Also answers how long a refusal took, which is how a public form '
     + N'that has become a timing oracle would show up.')
    , (N'auth', N'TRIGGER', N'trg_au_updt_RegistrationAttempt', NULL
     , N'Audit stamp for auth.RegistrationAttempt, plus two E-50010 guards: AttemptKind, ClientAddress, '
     + N'ApplicationCode and AttemptedUtc are immutable because each is an input to the count, and Outcome is terminal '
     + N'once it leaves Received. ProposedTenantCode, UserAgent and OrganizationRegistrationId stay editable, the last '
     + N'because the registration id does not exist when the row is written.');

    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    SELECT N'auth', N'TABLE', N'OrganizationRegistration', c.ColumnName, c.Description
      FROM (VALUES
            (N'IsDeleted',            N'Soft-delete flag. 1 = deleted, 0 = active. This database performs no hard deletes; every read filters IsDeleted = 0.')
          , (N'auditDeletedBy',       N'Login or acting profile that soft-deleted the row. NULL on a live row and NOT NULL on a deleted one -- CK_auth_OrganizationRegistration_DeletedPair pairs it to the flag. An undelete must clear it in the same statement, because the CHECK runs before the AFTER trigger.')
          , (N'auditDeletedDateUtc',  N'UTC timestamp of the soft delete, stamped with the same instant as auditModifiedDateUtc. NULL on a live row.')
          , (N'auditCreatedBy',       N'Login that inserted the row. On a self-service registration this is the pooled application login and NOT the submitter -- the submitter is anonymous, which is what ContactEmail and ClientAddress are for.')
          , (N'auditCreatedDateUtc',  N'UTC timestamp of row insert. SubmittedUtc is the business fact; this is the storage fact, and they agree except on a migration.')
          , (N'auditModifiedBy',      N'Login or acting profile that last modified the row. On an approval this is the reviewing profile, which ReviewedByProfileId also records deliberately -- the audit column answers "which login touched this row" and nothing else (BL-044).')
          , (N'auditModifiedDateUtc', N'UTC timestamp of last modification. Recomputed by the AFTER UPDATE trigger on every update, so it cannot be back-dated by hand.')
         ) AS c (ColumnName, Description);

    -- auth.RegistrationAttempt's seven, worded for a table nothing but one procedure ever writes.
    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    SELECT N'auth', N'TABLE', N'RegistrationAttempt', c.ColumnName, c.Description
      FROM (VALUES
            (N'IsDeleted',            N'Soft-delete flag. 1 = deleted, 0 = active. This database performs no hard deletes; every read filters IsDeleted = 0 -- INCLUDING the throttle count, which means soft-deleting an attempt really does return its allowance. That is a privileged act with an audit trail, and it is the intended way to clear a throttle that has caught the wrong people.')
          , (N'auditDeletedBy',       N'Login or acting profile that soft-deleted the row. NULL on a live row and NOT NULL on a deleted one -- CK_auth_RegistrationAttempt_DeletedPair pairs it to the flag. This is the column that says who returned an address''s allowance.')
          , (N'auditDeletedDateUtc',  N'UTC timestamp of the soft delete, stamped with the same instant as auditModifiedDateUtc. NULL on a live row.')
          , (N'auditCreatedBy',       N'Login that inserted the row -- always the pooled application login, because every caller of a public registration form is anonymous. The caller''s own identity claim is ClientAddress and UserAgent, unverified and marked as such by being data rather than attribution.')
          , (N'auditCreatedDateUtc',  N'UTC timestamp of row insert. AttemptedUtc is the business fact and the window boundary; this is the storage fact, and they agree except on a migration.')
          , (N'auditModifiedBy',      N'Login that last modified the row, which in practice is the same application login concluding its own attempt.')
          , (N'auditModifiedDateUtc', N'UTC timestamp of last modification. Recomputed by the AFTER UPDATE trigger on every update, so it cannot be back-dated by hand.')
         ) AS c (ColumnName, Description);

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


-- *** 5. Grants ***
-- NONE, ON EITHER TABLE.  INV-11: applicationRole reaches auth.OrganizationRegistration only through
-- auth.uspRegisterOrganization, auth.uspApproveOrganization and auth.uspRegisterExternalUser in
-- 155_auth_registration_procedures.sql, and auth.RegistrationAttempt only through auth.uspRecordRegistrationAttempt in
-- the same file, by ownership chaining.  A direct grant on the first would let an unauthenticated caller INSERT a row
-- that says Approved; a direct grant on the second would let one DELETE its way out of the throttle, which is the same
-- fault wearing different clothes.
PRINT N'080_auth_registration.sql grants nothing on either table. INV-11: auth.OrganizationRegistration is reached '
    + N'only through the three procedures in 155_auth_registration_procedures.sql and auth.RegistrationAttempt only '
    + N'through auth.uspRecordRegistrationAttempt. A direct INSERT grant on the first would let a caller write a row '
    + N'that says Approved; a direct UPDATE grant on the second would let one clear its own throttle.';
GO


-- *** 6. Closing report ***
DECLARE @Report TABLE
(
    RowNo    INT IDENTITY (1, 1) PRIMARY KEY,
    Severity INT             NOT NULL,
    Status   VARCHAR (10)    NOT NULL,
    Item     NVARCHAR (200)  NOT NULL,
    Detail   NVARCHAR (1000)     NULL
);

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (x.ObjName, x.ObjType) IS NULL THEN 1 ELSE 4 END
     , CASE WHEN OBJECT_ID (x.ObjName, x.ObjType) IS NULL THEN 'MISSING' ELSE 'OK' END
     , x.Label + N' ' + x.ObjName
     , x.Detail
  FROM (VALUES (N'Table',   N'U',  N'auth.OrganizationRegistration'
                           , N'Section 16.4. The only table an unauthenticated caller writes. No tenant until approval.')
             , (N'Trigger', N'TR', N'auth.trg_au_updt_OrganizationRegistration'
                           , N'Audit stamp; the submission immutable and Status write-once out of Pending -- E-50010.')
             , (N'Table',   N'U',  N'auth.RegistrationAttempt'
                           , N'G-24. One row per public registration call, whatever the outcome. The source of the '
                           + N'per-address count behind E-50068.')
             , (N'Trigger', N'TR', N'auth.trg_au_updt_RegistrationAttempt'
                           , N'Audit stamp; the counted columns immutable and Outcome terminal out of Received -- '
                           + N'E-50010.')
       ) AS x (Label, ObjType, ObjName, Detail);

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 4 THEN 4 ELSE 1 END
     , CASE WHEN COUNT (*) = 4 THEN 'OK' ELSE 'INCOMPLETE' END
     , N'CHECK constraints'
     , CONCAT (COUNT (*), N' of 4 present: _Status (the closed set), _Concluded (Status tied to ReviewedUtc, '
             , N'ReviewedByProfileId and TenantId), _Named (public input is non-empty), _DeletedPair.')
  FROM sys.check_constraints
 WHERE parent_object_id = OBJECT_ID (N'auth.OrganizationRegistration');

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 2 THEN 4 ELSE 1 END
     , CASE WHEN COUNT (*) = 2 THEN 'OK' ELSE 'INCOMPLETE' END
     , N'Indexes on auth.OrganizationRegistration'
     , CONCAT (COUNT (*), N' of 2 present: UX_auth_OrganizationRegistration_Pending (filtered on IsDeleted = 0 AND '
             , N'Status = Pending, which is what lets a rejected organization ask again) and '
             , N'IX_auth_OrganizationRegistration_Queue (the review list, oldest first).')
  FROM sys.indexes
 WHERE name IN (N'UX_auth_OrganizationRegistration_Pending', N'IX_auth_OrganizationRegistration_Queue');

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.KeyCols = 2 THEN 4 ELSE 1 END
     , CASE WHEN x.KeyCols = 2 THEN 'OK' ELSE 'VIOLATED' END
     , N'Foreign key FK_auth_OrganizationRegistration_auth_Tenant is composite'
     , CONCAT (x.KeyCols, N' column(s). Anything but 2 means an approval could point a registration at a tenant in '
             , N'a different application -- D-09 as a convention rather than a constraint.')
  FROM (SELECT KeyCols = COUNT (*)
          FROM sys.foreign_keys        AS fk
          JOIN sys.foreign_key_columns AS fkc ON fkc.constraint_object_id = fk.object_id
         WHERE fk.name = N'FK_auth_OrganizationRegistration_auth_Tenant') AS x
 WHERE x.KeyCols > 0;

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 7 THEN 4 ELSE 1 END
     , CASE WHEN COUNT (*) = 7 THEN 'OK' ELSE 'INCOMPLETE' END
     , N'CHECK constraints on auth.RegistrationAttempt'
     , CONCAT (COUNT (*), N' of 7 present: _AttemptKind, _ClientAddress (trimmed and non-empty, because the count '
             , N'groups on the string), _Outcome, _ConcludedPair, _FailureReason, _Registration (an Accepted attempt '
             , N'names a registration) and _DeletedPair.')
  FROM sys.check_constraints
 WHERE parent_object_id = OBJECT_ID (N'auth.RegistrationAttempt');

-- THE ONE DECISION IN THIS FILE THAT WOULD STILL COMPILE IF IT WERE REVERSED.  IX_auth_RegistrationAttempt_Address must
-- NOT be filtered on Outcome.  A well-meaning edit that added  AND Outcome = 'Refused'  to match
-- IX_auth_LoginAttempt_Address would look like consistency and would silently make every successful registration free:
-- section 7.4 counts failed sign-ins because a success proves identity, and nothing about a well-formed registration
-- proves anything at all.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.FilterText IS NULL THEN 1
            WHEN x.FilterText LIKE N'%Outcome%' THEN 1
            ELSE 4 END
     , CASE WHEN x.FilterText IS NULL THEN 'MISSING'
            WHEN x.FilterText LIKE N'%Outcome%' THEN 'VIOLATED'
            ELSE 'OK' END
     , N'The throttle index counts arrivals, not failures'
     , CONCAT (N'IX_auth_RegistrationAttempt_Address filter: ', COALESCE (x.FilterText, N'(index absent)')
             , N'. It must name IsDeleted and NOT Outcome. Filtering on Outcome would make every accepted '
             , N'registration free and leave the count measuring only the attempts that were already refused.')
  FROM (SELECT FilterText = (SELECT i.filter_definition
                               FROM sys.indexes AS i
                              WHERE i.name      = N'IX_auth_RegistrationAttempt_Address'
                                AND i.object_id = OBJECT_ID (N'auth.RegistrationAttempt'))) AS x;

-- G-24 asked for a DECISION either way -- a throttle, or a comment saying the edge owns it.  This row states which was
-- taken, in the transcript, so a reader does not have to infer it from the presence of a table.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.Threshold IS NULL THEN 2
            WHEN x.Threshold = 0 THEN 3
            ELSE 4 END
     , CASE WHEN x.Threshold IS NULL THEN 'REVIEW'
            WHEN x.Threshold = 0 THEN 'DISABLED'
            ELSE 'OK' END
     , N'G-24: the database throttles registration, and the edge still has to (G-06)'
     , CONCAT (N'Registration.ThrottleThreshold = ', COALESCE (CAST (x.Threshold AS NVARCHAR (11)), N'(absent)')
             , N' attempt(s) per address per Registration.ThrottleWindowMinutes = '
             , COALESCE (CAST (x.WindowMin AS NVARCHAR (11)), N'(absent)'), N' minute(s), counted over '
             , N'auth.RegistrationAttempt regardless of outcome and refused as E-50068 once crossed. 0 disables it. '
             , N'THIS IS THE DATABASE HALF ONLY: G-06 remains open for rate limiting at the gateway and a CAPTCHA on '
             , N'the public form, because a throttle behind an unlimited form is a throttle an attacker pays once per '
             , N'address.')
  FROM (SELECT Threshold = TRY_CAST ((SELECT s.SettingValue FROM config.ApplicationSetting AS s
                                       WHERE s.SettingKey = N'Registration.ThrottleThreshold'
                                         AND s.IsDeleted  = 0) AS INT)
             , WindowMin = TRY_CAST ((SELECT s.SettingValue FROM config.ApplicationSetting AS s
                                       WHERE s.SettingKey = N'Registration.ThrottleWindowMinutes'
                                         AND s.IsDeleted  = 0) AS INT)) AS x;

INSERT @Report (Severity, Status, Item, Detail)
SELECT 3, 'PENDING', N'Procedure ' + x.ProcName, x.Reason
  FROM (VALUES (N'auth.uspRegisterOrganization', N'Section 16.4 step 1. T-087, 155_auth_registration_procedures.sql.')
             , (N'auth.uspApproveOrganization',  N'Section 16.4 step 2, the human gate. T-087.')
             , (N'auth.uspRegisterExternalUser', N'Section 16.4 step 3, defaults granted automatically. T-087.')
             , (N'auth.uspRecordRegistrationAttempt'
              , N'G-24. The only writer of auth.RegistrationAttempt; until it exists the table is inert and both '
              + N'public entry points are unthrottled. 155_auth_registration_procedures.sql.')
       ) AS x (ProcName, Reason)
 WHERE OBJECT_ID (x.ProcName, N'P') IS NULL;

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 43 THEN 4 ELSE 2 END
     , CASE WHEN COUNT (*) = 43 THEN 'OK' ELSE 'INCOMPLETE' END
     , N'MS_Description on both tables and both triggers'
     , CONCAT (COUNT (*), N' of 43 present: auth.OrganizationRegistration with its 20 columns and its trigger (22), '
             , N'auth.RegistrationAttempt with its 19 columns and its trigger (21). Conventions rule 4.')
  FROM sys.extended_properties AS ep
  JOIN sys.objects             AS o ON o.object_id = ep.major_id
 WHERE ep.name     = N'MS_Description'
   AND o.schema_id = SCHEMA_ID (N'auth')
   AND o.name IN (N'OrganizationRegistration', N'trg_au_updt_OrganizationRegistration'
                , N'RegistrationAttempt',      N'trg_au_updt_RegistrationAttempt');

INSERT @Report (Severity, Status, Item, Detail)
SELECT 4, 'OK', N'Registration arrivals as this file found them'
     , CONCAT (N'auth.RegistrationAttempt holds ', COUNT (*), N' live row(s) from '
             , COUNT (DISTINCT a.ClientAddress), N' distinct address(es): '
             , COALESCE (SUM (CASE WHEN a.Outcome = 'Received'  THEN 1 ELSE 0 END), 0), N' Received, '
             , COALESCE (SUM (CASE WHEN a.Outcome = 'Accepted'  THEN 1 ELSE 0 END), 0), N' Accepted, '
             , COALESCE (SUM (CASE WHEN a.Outcome = 'Refused'   THEN 1 ELSE 0 END), 0), N' Refused, '
             , COALESCE (SUM (CASE WHEN a.Outcome = 'Throttled' THEN 1 ELSE 0 END), 0)
             , N' Throttled. A Received row that never concluded is not an error: it is a call that died before its '
             , N'outcome was known, and it counts against its address exactly as the design intends.')
  FROM auth.RegistrationAttempt AS a
 WHERE a.IsDeleted = 0;

IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
    PRINT N'Organization registration: PROBLEMS found. Read the report below before running the next script.';
ELSE
    PRINT N'Organization registration: no problems found. Items listed as PENDING belong to T-087.';

PRINT N'';

SELECT Severity, Status, Item, Detail
  FROM @Report
 ORDER BY Severity, RowNo;
GO
