/***********************************************************************************************************************
Script:         _tests/075_registration_probes.sql
Purpose:        Provokes the two auth.uspRegisterExternalUser refusals that no template test reaches, so that
                _tests/080_error_catalogue.sql finds them in logs.ExecutionLog:
                  *  E-50061  the registration is not Approved (a fresh Pending registration is used);
                  *  E-50066  the user name is already in use (an existing Approved registration from 070 is used,
                              with the user name of an account that already exists).
Target:         SQL Server 2022 or newer.
Run as:         db_owner in the target database.
Run in:         The target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/_tests/075_registration_probes.sql
Idempotent:     Yes.  The Pending registration is found again by its proposed tenant code on a second run.
Depends on:     155_auth_registration_procedures.sql.  _tests/070_variants_end_to_end.sql must have run first (it leaves
                an Approved registration with an active tenant).  900_bootstrap_first_admin.sql (an existing user).
Implements:     G-53, BL-086.  080 fails on a clean build without this file: its coverage check finds E-50061 and
                E-50066 reachable and never raised.  Runs between 070 and 080 by its name.
***********************************************************************************************************************/
:on error exit
SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;

IF DB_NAME () <> N'$(DbName)'
    THROW 50000, N'075_registration_probes.sql: connected to the wrong database; check -d against -v DbName.', 1;
GO

DECLARE @Report TABLE (Severity TINYINT, Status NVARCHAR (20), Item NVARCHAR (200), Detail NVARCHAR (1000));
DECLARE @PendingId    INT
      , @ApprovedId   INT
      , @AppCode      NVARCHAR (50)
      , @TakenName    NVARCHAR (256)
      , @Err          INT;

-- *** Fixtures: an Approved registration with a usable tenant, and a user name that exists ***
SELECT TOP (1)
       @ApprovedId = orr.OrganizationRegistrationId
     , @AppCode    = a.ApplicationCode
  FROM auth.OrganizationRegistration AS orr
  JOIN auth.Tenant                   AS t ON t.TenantId = orr.TenantId AND t.IsActive = 1 AND t.IsDeleted = 0
  JOIN auth.Application              AS a ON a.ApplicationId = t.ApplicationId
 WHERE orr.Status    = N'Approved'
   AND orr.IsDeleted = 0
 ORDER BY orr.OrganizationRegistrationId;

SELECT TOP (1) @TakenName = u.UserName
  FROM auth.[User] AS u
 WHERE u.IsDeleted = 0
 ORDER BY u.UserId;

IF @ApprovedId IS NULL OR @TakenName IS NULL
    THROW 50000, N'075: no Approved registration or no existing user. Run 900 and _tests/070 first.', 1;

-- *** A Pending registration, created once ***
SELECT @PendingId = orr.OrganizationRegistrationId
  FROM auth.OrganizationRegistration AS orr
 WHERE orr.ProposedTenantCode = N'REG075PEND'
   AND orr.IsDeleted          = 0;

IF @PendingId IS NULL
    EXEC auth.uspRegisterOrganization
          @ApplicationCode            = @AppCode
        , @ProposedTenantCode         = N'REG075PEND'
        , @OrganizationName           = N'Registration Probe Organization'
        , @ContactEmail               = N'contact@probe.example.invalid'
        , @ContactName                = N'Probe Contact'
        , @ClientAddress              = N'192.0.2.75'
        , @OrganizationRegistrationId = @PendingId OUTPUT;

-- *** E-50061: enrol into a registration that is not Approved ***
SET @Err = NULL;
BEGIN TRY
    EXEC auth.uspRegisterExternalUser
          @OrganizationRegistrationId = @PendingId
        , @UserName                   = N'reg075.pending'
        , @DisplayName                = N'Probe Pending'
        , @Email                      = N'pending@probe.example.invalid'
        , @ClientAddress              = N'192.0.2.75';
END TRY
BEGIN CATCH
    SET @Err = ERROR_NUMBER ();
END CATCH;

INSERT @Report VALUES (CASE WHEN @Err = 50061 THEN 4 ELSE 1 END, CASE WHEN @Err = 50061 THEN N'OK' ELSE N'FAILED' END
                     , N'E-50061 on a Pending registration', CONCAT (N'Raised ', COALESCE (CAST (@Err AS NVARCHAR (12)), N'nothing')));

-- *** E-50066: enrol with a user name that is taken ***
SET @Err = NULL;
BEGIN TRY
    EXEC auth.uspRegisterExternalUser
          @OrganizationRegistrationId = @ApprovedId
        , @UserName                   = @TakenName
        , @DisplayName                = N'Probe Duplicate'
        , @Email                      = N'duplicate@probe.example.invalid'
        , @ClientAddress              = N'192.0.2.76';
END TRY
BEGIN CATCH
    SET @Err = ERROR_NUMBER ();
END CATCH;

INSERT @Report VALUES (CASE WHEN @Err = 50066 THEN 4 ELSE 1 END, CASE WHEN @Err = 50066 THEN N'OK' ELSE N'FAILED' END
                     , N'E-50066 on a user name in use', CONCAT (N'Raised ', COALESCE (CAST (@Err AS NVARCHAR (12)), N'nothing')));

SELECT Severity, Status, Item, Detail FROM @Report ORDER BY Severity, Item;

IF EXISTS (SELECT 1 FROM @Report WHERE Severity = 1)
    THROW 50000, N'075_registration_probes.sql: at least one probe did not raise its number. See the report above.', 1;
GO
