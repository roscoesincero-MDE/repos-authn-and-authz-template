-- Throwaway check, not part of the template.  170_permissions.sql's section 3 deny is now PERMANENT, not a probe's
-- temporary one, so the claim "it costs nothing" has to be re-measured against the shipped state rather than against a
-- deny this script put there itself.  Adds no permission of its own; the only thing it creates is a user it drops.
-- Question: with 170 deployed, can a principal whose ONLY membership is applicationRole still authenticate, and is it
-- still refused a direct read of auth and of the pepper?
SET XACT_ABORT ON;
SET NOCOUNT ON;
GO

IF DATABASE_PRINCIPAL_ID (N'probe170smoke') IS NOT NULL
BEGIN
    DROP USER probe170smoke;
END;
GO

CREATE USER probe170smoke WITHOUT LOGIN;
ALTER ROLE applicationRole ADD MEMBER probe170smoke;
GO

DECLARE @Report TABLE (Item NVARCHAR (200), Result NVARCHAR (400));

EXECUTE AS USER = N'probe170smoke';

BEGIN TRY
    DECLARE @AttemptId BIGINT, @Phc NVARCHAR (512), @Mfa BIT;

    EXEC auth.uspGetLoginVerifier @ApplicationCode = N'AUTHTEST', @TenantCode = N'AUTHTEST_ACME'
       , @UserName = N'authtest.alice', @ClientAddress = N'203.0.113.98'
       , @LoginAttemptId = @AttemptId OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;

    INSERT @Report (Item, Result)
    VALUES (N'Round trip 1 as an applicationRole member, 170 deployed'
          , CONCAT (N'SUCCEEDED -- exchange ', @AttemptId, N', verifier of ', LEN (@Phc), N' characters. The deny on '
                  , N'SCHEMA::auth costs the procedures nothing.'));
END TRY
BEGIN CATCH
    INSERT @Report (Item, Result)
    VALUES (N'Round trip 1 as an applicationRole member, 170 deployed'
          , CONCAT (N'REFUSED, error ', ERROR_NUMBER (), N': ', LEFT (ERROR_MESSAGE (), 250)));
END CATCH;

BEGIN TRY
    DECLARE @Users INT = (SELECT COUNT (*) FROM auth.[User]);

    INSERT @Report (Item, Result)
    VALUES (N'Direct SELECT from auth.[User]', N'SUCCEEDED -- INV-11 IS NOT ENFORCED, 170 section 3 is not in effect');
END TRY
BEGIN CATCH
    INSERT @Report (Item, Result)
    VALUES (N'Direct SELECT from auth.[User]', CONCAT (N'refused, error ', ERROR_NUMBER (), N' -- INV-11 enforced'));
END CATCH;

BEGIN TRY
    DECLARE @Creds INT = (SELECT COUNT (*) FROM auth.UserCredential);

    INSERT @Report (Item, Result) VALUES (N'Direct SELECT from auth.UserCredential', N'SUCCEEDED -- verifiers readable');
END TRY
BEGIN CATCH
    INSERT @Report (Item, Result)
    VALUES (N'Direct SELECT from auth.UserCredential', CONCAT (N'refused, error ', ERROR_NUMBER ()));
END CATCH;

BEGIN TRY
    DECLARE @Peek NVARCHAR (200) = (SELECT SettingValue FROM config.ApplicationSetting
                                     WHERE SettingKey = N'Authn.DummyVerifierPepper');

    INSERT @Report (Item, Result) VALUES (N'Direct SELECT of the pepper', N'SUCCEEDED -- section 19.2 is defeated');
END TRY
BEGIN CATCH
    INSERT @Report (Item, Result)
    VALUES (N'Direct SELECT of the pepper', CONCAT (N'refused, error ', ERROR_NUMBER (), N' -- pepper unreadable'));
END CATCH;

-- The other half of section 1: the schema grant is real, so a non-sensitive config table IS readable.
BEGIN TRY
    DECLARE @Scoped INT = (SELECT COUNT (*) FROM config.TenantScopedTable);

    INSERT @Report (Item, Result)
    VALUES (N'Direct SELECT from config.TenantScopedTable'
          , CONCAT (N'SUCCEEDED -- ', @Scoped, N' row(s). SCHEMA::config is genuinely granted, not granted-then-denied '
                  , N'into uselessness.'));
END TRY
BEGIN CATCH
    INSERT @Report (Item, Result)
    VALUES (N'Direct SELECT from config.TenantScopedTable', CONCAT (N'refused, error ', ERROR_NUMBER ()));
END CATCH;

-- BOTH parameters are supplied because neither has a default.  The first run of this script omitted them and came back
-- with error 201, "expects parameter which was not supplied", which is NOT a permission refusal -- and that is itself
-- worth recording: under the earlier probe's schema-level DENY the same malformed call returned 229 instead, because the
-- permission check happens before parameter binding.  A refusal and a bad call are easy to confuse here, so the CATCH
-- below distinguishes 229 from everything else rather than treating any error as a deny.
BEGIN TRY
    EXEC util.uspPhase0Probe @ProbeName = N'probe170smoke', @ForceFailure = 0;

    INSERT @Report (Item, Result)
    VALUES (N'EXEC util.uspPhase0Probe', N'SUCCEEDED -- the util table-verb deny left EXECUTE alone, as intended');
END TRY
BEGIN CATCH
    INSERT @Report (Item, Result)
    VALUES (N'EXEC util.uspPhase0Probe'
          , CONCAT (CASE WHEN ERROR_NUMBER () = 229 THEN N'REFUSED 229 -- section 2 got it wrong, EXECUTE is blocked'
                         ELSE CONCAT (N'error ', ERROR_NUMBER (), N', not a permission refusal: ') END
                  , LEFT (ERROR_MESSAGE (), 200)));
END CATCH;

REVERT;

SELECT Item, Result FROM @Report;
GO

DROP USER probe170smoke;
GO

PRINT N'Smoke check cleaned up: probe170smoke dropped. No permission was added or removed by this script.';
GO
