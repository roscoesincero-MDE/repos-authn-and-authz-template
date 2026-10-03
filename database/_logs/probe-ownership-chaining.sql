-- Throwaway measurement, not part of the template.  Question: does a DENY SELECT on config.ApplicationSetting stop
-- auth.uspGetLoginVerifier, which reads that table, when the caller is a member of applicationRole and nothing else?
-- If ownership chaining holds, the procedure works and the direct read does not.  Cleans up after itself.
SET XACT_ABORT ON;
SET NOCOUNT ON;
GO

IF DATABASE_PRINCIPAL_ID (N'probe170') IS NOT NULL
BEGIN
    DROP USER probe170;
END;
GO

CREATE USER probe170 WITHOUT LOGIN;
ALTER ROLE applicationRole ADD MEMBER probe170;
DENY SELECT ON config.ApplicationSetting TO applicationRole;
GO

DECLARE @Report TABLE (Item NVARCHAR (200), Result NVARCHAR (400));

EXECUTE AS USER = N'probe170';

INSERT @Report (Item, Result)
VALUES (N'HAS_PERMS_BY_NAME config.ApplicationSetting SELECT'
      , CAST (HAS_PERMS_BY_NAME (N'config.ApplicationSetting', N'OBJECT', N'SELECT') AS NVARCHAR (10)))
     , (N'HAS_PERMS_BY_NAME auth.[User] SELECT'
      , CAST (HAS_PERMS_BY_NAME (N'auth.[User]', N'OBJECT', N'SELECT') AS NVARCHAR (10)))
     , (N'HAS_PERMS_BY_NAME auth.uspGetLoginVerifier EXECUTE'
      , CAST (HAS_PERMS_BY_NAME (N'auth.uspGetLoginVerifier', N'OBJECT', N'EXECUTE') AS NVARCHAR (10)));

BEGIN TRY
    DECLARE @Peek NVARCHAR (200) = (SELECT SettingValue FROM config.ApplicationSetting
                                     WHERE SettingKey = N'Authn.DummyVerifierPepper');

    INSERT @Report (Item, Result) VALUES (N'Direct SELECT of the pepper', N'SUCCEEDED -- ' + @Peek);
END TRY
BEGIN CATCH
    INSERT @Report (Item, Result) VALUES (N'Direct SELECT of the pepper', CONCAT (N'refused, error ', ERROR_NUMBER ()));
END CATCH;

BEGIN TRY
    DECLARE @AttemptId BIGINT, @Phc NVARCHAR (512), @Mfa BIT;

    EXEC auth.uspGetLoginVerifier @ApplicationCode = N'AUTHTEST', @TenantCode = N'AUTHTEST_ACME'
       , @UserName = N'probe170.nobody', @ClientAddress = N'203.0.113.99'
       , @LoginAttemptId = @AttemptId OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;

    INSERT @Report (Item, Result)
    VALUES (N'EXEC auth.uspGetLoginVerifier, which reads config and writes auth'
          , CONCAT (N'SUCCEEDED -- exchange ', @AttemptId, N', verifier of ', LEN (@Phc), N' characters'));
END TRY
BEGIN CATCH
    INSERT @Report (Item, Result)
    VALUES (N'EXEC auth.uspGetLoginVerifier, which reads config and writes auth'
          , CONCAT (N'refused, error ', ERROR_NUMBER (), N': ', ERROR_MESSAGE ()));
END CATCH;

REVERT;

SELECT Item, Result FROM @Report;
GO

REVOKE SELECT ON config.ApplicationSetting FROM applicationRole;
DROP USER probe170;
GO

PRINT N'Probe cleaned up: the DENY is revoked and probe170 is dropped.';
GO
