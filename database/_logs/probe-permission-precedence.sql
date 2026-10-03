-- DO NOT RUN THIS AGAIN AS IT STANDS.  Its cleanup at the bottom used to be correct and now is not: it revokes
-- DENY ... ON SCHEMA::auth FROM applicationRole, which since 170_permissions.sql shipped is a PERMANENT part of the
-- permission model and the enforcement of INV-11.  Re-running this would quietly undo that and report success.  The
-- REVOKE of SCHEMA::util is still fine.  Kept for the record of what was measured; if you need to measure again, copy it
-- and drop the auth REVOKE.  Run database/170_permissions.sql afterwards to put the model back either way.
--
-- Throwaway measurement, not part of the template.  Two questions 170_permissions.sql needs answered before it commits
-- to a model, neither of which is safe to assume from the documentation:
--   1. Does DENY EXECUTE ON SCHEMA::util override an existing object-level GRANT on util.uspPhase0Probe?
--   2. Does DENY on the four table verbs on SCHEMA::auth break the auth procedures, which read and write those tables?
-- Cleans up after itself.
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

DENY EXECUTE ON SCHEMA::util TO applicationRole;
DENY SELECT, INSERT, UPDATE, DELETE ON SCHEMA::auth TO applicationRole;
GO

DECLARE @Report TABLE (Item NVARCHAR (200), Result NVARCHAR (400));

EXECUTE AS USER = N'probe170';

INSERT @Report (Item, Result)
VALUES (N'HAS_PERMS_BY_NAME util.uspPhase0Probe EXECUTE, object GRANT under a schema DENY'
      , CAST (HAS_PERMS_BY_NAME (N'util.uspPhase0Probe', N'OBJECT', N'EXECUTE') AS NVARCHAR (10)))
     , (N'HAS_PERMS_BY_NAME auth.uspGetLoginVerifier EXECUTE, unaffected by a table-verb DENY'
      , CAST (HAS_PERMS_BY_NAME (N'auth.uspGetLoginVerifier', N'OBJECT', N'EXECUTE') AS NVARCHAR (10)));

BEGIN TRY
    EXEC util.uspPhase0Probe;

    INSERT @Report (Item, Result) VALUES (N'EXEC util.uspPhase0Probe', N'SUCCEEDED -- the object GRANT won');
END TRY
BEGIN CATCH
    INSERT @Report (Item, Result)
    VALUES (N'EXEC util.uspPhase0Probe', CONCAT (N'refused, error ', ERROR_NUMBER (), N' -- the schema DENY won'));
END CATCH;

BEGIN TRY
    DECLARE @AttemptId BIGINT, @Phc NVARCHAR (512), @Mfa BIT;

    EXEC auth.uspGetLoginVerifier @ApplicationCode = N'AUTHTEST', @TenantCode = N'AUTHTEST_ACME'
       , @UserName = N'probe170.nobody', @ClientAddress = N'203.0.113.99'
       , @LoginAttemptId = @AttemptId OUTPUT, @VerifierPhc = @Phc OUTPUT, @RequiresMfa = @Mfa OUTPUT;

    INSERT @Report (Item, Result)
    VALUES (N'EXEC auth.uspGetLoginVerifier under DENY on SCHEMA::auth'
          , CONCAT (N'SUCCEEDED -- exchange ', @AttemptId, N'. Ownership chaining is not evaluated against a DENY.'));
END TRY
BEGIN CATCH
    INSERT @Report (Item, Result)
    VALUES (N'EXEC auth.uspGetLoginVerifier under DENY on SCHEMA::auth'
          , CONCAT (N'refused, error ', ERROR_NUMBER (), N': ', LEFT (ERROR_MESSAGE (), 200)));
END CATCH;

BEGIN TRY
    DECLARE @Peek INT = (SELECT COUNT (*) FROM auth.[User]);

    INSERT @Report (Item, Result) VALUES (N'Direct SELECT from auth.[User]', N'SUCCEEDED -- INV-11 is not enforced');
END TRY
BEGIN CATCH
    INSERT @Report (Item, Result)
    VALUES (N'Direct SELECT from auth.[User]', CONCAT (N'refused, error ', ERROR_NUMBER ()));
END CATCH;

REVERT;

SELECT Item, Result FROM @Report;
GO

REVOKE EXECUTE ON SCHEMA::util FROM applicationRole;
REVOKE SELECT, INSERT, UPDATE, DELETE ON SCHEMA::auth FROM applicationRole;
DROP USER probe170;
GO

PRINT N'Probe cleaned up: both denies revoked and probe170 dropped.';
GO
