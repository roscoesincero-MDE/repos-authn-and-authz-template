// =====================================================================================================================
//  T-040  --  the two-round-trip password verification, proved from the client side
//  ===================================================================================================================
//
//  WHAT THIS EXISTS TO PROVE, AND WHY IT HAS TO BE A CLIENT PROGRAM
//
//  Decision D-08 says the database never sees a password and never computes a digest.  Everything in
//  database/_tests/040_identity_and_authn.sql therefore has to TELL auth.uspCompleteLogin whether the password matched,
//  by passing @PasswordVerified = 1 or 0 -- which means the one thing that file cannot test is whether the arrangement
//  actually works.  Its fixture verifiers are well-formed strings that no password produces.
//
//  This harness closes that hole.  It computes real Argon2id, against a real verifier string it wrote itself, over the
//  real two round trips:
//
//      round trip 1   auth.uspGetLoginVerifier   ->  a PHC string and an exchange id
//      (client)       parse it, derive the digest with ITS parameters and ITS salt, compare in constant time
//      round trip 2   auth.uspCompleteLogin      ->  a session, or E-50106
//
//  and then does the same thing for a user name nobody holds, where round trip 1 returns a DERIVED DUMMY.  The point of
//  that third case is the one T-042 asks about: the client cannot tell the difference.  It parses the dummy with the same
//  parser, spends the same Argon2id work on it, and reaches the same refusal by the same path.
//
//  WHY Argon2id FROM A PACKAGE AND NOT PBKDF2 FROM THE BOX
//
//  .NET ships Rfc2898DeriveBytes and does not ship Argon2id, so the cheap version of this harness would prove the shape
//  of the exchange with the wrong algorithm in it -- and a proof that PBKDF2 round-trips says nothing about whether the
//  m=19456,t=2,p=1 parameters baked into Authn.DummyVerifierPhcTemplate produce fields of the length the template claims.
//  Konscious.Security.Cryptography.Argon2 is a single managed dependency and this is a throwaway harness, so the
//  trade is easy.  A production application should make its own decision about which implementation it trusts; what it
//  must NOT do is change the parameters without changing that template, because the dummy has to look like the real one.
//
//  WHAT IT WRITES, AND WHY THAT IS db_owner WORK
//
//  There is no procedure for setting a password in Phase 2 -- that is Phase 4's business -- so the harness inserts its
//  own auth.UserCredential row directly.  It creates one user, t040.real, in the AUTHTEST fixture that
//  database/_tests/040_identity_and_authn.sql builds, soft-deletes its own previous attempts on the way in, and ends the
//  session it opened on the way out.  It asserts the fixture exists rather than creating it: a harness that quietly
//  builds half an application is a harness whose passing run means nothing.
//
//  Run:   dotnet run --project tools/T040-PasswordVerification -- --server MDE-55TT2J4 --database testTemplate
//  Exit:  0 if every observation held, 1 otherwise.  The report is the output.
// =====================================================================================================================

using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using Microsoft.Data.SqlClient;

namespace T040PasswordVerification;

internal enum Status
{
    Ok,
    Failed,
    Info
}

internal sealed record Observation (Status Status, string Item, string Detail);

internal static class Program
{
    // The fixture this harness attaches itself to, and the one account it owns.
    private const string ApplicationCode = "AUTHTEST";
    private const string TenantCode = "AUTHTEST_ACME";
    private const string UserName = "t040.real";
    private const string UnknownUserName = "t040.nobody";
    private const string ClientAddress = "203.0.113.10";   // a different documentation range from the SQL test's, so the
                                                           // two files' throttle counts cannot interfere with each other
    private const string Actor = "tools/T040-PasswordVerification";

    // The password is a constant in a throwaway harness on purpose: there is nothing here worth protecting, and a
    // prompt would stop this running unattended.  Nothing else in the repository uses it.
    private const string CorrectPassword = "correct horse battery staple";
    private const string WrongPassword = "correct horse battery staplf";

    private static readonly List<Observation> Observations = [];

    private static int Main (string[] args)
    {
        string server = ArgOr (args, "--server", "MDE-55TT2J4");
        string database = ArgOr (args, "--database", "testTemplate");

        var builder = new SqlConnectionStringBuilder
        {
            DataSource = server,
            InitialCatalog = database,
            IntegratedSecurity = true,
            Encrypt = SqlConnectionEncryptOption.Mandatory,
            TrustServerCertificate = true,       // the same posture as sqlcmd -C: a dev instance with a self-signed cert
            ApplicationName = Actor,
            ConnectTimeout = 15
        };

        Console.WriteLine ($"T-040 password verification harness against [{server}].[{database}]");
        Console.WriteLine (new string ('-', 118));

        try
        {
            using var connection = new SqlConnection (builder.ConnectionString);
            connection.Open ();

            AssertFixture (connection);
            string verifierWritten = PrepareAccount (connection);

            RunCorrectPassword (connection, verifierWritten);
            RunWrongPassword (connection);
            RunUnknownUser (connection);
            CompareWork (connection);
        }
        catch (Exception ex)
        {
            Observations.Add (new Observation (Status.Failed, "The harness did not finish",
                $"{ex.GetType ().Name}: {ex.Message}"));
        }

        return Report ();
    }

    // -----------------------------------------------------------------------------------------------------------------
    //  The experiments
    // -----------------------------------------------------------------------------------------------------------------

    // ASSERTED, NOT CREATED.  Same rule as the SQL test files: a harness that builds the fixture it is testing against
    // cannot tell "the deployment is fine" from "I just made it fine".
    private static void AssertFixture (SqlConnection connection)
    {
        object? tenantId = Scalar (connection,
            """
            SELECT t.TenantId
              FROM auth.Tenant      AS t
              JOIN auth.Application AS a ON a.ApplicationId = t.ApplicationId
             WHERE a.ApplicationCode = @app
               AND t.TenantCode      = @tenant
               AND t.IsDeleted       = 0
            """,
            ("@app", ApplicationCode), ("@tenant", TenantCode));

        if (tenantId is null)
        {
            throw new InvalidOperationException (
                $"The {ApplicationCode}/{TenantCode} fixture is not present. Run " +
                "database/_tests/040_identity_and_authn.sql first -- it builds the application, the two tenants and the " +
                "authentication policy this harness signs in against. Nothing has been changed.");
        }

        object? templateValue = Scalar (connection,
            "SELECT SettingValue FROM config.ApplicationSetting " +
            "WHERE SettingKey = N'Authn.DummyVerifierPhcTemplate' AND IsDeleted = 0");

        string template = templateValue as string ?? string.Empty;

        Observations.Add (new Observation (
            template.StartsWith ("$argon2id$", StringComparison.Ordinal) ? Status.Ok : Status.Failed,
            "The database's dummy template names argon2id, which is what this harness computes",
            $"Authn.DummyVerifierPhcTemplate = {template}. If that ever says anything other than argon2id with these " +
            "parameters, the derived dummy stops resembling a real verifier and the whole of section 19.2 quietly " +
            "stops working -- so the harness checks it rather than assuming it."));
    }

    // Writes a REAL Argon2id verifier for a known password, using the same parameters and field widths the database's
    // dummy template claims.  Returns the PHC string written, so the experiment can check the database handed back the
    // same one rather than something of its own.
    private static string PrepareAccount (SqlConnection connection)
    {
        byte[] salt = RandomNumberGenerator.GetBytes (16);
        byte[] hash = Argon2 (CorrectPassword, salt);
        string phc = Phc.Format (Phc.DefaultMemoryKiB, Phc.DefaultIterations, Phc.DefaultParallelism, salt, hash);

        Execute (connection,
            """
            DECLARE @UserId INT;

            IF NOT EXISTS (SELECT 1 FROM auth.[User] WHERE UserName = @user)
            BEGIN
                INSERT auth.[User] (UserName, DisplayName, Email, IsActive, IsPlatformAdmin, IsLockedOut
                                  , MustChangePassword, auditCreatedBy, auditModifiedBy)
                VALUES (@user, N'T-040 harness, a real Argon2id credential', @user + N'@authtest.invalid', 1, 0, 0, 0
                      , @actor, @actor);
            END;

            SELECT @UserId = UserId FROM auth.[User] WHERE UserName = @user;

            -- The reset. Both lockout arms are windowed, so a second run inside fifteen minutes would otherwise inherit
            -- the first run's failures -- exactly the argument _tests/040 makes for soft-deleting its own attempts.
            UPDATE auth.[User]
               SET IsActive        = 1
                 , IsLockedOut     = 0
                 , LockoutEndUtc   = NULL
                 , auditModifiedBy = @actor
             WHERE UserId = @UserId;

            UPDATE auth.LoginAttempt
               SET IsDeleted           = 1
                 , auditDeletedBy      = @actor
                 , auditDeletedDateUtc = SYSUTCDATETIME ()
                 , auditModifiedBy     = @actor
             WHERE IsDeleted = 0
               AND (UserName LIKE N't040.%' OR ClientAddress LIKE N'203.0.113.%');

            UPDATE auth.UserSession
               SET IsDeleted           = 1
                 , auditDeletedBy      = @actor
                 , auditDeletedDateUtc = SYSUTCDATETIME ()
                 , auditModifiedBy     = @actor
             WHERE UserId = @UserId AND IsDeleted = 0;

            -- A fresh verifier every run, so nothing here can come to depend on a constant digest.
            UPDATE auth.UserCredential
               SET IsDeleted           = 1
                 , auditDeletedBy      = @actor
                 , auditDeletedDateUtc = SYSUTCDATETIME ()
                 , auditModifiedBy     = @actor
             WHERE UserId = @UserId AND IsDeleted = 0;

            INSERT auth.UserCredential (UserId, CredentialType, VerifierPhc, LastChangedUtc
                                      , auditCreatedBy, auditModifiedBy)
            VALUES (@UserId, 'Password', @phc, SYSUTCDATETIME (), @actor, @actor);
            """,
            ("@user", UserName), ("@actor", Actor), ("@phc", phc));

        Observations.Add (new Observation (Status.Info,
            "Wrote a real Argon2id verifier for t040.real",
            $"{phc[..Math.Min (31, phc.Length)]}... -- {phc.Length} characters, salt field {Phc.Parse (phc).SaltField.Length}, " +
            $"digest field {Phc.Parse (phc).HashField.Length}. Written directly as db_owner because setting a password " +
            "is Phase 4's procedure and does not exist yet."));

        return phc;
    }

    private static void RunCorrectPassword (SqlConnection connection, string verifierWritten)
    {
        (long attemptId, string verifier, bool _) = GetLoginVerifier (connection, UserName);

        Phc parsed = Phc.Parse (verifier);
        byte[] candidate = Argon2 (CorrectPassword, parsed.Salt, parsed.MemoryKiB, parsed.Iterations, parsed.Parallelism,
            parsed.Hash.Length);
        bool matched = CryptographicOperations.FixedTimeEquals (candidate, parsed.Hash);

        Observations.Add (new Observation (
            verifier == verifierWritten && matched ? Status.Ok : Status.Failed,
            "Round trip 1 returns the stored verifier, and Argon2id over the real password matches it",
            $"The database returned the string this harness wrote: {(verifier == verifierWritten ? "yes" : "NO")}. " +
            $"Digest comparison: {(matched ? "match" : "NO MATCH")}, using CryptographicOperations.FixedTimeEquals -- " +
            "a byte-by-byte loop that returns early leaks the length of the common prefix, which over enough attempts " +
            "is the digest."));

        (long? sessionId, int? errorNumber, _) = CompleteLogin (connection, attemptId, matched);

        Observations.Add (new Observation (
            sessionId is not null && errorNumber is null ? Status.Ok : Status.Failed,
            "Round trip 2 with a genuinely verified password issues a session",
            $"Session {sessionId?.ToString () ?? "(none)"}, error {errorNumber?.ToString () ?? "(none)"}. This is the " +
            "whole of D-08 in one exchange: the client did the cryptography and the database decided what the result " +
            "entitles the client to."));

        if (sessionId is not null)
        {
            // Leave nothing live.  A harness that accumulates sessions every run is a harness that makes
            // 950_verify_deployment.sql's session report useless.
            Execute (connection, "EXEC auth.uspEndSession @UserSessionId = @sid, @EndReason = 'SignedOut';",
                ("@sid", sessionId.Value));
        }
    }

    private static void RunWrongPassword (SqlConnection connection)
    {
        (long attemptId, string verifier, bool _) = GetLoginVerifier (connection, UserName);

        Phc parsed = Phc.Parse (verifier);
        byte[] candidate = Argon2 (WrongPassword, parsed.Salt, parsed.MemoryKiB, parsed.Iterations, parsed.Parallelism,
            parsed.Hash.Length);
        bool matched = CryptographicOperations.FixedTimeEquals (candidate, parsed.Hash);

        (long? sessionId, int? errorNumber, _) = CompleteLogin (connection, attemptId, matched);

        Observations.Add (new Observation (
            !matched && sessionId is null && errorNumber == 50106 ? Status.Ok : Status.Failed,
            "One character wrong: the digest does not match and round trip 2 refuses with E-50106",
            $"Match: {matched}. Session: {sessionId?.ToString () ?? "(none)"}. Error {errorNumber?.ToString () ?? "(none)"}, " +
            "expected 50106. The password differs from the correct one by its last character, which Argon2id turns into " +
            "an entirely unrelated digest -- there is no partial credit to be had."));
    }

    // The case that matters most, and the reason this harness is not just a connectivity check.  t040.nobody does not
    // exist.  The client is not told that, and cannot work it out.
    private static void RunUnknownUser (SqlConnection connection)
    {
        (long attemptId, string verifier, bool _) = GetLoginVerifier (connection, UnknownUserName);

        bool parsed = true;
        Phc? phc = null;

        try
        {
            phc = Phc.Parse (verifier);
        }
        catch (Exception)
        {
            parsed = false;
        }

        Observations.Add (new Observation (parsed ? Status.Ok : Status.Failed,
            "The derived dummy parses with the SAME parser as a real verifier",
            parsed
                ? $"Parsed cleanly: argon2id, m={phc!.MemoryKiB}, t={phc.Iterations}, p={phc.Parallelism}, " +
                  $"{phc.Salt.Length}-byte salt, {phc.Hash.Length}-byte digest. A client cannot branch on something it " +
                  "cannot detect, which is the only form of this defence that works."
                : $"The dummy did NOT parse: {verifier}. A client that throws on the dummy and not on a real verifier " +
                  "has a user-enumeration oracle in its exception handler, whatever the database does."));

        bool matched = false;

        if (phc is not null)
        {
            byte[] candidate = Argon2 (CorrectPassword, phc.Salt, phc.MemoryKiB, phc.Iterations, phc.Parallelism,
                phc.Hash.Length);
            matched = CryptographicOperations.FixedTimeEquals (candidate, phc.Hash);
        }

        (long? sessionId, int? errorNumber, _) = CompleteLogin (connection, attemptId, matched);

        Observations.Add (new Observation (
            !matched && sessionId is null && errorNumber == 50106 ? Status.Ok : Status.Failed,
            "An unknown name reaches the same refusal, E-50106, by the same path",
            $"Match against the dummy: {matched}. Error {errorNumber?.ToString () ?? "(none)"}, expected 50106 -- the " +
            "same number the wrong password produced, from code that did not know which case it was in. No password " +
            "matches a dummy, because the digest field is the pepper's HMAC over the name and not any digest of any " +
            "password at all."));
    }

    // Two measurements, reported as INFO and never as a pass or a failure.  Neither is a timing proof: this is a shared
    // dev box, the numbers move by tens of percent between runs, and a real timing study needs thousands of samples and
    // a quiet machine.  What they ARE is a smoke test for the gross failure -- an unknown name costing half the work, or
    // twice it -- which is the mistake a naive implementation makes and which no amount of care in the SQL can hide.
    private static void CompareWork (SqlConnection connection)
    {
        (long attemptKnown, string verifierKnown, bool _) = GetLoginVerifier (connection, UserName);
        (long attemptUnknown, string verifierUnknown, bool _) = GetLoginVerifier (connection, UnknownUserName);

        double clientKnown = MedianArgon2Ms (verifierKnown);
        double clientUnknown = MedianArgon2Ms (verifierUnknown);

        Observations.Add (new Observation (
            verifierKnown.Length == verifierUnknown.Length ? Status.Ok : Status.Failed,
            "The two verifiers are the same length, so the client's Argon2id costs the same",
            $"Known {verifierKnown.Length} characters, unknown {verifierUnknown.Length}. Client-side median over five " +
            $"derivations: {clientKnown:F1} ms known, {clientUnknown:F1} ms unknown. The parameters are parsed out of " +
            "the string, so identical parameters mean identical work by construction -- the measurement is here to " +
            "catch a template that drifts, not to make a statistical claim."));

        double serverKnown = MedianRoundTripMs (connection, UserName);
        double serverUnknown = MedianRoundTripMs (connection, UnknownUserName);
        double ratio = serverKnown > 0 ? serverUnknown / serverKnown : 0;

        Observations.Add (new Observation (Status.Info,
            "Round trip 1 takes comparable time for a known and an unknown name",
            $"Median over five calls: {serverKnown:F1} ms known, {serverUnknown:F1} ms unknown, ratio {ratio:F2}. " +
            "NOT a timing proof and not scored: a dev instance with a cold cache and a shared disk moves these numbers " +
            "more than the difference being looked for. The known path reads a credential row; the unknown path runs two " +
            "HASHBYTES calls and a base64 conversion. Both are microseconds of work inside a millisecond of round trip, " +
            "which is the actual reason this is not exploitable -- not the ratio printed here."));

        // Conclude both, so neither is left pending. A pending exchange is one that no throttle ever counts.
        CompleteLogin (connection, attemptKnown, false);
        CompleteLogin (connection, attemptUnknown, false);
    }

    // -----------------------------------------------------------------------------------------------------------------
    //  The two round trips, as the application would make them
    // -----------------------------------------------------------------------------------------------------------------

    private static (long AttemptId, string VerifierPhc, bool RequiresMfa) GetLoginVerifier (
        SqlConnection connection, string userName)
    {
        using var command = new SqlCommand ("auth.uspGetLoginVerifier", connection)
        {
            CommandType = System.Data.CommandType.StoredProcedure
        };

        command.Parameters.AddWithValue ("@ApplicationCode", ApplicationCode);
        command.Parameters.AddWithValue ("@TenantCode", TenantCode);
        command.Parameters.AddWithValue ("@UserName", userName);
        command.Parameters.AddWithValue ("@ClientAddress", ClientAddress);
        command.Parameters.AddWithValue ("@UserAgent", Actor);

        SqlParameter attemptId = command.Parameters.Add ("@LoginAttemptId", System.Data.SqlDbType.BigInt);
        attemptId.Direction = System.Data.ParameterDirection.Output;

        SqlParameter verifier = command.Parameters.Add ("@VerifierPhc", System.Data.SqlDbType.NVarChar, 512);
        verifier.Direction = System.Data.ParameterDirection.Output;

        SqlParameter requiresMfa = command.Parameters.Add ("@RequiresMfa", System.Data.SqlDbType.Bit);
        requiresMfa.Direction = System.Data.ParameterDirection.Output;

        command.ExecuteNonQuery ();

        return ((long) attemptId.Value, (string) verifier.Value, (bool) requiresMfa.Value);
    }

    private static (long? SessionId, int? ErrorNumber, string? ErrorMessage) CompleteLogin (
        SqlConnection connection, long attemptId, bool passwordVerified)
    {
        using var command = new SqlCommand ("auth.uspCompleteLogin", connection)
        {
            CommandType = System.Data.CommandType.StoredProcedure
        };

        command.Parameters.AddWithValue ("@LoginAttemptId", attemptId);
        command.Parameters.AddWithValue ("@PasswordVerified", passwordVerified);
        command.Parameters.AddWithValue ("@SessionTokenHash", RandomNumberGenerator.GetBytes (32));

        SqlParameter sessionId = command.Parameters.Add ("@UserSessionId", System.Data.SqlDbType.BigInt);
        sessionId.Direction = System.Data.ParameterDirection.Output;

        SqlParameter userId = command.Parameters.Add ("@UserId", System.Data.SqlDbType.Int);
        userId.Direction = System.Data.ParameterDirection.Output;

        SqlParameter mustChange = command.Parameters.Add ("@MustChangePassword", System.Data.SqlDbType.Bit);
        mustChange.Direction = System.Data.ParameterDirection.Output;

        SqlParameter absolute = command.Parameters.Add ("@AbsoluteExpiryUtc", System.Data.SqlDbType.DateTime2);
        absolute.Direction = System.Data.ParameterDirection.Output;

        SqlParameter idle = command.Parameters.Add ("@IdleExpiryUtc", System.Data.SqlDbType.DateTime2);
        idle.Direction = System.Data.ParameterDirection.Output;

        // NO TRANSACTION AROUND THIS CALL, deliberately, and the same goes for any real caller. The procedure commits
        // the failure it recorded before it raises, so that the raise cannot erase the lockout increment -- but an
        // ambient transaction makes XACT_STATE () non-zero at that moment and the procedure's own CATCH rolls the
        // CALLER's transaction back instead. A TransactionScope here would hand an attacker unlimited guesses. UI-27.
        try
        {
            command.ExecuteNonQuery ();

            return (sessionId.Value as long?, null, null);
        }
        catch (SqlException ex)
        {
            return (null, ex.Number, ex.Message);
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    //  Argon2id, and the PHC string it lives in
    // -----------------------------------------------------------------------------------------------------------------

    private static byte[] Argon2 (string password, byte[] salt, int memoryKiB = Phc.DefaultMemoryKiB,
        int iterations = Phc.DefaultIterations, int parallelism = Phc.DefaultParallelism, int length = 32)
    {
        using var argon = new Argon2id (Encoding.UTF8.GetBytes (password))
        {
            Salt = salt,
            MemorySize = memoryKiB,
            Iterations = iterations,
            DegreeOfParallelism = parallelism
        };

        return argon.GetBytes (length);
    }

    private static double MedianArgon2Ms (string verifierPhc)
    {
        Phc phc = Phc.Parse (verifierPhc);
        var samples = new List<double> ();

        for (int i = 0; i < 5; i++)
        {
            long start = Stopwatch.GetTimestamp ();
            Argon2 (CorrectPassword, phc.Salt, phc.MemoryKiB, phc.Iterations, phc.Parallelism, phc.Hash.Length);
            samples.Add (Stopwatch.GetElapsedTime (start).TotalMilliseconds);
        }

        samples.Sort ();

        return samples[samples.Count / 2];
    }

    private static double MedianRoundTripMs (SqlConnection connection, string userName)
    {
        var samples = new List<double> ();

        for (int i = 0; i < 5; i++)
        {
            long start = Stopwatch.GetTimestamp ();
            (long attemptId, _, _) = GetLoginVerifier (connection, userName);
            samples.Add (Stopwatch.GetElapsedTime (start).TotalMilliseconds);

            CompleteLogin (connection, attemptId, false);
        }

        samples.Sort ();

        return samples[samples.Count / 2];
    }

    // -----------------------------------------------------------------------------------------------------------------
    //  Plumbing
    // -----------------------------------------------------------------------------------------------------------------

    private static string ArgOr (string[] args, string name, string fallback)
    {
        int index = Array.FindIndex (args, a => string.Equals (a, name, StringComparison.OrdinalIgnoreCase));

        return index >= 0 && index + 1 < args.Length ? args[index + 1] : fallback;
    }

    private static object? Scalar (SqlConnection connection, string sql, params (string Name, object Value)[] parameters)
    {
        using var command = new SqlCommand (sql, connection);

        foreach ((string name, object value) in parameters)
        {
            command.Parameters.AddWithValue (name, value);
        }

        object? result = command.ExecuteScalar ();

        return result == DBNull.Value ? null : result;
    }

    private static void Execute (SqlConnection connection, string sql, params (string Name, object Value)[] parameters)
    {
        using var command = new SqlCommand (sql, connection);

        foreach ((string name, object value) in parameters)
        {
            command.Parameters.AddWithValue (name, value);
        }

        command.ExecuteNonQuery ();
    }

    private static int Report ()
    {
        foreach (Observation observation in Observations)
        {
            string tag = observation.Status switch
            {
                Status.Ok => "OK    ",
                Status.Failed => "FAILED",
                _ => "INFO  "
            };

            Console.WriteLine ($"{tag}  {observation.Item}");
            Console.WriteLine ($"        {observation.Detail}");
            Console.WriteLine ();
        }

        int failed = Observations.Count (o => o.Status == Status.Failed);
        int ok = Observations.Count (o => o.Status == Status.Ok);

        Console.WriteLine (new string ('-', 118));

        if (failed > 0)
        {
            Console.WriteLine ($"T-040: {failed} observation(s) FAILED, {ok} held. The two-round-trip exchange is not " +
                "behaving as the design describes -- the detail is above.");

            return 1;
        }

        Console.WriteLine ($"T-040: no problems found. {ok} observation(s) held. Argon2id was computed by this client " +
            "against a verifier the database issued, an unknown name was answered with a dummy this client could not " +
            "distinguish, and both wrong answers were refused with the same number.");

        return 0;
    }
}

// PHC string format, the argon2id subset:  $argon2id$v=19$m=<KiB>,t=<iterations>,p=<lanes>$<salt>$<digest>
//
// The base64 fields are UNPADDED, which is what the format specifies and what the database's template assumes when it
// claims 22 characters of salt and 43 of digest -- those are exactly 16 and 32 bytes without padding. Convert.FromBase64
// String insists on padding, so it is added back here rather than pretending the format has it.
internal sealed record Phc (int MemoryKiB, int Iterations, int Parallelism, byte[] Salt, byte[] Hash,
    string SaltField, string HashField)
{
    public const int DefaultMemoryKiB = 19456;
    public const int DefaultIterations = 2;
    public const int DefaultParallelism = 1;

    public static Phc Parse (string phc)
    {
        string[] parts = phc.Split ('$');

        // ["", "argon2id", "v=19", "m=...,t=...,p=...", salt, hash]
        if (parts.Length != 6 || parts[1] != "argon2id")
        {
            throw new FormatException ($"Not an argon2id PHC string: {phc}");
        }

        int memory = DefaultMemoryKiB, iterations = DefaultIterations, parallelism = DefaultParallelism;

        foreach (string pair in parts[3].Split (','))
        {
            string[] kv = pair.Split ('=');

            if (kv.Length != 2)
            {
                throw new FormatException ($"Malformed parameter '{pair}' in {phc}");
            }

            switch (kv[0])
            {
                case "m": memory = int.Parse (kv[1]); break;
                case "t": iterations = int.Parse (kv[1]); break;
                case "p": parallelism = int.Parse (kv[1]); break;
            }
        }

        return new Phc (memory, iterations, parallelism, FromBase64 (parts[4]), FromBase64 (parts[5]), parts[4],
            parts[5]);
    }

    public static string Format (int memoryKiB, int iterations, int parallelism, byte[] salt, byte[] hash) =>
        $"$argon2id$v=19$m={memoryKiB},t={iterations},p={parallelism}${ToBase64 (salt)}${ToBase64 (hash)}";

    private static byte[] FromBase64 (string field) =>
        Convert.FromBase64String (field.PadRight (field.Length + (4 - field.Length % 4) % 4, '='));

    private static string ToBase64 (byte[] bytes) => Convert.ToBase64String (bytes).TrimEnd ('=');
}
