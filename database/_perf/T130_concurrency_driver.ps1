<#
.SYNOPSIS
    The half of T-130's concurrency harness that needs more than one connection at a time: a sign-in storm, the
    switch-versus-deactivate deadlock pair, and a connection coming back out of a pool.

.DESCRIPTION
    database/_perf/T130_concurrency_harness.sql measures everything one connection can see honestly -- lock footprints,
    the escalation point on auth.ProfilePermissionScope, the predicate's buffer-pool working set, and the lock ORDER of
    auth.uspSwitchProfile against auth.uspDeactivateProfile. Three of the five questions DES-AUTH-001 section 6 asks are
    not statement properties at all, and this file answers those:

      TEST P  THE POOLED CONNECTION. auth.uspSetSessionContext sets its five identity keys with @read_only = 1, so a
              connection that has been told who it is cannot be told otherwise (error 15664, UI-06, G-36). Every
              application in the world hands that connection back to a pool. If ADO.NET's sp_reset_connection does NOT
              clear SESSION_CONTEXT, the next caller to pick that connection up hits E-50022 on its first statement and
              the application is down. sp_reset_connection is issued by the CLIENT, so no T-SQL script can test this:
              only a pooling client can, which is what this is.

      TEST S  THE SIGN-IN STORM. Many connections driving the real auth.uspGetLoginVerifier / auth.uspVerifyMfa /
              auth.uspCompleteLogin path at once, with a sys.dm_os_wait_stats delta around it so the answer is WHAT they
              waited on and not just how long they took. Each worker signs in a DIFFERENT user, because a TOTP time step
              may be spent exactly once and two workers sharing a user would measure the MFA replay guard instead of
              contention.

      TEST D  THE DEADLOCK PAIR, WITH A POSITIVE CONTROL. Two connections replay the statement order the two procedures
              take -- the switch writing auth.UserSession, the deactivation writing auth.UserProfile and then
              auth.UserSession -- and count error 1205. Then, unless -SkipPositiveControl is given, it runs the SAME
              pair with one change: the switch holds its auth.UserSession write while taking a lock on
              auth.UserProfile, which is the shape auth.uspSwitchProfile would have if its early COMMIT were moved
              down. That variant deadlocks on purpose. Without it, "no deadlocks found" and "the harness is broken"
              look identical, and this file would be worthless.

    WHY TEST D REPLAYS THE ORDER RATHER THAN CALLING THE TWO PROCEDURES. Calling auth.uspDeactivateProfile for real
    needs an administrator who may deactivate that profile, signed in, elevated and switched to a hat that carries the
    permission -- and calling auth.uspSwitchProfile for real spends the connection it was called on, so each iteration
    would need a fresh sign-in. That is a fixture, not a measurement, and every part of it can fail for reasons that
    have nothing to do with lock order. The replay isolates the question: it takes the same locks on the same rows in
    the same order, in transactions that are ROLLED BACK, so no profile is deactivated and no session is moved. The
    harness's section 4 is what proves the replayed order is still the deployed one.

    NOTHING THIS FILE DOES IS PERMANENT, with one exception that is reported: the storm creates real sessions through
    the real sign-in path, because a fake sign-in would not measure the sign-in path. They are ended at the end of the
    test by one administrative UPDATE, identified by the client address the storm signs in from.

.PARAMETER ServerInstance
    The SQL Server instance. Defaults to MDE-55TT2J4.

.PARAMETER DatabaseName
    The target database. Must be populated: the storm needs distinct users with a confirmed TOTP factor, and the
    deadlock test needs a session that is wearing a profile. Defaults to testTemplateS1.

.PARAMETER StormWorkers
    Simultaneous connections in the sign-in storm. Defaults to 16. The interesting number on a given box is the one
    where the wait delta stops being flat; raise it until it does.

.PARAMETER SignInsPerWorker
    Sign-ins each storm worker performs, each as a different user. Defaults to 8.

.PARAMETER DeadlockIterations
    Iterations each side of the deadlock pair runs. Defaults to 80. A deadlock is a race; a low number proves nothing,
    which is what the positive control is for.

.PARAMETER SkipPositiveControl
    Do not run the deliberately deadlocking variant. The report then says the deadlock result is UNVERIFIED, because it
    is.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File database/_perf/T130_concurrency_driver.ps1 `
        -DatabaseName testTemplateS1

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File database/_perf/T130_concurrency_driver.ps1 `
        -DatabaseName testTemplateS1 -StormWorkers 48 -SignInsPerWorker 4
    A wider storm. 192 sign-ins, 48 at a time.

.NOTES
    Task T-130, gap G-49. Run database/_perf/T130_concurrency_harness.sql first: it reports the single-connection half
    and refuses to run against an unpopulated database, which is the check this file does not repeat.

    pwsh is not installed on the development box these conventions were written on, so this file is Windows PowerShell
    5.1 compatible: System.Data.SqlClient rather than Microsoft.Data.SqlClient, and runspaces rather than
    ForEach-Object -Parallel.
#>
[CmdletBinding()]
param
(
    [string] $ServerInstance      = 'MDE-55TT2J4',
    [string] $DatabaseName        = 'testTemplateS1',
    [int]    $StormWorkers        = 16,
    [int]    $SignInsPerWorker    = 8,
    [int]    $DeadlockIterations  = 80,
    [switch] $SkipPositiveControl
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$StormAddress = '203.0.113.131'
$MaxPool      = [Math]::Max(32, $StormWorkers + 8)

# Encrypt plus TrustServerCertificate is what sqlcmd -C means, and -C is mandatory on this instance.
$BaseCs  = "Server=$ServerInstance;Database=$DatabaseName;Integrated Security=SSPI;Encrypt=True;" +
           "TrustServerCertificate=True;Application Name=T130-driver;Pooling=True;Max Pool Size=$MaxPool"
$Findings = New-Object System.Collections.ArrayList

function Add-Finding
{
    param ([string] $Status, [string] $Question, [string] $Item, [string] $Detail)

    $null = $Findings.Add([pscustomobject] @{
        Status   = $Status
        Question = $Question
        Item     = $Item
        Detail   = $Detail
    })
}

function Open-Connection
{
    param ([string] $ConnectionString = $BaseCs)

    $c = New-Object System.Data.SqlClient.SqlConnection $ConnectionString
    $c.Open()
    return $c
}

function Invoke-Scalar
{
    param ($Connection, [string] $Sql)

    $cmd = $Connection.CreateCommand()
    $cmd.CommandText = $Sql
    $cmd.CommandTimeout = 600
    try   { return $cmd.ExecuteScalar() }
    finally { $cmd.Dispose() }
}

function Invoke-NonQuery
{
    param ($Connection, [string] $Sql)

    $cmd = $Connection.CreateCommand()
    $cmd.CommandText = $Sql
    $cmd.CommandTimeout = 600
    try   { return $cmd.ExecuteNonQuery() }
    finally { $cmd.Dispose() }
}

function Get-Rows
{
    param ($Connection, [string] $Sql)

    $cmd = $Connection.CreateCommand()
    $cmd.CommandText = $Sql
    $cmd.CommandTimeout = 600
    $table = New-Object System.Data.DataTable
    try
    {
        $reader = $cmd.ExecuteReader()
        $table.Load($reader)
        $reader.Close()
    }
    finally { $cmd.Dispose() }

    # THE COMMA IS NOT A TYPO AND REMOVING IT BREAKS EVERY CALLER.  PowerShell unrolls anything enumerable on the way
    # out of a function, and a DataTable enumerates its DataRows -- so `return $table` hands the caller an ARRAY OF ROWS,
    # and every `$result.Rows.Count` below then fails with "The property 'Rows' cannot be found on this object" under
    # Set-StrictMode.  Wrapping in a single-element array makes the unrolling give back the DataTable itself.
    return ,$table
}

function Write-Wrapped
{
    param ([string] $Text, [int] $Width = 112, [string] $Indent = '         ')

    $words = $Text -split '\s+'
    $line  = ''
    foreach ($w in $words)
    {
        if ($line.Length -gt 0 -and ($line.Length + 1 + $w.Length) -gt $Width)
        {
            Write-Host ($Indent + $line)
            $line = $w
        }
        else
        {
            $line = if ($line.Length -eq 0) { $w } else { "$line $w" }
        }
    }
    if ($line.Length -gt 0) { Write-Host ($Indent + $line) }
}

Write-Host ''
Write-Host "T130 concurrency driver: $ServerInstance / $DatabaseName"
Write-Host ''

# =====================================================================================================================
# TEST P.  Section 6, fifth bullet.  The pooled connection and sp_reset_connection.
#
#   Max Pool Size = 1 is what makes this a test rather than a hope: with one connection in the pool, the second Open
#   MUST hand back the same physical connection, and the SPID comparison proves it did. Anything else and the test is
#   inconclusive, which it says rather than passing.
# =====================================================================================================================
Write-Host 'TEST P  the pooled connection ...'

$poolCs = "Server=$ServerInstance;Database=$DatabaseName;Integrated Security=SSPI;Encrypt=True;" +
          "TrustServerCertificate=True;Application Name=T130-pool;Pooling=True;Max Pool Size=1;Min Pool Size=0"

$c1     = Open-Connection $poolCs
$spid1  = [int] (Invoke-Scalar $c1 'SELECT @@SPID;')
$null   = Invoke-NonQuery $c1 "EXEC sys.sp_set_session_context @key = N'T130Pool', @value = 4242, @read_only = 1;"
$seen1  = Invoke-Scalar $c1 "SELECT CAST (SESSION_CONTEXT (N'T130Pool') AS INT);"
$c1.Close()

$c2     = Open-Connection $poolCs
$spid2  = [int] (Invoke-Scalar $c2 'SELECT @@SPID;')
$seen2  = Invoke-Scalar $c2 "SELECT CAST (SESSION_CONTEXT (N'T130Pool') AS INT);"

# If the keys really are gone, setting the same read-only key again must succeed. That is the property the next user of
# a pooled connection depends on, and it is not the same claim as "the value reads back NULL".
$resettable = $false
try
{
    $null = Invoke-NonQuery $c2 "EXEC sys.sp_set_session_context @key = N'T130Pool', @value = 99, @read_only = 1;"
    $resettable = $true
}
catch { $resettable = $false }

$c2.Close()

if ($spid1 -ne $spid2)
{
    Add-Finding 'INCONCLUSIVE' '6.5 pooled connections' 'sp_reset_connection and SESSION_CONTEXT' (
        "The pool handed back a DIFFERENT connection (SPID $spid1 then $spid2) even at Max Pool Size = 1, so nothing " +
        "was reused and the test measured nothing. Re-run; if it persists, something is closing connections out from " +
        "under the pool.")
}
elseif (($null -eq $seen2 -or $seen2 -is [System.DBNull]) -and $resettable)
{
    Add-Finding 'OK' '6.5 pooled connections' 'sp_reset_connection and SESSION_CONTEXT' (
        "The same physical connection (SPID $spid1) came back out of the pool with SESSION_CONTEXT EMPTY -- the key " +
        "read $seen1 before the Close and NULL after the Open -- and a read-only key of the same name could be set " +
        "again. ADO.NET's sp_reset_connection clears session context, so the template's read-only identity keys are " +
        "safe under pooling: every pooled connection starts blank and auth.uspSetSessionContext sets it for the new " +
        "caller. This is the single fact the whole session-context design rests on under a real application, and it " +
        "is now measured rather than assumed.")
}
else
{
    Add-Finding 'RISK' '6.5 pooled connections' 'sp_reset_connection and SESSION_CONTEXT' (
        "The same physical connection (SPID $spid1) came back out of the pool still carrying SESSION_CONTEXT " +
        "(value read back: $seen2; the key could be re-set: $resettable). Every one of the five identity keys is set " +
        "@read_only = 1, so the next caller cannot overwrite them and auth.uspSetSessionContext will raise E-50022 on " +
        "its first statement. That is an outage rather than a disclosure -- which is the design working -- but it is " +
        "an outage on every pooled reuse, and the application layer must call sp_reset_connection explicitly or " +
        "disable pooling.")
}

# =====================================================================================================================
# TEST S.  Section 6, first bullet.  The sign-in storm.
# =====================================================================================================================
Write-Host 'TEST S  the sign-in storm ...'

$setup   = Open-Connection
$needed  = $StormWorkers * $SignInsPerWorker
$step    = [long] [Math]::Floor([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() / 30)

# A user is usable by the storm only if the whole path can succeed for it: a confirmed TOTP factor whose last used time
# step is BEHIND the current one (a step may be spent once, ever), an active default profile, and a usable tenant.
$users = Get-Rows $setup @"
SELECT TOP ($needed) UserName = u.UserName, TenantCode = t.TenantCode
  FROM auth.[User]            AS u
 INNER JOIN auth.UserProfile  AS p ON p.UserId   = u.UserId   AND p.IsDeleted = 0 AND p.IsActive = 1 AND p.IsDefault = 1
 INNER JOIN auth.Tenant       AS t ON t.TenantId = p.TenantId AND t.IsDeleted = 0
 WHERE u.IsDeleted   = 0
   AND u.IsActive    = 1
   AND u.IsLockedOut = 0
   AND auth.udfIsTenantUsable (p.TenantId) = 1
   AND EXISTS (SELECT 1 FROM auth.UserMfaFactor AS m
                WHERE m.UserId = u.UserId AND m.FactorType = 'Totp' AND m.IsConfirmed = 1 AND m.IsDeleted = 0
                  AND COALESCE (m.LastUsedTimeStep, -1) < $step)
 ORDER BY u.UserId;
"@

if ($users.Rows.Count -lt $StormWorkers)
{
    Add-Finding 'SKIPPED' '6.1 sign-in storm' 'Concurrent sign-ins through the real path' (
        "Only $($users.Rows.Count) usable user(s) found; a storm needs at least one per worker and a DIFFERENT user " +
        "per sign-in, because a TOTP time step may be spent exactly once. Load a scenario population, or lower " +
        "-StormWorkers.")
}
else
{
    $waitSql = @"
SELECT WaitType = wait_type, Tasks = waiting_tasks_count, WaitMs = wait_time_ms
  FROM sys.dm_os_wait_stats
 WHERE wait_type LIKE 'LCK_M_%' OR wait_type LIKE 'PAGELATCH%' OR wait_type IN ('WRITELOG', 'PAGEIOLATCH_SH');
"@
    $before = @{}
    foreach ($r in (Get-Rows $setup $waitSql).Rows) { $before[$r.WaitType] = [pscustomobject] @{ Tasks = [long] $r.Tasks; WaitMs = [long] $r.WaitMs } }

    # One slice of users per worker, so no two workers ever touch the same TOTP factor.
    $slices = @()
    for ($w = 0; $w -lt $StormWorkers; $w++)
    {
        $slice = @()
        for ($i = $w; $i -lt $users.Rows.Count; $i += $StormWorkers)
        {
            if ($slice.Count -lt $SignInsPerWorker) { $slice += ,@($users.Rows[$i].UserName, $users.Rows[$i].TenantCode) }
        }
        $slices += ,$slice
    }

    $worker = {
        param ($ConnectionString, $Slice, $ClientAddress, $TimeStep)

        $result = [pscustomobject] @{ Ok = 0; Errors = @(); Latencies = @(); Messages = @() }
        $conn   = New-Object System.Data.SqlClient.SqlConnection $ConnectionString
        $conn.Open()
        $rng = New-Object System.Random ([int] (Get-Random))

        foreach ($pair in $Slice)
        {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            try
            {
                # [System.Data.SqlDbType]:: IS NOT DECORATION, AND A BARE STRING HERE IS A SILENT DEFECT.
                # SqlParameterCollection carries an obsolete Add (String, Object) overload, and PowerShell binds a plain
                # string to THAT rather than to Add (String, SqlDbType) -- so Add('@LoginAttemptId', 'BigInt') adds an
                # NVARCHAR parameter whose VALUE is the string "BigInt". Input parameters get away with it because the
                # .Value assignment that follows re-infers the type; an OUTPUT parameter has nothing to infer from, so
                # the procedure's bigint output has nowhere to go and every call dies with error 8114, "Error converting
                # data type bigint to nvarchar". That is exactly how this storm first reported 0 sign-ins out of 128.
                $get = $conn.CreateCommand()
                $get.CommandType = 'StoredProcedure'
                $get.CommandText = 'auth.uspGetLoginVerifier'
                $null = $get.Parameters.Add('@ApplicationCode', [System.Data.SqlDbType]::NVarChar,  50).Value = 'TEMPLATE'
                $null = $get.Parameters.Add('@UserName',        [System.Data.SqlDbType]::NVarChar, 256).Value = $pair[0]
                $null = $get.Parameters.Add('@ClientAddress',   [System.Data.SqlDbType]::NVarChar,  45).Value = $ClientAddress
                $null = $get.Parameters.Add('@TenantCode',      [System.Data.SqlDbType]::NVarChar,  50).Value = $pair[1]
                $null = $get.Parameters.Add('@UserAgent',       [System.Data.SqlDbType]::NVarChar, 512).Value = 'T130_storm'
                $pAtt = $get.Parameters.Add('@LoginAttemptId',  [System.Data.SqlDbType]::BigInt);  $pAtt.Direction = 'Output'
                $pPhc = $get.Parameters.Add('@VerifierPhc',     [System.Data.SqlDbType]::NVarChar, 512); $pPhc.Direction = 'Output'
                $pMfa = $get.Parameters.Add('@RequiresMfa',     [System.Data.SqlDbType]::Bit);     $pMfa.Direction = 'Output'
                $null = $get.ExecuteNonQuery()
                $attempt = [long] $pAtt.Value
                $mfa     = [bool] $pMfa.Value
                $get.Dispose()

                if ($mfa)
                {
                    $ver = $conn.CreateCommand()
                    $ver.CommandType = 'StoredProcedure'
                    $ver.CommandText = 'auth.uspVerifyMfa'
                    $null = $ver.Parameters.Add('@LoginAttemptId', [System.Data.SqlDbType]::BigInt).Value = $attempt
                    $null = $ver.Parameters.Add('@TimeStep',       [System.Data.SqlDbType]::BigInt).Value = $TimeStep
                    $null = $ver.Parameters.Add('@FactorType',     [System.Data.SqlDbType]::VarChar, 20).Value = 'Totp'
                    $pSat = $ver.Parameters.Add('@MfaSatisfied',   [System.Data.SqlDbType]::Bit); $pSat.Direction = 'Output'
                    $null = $ver.ExecuteNonQuery()
                    $ver.Dispose()
                }

                $hash = New-Object byte[] 32
                (New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($hash)

                $fin = $conn.CreateCommand()
                $fin.CommandType = 'StoredProcedure'
                $fin.CommandText = 'auth.uspCompleteLogin'
                $null = $fin.Parameters.Add('@LoginAttemptId',   [System.Data.SqlDbType]::BigInt).Value    = $attempt
                $null = $fin.Parameters.Add('@PasswordVerified', [System.Data.SqlDbType]::Bit).Value       = $true
                $null = $fin.Parameters.Add('@SessionTokenHash', [System.Data.SqlDbType]::VarBinary, 32).Value = $hash
                $null = $fin.Parameters.Add('@IsBypassRoute',    [System.Data.SqlDbType]::Bit).Value       = $false
                $pSid = $fin.Parameters.Add('@UserSessionId',      [System.Data.SqlDbType]::BigInt);    $pSid.Direction = 'Output'
                $pUid = $fin.Parameters.Add('@UserId',             [System.Data.SqlDbType]::Int);       $pUid.Direction = 'Output'
                $pMcp = $fin.Parameters.Add('@MustChangePassword', [System.Data.SqlDbType]::Bit);       $pMcp.Direction = 'Output'
                $pAbs = $fin.Parameters.Add('@AbsoluteExpiryUtc',  [System.Data.SqlDbType]::DateTime2); $pAbs.Direction = 'Output'
                $pIdl = $fin.Parameters.Add('@IdleExpiryUtc',      [System.Data.SqlDbType]::DateTime2); $pIdl.Direction = 'Output'
                $null = $fin.ExecuteNonQuery()
                $fin.Dispose()

                $result.Ok++
            }
            catch
            {
                # THE UNWRAPPING IS NOT DEFENSIVE PROGRAMMING, IT IS THE DIFFERENCE BETWEEN A MEASUREMENT AND A SHRUG.
                # PowerShell wraps an exception thrown by a .NET METHOD CALL in a MethodInvocationException, so
                # `$_.Exception -is [SqlException]` is FALSE for every SQL error raised by ExecuteNonQuery, and the first
                # run of this test reported 128 failures all numbered -1: true, useless, and indistinguishable from a
                # client-side bug. The message is kept for the same reason -- a number identifies the refusal only to a
                # reader who already knows the catalogue, and three messages cost nothing to carry.
                $ex = $_.Exception
                while ($null -ne $ex -and -not ($ex -is [System.Data.SqlClient.SqlException]) -and $null -ne $ex.InnerException)
                {
                    $ex = $ex.InnerException
                }
                $n = if ($ex -is [System.Data.SqlClient.SqlException]) { $ex.Number } else { -1 }
                $result.Errors += $n
                if ($result.Messages.Count -lt 3) { $result.Messages += ('{0}: {1}' -f $n, $ex.Message) }
            }
            $sw.Stop()
            $result.Latencies += $sw.Elapsed.TotalMilliseconds
            [System.Threading.Thread]::Sleep($rng.Next(0, 15))
        }

        $conn.Close()
        return $result
    }

    $pool = [runspacefactory]::CreateRunspacePool(1, $StormWorkers)
    $pool.Open()
    $handles = @()
    $stormSw = [System.Diagnostics.Stopwatch]::StartNew()

    foreach ($slice in $slices)
    {
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool
        $null = $ps.AddScript($worker).AddArgument($BaseCs).AddArgument($slice).AddArgument($StormAddress).AddArgument($step)
        $handles += ,[pscustomobject] @{ Ps = $ps; Handle = $ps.BeginInvoke() }
    }

    $ok = 0; $errs = @(); $lat = @(); $msgs = @()
    foreach ($h in $handles)
    {
        $out = $h.Ps.EndInvoke($h.Handle)
        foreach ($r in $out) { $ok += $r.Ok; $errs += $r.Errors; $lat += $r.Latencies; $msgs += $r.Messages }
        $h.Ps.Dispose()
    }
    $stormSw.Stop()
    $pool.Close()
    $pool.Dispose()

    $after = @{}
    foreach ($r in (Get-Rows $setup $waitSql).Rows) { $after[$r.WaitType] = [pscustomobject] @{ Tasks = [long] $r.Tasks; WaitMs = [long] $r.WaitMs } }

    $deltas = @()
    foreach ($k in $after.Keys)
    {
        $b = if ($before.ContainsKey($k)) { $before[$k] } else { [pscustomobject] @{ Tasks = 0; WaitMs = 0 } }
        $dt = $after[$k].Tasks  - $b.Tasks
        $dm = $after[$k].WaitMs - $b.WaitMs
        if ($dt -gt 0 -or $dm -gt 0) { $deltas += ,[pscustomobject] @{ WaitType = $k; Waits = $dt; WaitMs = $dm } }
    }
    # @() again, and for the StrictMode reason: Sort-Object hands back a bare object when the pipeline held ONE item,
    # and a bare PSCustomObject has no .Count for the two tests below to read.
    $deltas = @($deltas | Sort-Object -Property WaitMs -Descending)

    $sorted = @($lat | Sort-Object)
    $p50 = if ($sorted.Count -gt 0) { [Math]::Round($sorted[[int] [Math]::Floor($sorted.Count * 0.50)], 1) } else { 0 }
    $p95 = if ($sorted.Count -gt 0) { [Math]::Round($sorted[[int] [Math]::Min($sorted.Count - 1, [Math]::Floor($sorted.Count * 0.95))], 1) } else { 0 }
    $max = if ($sorted.Count -gt 0) { [Math]::Round(($sorted | Select-Object -Last 1), 1) } else { 0 }
    $secs = [Math]::Max(0.001, $stormSw.Elapsed.TotalSeconds)
    $rate = [Math]::Round($ok / $secs, 1)

    $errText = if ($errs.Count -eq 0) { 'no failures' }
               else { 'failures: ' + (($errs | Group-Object | ForEach-Object { "$($_.Count)x error $($_.Name)" }) -join ', ') +
                      '. First message(s): ' + ((@($msgs) | Select-Object -Unique -First 2) -join ' || ') }

    $waitText = if ($deltas.Count -eq 0) { 'NO measurable lock, latch or log wait accumulated on the whole instance during the storm' }
                else { 'waits accumulated: ' + (($deltas | Select-Object -First 6 | ForEach-Object { "$($_.WaitType) $($_.Waits) waits / $($_.WaitMs) ms" }) -join '; ') }

    # Summed by hand rather than with Measure-Object -Sum, because Measure-Object emits NOTHING at all for an empty
    # pipeline, and .Sum on nothing is a StrictMode error rather than a zero -- and "no lock waits at all" is the
    # expected result here, so the empty case is the normal case.
    $lockWaits = 0
    foreach ($d in $deltas) { if ($d.WaitType -like 'LCK_M_*') { $lockWaits += [long] $d.WaitMs } }

    # A thousand milliseconds of LOCK waiting across the whole storm is the line between "sign-ins do not block each
    # other", which is the design, and "something in the path serializes", which would need explaining.
    # And a storm in which nothing completed has measured nothing: 0 sign-ins with 128 failures would otherwise be
    # reported as "no lock waiting", which is true and worthless. A separate verdict, because the subject is the harness.
    $stormStatus = if ($ok -eq 0) { 'INCONCLUSIVE' } elseif ($lockWaits -gt 1000) { 'RISK' } else { 'OK' }

    Add-Finding $stormStatus '6.1 sign-in storm' 'Concurrent sign-ins through the real path' (
        "$ok sign-in(s) completed on $StormWorkers simultaneous connections in $([Math]::Round($secs,1))s -- " +
        "$rate per second, p50 $p50 ms, p95 $p95 ms, max $max ms, $errText. Instance-wide $waitText. Of that, " +
        "$lockWaits ms was LOCK waiting: sign-ins do not block each other on rows, because each one inserts its own " +
        "auth.UserSession row. What DOES serialize at volume is the latch on the last page of the clustered index and " +
        "the log flush, which is why PAGELATCH and WRITELOG are in the wait filter above and why the harness reports " +
        "whether OPTIMIZE_FOR_SEQUENTIAL_KEY is on. These numbers are from a development instance with one client " +
        "machine: the shape is transferable, the absolute values are not.")

    # ONE administrative UPDATE rather than auth.uspEndSession per session, and the reason is UI-06: ending a session
    # through the procedure needs that session's token hash on a connection that is allowed to act as it, and a
    # connection that has been given one identity cannot be given another. Sixteen hundred sign-ins would need sixteen
    # hundred connections. This is a test fixture cleaning up after itself, not a model of how an application ends a
    # session.
    $ended = Invoke-Scalar $setup @"
UPDATE auth.UserSession
   SET EndedUtc        = SYSUTCDATETIME ()
     , EndReason       = 'Revoked'
     , auditModifiedBy = N'T130_driver'
 WHERE ClientAddress = N'$StormAddress' AND EndedUtc IS NULL AND IsDeleted = 0;
SELECT @@ROWCOUNT;
"@
    Write-Host "        (ended $ended storm session(s) -- the storm signs in for real, so it has to clean up after itself.)"
}

# =====================================================================================================================
# TEST D.  Section 6, fourth bullet.  The switch-versus-deactivate pair, and the control that proves detection works.
# =====================================================================================================================
Write-Host 'TEST D  the deadlock pair ...'

$fixture = Get-Rows $setup @"
SELECT TOP (1) UserSessionId = s.UserSessionId, UserProfileId = s.ActiveUserProfileId
  FROM auth.UserSession AS s
 WHERE s.ActiveUserProfileId IS NOT NULL AND s.IsDeleted = 0
 ORDER BY s.UserSessionId DESC;
"@

if ($fixture.Rows.Count -eq 0)
{
    Add-Finding 'SKIPPED' '6.4 switch versus deactivate' 'The pair, replayed from two connections' (
        "No session in auth.UserSession is wearing a profile, so there is no row the two orders can contend over. " +
        "Run database/_scenarios/S1_prove_duties.sql, or any smoke test that switches a profile, and try again.")
}
else
{
    # NOT a variable called p-i-d.  That name is a read-only automatic holding this process's own id, and assigning
    # to it throws before the test gets anywhere near the database.
    $sid    = [long] $fixture.Rows[0].UserSessionId
    $profId = [int]  $fixture.Rows[0].UserProfileId

    # The switch's transaction: auth.UserSession, then COMMIT. With $Control, the profile lock is taken BEFORE the
    # rollback and while the session lock is still held -- the shape the procedure would have if its early COMMIT moved.
    $switchSide = {
        param ($ConnectionString, $SessionId, $ProfileId, $Iterations, $Control)

        $deadlocks = 0; $other = 0; $msgs = @()
        $conn = New-Object System.Data.SqlClient.SqlConnection $ConnectionString
        $conn.Open()
        $rng = New-Object System.Random ([int] (Get-Random))

        $sql = @"
SET XACT_ABORT OFF;
BEGIN TRANSACTION;
UPDATE auth.UserSession SET LastSeenUtc = LastSeenUtc WHERE UserSessionId = @sid;
WAITFOR DELAY '00:00:00.030';
"@
        if ($Control)
        {
            $sql += "DECLARE @sink INT; SELECT @sink = p.UserProfileId FROM auth.UserProfile AS p WITH (UPDLOCK) WHERE p.UserProfileId = @pid;`n"
        }
        $sql += "IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;"

        for ($i = 0; $i -lt $Iterations; $i++)
        {
            $cmd = $conn.CreateCommand()
            $cmd.CommandText = $sql
            $cmd.CommandTimeout = 60
            $null = $cmd.Parameters.Add('@sid', [System.Data.SqlDbType]::BigInt).Value = $SessionId
            $null = $cmd.Parameters.Add('@pid', [System.Data.SqlDbType]::Int).Value    = $ProfileId
            try { $null = $cmd.ExecuteNonQuery() }
            catch
            {
                # Unwrapped for the reason the storm's catch explains at length: error 1205 arrives inside a
                # MethodInvocationException, so a test that compares $_.Exception directly can NEVER see a deadlock and
                # reports "no deadlock" forever -- positive control included, which is how this was found.
                $ex = $_.Exception
                while ($null -ne $ex -and -not ($ex -is [System.Data.SqlClient.SqlException]) -and $null -ne $ex.InnerException)
                {
                    $ex = $ex.InnerException
                }
                if ($ex -is [System.Data.SqlClient.SqlException] -and $ex.Number -eq 1205) { $deadlocks++ }
                else { $other++; if ($msgs.Count -lt 2) { $msgs += $ex.Message } }
                # A deadlock victim's transaction is already rolled back, but an aborted batch can leave one open, so
                # the connection is cleared before the next iteration rather than accumulating an open transaction that
                # would hold locks for the rest of the run and turn every later iteration into a false positive.
                if ($conn.State -ne 'Open') { $conn.Close(); $conn.Open() }
                else { $c2 = $conn.CreateCommand(); $c2.CommandText = 'IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;'; try { $null = $c2.ExecuteNonQuery() } catch { }; $c2.Dispose() }
            }
            $cmd.Dispose()
            [System.Threading.Thread]::Sleep($rng.Next(0, 10))
        }

        $conn.Close()
        return [pscustomobject] @{ Side = 'switch'; Deadlocks = $deadlocks; Other = $other; Messages = $msgs }
    }

    # The deactivation's transaction, in its deployed order: auth.UserProfile first, then auth.UserSession.
    $deactivateSide = {
        param ($ConnectionString, $SessionId, $ProfileId, $Iterations)

        $deadlocks = 0; $other = 0; $msgs = @()
        $conn = New-Object System.Data.SqlClient.SqlConnection $ConnectionString
        $conn.Open()
        $rng = New-Object System.Random ([int] (Get-Random))

        $sql = @"
SET XACT_ABORT OFF;
BEGIN TRANSACTION;
UPDATE auth.UserProfile SET auditModifiedBy = auditModifiedBy WHERE UserProfileId = @pid;
WAITFOR DELAY '00:00:00.030';
UPDATE auth.UserSession SET LastSeenUtc = LastSeenUtc WHERE ActiveUserProfileId = @pid AND EndedUtc IS NULL;
IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
"@
        for ($i = 0; $i -lt $Iterations; $i++)
        {
            $cmd = $conn.CreateCommand()
            $cmd.CommandText = $sql
            $cmd.CommandTimeout = 60
            $null = $cmd.Parameters.Add('@pid', [System.Data.SqlDbType]::Int).Value = $ProfileId
            try { $null = $cmd.ExecuteNonQuery() }
            catch
            {
                # Unwrapped for the reason the storm's catch explains at length: error 1205 arrives inside a
                # MethodInvocationException, so a test that compares $_.Exception directly can NEVER see a deadlock and
                # reports "no deadlock" forever -- positive control included, which is how this was found.
                $ex = $_.Exception
                while ($null -ne $ex -and -not ($ex -is [System.Data.SqlClient.SqlException]) -and $null -ne $ex.InnerException)
                {
                    $ex = $ex.InnerException
                }
                if ($ex -is [System.Data.SqlClient.SqlException] -and $ex.Number -eq 1205) { $deadlocks++ }
                else { $other++; if ($msgs.Count -lt 2) { $msgs += $ex.Message } }
                if ($conn.State -ne 'Open') { $conn.Close(); $conn.Open() }
                else { $c2 = $conn.CreateCommand(); $c2.CommandText = 'IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;'; try { $null = $c2.ExecuteNonQuery() } catch { }; $c2.Dispose() }
            }
            $cmd.Dispose()
            [System.Threading.Thread]::Sleep($rng.Next(0, 10))
        }

        $conn.Close()
        return [pscustomobject] @{ Side = 'deactivate'; Deadlocks = $deadlocks; Other = $other; Messages = $msgs }
    }

    function Invoke-Pair
    {
        param ([bool] $Control)

        $pool = [runspacefactory]::CreateRunspacePool(1, 2)
        $pool.Open()

        $a = [powershell]::Create(); $a.RunspacePool = $pool
        $null = $a.AddScript($switchSide).AddArgument($BaseCs).AddArgument($sid).AddArgument($profId).AddArgument($DeadlockIterations).AddArgument($Control)
        $b = [powershell]::Create(); $b.RunspacePool = $pool
        $null = $b.AddScript($deactivateSide).AddArgument($BaseCs).AddArgument($sid).AddArgument($profId).AddArgument($DeadlockIterations)

        $ha = $a.BeginInvoke(); $hb = $b.BeginInvoke()
        $ra = $a.EndInvoke($ha); $rb = $b.EndInvoke($hb)
        $a.Dispose(); $b.Dispose(); $pool.Close(); $pool.Dispose()

        $dl = 0; $ot = 0; $ms = @()
        foreach ($r in @($ra) + @($rb)) { if ($null -ne $r) { $dl += $r.Deadlocks; $ot += $r.Other; $ms += $r.Messages } }
        return [pscustomobject] @{ Deadlocks = $dl; Other = $ot; Messages = @(@($ms) | Select-Object -Unique) }
    }

    $faithful = Invoke-Pair $false
    Write-Host "        (deployed order: $($faithful.Deadlocks) deadlock(s), $($faithful.Other) other error(s) in $($DeadlockIterations * 2) transactions.)"

    $control = $null
    if (-not $SkipPositiveControl)
    {
        $control = Invoke-Pair $true
        Write-Host "        (positive control: $($control.Deadlocks) deadlock(s), $($control.Other) other error(s) in $($DeadlockIterations * 2) transactions.)"
    }

    if ($faithful.Deadlocks -gt 0)
    {
        Add-Finding 'RISK' '6.4 switch versus deactivate' 'The pair, replayed from two connections' (
            "$($faithful.Deadlocks) deadlock(s) in $($DeadlockIterations * 2) transactions replaying the DEPLOYED " +
            "order. A profile switch and a concurrent deactivation of the same profile can close a cycle on this " +
            "database, which means a user switching hats will occasionally see error 1205 while an administrator is " +
            "deactivating that hat. Check the harness's section 4a: something has moved the switch's COMMIT below its " +
            "auth.UserProfile read, or added an auth.UserProfile write inside its transaction.")
    }
    elseif ($null -ne $control -and $control.Deadlocks -gt 0)
    {
        Add-Finding 'OK' '6.4 switch versus deactivate' 'The pair, replayed from two connections' (
            "No deadlock in $($DeadlockIterations * 2) transactions replaying the deployed order, AND " +
            "$($control.Deadlocks) deadlock(s) in the same number of transactions replaying the one-line variant in " +
            "which the switch holds its auth.UserSession write while taking a lock on auth.UserProfile. The pair is " +
            "deadlock-free because auth.uspSwitchProfile COMMITS before it reads auth.UserProfile, and the control " +
            "proves this harness detects a cycle when there is one -- which is the only thing that makes the first " +
            "half of that sentence worth anything. The invariant is fragile and belongs in a code review checklist: " +
            "move that COMMIT down and the control's result becomes the real one.")
    }
    elseif ($null -ne $control)
    {
        Add-Finding 'INCONCLUSIVE' '6.4 switch versus deactivate' 'The pair, replayed from two connections' (
            "No deadlock in the deployed order and NONE IN THE POSITIVE CONTROL EITHER, so this run proves nothing: " +
            "the control is supposed to deadlock. The two orders reported $($faithful.Other) and $($control.Other) " +
            "NON-deadlock error(s)" +
            $(if ($control.Messages.Count -gt 0) { ' (' + ((@($control.Messages) | Select-Object -First 2) -join ' || ') + ')' } else { '' }) +
            ". If those counts are high the replay never ran and the messages say why; if they are zero the two sides " +
            "did not overlap -- raise -DeadlockIterations, or the instance is fast enough that the 30 ms WAITFOR no " +
            "longer interleaves them.")
    }
    else
    {
        Add-Finding 'UNVERIFIED' '6.4 switch versus deactivate' 'The pair, replayed from two connections' (
            "No deadlock in $($DeadlockIterations * 2) transactions replaying the deployed order. The positive " +
            "control was skipped, so this result is UNVERIFIED: a harness that has not been shown to detect a " +
            "deadlock cannot be quoted as evidence that there is none. Re-run without -SkipPositiveControl.")
    }
}

$setup.Close()

# =====================================================================================================================
# The report.
# =====================================================================================================================
Write-Host ''
Write-Host '--- T130 driver report ---------------------------------------------------------------------------------'
Write-Host ''

foreach ($f in $Findings)
{
    Write-Host ('[{0}] {1} -- {2}' -f $f.Status, $f.Question, $f.Item)
    Write-Wrapped $f.Detail
    Write-Host ''
}

$bad = @($Findings | Where-Object { $_.Status -in @('RISK', 'INCONCLUSIVE') })
Write-Host ('{0} finding(s): {1} OK, {2} needing attention.' -f $Findings.Count,
            @($Findings | Where-Object { $_.Status -eq 'OK' }).Count, $bad.Count)
Write-Host ''
Write-Host 'Read this beside database/_perf/T130_concurrency_harness.sql, which answers the two questions that do not'
Write-Host 'need concurrency -- the escalation point on auth.ProfilePermissionScope and the predicate''s working set --'
Write-Host 'and which reads the deployed lock ORDER that test D above replays.'

if ($bad.Count -gt 0) { exit 1 } else { exit 0 }
