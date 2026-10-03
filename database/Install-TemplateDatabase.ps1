<#
.SYNOPSIS
    Deploys the authentication and authorization template database, in order, with the sqlcmd switches these
    conventions require.

.DESCRIPTION
    Runs every script of the deployment in install order against one target database, stopping at the first failure.
    It exists because the switches are easy to get wrong in ways that fail quietly:

      -I   sqlcmd is the one client that defaults QUOTED_IDENTIFIER OFF. The setting is baked in at CREATE time, and a
           module carrying it OFF cannot run DML against a table with a filtered index -- error 1934, surfacing later,
           inside a procedure whose text is correct. Every unique constraint in this design is a filtered index by way
           of the soft-delete rule, so this is every table.

      -b   Without it, sqlcmd returns exit code 0 even when the batch raised an error. A deployment loop that does not
           pass -b reports success for a run that failed half way through. This is the single most important switch in
           this file.

      -v DbName=   Three of the installers assert it against DB_NAME () and stop if they disagree with -d. None of them
           carries an in-file default and none should: measured on sqlcmd 17, an in-file :setvar OVERRIDES -v rather
           than yielding to it, so a "harmless default" silently decides the target on every documented run.

    Idempotent by construction: every script is guarded, CREATE OR ALTER, MERGE, or a conditional ALTER. Running this
    twice is the supported way to prove that, and -VerifyIdempotent does it for you.

.PARAMETER ServerInstance
    The SQL Server instance. Defaults to MDE-55TT2J4.

.PARAMETER DatabaseName
    The target database. Created by 000_prerequisites.sql if it does not exist, reused if it does. Defaults to
    testTemplate.

.PARAMETER Credential
    SQL Server authentication. Omit for Windows integrated authentication, which is the default.

.PARAMETER VerifyIdempotent
    Run the whole sequence twice and compare. The second pass must change nothing; this is a Phase 0 exit criterion
    and the exercise the conventions skill's README asks for and that has never been performed.

.PARAMETER SkipVerification
    Skip the closing read-only checks (checkDbChangeLogging.sql and logs.uspDdlAuditVerify).

.PARAMETER BootstrapAdminVerifierPhc
    The PHC string for the first administrator's password, produced by the APPLICATION's own argon2id hasher. Supplying
    it runs 900_bootstrap_first_admin.sql after the deployment; omitting it skips that step entirely, and the database
    comes up with no user, no profile and no way in -- which is the correct state for a deployment whose administrator
    was created by an earlier run, because 900 refuses to run twice (E-50080).

    The five bootstrap values are passed to sqlcmd THROUGH THE ENVIRONMENT and not through -v. A -v value cannot
    contain a space -- no quoting form works, sqlcmd reports 'Name=a b': Invalid argument and exits -- and sqlcmd
    resolves $(Name) from -v first and from the process environment second. A display name has a space in it and a PHC
    string has commas and equals signs, so the environment is the only route that carries them intact. UI-42.

.PARAMETER BootstrapAdminUserName
    The first administrator's login name. Defaults to first.admin.

.PARAMETER BootstrapAdminDisplayName
    The first administrator's display name. Defaults to First Administrator.

.PARAMETER BootstrapAdminEmail
    The first administrator's email address. Defaults to first.admin@example.invalid, which is deliberately a domain
    that cannot receive mail -- a template should not ship a plausible address.

.PARAMETER BootstrapAppCode
    The application code 900 resolves the root tenant beneath. Defaults to TEMPLATE, which is what 115 seeds.

.EXAMPLE
    .\Install-TemplateDatabase.ps1
    Deploys to MDE-55TT2J4\testTemplate using Windows authentication.

.EXAMPLE
    .\Install-TemplateDatabase.ps1 -WhatIf
    Prints the exact sqlcmd command line for every script, in order, and runs nothing.

.EXAMPLE
    .\Install-TemplateDatabase.ps1 -VerifyIdempotent
    Deploys, then deploys again, and reports whether the second pass changed anything.

.NOTES
    PLAN-AUTH-001 task T-011.  Transcripts are written to database\_logs\, which .gitignore excludes -- a transcript
    names the server, the login that ran it, and every object in the database.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]                       $ServerInstance   = 'MDE-55TT2J4',
    [string]                       $DatabaseName     = 'testTemplate',
    [System.Management.Automation.PSCredential] $Credential,
    [switch]                       $VerifyIdempotent,
    [switch]                       $SkipVerification,
    [string]                       $BootstrapAdminVerifierPhc,
    [string]                       $BootstrapAdminUserName    = 'first.admin',
    [string]                       $BootstrapAdminDisplayName = 'First Administrator',
    [string]                       $BootstrapAdminEmail       = 'first.admin@example.invalid',
    [string]                       $BootstrapAppCode          = 'TEMPLATE'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot  = Split-Path -Parent $PSScriptRoot
$SkillRoot = Join-Path $RepoRoot '.claude/skills/ponytail-sql-objects'
$LogDir    = Join-Path $PSScriptRoot '_logs'

# ---------------------------------------------------------------------------------------------------------------------
# The manifest. Install order, which is NOT build order -- config tables install seventh and were built in Phase 4.
#
#   Database   : 'master' for the one script that creates the database, 'target' for everything else.
#   PassDbName : whether the script consumes $(DbName). extended-properties.sql and checkDbChangeLogging.sql do not.
#   RequiresAuth : the script asserts BOTH auth.Tenant and auth.UserProfile. Both exist from Phase 3 onwards --
#                  040_auth_userprofile.sql builds auth.User AND auth.UserProfile (T-046) -- so nothing in the manifest
#                  is skipped on a complete deployment any more. The flag and the probe are KEPT because a project that
#                  deploys a subset, or a database half way through an upgrade, still needs the named skip rather than a
#                  failure at step 18. Test-AuthSchemaPresent tests BOTH -- see the comment on it. Two files used to say
#                  Phase 2 here; that was BL-025.
#
# The order below is the dependency order each script DECLARES, not the numeric order of its filename. They no longer
# agree, and where they disagree the declaration wins -- ELEVEN orderings are load-bearing and none of them is obvious.
# This line said "six" from Phase 4 until the Phase 5-7 closeout, while the list beneath it grew to eleven: a count in
# prose next to the thing it counts is a count that goes stale, and the only fix is to re-count it when the list moves.
# The eleventh (140 -> 150) is not a manifest ordering at all but a RUN-TIME dependency that survives the install order
# only because of a guard, which is why it is stated here with the others rather than left to be discovered:
#   *  025_config_tables.sql installs before any auth table, because 110's procedures read settings out of it, and
#      120_rls_policy.sql builds the policy from config.TenantScopedTable. Install order is not build order.
#   *  100_auth_functions.sql installs after 065, not with the Phase 1 scripts: auth.tvfPermissionScope reads
#      auth.ProfilePermissionScope, and the three RLS predicates read it too.
#   *  105_auth_session_procedures.sql installs AFTER 110 and 112, out of numeric order, because
#      auth.uspSetSessionContext calls auth.uspEndSession when it finds an expired session. 105 only WARNS about the
#      absence -- deferred name resolution installs the procedure regardless -- so the cost of getting this wrong is a
#      warning in a transcript that looks like a defect and is not, which is reason enough to get it right.
#   *  165_logs_procedures.sql installs at 20, immediately after the logs tables it writes to and BEFORE EVERY
#      PROCEDURE SCRIPT -- far out of numeric order, and the least cosmetic ordering in the file. SIX scripts assert
#      its procedures at install time and throw without them: 125, 130, 140, 145, 160 and 150, the last because
#      auth.uspDemandPermission writes the denial trail through logs.uspRecordAuthorizationDenial. It was at 33, after
#      140, and the first clean-database build in the project's history stopped at step 29 saying so -- which is the
#      whole argument for building one. 165 itself needs only logs.AuthorizationChange, logs.AuthorizationDenial and
#      logs.DataChangeLog (085) plus the rule 8 logging pair, so 20 is the earliest point it CAN go and therefore the
#      point at which no later reordering can break it again. BL-058.
#   *  180_dbo_application_procedures.sql installs at 35, BEFORE 120_rls_policy.sql, and its own section 0 warns rather
#      than refuses when it finds no predicate on dbo.CaseFile. That looks backwards -- the procedures exist to be
#      constrained by the policy -- and it is the right way round for two reasons. Deferred name resolution means a
#      procedure compiles without its tables' policies, so nothing forces the other order; and 120 cannot run before 180
#      without paying for it, because a bound policy freezes the shape of dbo.CaseFile and the schema-bound predicate
#      functions (error 3729). The cost is a window, between step 35 and step 36, in which these ten procedures enforce
#      their own permission demands and NOTHING ELSE: every tenant's rows are visible to every profile and P-06 is not in
#      force. That window is inside one install pass and it is called out in 180's closing report as UNBOUND, which is why
#      a deployment that stops at step 35 must not be treated as a deployment.
#   *  120_rls_policy.sql installs third from last, after every script that creates or alters an object the policy
#      binds. A schema-bound function cannot be altered while a policy binds it (error 3729) and neither can the shape
#      of a protected table change, so 030, 065, 090 and 100 must all have finished first. Binding last has a second
#      benefit worth stating: no other script runs under an active policy, so no script's closing report can be
#      silently emptied by a predicate that denies the deploying session (UI-18). Invoke-PolicyDrop, below, is the other
#      half of this -- on a re-run the policy from last time is dropped before the pass begins.
#   *  175_perf_instrumentation.sql installs at 37, after 150_auth_query_procedures.sql and before
#      170_permissions.sql, and the dependency in both directions is worth stating because it runs the opposite way from
#      every other pair in this manifest. 175 needs 150 to have run, but NOT to install: its objects compile against
#      nothing in 150. What it needs 150 for is its closing report, which reads sys.sql_modules to check that
#      auth.uspDemandPermission actually contains the "-- 1b. The sampled probe" block, and would otherwise report a
#      correct deployment as NOT WIRED. The dependency the other way -- 150 calling logs.uspRecordPermissionProbe -- is a
#      runtime OBJECT_ID guard and not an install-time assertion, deliberately, so that 150 installs and works on a
#      database where 175 was never run and the probe simply never fires. That is the supported configuration for anybody
#      who does not want a measurement table in their database. T-070, G-22.
#   *  135_audit_triggers.sql installs at 38, second to last, and it is the only script in the manifest that creates
#      nothing at all. It is a standing assertion: every table carrying the audit block must have an update trigger that
#      maintains it, and a table that does not gets E-50211 -- which stops the install. It goes this late for two
#      reasons. It has to see every table, including logs.PermissionProbe, which does not exist until step 37 creates it;
#      and an assertion is worth most when it runs after the last thing that could have broken what it asserts. It is
#      ahead of 170 rather than behind it only because 170 must have the last word (below). Note what it does NOT demand:
#      33 of 34 tables pair IsDeleted with auditDeletedBy in a CHECK constraint, and on those the CALLER owns the
#      soft-delete stamp rather than the trigger, because SQL Server evaluates CHECK constraints BEFORE an AFTER trigger
#      fires. 135 reports those as CALLER and does not insist the trigger stamp a delete it can never see.
#   *  170_permissions.sql installs LAST, because it names objects across every schema and a GRANT or DENY on a missing
#      object is an error rather than a skip. That is also why 175 goes in front of it rather than behind it: 175 creates
#      logs.PermissionProbe and logs.vwPredicateFunctionStats, and 170 being the last word on who may read what is worth
#      more than the tidiness of ending the manifest on the number it started the decade with.
#   *  115_seed_reference_data.sql installs BEFORE 120_rls_policy.sql, and the gap between them is not cosmetic either:
#      120 resolves Data.Read's permission id out of auth.Permission and bakes the integer into three schema-bound
#      predicates. On a database where 115 has not run it finds nothing, substitutes the sentinel -1, and every
#      predicate denies every non-maintenance session -- fail-closed, correct in direction and baffling in practice
#      (UI-35). It also installs before 900_bootstrap_first_admin.sql needs it, because 115 owns the application, the
#      root tenant and the five roles the bootstrap grants by code (E-50086, E-50087).
#   *  140_auth_profile_procedures.sql CALLS 150_auth_query_procedures.sql at run time -- auth.uspSwitchProfile returns
#      the new profile's navigation through auth.uspGetNavigationForProfile (G-36, BL-057) -- and it still installs
#      first, at 29 against 34. That is safe only because the call site is wrapped in an OBJECT_ID guard: deferred name
#      resolution would install it either way, but a deployment that stopped between the two would otherwise have a
#      switch that throws instead of one that returns one result set short. Do not remove the guard to tidy it up.
# ---------------------------------------------------------------------------------------------------------------------
$Manifest = @(
    @{ Order =  1; Path = Join-Path $PSScriptRoot  '000_prerequisites.sql';                           Database = 'master'; PassDbName = $true;  RequiresAuth = $false; What = 'Server version, database create-if-absent, database options' }
    @{ Order =  2; Path = Join-Path $PSScriptRoot  '005_schemas_and_roles.sql';                       Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'Schemas auth/logs/config/util and the four database roles' }
    @{ Order =  3; Path = Join-Path $SkillRoot     'templates/extended-properties.sql';               Database = 'target'; PassDbName = $false; RequiresAuth = $false; What = 'util.uspSetObjectDescription -- everything downstream needs it' }
    @{ Order =  4; Path = Join-Path $SkillRoot     'scripts/logdBChanges.sql';                        Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'DDL change logging, so the rest of the deployment is recorded' }
    @{ Order =  5; Path = Join-Path $SkillRoot     'scripts/logExecutionLogging.sql';                 Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'logs.ExecutionLog and the four logging procedures' }
    @{ Order =  6; Path = Join-Path $SkillRoot     'scripts/permissions.sql';                         Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'Schema-level grants. Run AFTER the roles exist or every grant is silently skipped' }
    @{ Order =  7; Path = Join-Path $PSScriptRoot  '025_config_tables.sql';                           Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'config.ApplicationSetting and config.TenantScopedTable, seeded with the shipped defaults 110 reads' }
    @{ Order =  8; Path = Join-Path $PSScriptRoot  '030_auth_tenant.sql';                             Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'Tenancy -- auth.Application, auth.TenantType, auth.Tenant, auth.TenantClosure and their triggers' }
    @{ Order =  9; Path = Join-Path $PSScriptRoot  '035_auth_tenant_policy.sql';                      Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'auth.TenantAuthenticationPolicy and auth.TenantDefaultRole -- which routes a tenant allows' }
    @{ Order = 10; Path = Join-Path $PSScriptRoot  '040_auth_userprofile.sql';                        Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'auth.User -- the person, NOT tenant-scoped -- and auth.UserProfile, the hat they wear at one tenant (T-046)' }
    @{ Order = 11; Path = Join-Path $PSScriptRoot  '045_auth_identity.sql';                           Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'Credentials, password history, MFA factors, recovery codes, federated links, auth.LoginAttempt' }
    @{ Order = 12; Path = Join-Path $PSScriptRoot  '050_auth_permission.sql';                         Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'auth.PermissionCategory and auth.Permission -- the vocabulary. The 35 rows themselves are the Phase 6 seed (T-089)' }
    @{ Order = 13; Path = Join-Path $PSScriptRoot  '055_auth_role.sql';                               Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'auth.Role and auth.RolePermission -- the administrator vocabulary, and the only editable half of it' }
    @{ Order = 14; Path = Join-Path $PSScriptRoot  '060_auth_profile_role.sql';                       Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'auth.UserProfileRole -- the grant. One row per (profile, role, scope): who holds what authority, where' }
    @{ Order = 15; Path = Join-Path $PSScriptRoot  '065_auth_effective_permission.sql';               Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'auth.ProfilePermissionScope, the materialized effective grant, and the procedure that rebuilds one profile' }
    @{ Order = 16; Path = Join-Path $PSScriptRoot  '070_auth_session.sql';                            Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'auth.UserSession and its write-once EndedUtc trigger, and the INV-08 bypass CHECK' }
    @{ Order = 17; Path = Join-Path $PSScriptRoot  '075_auth_ui_catalog.sql';                         Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'auth.UiElement and auth.UiElementPermission -- the navigation catalogue, and what each element demands' }
    @{ Order = 18; Path = Join-Path $PSScriptRoot  '080_auth_registration.sql';                       Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'auth.OrganizationRegistration -- the Variant 3 queue, and the only table an unauthenticated caller writes to' }
    @{ Order = 19; Path = Join-Path $PSScriptRoot  '085_logs_auth_tables.sql';                        Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'The logs-side audit tables the authentication, authorization and domain procedures write to' }
    @{ Order = 20; Path = Join-Path $PSScriptRoot  '165_logs_procedures.sql';                         Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'The three trail recorders. Immediately after the tables they write to, and BEFORE every procedure script -- six of them assert these three and throw without them' }
    @{ Order = 21; Path = Join-Path $PSScriptRoot  '090_dbo_application.sql';                         Database = 'target'; PassDbName = $true;  RequiresAuth = $true;  What = 'The demo domain -- dbo.CaseFile and dbo.CaseNote, the two tables 120 binds the policy to' }
    @{ Order = 22; Path = Join-Path $PSScriptRoot  '095_auth_views.sql';                              Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'auth.vwTenantHierarchy. A view resolves names at CREATE time, so it installs BEFORE the function it cannot call' }
    @{ Order = 23; Path = Join-Path $PSScriptRoot  '100_auth_functions.sql';                          Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'Six scalar functions, auth.tvfPermissionScope, and the three SCHEMABINDING RLS predicates 120 binds' }
    @{ Order = 24; Path = Join-Path $PSScriptRoot  '110_auth_authn_procedures.sql';                   Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'The seven authentication procedures -- all three sign-in routes, both lockout arms' }
    @{ Order = 25; Path = Join-Path $PSScriptRoot  '112_auth_mfa_procedures.sql';                     Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'The four MFA procedures -- enrol, confirm, issue recovery codes, re-key. T-041, gap G-07 closed' }
    @{ Order = 26; Path = Join-Path $PSScriptRoot  '105_auth_session_procedures.sql';                 Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'Session context set and clear, and the two maintenance-bypass procedures. AFTER 110 -- it calls auth.uspEndSession' }
    @{ Order = 27; Path = Join-Path $PSScriptRoot  '115_seed_reference_data.sql';                     Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'The reference data that is code -- one application, the root and external-organization tenants, 35 permissions, 14 roles, the UI catalogue. 120 MUST follow it' }
    @{ Order = 28; Path = Join-Path $PSScriptRoot  '125_auth_tenant_procedures.sql';                  Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'The five tenancy procedures' }
    @{ Order = 29; Path = Join-Path $PSScriptRoot  '130_auth_user_procedures.sql';                    Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'The user and credential procedures -- create, update, deactivate, set a password, and the two lockout arms' }
    @{ Order = 30; Path = Join-Path $PSScriptRoot  '140_auth_profile_procedures.sql';                 Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'The profile procedures -- create, update, deactivate, and auth.uspSwitchProfile. Calls 150 at run time, guarded' }
    @{ Order = 31; Path = Join-Path $PSScriptRoot  '145_auth_role_procedures.sql';                    Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'The role procedures -- define a role, edit it, retire it, grant it, revoke it, change a grant expiry' }
    @{ Order = 32; Path = Join-Path $PSScriptRoot  '155_auth_registration_procedures.sql';            Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'The Variant 3 procedures -- register an organization, approve or reject it, register an external user' }
    @{ Order = 33; Path = Join-Path $PSScriptRoot  '160_auth_admin_procedures.sql';                   Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'Platform administration -- the flag either way, and the two cache rebuilds. The only procedures whose subject is the database itself' }
    @{ Order = 34; Path = Join-Path $PSScriptRoot  '150_auth_query_procedures.sql';                   Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'auth.uspDemandPermission -- the gate every business procedure calls at step 5, before it opens a transaction' }
    @{ Order = 35; Path = Join-Path $PSScriptRoot  '180_dbo_application_procedures.sql';              Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'The demonstration domain calling surface -- seven writes and three reads over dbo.CaseFile and dbo.CaseNote, and the reference implementation of section 14 (T-102)' }
    @{ Order = 36; Path = Join-Path $PSScriptRoot  '120_rls_policy.sql';                              Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'auth.uspRebuildTenantAccessPolicy and the policy it builds: four predicates per registered table. Binds LAST' }
    @{ Order = 37; Path = Join-Path $PSScriptRoot  '175_perf_instrumentation.sql';                    Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'The sampled permission probe, the predicate-function statistics and the extended-events session -- gap G-22, decision D-07' }
    @{ Order = 38; Path = Join-Path $PSScriptRoot  '135_audit_triggers.sql';                          Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'The standing assertion that every audited table HAS an update trigger that maintains its audit block. Creates nothing; throws E-50210 or E-50211 (T-101)' }
    @{ Order = 39; Path = Join-Path $PSScriptRoot  '170_permissions.sql';                             Database = 'target'; PassDbName = $true;  RequiresAuth = $false; What = 'Every schema stated for every role, and it FAILS on a schema that is neither granted nor denied -- gap G-19' }
)

# ---------------------------------------------------------------------------------------------------------------------

function Write-Banner {
    param([string] $Text, [string] $Colour = 'Cyan')
    Write-Host ''
    Write-Host ('=' * 118) -ForegroundColor $Colour
    Write-Host $Text        -ForegroundColor $Colour
    Write-Host ('=' * 118) -ForegroundColor $Colour
}

function Get-AuthArgs {
    if ($Credential) {
        return @('-U', $Credential.UserName, '-P', $Credential.GetNetworkCredential().Password)
    }
    return @('-E')   # Windows integrated
}

function Invoke-SqlScript {
    <#  Returns $true on success. Never throws on a T-SQL error -- the caller decides whether to stop.  #>
    param(
        [hashtable] $Step,
        [string]    $TranscriptPath
    )

    $db = if ($Step.Database -eq 'master') { 'master' } else { $DatabaseName }

    $sqlArgs = @('-S', $ServerInstance, '-d', $db) + (Get-AuthArgs) + @('-I', '-C', '-b')
    if ($Step.PassDbName) { $sqlArgs += @('-v', "DbName=$DatabaseName") }
    $sqlArgs += @('-i', $Step.Path)

    # Printable form, with any password redacted.
    $printable = ($sqlArgs | ForEach-Object {
        if ($_ -match '\s') { '"{0}"' -f $_ } else { $_ }
    }) -join ' '
    if ($Credential) { $printable = $printable -replace [regex]::Escape($Credential.GetNetworkCredential().Password), '********' }

    Write-Host ''
    Write-Host ("[{0}/{1}] {2}" -f $Step.Order, $Manifest.Count, (Split-Path -Leaf $Step.Path)) -ForegroundColor White
    Write-Host ("        {0}" -f $Step.What) -ForegroundColor DarkGray
    Write-Host ("        sqlcmd {0}" -f $printable) -ForegroundColor DarkGray

    # -WhatIf is honoured here rather than through $PSCmdlet.ShouldProcess: $PSCmdlet belongs to the script's own
    # cmdlet binding, and reaching it from a nested function under Set-StrictMode is a needless risk for a switch
    # $WhatIfPreference already reports correctly.
    if ($WhatIfPreference) { return $true }

    $output = & sqlcmd @sqlArgs 2>&1
    $ok     = ($LASTEXITCODE -eq 0)

    $output | ForEach-Object { Write-Host ('        ' + $_) }
    if ($TranscriptPath) {
        Add-Content -Path $TranscriptPath -Value ("`n--- {0} ---" -f (Split-Path -Leaf $Step.Path))
        Add-Content -Path $TranscriptPath -Value ($output | Out-String)
    }

    if ($ok) { Write-Host '        OK' -ForegroundColor Green }
    else     { Write-Host ("        FAILED (sqlcmd exit {0})" -f $LASTEXITCODE) -ForegroundColor Red }

    return $ok
}

function Test-AuthSchemaPresent {
    <#  Tests EVERY table a RequiresAuth script asserts, not just the first one.

        This probe used to test auth.Tenant alone, and Phase 1 turned that into a real defect rather than an
        untidiness: the moment 030_auth_tenant.sql created auth.Tenant, the probe answered YES, 090_dbo_application.sql
        was run rather than skipped, and it threw on the still-absent auth.UserProfile -- failing the whole deployment
        under -b at the exact moment Phase 1 succeeded. A partial probe for an all-or-nothing dependency is a probe that
        reports YES while the answer is "some". Add to this list whenever a RequiresAuth script asserts something new.
    #>
    if ($WhatIfPreference) { return $false }
    $probeArgs = @('-S', $ServerInstance, '-d', $DatabaseName) + (Get-AuthArgs) +
                 @('-I', '-C', '-b', '-h', '-1', '-W',
                   '-Q', ("SET NOCOUNT ON; SELECT CASE WHEN OBJECT_ID('auth.Tenant','U') IS NOT NULL " +
                          "AND OBJECT_ID('auth.UserProfile','U') IS NOT NULL THEN 'YES' ELSE 'NO' END;"))
    $result = & sqlcmd @probeArgs 2>&1
    if ($LASTEXITCODE -ne 0) { return $false }
    return (($result | Out-String) -match 'YES')
}

function Invoke-PolicyDrop {
    <#  Unbinds auth.TenantAccessPolicy before a pass, and reports what it did.

        THIS IS WHAT MAKES A SECOND DEPLOYMENT POSSIBLE AT ALL, and it is not a tidying step. Once
        120_rls_policy.sql has bound the policy:

          *  auth.tvfTenantReadPredicate and its two siblings cannot be altered -- error 3729, "cannot be dropped or
             altered because it is being referenced by object TenantAccessPolicy" -- so 100_auth_functions.sql fails.
          *  the same applies to any change to a table a bound predicate references through SCHEMABINDING, which is why
             030_auth_tenant.sql and 065_auth_effective_permission.sql are in the same boat, and to the two protected
             tables themselves in 090_dbo_application.sql.

        So the whole idempotency claim of this installer -- "run it twice, nothing changes" -- is false the moment
        Phase 4 ships, unless the policy is dropped first and rebuilt by step 36. That is exactly the sequence section
        21.3 of the design document prescribes for changing a schema-bound object, performed here rather than left to a
        person to remember at the point where forgetting it costs a failed deployment.

        On a first deployment the procedure does not exist yet and this is a no-op that says so.

        WHAT IT COSTS, STATED: between this call and step 36, dbo.CaseFile and dbo.CaseNote are UNPROTECTED. Deploying
        to a database holding real data therefore opens a window in which any session sees every tenant's rows. That is
        a property of re-creating a security policy and not of this script; the mitigation is that a deployment is a
        maintenance window, and the alternative -- leaving the policy bound and the deployment broken -- is worse.
    #>
    param([string] $TranscriptPath)

    if ($WhatIfPreference) {
        Write-Host ''
        Write-Host '[pre] EXEC auth.uspRebuildTenantAccessPolicy @Action = N''Drop'';' -ForegroundColor DarkGray
        return $true
    }

    # The database itself may not exist yet -- 000_prerequisites.sql creates it at step 1 -- and sqlcmd -d against a
    # database that is not there is an error, which under the -b this file insists on would abort the pass before it
    # started. So the existence question is asked in master first, where the answer is always available.
    $existsArgs = @('-S', $ServerInstance, '-d', 'master') + (Get-AuthArgs) +
                  @('-I', '-C', '-b', '-h', '-1', '-W',
                    '-Q', ("SET NOCOUNT ON; SELECT CASE WHEN DB_ID(N'{0}') IS NULL THEN 'NO' ELSE 'YES' END;" -f $DatabaseName))
    $exists = & sqlcmd @existsArgs 2>&1
    if ($LASTEXITCODE -ne 0 -or -not (($exists | Out-String) -match 'YES')) {
        Write-Host ''
        Write-Host '[pre] Unbind auth.TenantAccessPolicy -- skipped.' -ForegroundColor White
        Write-Host ("        Database [{0}] does not exist yet; step 1 creates it. There is no policy to unbind." -f $DatabaseName) -ForegroundColor DarkGray
        return $true
    }

    # @TablesBound is NOT the count of tables this drop just unprotected. Under @Action = N'Drop' the procedure
    # initialises it to 0 and never sets it again -- correctly, because after a drop the policy protects nothing -- so
    # printing it under the label "tables now unprotected" printed a structural 0 on every re-run of every database,
    # which is a number that cannot be wrong and therefore cannot be read. The count that means something is how many
    # live rows config.TenantScopedTable holds, because those are the tables that WERE protected a moment ago and are
    # not now. Asked separately, and guarded, because on a first deployment the registry does not exist either. BL-065.
    $sql = "SET NOCOUNT ON; " +
           "IF OBJECT_ID('auth.uspRebuildTenantAccessPolicy','P') IS NULL " +
           "  PRINT 'No policy rebuild procedure yet (120_rls_policy.sql has never run). Nothing to unbind.'; " +
           "ELSE BEGIN " +
           "  DECLARE @Unbound INT, @Skipped INT, @Registered INT = 0; " +
           "  EXEC auth.uspRebuildTenantAccessPolicy @Action = N'Drop', @TablesBound = @Unbound OUTPUT, @TablesSkipped = @Skipped OUTPUT; " +
           "  IF OBJECT_ID('config.TenantScopedTable','U') IS NOT NULL " +
           "    SELECT @Registered = COUNT (*) FROM config.TenantScopedTable WHERE IsDeleted = 0 AND IsActive = 1; " +
           "  PRINT CONCAT('auth.TenantAccessPolicy dropped. Step 36 rebuilds it. Registered tables now unprotected: ', @Registered); " +
           "END;"

    $dropArgs = @('-S', $ServerInstance, '-d', $DatabaseName) + (Get-AuthArgs) + @('-I', '-C', '-b', '-Q', $sql)

    Write-Host ''
    Write-Host '[pre] Unbind auth.TenantAccessPolicy so the schema-bound objects can be re-created (error 3729)' -ForegroundColor White
    $out = & sqlcmd @dropArgs 2>&1
    $ok  = ($LASTEXITCODE -eq 0)
    $out | ForEach-Object { Write-Host ('        ' + $_) }
    if ($TranscriptPath) { Add-Content -Path $TranscriptPath -Value ($out | Out-String) }

    if ($ok) { Write-Host '        OK' -ForegroundColor Green }
    else {
        Write-Host '        FAILED -- the policy could not be dropped, so 030, 065, 090 and 100 will fail with 3729.' -ForegroundColor Red
    }
    return $ok
}

function Invoke-Pass {
    param([string] $Label, [string] $TranscriptPath)

    Write-Banner ("{0}  ->  {1}\{2}" -f $Label, $ServerInstance, $DatabaseName)

    if (-not (Invoke-PolicyDrop -TranscriptPath $TranscriptPath)) { return $false }

    $authPresent = $null
    foreach ($step in $Manifest) {

        if (-not (Test-Path $step.Path)) {
            Write-Host ''
            Write-Host ("[{0}/{1}] {2}" -f $step.Order, $Manifest.Count, (Split-Path -Leaf $step.Path)) -ForegroundColor White
            Write-Host '        NOT FOUND -- skipped.' -ForegroundColor Yellow
            continue
        }

        if ($step.RequiresAuth) {
            if ($null -eq $authPresent) { $authPresent = Test-AuthSchemaPresent }
            if (-not $authPresent) {
                Write-Host ''
                Write-Host ("[{0}/{1}] {2}" -f $step.Order, $Manifest.Count, (Split-Path -Leaf $step.Path)) -ForegroundColor White
                Write-Host '        SKIPPED -- auth.UserProfile does not exist yet.' -ForegroundColor Yellow
                Write-Host '        This script asserts BOTH auth.Tenant and auth.UserProfile and throws without either.' -ForegroundColor DarkGray
                Write-Host '        auth.Tenant arrived with Phase 1 (030_auth_tenant.sql). auth.UserProfile is PHASE 3, task' -ForegroundColor DarkGray
                Write-Host '        T-046: a profile binds a person to a tenant AND carries role grants, so it belongs with the' -ForegroundColor DarkGray
                Write-Host '        authorization tables, not with auth.User. 040_auth_userprofile.sql builds auth.User only and' -ForegroundColor DarkGray
                Write-Host '        argues the split in its banner. The dependency is half met, which is expected after Phase 2' -ForegroundColor DarkGray
                Write-Host '        and is not a failure. This message used to say Phase 2 and was wrong -- BL-025.' -ForegroundColor DarkGray
                continue
            }
        }

        if (-not (Invoke-SqlScript -Step $step -TranscriptPath $TranscriptPath)) {
            Write-Host ''
            Write-Host 'DEPLOYMENT STOPPED. The script above failed; nothing after it was run.' -ForegroundColor Red
            Write-Host 'Fix what it reported and run this again -- every script converges, so a re-run is safe.' -ForegroundColor Red
            return $false
        }
    }
    return $true
}

function Invoke-Bootstrap {
    <#  900_bootstrap_first_admin.sql. NOT a manifest step, deliberately: the manifest is idempotent by construction and
        this file is the one script in the repository that must never run twice. It is an act performed ON the schema
        rather than part of it, so it runs after the last pass, once, and only when a credential was supplied.

        Everything except DbName goes through the ENVIRONMENT -- see the .PARAMETER notes: a -v value cannot contain a
        space and both the display name and the PHC string routinely do.  #>
    param([string] $TranscriptPath)

    $script = Join-Path $PSScriptRoot '900_bootstrap_first_admin.sql'

    Write-Banner 'Bootstrap the first administrator (900_bootstrap_first_admin.sql)' 'Magenta'

    if (-not (Test-Path $script)) {
        Write-Host ("        {0} is missing. Nothing bootstrapped." -f $script) -ForegroundColor Red
        return $false
    }

    $sqlArgs = @('-S', $ServerInstance, '-d', $DatabaseName) + (Get-AuthArgs) +
               @('-I', '-C', '-b', '-v', "DbName=$DatabaseName", '-i', $script)

    Write-Host ("        user   : {0} ({1})" -f $BootstrapAdminUserName, $BootstrapAdminDisplayName) -ForegroundColor DarkGray
    Write-Host ("        email  : {0}" -f $BootstrapAdminEmail) -ForegroundColor DarkGray
    Write-Host  '        phc    : (supplied, not printed)' -ForegroundColor DarkGray
    Write-Host ("        appcode: {0}" -f $BootstrapAppCode) -ForegroundColor DarkGray

    if ($WhatIfPreference) { return $true }

    $env:AppCode          = $BootstrapAppCode
    $env:AdminUserName    = $BootstrapAdminUserName
    $env:AdminDisplayName = $BootstrapAdminDisplayName
    $env:AdminEmail       = $BootstrapAdminEmail
    $env:AdminVerifierPhc = $BootstrapAdminVerifierPhc

    try {
        $output = & sqlcmd @sqlArgs 2>&1
        $ok     = ($LASTEXITCODE -eq 0)
    }
    finally {
        # The verifier does not stay in the environment of this process one statement longer than it has to.
        Remove-Item Env:AdminVerifierPhc -ErrorAction SilentlyContinue
        Remove-Item Env:AdminUserName    -ErrorAction SilentlyContinue
        Remove-Item Env:AdminDisplayName -ErrorAction SilentlyContinue
        Remove-Item Env:AdminEmail       -ErrorAction SilentlyContinue
        Remove-Item Env:AppCode          -ErrorAction SilentlyContinue
    }

    $output | ForEach-Object { Write-Host ('        ' + $_) }
    if ($TranscriptPath) {
        Add-Content -Path $TranscriptPath -Value "`n--- 900_bootstrap_first_admin.sql ---"
        Add-Content -Path $TranscriptPath -Value ($output | Out-String)
    }

    if ($ok) {
        Write-Host '        OK' -ForegroundColor Green
    }
    else {
        # E-50080 is the expected outcome on any database that has been bootstrapped already, including the second pass
        # of -VerifyIdempotent. It is reported as a skip rather than a failure, because it is the design working.
        if ($output -match '50080') {
            Write-Host '        Already bootstrapped (E-50080). Skipped -- this is the refusal working, not a failure.' -ForegroundColor Yellow
            return $true
        }
        Write-Host ("        FAILED (sqlcmd exit {0})" -f $LASTEXITCODE) -ForegroundColor Red
    }

    return $ok
}

function Invoke-Verification {
    param([string] $TranscriptPath)

    Write-Banner 'Verification (read-only)' 'DarkCyan'

    $checkScript = Join-Path $SkillRoot 'scripts/checkDbChangeLogging.sql'
    if (Test-Path $checkScript) {
        $step = @{ Order = '+'; Path = $checkScript; Database = 'target'; PassDbName = $false; RequiresAuth = $false
                   What = 'Is the change-logging machinery present and current' }
        [void] (Invoke-SqlScript -Step $step -TranscriptPath $TranscriptPath)
    }

    if (-not $WhatIfPreference) {
        Write-Host ''
        Write-Host '        EXEC logs.uspDdlAuditVerify;' -ForegroundColor DarkGray
        $verifyArgs = @('-S', $ServerInstance, '-d', $DatabaseName) + (Get-AuthArgs) +
                      @('-I', '-C', '-b', '-Q', 'EXEC logs.uspDdlAuditVerify;')
        $out = & sqlcmd @verifyArgs 2>&1
        $out | ForEach-Object { Write-Host ('        ' + $_) }
        if ($TranscriptPath) { Add-Content -Path $TranscriptPath -Value ($out | Out-String) }
    }
}

# =====================================================================================================================

Write-Banner 'Database Authentication & Authorization Template -- deployment'

if (-not (Get-Command sqlcmd -ErrorAction SilentlyContinue)) {
    throw 'sqlcmd was not found on PATH. Install the SQL Server command line tools (mssql-tools / "SQL Server Command Line Utilities") and try again.'
}

Write-Host ("Server        : {0}" -f $ServerInstance)
Write-Host ("Database      : {0}" -f $DatabaseName)
Write-Host ("Authentication: {0}" -f $(if ($Credential) { 'SQL login ' + $Credential.UserName } else { 'Windows integrated' }))
Write-Host ("Repository    : {0}" -f $RepoRoot)

$transcript = $null
if (-not $WhatIfPreference) {
    if (-not (Test-Path $LogDir)) { [void] (New-Item -ItemType Directory -Path $LogDir -Force) }
    $transcript = Join-Path $LogDir ("deploy_{0}_{1:yyyyMMdd_HHmmss}.log" -f $DatabaseName, (Get-Date))
    Write-Host ("Transcript    : {0}" -f $transcript)
    Set-Content -Path $transcript -Value ("Deployment of {0} to {1}\{2} at {3:u}" -f $RepoRoot, $ServerInstance, $DatabaseName, (Get-Date))
}

if (-not (Invoke-Pass -Label 'PASS 1 -- deploy' -TranscriptPath $transcript)) { exit 1 }

if ($VerifyIdempotent) {
    Write-Host ''
    Write-Host 'Second pass. Every script must report no change; anything else is a convergence defect.' -ForegroundColor Yellow
    if (-not (Invoke-Pass -Label 'PASS 2 -- idempotency check' -TranscriptPath $transcript)) { exit 1 }
    Write-Banner 'Both passes completed. Compare the two passes in the transcript: the second must have changed nothing.' 'Green'
}

if ($BootstrapAdminVerifierPhc) {
    if (-not (Invoke-Bootstrap -TranscriptPath $transcript)) { exit 1 }
}
else {
    Write-Host ''
    Write-Host 'No -BootstrapAdminVerifierPhc was supplied, so 900_bootstrap_first_admin.sql was NOT run. This database' -ForegroundColor Yellow
    Write-Host 'has no user, no profile and no way in until it is. That is the correct state for a re-deployment; on a' -ForegroundColor DarkGray
    Write-Host 'new one, re-run with -BootstrapAdminVerifierPhc <the PHC string your application produced>.' -ForegroundColor DarkGray
}

if (-not $SkipVerification) { Invoke-Verification -TranscriptPath $transcript }

Write-Banner 'Done.' 'Green'
if ($transcript) { Write-Host ("Transcript: {0}" -f $transcript) }
Write-Host ''
Write-Host 'What this deployment does NOT yet include:' -ForegroundColor Yellow
Write-Host '  ONE project script is still unwritten, and it is not in the manifest above:' -ForegroundColor DarkGray
Write-Host '   950_verify_deployment.sql   the post-deployment verification report (Phase 8, T-103)' -ForegroundColor DarkGray
Write-Host '  Until it exists, -SkipVerification is the only honest setting: each script checks its own work in its own' -ForegroundColor DarkGray
Write-Host '  closing report, and nothing checks the database as a whole or notices drift introduced after a deployment.' -ForegroundColor DarkGray
Write-Host '  See workbooks\build-and-traceability.xlsx, Scripts sheet, for the full inventory in install order, and' -ForegroundColor DarkGray
Write-Host '  workbooks\implementation-tracking.xlsx for its task.' -ForegroundColor DarkGray
Write-Host ''
Write-Host '  THE PERMISSION CATALOGUE IS SEEDED BY A SCRIPT, AND THAT HAS A VISIBLE CONSEQUENCE:' -ForegroundColor DarkGray
Write-Host '   050_auth_permission.sql builds auth.Permission empty; step 26 (115_seed_reference_data.sql) puts the 35' -ForegroundColor DarkGray
Write-Host '   rows in, and step 36 (120_rls_policy.sql) resolves Data.Read to bind the predicates -- which is the whole' -ForegroundColor DarkGray
Write-Host '   reason 120 is near the end. If 120 runs with no Data.Read row to resolve it builds the predicates around the' -ForegroundColor DarkGray
Write-Host '   sentinel permission id -1, and every predicate then denies every session that is not a maintenance' -ForegroundColor DarkGray
Write-Host '   session. That is fail-CLOSED and deliberate. After ANY change to the catalogue, re-run 120_rls_policy.sql,' -ForegroundColor DarkGray
Write-Host '   or the predicates keep resolving the old ids and nothing complains (UI-35).' -ForegroundColor DarkGray
Write-Host ''
Write-Host '  One script in the manifest above is deliberately partial, and says so when it runs:' -ForegroundColor DarkGray
Write-Host '   170_permissions.sql states every schema for every role, but the matching assertion inside' -ForegroundColor DarkGray
Write-Host '   950_verify_deployment.sql is Phase 8 and that script does not exist -- so an ad-hoc REVOKE made after' -ForegroundColor DarkGray
Write-Host '   deployment is not yet caught by anything. BL-029.' -ForegroundColor DarkGray
Write-Host ''
Write-Host 'The tests are NOT in the manifest, and are not run by this script. There are eight:' -ForegroundColor Yellow
Write-Host '  database\_tests\010_phase0_instrumentation.sql     the rule 8 instrumentation contract, on util.uspPhase0Probe' -ForegroundColor DarkGray
Write-Host '  database\_tests\020_tenancy_variant_trees.sql      builds the three variant tenant trees' -ForegroundColor DarkGray
Write-Host '  database\_tests\030_tenancy_closure_reparent.sql   moves a populated subtree and verifies the closure' -ForegroundColor DarkGray
Write-Host '  database\_tests\040_identity_and_authn.sql          all three sign-in routes, both lockout arms, INV-07/08' -ForegroundColor DarkGray
Write-Host '  database\_tests\050_authorization_and_session.sql  fourteen grant mutations against the materialized scope' -ForegroundColor DarkGray
Write-Host '  database\_tests\060_row_security.sql               the DES 10.3 matrix, the bypass window, and UI-18' -ForegroundColor DarkGray
Write-Host '  database\_tests\070_variants_end_to_end.sql        one variant end to end, admin to sign-in -- Phase 6 exit' -ForegroundColor DarkGray
Write-Host '  database\_tests\080_error_catalogue.sql            harvests every THROW and reconciles it against Appendix B' -ForegroundColor DarkGray
Write-Host '' -ForegroundColor DarkGray
Write-Host '  TWO SWITCHES OR THEY DO NOT RUN. Every test needs -v Seed=<unique-text-with-no-spaces>, fresh on EVERY run:' -ForegroundColor Yellow
Write-Host '  the seed becomes a session token and a token cannot be reused. 070 also needs -v Variant=VARIANT1, VARIANT2' -ForegroundColor DarkGray
Write-Host '  or VARIANT3, and is idempotent for a given variant. A -v value cannot contain a space -- UI-41.' -ForegroundColor DarkGray
Write-Host '  050 and 060 invent their own permissions and re-run 120 to bind them, which leaves a DEVELOPMENT policy' -ForegroundColor DarkGray
Write-Host '  naming the test fixtures. Re-run 120_rls_policy.sql afterwards to get the shipped one back.' -ForegroundColor DarkGray
Write-Host '  They create development fixtures -- applications with no business meaning -- so they are run by hand' -ForegroundColor DarkGray
Write-Host '  against a development database and never against one a project team has put real data in. Either order,' -ForegroundColor DarkGray
Write-Host '  any number of times; each restores the shape the other expects.' -ForegroundColor DarkGray
Write-Host '' -ForegroundColor DarkGray
Write-Host '  The three measurement scripts are separate again, and are NOT run against a database holding real data:' -ForegroundColor Yellow
Write-Host '   database\_perf\T069_load_volumes.sql      populates volume -- tenants, profiles, scope rows, case files' -ForegroundColor DarkGray
Write-Host '   database\_perf\T070_measure_predicates.sql the predicate cost, in LOGICAL READS. Microseconds vary; reads do not' -ForegroundColor DarkGray
Write-Host '   database\_perf\T071_measure_rebuilds.sql   the two scope-rebuild shapes -- gap G-39' -ForegroundColor DarkGray
Write-Host '  Their results are docs\30-performance-measurements.md. Read its section 1 before quoting any number from it.' -ForegroundColor DarkGray
Write-Host ''
Write-Host '  One test is a .NET console program rather than a script, because decision D-08 puts the Argon2id' -ForegroundColor Yellow
Write-Host '  computation in the client and a T-SQL test can therefore only assert what it was told:' -ForegroundColor Yellow
Write-Host '   dotnet run --project tools\T040-PasswordVerification -- --server <server> --database <database>' -ForegroundColor DarkGray
Write-Host '  It needs database\_tests\040_identity_and_authn.sql to have been run at least once first, for the fixture.' -ForegroundColor DarkGray
Write-Host ''
