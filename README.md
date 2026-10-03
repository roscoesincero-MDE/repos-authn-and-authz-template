# Database Authentication & Authorization Template

A SQL Server 2022 database template that provides multi-tenant authentication and authorization —
a hierarchical tenant tree, profile-based role assignment, and row-level security — for web
applications built on .NET, Dapper and stored procedures.

It exists so that every new application does not reinvent "who is this person, which organization
are they acting for, and which rows may they touch" — and so that applications currently using
Active Directory for authorization have somewhere consistent to convert to. One design, configured
three ways: an agency with subordinate jurisdictions, an agency-internal system organized by
administration and program, and an agency with external organizations.

![status](https://img.shields.io/badge/status-work%20in%20progress-orange)
![design](https://img.shields.io/badge/design-v1.7%20draft-blue)
![SQL Server](https://img.shields.io/badge/SQL%20Server-2022%20only-CC2927)
![.NET](https://img.shields.io/badge/.NET-10-512BD4)
![scripts](https://img.shields.io/badge/scripts-36%20of%2037-lightgrey)
![phases 0-7](https://img.shields.io/badge/phases%200%20to%207-deployed%20%26%20verified-brightgreen)
![phase 8](https://img.shields.io/badge/phase%208-not%20started-lightgrey)
![milestone](https://img.shields.io/badge/milestones-M1%20to%20M4%20reached-blue)
![D-07](https://img.shields.io/badge/D--07-GO-brightgreen)
![scenario 1](https://img.shields.io/badge/scenario%201-4%20runs%2C%20all%20pass-brightgreen)

> These badges are static declarations, not continuous integration. There is no build yet.

---

## Status — read this before cloning

**This is a work in progress. The design is complete, the database deploys end to end, and what is
missing is the script that checks it independently.**

| | |
|---|---|
| Design document | Complete — v1.7, out for review |
| Project plan | Complete — v1.9, 9 phases, 5 milestones; **Phases 0 to 7 complete, M1 to M4 reached** |
| Tracking workbooks | Complete and seeded; **115 of 129 tasks Complete**, none Blocked; fourteen remain — the eight original Phase 8 items and six filed by the scenario 1 test, one of them `Critical` |
| **Database scripts** | **36 of 37 written.** The one that is not is `950_verify_deployment.sql` (`T-104`) — plus the deployment runner, eight test scripts, three measurement scripts and one .NET harness |
| **Phase 0 foundation** | **Deployed and verified** — `MDE-55TT2J4\testTemplate`, 2026-09-19, twice |
| **Phase 1 tenancy model** | **Deployed and verified** — both exit criteria evidenced by test |
| **Phase 2 identity and authentication** | **Deployed and verified** — all three sign-in routes, both lockout arms, first-factor enrolment; all four exit criteria evidenced by test |
| **Phase 3 authorization** | **Deployed and verified** — 22 observations in `_tests/050`, 0 failed |
| **Phase 4 row security** | **Deployed and verified** — `auth.TenantAccessPolicy` bound to two tables, 16 observations in `_tests/060`, 0 failed |
| **Phase 5 performance** | **Measured, and `D-07` is a formal GO** — `docs/30-performance-measurements.md` is the record, **M3 reached**. A protected point read costs **8 logical reads against 3**, and the plan shape holds at 10,650 tenants |
| **Phase 6 administration** | **Deployed and verified** — the administrative write surface, the seeds, the registration flow and the bootstrap. All three variants of design §17 build end to end **through the procedures** (`_tests/070`), and Appendix B is reconciled by measurement rather than by reading (`_tests/080`). **M4 reached** — `docs/40-ui-handoff-m4.md`. **Amended 2026-09-21**: nine gap rows closed, seven procedures and two tables added to existing scripts, and the contract taken to v1.1 through its own change-control rule |
| **Phase 7 demo domain** | **Deployed and verified** — `180_dbo_application_procedures.sql`, the reference implementation of design §14, and `135_audit_triggers.sql`, the standing assertion that every audited table has its trigger |
| Deployable end to end | **Yes.** 39 manifest steps, exit 0, and a second pass that changes nothing — measured again on 2026-09-20. What it is *not* yet is **independently verified**: nothing but each script's own report checks the result, which is `950_verify_deployment.sql` and Phase 8 |
| User interface | Not started — a separate project. **M4 is reached, and `docs/40-ui-handoff-m4.md` is its entry point**: the frozen contract, not a pointer to six documents |

You can clone this today and get a design to review, a plan to cost, a task list to assign, a working
set of SQL conventions with a validation gate, and a database that **stands up complete and populated
from one command**: the conventions machinery, the tenant hierarchy, **working authentication** — all
three sign-in routes, both lockout arms, sessions, first-factor enrolment and re-keying — **working
authorization**, **row-level security bound to two demo tables**, the **35-permission catalogue and
fourteen shipped roles seeded**, the **administrative procedures that create users, profiles and
roles**, the Variant 3 registration queue, a **bootstrap first administrator**, and a demonstration
domain exercised through the same calling contract a real application would use.

A session proves who somebody is, resolves which organization they are acting for, answers "may they
do this, here" in two index seeks, and is refused the rows outside its scope by the database rather
than by a `WHERE` clause somebody remembered to write. That last claim is now **measured rather than
asserted** — `docs/30-performance-measurements.md`, and read its §1 before quoting any number from it.

What you cannot get is a deployment anybody has verified from the outside. Every script checks its own
work and reports on it, which is not the same thing, and `BL-065` is the argument: **an installer that
finishes with `EXIT=0` and no independent verification of what it produced is a green report beside an
unknown state.** Five gap rows block a production go-live and one blocks Variant 3 specifically — see
[Known gaps](#known-gaps), and read them before you plan a deployment rather than after.

**What has been executed.** The runner's **thirty-nine** manifest steps were run against
`MDE-55TT2J4\testTemplate` repeatedly through 2026-09-19 and 2026-09-20 as each phase added scripts,
and last on 2026-09-20 after the Phase 5 to 7 closeout: **every step OK, nothing skipped, exit 0**, and
two consecutive full passes each emitting exactly **824** `logsData.DdlChange` rows and leaving
identical state — which is the shape convergence takes here, and is explained under *Verify* below.
A separate database, `testTemplateFresh`, proved this project's first **clean-database** deployment
rather than a convergence onto an existing one; `testTemplateBoot` holds the Phase 5 volumes and is
left at 10,650 tenants on purpose.

- **Phase 0** — `000_prerequisites.sql`, `005_schemas_and_roles.sql` and all four conventions-skill
  installers, plus the instrumentation probe in `database/_tests/`. Nothing in the scripts had to
  change to make that work, but the run produced four Build Log entries (`BL-015`–`BL-018`) and one
  gap (`G-19`), which is the argument for the phase existing. Read them before your first deployment;
  two describe output you will see and should not mistake for a failure. Phase 1 then corrected two
  Phase 0 artefacts — the runner's dependency probe (`BL-023`) and a spurious aggregate-NULL warning
  in `005_schemas_and_roles.sql` (`BL-024`) — which is what a second phase deploying onto the first
  is for.
- **Phase 1** — `030_auth_tenant.sql`, `095_auth_views.sql`, `100_auth_functions.sql` and
  `125_auth_tenant_procedures.sql`: four tables, one view, one function, five procedures. Both exit
  criteria are evidenced by the two test scripts rather than asserted here: all three variant trees
  build from script, and the closure is correct after a **re-parenting** — not only after a fresh
  build, which is the case an incremental algorithm gets wrong and the reason the rebuild is whole.
  Six Build Log entries (`BL-019`–`BL-024`) and one gap (`G-20`).
- **Phase 2** — `025_config_tables.sql`, `035_auth_tenant_policy.sql`, `040_auth_userprofile.sql`,
  `045_auth_identity.sql`, `070_auth_session.sql`, `085_logs_auth_tables.sql`,
  `110_auth_authn_procedures.sql`, `112_auth_mfa_procedures.sql` and `170_permissions.sql`: ten
  tables, five functions, the seven authentication procedures and the four MFA enrolment procedures,
  plus the permission model for the whole database. All four exit criteria are evidenced by
  `database/_tests/040_identity_and_authn.sql` — 42 observations intended, none failed — and by a
  .NET harness that computes real Argon2id digests client-side, because the one thing `D-08` hangs on
  cannot be tested from inside T-SQL. Eleven Build Log entries (`BL-025`–`BL-035`), three gaps
  **closed** (`G-19`, `G-20`, and `G-07` by a decision that was management's rather than this
  project's), one new (`G-21`), and seven new UI gotchas — `UI-26` and `UI-27`, both Critical, and
  `UI-28`–`UI-32` from the `G-07` decision. The last script, its test section and five of those
  gotchas landed on 2026-09-20, the day after the rest of the phase.
- **Phase 3** — `040_auth_userprofile.sql` (now with `auth.UserProfile`), `050_auth_permission.sql`,
  `055_auth_role.sql`, `060_auth_profile_role.sql`, `065_auth_effective_permission.sql`,
  `085_logs_auth_tables.sql` (three authorization trails added), `100_auth_functions.sql`
  (`udfHasPermission`, `tvfPermissionScope`), `105_auth_session_procedures.sql`,
  `150_auth_query_procedures.sql` and `165_logs_procedures.sql`. Six tables, one materialized
  derivation, and the two objects everything above them calls: `auth.uspSetSessionContext`, which turns
  a session token into five read-only `SESSION_CONTEXT` keys, and `auth.uspDemandPermission`, the gate
  every business procedure calls before it opens a transaction. Evidenced by
  `database/_tests/050_authorization_and_session.sql` — **22 observations, 0 failed, 3 notes** — whose
  central experiment is fourteen grant mutations in sequence, each followed by a check that the
  *materialized* `auth.ProfilePermissionScope` still equals what the derivation says it should be.
  Build Log `BL-036`, `BL-037`, `BL-040`, `BL-042`, `BL-043` and `BL-044`.
- **Phase 4** — `120_rls_policy.sql`, the three `SCHEMABINDING` predicates in
  `100_auth_functions.sql`, the maintenance-bypass pair in `105_auth_session_procedures.sql`, and
  `090_dbo_application.sql`, which the runner **no longer skips**. `auth.TenantAccessPolicy` is built
  from `config.TenantScopedTable` rather than from a hand-written list — four predicates per registered
  table, `FILTER` plus three `BLOCK` operations — and is bound to `dbo.CaseFile` and `dbo.CaseNote`.
  The registry and the settings table are `025_config_tables.sql`, whose two tasks (`T-059`, `T-060`)
  are Phase 4's even though the file itself was installed back in Phase 2, because
  `110_auth_authn_procedures.sql` could not read a tunable threshold without it — which is the
  Scripts sheet's Phase column and its install order disagreeing on purpose.
  Evidenced by `database/_tests/060_row_security.sql`: **16 observations, 0 failed, 3 notes**, covering
  the whole of design §10.3, the bypass window, and the case that surprises people — **row-level
  security applies to `db_owner`**, so a `db_owner` connection with no session context sees zero rows.
  Its section 4 — the check that the deployed predicate really carries the fixture's own permission
  ids, which is the only thing standing between `UI-35` and a suite that passes by denying everything —
  was repaired on 2026-09-21: it had compared two independently-ordered `STRING_AGG` renderings as
  **text**, so it called the policy stale the moment the catalogue reached six `Data.Read` rows, and in
  that form it could never have reported the drift it exists for. It now compares the ids as a **set**,
  by `EXCEPT` in both directions. `T-121`, `BL-075`.
  Build Log `BL-038`, `BL-039`, `BL-041`, `BL-045` and `BL-046`, plus `BL-047`–`BL-049` from the
  closeout that followed. Two new gaps (`G-22`, `G-23`) and seven new UI gotchas (`UI-33`–`UI-39`),
  and **not one of the nine came from re-reading the design**: three are SQL Server or a convention
  refusing what the design assumed (`UI-34`, `UI-37`, `UI-38`), two are silent-failure modes a client
  has to defend against (`UI-33`, `UI-35`), two are behaviours only a test exposes (`UI-36`, `UI-39`),
  and two are gaps the phase opened rather than closed (`G-22`, `G-23` — both since closed, and `G-23`
  the hard way, described below).

- **Phase 5** — `175_perf_instrumentation.sql` and the three scripts Phase 5 added to `database/_perf/`
  (two more joined them later with `T-130`, the concurrency measurement). This phase
  wrote almost no schema and produced the document that now governs every performance claim in the
  project: `docs/30-performance-measurements.md` (`PERF-AUTH-001`), measured on a purpose-built
  `testTemplateBoot` at 1,050 and then 10,650 tenants, 5,000 profiles and 200,000 case files. The
  verdict on `D-07` is a **GO** and milestone **M3** is reached. The headline is that a protected point
  read costs **8 logical reads against 3** and a protected range scan **1,007 against 6**, while the
  large unfiltered aggregate costs **1,002,655 against 1,405** — a **714×** difference that is a
  property of the *query* rather than of the predicate, which is why `UI-40` exists and why the GO
  carries one condition: **callers filter by tenant themselves and let the predicate verify it.** The
  methodological finding is the one to carry away: **logical reads are stable across runs and
  microsecond figures are not** — two runs on the same population returned identical reads and times
  differing by up to 20% — so every argument here is made on reads. `G-22` closed (the hot path is
  sampled now, at `Perf.PermissionProbeSampleRate`, shipped at 0), `G-09` closed by measurement, and
  `G-39` filed *because* of a measurement: one all-profiles scope rebuild is **224× cheaper** than a
  thousand single-profile ones, and no shipped procedure takes the fast path.
- **Phase 6** — the largest phase in the plan and the one that turns a model into a system: eleven
  artefacts, `075_auth_ui_catalog.sql`, `080_auth_registration.sql`, two more views in
  `095_auth_views.sql`, `115_seed_reference_data.sql`, `130_auth_user_procedures.sql`,
  `140_auth_profile_procedures.sql`, `145_auth_role_procedures.sql`, the three remaining procedures in
  `150_auth_query_procedures.sql`, `155_auth_registration_procedures.sql`,
  `160_auth_admin_procedures.sql` and `900_bootstrap_first_admin.sql`. Both exit criteria are evidenced
  by test rather than asserted: `_tests/070` builds **all three variants of design §17 end to end
  through the procedures**, from the bootstrap administrator onward, and passes for each; `_tests/080`
  harvests every `THROW` in the database and reconciles it against Appendix B — **122 throwable, 117
  observed, 96 probed, 6 accounted for, none unaccounted**. Milestone **M4** is reached at `T-095`,
  which is `docs/40-ui-handoff-m4.md`. Seven gap rows closed here (`G-25`, `G-26`, `G-29`, `G-33` to
  `G-36`), all of them a document disagreeing with working code; six more were targeted at this phase
  and left open (`G-24`, `G-27`, `G-30`, `G-32`, `G-42`, `G-43`), two of those — `G-30` and `G-42` —
  blocking a production go-live. **All six were closed on 2026-09-21**, together with `G-12`, `G-18`
  and `G-21` from earlier phases, by seven tasks (`T-113`–`T-119`) that added no new script: four
  credential procedures to `110`, two per-tenant configuration writers to `125`,
  `auth.uspRecordRegistrationAttempt` to `155`, `auth.TenantTrustedIssuer` to `035` and
  `auth.RegistrationAttempt` to `080`. `G-36` is the one with a consequence for the client: **a sign-in
  costs two connections**, because `SESSION_CONTEXT` cannot be re-pointed and a profile switch
  therefore spends the connection that performed it.
- **Phase 7** — `180_dbo_application_procedures.sql` (seven writes and three reads over the two demo
  tables, and the reference implementation of design §14), `135_audit_triggers.sql`, and the hardening
  of `090_dbo_application.sql` itself: audit triggers, attribution from `SESSION_CONTEXT`, `TenantId`
  immutability, and both tables registered in `config.TenantScopedTable` by the script that creates
  them rather than by a later one. `135` is the phase's most transferable piece and it **creates
  nothing**: it enumerates the audited tables from the catalog, asserts that each one carries an
  enabled `AFTER UPDATE` trigger maintaining its audit block, and throws if one does not — 37 tables in
  scope, 36 required, 36 present, and the single exemption (`logs.ExecutionLog`, a single-writer table
  where a trigger would fire inside every error handler) held as a **row with its reason** rather than
  as a name in the code.

`BL-050`–`BL-066` record Phases 5, 6 and 7 and the closeout that followed them,
`BL-067`–`BL-073` the gap-closing pass of 2026-09-21, and `BL-074`–`BL-075` the suite run that
verified that pass — of which **four exist because a gap row was
wrong**, not because a script was: a procedure named in the register and in Appendix B that this
template never built, a permission named in a proposed resolution that is not in Appendix A, a control
a row asked the *application* to assert, and a settings count four artefacts had been repeating two
revisions after it stopped being true. Read `BL-066` if you read only one: `logs.PermissionProbe` was writable by `applicationRole` for three phases while
`170_permissions.sql` reported no problems, because its check asserted the same four table names its
grant section denied — the two agreed with each other and neither agreed with the database. `G-23` had
predicted it in writing and the prediction did not prevent it, which is the actual finding: **a warning
in a report is not a control.** Both halves now enumerate `sys.tables` in the schema and subtract a
documented exemption list, with a count assertion beside them, because an enumeration over an empty set
is an assertion that cannot fail.

**Two things are installed and deliberately not yet what they will be in production, and both are
about keys and policy rather than about unfinished code.**

**MFA enrolment ships pointing at a development key.** `T-041` was
blocked by `G-07` — where the key that wraps a TOTP secret lives was undecided — until management
decided it: application-side envelope encryption under a TPM-backed CNG key on the application-layer
server, with the database holding the ciphertext and the *name* of the key that made it, and never
key material. `112_auth_mfa_procedures.sql` implements that in four procedures — enrol, confirm,
issue recovery codes, re-key — so the user who used to be stuck, refused `E-50109` under a policy
requiring MFA with no factor to satisfy it, now enrols from the very exchange the policy refused.
What ships is a **development** key reference: `Authn.MfaKeyReferenceCurrent` is
`dev:local/authn-mfa-kek#v1`, and `dev:` means a workstation key with no hardware protection. The
closing reports of `025`, `045` and `112` each say so, as a `REVIEW` row rather than a failure,
because on a workstation it is the correct state and a script that called it a problem would be
crying wolf on every developer's machine. Moving to `cng:` is one setting and a re-key sweep with
`auth.uspRotateMfaFactorKey` rather than a schema change, which is what the `scheme:name#vN` grammar
on `KeyReference` exists for. Read `UI-28` before you deploy the application server: the key is
machine-bound, and a rebuilt server cannot read what the old one wrote.

**The deployment ships with the MFA requirement switched off, and one of the two reasons it used to
ship that way has been fixed.** `900_bootstrap_first_admin.sql` writes the root authentication policy
with `RequireMfaForLocal = 0` because it has to: `auth.uspCompleteLogin` falls back to *requiring* a
factor when no policy resolves, the account the bootstrap creates has none, and enrolling one needs a
session that a refused sign-in cannot produce — so a bootstrap with no policy row produces an
administrator who can never sign in. The script prints the instruction to enrol a factor and set the
flag back to 1. That is `G-37`, it is **High**, it blocks a production go-live, and the reason it is
still open is the honest one: **today the paragraph you are reading is the control.** It becomes a real
one when `950_verify_deployment.sql` asserts it and fails.

The second half of that pair is closed. `auth.uspSwitchProfile` used to read the *absence* of a policy
row as the absence of a step-up requirement, so a deployment that wrote no policy rows demanded no
step-up anywhere (`G-30`). `025_config_tables.sql` now seeds
`Authn.RequireStepUpForPrivilegedDefault` at **1** and the writer falls back to it, so the template
fails **closed** and relaxing it is a decision somebody makes in a row rather than an accident of an
empty table. The fallback deliberately did **not** go into `auth.udfResolveAuthPolicy`, which is on
the authorization hot path and is measured in `docs/30-performance-measurements.md`; it went into the
caller, where a settings read costs one lookup per switch rather than one per permission check.
`auth.uspSetTenantAuthenticationPolicy` now exists as well, so a subtree's sign-in routes are a
procedure call under `Tenant.Update` instead of an `INSERT` somebody runs by hand under `db_owner`.

See [Installation](#installation--setup) for how it runs.

---

## Repository layout

```
.
├── docs/
│   ├── 00-documentation-index.md      Start here — what every document is and who it's for
│   ├── 10-database-authn-authz-design.md   DES-AUTH-001 — the design (27 sections)
│   ├── 20-project-plan.md             PLAN-AUTH-001 — phases, risks, prerequisites
│   ├── 30-performance-measurements.md PERF-AUTH-001 — the measured record, and the D-07 go/no-go
│   ├── 40-ui-handoff-m4.md            UIH-AUTH-001 — the frozen contract the UI project builds against
│   └── 60-scenario-test-1.md          SCEN-AUTH-001 — one agency, 67 counties, 12,830 users; four runs and seven gaps
├── workbooks/
│   ├── implementation-tracking.xlsx   129 tasks, 109 person-days, formula roll-up by phase
│   ├── build-and-traceability.xlsx    Scripts in install order · Build Log (85 entries) · Traceability
│   ├── gaps.xlsx                      51 gaps; 24 closed, 4 block production, 1 blocks Variant 3
│   └── ui-gotchas.xlsx                49 things the UI team needs to know; 10 marked Critical
├── database/
│   ├── Install-TemplateDatabase.ps1   The deployment runner — 39 steps, in declared-dependency order
│   ├── 000_prerequisites.sql          Server checks, create-if-absent database, database options
│   ├── 005_schemas_and_roles.sql      The four schemas and the four database roles
│   ├── 025_config_tables.sql          config.ApplicationSetting and the tenant-scoped-table registry
│   ├── 030_auth_tenant.sql            Tenancy — Application, TenantType, Tenant, TenantClosure
│   ├── 035_auth_tenant_policy.sql     Which sign-in routes a subtree allows; most tenants have no row
│   ├── 040_auth_userprofile.sql       auth.User — the person — and auth.UserProfile, the hat they wear
│   ├── 045_auth_identity.sql          Credentials, password history, MFA factors, federated links, LoginAttempt
│   ├── 050_auth_permission.sql        The permission vocabulary — categories and codes. The 35 rows arrive at 115
│   ├── 055_auth_role.sql              auth.Role and auth.RolePermission — the only editable half of the vocabulary
│   ├── 060_auth_profile_role.sql      auth.UserProfileRole — the grant: who holds what authority, where
│   ├── 065_auth_effective_permission.sql  The materialized effective grant, and the rebuild that owns it
│   ├── 070_auth_session.sql           auth.UserSession — the token is not stored, a SHA-256 of it is
│   ├── 075_auth_ui_catalog.sql        auth.UiElement and auth.UiElementPermission — screens, tabs, what each demands
│   ├── 080_auth_registration.sql      auth.OrganizationRegistration — the Variant 3 queue; the one table a stranger writes
│   ├── 085_logs_auth_tables.sql       The authentication narrative and the three authorization trails
│   ├── 090_dbo_application.sql        The demo domain — dbo.CaseFile and dbo.CaseNote, the two tables 120 protects
│   ├── 095_auth_views.sql             Five views. vwTenantHierarchy installs before the function it cannot call
│   ├── 100_auth_functions.sql         Six scalar functions, one table-valued, and the three RLS predicates
│   ├── 105_auth_session_procedures.sql    Session context set and clear, and the maintenance-bypass pair
│   ├── 110_auth_authn_procedures.sql  Eleven procedures — three sign-in routes, both lockout arms, and the password lifecycle
│   ├── 112_auth_mfa_procedures.sql    Enrol, confirm, issue recovery codes, re-key — and never a key in sight
│   ├── 115_seed_reference_data.sql    The reference data that is code: 35 permissions, 14 roles, 26 UI elements
│   ├── 120_rls_policy.sql             auth.TenantAccessPolicy, built from the registry. Binds late, unbinds first
│   ├── 125_auth_tenant_procedures.sql Seven — the five tenancy procedures, plus the two per-tenant configuration writers
│   ├── 130_auth_user_procedures.sql   The user procedures. Passwords live in 110, on purpose — see INV-11
│   ├── 135_audit_triggers.sql         Creates nothing. Asserts that every audited table HAS its update trigger
│   ├── 140_auth_profile_procedures.sql    Profiles, and uspSwitchProfile — the procedure that spends its connection
│   ├── 145_auth_role_procedures.sql   Define, edit, retire, grant, revoke — every one writing a trail row
│   ├── 150_auth_query_procedures.sql  The gate, plus the three read procedures the UI contract is made of
│   ├── 155_auth_registration_procedures.sql   Variant 3 — register an organization, approve it, register a user
│   ├── 160_auth_admin_procedures.sql  Platform administration and the two cache rebuilds
│   ├── 165_logs_procedures.sql        The three trail recorders. BEFORE every procedure script that asserts them
│   ├── 170_permissions.sql            Every schema stated for every role; fails on one that is neither. LAST
│   ├── 175_perf_instrumentation.sql   The sampled permission probe — gap G-22, shipped at sample rate 0
│   ├── 180_dbo_application_procedures.sql The demo calling surface: seven writes, three reads, design §14 by example
│   ├── 900_bootstrap_first_admin.sql  The one script that must never run twice. NOT a manifest step, deliberately
│   ├── 950_verify_deployment.sql      NOT WRITTEN — T-104, Phase 8. The independent check of everything above
│   ├── _tests/
│   │   ├── 010_phase0_instrumentation.sql   Proves the instrumentation records
│   │   ├── 020_tenancy_variant_trees.sql    Builds the three variant tenant trees
│   │   ├── 030_tenancy_closure_reparent.sql Moves a populated subtree; verifies the closure
│   │   ├── 040_identity_and_authn.sql       42 experiments — three sign-in routes, both lockout arms, enrolment
│   │   ├── 050_authorization_and_session.sql  22 observations — fourteen grant mutations, session context, expiry
│   │   ├── 060_row_security.sql             16 observations — the DES §10.3 matrix, the bypass window, UI-18
│   │   ├── 070_variants_end_to_end.sql      One variant end to end through the procedures — bootstrap to sign-in
│   │   └── 080_error_catalogue.sql          Harvests every THROW and reconciles it against Appendix B
│   │                                        None of the eight is installed by the runner. Only 070 and 080
│   │                                        read $(Seed); 070 also takes -v Variant=VARIANT1|2|3
│   ├── _perf/
│   │   ├── T069_load_volumes.sql            Populates volume: tenants, profiles, scope rows, 200,000 case files
│   │   ├── T070_measure_predicates.sql      The predicate cost, in logical reads. Microseconds vary; reads do not
│   │   ├── T071_measure_rebuilds.sql        The two rebuild shapes, and the 224× between them — gap G-39
│   │   ├── T130_concurrency_harness.sql     Lock footprints and the role-change ladder. One session, re-runnable
│   │   └── T130_concurrency_driver.ps1      PowerShell: the sign-in storm, pooling, and the deadlock pair with a
│   │                                        POSITIVE CONTROL. Not T-SQL because two connections are the point
│   └── _scenarios/
│       ├── S1_load_agency.sql               One agency over N counties, thirteen cohorts. Parameterised, resumable
│       └── S1_prove_duties.sql              34 asserted observations over 18 connections that the population works.
│                                             Sections 6, 7 and 9 once proved G-50, G-48 and G-51 reproduced and now
│                                             assert they are closed. No direct DML anywhere in it
├── tools/
│   └── T040-PasswordVerification/     .NET 10 console harness — the client half of D-08, real Argon2id
├── scripts/                           Python helpers that maintain the workbooks. Not part of any deployment
├── requirements.txt                   The original requirement statement, verbatim — the three application variants
├── additionalRequirements-T-041.txt   Management's G-07 decision, verbatim: where the key that wraps a TOTP seed lives
└── .claude/
    ├── skills/ponytail-sql-objects/   The SQL conventions: rules, templates, installers
    ├── hooks/validate-sql.py          The convention gate
    └── settings.json                  Wires the gate to run on every file write
```

The `.claude/` folder is not incidental. Opening this repository in Claude Code activates the SQL
conventions skill and the validation hook automatically, so objects get written to the project's
standards without anyone restating them. The skill is equally usable as plain documentation —
`.claude/skills/ponytail-sql-objects/SKILL.md` is the authority on the conventions whether or not
you use Claude.

---

## Prerequisites

### To read the design and plan

Nothing. They are Markdown and render on GitHub.

For the workbooks: Excel, LibreOffice Calc, or Google Sheets. They use `COUNTIFS` and `SUMIFS`
only, so they open anywhere.

### To run what SQL exists today

| | Requirement | Notes |
|---|---|---|
| Database | **SQL Server 2022** | The floor *and the ceiling*. 2025-only constructs are rejected by the gate, because they deploy cleanly on a developer's newer instance and fail at `CREATE` time on every 2022 server. The procedure template uses `LEAST()`, so 2017 and 2019 will not work either. A **newer** instance is allowed and warns: `000_prerequisites.sql` hard-fails below major 16 and prints a notice above it, the database is pinned to compatibility level 160, and the gate is what actually keeps a script written on a 2025 box deployable on a 2022 server. The instance this was verified on is 2025, so that notice is expected output (`BL-018`) |
| Client | `sqlcmd`, or SSMS with **Query → SQLCMD Mode** on | Not optional. **All 36 scripts in `database/` reference `$(DbName)` and 35 of them open with `:on error exit`**; without SQLCMD mode they fail on the first directive, before anything is created. The one script without `:on error exit` is `120_rls_policy.sql`, which raises through `THROW` from inside its own procedure and relies on `-b` for the exit code |
| Permission | `db_owner` on a **throwaway** database | One optional section of `logdBChanges.sql` also wants `ALTER ANY LOGIN`; without it that section reports and continues |
| Database roles | `applicationRole`, `readOnlyRole`, `logsAuditReader`, `rlsBypassRole` | Created for you by `005_schemas_and_roles.sql`, which is why it runs before anything that grants to them. Every grant in the project is guarded on the role existing, so **a name that does not exist is a silently skipped grant** — the object deploys, the script reports success, and nobody can execute it. If your estate uses different names, change them in three places together: `database/005_schemas_and_roles.sql`, which creates them, `database/170_permissions.sql`, which states every schema for every one of them, and the conventions skill's own `.claude/skills/ponytail-sql-objects/scripts/permissions.sql` |

Use a throwaway database. `000_prerequisites.sql` will create one for you — by default
`testTemplate` — and reuse it on every later run.

### To use the convention gate

Python 3. The hook is a single file with no third-party imports.

### For the .NET harness

`.NET 10 SDK` and a NuGet restore, for `tools/T040-PasswordVerification`. Nothing else in the
repository needs it. There is no `pwsh` requirement — the runner is Windows PowerShell 5.1 compatible.

### Later phases only

- **An Entra app registration** in a non-production tenant, for a real federated sign-in. Phase 2
  built and tested the database half — `(Issuer, SubjectId)` resolution, `INV-07`, the closed-by-default
  `AllowFederated` — against a fixture issuer, so this is now needed for integration rather than for
  construction. See `G-21`: nothing yet constrains *which* issuer is acceptable, and Phases 3 to 7 came
  and went without closing it, because a trusted-issuer list belongs to
  `auth.TenantAuthenticationPolicy` and `auth.uspBeginSsoLogin` and no later phase touched either.
- **A member of `rlsBypassRole`**, if you intend to run maintenance against protected tables. Phase 4
  made this real rather than theoretical: `auth.uspBeginMaintenanceSession` opens a bounded window, and
  `_tests/060` creates a bypass principal for section 7 and **takes the membership away again in section
  8**, because a test that leaves a bypass principal behind has widened the database it was checking.
  Treat membership as a temporary grant with an owner, not as a role somebody is in.
- **A TPM-backed CNG key container on the application-layer server**, and the application-side
  envelope encryption that uses it. This was gap `G-07`, the second of the two things that genuinely
  blocked a production deployment, and management **closed it on 2026-09-20** by choosing
  application-side encryption over Always Encrypted — which a template cannot use, because it does
  not know which columns a project will add and because every external reader, Power BI included,
  would need the column master key and a driver that understands it. What the database needs from you
  is one row changed: `Authn.MfaKeyReferenceCurrent`, from its shipped `dev:local/authn-mfa-kek#v1`
  to a `cng:` reference, followed by a re-key sweep. The web front end neither holds the key nor
  needs one. A self-hosted HashiCorp Vault is **not** adopted; the `vault:` scheme is reserved so
  that adopting one later is a setting and a sweep rather than a migration.

---

## Installation / setup

### 1. Clone

```bash
git clone <REPO-URL>           # TODO: fill in once the repository exists
cd <repo>
```

### 2. Deploy

```powershell
# Show the exact sqlcmd command line for every script, in order, and run nothing
.\database\Install-TemplateDatabase.ps1 -WhatIf

# Deploy to MDE-55TT2J4\testTemplate with Windows authentication
.\database\Install-TemplateDatabase.ps1

# Deploy, then deploy again and prove the second pass changes nothing
.\database\Install-TemplateDatabase.ps1 -VerifyIdempotent

# Deploy AND create the first administrator.  The PHC string is computed by your application, never here:
# the database never sees a password (D-08).  Without this switch, 900_bootstrap_first_admin.sql does not run
# and the runner says so.
.\database\Install-TemplateDatabase.ps1 -BootstrapAdminVerifierPhc '<the PHC string your application produced>'
```

Another server or database: `-ServerInstance` and `-DatabaseName`. SQL authentication:
`-Credential (Get-Credential)`; omit it for Windows integrated, which is the default. The bootstrap
takes four more optional parameters — `-BootstrapAdminUserName`, `-BootstrapAdminDisplayName`,
`-BootstrapAdminEmail` and `-BootstrapAppCode` — defaulting to `first.admin`, `First Administrator`,
`first.admin@example.invalid` (a domain that cannot receive mail, on purpose) and `TEMPLATE`, which is
the application code `115_seed_reference_data.sql` seeds.

The runner creates the database if it does not exist, runs every script in install order with the
switches below, stops at the first failure, and writes a transcript to `database/_logs/` — which
`.gitignore` excludes, because a transcript names the server, the login that ran it and every object
in the database.

> **The runner has been executed**, on 2026-09-19 and repeatedly through 2026-09-20 against
> `MDE-55TT2J4\testTemplate`: all **thirty-nine** manifest steps, every step OK, nothing skipped, a
> second pass that changed nothing, and `-VerifyIdempotent` exiting 0 — measured again after the
> Phase 5 to 7 closeout. Most of those runs added a phase's scripts to an already-deployed database, so
> they are convergence proofs; `testTemplateFresh` is the **fresh-install** proof, built from nothing on
> 2026-09-20. It has still only met one server and one Windows-authenticated login, so `-WhatIf` first is
> still good advice, and section 3 is the same sequence by hand.

**Two things the runner does that are not steps, and you must do by hand if you deploy by hand.**

**First**, before every pass it calls `auth.uspRebuildTenantAccessPolicy @Action = N'Drop'` to **unbind
`auth.TenantAccessPolicy`**, and step 36 rebuilds it. This is not tidying. Once the policy is bound,
`auth.tvfTenantReadPredicate` and its two siblings cannot be altered — **error 3729** — so
`100_auth_functions.sql` fails; and through `SCHEMABINDING` the same applies to
`030_auth_tenant.sql`, `065_auth_effective_permission.sql` and the two protected tables in
`090_dbo_application.sql`. The whole "run it twice and nothing changes" claim is **false** from Phase 4
onwards unless the policy comes off first. On a first deployment the procedure does not exist yet and
the call is a no-op that says so.

What it costs, stated plainly because the script states it: between the drop and step 36,
**`dbo.CaseFile` and `dbo.CaseNote` are unprotected**. Deploying to a database holding real data opens
a window in which any session sees every tenant's rows. `UI-34`, design §21.3.

**Second**, `900_bootstrap_first_admin.sql` is **not a manifest step and that is deliberate**: the
manifest is idempotent by construction and this is the one file in the repository that must never run
twice. It is an act performed *on* the schema rather than a part of it, so the runner runs it after the
last pass, once, and only when `-BootstrapAdminVerifierPhc` was supplied. On a database that already
has a first administrator it fails with `E-50080`, which the runner reports as a **skip** rather than a
failure, because that refusal is the design working. Everything except `DbName` reaches the script
through the **process environment** rather than through `-v`, because a `-v` value cannot contain a
space and both a display name and a PHC string routinely do (`UI-41`, `UI-42`); the runner removes
`$env:AdminVerifierPhc` on the way out, and that is the pattern to copy.

### 3. Or run it by hand

In this order — thirty-nine steps. **Install order is not build order, and eleven of these orderings
are load-bearing**; each is a place where the obvious sequence fails:

- the **roles** have to exist before anything grants to them, or every grant is silently skipped
  (`BL-012`) — step 2;
- `025_config_tables.sql` comes before any `auth` table, because a procedure that cannot read a setting
  cannot have a tunable lockout threshold — step 7, and its own two tasks are Phase 4's;
- `165_logs_procedures.sql` installs at **20**, immediately after the tables it writes to and **before
  every procedure script**, because six of them assert the three trail recorders and throw without them;
- `090_dbo_application.sql` at **21** asserts `auth.Tenant` *and* `auth.UserProfile`, which is why it
  was skipped for three phases and is not skipped now;
- `095_auth_views.sql` installs **before** `100_auth_functions.sql` (22 before 23), because a view
  resolves names at `CREATE` time and this one deliberately does not call the function;
- `110_auth_authn_procedures.sql` comes **before** `105_auth_session_procedures.sql` (24 before 26),
  because `105` calls `auth.uspEndSession`;
- `112_auth_mfa_procedures.sql` follows `110` (25) for a reason stronger than reading it: enrolment
  accepts the login attempt `110` **refused** as proof the password was right;
- `115_seed_reference_data.sql` at **27** is the seam between a schema and a system, and
  `120_rls_policy.sql` **must** come after it — the predicates carry permission ids as literals, so a
  policy built before the catalogue exists goes on denying everything (`UI-35`);
- `150_auth_query_procedures.sql` at **34** is *after* `140_auth_profile_procedures.sql` at 30, which
  **calls it at run time**. That dependency survives only on an `OBJECT_ID` guard inside `140`, and it
  is the one ordering here that a deployment cannot fail on and a *caller* can;
- `180_dbo_application_procedures.sql` at **35** is deliberately before `120` at **36**, which opens a
  documented **one-step window in which the demo tables are unprotected** — the alternative was
  re-binding the policy twice in one deployment;
- `120` binds at **36**, `175_perf_instrumentation.sql` at 37, `135_audit_triggers.sql` at **38**
  (it asserts a trigger on every audited table, so it has to be after the last table), and
  `170_permissions.sql` is **last**, because a `GRANT` on a missing object is an error rather than a
  skip.

If you are re-running by hand on a database where the policy has already been bound, **unbind it
first**:

```sql
EXEC auth.uspRebuildTenantAccessPolicy @Action = N'Drop';   -- see the note above; step 36 puts it back
```

```bash
# 1. Server checks, create-if-absent database, database options.  Runs in master -- the one script that does.
sqlcmd -S <server> -d master -v DbName=<db> -I -C -b -i database/000_prerequisites.sql

# 2. The four schemas and the four database roles.  Everything downstream guards its grants on these existing,
#    so a role that is absent is a grant that is silently skipped (BL-012).
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/005_schemas_and_roles.sql

# 3. util.uspSetObjectDescription  (no $(DbName) in this one)
sqlcmd -S <server> -d <db> -I -C -b -i .claude/skills/ponytail-sql-objects/templates/extended-properties.sql

# 4. DDL change logging, so the rest of the deployment is recorded
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i .claude/skills/ponytail-sql-objects/scripts/logdBChanges.sql

# 5. logs.ExecutionLog and the four logging procedures
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i .claude/skills/ponytail-sql-objects/scripts/logExecutionLogging.sql

# 6. Schema-level permissions from the conventions skill.  NOT the same thing as step 39 -- this one covers the
#    schemas the skill itself owns and says nothing about auth, config or util.  That absence WAS gap G-19; it is
#    closed, and 170_permissions.sql at step 39 is what closed it by stating every schema for every role.
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i .claude/skills/ponytail-sql-objects/scripts/permissions.sql

# 7. config.ApplicationSetting and config.TenantScopedTable, seeded with 23 of the 28 shipped defaults.
#    This is BEFORE any auth table on purpose: a procedure that cannot read a setting cannot have a
#    configurable lockout threshold, and a hard-coded threshold is a control nobody can tune.
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/025_config_tables.sql

# 8. Tenancy -- auth.Application, auth.TenantType, auth.Tenant, auth.TenantClosure and their audit triggers
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/030_auth_tenant.sql

# 9. auth.TenantAuthenticationPolicy, auth.TenantDefaultRole and auth.TenantTrustedIssuer -- which sign-in routes a
#     subtree allows, what a self-registered user receives, and which issuers a federated exchange may come from.
#    Neither table has a shipped procedure that writes it: gap G-43.
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/035_auth_tenant_policy.sql

# 10. auth.User -- the person, and NOT tenant-scoped -- and auth.UserProfile, the hat they wear at one tenant
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/040_auth_userprofile.sql

# 11. Credentials, password history, MFA factors, recovery codes, federated links, auth.LoginAttempt
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/045_auth_identity.sql

# 12. The permission vocabulary: auth.PermissionCategory and auth.Permission.  The 35 rows are not here -- they
#     arrive at step 27, per application, because the vocabulary is reference data and this is its shape.
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/050_auth_permission.sql

# 13. auth.Role and auth.RolePermission -- the administrator vocabulary, and the only editable half of it
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/055_auth_role.sql

# 14. auth.UserProfileRole -- the grant.  One row per (profile, role, scope): who holds what authority, where
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/060_auth_profile_role.sql

# 15. auth.ProfilePermissionScope -- the materialized effective grant -- and the procedure that rebuilds it.
#     One call rebuilding all profiles is 224x cheaper than one call per profile: gap G-39, measured.
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/065_auth_effective_permission.sql

# 16. auth.UserSession -- write-once EndedUtc trigger, and the CHECK that makes INV-08 impossible to violate.
#     Its FK to auth.UserProfile is added here by a guarded ALTER, not in step 10 -- BL-049.
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/070_auth_session.sql

# 17. auth.UiElement and auth.UiElementPermission -- the navigation catalogue, and what each element demands.
#     The catalogue is what auth.uspGetNavigationForProfile reads at step 34; it has no version story yet (G-18).
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/075_auth_ui_catalog.sql

# 18. auth.OrganizationRegistration -- the Variant 3 queue -- and auth.RegistrationAttempt, the per-address counter
#     behind it.  The only two tables an unauthenticated caller writes to.
#     It captures the submitting address, which is the raw material for the throttle nothing implements yet (G-24).
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/080_auth_registration.sql

# 19. The authentication narrative and the authorization trails.  Readable by logsAuditReader, and DENIED to
#     applicationRole for all three write verbs -- by enumeration of the schema, not by a list of names (BL-066).
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/085_logs_auth_tables.sql

# 20. The three trail recorders.  Immediately after the tables they write to, and BEFORE every procedure script:
#     six of them assert these three exist and throw without them.
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/165_logs_procedures.sql

# 21. The demo domain: dbo.CaseFile and dbo.CaseNote.  It asserts auth.Tenant AND auth.UserProfile, registers both
#     tables in config.TenantScopedTable itself, and these are the two tables step 36 protects.
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/090_dbo_application.sql

# 22. Five views.  A VIEW resolves names at CREATE time, so vwTenantHierarchy installs BEFORE the function it
#     deliberately does not call -- install order is not build order.
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/095_auth_views.sql

# 23. Six scalar functions, auth.tvfPermissionScope, and the three SCHEMABINDING predicates step 36 binds.
#     If the policy is still bound from a previous run, this is the script that fails with error 3729.
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/100_auth_functions.sql

# 24. Eleven procedures: the seven authentication ones, plus the password lifecycle -- set, change, and the expiry
#     sweep.  AFTER 035 and 040, which it reads, and after 025, which it configures from.
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/110_auth_authn_procedures.sql

# 25. The four MFA enrolment procedures.  AFTER 110, and not merely because it reads it: uspEnrolMfaFactor accepts
#     the login attempt 110 REFUSED as proof the password was right, which works only because 110 writes
#     PasswordVerified BEFORE the MFA checks.  Deploying 112 without 110 leaves the bootstrap with no proof to use.
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/112_auth_mfa_procedures.sql

# 26. Session context set and clear, and the two maintenance-bypass procedures.  AFTER 110 -- it calls
#     auth.uspEndSession, so installing it earlier gets a deferred-resolution warning for no reason.
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/105_auth_session_procedures.sql

# 27. The reference data that IS code: one application, the root and external-organization tenants, 35 permissions
#     in 7 categories, 14 baseline roles, 44 role-permission rows, 26 UI elements, 50 element-permission rows --
#     all per application.  Step 36 MUST follow this: the predicates carry permission ids as literals, so a policy
#     built against an empty catalogue keeps denying and nothing complains (UI-35).
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/115_seed_reference_data.sql

# 28. Seven: the five tenancy procedures, plus uspSetTenantAuthenticationPolicy and uspSetTenantDefaultRoles, which
#     are the only supported way to change what a subtree allows and what a self-registered user receives.
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/125_auth_tenant_procedures.sql

# 29. The user procedures -- create, update, deactivate, and both lockout arms.  Passwords are deliberately NOT here:
#     auth.uspSetPassword and auth.uspChangePassword are in step 24, beside the procedures that read a verifier, so
#     that INV-11's single writer of auth.UserCredential is one module rather than two.
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/130_auth_user_procedures.sql

# 30. The profile procedures, including auth.uspSwitchProfile.  It CALLS step 34 at run time, behind an OBJECT_ID
#     guard, which is why it can install before it -- the only ordering here that a deployment cannot fail on.
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/140_auth_profile_procedures.sql

# 31. Define a role, edit it, set its permissions, grant it, revoke it, list what a caller may assign.  Every one
#     writes logs.AuthorizationChange, and every grant or revoke rebuilds the profile scope it changed.
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/145_auth_role_procedures.sql

# 32. Variant 3 -- register an organization, approve or reject it, register an external user
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/155_auth_registration_procedures.sql

# 33. Platform administration -- the flag either way, and the two cache rebuilds.  The only procedures whose
#     subject is the database itself rather than somebody in it.
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/160_auth_admin_procedures.sql

# 34. The gate every business procedure calls at step 5 before it opens a transaction, plus the three read
#     procedures the UI contract is made of.  Its own report has no PENDING rows any more.
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/150_auth_query_procedures.sql

# 35. The demonstration calling surface: seven writes and three reads over the two demo tables, and the reference
#     implementation of design section 14.  It is deliberately BEFORE the policy rebuild, which is the one-step
#     window in which the demo tables are unprotected -- stated here because the alternative was binding twice.
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/180_dbo_application_procedures.sql

# 36. auth.uspRebuildTenantAccessPolicy, and the policy it builds from config.TenantScopedTable: four predicates
#     per registered table.  Binds late, because a bound predicate freezes everything it references (error 3729).
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/120_rls_policy.sql

# 37. The sampled permission probe, the predicate statistics and the extended-events session -- gap G-22, D-07.
#     Perf.PermissionProbeSampleRate ships at 0, so it costs nothing until somebody turns it on.
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/175_perf_instrumentation.sql

# 38. Creates NOTHING.  It enumerates the audited tables from the catalog and asserts that each one carries an
#     enabled AFTER UPDATE trigger maintaining its audit block -- 36 required, 36 present, one documented
#     exemption held as a row with its reason.  It has to run after the last table, which is why it is here.
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/135_audit_triggers.sql

# 39. LAST, and it must be last: the permission model for every schema every earlier script created.  It FAILS on a
#     schema that is neither granted nor denied (G-19), and it denies the three write verbs on every table in
#     SCHEMA::logs except one documented exemption -- by enumeration, with a count assertion beside it (BL-066).
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/170_permissions.sql

# NOT a step, and never twice: the first administrator.  900_bootstrap_first_admin.sql refuses with E-50080
# on a database that already has one, which is the refusal working rather than a failure.  Everything except
# DbName goes through the ENVIRONMENT, because a -v value cannot contain a space and a display name and a PHC
# string both do (UI-41, UI-42).  Unset AdminVerifierPhc afterwards -- it is a credential.
export AppCode=TEMPLATE AdminUserName=first.admin AdminEmail=first.admin@example.invalid
export AdminDisplayName='First Administrator'
export AdminVerifierPhc='<the PHC string your application produced>'
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/900_bootstrap_first_admin.sql
unset AdminVerifierPhc
```

Three switches, and all three are load-bearing:

**`-b`** makes `sqlcmd` return a non-zero exit code when the batch raised an error. Without it a
deployment loop reports success for a run that failed half way through. If you script these
commands, this is the one to not leave out.

**`-I`** is required. `sqlcmd` is the one client that defaults `QUOTED_IDENTIFIER` **off**, the
setting is baked in at `CREATE` time, and a module carrying it off cannot run DML against a table
with a filtered index — error 1934, surfacing later, inside a procedure whose text is correct.
Every unique constraint in this design is a filtered index, by way of the soft-delete rule.

**`-d` and `-v DbName=` must name the same database.** Each script asserts it and stops before
changing anything if they disagree. That assertion exists because these files once carried a
hard-coded `USE [...]`, so passing `-d` and forgetting to edit the file installed the subsystem
into the wrong database — and then printed a clean report, because the report ran there too.

### 4. Verify

```bash
sqlcmd -S <server> -d <db> -I -C -b -i .claude/skills/ponytail-sql-objects/scripts/checkDbChangeLogging.sql
```

```sql
EXEC logs.uspDdlAuditVerify;
```

On a complete Phase 0 to Phase 7 deployment those return **20 OK/INFO rows with no failures** and
**7 OK plus one INFO watermark row** respectively — measured again on 2026-09-21 after the gap-closure
pass that added two tables. Neither *count* has moved across six phases, because both checks assert the
shape of the logging subsystem rather than the size of the database: two new tables moved what the rows
*say* without moving how many there are, which is the property that makes a count worth asserting.

One row inside the first count does move, and it is the one worth reading rather than counting:
`plain table audit triggers`. Phase 1 gave it four tables to talk about, Phase 2 sixteen, Phase 4
twenty-five, after Phase 7 it named 28, and on 2026-09-21 it names **30** — `auth.RegistrationAttempt`
and `auth.TenantTrustedIssuer` joined it the moment they were created, because their triggers ship in
the same file they do. Every one is asserted to carry an enabled `AFTER UPDATE` trigger. As of Phase 7
it is no longer the only thing making that assertion: step 38, `135_audit_triggers.sql`, makes the same
claim over a wider scope (`auth`, `config`, `dbo`, `logs`, `util` — 36 tables required, 36 present, out
of 37 examined) and **throws** rather than reporting, which is the difference between a check and a
control. The two counts differ by design and the gap between them is the point: `checkDbChangeLogging`
finds only *plain* tables carrying the audit block, while `135` takes every table in the five schemas
and forces each one to be either audited or exempt **with a reason**. That check is
suppressed entirely when the database holds no plain table carrying the audit block, because "0 plain
tables are correct" reads like a fault — so Phase 1 was the first deployment in which it had anything
to say. What it is really asserting is `BL-022`'s subject: audit triggers ship beside the tables they
guard rather than in the later `135_audit_triggers.sql`, because a table that exists for six scripts
without its audit trigger is a table whose first six scripts of history are unrecorded.

Two pieces of first-run output are expected and are not defects:

- A **deferred-resolution warning** on `logs.uspDdlAuditVerify`, which references
  `logs.uspRecordExecutionError` from the installer that runs next. It does not appear on a second
  run, and swapping the two scripts to silence it would stop the second one's own DDL being
  recorded. `BL-017`.
- The **above-major-16 version notice** from `000_prerequisites.sql` on anything newer than SQL
  Server 2022. `BL-018`.

Then **run the whole sequence again**. A second run must change nothing and report nothing; that is
the re-runnability requirement, and confirming it is a Phase 0 exit criterion.
`Install-TemplateDatabase.ps1 -VerifyIdempotent` does both passes and puts them in one transcript.

One caveat on how you check that. *State* converges; the **DDL change log does not**. Each pass adds
rows to `logsData.DdlChange` even when nothing differs, because `CREATE OR ALTER` and each
unconditional `GRANT`/`DENY` raise a DDL event whether or not anything changed. On the thirty-nine-step
deployment as it stands that is **exactly 824 rows per pass** — measured on 2026-09-20 by taking
`MAX (ChangeId)` before and after two consecutive full runs, which gave 7914 → 8738 → 9562, identical
deltas. A **first** pass after new guarded DDL is added emits a few more than every pass after it,
because DDL guarded on its object not already existing runs exactly once — which is worth knowing
before you compare a first pass against a steady-state one and conclude the deployment did not
converge. It was about 45 when the deployment was the six Phase 0
steps, 122 after Phase 1, 416 after Phase 2, 636 after Phase 4 and 824 after Phase 7; the number grows with every script added, and
`170_permissions.sql` alone contributes a large share of it because every `GRANT` and `DENY` is
unconditional by design. Do not treat it as a constant to assert against. "Did the change log stay quiet?" is the wrong test
and will say no on a perfectly converged database — compare the two transcripts instead. `BL-016`.

### 5. Optional: run the eight test scripts, the three measurement scripts and the .NET harness

```bash
# Proves the instrumentation records -- Phase 0
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/_tests/010_phase0_instrumentation.sql

# Builds the three variant tenant trees -- Phase 1, exit criterion 1
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/_tests/020_tenancy_variant_trees.sql

# Moves a populated subtree and verifies the closure -- Phase 1, exit criterion 2
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/_tests/030_tenancy_closure_reparent.sql

# Three sign-in routes, both lockout arms, INV-07, INV-08 and first-factor enrolment -- all four exit criteria
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/_tests/040_identity_and_authn.sql

# Fourteen grant mutations against the materialized scope, and the session-context contract -- Phase 3
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/_tests/050_authorization_and_session.sql

# The DES 10.3 read/insert/update matrix, the maintenance bypass window, and UI-18 -- Phase 4
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/_tests/060_row_security.sql

# One variant of DES section 17, end to end THROUGH THE PROCEDURES, bootstrap to sign-in -- Phase 6.
# Needs BOTH switches.  Run it three times, once per variant; it is idempotent for a given variant.
# -v Seed= must be FRESH on every run: the seed becomes a session token, and a token is not reusable.
sqlcmd -S <server> -d <db> -v DbName=<db> -v Variant=VARIANT1 -v Seed=run1a -I -C -b -i database/_tests/070_variants_end_to_end.sql
sqlcmd -S <server> -d <db> -v DbName=<db> -v Variant=VARIANT2 -v Seed=run1b -I -C -b -i database/_tests/070_variants_end_to_end.sql
sqlcmd -S <server> -d <db> -v DbName=<db> -v Variant=VARIANT3 -v Seed=run1c -I -C -b -i database/_tests/070_variants_end_to_end.sql

# Harvests every THROW in the database and reconciles it against Appendix B -- Phase 6.  Fresh seed again.
sqlcmd -S <server> -d <db> -v DbName=<db> -v Seed=run1d -I -C -b -i database/_tests/080_error_catalogue.sql

# 050 and 060 invent their own permissions and re-run 120 to bind them, which leaves a DEVELOPMENT
# policy naming the test fixtures.  Put the shipped one back when you are done:
sqlcmd -S <server> -d <db> -v DbName=<db> -I -C -b -i database/120_rls_policy.sql
```

**No `-v` value may contain a space, in any quoting form** — `UI-41`, measured, and none of the obvious
quotings work. That is why the seed is a token rather than a sentence.

The three measurement scripts are separate, and they are the only scripts here that deliberately
**populate volume**: 1,050 then 10,650 tenants, 5,000 profiles, 57,342 scope rows and 200,000 case
files. Run them against a database built for the purpose and nothing else — `testTemplateBoot` was
built, measured and left where it stood:

```bash
sqlcmd -S <server> -d <bootdb> -v DbName=<bootdb> -I -C -b -i database/_perf/T069_load_volumes.sql
sqlcmd -S <server> -d <bootdb> -v DbName=<bootdb> -I -C -b -i database/_perf/T070_measure_predicates.sql
sqlcmd -S <server> -d <bootdb> -v DbName=<bootdb> -I -C -b -i database/_perf/T071_measure_rebuilds.sql
```

The scenario scripts are separate again, and for a different reason: they build a **population** rather
than a volume or a fixture. One state agency over N counties, thirteen user cohorts, ~12,830 users at 67
counties, and a proof that each cohort can do the work it was described as doing. The loader is
`NOT EXISTS`-guarded throughout, so re-running it is safe; `-v Wave` is what adds users without adding
tenants:

```bash
sqlcmd -S <server> -d <db> -I -C -b -v DbName=<db> -v AgencyCode=DEP -v AgencyName=DepartmentOfEnvironmentalProtection -v CountyCount=67 -v Wave=w1 -v Seed=s1load01 -i database/_scenarios/S1_load_agency.sql
sqlcmd -S <server> -d <db> -I -C -b -v DbName=<db> -v AgencyCode=DEP -v Wave=w1 -v Seed=s1p01 -v RunLabel=r01 -i database/_scenarios/S1_prove_duties.sql
```

Three rules, none of them optional. **`-v Seed` and `-v RunLabel` on the prover must be fresh every run**
— both become session-token material, and a repeat collides. **No `-v` value may contain a space**, which
is why `DepartmentOfEnvironmentalProtection` is written the way it is (`UI-41`). And the prover takes
about 90 seconds because it deliberately waits for a fresh TOTP step twice; that wait is `UI-47` and it is
the design working, not a hang. The pass criterion is the **exit code** — every one of the 34 checks
`THROW`s. Full write-up, including what four green runs do *not* prove: `docs/60-scenario-test-1.md`.

```powershell
# The client half of D-08: real Argon2id, computed outside the database.  Needs _tests/040 to have run once,
# for the fixture.  Both arguments default to MDE-55TT2J4 and testTemplate.
dotnet run --project tools\T040-PasswordVerification -- --server <server> --database <database>
```

**None of the eleven scripts, and not the harness, is part of the deployment or in the runner's
manifest.** They create development fixtures, so run them against a database you are willing to
discard and never against one a project team has put real data in. `050` and `060` go further than the
others: they seed permissions of their own and **rebuild the row-security policy** so those permissions
are bound, which leaves a development policy in place until you re-run `120_rls_policy.sql`. Only `070`
and `080` require switches; the runner's closing advice suggests passing `-v Seed=` to all eight, which
is harmless — `sqlcmd` ignores a `-v` that a script never references.

The measurement results belong in `docs/30-performance-measurements.md` rather than in a transcript,
and **its §1 is the part to read before quoting any number from it**: reads are reproducible,
microseconds are not, and the document says which of its own figures to distrust.

`020` and `030` are where the Phase 1 exit criteria are actually met, and they are worth reading as
well as running:

- **`020_tenancy_variant_trees.sql`** builds all three tenant shapes from script — a two-level
  hierarchy, a deep one, and a single-tenant application whose root is also its only tenant — and
  makes 16 assertions about them, including `INV-02` in both halves: exactly one root per
  application, and only a root with a null parent.
- **`030_tenancy_closure_reparent.sql`** is the one that matters. It moves a populated subtree to a
  new parent and then checks the closure, because a closure that is right after a fresh build and
  wrong after a re-parenting is the defect an incremental maintenance algorithm actually has, and the
  reason `auth.uspRebuildTenantClosure` rebuilds the table whole rather than patching it. It also
  proves the round trip is byte-identical — move a subtree away, move it back, and the closure equals
  what it was — that a second rebuild changes nothing, and that an attempt to make a tenant its own
  ancestor fails with error 530 while **leaving the closure whole**, which is the part a failed
  rebuild could plausibly get wrong. It reports **23 observations, 0 violations**, exit 0 — twenty on the
  three movements and three on the refused cycle — and it is
  the one file in the suite whose constants are a claim about *another* file's fixture — see the note
  below on running it after `070`.

Either order, any number of times; each restores the shape the other expects.

**That is true of `020` and `030` and it was not true of `030` and `070`, which is worth knowing
before you run the suite in an order the README has not blessed.** `030` sits before `070` in the
sequence above, so until 2026-09-21 nobody had run it *after* `070` — and when somebody did, `030`
reported seven `VIOLATED` rows on a closure that was provably correct. Two things about `070` did it.
It adds two tenants to the `VARIANT2` tree, and `030`'s four pair-count constants had been compared
against every live pair in that application rather than against the nine tenants `020` declares. And
it soft-deletes the organization tenant its own previous run approved — which matters because
**`auth.vwTenantHierarchy` and `auth.TenantClosure` are deliberately asymmetric about a soft-deleted
tenant**: the view drops it *and its whole subtree*, while `auth.uspRebuildTenantClosure` keeps its
pairs live on purpose, because a closure that filtered `IsDeleted` would take a deleted administration
out of its descendants' ancestor set and make `auth.udfIsTenantUsable` fail **open** beneath it. `030`
compares `SUM (Depth + 1)` over the view against `COUNT (*)` over the closure, so those two correct
behaviours made its load-bearing invariant disagree with itself. Both problems were in the test. The
file now states two scoping rules in its own header — the constants measure a declared nine-tenant
fixture, resolved nine-or-nothing, and every count compared against the view counts only what the view
can see — and the asymmetry it tripped over is written up for UI builders as `UI-45`, because a screen
can be built on the same bad assumption. `T-120`, `BL-074`.

`040_identity_and_authn.sql` is where the Phase 2 exit criteria are met, and it reports **42
observations, 0 failed, 4 notes** on a correct deployment. It prints one row per experiment with the
numbers it measured rather than a bare pass, and closes with a roll-up counting how many observations
exercised each named exit criterion. Three of its rows are worth reading even when everything passes:

- **Section 12 is the newest and the longest, and it is one user's story.** `frank` is refused
  `E-50109` in section 10b — under a policy requiring MFA, holding no factor — and section 12 takes
  that refusal and enrols from it: `auth.udfResolveEnrolmentActor` returns his user id from the
  refused attempt, he enrols, re-sends, confirms, draws recovery codes, signs in, and has his factor
  re-keyed onto a second key label and back. Eleven observations, covering every one of `E-50117` to
  `E-50123`. Until 2026-09-20 this section was a single `BLOCKED` row saying enrolment did not exist,
  and the same numbering that recorded the lockout now records the way out of it.
- **Section 13 carries the `GAP` row, and it was filed *because this test could not write an
  assertion*.** Nothing constrains which issuer a federated sign-in may come from, so a wrong issuer
  is untestable. `G-21`.
- **What it deliberately does not claim.** Every `@SecretCiphertext` it passes is random bytes. A
  database test cannot tell a real AES-GCM envelope from noise, because the database holds no key —
  that is `G-07`'s decision working rather than a shortfall, and the encryption is verified where the
  application is. `dave`'s factor is still inserted directly as `db_owner`, kept on purpose as the
  control that stops the experiments which *consume* a factor depending on the ones that *create*
  one.
- **Section 0 states a precondition about the harness itself:** nothing here wraps a procedure call in
  a transaction, and no caller may either. `UI-27` — see §6 below.

`050_authorization_and_session.sql` is where the Phase 3 exit criteria are met — **22 observations, 0
failed, 3 notes**. Three of its sections are worth reading on their own:

- **Sections 5e and 5g are the newest, and they are here rather than in `_tests/080` for a reason that
  constrains any test you write against this database.** `080` measures *refusals*, and neither of these
  is one: 5e asserts the three password-expiry columns of `auth.uspGetProfileContext` — the warning
  window, the count going **negative** past the deadline, and the thirty-two-column shape — and 5g
  asserts that `Authn.RequireStepUpForPrivilegedDefault` is seeded and honoured. They could not go in
  `_tests/040` either, which has no `auth.UserProfile` rows for the context procedure to join to, and
  they could not borrow another section of this file, because **one connection may not serve two
  profiles**: `auth.uspSetSessionContext` refuses a second, different profile on the same connection
  with `E-50022`, and the identity keys are read-only. 5g then hand-soft-deletes its own policy row so
  that section 5f keeps measuring the no-policy path — in **one** statement, because
  `CK_auth_TenantAuthenticationPolicy_DeletedPair` requires `IsDeleted`, `auditDeletedBy` and
  `auditDeletedDateUtc` to move together and is checked before the `AFTER UPDATE` trigger runs — and
  having to reach past the procedure surface to do that is how `G-44` came to be filed.
- **Section 4 is `T-057`, and it is a loop rather than fourteen hand-written blocks.** Each row of
  `#Mutation` carries one statement — grant a role, revoke it, change a role's permissions, soft-delete
  a profile, resurrect it — and after *every* one of them the test recomputes the derivation from
  `auth.UserProfileRole` and `auth.RolePermission` and asserts that the materialized
  `auth.ProfilePermissionScope` still equals it — two `EXCEPT` queries, in both directions, because the
  two failures are not equally dangerous. *Should have and does not* is a user filing a ticket; *should
  not have and does* is nobody filing anything. The derived query is written longhand from design §8.6
  rather than borrowed from `auth.uspRebuildProfilePermissionScope`, because a test that reuses the
  implementation's definition of correct can only prove the code agrees with itself. The sequence is
  deliberately untidy — revoke and re-grant, expire something already expired, edit a role two profiles
  hold, retire a permission out from under a role, deactivate a profile and bring it back — since
  "arbitrary" in `T-057` means the result must not depend on the order. Section 4a covers the
  resurrection case, where a revoked grant is restored **in place** and the row counts can match while
  the contents do not.
- **Section 5 is `T-058`, and it is the one with a consequence for the client.** The five identity keys
  `auth.uspSetSessionContext` sets are `read_only`, so a second call for a **different** profile on the
  same connection is refused `E-50022` — the database cannot un-set them (**Msg 15664**). They are also
  **not transactional**: a key set inside a transaction survives its `ROLLBACK`, measured here rather
  than assumed. The consequence is `UI-06`/`UI-36`: **one connection serves one profile**, so a pooled
  connection must be cleared before reuse and a profile switch means a new connection.

`060_row_security.sql` is where the Phase 4 exit criteria are met — **16 observations, 0 failed, 3
notes** — and it plants its rows with the bypass key before testing what a scoped session can see:

- **Section 5 is `T-068`, and it is the result people do not expect.** Row-level security applies to
  `db_owner`. A `db_owner` connection that has not called `auth.uspSetSessionContext` sees **zero rows**
  in `dbo.CaseFile`, because the predicate has no acting tenant to compare against and fails closed.
  That is also why the fixture needs `rlsBypassRole` to plant anything at all.
- **Section 6 is the whole of design §10.3**: read in scope and out, insert anchored to the acting
  tenant, update both before and after. A `BLOCK` violation is **Msg 33504**, not a `CHECK` error — and
  an attempt to *move* a row to another tenant is refused **Msg 547** first, by the composite foreign
  key, which reaches the caller before the policy does.
- **Section 7 is `T-066`**, run under a real member of `rlsBypassRole`, and section 8 takes the
  membership away again — because a test that leaves a bypass principal behind has widened the database
  it was checking.

`070_variants_end_to_end.sql` is where the Phase 6 exit criterion is met, and it is the only test that
uses **nothing but the procedures**. It takes a variant and builds it from the beginning: bootstrap the
first administrator, define the tenants, create users and profiles, define and grant roles, sign in,
set session context, switch profile, read the navigation catalogue, do the domain work through `180`'s
procedures, and sign out. **All three variants pass, once each.** Nothing in it writes a table
directly, which is the point — `_tests/050` had to apply its grant mutations as `db_owner` DML because
in Phase 3 the procedures did not exist to call, and this test is the answer to that.

`080_error_catalogue.sql` is the other Phase 6 criterion and it measures the documentation rather than
the database: it harvests every `THROW` in every module from `sys.sql_modules` and reconciles what it
finds against design Appendix B — **122 throwable, 117 observed, 96 probed, 6 accounted for, none
unaccounted**. Those figures were **re-measured** on 2026-09-21 rather than adjusted on paper, after
eleven numbers were added to the registry; every one of the eleven became a number something actually
raises, and the accounted-for list did not grow. The accounted-for six are the honest residue, and the file holds each one as a row with
its reason rather than a silence: `E-50010`, `E-50011` and `E-50012` are raised by immutability triggers,
which have no `CATCH` block to write `logs.ExecutionLog` from and so can never enter the ledger — they are
proved by probe instead; `E-50043`, `E-50096` and `E-50141` are **unreachable**, each because an earlier
check in the same procedure always wins, and the file says which one and proves the error that fires in
its place. Three of those are findings about the design, not gaps in the test. Read it if
you ever have to argue that a registry is complete: the number that matters is not how many errors were
found but how many were **left over**, and the file is built so that a new `THROW` with no Appendix B
row makes the count non-zero.

`tools/T040-PasswordVerification` covers the one claim the SQL test cannot make. Because `D-08` puts
Argon2id in the client, `_tests/040` has to pass `@PasswordVerified` by hand; the harness computes a
real digest against a verifier string the database issued, and also shows that the derived dummy
returned for a name nobody holds parses identically, costs the same work, and reaches the same
`E-50106`. Seven observations, exit code 0.

`010_phase0_instrumentation.sql` creates test fixtures
(`util.Phase0ProbeTarget`, `util.uspPhase0Probe`) that a project cloning this template should not
inherit. Run it on a throwaway database when you want to see conventions rule 8 working: it calls an
instrumented procedure three ways — successfully, failing with no ambient transaction, and failing
inside a caller's open transaction — and reports the `logs.ExecutionLog` rows all three produced. The
third is worth looking at: its row carries `ReCreatedAfterRollback = 1` and there is a gap in the
identity sequence where the start row the rollback destroyed used to be. That is the one path no
other placement exercises, and it is the reason the re-creation block in the procedure template is
not optional. Drop its two objects when you are done, or use a database you are going to discard.

### 6. What you cannot do yet

**Most of what used to be on this page is gone.** Through Phase 4 this section said the permission
catalogue was empty, the read surface a UI binds to did not exist, and neither did the administrative
write surface. All three are now false: `115_seed_reference_data.sql` seeds the vocabulary at step 27,
`150_auth_query_procedures.sql` ships all four of its procedures with no `PENDING` rows left in its own
closing report, and `130`/`140`/`145`/`155`/`160`/`900` are written, deployed and exercised by
`_tests/070` through nothing but procedure calls. **Nothing is skipped on a complete deployment**, and
one script remains unwritten: `950_verify_deployment.sql`, which is `T-104`. What follows is what is
actually still missing.

**Nothing verifies the deployment except you.** There is no `950_verify_deployment.sql`, so the claim
"this database is correctly built" rests on the runner's exit code, the four verification scripts of
step 4 above, and the eight test scripts you have to remember to run. Phase 8 is the whole of that
answer and none of it exists yet. Until then, treat a green deployment as *no error was reported*, not
as *verified*.

**The MFA requirement ships off, and the deployment does not say so.** MFA enrolment and consumption
work; what is missing is anything that *requires* them. `900_bootstrap_first_admin.sql` must write the
root authentication policy with `RequireMfaForLocal = 0`, because the administrator it creates has no
factor and enrolling one needs a session — and policy inherits, so that row is the effective policy for
every tenant beneath it (`G-37`). It is High, it blocks production, and the paragraph below about the
development key is the other leg of the same problem. What used to sit beside it — a tenant with no
policy row anywhere above it getting **no step-up challenge** on a privileged profile switch, because
the resolver returned `NULL` and the caller read that as `0` — is fixed:
`Authn.RequireStepUpForPrivilegedDefault` is seeded at 1 and the template now fails closed (`G-30`,
closed 2026-09-21).

**Some invariants are asserted once rather than continuously.** `G-01` is the only open Critical in the
register and it is in the Known gaps section below in full: nothing proves that every tenant-scoped table
is registered *and* covered by a predicate, and that failure is silent and open. `G-02` and `G-03` are the
same shape for `auth.TenantClosure` and `auth.ProfilePermissionScope` — both maintained by procedure,
both verified by test, and neither re-checked tomorrow. All three want one scheduled job and none of them
has it. `G-14` is the administrative version: no break-glass path if the last platform administrator
profile is locked out or leaves, which is the bootstrap's refusal working correctly and being fatal
anyway. Two smaller ones: `G-31`, where two procedures apply the same pair of checks in opposite order so
the refusal you get depends on which you called, and `G-41`, where `auditCreatedBy` is populated from
different sources in different scripts.

**`_tests/050` still writes tables directly.** Fourteen grant mutations, applied as `db_owner` DML
rather than through `145`'s procedures, because in Phase 3 those procedures did not exist. They exist
now. The test was not rewritten, which is deliberate — it tests the *model* independently of the
procedures, and `_tests/070` is the end-to-end proof that the procedures work. Read them as a pair.

**MFA enrolment runs on a development key until you change one row.** `112_auth_mfa_procedures.sql`
is deployed and tested, so creating a factor works as well as consuming one, but the shipped
`Authn.MfaKeyReferenceCurrent` is `dev:local/authn-mfa-kek#v1` — a workstation key with no hardware
protection. Production means a `cng:` reference to a TPM-backed container on the application-layer
server, and a re-key sweep with `auth.uspRotateMfaFactorKey` for anything enrolled before the change.
The database refuses to enrol under any label but the current one (`E-50118`), so the failure mode
here is a refusal rather than a secret quietly wrapped under the wrong key.

**Never call an authentication procedure inside an ambient transaction.** This is `UI-27`/`BL-031` and
it is the one thing on this page that fails *open*. Every refusal path in
`110_auth_authn_procedures.sql` records the failure, commits it, and then re-raises. A .NET caller
holding a `TransactionScope` makes `XACT_STATE ()` non-zero, so the throw unwinds the **caller** and
rolls back the committed failure record and the lockout increment along with it: unlimited password
guesses, nothing in the audit trail, and no symptom anywhere. It is not something the database can
defend against, which is why it is stated here and in the gotchas workbook rather than only in a
comment.

**Expect error 3729 if you re-run a script by hand without unbinding the policy first.** `Msg 3729,
"Cannot ALTER 'auth.tvfTenantReadPredicate' because it is being referenced by object
'TenantAccessPolicy'"`. The three predicates are `WITH SCHEMABINDING`, and a function a live security
policy references cannot be altered at all. The runner handles this for you; by hand, run
`EXEC auth.uspRebuildTenantAccessPolicy @Action = N'Drop';` first and `120_rls_policy.sql` last.
`UI-34`.

---

## Usage

### If you are reviewing the design

Read `docs/00-documentation-index.md` first — it is a map of everything else and says who each
document is for. Then, in the design:

| Read | For |
|---|---|
| §1–§4 | Scope, terminology, principles, and the decisions with their rejected alternatives |
| **§17** | The conformance walk-through — every user from every scenario in the requirements, with the rows that represent them. This is where the design is tested |
| §10.3 | The filter/block asymmetry: reading is scoped, inserting is anchored to the acting tenant. This is now built and measured — `_tests/060` walks the whole table |
| §11.1 | `INV-05` — the four-clause rule for who may grant what to whom |
| §21.3 | The drop-and-rebuild sequence for changing a schema-bound object. Upgraded from a caution to a deployment blocker in v1.5, because error 3729 is not advisory (`BL-038`, `UI-34`) — and read it beside step 36 of the manifest, which is where the finished deployment puts the bind and why `180` deliberately precedes it |
| §14 | The calling contract, with `database/180_dbo_application_procedures.sql` as its reference implementation: ten procedures, each one demanding its permission before it opens a transaction |

If you disagree with the design, disagree in **§4**. That is where each decision is stated with
what was rejected and why.

### If you are implementing it

1. Open `workbooks/implementation-tracking.xlsx` and claim a task. Tasks carry their phase,
   artefact, design reference and dependency.
2. Check the **Scripts** sheet of `workbooks/build-and-traceability.xlsx` for where your artefact
   sits in install order and what it depends on.
3. Read `.claude/skills/ponytail-sql-objects/SKILL.md` before writing any object — or let the
   skill apply itself if you are working in Claude Code.
4. Copy the relevant template from `.claude/skills/ponytail-sql-objects/templates/` rather than
   writing from scratch. Use `database/090_dbo_application.sql` as the worked example of a finished
   tenant-scoped table, and `database/030_auth_tenant.sql` as the worked example of a script that has
   actually been deployed — four tables, their constraints, their seed data and their audit triggers,
   convergent, with the reasoning for each decision in the file. For a **procedure**, the worked
   example is `database/110_auth_authn_procedures.sql`: seven instrumented writing procedures, every
   refusal path recording its failure before it raises, and a closing report that re-asserts its own
   claims against `sys.parameters` rather than trusting a comment. Read
   `database/112_auth_mfa_procedures.sql` next for the case where the *caller* may be either a live
   session or a refused login attempt: that is one exclusive pair of parameters and one scalar
   function, `auth.udfResolveEnrolmentActor`, rather than two near-copies of each procedure. For a
   **tenant-scoped business table**, the worked example is now `database/090_dbo_application.sql`
   deployed and protected rather than skipped — read it beside `database/120_rls_policy.sql`, which
   builds the policy from `config.TenantScopedTable` instead of from a list in the script, so adding a
   table to the registry and re-running is the whole of enrolling it. For a procedure **over a
   tenant-scoped business table** — which is what you will actually be writing — the worked example is
   `database/180_dbo_application_procedures.sql`, the reference implementation of design §14: ten
   procedures, each demanding its permission through `auth.uspDemandPermission` *before* it opens a
   transaction, each letting the row-security policy do the scoping rather than repeating it in a
   `WHERE` clause, and none of them trusting a tenant id the caller supplied. Copy its shape and the
   §14 contract comes with it.
5. Read `database/_tests/070_variants_end_to_end.sql` before you write your own test. It builds each of
   the three variants from an empty database using **nothing but procedures** — bootstrap, tenants,
   users, profiles, roles, grants, sign-in, session context, profile switch, navigation, domain work,
   sign-out — and it is idempotent per variant. It is the answer to "how is this supposed to be called",
   in executable form, and it is the pattern for an integration test that does not need `db_owner`.
6. Run the gate before committing:

   ```bash
   echo '{"tool_input":{"file_path":"'$PWD'/database/030_auth_tenant.sql"}}' \
     | CLAUDE_PROJECT_DIR=$PWD python3 .claude/hooks/validate-sql.py
   ```

   Silence and exit 0 means clean. It exits 2 and names every violation otherwise.
7. **If what you built differs from the design, add a Build Log entry** in
   `build-and-traceability.xlsx` saying what changed and why — at the time you make the change, not
   at the end of the project.

### If you are building the user interface

**Start with `docs/40-ui-handoff-m4.md`.** Milestone **M4** is reached, which means the read surface a
client binds to exists and is callable, and that document is the handoff: it names the procedures, their
parameters, what each one returns and the order a request calls them in. It is frozen at M4, so what it
describes is what is deployed rather than what is planned. Read `workbooks/ui-gotchas.xlsx` beside it,
then design §13 (the screen and tab authorization surface), §14 (the calling contract) and Appendix B
(the error-number registry). The workbook now holds **42 entries and nine are marked `Critical`** — that
severity is the read-before-you-code list.

Three entries change how the client is *built* rather than how it looks, and they are the cheapest ones
to act on early:

- **`UI-36` — one connection serves one profile.** The five session-context keys are read-only once set,
  so a pooled connection cannot be reused for a different profile and a profile switch means a new
  connection. Measured, not inferred: a second `auth.uspSetSessionContext` for a different profile
  raises `E-50022`, and the keys are **not transactional** — one set inside a transaction survives its
  `ROLLBACK`. This is a connection-management decision, and it is much cheaper to make before the data
  layer is written than after.
- **`UI-33` — `auth.tvfPermissionScope` says where authority is *recorded*, not where it can be used.**
  It answers exactly one question — which tenants does this profile hold this permission on — and does
  **not** join `auth.udfIsTenantUsable`, so a deactivated tenant, or one whose parent is deactivated,
  still comes back. A tenant picker built straight from it offers destinations that will refuse the
  write. Filter it, or build the picker from something that does.
- **`UI-35` — a rebuilt policy is a deployment step, not an afterthought.** Change the permission
  catalogue and the predicates keep the *old* ids, because they carry them as literals. The symptom is
  an empty grid with nothing in any log, which is `UI-18` from the other direction: `G-01` is the
  Critical gap that fails **open**, and `UI-35` is its counterpart that fails **closed**. Both are
  silent.

`UI-26` is the sign-in contract in one line: **every sign-in failure shows the same message, whatever
the number.** `E-50116`, the per-address throttle, is not an exception — naming it tells an attacker
their address is being counted. The numbers exist so the audit trail can distinguish cases the user
may not. `UI-22` also changed in Phase 2: bulk role assignment takes a JSON array, not a `DataTable`
as a table-valued parameter (`G-20`), which is less client-side code rather than more.

`UI-28` to `UI-32` arrived with the `G-07` decision on 2026-09-20, and three of the five are not the
UI team's code at all: the key is machine-bound and a rebuilt application server cannot read what the
old one wrote (`UI-28`), Power BI and every other external reader sees ciphertext and there is no
view that will decrypt it (`UI-29`), and the `"Encrypted": false` flag in `appsettings.secrets.json`
is a **one-way** switch (`UI-30`). They are in this workbook because there is nowhere else yet, and
whoever deploys the application server needs them. The other two are yours: `UI-31`, a user who must
have a second factor and has none enrols **from the refusal itself** rather than from a settings page
they cannot reach; and `UI-32`, re-keying a factor reopens a one-step replay window, which is the
safe trade and needs to be the safe trade on purpose.

`UI-33` to `UI-39` came from Phases 3 and 4. `UI-34` belongs to whoever deploys rather than to whoever
builds screens — re-running a script against a database where the policy is bound fails with **Msg
3729**, and the fix is the drop-and-rebuild sequence documented above; read `UI-18` beside it, because an
empty grid in SSMS is row-level security and not data loss, and everybody meets that once. Three more are
error-message contracts a form has to get right: you cannot stamp `auditDeletedBy` yourself, the trigger
owns it (`UI-37`); **moving a record to another organization fails with Msg 547, not with an
authorization error** (`UI-38`), because the composite foreign key refuses before the policy is
consulted, so the message a user sees must not say "permission"; and an authentication-event row must
name somebody — a fully anonymous event is refused (`UI-39`).

**`UI-40` is the one that will change your queries, and it is the condition the row-security design was
accepted on.** Every query against a tenant-scoped table must filter by tenant *itself* — row-level
security is the net, not the `WHERE` clause. This is measured rather than advised: the predicate costs a
flat ~5 logical reads for **every row the query touches**, whether it admits that row or rejects it, so
an unfiltered aggregate returning 1,000 visible rows out of 200,000 pays for all 200,000 — 1,002,655
logical reads against 1,405 unprotected, a **714×** difference that is a property of the *query* and not
of the predicate. The same predicate on the same data costs 8 reads when the query is keyed. The constant
also rises with the size of the calling profile's scope, so a user with authority in fifty organizations
pays more per row examined on every query, including ones that return nothing. Get `ActingTenantId` from
`auth.uspGetProfileContext` once per request, put it in the `WHERE` clause, and let the policy verify
rather than discover. Treat an unbounded aggregate over a policy-bound table as a defect in review. Bulk
reporting is not this surface's job — Power BI reads the tables directly under its own credential
(`UI-29`). The numbers are in `docs/30-performance-measurements.md` §3.2.

`UI-41` and `UI-42` belong to whoever runs the scripts rather than to whoever builds screens, and they
are here because they cost an afternoon to find. **A `sqlcmd -v` value cannot contain a space, in any
quoting form** — not single quotes, not double quotes, not backslashes, not quoting the whole pair; all
four were measured. You get `'Name=a b': Invalid argument` and nothing runs, which reads like a broken
script rather than a broken command line. The way through is `UI-42`: sqlcmd resolves `$(Name)` from `-v`
**first** and from the process environment **second**, and an environment variable carries spaces,
commas and the `$` characters of a PHC string intact. The trap in that direction is that a leftover `-v`
of the same name silently wins over the variable you exported, with no warning.
`database/Install-TemplateDatabase.ps1` lines 448–452 is the worked example, and it removes
`$env:AdminVerifierPhc` in a `finally` because the value was a credential.

The dependency runs one way. The UI project may not require a change to the authorization model
without that change coming back through the design — the moment a screen needs a *role name*, the
model that lets each organization define its own roles has been broken.

### If you are adopting the template for a new application

The three application variants differ **only in seed data and tenant authentication policy rows**.
The tables, procedures and predicates are identical. See design §1.3 for the differences and §16
for what gets seeded.

That claim is now **executable** rather than asserted. `database/_tests/070_variants_end_to_end.sql` takes
`-v Variant=VARIANT1|VARIANT2|VARIANT3` and builds the named variant from an empty database using nothing
but procedure calls; **all three pass, once each, against one unchanged schema.** Run the one closest to
your application and read what it does as the shape of your own seeding script. The two levers are
`115_seed_reference_data.sql` for the vocabulary and `auth.TenantAuthenticationPolicy` for the sign-in
routes — and the second has no writer yet (`G-43`), so expect to insert those rows yourself.

### Reading the Build Log

> **Read the Build Log before concluding that a script disagrees with the design.** That conclusion
> is usually wrong and occasionally right, and the difference is not visible from the script. A
> deliberate divergence has an entry naming the reason and who decided; a divergence with no entry
> is a defect.

---

## Configuration

### Deployment-time

| Setting | Where | Notes |
|---|---|---|
| Server and database | `-ServerInstance` / `-DatabaseName` on the runner | Default to `MDE-55TT2J4` and `testTemplate`. Change the defaults in `database/Install-TemplateDatabase.ps1` or pass them per run |
| Target database | `-v DbName=<db>` on every installer | **There is deliberately no in-file default.** An in-file `:setvar` *overrides* `-v` rather than giving way to it, so a "harmless default" would silently win over the database you named |
| `RowHistory` | The Configuration table near the top of `SKILL.md` | Off by default: one table, current values only. On: system-versioned base table, view wrapper, three `INSTEAD OF` triggers. **Off for every table in this design** — the authorization trail is an event stream in `logs.AuthorizationChange`, which answers "who granted what, when, under what authority" better than a row-version history would |
| Role names | `database/005_schemas_and_roles.sql`, `database/170_permissions.sql`, the conventions' `scripts/permissions.sql` and the procedure templates | If your estate names roles differently, change them in all of those. A typo is a silently skipped grant, because every grant here is guarded on the principal existing |
| `ddl_audit_user` | `scripts/logdBChanges.sql` | The loginless principal the DDL trigger runs as. Rename only before the first run |
| Convention gate | `.claude/settings.json` | Runs `validate-sql.py` on every `Write` or `Edit`. Remove the hook entry to disable it |

### Runtime — `config.ApplicationSetting`

**These exist now** — `025_config_tables.sql` is deployed and seeded — so they are rows rather than
constants and change without a deployment. **Twenty-eight keys**, each carrying both its current value
and the `ShippedDefault` it came with, so "has anybody changed this?" is answerable from the table
itself. They arrive from **three** scripts with deliberately no overlap, because a setting seeded in two
places is a setting with two defaults and the second script to run wins silently: `025_config_tables.sql`
seeds **twenty-three**, `115_seed_reference_data.sql` **four**, and `175_perf_instrumentation.sql` the
probe burst count, which is the one key that is meaningless without the code in that file to read it.
Twenty are read by `110_auth_authn_procedures.sql` or `112_auth_mfa_procedures.sql` at the moment each
is needed rather than cached. Of the remaining eight, `Authz.AllowSelfGrant` is read by the
authorization side and appears permanently in the deployment report while it is on; the three
`Perf.PermissionProbe*` keys are read by `175_perf_instrumentation.sql`'s probe, which is off by
default; `Registration.ExternalBranchTenantCode`, `Registration.ThrottleThreshold` and
`Registration.ThrottleWindowMinutes` are read by `155_auth_registration_procedures.sql`; and
`Ui.CatalogueVersion` is read by `auth.uspGetNavigationForProfile` in
`150_auth_query_procedures.sql`.

> The counts above were **measured** against `config.ApplicationSetting` on 2026-09-21, not carried
> forward. Four artefacts had been saying "eighteen" and "three" since Phase 2, two revisions after it
> stopped being true, and nothing caught it because nothing executes a document (`BL-072`).

| Key | Shipped | Purpose |
|---|---|---|
| `Authn.LockoutThreshold`, `Authn.LockoutWindowMinutes`, `Authn.LockoutDurationMinutes` | 5, 15, 15 | Per **account**. Crossing the threshold writes `IsLockedOut` and a `LockoutEndUtc` an administrator can see and clear |
| `Authn.AddressThreshold`, `Authn.AddressWindowMinutes` | 20, 15 | Per **client address**, counted independently — this is the arm that stops credential stuffing, and it writes **no state anywhere**, so a throttle cannot outlive its window |
| `Authn.SessionLifetimeMinutes`, `Authn.IdleTimeoutMinutes` | 480, 60 | Fallbacks. A tenant's `auth.TenantAuthenticationPolicy` overrides both, and the resolved values are *stored* on the session so a policy edited at lunchtime cannot change a live session's lifetime |
| `Authn.LoginExchangeTimeoutSeconds` | 300 | How long round trip 1 stays valid. An expired exchange is **concluded** as a failure rather than left pending, because a pending row is a row neither throttle counts |
| `Authn.TotpStepSeconds`, `Authn.TotpWindowSteps` | 30, 1 | The clock tolerance for a TOTP code. A code outside it and a code replayed inside it both raise `E-50111`, deliberately the same number |
| `Authn.MfaKeyReferenceCurrent` | `dev:local/authn-mfa-kek#v1` | The **name** of the key that new factors are encrypted under, in the form `scheme:name#vN`. `auth.uspEnrolMfaFactor` stamps it onto the row and **refuses** any other label (`E-50118`), so a stale application encrypting under a retired key cannot enrol. `dev:` is not a production value; change this to a `cng:` reference and re-key |
| `Authn.MfaKeyReferenceSchemes` | `cng,vault,dev` | Which custody schemes are allowed at all. `cng` is a TPM-backed container on the application-layer server, `dev` is a workstation key with no hardware protection, and `vault` is **reserved** for a self-hosted HashiCorp Vault that is deliberately not adopted — a seam, so that moving custody later is this row plus a sweep rather than a schema change |
| `Authn.MfaEnrolmentWindowSeconds` | 900 | How long a sign-in refused for want of a factor stays usable as proof for a first enrolment. Separate from `Authn.LoginExchangeTimeoutSeconds` on purpose: that one is a round trip, this one is a person fetching their phone. **Set it to 0 and the bootstrap route closes entirely** — a configuration choice, not a fault, and the fallback is an administrator enrolling on the user's behalf |
| `Authn.MfaRecoveryCodeCount` | 10 | The **most** codes one batch may carry. `auth.uspIssueMfaRecoveryCodes` takes a JSON array of SHA-256 hashes — 64 hex characters each, distinct — and refuses an empty batch, an over-long one, a wrong length, a non-hex string or a duplicate as one error (`E-50121`), because they are all the same fault in the caller's generator. The codes themselves are generated by the application and shown once |
| `Authn.PasswordHistoryDepth` | 5 | How many previous verifiers a reuse check walks. A configuration value rather than however many rows a temporal table happens to hold. `auth.uspGetPasswordChangeContext` returns that many rows and the **application** compares them, because `D-08` means the database can no more compare a password than receive one |
| `Authn.PasswordLifetimeDays` | **0** | How long a password lasts. **0 means no expiry, and that is what ships** — the mechanism is delivered and the policy is the deployment's. Set it and `auth.uspExpireCredentials` starts stamping `MustChangePassword` on a sweep; until then the three password columns of `auth.uspGetProfileContext` are `NULL` for everybody and that code path is untested on your data (`UI-44`) |
| `Authn.PasswordExpiryWarningDays` | 14 | How far ahead `auth.uspGetProfileContext` sets `PasswordExpiryWarning`. Do **not** recompute this window in the application: the arithmetic is already done and a second copy of it is a second answer |
| `Authn.RequireStepUpForPrivilegedDefault` | **1** | What a privileged profile switch demands when **no** `auth.TenantAuthenticationPolicy` row resolves anywhere above the tenant. It ships at 1 so the template fails **closed**; before `G-30` closed, an empty policy table meant no step-up anywhere and nothing said so. Read by `auth.uspSwitchProfile` rather than by `auth.udfResolveAuthPolicy`, deliberately — the resolver is on the authorization hot path and a settings read there would cost one lookup per permission check instead of one per switch |
| `Authn.DummyVerifierPhcTemplate` | `$argon2id$v=19$m=19456,t=2,p=1$…` | The shape of the verifier handed back for a name nobody holds. The lengths must match the real ones — 97 characters — or the dummy is distinguishable by eye |
| `Authn.DummyVerifierPepper` | generated | **`IsSensitive = 1`, and the one row in the database denied to both application roles.** It derives the dummy per name, so two unknown names differ from each other exactly as two real accounts would |
| `Authz.AllowSelfGrant` | 0 | Whether an administrator may grant a role to a profile of their own user. Needed once for bootstrapping; turning it on is logged and appears permanently as a warning in the deployment report |
| `Perf.PermissionProbeSampleRate` | 0 | What fraction of permission checks `auth.uspDemandPermission` records to `logs.PermissionProbe`, as a percentage. **Ships at 0, which means the instrumentation costs nothing until somebody turns it on** — an off-by-default diagnostic rather than a tax everybody pays. Raise it when you are investigating, and put it back |
| `Perf.PermissionProbeBurstCount` | 25 | The most probe rows one session may write, whatever the sample rate says. The guard that stops a diagnostic left switched on from becoming the slowest thing in the database |
| `Perf.PermissionProbeRetentionDays` | 14 | How long probe rows are meant to live. The value is honoured by whatever purges them, which is nothing yet — the same gap as the rest of log retention (`G-13`) |
| `Registration.ExternalBranchTenantCode` | `EXTORG` | The `TenantCode` under which an approved Variant 3 organization is created. A configuration value rather than a literal in `155_auth_registration_procedures.sql`, because the tenant it names is seed data a project may rename |
| `Registration.ThrottleThreshold`, `Registration.ThrottleWindowMinutes` | 10, 60 | Per **client address**, counted over `auth.RegistrationAttempt` and shared by **both** public forms — organization registration and external-user registration draw on one budget, because an attacker does not care which endpoint they flooded. Crossing it raises `E-50068` and writes nothing. The arrival is recorded **before** any other validation, which costs a row per malformed request and is the point: a malformed request is the cheapest flood to generate. This does **not** close `G-06` |
| `Ui.CatalogueVersion` | a digest | A hash of every `(ElementCode, PermissionCode, AccessMode)` triple in the navigation catalogue, recomputed by `115_seed_reference_data.sql` and refused as `E-50230` when `auth.uspGetNavigationForProfile` is passed a different one. Labels, sort orders and parentage are excluded, so re-ordering a menu does not invalidate a build but renaming a **code** does. The one row `115` overwrites on a match, against its own rule, because it is a fact about the catalogue rather than an operator's tuning. Read `UI-43`: the argument is optional in the signature and mandatory in practice |
| Log retention | — | Per table. `Perf.PermissionProbeRetentionDays` states an intent for one table; nothing enforces it and no other table has even that. Gap `G-13` |

`config.ApplicationSetting` is granted to nobody at table level: `170_permissions.sql` grants
`SELECT` on `SCHEMA::config` to both roles and then **denies** this one table, because of that pepper.
The procedures still read it through ownership chaining. If an application ever needs to read
non-sensitive settings directly, the intended extension is a view filtered on `IsSensitive = 0` — named
in the script and deliberately not built until something needs it.

### Deployment-time — `config.TenantScopedTable`

**The registry that decides which tables row-level security protects.** One row per protected table,
naming its schema, its table and its tenant column; `120_rls_policy.sql` reads it and builds four
predicates per row — one `FILTER` and three `BLOCK` operations. It ships holding the two demo tables:

| Schema | Table | Tenant column |
|---|---|---|
| `dbo` | `CaseFile` | `TenantId` |
| `dbo` | `CaseNote` | `TenantId` |

Adding a tenant-scoped table to a project therefore means **two** things, and the second is the one that
gets forgotten: insert the row, then **re-run `120_rls_policy.sql`**. A table that is in the registry but
not in the policy is unprotected and nothing says so — that is gap `G-01`, the only Critical gap still
open, and the reason it is Critical is that the failure is silent and looks exactly like working
software. A table that is in the policy while the permission catalogue has changed underneath it is the
opposite failure, `UI-35`, and is equally silent.

### Runtime — `auth.TenantAuthenticationPolicy`

The one table that makes three application variants into one design. Policy inherits down the
tenant tree: a tenant with no row of its own uses its nearest ancestor's.

| Variant | Policy rows |
|---|---|
| Agency + jurisdictions | Root: local + TOTP. Agency: federated preferred, local permitted only for platform administrators. Jurisdictions inherit root |
| Agency-internal by program | Root: local + TOTP. Agency: federated preferred. Administrations and programs inherit the agency — no rows below it at all |
| Agency + external organizations | Root only: local + TOTP, federated not permitted. Everything inherits |

**You write these rows by hand.** `900_bootstrap_first_admin.sql` inserts the root row once — and inserts
it with `RequireMfaForLocal = 0`, because the administrator it is creating has no factor yet — and no
shipped procedure writes the table at all. That is gap `G-43` for the missing procedure and gap `G-37` for
the row the bootstrap leaves behind; the second one **blocks a production deployment**. Read the two rows
of this table you care about, write them, and set the root flag back to 1 once the first administrator has
enrolled. Nothing checks that you did (`G-04`).

### Environment-specific

Connection strings, signing keys and the key-encryption key that wraps the TOTP seeds live outside
this repository and outside the database. **No secret in this design is recoverable from the database
alone** — the TOTP seed was the exception until `G-07` was decided, and is not one now: the database
holds the ciphertext and the *name* of the key, and nothing in it can turn that name into key
material under any role.

Per management, the application's own secrets live encrypted in `appsettings.secrets.json` — the SQL
Server login password, an API ID and an API key today, and the list is expected to grow. The file
carries an `"Encrypted": false` flag; the application validates every entry, encrypts them, and sets
the flag to true. That is an application-side process with no database half at all, and it is
mentioned here because the flag looks like configuration and is in fact a one-way migration: once
true, the plaintext is gone. `UI-30`.

The key-encryption key itself is a TPM-backed CNG container on the **application-layer** server. The
web front end does not hold it and does not need it. It is machine-bound, which is the protection and
also the risk — a rebuilt server cannot read what the old one wrote, so the recovery story is enrolled
users re-enrolling. Plan for that before you need it. `UI-28`, design §6.4.

---

## Known gaps

**51 are tracked in `workbooks/gaps.xlsx`; 24 are now Closed.** The count went up as the build went on,
which is the register working rather than the project decaying — a gap filed is a gap somebody can argue
with, and most of the rows closed so far were filed by the phase that built the thing they are about.
Nine closed in one pass on 2026-09-21, and the thing worth taking from that pass is not the nine: it is
that **four of the seven Build Log entries it produced exist because the gap row was wrong**. A proposed
resolution is worth nothing until somebody has tried to build it.

Seven more were filed the same day by the **scenario 1 test** — `G-45` to `G-51` — and they are the reason
the count jumped. Not one of them is a design error and not one is an object misbehaving; they are things
**no object says**, and they became visible only because a named customer's organisation was loaded as data
and asked to do its job. Two were found before a single row was inserted, because the seed data had no role
meaning "can do the work" and none meaning "can assign profiles". **All seven were closed later the same
day** by `T-125`–`T-130`, which is why no row from that batch appears in the list below.

The most useful thing about that batch is not the seven artefacts, it is **what closing them did to the
tests that found them**. Three sections of `S1_prove_duties.sql` existed to prove that `G-48`, `G-50` and
`G-51` reproduced. A test that proves a gap reproduces becomes a green light pointing the wrong way the
moment the gap is fixed, so all three were inverted — and two of the three now assert a *behaviour* rather
than an artefact, which is the harder and more durable thing to do. Section 6 does not check that
`UserSessionId` exists on the audit row; it counts the same switches twice, once by joining on the session
and once by correlating on name and time the way an auditor used to be forced to, and requires the two
counts to be **equal**. Section 7 does not trust the `OUTPUT` parameter of the new step-up procedure; it
reads the session row back and compares them, because a procedure that returned an elevation time it had
not persisted would leave the `E-50052` refusal exactly where it was and reopen `G-48` underneath a passing
test. The one gap in the batch that was not closed by an artefact at all is `G-49`, which closed as
**measured rather than fixed**: nothing was broken, something was unmeasured, and the answer is
`docs/30-performance-measurements.md` §9.

**Three block a production deployment**, and a fourth blocks one variant. They are listed here in full
because a reader who takes nothing else from this page should take these:

- **`G-01` — nothing continuously verifies that every tenant-scoped table is registered and covered by a
  security predicate.** Now the **only** open `Critical` in the project, and the oldest unclosed row in it —
  `G-48` was the other one and was closed on 2026-09-21. An unregistered table returns every tenant's rows to
  every tenant, with no error and nothing in any log. It **fails open, silently**, and looks exactly like
  correct operation. Checked at deployment time today; it needs to be a scheduled job. Phase 4 made this
  sharper rather than safer: `120_rls_policy.sql` now proves the mechanism works, so the only thing
  standing between a new table and universal exposure is somebody remembering to register it.
- **`G-37` — the bootstrap writes a root authentication policy with `RequireMfaForLocal = 0`.** High, and
  the circularity behind it is genuine: `uspCompleteLogin` fails **closed** when no policy resolves, the
  bootstrapped administrator has no confirmed factor, and enrolling one needs a live session. So the
  bootstrap must relax the root row — and policy inherits nearest-ancestor-wins, which makes that row the
  effective policy for every tenant beneath it that has not written its own. The script prints the
  instruction to enrol a factor and set the flag back to 1. Until `950_verify_deployment.sql` asserts it,
  **that `PRINT` and this paragraph are the control.**
- **`G-14` — no break-glass path for a locked-out last platform administrator.** High.
  `900_bootstrap_first_admin.sql` refuses to run once any profile exists, which is exactly what stops the
  bootstrap being a back door — and it also means a database nobody can administer has no recovery. The
  resolution is a documented dual-control DBA procedure run under `db_owner`, writing a high-severity
  event: a physical-access control, not a permission.
- **`G-06` — no anti-automation on Variant 3 public registration.** Medium, and it blocks **Variant 3**
  go-live only. **One of its three controls now exists and the row is still open, deliberately.**
  `auth.uspRecordRegistrationAttempt` counts arrivals per client address over `auth.RegistrationAttempt`
  and both public entry points refuse a crossed threshold as `E-50068`, on one shared budget, with the
  arrival recorded *before* any other validation because a malformed request is the cheapest flood to
  generate (`G-24`, closed). The other two controls are edge rate limiting and a challenge on the form,
  and both are on the far side of a network boundary this database does not reach: a counter behind an
  unlimited public form is a control an attacker pays for **once per address**. Closing this row on the
  strength of the throttle would have been the register telling a project it is protected where it is
  not, so DES §16.4 carries a paragraph headed *`G-06` is not closed by the throttle* and
  UIH-AUTH-001 §8 item 9 says the same thing to the team that owns the form.

Three smaller open rows are worth knowing before they surprise you. **`G-31`** — two procedures apply the
same pair of checks in opposite order, so which refusal you get depends on which one you called.
**`G-41`** — `auditCreatedBy` is populated from different sources in different scripts. **`G-13`** — log
retention is configured in one place and enforced nowhere.

**`G-39` is the only gap in the register that exists because of a measurement**, and it is worth reading
for that reason alone. One call with `@UserProfileId = NULL` rebuilds **all 5,000** profile scopes in
**181 ms**. A thousand calls each naming one profile take **40,555 ms** — 40.6 ms and 1,470 logical reads
apiece, most of it a transaction, a session-context establishment, a permission demand and two
`logs.ExecutionLog` writes rather than the scope computation. **The blunt instrument does five times the
work in a 224th of the time**, and the procedure has no list parameter, so the surface quietly tells an
administrator retiring a role to loop. Nothing was broken and no design was wrong; a number was taken and
it turned out to matter. Everything else in the register came from reading the design or from a test being
unable to write an assertion.

**Nine rows closed on 2026-09-21, and the four departures are the part worth reading.** `G-12`
(credential expiry), `G-18` (nothing stamped the UI catalogue), `G-21` (no issuer allow-list), `G-24`
(no registration throttle), `G-27` (the four `User.*` permissions are deliberately not tenant-scoped),
`G-30`, `G-32` (no number for a malformed element inside a well-formed bulk array), `G-42` and `G-43`
(two per-tenant configuration tables with no writer). Four were delivered differently from what their
own rows proposed, and in each case the row was wrong rather than the implementer inventive:

- **`G-42` asked for two procedures and got four.** `D-08` puts Argon2id in the application, which has
  a consequence nobody had written down: a database that never receives a password cannot *compare* one
  against a stored PHC string either, because that needs the hashing parameters and a per-verifier salt.
  So the reuse check had to become a read procedure plus an argument —
  `auth.uspGetPasswordChangeContext` — exactly as sign-in is `uspGetLoginVerifier` plus a verdict.
  `auth.uspExpireCredentials` is `G-12`'s sweep, folded in because a password that cannot be set cannot
  usefully expire.
- **`G-43` asked for a `Tenant.Manage` permission that is not in Appendix A.** The writers demand
  `Tenant.Update`, with `Authz.RoleAssign` added to the default-roles one because a default-role list is
  a standing grant rather than a label. `Config.Manage` was considered and rejected: it is
  platform-wide, and using it would have turned a per-tenant screen into a platform-administrator
  screen.
- **`G-18` asked the *application* to assert the catalogue version at start-up.** The **database**
  refuses a mismatch instead (`E-50230`), because a control the caller may skip is not a control and a
  catalogue can be extended while an application is running. `@ExpectedCatalogueVersion` is optional in
  the signature and mandatory in practice, which is `UI-43` and is why it is `High`.
- **`G-32` named `auth.uspAssignRolesToProfiles`, which has never existed** — and neither has the
  Appendix B row for `E-50046` that named it too, for four phases. `INV-04`, `INV-05` and `INV-06` are
  each evaluated against the grant in hand, so a set-based `MERGE` over profiles could not check them
  and never will. `E-50180` was **raised** from the two new writers before it was registered, because
  registering it first would have put a permanently unaccounted row in the `_tests/080` ledger — a
  report that always fails.

Two of the nine were closed with **no code at all**. `G-27` kept the design and promoted its reasoning
into a rule: DES §11.4 now states that any attribute not needed to identify a person belongs on a
tenant-scoped table, and gives three consequences rather than restating the position. And the pass
**filed** a row as well as closing them — `G-44`, `Low`: nothing deletes an
`auth.TenantAuthenticationPolicy` row, so a tenant cannot be returned to inheriting its parent's
policy. It was found because a test had to reach past the shipped procedure surface and hand-soft-delete
one to keep measuring the no-policy path, which is the most reliable way this project has found of
noticing a missing procedure.

**`G-07` — closed 2026-09-20, and worth reading closed.** It was the other Critical row, and the only
gap in this project that cost something *while it was open*: `T-041` was `Blocked` on it, so MFA
enrolment did not exist, everything that consumed a second factor had to be tested against a factor
inserted directly by `db_owner`, and one fixture account was permanently unable to sign in. The
decision was not this project's to make, and management made it —
`additionalRequirements-T-041.txt`, recorded verbatim in the gap row. **Always Encrypted was rejected
outright**, for reasons specific to a template rather than to this schema: external services read
these tables directly and Power BI is named, so encrypted columns would have gone dark for every
project built on the template, and a template does not know which columns a project will add, so it
cannot know which to enrol. What was chosen instead is **application-side envelope encryption** under
a **TPM-backed CNG key on the application-layer server** — the web front end holds nothing. The
database holds opaque bytes and the *name* of the key that made them, and can turn that name into key
material under no role at all. A self-hosted HashiCorp Vault is not adopted and the `vault:` scheme is
reserved for it, so that changing custody later is one setting and a re-key sweep. Implemented the
same day by `112_auth_mfa_procedures.sql`, the `KeyReference` grammar in `045_auth_identity.sql` and
four `Authn.Mfa*` settings; verified by section 12 of `_tests/040`, where the fixture user who could
not sign in at all enrols from the exchange that refused him. What is **not** verifiable from the
database, and never will be, is that a `cng:` label is genuinely TPM-backed and that the ciphertext is
a real envelope — both are the application's, by the same decision, and `UI-28` to `UI-32` carry them
to the teams that own them.

**`G-19` — closed in Phase 2**, earlier than its Phase 8 target, because
`110_auth_authn_procedures.sql` could not run until it was. The conventions `permissions.sql` grants
and denies nothing at all on `SCHEMA::config` or `SCHEMA::util`, so both were invisible to
`applicationRole` and `readOnlyRole` with no error anywhere — the kind of finding a grant written
beside its own object can never make, because it is an **absence**. `170_permissions.sql` now states
every one of the seven schemas for every role and fails on one that is neither granted nor denied. One
half remains open and is tracked as `BL-029`: the matching assertion belongs in
`950_verify_deployment.sql`, which is Phase 8, so an ad-hoc `REVOKE` after deployment is still caught
by nothing.

**`G-20` — closed in Phase 2**, in the design document and before Phase 3 began, which is where its
own resolution insisted it be done rather than at the gate under time pressure. It was a disagreement
between two artefacts of this repository rather than an omission in either: design §14.6 specified
**table-valued parameters** for bulk grant and revoke, and the convention gate rejects
`CREATE TYPE … AS TABLE` outright, because a TVP type needs its own `EXECUTE` grant on the `TYPE` that
no deployment script here issues — so the procedure would deploy, pass every check, and fail for the
application with a permission error on a type nobody thinks of as a securable. The gate's reason was
the stronger one, so **the design changed**: an `NVARCHAR (MAX)` JSON array shredded with `OPENJSON`
under an `ISJSON (@Payload, ARRAY) = 0` guard, and task `T-045` deleted rather than re-scoped, because
with no type to create it had no content. The gate is a participant in this design, not a lint pass
over it.

**`G-21`** was found by a test being *unable to write an assertion*. Nothing in the database constrains
**which issuer** a federated sign-in may come from: any string in `@Issuer` that matches a stored link
is accepted, so `_tests/040` can prove a wrong subject resolves to nobody and can say nothing whatever
about a wrong issuer. The application is trusted for that today, which is a real trust boundary and is
filed rather than assumed. Its target was Phase 3 and **Phase 3 did not resolve it** — the phase built
authorization, and a trusted-issuer list belongs to `auth.TenantAuthenticationPolicy` and
`uspBeginSsoLogin`, neither of which Phase 3 touched. It stays open with a resolution written out: a
child table keyed by `(TenantId, Issuer)` and a new refusal in the `50100` range.

**`G-22` and `G-23` came out of Phase 4 and both closed on 2026-09-20.** They are the pair most worth
reading closed, because one of them predicted its own failure and the prediction came true before the fix
did.

- **`G-22` — the authorization hot path was the only unmeasured path in the database.** Closed by
  `175_perf_instrumentation.sql`. Every writing procedure here is instrumented;
  `auth.udfHasPermission` and the predicates were not, because a function cannot write and a predicate
  that logged per call would double the cost of the thing it was measuring. What shipped is a **sampled**
  probe written by the *procedure* — `Perf.PermissionProbeSampleRate`, seeded at **0** — with a burst
  count and a retention setting beside it. **The probe's own cost was measured rather than assumed**, and
  that is what justifies the sampling: reading the configuration alone is 5 logical reads against the
  demand procedure's 12, so an unconditional probe would have been **42%** of a permission check. It also
  shipped one thing the resolution never asked for and which turned out to be the most useful thing in
  the file: `logs.vwPredicateFunctionStats` builds its list of the six security functions from a `VALUES`
  constructor and `LEFT JOIN`s the DMV, because **an inlined scalar function vanishes from
  `sys.dm_exec_function_stats` entirely** and inline table-valued functions never appear at all — so a
  naive query reports the hot path as never called, which is indistinguishable from a predicate that is
  not bound. The extended-events session is shipped as a statement to run, not created by the install,
  because a deployment that creates a server-level XE session reads as a broken deployment.
- **`G-23` — a new `logs` table was writable by `applicationRole` until somebody remembered to deny it.**
  Closed by the inversion this row itself proposed, and **not** by adding a fifth name. The prediction
  came true first: Phase 5 created `logs.PermissionProbe`, the inherited `SCHEMA::logs` grant made it
  writable on the day it was created, and `170_permissions.sql` printed "no problems found" on every
  deployment for three phases — measured, `HAS_PERMS_BY_NAME` returned 1, 1, 1 for the probe against 0, 0,
  0 for the four trails. `170` now **enumerates** `sys.tables` in `SCHEMA::logs`, subtracts a list holding
  `logs.ExecutionLog` with its reason, denies the three write verbs on everything else, and reports
  `EXEMPT`/`OK`/`VIOLATED` per table with a count row beside it, so an empty `logs` schema cannot pass as
  a clean one. The lesson is the uncomfortable one: **this row did not prevent what it predicted.** The
  warning asked a future reader to act at a moment nobody could name, and the person who added the table
  was not reading `170`. `BL-066`.

Five rows — `G-05`, `G-10`, `G-11`, `G-15`, `G-17` — are deliberate design positions rather than
omissions, recorded with their reasoning so a reviewer can disagree with the reasoning. One of them,
`G-17`, has "resist" as its resolution. That is a different conversation from pointing out an oversight.

Two more are open against a *future event* rather than against today: `G-04` is blocked by the first
production change to either policy table, and `G-16` by the first reporting requirement. They are not
work anybody can do now, and they are on the register so that the event does not arrive as a surprise.

---

## Contributing

<!-- TODO: replace with your team's actual process before publishing -->

- Branch from `main`, one branch per task ID from the tracking workbook (`T-089-seed-reference-data`).
- Every SQL file must pass `.claude/hooks/validate-sql.py` before commit.
- Update the task row and, where the code diverged from the design, add a Build Log entry.
- Design changes go through `docs/10-database-authn-authz-design.md` with a version bump — not
  through a script comment.

**A note on the workbooks.** They are `.xlsx`, so Git cannot diff or merge them: two people editing
the tracker on separate branches produces a conflict only one of them can resolve, by hand. Until
that becomes painful enough to fix, the simplest arrangement is that one person owns each workbook
and others raise changes to them. If it does become painful, the fix is a CSV export committed
alongside the workbook, not a different tracker.

---

## Documentation

| Document | What it is |
|---|---|
| [`docs/00-documentation-index.md`](docs/00-documentation-index.md) | The map. Start here |
| [`docs/10-database-authn-authz-design.md`](docs/10-database-authn-authz-design.md) | DES-AUTH-001 — the design |
| [`docs/20-project-plan.md`](docs/20-project-plan.md) | PLAN-AUTH-001 — the plan |
| [`docs/30-performance-measurements.md`](docs/30-performance-measurements.md) | PERF-AUTH-001 — every number Phase 5 measured, with the scripts that produced them and the conditions they hold under. Read §1 before quoting any of it: **logical reads are stable and microseconds vary by up to 20%**, so the reads are the finding and the timings are context. §3.2 is the D-07 go/no-go and `UI-40`'s evidence |
| [`docs/40-ui-handoff-m4.md`](docs/40-ui-handoff-m4.md) | UIH-AUTH-001 — the M4 handoff to a UI project: the procedures a client calls, in the order a request calls them, with what each returns. **Frozen at M4**, so it describes what is deployed and not what is planned; §8 is the honest list of what it does *not* deliver |
| [`docs/60-scenario-test-1.md`](docs/60-scenario-test-1.md) | SCEN-AUTH-001 — the scenario 1 test: the population it builds cohort by cohort, the four runs, what the eighteen connections of the prover settle, what four green runs deliberately do **not** claim, and the seven gaps it filed |
| [`.claude/skills/ponytail-sql-objects/SKILL.md`](.claude/skills/ponytail-sql-objects/SKILL.md) | The SQL conventions. The authority |
| [`.claude/skills/ponytail-sql-objects/README.md`](.claude/skills/ponytail-sql-objects/README.md) | How to install and use the conventions skill, with a troubleshooting table worth reading before you need it |
| [`.claude/skills/ponytail-sql-objects/references/instrumentation.md`](.claude/skills/ponytail-sql-objects/references/instrumentation.md) | Conventions rule 8 in full — including why `logs.ExecutionLog` has permanent gaps in its identity sequence. Read it the first time you notice one and wonder what was deleted: nothing was |
| [`tools/T040-PasswordVerification/README.md`](tools/T040-PasswordVerification/README.md) | The client half of `D-08`: what the .NET harness proves, what it deliberately does not claim, and why its timing figures are `INFO` rather than pass-or-fail |

---

## License

<!-- TODO: decide before making this repository public. -->
Not yet determined.

## Maintainers

<!-- TODO: names and contact before publishing. -->
