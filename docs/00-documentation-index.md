# Documentation Index

**Document ID:** IDX-AUTH-001
**Version:** 2.1
**Date:** 2026-09-25
**Covers:** the database authentication and authorization template
**Changed in 2.1 (2026-09-25):** Four defects were found downstream by the WellDrillersLicense build, carried back and **closed**: `G-52`–`G-55`, build log `BL-086`. For each, the test was written first and failed on an unfixed clean build.
- `G-52` (**Critical**): a refused sign-in was enrolment proof even for an account that already had a factor. The password alone could therefore issue working recovery codes for a TOTP account. `auth.udfResolveEnrolmentActor` is now first-factor only, and `_tests/040` §12m′ proves it.
- `G-53`: E-50061 and E-50066 were never raised by any test, so 080's coverage check failed on a clean build. The new `_tests/075_registration_probes.sql` raises both.
- `G-54`: the 900 root-policy note overflowed `NVARCHAR (1000)`, so every fresh bootstrap failed (Msg 2628).
- `G-55`: re-granting a revoked role through `auth.uspAssignRoleToProfile` always failed with E-50010. `trg_au_updt_UserProfileRole` now lets a resurrection re-stamp `GrantedUtc` and `GrantedByProfileId`, and `_tests/080` §8b″ proves it.
- `G-56` (BL-087): re-running 115 withdrew the View gates of elements another script had added, so they became visible to every profile. It also seeded the CaseFile demo menu without the demo domain. Gate withdrawal is now limited to 115's own elements, and the demo elements follow `dbo.CaseFile`. It was proved downstream on builds with and without the demo; the test was not written first.

010–080 now pass on a fresh build and on a re-run (`_tests/Build-Upstream.sh`).

**Changed in 2.0:** **All seven gaps the scenario test filed one version ago are closed**, `G-45`–`G-51`,
by `T-125`–`T-130` — and with them **Phases 0 to 7 are complete in full**, so the only eight tasks left in
the workbook are Phase 8 Verification. The tracking workbook reads **129 tasks, 109 person-days estimated,
74.25 actual, 121 Complete**. Seven Build Log entries, `BL-079`–`BL-085`. Five UI gotchas, `UI-50`–`UI-54`,
and **two rewritten**, which is the part to notice: `UI-46` told the UI team to query `auth.UserProfile`
directly and `UI-48` said the step-up challenge was *"a dead end, not a challenge"*, and a gotcha that
tells you to work around something that has been fixed is worse than no gotcha at all. Gap rows now read
**51, of which 31 Closed**, and **`G-01` is the only open `Critical` left** — it has been there since the
design. The `Traceability` sheet has **no `Gap` row at all** for the first time.
The single most valuable artefact is `auth.uspElevateSession` (`G-48`, `Critical`): the step-up challenge
that guards every privileged profile can now be answered, where **0 of 271** sessions had ever been
elevated. **What the closures are worth reading for, though, is a rule about tests.** Three sections of
`S1_prove_duties.sql` were written to prove `G-48`, `G-50` and `G-51` reproduced; a test that proves a gap
reproduces becomes a **green light pointing the wrong way** the moment the gap is fixed, so all three were
inverted — and two were deliberately written to assert a *behaviour* rather than an artefact. Section 6
does not check that `UserSessionId` exists; it takes the same count by joining and by correlating and
requires the two to be **equal**. Section 7 does not trust the `OUTPUT` parameter of the new procedure; it
reads the row back and compares, because a procedure returning a time it had not persisted would reopen
`G-48` underneath a passing test. `G-49` closed as **measured, not fixed** — nothing was broken, something
was unmeasured — and PERF-AUTH-001 §9 is new: 128 sign-ins on 16 simultaneous connections with **zero
milliseconds of `LOCK` waiting**, a bulk role change linear to 1,000 profiles with **no table-level lock**,
and 160 switch-versus-deactivate pairs with **no deadlock against 80 in a positive control**. That control
is the lesson, not the number: without it the detector reported a clean bill of health while being
**structurally unable to see a deadlock** (`UI-53`). Three of the seven closures also departed from what
the gap row proposed, and the departures are recorded in `workbooks/gaps.xlsx` rather than smoothed over.
DES-AUTH-001 stays at **v1.7** and UIH-AUTH-001 at **v1.1**: as version 1.9 said, not one of the seven was
a design error, and closing them proved it — every one was answered by an artefact, not by a redesign
**Changed in 1.9:** A **scenario test**, which is a thing this project had not done before: a named
customer's organisation — one state agency, 67 counties, ~12,830 users, thirteen cohorts — loaded as data
and then asked to do its job. `test_scenario_1.txt` asked for it four times over, and **all four runs pass
at exit 0**: on the existing `testTemplate`; on a new `testTemplateS1`; on that database again with the user
count doubled and the tenant count deliberately unchanged; and a fourth time with a second agency of 100
counties beside the first, ending at **171 tenants, 44,432 users, 103,352 profiles and 366,452 scope rows**.
Two new scripts under a new directory, `database/_scenarios/`, neither in the install manifest and neither a
test fixture — a *population* is something you use, not something you assert against and throw away. One new
document, `docs/60-scenario-test-1.md` (SCEN-AUTH-001). Three tasks added and complete, `T-122`–`T-124`, so
the tracking workbook reads **129 tasks, 109 person-days, 115 Complete**. Three Build Log entries,
`BL-076`–`BL-078`. Four UI gotchas, `UI-46`–`UI-49`. Seven traceability rows, of which **five are `Partial`
or `Gap`**. **And seven gap rows, `G-45`–`G-51`, one of them `Critical`** — which is the reason this version
exists. `G-48`: no shipped procedure writes `auth.UserSession.ElevatedUntilUtc`, so the step-up challenge
that guards every privileged profile **cannot be satisfied by anything in the database**. Measured: 271
sessions in `testTemplate` and **0 ever elevated**; 2,490 users holding a privileged profile on the four-run
database; 169 of 169 tenant policies requiring step-up; and the shipped default requiring it too. Every
platform administrator and every "can assign profiles" cohort in the scenario is locked out of the profile
they exist to hold, and **it hid for the entire build because all five policy fixtures in this repository set
`RequireStepUpForPrivileged = 0`**. Alongside it: the hat menu cannot be built from the procedure surface
(`G-51`), the profile-switch audit trail carries no session id (`G-50`), `Data.Execute` is seeded and
enforced nowhere (`G-45`), and the seed data has **no role meaning "can do the work" and none meaning "can
assign profiles"** (`G-46`, `G-47`), so the loader had to invent both before it could place a single profile.
DES-AUTH-001 stays at **v1.7** and UIH-AUTH-001 at **v1.1**: not one of the seven is a design error.
**The finding worth carrying out of this version is about where gaps come from.** None of these seven was
findable by re-reading the design, and five of them were not findable by any test in the suite — because
every fixture in `database/_tests/` builds the profiles it needs directly and so can never discover that the
seed pool is missing a role, and every test knows which profile it wants and so never needs a menu. It took
a population that was large, awkward and *shaped like a real customer* to make them visible
**Changed in 1.8:** The 2026-09-21 gap-closing pass **verified** — a full thirty-nine-step
redeployment at exit 0 followed by the whole test suite in the documented order, `010` through `080`
with `070` once per variant, every file exit 0 — and the two defects that pass found, **both of them
in tests rather than in anything the tests examine**. `_tests/030` threw seven `VIOLATED` rows on a
closure that was provably correct; `_tests/060` reported the row-security policy stale while printing
the fixture's own permission id inside the very list it claimed was missing. Two new tasks, `T-120`
and `T-121`, filed under **Phases 1 and 4** because each repairs that phase's own exit-criteria test,
so the tracking workbook reads **120 tasks, 100.5 person-days, 112 Complete**. Two Build Log entries,
`BL-074` and `BL-075`, which are the first on that sheet where neither the design nor a shipped object
was wrong. One new UI gotcha, **`UI-45`**, and it was filed *from a test*: a soft-deleted tenant leaves
`auth.vwTenantHierarchy` together with its whole subtree while `auth.uspRebuildTenantClosure`
deliberately keeps its closure pairs live, so a tree built from the view and a decision taken by
`auth.udfIsTenantUsable` disagree about the same tenant — which is `BL-020` working as designed and
is also how an administrator ends up troubleshooting a lockout against the one source that has
already hidden the cause. **No gap row moved and no design document changed**: twenty-four of the
forty-four still Closed, DES-AUTH-001 still **v1.7**, UIH-AUTH-001 still **v1.1**; PLAN-AUTH-001 goes
to **v1.8** for the task and effort figures. One count in this file was found stale and re-measured
from `135_audit_triggers.sql`'s own report: the five-schema audit-trigger census is **thirty-six
triggers over thirty-seven tables**, not thirty-four over thirty-five. **The finding worth carrying
out of this version is about the direction of a test failure.** Both defects failed *towards* alarm,
and a test that calls a correct database broken is worse than one that never runs, because it teaches
the next reader to explain the report away — and the run after that is the one where the report is
true
**Changed in 1.7:** **Nine gap rows closed in a single pass** — `G-12`, `G-18`, `G-21`, `G-24`,
`G-27`, `G-30`, `G-32`, `G-42` and `G-43` — and with them most of the counts in this file, because
almost every "how many" sentence here is downstream of the gap register. **Seven new procedures and
two new tables**, no new scripts: `auth.uspSetPassword`, `auth.uspGetPasswordChangeContext`,
`auth.uspChangePassword` and `auth.uspExpireCredentials` in `110_auth_authn_procedures.sql`;
`auth.uspSetTenantAuthenticationPolicy` and `auth.uspSetTenantDefaultRoles` in
`125_auth_tenant_procedures.sql`; `auth.uspRecordRegistrationAttempt` in
`155_auth_registration_procedures.sql`; `auth.TenantTrustedIssuer` in `035_auth_tenant_policy.sql`
and `auth.RegistrationAttempt` in `080_auth_registration.sql`. `auth.uspGetProfileContext` gained
three password-expiry columns and `auth.uspGetNavigationForProfile` gained an optional
`@ExpectedCatalogueVersion`. Eleven new error numbers — `E-50068`, `E-50097`, `E-50098`, `E-50124`,
`E-50180`, `E-50220`–`E-50224` and `E-50230` — so **Appendix B now runs to `E-50230`** and the
`_tests/080` ledger, **re-measured rather than recalculated, reads 122 throwable / 117 observed / 96
probed / 6 accounted / none unaccounted** against 111/106/88 at v1.6. Seven Build Log entries
(`BL-067`–`BL-073`), two UI gotchas (`UI-43`, `UI-44`), seven tasks (`T-113`–`T-119`, 7.0 days
estimated against 7.0 actual) and one new gap, `G-44`, filed by a test's own cleanup because nothing
deletes a policy row. **Twenty-four of the forty-four gaps are now Closed.** DES-AUTH-001 is at v1.7
and UIH-AUTH-001 at v1.1 — the first amendment to the frozen `M4` contract, taken through its own
§10 change-control rule, which is what `BL-071` exists to record. **The production-go-live list
halved**: `G-30` and `G-42` are closed, leaving `G-01`, `G-14` and `G-37`, all three of them Phase 8
rows from the design pass rather than anything the build discovered. **Four of the seven Build Log
entries exist because the gap row was wrong about something** — a procedure named in `G-32` and in
Appendix B that this template never built, a permission named in `G-43` that is not in Appendix A, a
control `G-18` asked the *application* to assert, and a settings count four artefacts had been
repeating since Phase 2. That is the transferable finding of the pass and `BL-072` is where it is
argued
**Changed in 1.6:** Phases 5, 6 and 7 executed and complete — the counts, the state-of-execution
notes, and the new artefacts. **Two new documents are registered here for the first time**, and both
are authoritative rather than explanatory: `docs/30-performance-measurements.md` (PERF-AUTH-001), the
record for every performance number this project quotes, and `docs/40-ui-handoff-m4.md`
(UIH-AUTH-001), the frozen `M4` contract. Twelve new scripts (`075_auth_ui_catalog.sql`,
`080_auth_registration.sql`, `115_seed_reference_data.sql`, `130_auth_user_procedures.sql`,
`135_audit_triggers.sql`, `140_auth_profile_procedures.sql`, `145_auth_role_procedures.sql`,
`155_auth_registration_procedures.sql`, `160_auth_admin_procedures.sql`,
`175_perf_instrumentation.sql`, `180_dbo_application_procedures.sql`,
`900_bootstrap_first_admin.sql`, and `090` and `150` completed rather than partial), two new test
files (`_tests/070`, `_tests/080`), three new `_perf` scripts, seventeen Build Log entries
(`BL-050`–`BL-066`), three UI gotchas (`UI-40`–`UI-42`), twenty gaps (`G-24`–`G-43`, nine of them
closed in the same batch) and thirty-four tasks closed (`T-069`–`T-102`). **Fifteen of the
forty-three gaps are now Closed**, four of them during this pass rather than during the phases:
`G-09` and `G-22`, which the Phase 5 measurements had already answered and which a target-phase sweep
found still marked Open; `G-18`, whose claim to block `M4` was withdrawn in writing after `M4`
shipped; and `G-23`, which was closed by discovering that **its own prediction had come true** —
`logs.PermissionProbe` was writable by `applicationRole` for three phases while
`170_permissions.sql` reported no problems (`BL-066`). **Thirty-six of the thirty-seven project scripts are written and one remains** —
`950_verify_deployment.sql`, `T-104`; the manifest is **thirty-nine** steps; `M3` and `M4` are both
reached and `D-07` is a formal GO. DES-AUTH-001 is at v1.6 with sixteen sections amended and
Appendix B widened to `E-50211`; PLAN-AUTH-001 is at v1.6 with Phases 5–7 closed at 26.0 person-days
against 35.5. `G-01` is **no longer the only Critical gap conversation**: three gaps now block
production go-live — `G-30`, `G-37` and `G-42` — and none of the three is a Critical severity row,
which is the more useful thing to know about them
**Changed in 1.5:** Phases 3 and 4 executed and complete — the counts, the state-of-execution notes,
and the new artefacts. Eight new scripts (`050_auth_permission.sql`, `055_auth_role.sql`,
`060_auth_profile_role.sql`, `065_auth_effective_permission.sql`,
`105_auth_session_procedures.sql`, `120_rls_policy.sql`, `150_auth_query_procedures.sql`,
`165_logs_procedures.sql`), two new test files (`_tests/050`, `_tests/060`), fourteen Build Log
entries (`BL-036`–`BL-049`), seven UI gotchas (`UI-33`–`UI-39`), two gaps (`G-22`, `G-23`), and
twenty-five tasks closed (`T-043`, `T-044`, `T-046`–`T-068`). Twenty-four of the thirty-six project
scripts are now written and twelve remain; the manifest is **twenty-eight** steps and a deployment
now unbinds the security policy before every pass; `M2` is reached. DES-AUTH-001 is at v1.5 with new
§9.2 and §9.3, a rewritten §10.2 and §21.3, and `E-50047`, `E-50130`–`E-50135`, `E-50140` and
`E-50141` in Appendix B. `G-01` is still the only remaining Critical gap, but it now has a `Critical`
UI counterpart — `UI-35`, a stale permission-id list, which is the same failure mode pointing the
other way: silent *denial* rather than silent exposure
**Changed in 1.4:** `G-07` closed by management and the work it was blocking done — the counts, the
state-of-execution notes, and the new artefacts (`112_auth_mfa_procedures.sql`, the two actor resolvers
in `100_auth_functions.sql`, `_tests/040` section 12, `BL-033`–`BL-035`, `UI-28`–`UI-32`, `T-112`).
`T-041` is complete and no task is Blocked; the manifest is twenty steps; `G-01` is the only remaining
Critical gap; DES-AUTH-001 is at v1.4 with a new §6.4 and `E-50117`–`E-50123` in Appendix B
**Changed in 1.3:** Phase 2 executed and complete — the script, task and manifest counts, the
state-of-execution notes, and the new artefacts (`025_config_tables.sql`,
`035_auth_tenant_policy.sql`, `040_auth_userprofile.sql`, `045_auth_identity.sql`,
`070_auth_session.sql`, `085_logs_auth_tables.sql`, `110_auth_authn_procedures.sql`,
`170_permissions.sql`, `_tests/040`, the new `tools/` directory, `BL-025`–`BL-032`, `G-21`,
`UI-26`, `UI-27`, `T-025`–`T-044`). `G-19` and `G-20` are closed and `T-045` is deleted
**Changed in 1.2:** Phase 1 executed and complete — the script and task counts, the
state-of-execution notes, and the new artefacts (`030_auth_tenant.sql`, `095_auth_views.sql`,
`100_auth_functions.sql`, `125_auth_tenant_procedures.sql`, `_tests/020`, `_tests/030`,
`BL-019`–`BL-024`, `G-20`, `T-014`–`T-024`)
**Changed in 1.1:** Phase 0 executed and complete — the counts, the state-of-execution notes and
the new artefacts (`_tests/010_phase0_instrumentation.sql`, `BL-015`–`BL-018`, `G-19`, `T-111`)

Every document in this package, what it is, who it is for, and when it changes. Start here.

---

## Where to start, depending on why you opened this

| You are | Read, in this order |
|---|---|
| **Reviewing the design** | `docs/10-…-design.md` §1–§4, then §17 (the conformance walk-through), then §11 and §10. §17 is where the design is tested against every scenario in the requirements |
| **Approving the work** | `docs/20-project-plan.md`, then `workbooks/gaps.xlsx` — `G-01` is still the only Critical row open, and it is now one of only **three** rows that say **Production go-live** in the Blocks column: `G-01`, `G-14` and `G-37`. All three are Phase 8 rows filed during the design pass. The two that the build itself filed, `G-30` and `G-42`, were closed on 2026-09-21, which is the more useful thing to know about that list — it is shrinking from the code end and not from the design end. `G-06` blocks Variant 3 go-live specifically and is **deliberately still open** after the registration throttle was built; read its Notes before accepting the throttle as the control. Then the plan's §5 for the `M3` go/no-go on `D-07`, which was taken on measurements and not on argument. Pace, if you need it: Phases 0–2 at 40% of estimate, 3–4 at 94%, 5–7 at 78%, cumulative 64.3 days against 93.0 for the eight phases executed |
| **Deciding whether it is fast enough** | `docs/30-performance-measurements.md` — PERF-AUTH-001, and it is the record. Read §1 for the method before any number: logical-read counts are stable across runs on this hardware and microsecond figures vary by up to 20%, so every argument rests on reads |
| **Building it** | `docs/10-…-design.md` in full, then the **Scripts** sheet of `workbooks/build-and-traceability.xlsx`, then your tasks in `workbooks/implementation-tracking.xlsx` |
| **Building the UI** | **`docs/40-ui-handoff-m4.md` first — that is the contract, delivered at `M4` on 2026-09-20 and amended to v1.1 on 2026-09-21.** Then `workbooks/ui-gotchas.xlsx` for the fifty-four traps, then design §13, §14 and Appendix B. Nine gotchas are Critical and are the read-before-you-code list. Four decide code before it is written: `UI-36`, because the session identity is read-only and non-transactional and that dictates your connection handling (a sign-in costs two connections and a profile switch spends the one it was made on); `UI-35`, because a stale permission-id list makes rows vanish with no error; and `UI-40`, because row-level security is the net and not your `WHERE` clause — every query against a tenant-scoped table must still filter by tenant itself; and `UI-43`, because `@ExpectedCatalogueVersion` is **optional in the signature and mandatory in practice** — read the catalogue version at build time and pass it on every navigation call, or you are back in the state `G-18` was filed for, where a catalogue drift produces no error anywhere for anybody. **`UI-46` and `UI-48` arrived on 2026-09-21, were **rewritten the same day** when `T-125` and `T-126` closed the gaps behind them, and both still decide a screen rather than a detail.** The hat menu — the *first* authenticated screen, needed by all 12,830 users of scenario 1 and by up to 22 hats for one of them — now has `auth.uspListMyProfiles`, which demands no permission and takes no user id; what `UI-46` warns about is that there are **two** listers and the administrative one is the one you find first by searching for "profiles". The step-up challenge behind `E-50052` can now be answered by `auth.uspElevateSession`, and `UI-50` is the part that will bite: the elevation and the retried switch each need a **fresh connection**, because the one that met `E-50052` is already contexted and `UI-06` means it cannot be re-contexted. Read `UI-52`, `UI-53` and `UI-54` before writing any data-access code at all — they were found by a .NET client against this database, and `UI-53` in particular undercuts `UI-08`: a `SqlException` from a method call arrives **wrapped**, so branching on the error number needs the inner exception or every database error takes the else branch. `UI-41` and `UI-42` are `sqlcmd` mechanics and will only matter when you are debugging against the database by hand |
| **Deploying it** | `README.md` §Installation, then `database/Install-TemplateDatabase.ps1`. The full sequence — **thirty-nine** manifest steps, Phase 0 through Phase 7 — has been run against `MDE-55TT2J4\testTemplate` and converges on a second pass: `BL-014`, with `BL-015`–`BL-018` for what the first Phase 0 run found, `BL-019`–`BL-024` for Phase 1, `BL-025`–`BL-035` for Phase 2 and the `G-07` follow-on, `BL-036`–`BL-049` for Phases 3 and 4, `BL-050`–`BL-066` for Phases 5 to 7 and the closeout after them, `BL-067`–`BL-073` for the 2026-09-21 gap-closing pass, which added objects to eight existing scripts and no new script at all, and `BL-074`–`BL-075` for the suite run that verified it. The runner **unbinds the row-level security policy before every pass and rebuilds it at step 36**; without that, a second deployment fails with `Msg 3729` (`UI-34`). Read `BL-058` before re-ordering anything: eleven of the manifest's departures from filename order are load-bearing. One script is still unwritten — `950_verify_deployment.sql` — and `900_bootstrap_first_admin.sql` is deliberately **not** a manifest step |
| **Writing SQL here** | `.claude/skills/ponytail-sql-objects/SKILL.md`, then `database/090_dbo_application.sql` for a table and `database/180_dbo_application_procedures.sql` for a procedure. `180` is deliberately dull — no paging DSL, no dynamic `ORDER BY`, no table-valued parameters — because what is worth copying is the **order of the nine statements**, not the cleverness. A project deletes the demo domain and keeps the shape |
| **Auditing it** | design §19, §11 and Appendix D, then `logs.vwAuthorizationTrail` and `auth.vwProfilePermission` once deployed |
| **Converting an existing Active Directory application** | design §18. The method is three columns wide and the third one is the work |

---

## 1. Design and planning

### `README.md` — the repository front door

What a visitor to the GitHub repository reads first. It carries the status banner (design complete,
**36 of the 37 project scripts written and one unwritten**, Phases 0 through 7 deployed and verified
on a real server, the whole model exercised end to end through the procedures by
`_tests/070_variants_end_to_end.sql`), the prerequisites, the deployment runner and the same sequence
by hand with its exact `sqlcmd` lines, usage by role, and the configuration surface.

It is the one document written for someone who has never seen this project and may only read one
thing. Keep the status table in it honest: a README that implies a clone-and-deploy story this
repository cannot yet support is worse than no README, because it costs a stranger an afternoon
before they find out.

Changes whenever the script count, the prerequisites or the install steps change.

### `docs/00-documentation-index.md` — this file · IDX-AUTH-001

The map. Lists every document, what it represents, who maintains it and when it changes. Update
it whenever a document is added, renamed or retired; a stale index is worse than none, because
people trust it.

### `docs/10-database-authn-authz-design.md` — DES-AUTH-001

**The design.** The authoritative description of what is being built and why. **v1.7**, roughly
43,900 words across 27 sections. It has grown by twenty-six thousand words since the build began, and
almost none of that growth is new design: it is the design being corrected where implementation
proved it wrong, each correction carrying the Build Log entry or gap row that found it. The v1.6
amendments are worth characterising, because they were all of one kind — sixteen sections changed, and
every change was either a number the document had asserted without measuring it or a rule that turned
out to live only in code. Not one was found by re-reading the design; each came from reconciling a
`gaps.xlsx` row against the code it describes.

**The v1.7 amendments are of the opposite kind, and the contrast is the useful part.** v1.6 corrected
the document to match the code; v1.7 was written *before* the code, because nine gap rows had each
named a design section their resolution would have to amend. So §6.3 (credential lifecycle), §7.2 and
§8.5 (per-tenant configuration), §7.3 (trusted issuers), §13.1 (the catalogue version stamp), §16.4
(the registration throttle) and Appendix B were amended as part of closing the rows, not afterwards.
Two sections were amended with **no code at all**: §11.4, which turns "`auth.[User]` happens to hold
only identity" into the standing rule that any attribute not needed to identify a person belongs on a
tenant-scoped table, and §16.4, which carries a paragraph headed *`G-06` is not closed by the
throttle* naming the two obligations that live on the far side of a network boundary. A design
document that only ever catches up with its code is a design document that has stopped being used to
decide anything.

What it represents: one database design serving three application variants — an agency with
subordinate jurisdictions, an agency-internal system organized by administration and program,
and an agency with external organizations. It defines the tenant hierarchy, the profile and role
model, the permission catalogue, authentication including federated sign-in and the platform
administrator bypass, row-level security, the administrative authority rules, profile switching,
and the screen-and-tab authorization surface the UI project will bind to.

Four sections carry more weight than the rest:

- **§4** — the decisions, each with the alternatives that were rejected and why. If you disagree
  with the design, disagree here.
- **§10.3** — the filter/block asymmetry. Reading is scoped, inserting is anchored to the acting
  tenant. This is the rule that turns the requirement's "data entry error" narrative into
  something the database enforces.
- **§11.1** — `INV-05`, the four-clause rule governing who may grant what to whom. One sentence,
  and the most consequential one in the document.
- **§17** — the conformance walk-through. Every user in every scenario from the source
  requirements, with the actual rows that represent them.

Who maintains it: the database architect. Changes when a decision changes, and carries a version
number when it does. Everything else in this package points at it.

### `docs/20-project-plan.md` — PLAN-AUTH-001

**The plan.** Nine phases, five milestones, the risk register, the prerequisites that block a
start, and the handoff contract for the UI project.

What it represents: the work of building what DES-AUTH-001 describes, ordered so the database is
deployable at the end of every phase rather than only at the end. Phase order is not arbitrary —
the security predicate goes in before the demo domain, so the worked example is built *under* the
model rather than having it applied afterwards.

Two sections are easy to skip and should not be:

- **§7** — findings carried in from the source material. Seven of them, four of which would have
  shipped silently — including two that make a deployment *report success for a run that failed*
  (`F-06`) and *apply a permission model to nobody* (`F-07`).
- **§9** — risks. `R-04` is the one to watch: it is the only risk whose failure mode is silent,
  permissive, and indistinguishable from correct operation. Three risks are now retired and two are
  new, and the two new ones (`R-10`, `R-11`) are of a kind the register did not previously hold: risks
  that the system will be used **correctly and unsuccessfully**, by someone whose screen gives them
  no reason to suspect a problem.

Who maintains it: the project lead. **v1.8**, with Phases 0 through 7 marked complete, `M1` through
`M4` reached, and one exit criterion explicitly *carried* rather than met — Phase 7's, which cites
`950_verify_deployment.sql` and therefore could not be satisfied before `T-104`. Changes when the
shape of the work changes. Phase effort figures are taken from the tracking workbook's roll-up rather
than being an independent estimate, so if the two disagree the workbook is right and this is stale.

### `docs/30-performance-measurements.md` — PERF-AUTH-001

**The record.** Every performance number quoted anywhere in this package — in the design, in the
plan, in the Build Log, in a README — is quoted *from here*, and if a figure appears somewhere else
without appearing here it has not been measured. Roughly 3,000 words across eight sections, produced
by `T-069`–`T-074` and standing behind the `M3` go/no-go.

**Read §1 before any number in it.** The method is the part that makes the rest usable: logical-read
counts on this hardware are identical across runs and microsecond figures vary by up to 20%, so every
argument in the document rests on **reads** and the timings are reported as texture. A reviewer who
takes the microseconds as the finding will disagree with the document for the wrong reason.

Four results decide things:

- **§3.1** — the point read. 8 logical reads protected against 3 unprotected. This is the question
  `D-07` actually asked, and the answer is why the derived-closure model stands.
- **§3.2** — the aggregate, 714× the reads. The predicate is cheap per row and expensive per million,
  which makes a reporting path an `rlsBypassRole` conversation rather than a tuning one (`R-10`).
- **§4** — the plan shape. Scope scans 0 and closure scans 0 on all three access patterns, at both
  tenant counts. The design claimed a seek on the inner side of a semi-join and had never shown it.
- **§5.1** — `G-39`. One all-profiles rebuild is **224× cheaper** than a thousand single-profile
  rebuilds producing the same result, and nothing in the procedure surface steers a caller to it.

§6 is the section a sceptical reviewer should read second: what was *not* measured, and why. Changes
only when something is re-measured — and note §8, because `testTemplateBoot` was left at 10,650
tenants and must be dropped and rebuilt before any comparable figure can be taken.

### `docs/40-ui-handoff-m4.md` — UIH-AUTH-001

**The contract, frozen at `M4` on 2026-09-20, amended to v1.1 on 2026-09-21** and the first document
the UI team should open. Ten sections: the sign-in wire sequence, the three contract procedures with full result-set column lists,
the calling contract as five operative rules, the error numbers regrouped by *what the UI should do*
rather than by number, the non-optional gotchas, and — §8 — what is deliberately **not** delivered.

It is one document rather than a pointer to the six deliverables PLAN §8 names, and that is a
decision: a contract assembled by reference is a contract whose reader has to reconcile six versions
of it. §2 maps it back onto those six rows so nothing is lost by reading only this.

**§8 is the section that keeps it honest, and v1.1 is the proof that it works.** The largest hole §8
named — no procedure to set a password (`G-42`), so account provisioning was the one flow the
contract could not support end to end — was closed on 2026-09-21, and the section now says so rather
than being quietly deleted. What remains in §8 is smaller and more honest for it: item 9 says a
Variant 3 deployment should not put a publicly reachable registration page into production until edge
rate limiting and a challenge on the form exist, because the per-address throttle built for `G-24`
does **not** close `G-06`. Naming a hole inside the handoff rather than only in `gaps.xlsx` is the
difference between a freeze and a claim; naming which holes are *still* there after a pass that filled
three of them is the difference between a living contract and a stale one.

Changes when the surface changes, which after `M4` means a design change first — §10 says so and names
the route. **v1.1 was taken through that route**, which is why `BL-071` exists: §10 requires a Build
Log entry for any amendment, and an amendment that skipped it would have proved the rule optional on
the first occasion it applied. Three things moved: `@ExpectedCatalogueVersion` on the navigation call
(§4.2, and read `UI-43` before implementing it), three password-expiry columns on the profile context
(§4.1, and `UI-44` for the two properties that look like defects and are not), and the credential
procedures in §6. Maintained by the database architect, read by the UI project.

### `docs/60-scenario-test-1.md` — SCEN-AUTH-001

**A named customer, loaded as data, and asked to do its job.** One state agency over 67 counties, ~12,830
users in thirteen cohorts, four runs, all passing. Read it for one of three reasons.

**To see what the template does under a realistic shape.** §3 is the population cohort by cohort, measured
rather than calculated: 170 agency users holding 5,730 profiles, 12,660 county users holding 24,760, and the
two modelling decisions the scenario's wording does not settle — that "can assign profiles and have
read-only access" is *one* profile bundling two roles, and that C4's "switch between read-only and CRUD" is
*two* profiles in one county, which is what makes it a switch.

**To see what four runs prove and what they do not.** §5 is the eighteen connections of the prover and what
each settles; §6 is the limit, in full. Ten named users stand for thirteen cohorts, because 12,830 serial
sign-ins is about nine hours and would *still* be serial — so the passes mean every code path works, and
they do not mean "13,000 users work". That distinction is `G-49`.

**To find the seven gaps with their evidence — and what each of them became.** §7, and `G-48` first:
the step-up challenge that guards every privileged profile could not be satisfied by anything in the
database. **All seven are closed as of 2026-09-21**, and the seven write-ups are deliberately *kept in the
present tense of the day they were found*, each with a closure paragraph under it, because how a gap gets
found is the part of that document worth re-reading and a finding rewritten into "there used to be a
problem" teaches nobody anything. §8 is still the part worth reading twice — two found before a single row
was inserted, three by a proof failing against a database where every object behaved as written, one by
taking the customer's own words literally, and one by refusing to overclaim. The new subsection at the end
of §7 is the other half of that lesson: three findings came out of writing the *probes* rather than the
features, including that `auth.[User]` has **no `ApplicationId` column** and deliberately so, and that the
`Authn.LockoutThreshold`-th failed step-up is the one that revokes rather than the one after it.

§9 is how to run it again, including the three rules that are not optional and the two `T-130` concurrency
artefacts. Maintained alongside the two scripts it documents, which cite it in their `Implements:` lines.

---

## 2. Workbooks

Four, each answering a different question. All four have a Legend sheet naming which cells are
meant to be edited.

### `workbooks/implementation-tracking.xlsx`

**The living document.** 129 tasks across the nine phases, 109 person-days estimated and **74.25
actual**. **121 are Complete** as of 2026-09-21, and the eight that are not are **all of them Phase 8
Verification** — `T-103`–`T-110`. **Phases 0 through 7 are complete in full**, which is new as of the
closure of `G-45`–`G-51` and is the single most useful fact on the sheet: all 15 of Phase 0 (4.75
person-days against 7.5 estimated), all 12 of Phase 1 (1.9 against 8.25), all 22 of Phase 2 (8.45 against
17.25), all 15 of Phase 3 (11.8 against 12.25), all 11 of Phase 4 (7.6 against 8.25), all 6 of Phase 5 (3.8
against 6), all 28 of Phase 6 (25.5 against 30.5), all 11 of Phase 7 (8.45 against 10), and 1 of the 9 of
Phase 8 (2.0 against 9) — that one being `T-130`, the concurrency measurement, which is filed here rather
than with the gap that prompted it because load work belongs to the verification phase. **No task is
Blocked.** `T-041` was, on `G-07`, and was
completed on 2026-09-20 when management decided the question; `T-112` was added the same day for the
enrolment surface itself, which the plan had assumed would fall out of `T-041` and does not. One task
has been **deleted**: `T-045` is gone, not done, which is why the numbering skips from `T-044` to
`T-046`. Two numbering oddities, then, and the Legend sheet explains both — the missing `T-045`, and
why the rows now end at `T-130` while only 129 tasks exist.

**`T-113` to `T-119` are the seven that are not in PLAN-AUTH-001**, and they are filed under Phase 6
because that is the phase whose gaps they close, not because that is when they were done. They came
in at **7.0 actual days against 7.0 estimated** — the only batch in this project to land on its
estimate, which says more about the gap rows having specified the work in advance than about anyone's
judgement, and four of the seven departed from what those rows proposed anyway. **`T-120` and `T-121`
were added the next day on the same rule applied in the other direction** — into Phases 1 and 4, not
into the verification pass that found them, because each repairs that phase's own exit-criteria test.
They are the only two tasks in this workbook that exist because a *test* was wrong, and 0.7 actual
days against 0.5 estimated makes them the cheapest rows here. Adding them also
exposed a latent defect in the workbook itself, which is the part worth carrying elsewhere: every
`Phase Summary` roll-up formula ranged over `Tasks!$B$2:$B$112`, **exactly** the last task row, so the
first appended task would have been counted in no phase at all and Phase 6 would have under-reported
by seven while the sheet still looked healthy. The ranges now run to row 130. A range that merely
reaches the last row is a range that is one append away from lying.

**The ratio changed at Phase 3, and that is the most useful number in the workbook.** Phases 0–2
came in at 41% of estimate; Phases 3–4 at 95% — 19.4 days against 20.5; Phases 5–7 at 73% — 26.0
against 35.5. Nothing slowed down and nothing sped up. Phases 3 and 4 were simply the first phases
where the design turned out to be *wrong* in places rather than merely incomplete, and correcting a
design mid-build costs what the estimate assumed building would. The 73% that followed is mostly
Phase 5, where a measurement phase is fast precisely because the answer came back yes: three scripts
and a document in 3.8 days against 6, where a plan shape that had come back a scan would have spent
the six and then some. Plan Phase 8 at estimate.

**Two things about the Actual Days column, because they are not the same kind of number.** Phases 1
through 4 are one session's elapsed time apportioned across the phase's tasks in proportion to
estimate, and the Phase Summary footnote says so — only the phase total is measured there. **From
Phase 5 onward they are per-task figures**, so the row-level variances mean something: exactly one
task in Phases 5–7 exceeded its own estimate, `T-094` at 1.6 against 1, because the error catalogue's
coverage report found the suite was crediting itself with residue. Either way, a team with a timesheet
should overwrite these rather than inherit an allocation as though it were a measurement.

The Legend's closing note is the one to read before trusting a date: **Phases 0 to 7 were built in a
small number of sittings rather than over the calendar the estimates assume**, so `Started` and
`Completed` record the date the work landed and every row from Phase 3 onward carries `2026-09-20` in
both columns. It also records the one set of rows that did not land on `testTemplate` at all —
`T-069`–`T-073`, which ran against `testTemplateBoot`, because a measurement fixture in the working
database is a row somebody will eventually mistake for real.

| Sheet | Holds |
|---|---|
| Tasks | One row per task: phase, artefact, design reference, dependency, estimate, and the columns you fill in |
| Phase Summary | Formula roll-up by phase and status. Entirely formulas — do not type into it |
| Legend | Which cells to edit, the status values, and one worked example of a completed row |

Changes continuously. This is the only document in the package that is expected to be different
tomorrow.

### `workbooks/build-and-traceability.xlsx`

**The bridge between the design and the code.** Answers three questions a design document cannot.

| Sheet | Holds |
|---|---|
| Overview | What the workbook is for, and two ordering constraints that are not obvious |
| Scripts | Every artefact in **install order**, with objects created, dependencies and status: 57 rows, of which **56 are Verified and one is Not started** — `950_verify_deployment.sql`. The runner is order 0 and order 5a is the conventions permission script, which the runner applies at that point rather than at the end where `170_permissions.sql` sits. The rows outside the order — the eight under `database/_tests/`, the **five** under `database/_perf/`, the two under `database/_scenarios/`, `900_bootstrap_first_admin.sql` and `tools/T040-PasswordVerification` — are there because they are deliberately **not** installed, which is a fact about them worth recording rather than an omission. Read the sheet's closing note for the three rows that are **not T-SQL** and the three different reasons why, one of which is that measuring concurrency needs two connections at once and T-SQL cannot open the second. The authoritative list; the project plan points here rather than duplicating it. Read its closing note for the thing this sheet cannot show: **the sheet's order is not the install order**, and **eleven** of the manifest's departures from it are load-bearing |
| Build Log | What changed between the plan and the code while the scripts were being written, and why. **85 entries**, `BL-001` to `BL-085` |
| Traceability | Design section to implementing artefact — 96 rows. The first 27 trace the **original requirements** rather than the design, so a reviewer can check that nothing asked for was lost on the way in. Coverage now reads **Verified 81, Partial 7, Gap 0, Built 1, Designed 7**, and **there is no `Gap` row left on the sheet** — the four that arrived with the scenario 1 test were closed on 2026-09-21 and were **updated in place rather than answered by a second row**, because a requirement with two rows has no status at all. Exactly one row was *added* at closure, DES §15 concurrency, a requirement that had no row whatever, which is the whole reason `G-49` was findable. The one row that moved *up* before all this is still the one to read: DES §10.1 tenant confinement was already `Verified`, and the scenario's fourth run — two agencies, 171 tenants in one database — is the first test in which that assertion **could have failed**. Before it, the claim passed because there was nothing else in the table to see: five-sixths of the design is standing on something that has been run, against two-fifths at the end of Phase 4. Both new `Partial` rows were **deliberately not rounded up** — DES §16.4 because the throttle is only one of `G-06`'s three controls and the other two are outside the database, and DES §11.4 because it states a rule rather than installing a mechanism |

**Read the Build Log before concluding that a script disagrees with the design.** That conclusion
is usually wrong and occasionally right, and the difference is not visible from the script. A
deliberate divergence has an entry naming the reason and who decided; a divergence with no entry
is a defect.

It currently holds 85 entries: eight from the design pass, six from the first implementation pass,
four from the first real deployment — `BL-015` through `BL-018`, which are the four things Phase 0
found and are the reason that phase is not skippable — six from Phase 1, `BL-019` through `BL-024`,
eleven from Phase 2 and its follow-on, `BL-025` through `BL-035`, fourteen from Phases 3 and 4,
`BL-036` through `BL-049`, seventeen from Phases 5, 6 and 7, `BL-050` through `BL-066`, seven
from the 2026-09-21 gap-closing pass, `BL-067` through `BL-073`, two from the suite run that
verified that pass, `BL-074` and `BL-075`, three from the scenario 1 test, `BL-076` through `BL-078` —
the first entries on the sheet found by **loading a realistic population**, which is a fourth way of
finding things alongside writing code, running a test and taking a measurement — and seven closing the
seven gaps that test filed, `BL-079` through `BL-085`, of which the last is the one to read: it records
**inverting the tests that found the gaps**, because a test written to prove a gap reproduces passes by
describing a database that no longer exists the moment the gap is fixed.

**Read the last seven as a set, because four of them are the same finding twice over.** Each of those
four exists because a *gap row* was wrong, not because a script was: `G-32` and Appendix B both named
`auth.uspAssignRolesToProfiles`, a procedure this template never built and never will (`BL-072`);
`G-43` asked for a `Tenant.Manage` permission that is not in Appendix A (`BL-068`); `G-18` asked the
application to assert the catalogue version, which leaves the control with the party whose defect it
catches (`BL-069`); and four artefacts had been repeating a settings count that was two revisions
stale (`BL-072` again). A gap register is a document too, and nothing executes a document.

The Phase 1 six are worth reading as a set, because four of them are the same kind of finding: a
rule that is right in general and wrong for one file. `BL-021` and `BL-022` both move work *earlier*
than the install order puts it, because a table whose first row is impossible for seventeen scripts
is not installed but merely created. `BL-019` records a mechanism that was tried and **measured** to
fail rather than argued against. `BL-023` is the one worth generalising: a partial probe for an
all-or-nothing dependency reports YES while the true answer is "some".

Two of the Phase 2 eleven are the ones to read first. `BL-028` records permission precedence as
**measured** rather than as documented, and two of its three results are counter-intuitive: a `DENY`
on a table does not stop a procedure that reads it, because ownership chaining never consults the
permission, yet a `DENY` at *schema* level beats a `GRANT` at *object* level — so the column-level
exception every SQL Server developer knows does not generalise. `BL-031` is the one with a live
consequence for the UI: calling an authentication procedure inside an ambient transaction discards
the failure record and the lockout increment along with the raised error, which fails open silently.

The Phase 3 and Phase 4 fourteen divide almost evenly into two kinds, and the division is the point.
Four are the design being **wrong** where it had been confident — `BL-041`, where the row-security
predicates were documented as scalar functions and cannot be (a predicate is table-valued, so the
naming table needed correcting); `BL-039`, where the predicate cannot join `auth.Permission` by code
at all, so `120_rls_policy.sql` substitutes the permission **ids** as literals and thereby invents a
failure mode the design had not imagined; `BL-036`, where the profile switcher's list of names is
ambiguous the moment one person holds two identically-titled hats at one organization; and `BL-038`,
where a second deployment of a file the security policy references simply fails. The other nine are
things **only running the code could have found** — and three of those were found by a test file
rather than by a deployment. `BL-046` is the one to read even if you read nothing else here: a defect
survived two phases because the deployment probe inside `105_auth_session_procedures.sql` could only
ever reach the *refusal* branch of its own permission gate, so every run reported success while the
accepted path had never once executed. `BL-047` and `BL-048` are its companions in the same lesson
applied to assertions — "nothing is granted" is the most brittle thing a verification can claim, and
`BL-048` records a schema-level grant and an object-level silence that were both true and together
left four audit trails writable.

`BL-049` was added last, during this closeout, and is the only entry found by querying the catalog on
a hunch rather than by running anything. It covers **two** missing foreign keys, which is why it is
worth reading. `auth.UserSession.ActiveUserProfileId` had had none for **five phases** and
`auth.TenantDefaultRole.RoleId` none for **two**, while the design said both were constrained and the
deployment printed `PENDING` for both on every single run. Neither `ALTER` had been forgotten — each was
written out in full in a comment addressed to "the next reader", who is not an owner. Both are now
guarded steps in the install path of the file that owns the child table, and both closing reports have a
third state so they can say `VIOLATION` once the excuse expires. The second was found minutes after the
first, by re-running the same query, and that is the generalisation worth taking away: **a pending row in
a green report is not a plan** — the same shape as `BL-047` and `G-23`. One of these is a slip; two found
in an afternoon by one query is a class of defect, and nothing in the process would have caught a third.

**The fifteen from Phases 5 to 7 divide differently, and the division is the interesting part.** Four
are a *design sketch* meeting the procedure it described and losing: `BL-053` is the clearest — four
procedure headers were written straight from the design's call sketches and **all four were dead on
their first statement**, because every one of them takes `@SessionTokenHash VARBINARY (32)` and the
sketches passed a token. Three are a **check constraint arbitrating a vocabulary** the design had
published loosely (`BL-054`, `BL-055`). Two are the install order being genuinely counter-intuitive
and load-bearing (`BL-058`, and `BL-051`'s root-tenant move). One is a measurement document rather
than an entry (`BL-059`). And `BL-057` is the one to read even if you read nothing else in this
range: **`auth.uspSwitchProfile` threw `E-50022` on every call, after succeeding.** Re-establishing
session context after a switch is not unnecessary, it is impossible — a read-only session key cannot
be set twice on one connection — so what looked like a defect turned out to be a *contract*: the
switching connection is spent, and a sign-in costs two connections for the same reason (`G-36`).

**The last two entries were both written after their phase was marked complete, and neither was found
by a failing step.** `BL-064`
records two defects in one file, both found while reconciling a gap row against the code rather than
against the tracker: a shipped error message recommending an action the database refuses with the same
number, and a closing-report assertion that **could not pass on any multi-application database** —
`COUNT (*) = 2` over an `ApplicationId`-scoped table, which printed "8 of 2 — 0 ERROR" on a perfectly
healthy database. It is the mirror image of `BL-047`, where the concern was an assertion that could
not fail, and the pair only reads as a lesson with both on the sheet. Its transferable half is this:
the identical mistake had already been found and fixed in `180` during Phase 7 and never grepped for
elsewhere, so **a fix applied where it was found is half a fix**.

`BL-065` is the third of that family and the one that closes the argument. Three stale statements in
the *installer's own output*, found by reading a 750 KB transcript rather than by any step failing: an
unbind message still naming step 27 after `120` moved to 36, a closing list naming five test files when
there are eight, and — the instructive one — a printed count that was **always zero by construction**,
because `@TablesBound` is initialised to 0 under `@Action = N'Drop'` and never set again. Put the three
entries together and the shape is unmistakable: `BL-047` was an assertion that could not fail, `BL-064`
one that could not pass, `BL-065` a number that could not vary. **An exit code does not check prose**,
and the habit that catches all three is asking of every printed figure: *what value would make me stop?*

### `workbooks/gaps.xlsx`

**What the design requires that no artefact provides.** 51 rows, of which **thirty-one are Closed** and
**exactly one of the open ones is `Critical`** — `G-01`, which has been there since the design and is the
oldest unclosed row in the project. `G-48` was the other one and was closed on 2026-09-21, the same day it
was filed, by `auth.uspElevateSession`.
Phases 5, 6 and 7 filed **twenty** of them — `G-24` through `G-43`, the largest batch of the project —
and closed eight of those inside the same pass, which makes this workbook the one that moved furthest
at the closeout; a dedicated pass on 2026-09-21 then closed nine more and filed `G-44`. Later the same day the scenario 1 test filed **seven**, `G-45`–`G-51`, and closed none — and those seven are the ones to read for *how* a gap gets found, because two were found before a single row was inserted (the loader could not express "CRUD access" or "can assign profiles" in any seeded role), three by a proof failing against a database where every object behaved exactly as written, one by taking the customer's own words literally, and one by declining to let four serial passes be read as "13,000 users work". **All seven were then closed later the same day**, which makes them also the best rows here for reading a *closure*: each `Notes` cell names where the delivered artefact departed from what the row proposed, and three of the seven did depart — `G-45` became a batched sweep rather than a per-row action, because a per-row module would have demanded `Data.Execute` once per named row and proved nothing `Data.Update` does not; `G-49` became a SQL harness **and** a PowerShell driver rather than one tool, because T-SQL cannot open a second connection; and `G-46`/`G-47` gained a second half nobody asked for, the loader asserting the seeded roles instead of creating them, because a loader that creates what it needs is a loader that hides the next omission of the same kind.

**Read the Legend's closing note before the rows** — both halves of it, because the second half is a
correction of the first. The eight closed at the Phase 5–7 closeout —
`G-25`, `G-26`, `G-29`, `G-33`, `G-34`, `G-36`, `G-38`, `G-40` — were **all closed by amending the
design, not the code**: every one was a rule the procedures already enforced, or a fact the
measurements already showed, that the design either did not state or stated wrongly. Not one needed a
line of SQL. And not one was found by re-reading the design. Each was found by reconciling a row of
*this workbook* against the code it describes, which in three cases turned up something worse than the
gap — see `BL-064`. The lesson the Legend draws is worth more than the rows: **a gap register is only
worth what its last reconciliation was worth.**

**Two more were closed after that note was written, and how they were missed is the transferable part.**
`G-09` and `G-22` both carried Target phase *5 Performance*, both were **answered** by the Phase 5
measurements, and both were still marked Open at the end of the closeout — because the closeout audited
the twenty *new* rows and the ones it could close by amending the design, and never re-read the two rows
whose target phase was the phase that had just finished. The register was reconciled against the code and
not against the calendar. The rule that falls out of it: **when a phase closes, read every row whose
Target phase is that phase**, whatever else the closeout is doing. `G-09` is closed by a measurement that
*declined to build something* — the whole-table closure rebuild is 39.4 ms at 1,050 tenants and 791 ms at
10,650, so the incremental version it proposed is not worth its complexity — and `G-22` by
`175_perf_instrumentation.sql` delivering all three parts of its resolution. The same sweep found four
Phase 6 rows (`G-06`, `G-12`, `G-18`, `G-24`) that could not be closed but had an **empty Notes column**,
which for a row whose target phase has passed reads as "nobody has looked" and is indistinguishable from
it; all four now say what the phase did and did not do. `G-18` is the one worth following: it claimed to
block the `M4` handoff, `M4` shipped without it, and rather than leave a contradiction standing the claim
was **withdrawn in writing** and the cheap half of its resolution written into UIH-AUTH-001 §10 —
*element codes are added to, never renamed*, because the application binds to the code (`UI-02`) and a
renamed element does not fail, it stops appearing for everybody with nothing in any log.

Of the nine that Phases 5–7 filed and left open, **six were open because closing them was code and
not prose** — `G-30` (a seeded setting plus its callers), `G-31` (ten procedures re-ordered), `G-32`
(a number that must be *raised* before it may be registered, or the `_tests/080` ledger acquires a row
that can never reconcile), `G-41` (a `DEFAULT` migration across every `auth` table), `G-42` and `G-43`
(six missing procedures between them). Each of the six had its absence stated in advance in the design
section a reader would actually look in, so the amendment was paid for and only the code was owed —
and on 2026-09-21 four of the six were paid: `G-30`, `G-32`, `G-42` and `G-43`. `G-31` and `G-41` are
still owed, both against `950_verify_deployment.sql` and Phase 8. `G-32` is the one to read for the
rule it proves: the number had to be **raised before it was registered**, because registering
`E-50180` first would have put a permanently unaccounted row in the `_tests/080` ledger — a report
that always fails, which is exactly the defect `BL-064` records elsewhere.

**Three open rows say `Production go-live` in the Blocks column**, and there were five until
2026-09-21: `G-01` and `G-14` from the design pass and `G-37` (the bootstrap writes a root policy with
`RequireMfaForLocal = 0`, and policy *inherits*) remain; `G-30` (a deployment with no policy row
anywhere demanded no step-up, because the resolver's fallback was the literal `0`) and `G-42` (nothing
but the bootstrap wrote `auth.UserCredential`) are closed. Only `G-01` is Critical-severity, which is
exactly why the other two need naming here: they are High rows that a release meeting can talk itself
past. `G-06` sits beside them with `Variant 3 production go-live`, and **it is open on purpose after
work was done on it** — `auth.uspRecordRegistrationAttempt` now counts arrivals per address and
refuses a crossed threshold (`E-50068`), and that is one of the row's three controls. The other two,
edge rate limiting and a challenge on the form, are on the far side of a network boundary this
database does not reach. Closing the row on the strength of the third would have been the workbook
telling a project it is protected where it is not.

**The nine closed on 2026-09-21 are worth reading for their *departures* rather than their
resolutions.** Four of the nine were delivered differently from what the row proposed, and in every
case the row was wrong rather than the implementer inventive: `G-42` asked for two procedures and got
four, because `D-08` means the database can no more *compare* a password than receive one, so the
reuse check had to become a read plus an argument; `G-43` asked for a `Tenant.Manage` permission that
does not exist in Appendix A and got `Tenant.Update`, plus `Authz.RoleAssign` on the default-roles
writer because a default-role list is a standing grant and not a label; `G-18` asked the
*application* to assert the catalogue version at start-up and the **database** now refuses a mismatch
instead, because a control the caller may skip is not a control and a catalogue can be extended while
an application is running; and `G-32` named `auth.uspAssignRolesToProfiles`, which has never
existed — nor has Appendix B's `E-50046` row, which named it too. Two of the nine were closed with no
code at all (`G-27` and, in part, `G-06`), and one — `G-44` — was **filed** by the pass, because a
test had to reach past the procedure surface and hand-soft-delete a policy row to keep measuring the
no-policy path.

Three of the twenty are not gaps in the ordinary sense but **measurements that changed what the design
should say**. `G-39` is the sharpest: rebuilding all five thousand profile scopes in one statement is
**224 times cheaper** than rebuilding them one at a time, and the procedure surface offers both
without hinting which is which, so the blunt instrument is the fast one and nothing says so.

The two gaps that came out of Phase 4 are still worth reading in their own right, and neither was
found by re-reading the design either:

- **`G-22`** — **closed in Phase 5**, and the row is worth reading closed because of what it got right
  when it was filed. The authorization hot path was the only unmeasured path in the database, and not by
  oversight: `auth.udfHasPermission`, `auth.tvfPermissionScope` and the three predicates are
  functions, a function cannot write to a table, and a schema-bound predicate running once per row
  must not try. So the one component that runs on every single query was the one component that
  reported nothing about itself, while every procedure around it logged. It was filed *against Phase 5*
  on the argument that the shape of the fix constrains the indexes — and the fix took the shape the row
  predicted: a sampled probe in the **procedures** (`Perf.PermissionProbeSampleRate`, shipped at **0**),
  an extended-events session **shipped as a statement rather than created by the install**, and
  `logs.vwPredicateFunctionStats` over `sys.dm_exec_function_stats`. The one thing the row did not
  anticipate is the most useful thing in `175`: **an inlined scalar function disappears from that DMV
  entirely**, and inline table-valued functions never appear at all, so a naive query over it reports the
  hot path as never called — indistinguishable from a predicate that is not bound. The view lists all six
  functions from a `VALUES` constructor and `LEFT JOIN`s the DMV, so a function with no statistics is a
  row saying so rather than an absence.
- **`G-23`** — a new table in the `logs` schema is writable by `applicationRole` until someone
  remembers to deny it. The conventions script grants the write verbs on `SCHEMA::logs`;
  `170_permissions.sql` now denies them on the four trail tables by name and asserts all twelve
  denies. The rule is inherited and permissive, the exception is enumerated and restrictive, so the
  fifth trail table repeats the hole *and the closing report still says 12 of 12 OK*. A green report
  beside an ungoverned table is the worst available shape for a control. The resolution is to invert
  the check: enumerate `sys.tables` in `logs`, subtract the one documented exception, and fail the
  deployment on anything unseen.

`G-21` remains open and was found in an unusual way of its own: by a test being **unable to write an
assertion**. Nothing in the database constrains *which issuer* a federated sign-in may come from, so
`_tests/040` can prove that a wrong subject resolves to nobody and can say nothing whatever about a
wrong issuer — there is no trusted-issuer list to check one against. Its target was Phase 3, which
has now passed without it; it is unchanged and still open.

`G-19` and `G-20` were both **closed in Phase 2**, each earlier than its target phase, and both are
worth reading in their closed state rather than being skipped as settled. `G-19` — the conventions
`permissions.sql` granting and denying nothing on `SCHEMA::config` or `SCHEMA::util` — became urgent
the moment `110_auth_authn_procedures.sql` needed a setting to read, and its resolution deviates
from what the gap row originally proposed: `SCHEMA::config` is granted and then
`config.ApplicationSetting` denied, because that table holds the dummy-verifier pepper. The
deviation is recorded in the gap row itself. `G-20` — design §14.6 requiring table-valued
parameters that the conventions hook rejects outright — was closed in the design document *before*
Phase 3 began, exactly as the resolution insisted, and deleted `T-045` rather than re-scoping it.

Each names a requirement of the design, what exists today, and what the difference costs. **One is
marked Critical and blocks production**, where there were two:

- **`G-01`** — nothing continuously verifies that every tenant-scoped table is registered and
  covered by a predicate. An unregistered table returns every tenant's rows to every tenant, with
  no error and nothing in any log. It fails open, silently, and looks exactly like correct
  operation.
- **`G-07`** — **closed 2026-09-20**, and worth reading closed. The protection of the TOTP secret was
  undecided, and it stopped being theoretical in Phase 2: `T-041` was `Blocked` on it and fixture user
  `frank` was, by construction, unable to sign in ever. Management decided it
  (`additionalRequirements-T-041.txt`): application-side envelope encryption under a TPM-backed CNG key
  on the application-layer server, secrets encrypted in `appsettings.secrets.json`, and SQL Server
  Always Encrypted **rejected** — external readers such as Power BI must keep reading these tables, and
  a template cannot know which columns a project will put in them, so there is no column list to enrol.
  The gap row records the decision, what the database holds (ciphertext and a key *label*, never a
  key), the `vault:` scheme reserved for a possible self-hosted HashiCorp Vault, and what remains
  untestable from the database. `frank` now enrols a first factor from his own refusal and signs in.

Four rows — `G-05`, `G-10`, `G-11`, `G-17` — are deliberate design positions rather than
omissions, recorded with their reasoning so a reviewer can disagree with the reasoning. That is a
different conversation from pointing out an oversight. Phase 6 added a fifth of that kind, `G-27`: the
four `User.*` permissions are **not** tenant-scoped, on purpose, because user records are global to a
deployment while profiles are not — filed so that the next reader who notices the asymmetry finds an
argument rather than an omission. It is the one of the five that is **Closed**, and how it closed is the
model for the other four: the resolution was to keep the design and promote the reasoning into a rule, so
DES §11.4 now states that *any attribute not needed to identify a person belongs on a tenant-scoped
table* and gives three consequences rather than restating the position. `auth.[User]` has no `TenantId`
and cannot have one (`D-02`), so every column added to it is readable by every tenant's administrators
without `Platform.BypassRowSecurity`; the attribute usually differs per hat anyway; and the identity set
is the one a **directory** can supply, which is why §18.1 converts cleanly. An accepted omission that has
been turned into a rule stops being re-litigated; one that is only argued in a spreadsheet cell does not.

### `workbooks/ui-gotchas.xlsx`

**For the team building the user interface.** 54 entries, each naming the trap, why it bites, and
what to do instead. Written for a .NET 10 application using the MVP pattern, Dapper, and stored
procedures only. Severity splits nine Critical, twenty-four High, twenty-one Medium.

**Two entries have been rewritten rather than added to, and that is worth knowing before you trust any
row here.** `UI-46` and `UI-48` were written on 2026-09-21 against gaps that closed the same day; both
described the missing behaviour in the present tense and told the UI team how to work around it, and
`UI-48` went so far as to call `E-50052` *"a dead end, not a challenge"*. Both now describe the shipped
behaviour, and both were **kept rather than deleted** because in each case the trap moved instead of
going away: there are now two profile listers and the administrative one is the one you find first, and
the step-up now works but spans three connections. `UI-52`, `UI-53` and `UI-54` arrived from `T-130` and
are the only rows in this workbook found by a **.NET client** rather than by reading or by `sqlcmd` —
which is why they are the three most likely to be relevant to the UI project on its first day, and why
`UI-53` matters out of proportion to its subject: it is the mechanism that silently defeats `UI-08`.

Three arrived with Phases 5 to 7, and they are unusual in this workbook because **one of them is
measured and the other two are not about the UI at all**:

- **`UI-40`** (High) — *row-level security is the net, not the `WHERE` clause.* Every query against a
  tenant-scoped table must filter by tenant itself. The predicate costs a flat **~5 logical reads for
  every row the query touches**, whether it admits that row or rejects it, so an unfiltered aggregate
  returning a thousand visible rows out of two hundred thousand pays for all two hundred thousand:
  **1,002,655 reads against 1,405** on the unprotected baseline. That 714× is a property of the
  *query*, not of the predicate — the same predicate on the same data costs 8 reads when the query is
  keyed. The per-row constant also rises with the size of the calling profile's scope, so a user with
  authority in fifty organizations pays more on every query, including ones that return nothing. This
  is the single condition attached to the `D-07` go/no-go: the design is accepted **on the condition
  that callers filter**.
- **`UI-41`** and **`UI-42`** (Medium) — a pair, and the second is the workaround for the first. A
  `sqlcmd -v` value **cannot contain a space** in any quoting form; single quotes, double quotes,
  backslash escapes and quoting the whole pair were each tried and none works, and the failure reads
  like a broken script rather than a broken command line. The way through is that `sqlcmd` resolves
  `$(Name)` from `-v` **first** and the process **environment second** — so an environment variable
  carries spaces, commas and the `$` characters of a PHC string through intact. The trap in the other
  direction is the part to remember: a leftover `-v` of the same name **silently wins** over the
  variable you carefully exported, and the script runs with the wrong value and no warning.
  `Install-TemplateDatabase.ps1` exports `$env:AdminVerifierPhc` and removes it on the way out; that
  is the pattern to copy.

Two more arrived on 2026-09-21 with the gap-closing pass, and both describe a surface that did not
exist the day before rather than a trap somebody fell into:

- **`UI-43`** (High) — *`@ExpectedCatalogueVersion` is optional in the signature and mandatory in
  practice.* `auth.uspGetNavigationForProfile` accepts `NULL` and keeps the pre-v1.1 behaviour, so a
  build that never passes it compiles, runs and renders a menu — possibly the wrong menu, silently,
  which is precisely the state `G-18` was filed for. The asymmetry will surprise you in the other
  direction too: a **missing** argument is allowed and a **blank** one is refused (`E-50230`), because
  a deployment whose configuration read came back empty must not thereby become an unchecked one. Read
  the version out of `config.ApplicationSetting` at build time, compile it in, and pass it every time.
- **`UI-44`** (Medium) — *the three password-expiry columns are `NULL` for a federated-only account,
  go **negative** past the deadline, and keep warning after it.* Both odd properties are deliberate
  and both are asserted in `_tests/050` section 5e, because the obvious "fix" — clamping the count at
  zero and dropping the warning — would silence the banner at the one moment the user has to act:
  `MustChangePassword` is set by a **batched** sweep, so the interval between a deadline and the next
  run of `auth.uspExpireCredentials` is real. A header that reads `NULL` as "expired" nags people who
  have nothing to change and then sends them to a form that refuses them (`E-50223`).
- **`UI-45`** (High) — *soft-deleting a tenant removes its **whole subtree** from
  `auth.vwTenantHierarchy` while every tenant under it stays live in `auth.TenantClosure`, so people
  disappear from the tree and are still refused by name.* The asymmetry is deliberate and `BL-020` is
  why: a closure that filtered `IsDeleted` would drop a deleted administration out of its descendants'
  ancestor set and make `auth.udfIsTenantUsable` fail **open** for every programme beneath it. The
  consequence for a screen is that a tree built from the view and a decision taken by the function
  disagree about the same tenant — an administrator watches a programme vanish with no audit event
  against it, while the user who works in that programme signs in, resolves a real profile, and is
  refused with `E-50021` naming a tenant the administrator can no longer find. So never diagnose a
  tenancy lockout from the hierarchy view: query `auth.Tenant` for `IsDeleted = 1` on the tenant *and
  every ancestor*. This row is the third of the three filed from a test rather than from the design,
  and it was filed because `_tests/030` had been written on the assumption these two objects can never
  disagree (`BL-074`).

Seven of the 42 — `UI-33` to `UI-39` — arrived with Phases 3 and 4, and **none of the seven came from
reading the design.** Six were found by a test file or a deployment failing; the seventh, `UI-33`, by
writing a function and noticing what it deliberately does not answer — `auth.tvfPermissionScope`
tells you where authority is *recorded*, not where it can be used today, so a tenant picker built
straight from it offers organizations the user will be refused for after the click. Two of the seven
belong to whoever deploys rather than to the UI team, and are here because the symptom lands on a
developer or a user: `UI-34`, a script that will not re-deploy against a database that already has
row-level security on, and `UI-35`, records that were visible yesterday.

Five of the 42 — `UI-28` to `UI-32` — arrived with the `G-07` decision on 2026-09-20 and are the
operational price of application-side encryption: a key bound to one machine, ciphertext for every
external reader, a one-way encryption flag in `appsettings.secrets.json`, first-factor enrolment out of
a refused sign-in, and a replay window that reopens for one TOTP step after a re-key. Three of those
five are not the UI team's code at all. They are in this workbook because it is the document the
receiving project actually reads, and all three are silent until they are expensive.

**Delivered to the UI project at milestone `M4`, reached 2026-09-20**, alongside the procedure contract
in `docs/40-ui-handoff-m4.md` — which cites this workbook rather than restating it, so the workbook is
the live document and the handoff is the entry point. **Nine rows are marked Critical**, and those nine
are the read-before-you-code list — the last of them added by Phase 4:

- `UI-01` — show the acting tenant and profile on every screen. This is the requirement's own
  gotcha, raised by name.
- `UI-02` — bind to UI element codes, never role names. The single most likely thing to be got
  wrong by a developer used to ASP.NET role attributes.
- `UI-04` — a profile switch invalidates everything cached.
- `UI-05` — set session context on every procedure call; never rely on a previous one. Works
  perfectly in development and fails intermittently in production.
- `UI-16` — the session token is a credential and never reaches a log.
- `UI-27` — **never call an authentication procedure inside an ambient transaction.** A
  `TransactionScope` around a sign-in attempt rolls back the failure record and the lockout
  increment that the procedure committed before raising. Unlimited guesses, nothing in the audit
  trail, and no symptom at all. This is the only gotcha in the workbook whose failure mode is
  invisible from the client side.
- `UI-26` — every sign-in failure shows the same message, whatever the error number. `E-50116`, the
  address throttle, is **not** an exception: naming it on screen tells an attacker their address is
  being counted. The numbers exist so the *audit trail* can distinguish cases the user may not.
- `UI-28` — the key that decrypts the MFA secrets lives on one machine and is not exportable. It
  arrived with the `G-07` decision and belongs to whoever builds the application server.
- `UI-35` — **a stale permission-id list in the row-security predicates is a silent denial.** The
  predicates cannot join the permission catalogue by code, so `120_rls_policy.sql` bakes the ids in
  as literals. Change the catalogue and nothing fails — rows simply stop matching, for some profiles
  and not others. Any change to `auth.Permission` is followed by
  `EXEC auth.uspRebuildTenantAccessPolicy @Action = N'Rebuild'`, and `120`'s closing report is also
  the diagnosis, because it re-derives the list and compares it with what is deployed.

**Three rows decide code before it is written rather than after**, and they are the ones to put in
front of an architect rather than a developer: `UI-36` (connection lifetime), `UI-35` (a stale
permission-id list is a silent denial) and `UI-40` (filter by tenant yourself). None of the three is
fixable late — the first shapes the data-access layer, the second shapes the deployment procedure, and
the third shapes every query in the application. `UI-36` constrains the
data-access layer: `auth.uspSetSessionContext` sets its five identity keys read-only, so a pooled
connection that has served one profile **cannot** serve another — a second call raises `E-50022` and
changes nothing — and session context is not transactional, so a `ROLLBACK` does not unset a key.
Open a connection, set context, do the work, close it. `UI-18` was written in the design pass and was
*proved* in Phase 4: an empty grid in SSMS is row-level security, not data loss, and it now has a
measured cause worth knowing — with the permission catalogue unseeded the predicates resolve to the
sentinel `-1` and deny every row.

`UI-22` changed in Phase 2 and the UI project should re-read it: bulk role assignment now takes a
JSON array rather than a `DataTable` as a table-valued parameter, which is simpler on the client
side as well — `G-20`.

---

## 3. Database scripts

### `database/Install-TemplateDatabase.ps1`

**The deployment runner.** Runs every script in install order against one target database with the
switches these conventions require, stops at the first failure, and writes a transcript to
`database/_logs/`. Defaults to `MDE-55TT2J4` and `testTemplate`. `-WhatIf` prints the exact command
line for every script and runs nothing; `-VerifyIdempotent` runs the whole sequence twice, which is
a Phase 0 exit criterion.

The manifest is **thirty-nine steps** after Phase 7, in declared-dependency order rather than in
filename order — every new script's own `Depends on:` line was read before it was placed. The two
orders no longer agree, and **where they disagree the declaration wins.** **Eleven orderings are
load-bearing**, and none of them is obvious; the manifest comment explains each, and these are the six
worth knowing before you read the file:

- `025_config_tables.sql` installs seventh, before any `auth` table, because `110`'s procedures read
  settings out of it and `120_rls_policy.sql` builds the policy from `config.TenantScopedTable`.
  Install order is not build order — that file was written in Phase 4 and installs before everything.
- `165_logs_procedures.sql` installs at **20**, immediately after the `logs` tables it writes to and
  **before every procedure script** — far out of numeric order, and the least cosmetic ordering in the
  file. **Six** scripts assert its procedures at install time and throw without them: `125`, `130`,
  `140`, `145`, `160` and `150`, the last because `auth.uspDemandPermission` writes the denial trail
  through `logs.uspRecordAuthorizationDenial`. It was at 33, and the **first clean-database build in
  the project's history stopped at step 29 saying so** — which is the whole argument for building one.
  Step 20 is the earliest point it *can* go, and therefore the point at which no later reordering can
  break it again (`BL-058`).
- `115_seed_reference_data.sql` installs at **27**, before `120`: the policy resolves `Data.Read`'s
  permission id out of `auth.Permission` and bakes the integer into three schema-bound predicates. On
  an unseeded database it finds nothing, substitutes the sentinel `-1`, and every predicate denies
  every non-maintenance session — fail-closed, correct in direction and baffling in practice
  (`UI-35`). It is also where `900` gets the application, the root tenant and the five roles it grants
  by code (`E-50086`, `E-50087`).
- `180_dbo_application_procedures.sql` installs at **35, before `120`**, and that looks backwards: the
  procedures exist to be constrained by the policy. It is the right way round because `120` cannot run
  before `180` without paying for it — a bound policy freezes the shape of `dbo.CaseFile` and the
  schema-bound predicates (`Msg 3729`) — and deferred name resolution means nothing forces the other
  order anyway. The cost is a **one-step window** in which those ten procedures enforce their own
  permission demands and *nothing else*: every tenant's rows visible to every profile, `P-06` not in
  force. `180`'s closing report calls that state **UNBOUND**, which is why **a deployment that stops at
  step 35 must not be treated as a deployment.**
- `120_rls_policy.sql` installs at **36**, fourth from last, after every script that creates or alters
  an object the policy binds. Binding late has a second benefit worth stating: no other script runs
  under an active policy, so no closing report can be silently emptied by a predicate that denies the
  deploying session (`UI-18`).
- `170_permissions.sql` installs **last**, because it names objects across every schema and a `GRANT`
  or `DENY` on a missing object is an error rather than a skip. That is also why `175` goes in front of
  it: `175` creates `logs.PermissionProbe` and `logs.vwPredicateFunctionStats`, and `170` having the
  last word on who may read what is worth more than ending the manifest on a tidy number.

The other five are `100` after `065`; `105` **after** `110` and `112`; `175` at 37 (which needs `150`
to have *run* but not to install — its closing report reads `sys.sql_modules` to confirm the sampled
probe is wired, while the dependency in the other direction is a runtime `OBJECT_ID` guard so that
`150` works on a database where `175` was never run); `135` at 38, the only script in the manifest that
creates nothing at all and exists purely as a standing assertion; and `140` → `150`, which is not a
manifest ordering but a **run-time** dependency surviving the install order only because the call site
is wrapped in an `OBJECT_ID` guard. **Do not remove that guard to tidy it up.**

One thing the manifest comment says about itself is worth repeating: the count line read "six" from
Phase 4 until this closeout while the list beneath it grew to eleven. **A count in prose next to the
thing it counts is a count that goes stale**, and the only fix is to re-count it when the list moves.

`Invoke-PolicyDrop` is the other half of the `120` item and runs **before every pass**: on any
database that already has row-level security on, the policy from the last deployment is dropped and
step 36 rebuilds it. Without it a second deployment fails at `030`, `065`, `090` or `100` with
`Msg 3729` — a failure a developer meets on their *second* local refresh and never their first, which
is `UI-34`.

**`900_bootstrap_first_admin.sql` is deliberately not a manifest step.** The manifest is idempotent by
construction and this is the one script in the repository that must **never** run twice, so the runner
treats it as an act performed *on* the schema rather than part of it: it runs after the last pass, once,
and only when `-BootstrapAdminVerifierPhc` supplies a PHC string the **application's** hasher produced.
Omit it and the database comes up with no user, no profile and no way in — which is the correct state
for a redeployment whose administrator already exists, because `900` refuses to run twice (`E-50080`).
The five bootstrap values reach `sqlcmd` **through the environment, not through `-v`**, because a
display name contains a space and a PHC string contains commas and equals signs; that is `UI-41` and
`UI-42`, and lines 448–452 are the worked example. `$env:AdminVerifierPhc` is removed on the way out.

`950_verify_deployment.sql` is the only planned script not yet written (`T-104`), so the manifest will
be forty steps and is thirty-nine today.

Nothing is skipped on a complete deployment any more. The `RequiresAuth` flag and
`Test-AuthSchemaPresent` are **kept** even so, because a project deploying a subset — or a database
half way through an upgrade — still needs the named skip at step 18 rather than a failure.

**Executed for the first time on 2026-09-19**, against `MDE-55TT2J4\testTemplate`, and re-run at the
close of each phase since. Two full twenty-eight-step runs on 2026-09-20 against the existing
database: the unbind reported OK, step 21 re-created the functions it could not have altered
otherwise, step 27 reported `2 table(s) protected` and `0 registry row(s) skipped`, and the run exited
0. `-VerifyIdempotent` exits 0 with its two passes differing only by the verification section appended
after the second. These runs were against an already-deployed database, so they are convergence
checks for the eight scripts Phases 3 and 4 added rather than proofs of fresh installation.

Phase 1 did change it, and the change was a defect fix rather than an extension.
`Test-AuthSchemaPresent` tested `auth.Tenant` alone, and `090_dbo_application.sql` asserts
`auth.Tenant` **and** `auth.UserProfile`. The moment `030_auth_tenant.sql` created the first, the
probe would have answered YES while the true answer was "some", `090` would have been run instead of
skipped, and `-b` would have failed the whole deployment at the exact moment Phase 1 succeeded. The
function now tests both and carries the reason, with an instruction to extend the list whenever a
`RequiresAuth` script asserts something new. `BL-023`.

### `database/000_prerequisites.sql`

Asserts the server version, creates the target database if it does not exist and reuses it if it
does, and sets compatibility level, `READ_COMMITTED_SNAPSHOT`, page verification and auto-close.
Both halves are proven: it created `testTemplate` on `MDE-55TT2J4` on the first run and reported
reusing it, unchanged, on the second.

The one script in the deployment that runs in `master` rather than the target, because it is the
script that creates the target — so its guard is inverted: it refuses to run anywhere *except*
`master`. `BL-011`.

### `database/005_schemas_and_roles.sql`

The four schemas (`auth`, `logs`, `config`, `util`) — seven in the finished database, once the
conventions skill adds `logsData`, `history` and its use of `dbo` — ownership forced to `dbo` so
ownership chaining works, and the four database roles. Section 4 is the membership policy for `rlsBypassRole`, written
out as four numbered rules, because a member of that role can read every tenant's rows unfiltered.

Runs **before** the conventions skill's installers, which is a departure from that skill's
documented order and is deliberate: a grant to a role that does not exist yet is silently skipped.
`BL-012`.

Corrected in Phase 1, after it had already reached Verified: its role-membership report counted with
`COUNT (m.member_principal_id)` over a `LEFT JOIN`, so on a fresh database — where every role is
empty — it printed `Warning: Null value is eliminated by an aggregate or other SET operation.` twice
in the deployment transcript. The count was always right; the transcript was not, and a reader who
learns to scroll past one warning will scroll past the next. Now a correlated `COUNT (*)`, which
returns 0 over no rows without warning. `BL-024`.

### `database/025_config_tables.sql`

`config.ApplicationSetting` — the typed, tenant-optional settings table the authentication
procedures read their thresholds from — and `config.TenantScopedTable`, the registry every
row-level-security predicate will be driven from in Phase 4.

**It arrived in Phase 2 from Phase 6, and the reason is worth knowing before moving it back.** Every
threshold `110_auth_authn_procedures.sql` enforces lives here: the lockout count and window, the
address-throttle count and window, the login-exchange timeout, and the pepper that derives the dummy
verifier an unknown user is answered with. A procedure that cannot read a setting cannot have a
configurable threshold, so either this table came forward or the numbers were hard-coded — and a
hard-coded lockout threshold is a security control nobody can tune without a deployment.

`config.ApplicationSetting` is the one table in the database **denied** to both application roles by
`170_permissions.sql`, because of that pepper. See `170` below; the deny is not an oversight and is
the one place the permission model departs from what `G-19` proposed.

### `database/030_auth_tenant.sql`

**The root of everything.** `auth.Application`, `auth.TenantType`, `auth.Tenant` and
`auth.TenantClosure`, their four `AFTER UPDATE` audit triggers, and 47 of 47 column descriptions.
Read it before any other `auth` script: every table added later hangs off `auth.Tenant`, and three
decisions made here shape the rest.

- **`auth.Application` exists so several independent tenant trees can live in one database.** That
  is what makes it possible to test that a scope expressed at one root cannot reach another — the
  worst failure this schema can have — without provisioning three databases. The three variant trees
  of DES §17 are three rows here.
- **`auth.Tenant` carries a denormalised `TenantTypeCode`** beside the type id, and the pair is held
  true by a composite foreign key against an unfiltered `UNIQUE`. `CK_auth_Tenant_RootHasNoParent`
  needs the code, and a `CHECK` may only read its own row. The alternative was tried and
  **measured**: a scalar function referenced by a `CHECK` cannot afterwards be `CREATE OR ALTER`ed
  (error 3729), which breaks the re-runnability every script here requires. `BL-019`.
- **`auth.TenantClosure` deliberately contains soft-deleted tenants.** It records shape and nothing
  else. Had it filtered on `IsDeleted = 0`, a deleted mid-tree tenant would vanish from its
  descendants' ancestor set and `auth.udfIsTenantUsable` would return 1 for a program beneath a
  deleted administration — failing **open**, which is the one kind of failure this design refuses
  anywhere. `BL-020`.

Two things arrive here that the install order would have put elsewhere, each for a reason worth
knowing before moving them back: the seven tenant types are seeded here rather than in
`115_seed_reference_data.sql`, because the composite foreign key cannot be satisfied until they
exist (`BL-021`); and the audit triggers ship here rather than in `135_audit_triggers.sql`, because
the audit column defaults fire on `INSERT` only and `auth.uspRebuildTenantClosure` — three scripts
later — is all `UPDATE`s (`BL-022`).

### `database/035_auth_tenant_policy.sql`

`auth.TenantAuthenticationPolicy` and `auth.TenantDefaultRole` — how a subtree of the hierarchy says
"sign-in works differently here".

**Most tenants have no row, and that is the design.** The unique index on `TenantId` is filtered on
`IsDeleted = 0`, `auth.udfResolveAuthPolicy` walks the closure upward and takes the lowest-depth
match, and the normal state of a deployed database is a policy on the root and nowhere else. A
hundred-tenant Variant 2 deployment has two or three rows here. There is deliberately no default row
per tenant: a row means "this subtree is different", and a table where every tenant has one is a
table where nobody can see which tenants were deliberately overridden.

Two things a reader is likely to get wrong, both of which the file answers in the column
descriptions rather than only in a comment. `RequireMfaForLocal` governs *ordinary* local sign-in and
has no authority over the platform-administrator bypass, which requires a second factor
unconditionally — `INV-08`, enforced in `auth.uspCompleteLogin` by `E-50107`. And
`auth.TenantDefaultRole.RoleId` is constrained by a **guarded `ALTER`, not by its `CREATE TABLE`** —
`auth.Role` installs at manifest step 13 and this file runs at step 9, so the key cannot be declared
with the column.

That second one is worth reading the banner for, because the file used to handle it the other way and
the other way failed. The `ALTER` was written out in the banner as a sentence addressed to the next
reader, the closing report printed `PENDING` on every run, and **the constraint was still missing at the
end of Phase 4** — two phases after `auth.Role` arrived. It is now the last thing section 2 does, guarded
on `IF OBJECT_ID(N'auth.Role') IS NOT NULL AND NOT EXISTS (… sys.foreign_keys …)`, applied `WITH CHECK`,
and the report has three states instead of two: `OK`, `PENDING` only while `auth.Role` is genuinely
absent, and `VIOLATION` once the parent exists and the key does not. `070_auth_session.sql` had the
identical defect and now has the identical fix; both are `BL-049`, and the pair is the strongest argument
in this package for the rule that a deferred statement belonging to no script belongs to nobody.

### `database/040_auth_userprofile.sql`

**`auth.User` — the person — and `auth.UserProfile`, the hat they wear at one organization.** The
second table arrived in Phase 3 as task `T-046`, which is why two places in this package used to say
Phase 2 and were wrong (`BL-025`), and why `090_dbo_application.sql` used to be skipped at deployment
and no longer is.

`auth.User` is **not tenant-scoped**, which surprises most readers of a multi-tenant schema: a person
is a person, and their relationship to a tenant is a profile. Email is not a key either — the same
address can legitimately belong to two accounts in two trees.

`auth.UserProfile` carries **the only unfiltered unique constraint in the database**, and the banner
argues for it: `UX_auth_UserProfile_Id_Tenant` on `(UserProfileId, TenantId)` exists so the demo
domain's composite foreign keys can reference the pair, which is what makes cross-tenant assignment
structurally impossible rather than merely checked. It is unfiltered because a foreign key cannot
reference a filtered index. `UX_auth_UserProfile_Default` is the one-default-profile-per-person rule
(`INV-03`), filtered on `IsDefault = 1 AND IsDeleted = 0`.

`ProfileName` is unique per `(UserId, TenantId)` among live rows, which the design did not ask for —
`BL-036`. The reason is the profile switcher: two hats both called "Case Worker" at the same
organization produce a list where the right choice cannot be identified, and picking the wrong one
sets a different `ScopeTenantId` and therefore a different set of visible rows. Uniqueness is per
tenant rather than per user because the same person legitimately holds a "Case Worker" hat at two
organizations.

### `database/045_auth_identity.sql`

The five credential and factor tables plus the exchange row: `auth.UserCredential`,
`auth.PasswordHistory`, `auth.UserFederatedIdentity`, `auth.UserMfaFactor`,
`auth.UserMfaRecoveryCode`, `auth.LoginAttempt`, with an audit trigger each.

**This database stores verifiers and cannot check them** — `D-08`, design §19.2.
`auth.UserCredential.VerifierPhc` holds a self-describing PHC string; the database hands it out and
is told the answer. The reason is not squeamishness about T-SQL: a memory-hard KDF run inside the
engine spends the server's working set on every guess *including* every guess by an attacker, and the
plaintext would land in a T-SQL parameter, which means the plan cache, Query Store and any Extended
Events session somebody left running.

**`INV-07` has teeth here, and they are in a trigger rather than the index.** Everyone remembers the
unique index on `(Issuer, SubjectId)`. The half that matters is that *re-pointing* an existing row is
account takeover in a single `UPDATE` — no insert, no delete, nothing unusual to see — so `UserId`,
`Issuer` and `SubjectId` are immutable and unlinking is a soft delete followed by an insert, which
leaves both halves in the trail.

`auth.PasswordHistory` is a separate table rather than a temporal history of the credential, so the
reuse depth is a configuration value rather than however many rows system-versioning happens to hold,
and so an unrelated `UPDATE` — an expiry date, a soft delete — does not make the reuse check slower
for reasons nobody can see.

### `database/050_auth_permission.sql`

`auth.PermissionCategory` and `auth.Permission` — the vocabulary every authorization decision is
expressed in. **It seeds nothing.** The 35 rows are `115_seed_reference_data.sql`, which is Phase 6
task `T-089` and has not run, so the catalogue is empty on the dev database today.

**Permissions are code, not configuration, and this is where that stops being a slogan.** A
permission code is a literal in stored-procedure bodies, a literal in `120_rls_policy.sql`, and a
literal in the .NET layer's screen wiring. Adding a row without adding the code that demands it
produces a permission nobody can exercise; deleting a row procedures still name produces `E-50031` at
run time on a screen that worked yesterday. So there is no administrative screen for this table and
there must never be one — `auth.Role` is the administrator's vocabulary, `auth.Permission` is the
developer's.

**The category is not scoped to an application and the permission is.** Seven families — `Data`,
`User`, `Authz`, `Tenant`, `Config`, `Audit`, `Platform` — mean the same thing in every variant.
Permissions carry `ApplicationId` because `D-09` makes the application the outermost scope, and the
consequence caught the design during implementation: a database serving four applications holds
**four rows** whose code is `Data.Read`, with four different ids. The row-security predicate resolves
that code to a literal at deploy time, so a single id would protect one application and fail *open*
for the other three. `BL-039`.

`IsTenantScoped = 0` is not a synonym for "granted to everybody" — it means the permission is
evaluated *without* a tenant. The three `Platform` permissions are the whole set, and `INV-09` adds a
second independent condition to them, `auth.User.IsPlatformAdmin = 1`, which is deliberately **not**
in this table: a grant to a profile whose user is not a platform administrator is a legal row that
confers nothing, so revoking the flag revokes the authority without unpicking every grant.

### `database/055_auth_role.sql`

`auth.Role` and `auth.RolePermission` — the administrator's vocabulary, and the only part of the
authorization model a human is expected to compose. **This file creates no table types**: `G-20`
closed by replacing them with one `@Payload NVARCHAR(MAX)` shredded by `OPENJSON` and refused with
`E-50046`, and the SQL gate rejects `CREATE TYPE ... AS TABLE` outright, so it is not a preference a
later script can quietly depart from.

**A role is owned by a tenant**, which is what makes role *definition* delegable without collision: a
role defined at the root is usable anywhere, one Anne Arundel defines is usable only within Anne
Arundel. That is `INV-04` — and **it is not enforced here.** "Ancestor-or-self" is a question about
`auth.TenantClosure` asked of a row in `auth.UserProfileRole`, two tables away, so it belongs to
`060` and raises `E-50042` there. What *is* enforced here is the half of `D-09` that can be:
`FK_auth_Role_OwnerTenant` references the unfiltered pair `(TenantId, ApplicationId)`, so a role
cannot be owned by a tenant in another application — otherwise `INV-04` would eventually compare
tenants in two unrelated trees, where the answer is not false but meaningless. `BL-040`.

**`IsSystemRole` protects a specific list of changes, and the split is the interesting part.** The
trigger refuses, on a system role, a change of `RoleCode`, a clearing of the flag, and a soft delete —
the changes that would break a re-run of `115_seed_reference_data.sql` or leave a deployment without a
role `900_bootstrap_first_admin.sql` grants by name. `RoleName` and `RoleDescription` stay **editable**,
because the seed converges them by `MERGE` and improving a shipped description is what that `MERGE` is
for. The permission *list* of a system role is protected in the procedure rather than the trigger, for
the same reason. The line is "an administrator may not edit a system role; the template may", and a
trigger cannot tell those two apart.

### `database/060_auth_profile_role.sql`

`auth.UserProfileRole` — **the table the whole design is about.** Everything before it is vocabulary;
this is the only place a human decision is recorded: this person, in this organization, may do these
things, over this part of the tree, granted by that person, until then. Four consequences, each one a
column.

**Scope is not the profile's tenant.** `ScopeTenantId` defaults to it — the common case an
administrator never has to think about — and setting it elsewhere is what Variant 2 needs: a program
officer carries Editor scoped at their program so their inserts land there, and Read-only scoped at
the agency so they see every other program's records without switching profile. One profile, two
grants. That is why the natural key is the **triple** `(UserProfileId, RoleId, ScopeTenantId)`: the
same role twice at two scopes is not a duplicate, it is the feature.

**Revocation is a soft delete and expiry is not.** Revoking sets `IsDeleted = 1` and the row stays,
because "who could approve this last March" is a question an auditor asks about a grant that no longer
exists. `ExpiresUtc` is a different mechanism for a different need, and an expired grant is filtered
out at *materialization* time rather than by anything that writes here. **Nothing expires a row; time
does.** The rule that follows is the one to carry away: this table is not the effective permission set
and must never be read as one. A live row here can be expired, can belong to a soft-deleted role, can
point at a deactivated profile, and can name a role whose permissions were emptied yesterday.

`GrantedByProfileId` is nullable because on an empty database `INV-05` has nobody to satisfy it.
`900_bootstrap_first_admin.sql` writes `NULL` rather than pointing the row at itself — a
self-reference would be indistinguishable from the self-grant `INV-06` exists to refuse, and would put
a fiction in the one column §11 relies on. The closing report counts them, and the count should be at
most one per deployment.

### `database/065_auth_effective_permission.sql`

`auth.ProfilePermissionScope` — the materialized effective grant — and
`auth.uspRebuildProfilePermissionScope`, the only thing that writes it. Three columns: this profile
holds this permission at this scope tenant. **Every authorization decision in the database reads this
table and nothing else**, which is the entire reason it exists — resolving four tables and a recursive
closure once per row was measured and is not a trade anyone would take. `D-07`.

**It is not expanded over the tenant subtree, and that is the design.** The obvious materialization
would store one row per descendant, turning one grant into hundreds and a re-parenting into a rewrite
for every profile whose reach changed. The expansion stays a join to `auth.TenantClosure` at read
time. So the rule governing every reader is: a row here says "at this tenant **and below**", never "at
exactly this tenant". Read it without the closure join and you answer a question nobody asked and deny
authority that was granted.

**What the rebuild deliberately does not filter is more instructive than what it does.** It removes
soft-deleted and expired grants, soft-deleted roles, mappings and permissions, and inactive profiles.
It leaves alone: `auth.Role.IsAssignable`, because `0` stops *new* grants and does not revoke existing
ones; the **user's** state, because lockout is a sign-in question refused by `E-50024` before a scope
row is read, and a lockout needing a rebuild to take effect would fail open for as long as the rebuild
took; and **tenant usability**, because §5.4 forbids deactivating a tenant from writing to anything
beneath it — `auth.udfIsTenantUsable` walks the ancestor chain at read time so that reactivating
restores everything.

The source is `SELECT DISTINCT`, and the loss is real and accepted: **this table cannot say which role
supplied a permission.** Two roles both conferring `Data.Read` at one scope produce the same triple
twice, which is a `MERGE` error rather than a duplicate row — and it is not hypothetical, because
seven of the fourteen baseline roles carry `Data.Read` on purpose. `auth.vwProfilePermission` answers
"why does this person have this" by resolving the same joins without the `DISTINCT`, rarely, on one
profile at a time.

### `database/070_auth_session.sql`

`auth.UserSession`. **The token is not in this table; a SHA-256 of it is.** A stored session token is
a stored password: anybody who can read the table — a backup, a replica, a support query — can
present every live session as its owner with no cracking required. It is a plain hash and
deliberately not a memory-hard KDF, because a session token is machine-generated with full entropy,
so guessing is not the attack and a KDF would add a cost to every authenticated request in the
estate.

`AbsoluteExpiryUtc` and `IdleExpiryUtc` are both **stored**, computed once at sign-in from the
resolved policy. Derived on read, a live session would silently become a one-hour session because
somebody edited a policy row at lunchtime — or a twelve-hour one. The rule in force when the session
started is the rule it lives under, and the only way to say that is to write it down.

`EndedUtc` is **write-once at the trigger** (`E-50010`), proven against a direct `UPDATE` as
`db_owner`: a session that can be un-ended can be resurrected by one statement after a sign-out, a
revoke or an incident response, and the ended row is the evidence that it ended.
`ActiveUserProfileId` is nullable, and **its foreign key is added by a guarded `ALTER` in section 1
rather than declared in the `CREATE TABLE`** — this table installs at manifest step 16 and
`auth.UserProfile` at step 10 of a phase that may not have run, so the condition is the *parent
table*, not the phase number. The closing report has three states, and the third one is the point:
`OK`, `PENDING` only while `auth.UserProfile` is absent, and **`VIOLATION`** once the parent exists and
the key does not.

It had two states for five phases, which is how it came to be missing. `FK_auth_UserSession_UserProfile`
did not exist at the end of Phase 4 — the design said it did, the `ALTER` was written out in full in
this file's banner for "the next reader", and every deployment printed `PENDING` and looked identical
to the last one. It was applied and verified trusted on 2026-09-20 during the closeout, and
`035_auth_tenant_policy.sql` turned out to have the same defect on
`FK_auth_TenantDefaultRole_Role` — found minutes later by the same query, fixed the same way. `BL-049`,
and the lesson generalises past both constraints: **a pending row in a green report is not a plan.**

### `database/075_auth_ui_catalog.sql`

`auth.UiElement` and `auth.UiElementPermission` — **the only part of the authorization model the user
can see.** Areas, screens, tabs, sections and commands in one tree per application, and the permissions
that gate each node. The tables ship **empty**, exactly as `050_auth_permission.sql` ships
`auth.Permission` empty; the starter catalogue is `115`'s job.

**An empty catalogue and an empty permission table fail in opposite directions, and the difference is
the thing to remember.** `auth.uspGetNavigationForProfile` over an empty catalogue returns no rows, so
the application renders no navigation — wrong, but wrong on the first screen a developer opens. An empty
`auth.Permission` makes `120_rls_policy.sql` bake the sentinel `-1` into every predicate and deny every
row to every non-maintenance session (`UI-35`). **A missing navigation entry hides a screen; a missing
permission entry denies every row.**

The default for an element with no permission row is **visible**, per DES §13.1, and this file does not
enforce a mapping — a `CHECK` cannot span two tables and a trigger that refused an unmapped element
would make the seed order matter. So the closing report **counts** them instead, on every deployment,
and `950_verify_deployment.sql` will warn on them. That default is right exactly once, for a home page.

Both the parent link and the permission link are **composite on `ApplicationId`**, against the
unfiltered pairs `UX_auth_UiElement_Id_Application` and `UX_auth_Permission_Id_Application`. A tab
cannot hang under a screen in another application and a screen cannot be gated by another application's
permission. That is `D-09` made structural rather than conventional, and it is the same argument as
`auth.RolePermission` (`BL-040`); the cost is one redundant `int` per row plus a trigger making it
immutable (`E-50010`).

### `database/080_auth_registration.sql`

`auth.OrganizationRegistration` — the Variant 3 self-service onboarding queue, and **the only table in
the design written by a caller who is not authenticated.** `auth.uspRegisterOrganization` takes no
session token, because DES §16.4 step 1 is a public form. Every other property of the table follows from
that single fact.

**No tenant is created by a registration.** `TenantId` is `NULL` until an agency user holding
`Tenant.Create` approves, and a `CHECK` ties it to `Status` rather than trusting the procedure — §16.4:
"self-service tenant creation in a public-facing application is how an attacker gets a tenant of their
own and an approved-looking identity." Nothing here is a credential: an organization name and a contact
address, no verifier, no token, no secret. The external *user*'s credential arrives later through
`auth.uspRegisterExternalUser`.

**The conclusion is write-once at the trigger** (`E-50010`), which refuses any `Status` change out of
`Approved` or `Rejected`. `auth.uspApproveOrganization` also raises `E-50060` for "already processed",
and the two are not redundant: one is a friendly error for a double-clicked button, the other holds
against somebody with SSMS.

`ClientAddress` is captured because it is the only attribution an anonymous submission has — **and it is
not a rate limit.** `E-50116` throttles sign-in per address; there is no equivalent for registration,
which is `G-24`, still open, and `G-06` for the edge half. The column is currently a promise the database
does not keep, and that is stated in both gap rows rather than left for a reader to discover.

Pending uniqueness is on the **proposed tenant code**, filtered to `IsDeleted = 0 AND Status = N'Pending'`
— not on the email, because two organizations may share an agent and one may correct its address
mid-review. Refusing a duplicate code at submission is kinder than refusing it at approval, after
somebody has been told to expect it; and a rejected registration falls out of the filter, so the code
can be requested again.

### `database/085_logs_auth_tables.sql`

`logs.AuthenticationEvent` — and the first question a reviewer asks is why it exists when
`auth.LoginAttempt` already does. **They record different kinds of thing with different lifetimes.**
`auth.LoginAttempt` is operational state: one row per exchange, updated as it proceeds, read on every
attempt to compute both counts, needed for as long as the lockout window plus an incident review.
`logs.AuthenticationEvent` is the narrative: append-only, never read by the authentication path, and
the only record of the things that are *not* sign-in attempts — a password changed, a factor removed,
a recovery code redeemed, a session revoked by an administrator. Truncating a year of the first would
be a reasonable retention decision; doing the same here would destroy the only record that a factor
was removed the day before the account signed in from somewhere new.

It is in `logs` rather than `logsData` because the audience is human, and that decides the permission
story: `logsAuditReader` reads it directly, with nothing at all on `SCHEMA::auth`. **That is the whole
reason it can be read**, and it is why nothing secret may go in `DetailJson` — no verifier, no token,
no token hash, no recovery-code hash. Anything put in there has escaped `INV-11` by the front door.

### `database/090_dbo_application.sql`

**The demo domain, and the worked example a developer copies.** `dbo.CaseFile` and
`dbo.CaseNote` — the smallest pair of tables that exercises every pattern a real tenant-scoped
table has to follow.

The business columns are deliberately thin and a real project should expect to replace them. The
*shape* is load-bearing: `TenantId` on every table and immutable, a composite foreign key rather
than a bare parent reference, a per-tenant natural key filtered on `IsDeleted = 0`, an
`AFTER UPDATE` audit trigger, a row-level security registration, and no delete path at all.

Modified from the supplied version. What changed, and why, is `BL-001` through `BL-003`,
`BL-007` and `BL-008` in the Build Log. In short: it had no audit triggers, its audit attribution
would have recorded the application's name on every row, its registry registration was deferred
to a later script and graded as expected when absent, and its header cited a gap number belonging
to a different project's register.

**Verified in Phase 7**, and the qualification that held it at *Drafted* for three phases is worth
knowing because it was about the *tests*, not the deployment. It was skipped at every deployment until
Phase 3 built `auth.UserProfile` (`T-046`, and not Phase 2 as this file and the runner both once said —
`BL-025`); it now runs at **step 21 of thirty-nine**. It stayed Drafted while nothing exercised the
tables through the intended surface, which `180_dbo_application_procedures.sql` now does (`T-102`).
What had already been exercised was the shape: `_tests/060` builds four case files in four tenants and
walks the whole of §10.3's access matrix against them.

Phase 7 also added the two things the supplied version lacked and the plan's findings `F-01` and `F-02`
named: `trg_au_updt_CaseFile` and `trg_au_updt_CaseNote`, so an `UPDATE` no longer leaves
`auditModifiedBy` at its insert-time value; and a `DEFAULT` on `auditCreatedBy` that prefers
`SESSION_CONTEXT (N'AppUser')` and falls back to `ORIGINAL_LOGIN ()`, so a row arriving by a route
nobody anticipated is still attributed to a person rather than to the pooled login. Writing the strong
expression here is what exposed `G-41` — **every `auth` table still carries the bare
`ORIGINAL_LOGIN ()`**, so the demonstration domain has better attribution than the authorization state
does, which is backwards.

Its composite foreign keys turned out to have a consequence the design had not written down. An
`UPDATE` that changes `TenantId` breaks `(AssignedToProfileId, TenantId)` **before** the block
predicate is ever evaluated, so the refusal of a tenant move is `Msg 547` — referential integrity —
rather than the `Msg 33504` the access matrix describes. Two defences in a row, and the outer one
speaks the wrong language. `BL-045`, `UI-38`.

### `database/095_auth_views.sql`

`auth.vwTenantHierarchy` — a recursive CTE giving each tenant's full path from the root, its depth,
its type label, and `AnyAncestorInactive`. The later views of DES §15.6 are listed as `PENDING` in
its closing report, so the distance between this file and the design is visible in a deployment
transcript rather than only on the Scripts sheet.

**It installs before `100_auth_functions.sql` and therefore cannot call `auth.udfIsTenantUsable`** —
a view resolves names at `CREATE` time, where a procedure gets deferred resolution. That is why
install order is not build order, and it is why `AnyAncestorInactive` is documented as **not** a
usability verdict: the verdict has one definition, it is the function, and `auth.uspGetTenantTree`
calls it per node.

### `database/100_auth_functions.sql`

**Ten** functions after Phase 3, each the single definition of one question, and the file is where the
naming rule was corrected: the four table-valued ones are `tvf`, not `udf`, which Appendix C already
implied — `BL-041`. Three are about state: `auth.udfIsTenantUsable`,
`auth.udfIsUserUsable` — which is what `E-50115` means, covering deleted, inactive and locked out
under one number and one message — and `auth.udfResolveAuthPolicy`, the upward walk of
`auth.TenantClosure` that makes a policy set on the root apply to a tenant that has no policy row of
its own. That last one is why `035_auth_tenant_policy.sql` needs so few rows to be useful, and its
measured proof is in `_tests/040`: a session took its 60-minute lifetime from the child tenant's
policy against a shipped default of 480, so the inheritance cannot have agreed by coincidence.

**The other two are the actor resolvers, and they arrived on 2026-09-20 with `T-112`.**
`auth.udfResolveSessionUser` answers "whose session is this" from a token hash, and
`auth.udfResolveEnrolmentActor` answers "whose sign-in was this" from a `LoginAttemptId` — and answers
it only for an attempt the database itself refused with `FailureReason = 'MfaRequired'`,
`PasswordVerified = 1`, inside `Authn.MfaEnrolmentWindowSeconds`. They are here rather than in
`112_auth_mfa_procedures.sql`, which is their only caller today, for one reason: "who is calling" is a
rule, every procedure in `112` asks it, and a rule with two copies is a rule with two answers. `112`
asserts both functions exist at install time instead of discovering their absence at the first call.

`auth.udfIsTenantUsable` — the single definition of what makes a tenant usable. 1 only when the
tenant **and every tenant above it** are active and undeleted, which is what makes deactivating an
administration take effect on every program beneath it without a single write to any of them, and
reversible for the same reason.

One `RETURN` of a `CASE` over two `EXISTS` so Froid inlines it, and deliberately **without**
`SCHEMABINDING` — this design binds only the three row-level-security predicates, where the engine
requires it. It fails closed three ways: an absent tenant, a closure that has never been built, and
a `NULL` argument all return 0. Two of the three are asserted in the script's own closing report, so
the deployment re-checks the claim rather than the reader trusting a comment.

**Phase 3 added the five authorization functions**, and two of them are the hot path. `auth.udfHasPermission`
is two seeks against `auth.ProfilePermissionScope` and reads `SESSION_CONTEXT` itself, returning 0 when
there is none. `auth.tvfPermissionScope` answers "which tenants does this profile hold this permission
on" — and **deliberately does not join `auth.udfIsTenantUsable`**, so a deactivated tenant still comes
back. That is not an oversight: authority must survive a deactivation so it returns intact when the
tenant does. It does mean a tenant picker built straight from it offers organizations the user will be
refused for after the click, with `E-50021`. `UI-33`, and the new design §9.2.

The three `tvfTenant*Predicate` functions are here in their **reference form**, joining
`auth.Permission` and comparing `PermissionCode`: readable, and what design §10.2 publishes.
`120_rls_policy.sql` re-creates them with the ids resolved to literals. Both forms are correct and the
design now documents both rather than presenting either as "the" predicate. These three are the only
objects in the database carrying `WITH SCHEMABINDING`, because the engine requires it of a predicate —
and that is why **this file cannot be re-run against a database whose policy is bound** (`Msg 3729`,
`UI-34`).

### `database/105_auth_session_procedures.sql`

The session-context surface: `auth.uspSetSessionContext` — **the first statement of every
authenticated request** — its counterpart, and the two maintenance-bypass procedures that are the
controlled door out of row-level security. It installs **after** `110` and `112`, out of numeric
order, because it calls `auth.uspEndSession` when it finds an expired session.

**The parameter is the hash, not the token**, and §9's sketch said otherwise. Every other object in
the database already agreed with the code: `070` stores SHA-256 and states the token is never stored,
five procedures in `110` and `112` take a hash. A procedure that hashed would have to fix an encoding,
and two callers disagreeing about UTF-8 versus UTF-16 would produce two hashes of one token with
nothing to say which was wrong. The design was corrected rather than the code — `BL-043`. The
consequence to state plainly: **inside this database the hash is the credential.** Anyone who can read
`auth.UserSession` can call this procedure with a stored hash and be issued another user's context,
which is why no application login holds `SELECT` on it (`INV-11`) and why the hash never reaches
`logs.ExecutionLog` — `@KeyParameters` records `(supplied)` and the resolved ids, never the bytes.

**This is the one procedure in the database that deliberately does not log a start row**, and the
reasoning is recorded rather than assumed. One `logs.ExecutionLog` row per request at fifty requests a
second is four and a third million rows a day whose entire content is "context was established, as it
was last time". The first performance review to notice that does not delete this call site — it deletes
the instrumentation everywhere, and the template loses rule 8 altogether. So both context procedures
use the error-only shape; the liveness slide is already recorded where it belongs, in
`auth.UserSession.LastSeenUtc`, which is one row per *session* that moves rather than one per request
that accumulates. The two maintenance procedures are fully instrumented: a human calls them a handful
of times a month and what they do is worth a row each. `G-22` holds the middle position nobody needs
yet.

**Session context is not transactional, and that decides the order of every statement in the file.**
Measured on this instance: a key set inside a transaction survives that transaction's `ROLLBACK`. So
`auth.uspSetSessionContext` sets its five keys *after* its work, never before, so a failure cannot
leave a connection carrying an identity whose only database write was rolled back — and
`auth.uspBeginMaintenanceSession` commits its `logs.AuthenticationEvent` row *before* it sets the
bypass key, so the record exists even if the session then fails. The keys are also **read-only once
set** (`Msg 15664` on an attempt to clear one), which is `UI-36` and decides how the .NET layer handles
connections.

### `database/110_auth_authn_procedures.sql`

**The largest file in the project, and the one to read before any other `auth` procedure.** The seven
authentication procedures: `uspGetLoginVerifier`, `uspRecordLoginFailure`, `uspCompleteLogin`,
`uspVerifyMfa`, `uspBeginSsoLogin`, `uspCompleteSsoLogin`, `uspEndSession`. All three sign-in routes,
both lockout arms, and every error number from `E-50100` to `E-50116`.

**Signing in is two round trips, and that is the whole shape of the file** — `D-08`. The application
asks who is trying and is handed a verifier string; it computes Argon2id; it reports one boolean.
Everything else is decided here from the tables: whether the user is active, whether MFA was
satisfied, whether the account is locked, how long the session lasts. The application is trusted for
exactly one fact and nothing else.

Four things in it are worth knowing before reading the code:

- **An unknown name always gets a verifier, and it is derived rather than constant.** A constant dummy
  means every unknown name yields byte-identical output, so seeing one unknown-name response
  identifies every other for free. The dummy is built by hashing a configured pepper with the user
  name, at the real field lengths — 97 characters against 97 — because a dummy with a short salt is
  distinguishable by eye, with no timing analysis at all.
- **Every number in the range shows the same message on screen** (`UI-26`); the numbers are for the
  log. A page that says "no such user" for one and "wrong password" for another is an enumeration
  oracle with a friendly tone. `E-50115` is the single exception, and only because it is raised
  *after* the credential has been verified, at which point the caller already knows the password.
- **The two counts are independent and only one of them is a state change.** The per-account count
  crossing its threshold writes `IsLockedOut` and a `LockoutEndUtc` an administrator can see and
  clear; the per-address count crossing its threshold writes **nothing anywhere** — there is no table
  of addresses — so a throttle cannot become a denial of service that outlives its window.
- **`UI-27`/`BL-031`: never call these procedures inside an ambient transaction.** Each refusal path
  records the failure, commits, and re-raises. A caller holding a `TransactionScope` makes
  `XACT_STATE ()` non-zero, so the throw unwinds the *caller* and takes the committed failure record
  and the lockout increment with it — unlimited guesses, nothing in the trail. This is the single
  most consequential line in the gotchas workbook and it is a property of the client, not of the
  database.

### `database/112_auth_mfa_procedures.sql`

**The enrolment surface `110` assumes exists, and did not until 2026-09-20.** Four procedures:
`auth.uspEnrolMfaFactor`, `uspConfirmMfaFactor`, `uspIssueMfaRecoveryCodes`, `uspRotateMfaFactorKey`.
`T-112`, written the day `G-07` was decided, and **not in PLAN-AUTH-001** — the plan had `T-041` as an
environment task and assumed the procedures fell out of the decision. They do not.

**Why it is not part of `110`.** `110` answers "can this deployment sign anybody in". `112` answers
"can this deployment enrol anybody", and the second is by necessity reachable by a caller who has *not*
signed in — different question, different threat model, different file. Read `110` first anyway: `112`'s
whole bootstrap rests on a row `110` writes.

**The bootstrap paradox, which is the interesting part.** A user under a policy requiring a second
factor and holding none is refused `E-50109`. No session, so nothing to authorize an enrolment against,
so the account can never sign in — and that was a real state, not a hypothetical one: fixture user
`authtest.frank` was in it by construction and the Phase 2 test asserted, as a *passing* observation,
that nobody could get him out of it. The way out is the refusal itself. `auth.udfResolveEnrolmentActor`
accepts only an attempt the database refused for want of MFA, with the password verified, inside
`Authn.MfaEnrolmentWindowSeconds` — 900 by default. `uspCompleteLogin` writes `PasswordVerified = 1`
*before* it evaluates the MFA checks (`D-14`), which is precisely what makes a refusal usable as proof.

Four things worth knowing before reading it:

- **The window grants an identity, not a permission.** An account that already holds a confirmed factor
  is refused `E-50119` however valid the proof, so this is a route to a *first* factor only. Setting
  `Authn.MfaEnrolmentWindowSeconds` to `0` closes the route with no code change and no redeployment, and
  first factors become administrative. That is the operator's decision to make, and it is one setting.
- **It fails closed on the key label.** `@KeyReference` must equal `Authn.MfaKeyReferenceCurrent` or it
  is `E-50118`. A factor written under a label nobody holds any more is invisible until the day the old
  key is gone and every factor stops decrypting at once.
- **It never sees a key or a plaintext secret.** The application encrypts; this file stores bytes and a
  label. That is `G-07`'s decision, DES §6.4, and the reason nothing here can be tested end to end from
  T-SQL — the test passes random bytes, because the database cannot tell them from a real ciphertext.
- **Confirmation deliberately does not spend the time step.** `uspConfirmMfaFactor` leaves
  `LastUsedTimeStep` as `NULL`, so the code the user just typed still works for the sign-in they are
  about to attempt. Spending it would refuse the only code their authenticator is currently showing.

New error numbers `E-50117` to `E-50123`, and a third `logs.AuthenticationEvent` type,
`'MfaEnrolmentRefused'`. Verified by `_tests/040` section 12, eleven observations, in which `frank` enrols
from his own refusal, draws recovery codes, signs in, and is re-keyed onto a second key label and back.
`BL-034`; the defect that section found is `BL-035`.

### `database/115_seed_reference_data.sql`

**The reference data that is code rather than configuration**, and the file a project edits first. One
application, the root tenant and the external-organizations branch, **35 permissions in 7 categories, 14
baseline roles, 44 role-permission rows, 26 UI elements and 50 element-permission rows** — all of those
counts **per application**, because `auth.Permission` and `auth.Role` are `ApplicationId`-scoped under
`D-09`. `testTemplate` currently holds four registered applications, so a global `COUNT(*)` against these
tables is four times the seed and means nothing on its own.

Every section is a `MERGE`, and that is the point rather than a convenience: the file converges on a
populated database and **re-asserts the catalogue on every deployment**, so a permission somebody deleted
by hand comes back.

**Run `120_rls_policy.sql` after this file, always.** `120` resolves `Data.Read`'s permission id and
bakes the integer into the predicate functions; on an unseeded database it finds nothing, substitutes the
sentinel `-1`, and every predicate denies every non-maintenance session. Seeding the catalogue *without*
rebuilding the policy leaves the predicates on the sentinel — fail-closed, which is the right direction
and a baffling experience (`UI-35`). The install manifest has them in that order at steps 27 and 36; a
hand-run does not, which is why the file says so in capitals.

**What it deliberately does not seed is the more interesting list.** `auth.TenantType` belongs to
`030_auth_tenant.sql`, because Phase 1 cannot build a tenant tree before the types exist and
`auth.Tenant`'s composite foreign key makes the `Root` row a structural prerequisite rather than reference
data (`BL-021`). `config.TenantScopedTable` belongs to `025`, because `120` reads that registry on every
deployment including one where this file has not run. **Most of `config.ApplicationSetting` belongs to
`025`** — the twenty-three authentication, authorization and registration tunables, because `110`,
`112` and `155` read them and install long before this file; §6 here adds only the four settings whose
consumers arrived in Phases 5 and 6, with deliberately zero overlap, because **a setting seeded in two
places is a setting with two defaults** (`BL-050`). Twenty-eight keys live in the deployed database:
twenty-three from `025`, four from here and the probe burst count from `175_perf_instrumentation.sql`,
which owns the one key that is meaningless without the code in that file to read it. Four artefacts
said "eighteen" and "three" until 2026-09-21, two revisions after it stopped being true (`BL-072`);
the counts above were **measured** against `config.ApplicationSetting` rather than carried forward. And no user, profile, credential or grant: that is `900`, once.

**The root tenant moved here from `900`, and the reason is a foreign key.** DES §16.3 originally
attributed it to the bootstrap, but the baseline roles are owned by the root tenant (`INV-04`, so they
are assignable anywhere), `auth.Role.OwnerTenantId` is `NOT NULL` with a composite key, and `900` grants
five roles *by code* (`E-50087`). So the roles cannot exist before the root tenant and `900` cannot run
before the roles. This file creates it and `900` asserts it. `900` still owns the root tenant's
**authentication policy**, which is a bootstrap decision — the password rules for the first administrator
— and not reference data. `BL-051`, `G-25`.

The six seed identifiers (`@AppCode`, `@RootCode`, `@ExtCode` and their names) are **`DECLARE`d literals,
not sqlcmd variables**, and a project is expected to change them. A `:setvar` in the file *overrides*
`-v` rather than defaulting for its absence (measured on sqlcmd 17, the same mechanism behind `UI-41`),
so a defaultable sqlcmd variable does not exist; making six of them mandatory would mean the installer
could not call this file without six more arguments.

### `database/120_rls_policy.sql`

The row-level security policy: one filter predicate and three block predicates on every table
registered in `config.TenantScopedTable`, built at deploy time by
`auth.uspRebuildTenantAccessPolicy`. It installs at **step 36 of thirty-nine**, after every script that
creates or alters anything the policy binds — and after `180_dbo_application_procedures.sql`, which is
why there is a documented one-step window in which the demo procedures enforce authorization and
nothing else.

**After this file has run, a connection that has not called `auth.uspSetSessionContext` sees nothing in
the registered tables. That includes `db_owner`. That includes the person deploying.** Read the file's
section 5 demonstration before deciding it is a bug — this is `UI-18`, and it was the design's
prediction until Phase 4 measured it.

**It re-creates the predicate functions `100_auth_functions.sql` already contains, and the two forms
are both correct.** `100` holds the *reference* form, which joins `auth.Permission` and compares
`PermissionCode = N'Data.Read'`: readable, published in design §10.2, and one extra join per row per
query on the hot path of every `SELECT` against every tenant-scoped table, forever. This file holds the
*deployed* form, with the join replaced by `pps.PermissionId IN (17, 84, 152)`. **The list is a list**,
because `auth.Permission` is keyed on `(ApplicationId, PermissionCode)` — a single scalar id, which is
the obvious first draft, silently protects one application and silently denies the rest. `BL-039`.

**The price is staleness and it is paid in the open.** A literal cannot notice a new application, so
anything that changes the catalogue must re-run this file, and its closing report compares the literals
embedded in the deployed definitions against the catalogue as it stands and **fails the file if they
differ** — which makes running it the diagnosis as well as the fix. This is `UI-35`, and it is the only
`Critical` gotcha added since Phase 2.

**With no catalogue at all the list is the sentinel `-1` and every non-bypass session is denied.** That
was the state of the dev database through Phases 4 and 5, because the permission rows arrive in
`115_seed_reference_data.sql` — which is why `115` installs at step 27 and this file at 36. It fails
closed and loudly; the report says so at severity 3. The alternative, omitting the `IN` clause when the
list is empty, would turn an unseeded database into one where every profile reads every tenant, which is
the failure this file exists to prevent. **Seed order and rebuild order are one instruction, not two:**
run `115`, then run this file, or the predicates keep the sentinel and every screen is empty.

It is the file that uses **dynamic SQL**, and for a reason a template cannot avoid: which tables are
registered, which column carries the tenant, and which ids exist are all *data*. A hand-written
`CREATE SECURITY POLICY` would have to be edited by every project that adds a table, and the one thing
a template must not require is editing the security layer to add a table. The generated statements are
captured in `@DynamicSql`, so a failure records the exact text that failed. A registered table a
project has not created yet is **skipped and counted**, not fatal — severity 2, visible and not
blocking.

### `database/125_auth_tenant_procedures.sql`

The five tenancy procedures: `uspRebuildTenantClosure`, `uspCreateTenant`, `uspUpdateTenant`,
`uspDeactivateTenant` and `uspGetTenantTree`.

**All five install today; only the first can be called.** The other four reference
`auth.uspSetSessionContext` and `auth.uspDemandPermission`, which arrive in Phases 2 and 3, so
deferred name resolution lets them install now and a call before then fails with 2812. A conditional
`IF OBJECT_ID (…)` gate around the permission demands was **rejected**: a permission check that is
skipped when its dependency is absent becomes a permission check that is skipped, which is finding
`F-07`'s shape. `uspRebuildTenantClosure` takes no session token and demands nothing, which is why
it is callable and why the Phase 1 fixtures use it.

The rebuild is parameterless and whole-table — a recursive CTE into one `MERGE`, in one transaction,
under `OPTION (MAXRECURSION 100)`, with no hard delete anywhere. A few thousand rows in
milliseconds, trivially correct, and correct after a re-parenting, which an incremental version is
not. `G-09` carries the performance question to Phase 5 should a tree ever grow ten times.

### `database/130_auth_user_procedures.sql`

The person-record surface: `auth.uspCreateUser`, `uspUpdateUser`, `uspDeactivateUser`, `uspGetUser`,
`uspSearchUsers`. **Nothing here touches a credential.** A user created by this file can be looked up and
given a profile and still cannot sign in — `auth.UserCredential`, `UserFederatedIdentity` and
`UserMfaFactor` are written by `110` and `112` from a verifier the *application* computed (`D-08`), and no
procedure in this file accepts a password, a verifier, a salt or a token. That is the correct order: the
person record and the means of proving you are that person are two facts with two lifecycles.

**`uspUpdateUser` deliberately does not expose `MustChangePassword`, `IsLockedOut` or `LockoutEndUtc`.**
Those belong to the authentication machinery. A `User.Update` holder who could clear `IsLockedOut` by hand
could undo a lockout without the window ever expiring, which is the whole throttle (DES §7.4). Forcing a
reset is `User.ResetCredential` in `110`, not `User.Update`.

**`User.Create` is demanded at the actor's own acting tenant, not at a target**, because a user has no
`TenantId` and so there is no target to demand it at. DES §11.4 calls this "deliberately weaker" in so
many words: anyone holding `User.Create` anywhere may create a person record, because a person with no
profile has access to nothing. Giving them a profile is `Authz.ProfileCreate` in `140`, and *that* is
scoped exactly like `Authz.RoleAssign`. The consequence is real and recorded rather than hidden — a county
administrator can see and rename a person with no profile in their county at all — which is `G-27`, whose
mitigation is that the person record holds a display name, a user name and an email and nothing else of
interest.

Every reference to the table is **`auth.[User]`, with the brackets**, and it is not a style choice: `USER`
is the niladic function, so `FROM auth.User AS u` is Msg 156 at `CREATE` time. This is the first file
whose procedures read and write the table directly, so it is the first place it bites. `UI-41`.

### `database/135_audit_triggers.sql`

**This script creates nothing, and the inversion is the whole point.** The plan asked for a script that
*generates* the `AFTER UPDATE` audit triggers; it asserts they already exist and **fails the deployment**
if one is missing, misnamed, disabled, or not maintaining the audit block (`E-50210`, `E-50211`).

The reason is that **the triggers are not interchangeable.** They share a shape, but each also enforces
its own table's immutability rules, and those are facts about the table rather than about the convention:
`dbo.trg_au_updt_CaseFile` refuses a change to `TenantId` (`E-50011`) and to `ApprovedByProfileId` once
set (`E-50010`); `auth.trg_au_updt_Role` refuses anything `INV-10` forbids on a system role (`E-50012`).
A generator reading `sys.columns` would either omit those rules or invent them — wrong while looking right
— and would have to `CREATE OR ALTER` over the hand-written triggers on every deployment, so the rules
would survive exactly until the next build. So the trigger ships in the same file as its table (`BL-022`),
and this file's job is to make that convention **enforceable**.

The scope is `auth`, `config`, `dbo`, `logs` and `util`: **37 tables, of which 36 must carry a
`trg_au_updt_` trigger, and 36 do** — re-measured 2026-09-21, when `auth.RegistrationAttempt` and
`auth.TenantTrustedIssuer` took the counts up from 35 and 34 without any change to this script, which is
the only evidence that matters for a script whose whole claim is that it enumerates rather than lists.
Whole-database totals are 41 tables and 36 triggers; the five without
one are `history.DdlChange`, `history.DdlObjectState`, `logsData.DdlChange`, `logsData.DdlObjectState` —
all outside the asserted schemas — and `logs.ExecutionLog`, which is inside it and **exempt by a row in an
`@Exempt` table carrying its reason.** That reason is worth reading: `logs.ExecutionLog` has a single
writer, so a trigger on it would fire inside every procedure's Rule 8 instrumentation *including the
`CATCH` block*, where an error it raised would **replace the error being reported**. An exemption held as
data with a stated reason is auditable; an exemption held as an omission is a missing trigger.

Why it is the second-to-last manifest step (38 of 39) follows from what it asserts: it needs every table
script to have run. It is the only script in the manifest that can fail a deployment for something no
other script would notice, because **a missing audit trigger is otherwise invisible** — the table works,
nothing errors, and its audit columns quietly stop being maintained. That defect is discovered by somebody
asking who changed a row and finding that nothing knows.

### `database/140_auth_profile_procedures.sql`

Six procedures: `auth.uspCreateProfile`, `uspUpdateProfile`, `uspDeactivateProfile`,
`uspListProfilesForUser`, **`uspSwitchProfile`** and `uspGrantTenantDefaultRoles`. This is where
`Authz.ProfileCreate` gets the scoping that `130` deliberately does not have — demanded **at the target
tenant**, exactly like `Authz.RoleAssign` — because a profile is the thing that confers access.

**`auth.uspSwitchProfile` is one of the three M4 contract procedures and the one with the trap in it.**
It deliberately does **not** re-establish the session context, because `sp_set_session_context
@read_only = 1` cannot be set twice on a connection: the engine raises 15664 and the procedure surfaces
it as `E-50022`. So **the connection that switched profile is spent** and the caller must open a new one
— which is why a sign-in costs two connections, and why `UI-36` decides the UI's connection handling
before it writes any data-access code. `G-36`, `BL-057`, UIH-AUTH-001 §4.3 and §5.

**`auth.uspGrantTenantDefaultRoles` (§6) resolves the tenant-default-role rule, and nothing else may.** It
walks the ancestor chain, grants the resolved set, and writes one `RoleGranted` trail row per role. It was
**extracted from `auth.uspCreateProfile` rather than written fresh**, because
`155_auth_registration_procedures.sql` needs the same rule on a path where nobody is authenticated — and
two implementations of an inheritance rule is the shape of defect that shows up as "new users in this
county get different roles depending on how they were created." It is an **internal helper**:
`applicationRole` has no `EXECUTE` on it, asserted by this file's closing report. It deliberately does
**not** rebuild the permission scope, because its callers do that once at the end rather than once per
role. `BL-056`, DES §11.5.

It is manifest step 30 and has a **run-time** dependency on `150` at step 34 — `auth.uspDemandPermission`.
That inversion survives only because of an `OBJECT_ID` guard, and it is one of the two orderings in the
manifest that is not enforced by a hard failure at install time. Worth knowing before reordering anything.

### `database/145_auth_role_procedures.sql`

Role definition and grant, six procedures: `auth.uspDefineRole`, `uspUpdateRole`,
**`uspSetRolePermissions`**, `uspAssignRoleToProfile`, `uspRevokeRoleFromProfile` and
`uspListAssignableRoles`. The permission list is set **as a set** rather than added and removed one at a
time, which is why there is one procedure where a reader expects two: a role's permission list is a
single fact, and a caller that sends the whole list cannot leave the role half-edited by failing between
two calls.

**This is the file where `P-02` is either honoured or broken**, and it is honoured by omission: no
procedure here accepts a role *name* as a behavioural input. Roles are delegable to each organization, so
a screen that needed a particular role name would have broken the model. The permission code is the
interface; the role is a bag of them that a tenant may define in any order.

`INV-10` lands here as `E-50012`: a **system** role's code and its permission set are not editable, because
`115` re-asserts them on every deployment and `900` grants five of them by code. An edit that survived
until the next install is worse than an edit refused now.

**Every mutation writes a trail row through `logs.uspRecordAuthorizationChange`**, and the six verbs
are the file's real interface: `RoleCreated`, `RoleModified`, `RolePermissionAdded`,
`RolePermissionRemoved`, `RoleGranted`, `RoleRevoked`. `uspSetRolePermissions` writes *added* and
*removed* rows for the diff rather than one "changed" row, because the question asked afterwards is
always which permission appeared and when.

Every grant, revoke and permission change **rebuilds the affected profile's permission scope** via
`auth.uspRebuildProfilePermissionScope` — which is where `G-39` bites: that procedure is **224× cheaper**
called once for 5,000 profiles (181 ms) than 1,000 times for one profile each (40,555 ms). A bulk caller
that loops is not slightly slow, it is two orders of magnitude slow. PERF-AUTH-001 §5.2.

`G-33` is visible in this file's own extended properties: **a role may not be re-owned**, because
re-owning it would silently rewiden or invalidate every grant it already holds (`trg_au_updt_Role`,
`E-50010`).

### `database/150_auth_query_procedures.sql`

**Complete since Phase 6: all four procedures.** `auth.uspDemandPermission` came first, in Phase 3,
because nothing else can be finished without it — five procedures in `125` already reference it and fail
at call time with `Msg 2812` until this file runs. `auth.uspGetProfileContext`,
`auth.uspGetNavigationForProfile` and `auth.uspCheckPermission` arrived with the UI surface at `T-092`.
All three are in the M4 contract, and `uspGetNavigationForProfile` is the one the UI project should read
first: it answers *which elements may this profile see*, by element **code** and never by role name,
which is `UI-02`.

It installs at **step 34**, late, after `155` and `160` — and `140_auth_profile_procedures.sql`, at step
30, **calls it at run time**, because `auth.uspSwitchProfile` returns the new navigation in the same
round trip. That is safe only because the call site is wrapped in an `OBJECT_ID` guard: a deployment
stopping between the two gets a switch that returns one result set short rather than one that throws.
**Do not remove the guard to tidy it up.**

`auth.uspDemandPermission` also carries the **sampled probe** added in Phase 5 for `G-22` — a block
`175_perf_instrumentation.sql` checks for by reading `sys.sql_modules`, and the reason `175` installs
after this file. The probe's configuration read costs **5 logical reads against the demand's own 12** —
42%, and only 18% if you measure in microseconds, which `PERF-AUTH-001` §1 tells you not to. That ratio
is why the probe is **sampled** rather than unconditional, and why `175` is optional (§3.3).

**It throws rather than returning a verdict**, and that is the whole design of §9's steps 5 and 6.
Step 5 produces a clean, catchable `E-50030` the UI can render as "you do not have permission to update
this case"; step 6 — row-level security — is the guarantee that a procedure which *forgot* step 5 still
cannot touch another tenant's rows. A procedure returning a bit would make the caller responsible for
checking it, and a caller that forgets to check a return value has silently skipped the entire
permission model, which is finding `F-07`'s shape. The non-throwing form is a separate procedure
(`T-085`) whose only purpose is deciding whether to render a button, and keeping them apart is what
lets the demand be unconditional.

**Two error numbers, and the order they are decided in matters.** `E-50030` is "denied"; `E-50031` is
"there is no such permission code in this application". Both are raised only *after* the denial is
recorded, because a code that does not exist is the single most useful row `logs.AuthorizationDenial`
can hold — it means a procedure asks for a permission nobody can ever hold, so the feature it guards is
dead and no test noticed. Deciding the number first would have been the natural shape and would have
lost exactly that row.

**A demand with no session context is a denial, not a different error.** `auth.udfHasPermission` reads
`SESSION_CONTEXT` itself and returns 0 when it is absent, so the caller is refused with `E-50030` and a
denial row whose `UserProfileId` is `NULL`. That `NULL` is the finding: a procedure is reachable without
session context, which is worse than any individual permission failure. Raising `E-50020` instead was
rejected — the `5002x` range signs the user out, and signing them out would hide a server-side defect
behind a plausible re-authentication.

The limitation is stated rather than papered over: called inside a caller's open transaction, the
rollback the denial provokes takes the trail row with it. The design's answer is the call *order* —
authorize at step 5, before the transaction opens at step 6 — and every procedure in this database
follows it. `BL-042`, and the new §9.3.

### `database/155_auth_registration_procedures.sql`

`auth.uspRegisterOrganization`, `auth.uspApproveOrganization`, `auth.uspRegisterExternalUser` — the
Variant 3 onboarding path. **Two of the three have no session, and that is the whole difficulty.** Every
other writing procedure in this database opens with `auth.uspSetSessionContext` and then demands a
permission; these two cannot, because the caller either has no account or is in the act of creating one.
So something else has to be the authority, and in each case **it is a row**:

- `uspRegisterOrganization` needs no authority **because it creates none** — one
  `auth.OrganizationRegistration` row at `Pending` and nothing else. No tenant, no user, no profile, no
  grant. Nobody can sign in as a result of calling it.
- `uspApproveOrganization` is fully authenticated, demands `Tenant.Create`, and is **the only step in the
  path that creates a tenant**. DES §16.4 calls the human gate deliberate.
- `uspRegisterExternalUser`'s authority is **an approved registration row naming a usable tenant**. An
  agency user already decided by hand that people from that organization may enrol; this procedure enrols
  one and grants only what that tenant's default role set gives — through
  `auth.uspGrantTenantDefaultRoles`, which is why that helper was extracted from `uspCreateProfile`
  (`BL-056`).

**The trust boundary is therefore not "is this caller authorized" but "has a human already approved this
organization".** Everything the unauthenticated paths can do was decided in advance by somebody who was
authenticated. That is the sentence to keep if the rest of the file is forgotten.

**There is no rate limiting here, on purpose.** A database procedure cannot tell a flood from a busy
morning without knowing things only the web tier has — the source, the cookie, the CAPTCHA result, the WAF
verdict — and a limit implemented here would be both ineffective (an attacker varies the proposed code) and
harmful (it would refuse a legitimate registrant *during* an attack). What the file does instead is make a
flood **cheap and visible**: a pending registration is one row that creates no authority, and
`ClientAddress` is captured so a burst from one source is a query away. The two halves of the remaining
work are `G-24` (a database-side counter, still an open decision) and `G-06` (the edge), and `G-06` still
blocks Variant 3 go-live because a throttle behind an unlimited public form is a throttle an attacker pays
once per address.

### `database/160_auth_admin_procedures.sql`

`auth.uspGrantPlatformAdmin`, `uspRevokePlatformAdmin`, `uspRebuildEffectivePermissions`,
`uspRebuildSecurityCache`. **These four are the only procedures in the database whose subject is the
database itself** — who may use the administrator sign-in route at all, and the two pieces of derived state
the whole model reads (`auth.TenantClosure` and `auth.ProfilePermissionScope`). None of their permissions
is tenant-scoped, which is why none of them passes `@TenantId` to `auth.uspDemandPermission`.

**The platform-admin flag is a pair of procedures rather than a column on `uspUpdateUser`, and that is
`D-05`.** Platform administration is an *authentication* capability, not a role: it decides which sign-in
routes exist for an account, and a platform administrator with no profile can sign in and do nothing at
all. `INV-09` then requires the flag **on top of** the `PLATFORM_ADMIN` role before any `Platform`
permission takes effect. So `130` refuses `@IsPlatformAdmin = 1` outright (`E-50155`) and `uspUpdateUser`
has no such parameter. The payoff: **every conferral of the capability in the deployment's entire history is
one `logs.AuthorizationChange` row**, `PlatformAdminGranted` or `PlatformAdminRevoked`, written here, so
"who can use the bypass route, and who let them" is one query. Folding the bit into `User.Create` would have
meant anybody who may create a person may create an administrator.

**The actor must already hold the flag, and that test comes *before* the permission test — `E-50084`.**
Holding `Platform.ManageApplications` is explicitly not sufficient. The ordering is not redundancy for its
own sake: `auth.udfHasPermission` already tests `IsPlatformAdmin` for the `Platform` family, so a caller
without the flag would be refused anyway — with `E-50030`, "you do not hold
`Platform.ManageApplications`", which is **the wrong sentence**. They may well hold it. What they do not
have is the flag. Checking first buys a true message; checking at all buys independence from
`udfHasPermission`'s internals, which is worth having for the one capability that can lock a deployment
out of itself. The revoke raises `E-50084` too, which is a **documented widening** of Appendix B rather
than a drift — Appendix B registered it against the grant alone, and the file says so where it happens.

### `database/165_logs_procedures.sql`

The three recorders for the three authorization trails: `logs.uspRecordAuthorizationChange`,
`logs.uspRecordAuthorizationDenial` and `logs.uspRecordDataChange` — **every path by which a row
reaches** `logs.AuthorizationChange`, `logs.AuthorizationDenial` or `logs.DataChangeLog`. It installs
**before** `150`, out of numeric order, and this one is not cosmetic: `150` asserts
`logs.uspRecordAuthorizationDenial` and throws without it.

**These three are fully instrumented, and a logging procedure that logs itself is not a
contradiction.** Rule 8 exempts exactly five procedures and all five are the `logs.ExecutionLog` chain
itself. These write the *authorization* trails, which is ordinary work that happens to land in the
`logs` schema. The recursion worry has a short answer: their instrumentation writes
`logs.ExecutionLog` through a procedure that is exempt and calls nothing, so the chain is two deep and
terminates. The cost is accepted, because the alternative is that when the trail stops for a day
nothing says whether it was never called, called and refused, or called and rolled back — which is the
question these tables exist to answer *about other procedures*.

**A trail row written inside the caller's transaction lives or dies with it.** For
`logs.AuthorizationChange` and `logs.DataChangeLog` that is exactly right: a grant that did not commit
must not appear in the trail as though it did. For `logs.AuthorizationDenial` it is a genuine
limitation, and the accumulate-and-flush-from-the-`CATCH` pattern cannot rescue it — the rollback is
the *caller's*, `SET XACT_ABORT ON` dooms that transaction, and an insert in a doomed transaction fails
too (`Msg 3930`). `BL-042` records it as an accepted limitation rather than hiding it behind a loopback
connection.

**The recorders throw on a malformed row rather than swallowing it** — `E-50130` to `E-50135`, a new
range in Appendix B. Every one is a defect in the *calling* procedure, and every one would be refused by
a `CHECK` constraint microseconds later anyway, so the choice is not between throwing and succeeding but
between a number the caller can branch on and a constraint name in a `547` message. Swallowing was
rejected: a recorder that returns success after discarding the row produces a trail that looks complete
and is not, which is `F-07`'s shape applied to auditing.

### `database/170_permissions.sql`

**The permission model for the whole database, and the last step of the installer.** It creates no
object and grants or denies on every one of the seven user schemas — `auth`, `config`, `dbo`,
`history`, `logs`, `logsData`, `util` — for all four roles. Written for `G-19`, whose finding was not
that a permission was wrong but that **an absence cannot be noticed**: a grant written beside its own
object can never observe that a schema nobody thought about has neither a grant nor a deny.

Three things in it were **measured** before it was written, on this server, because the documentation
does not settle them — `BL-028`:

1. A `DENY` on a table does **not** stop a procedure that reads it. Ownership chaining never consults
   the permission. This is what makes `INV-11` affordable.
2. A `DENY` at schema level **beats** a `GRANT` at object level — so the familiar column-level
   exception does not generalise, and a blanket `DENY EXECUTE ON SCHEMA::util` killed an
   already-granted `util.uspPhase0Probe`. That is why the `util` section denies the four table verbs
   and leaves `EXECUTE` alone.
3. A four-verb `DENY` on `SCHEMA::auth` leaves every authentication procedure working while refusing
   a direct read with 229 — re-verified against the shipped state as a real `applicationRole` member,
   not against a probe's own temporary deny. So `INV-11` is now **enforced** rather than satisfied.

It **asserts** the four roles rather than guarding on them, which inverts `005_schemas_and_roles.sql`'s
convention deliberately: a permission run that skipped half its work and reported success is the exact
failure `G-19` describes. And it departs from `G-19`'s own proposed resolution in one place, on the
record: `SCHEMA::config` is granted `SELECT` to both roles as proposed, and then
`config.ApplicationSetting` is denied to both, because it holds the dummy-verifier pepper and design
§19.2 outweighs the convenience. The named extension point is a filtered view over the non-sensitive
settings, deliberately not built until something needs it.

**One half of `G-19` remains open**: the deployment-time assertion that every schema appears in the
report with either a grant or a stated deny belongs in `950_verify_deployment.sql`, which is Phase 8
and does not exist. The query is written and working as this file's section 5a, so the Phase 8 task is
to move it rather than to invent it — `BL-029`. Until then an ad-hoc `REVOKE` after deployment is
caught by nothing, and the installer's footer says so.

**Phase 4 found the counterpart hole in the `logs` schema, and Phase 7 found that the fix for it was the
wrong shape. Read the two together; separately, each is half a lesson.**

`085_logs_auth_tables.sql` correctly said nothing is granted on the four audit trails. The conventions'
own `permissions.sql` grants `SELECT`, `INSERT`, `UPDATE` and `DELETE` on `SCHEMA::logs` to
`applicationRole`. **Both statements were true**, and together they left `logs.AuthenticationEvent`,
`logs.AuthorizationChange`, `logs.AuthorizationDenial` and `logs.DataChangeLog` directly writable by the
application login — so a compromised login could forge or erase the record of what it did. Phase 4 issued
object-level `DENY INSERT, UPDATE, DELETE` on all four, verified by impersonation in both directions: a
direct `UPDATE` as an `applicationRole` member fails with `229`, and the same write inside
`auth.uspRecordLoginFailure` still succeeds through ownership chaining. It was **narrowed, not revoked** —
the schema grant stays because it is the conventions script's, `SELECT` stays because nothing is leaked by
reading a trail you could have written, and `logs.ExecutionLog` stays writable because the framework writes
it from the application side. `BL-048`.

That fix closed the hole and opened `G-23`, which said in writing that **the schema grant is *inherited* and
the denies were *enumerated*, so the fifth `logs` table anybody added would repeat the hole and this file's
report would still say 12 of 12 OK.** `G-23` was right. `175_perf_instrumentation.sql` added
`logs.PermissionProbe` in Phase 5; its own banner claims "not granted to `applicationRole`; reached by
ownership chaining"; and measured as deployed, `HAS_PERMS_BY_NAME` returned **1, 1, 1** for `INSERT`,
`UPDATE` and `DELETE` on it to an `applicationRole` member while the four trails returned **0, 0, 0**. It
was writable for the whole of Phases 5, 6 and 7, and `170` printed "no problems found" every time, because
section 6e asserted the same four names section 4 denied: **the two agreed with each other and neither
agreed with the database.** `D-07` is taken on that table's contents, so a table the application can insert
rows into is a decision nobody can audit — which is the sentence `BL-048` wrote about the trails.

**It is closed by inverting both halves, not by adding a fifth name.** Section 4 now enumerates
`sys.tables` in `logs`, subtracts a `#LogsWriteExempt` list holding `logs.ExecutionLog` *with its reason*,
and issues the denies through `sp_executesql`; section 6e enumerates the same way and reports
`EXEMPT`-with-reason, `OK` or `VIOLATED` per table, **plus a count row**, because an enumeration over an
empty set is `BL-064`'s assertion-that-cannot-fail wearing different clothes. The exemption is a `#temp`
table rather than a `@table` variable for one reason: section 6e has to read the same list across a `GO`,
and declaring it twice would put the exemption in two places, which is the defect being repaired. Verified
by re-running the file (`EXIT=0`, five tables denied, one `EXEMPT`) and by impersonating a fresh
`applicationRole` member — probe writes now `0`, `SELECT` still `1`, `logs.ExecutionLog` `INSERT` still `1`.
`BL-066`.

**The generalisation is the reason this subsection is long.** `G-23` was filed, the warning was printed in
this file's own transcript in plain words, the resolution was written down — and the hole recurred anyway,
in a file whose author had read all of it. **A warning in a report is not a control**, because it asks a
future reader to act at a moment nobody can name, and the person who created `logs.PermissionProbe` was not
reading `170`. What works is a control that needs no reader: derive the governed set from the catalog and
hold the exemptions as data, so a new member of the set is governed by default and an exception has to be
written down to exist. That is now the third instance of the same move — `G-19` for schemas,
`135_audit_triggers.sql` for triggers, `G-23` for `logs` tables — which makes it a **rule of this
codebase**: where a control covers a set that can grow, enumerate the catalog and hold the exemptions as
rows.

**One script is still unwritten**, and it is the only one: `950_verify_deployment.sql` (`T-104`), which
`BL-029` owes section 6a's schema query and `G-37` owes its durable half.

### `database/175_perf_instrumentation.sql`

`logs.PermissionProbe`, three procedures over it (`uspRecordPermissionProbe`, `uspPurgePermissionProbe`,
`uspReportPermissionProbe`), `logs.vwPredicateFunctionStats`, and a shipped extended-events definition.
**Written to close `G-22`**, whose complaint was that the one component running on every single query was
the one component that reported nothing about itself, because a function cannot write to a table and a
per-row predicate must not try.

**The probe writes from the procedure and never from a function**, which is the constraint that decided the
whole design. `auth.uspDemandPermission` carries a sample gate: one call in N records the decision, the
elapsed time of a burst of that decision, the profile and the acting tenant. `Perf.PermissionProbeSampleRate`
ships at **0** — off — with `Perf.PermissionProbeRetentionDays` and `Perf.PermissionProbeBurstCount`
alongside it. **The caller does the timing, not the recorder**: the burst has to happen around the decision
the caller is already making, and moving the loop inside would have put a measurement procedure in the
authorization call graph.

**`logs.vwPredicateFunctionStats` is the most useful thing in the file, and the reason is a trap.** An
**inlined scalar function disappears from `sys.dm_exec_function_stats` entirely**, and inline table-valued
functions never appear in it at all. A naive query over that DMV therefore reports the authorization hot
path as *never called* — indistinguishable from a predicate that is not bound, which is the exact failure
anybody consulting it is trying to rule out. So the view lists all six functions the security design depends
on from a `VALUES` constructor and **`LEFT JOIN`s** the DMV: a function with no statistics becomes a row
saying so rather than an absence.

The extended-events session is **shipped as a `CREATE EVENT SESSION` statement in §8 and not created by the
install**, because a deployment that quietly creates a server-level XE session reads as a broken deployment.

**The probe's own cost was measured rather than assumed**, which is what justifies sampling at all: the
configuration read alone is **5 logical reads against the demand procedure's own 12 — 42%**. (It is 18% in
microseconds, and PERF-AUTH-001 §1 says not to argue from microseconds.) An unconditional probe would have
made that the headline instead of a footnote. `BL-059`, PERF-AUTH-001 §3.3, DES §10.6.

`logs.PermissionProbe` is append-only at the trigger (`E-50010`) for a stated reason: `D-07` is taken on
this table's contents, so a table anybody can tidy is a decision nobody can audit. **Only `IsDeleted` may
change, and `uspPurgePermissionProbe` is what changes it.** The table's own banner claimed it was "not
granted to `applicationRole`; reached by ownership chaining" — which was not true as deployed, and is the
subject of `BL-066` and the `170` subsection above.

### `database/180_dbo_application_procedures.sql`

Ten procedures over `dbo.CaseFile` and `dbo.CaseNote`. **What this file is for is not the case files.**
Nothing in this database needs a case file; the tables exist so the security model has something ordinary
to protect, and these procedures exist so a project has a worked example of every rule DES §14 states, in
the smallest domain that can carry all of them. **A project deletes both tables and both files and writes
its own. What it copies is the shape.**

So they are **deliberately dull**: no paging DSL, no dynamic `ORDER BY`, no `MERGE`, no table-valued
parameters, no optional-parameter catch-all `WHERE`. Every one of those is a legitimate technique and every
one would obscure the thing being demonstrated, which is **the order of the statements**:

1. `auth.uspSetSessionContext` — always first, never assumed (`UI-05`)
2. read the session's own values out of `SESSION_CONTEXT`
3. `auth.uspDemandPermission` — once per distinct authority, **before any transaction**
4. validate the arguments and the target row, and `THROW` a branchable number
5. `logs.uspStartExecutionLogging`
6. `BEGIN TRANSACTION`
7. the one or two statements that are the actual work, with `auditCreatedBy`/`auditModifiedBy` set explicitly
8. `logs.uspRecordDataChange` — the domain trail, **inside** the transaction
9. `COMMIT`, close the execution-log row; and in the `CATCH`: rollback, re-open the log row, record, rethrow

**Steps 3 and 4 in that order is the one decision here that is easy to get backwards.** Looking the row up
first and demanding afterwards turns "you may not do this" into "that row does not exist" for a caller who
was never entitled to know either way — and, worse, makes the error number depend on data rather than on
authority.

**There is no `@TenantId` parameter on any write, and that is `P-06` rather than an omission.** The tenant
comes from the session context; a parameter would be a second source of truth for the one fact the whole
row-security model rests on. `E-50200`–`E-50206` are this file's numbers.

It installs at **manifest step 35, before `120`**, which leaves a documented one-step window in which the
policy is unbound — the only such window in the manifest, and it is in the manifest comment rather than left
for a reader to notice.

### `database/900_bootstrap_first_admin.sql`

**The one script that is deliberately not idempotent.** It succeeds exactly once per database and raises
`E-50080` for ever afterwards. It creates the first user, their credential, their profile at the root tenant,
and grants five roles by code (`E-50087`); `115` creates the root tenant and this file **asserts** it, while
still owning the root tenant's *authentication policy*, which is a bootstrap decision rather than reference
data (`BL-051`, `G-25`).

**It is not a manifest step, on purpose.** The installer runs it once after the last pass and only when
`-BootstrapAdminVerifierPhc` is supplied. A deployment that silently created an administrator account would
be a deployment nobody could describe afterwards.

**Five of its six variables go through the process environment and not through `-v`, and both reasons were
measured the hard way** — this is where `UI-41` and `UI-42` come from:

1. **A `-v` value cannot contain a space.** Not with double quotes, not backslash-escaped, not as a
   pre-quoted argv from PowerShell or bash. sqlcmd reports `'AdminDisplayName=First Administrator': Invalid
   argument` and exits. A display name with a space in it is not an exotic input.
2. **sqlcmd resolves a scripting variable from `-v` first and from the process environment second.** So an
   environment variable carries spaces, commas, equals signs and the several `$` characters of a PHC string
   through untouched — and a **leftover `-v` silently wins over an exported variable**, which is the half of
   `UI-42` that bites during debugging.

`DbName` therefore stays on the command line where every other script expects it, and the five values that
can contain anything go through the environment. `Install-TemplateDatabase.ps1` does the same, at lines
448–452, and removes `$env:AdminVerifierPhc` on the way out.

A standing caution in the file: **a PHC string contains `$` characters**, and sqlcmd substitutes only `$`
followed by `(`. An argon2id PHC string has no parentheses so it passes through unexpanded — but a credential
format that ever did contain one would be silently corrupted, and the validation in §1a would not catch it.

`G-42` was the gap this file made visible, and it is **closed**: `auth.UserCredential` was written by this
script for one account and by nothing else, so there was no `uspSetPassword` or `uspChangePassword` for the
UI to call. `110_auth_authn_procedures.sql` now carries four procedures — `uspSetPassword`,
`uspGetPasswordChangeContext`, `uspChangePassword` and `uspExpireCredentials` — and `G-12` (credential
expiry), which was ordered behind it because there was no procedure for a password to expire *into*, closed
in the same pass. What this file still demonstrates is the shape those procedures had to keep: it computes
no hash, because `D-08` puts the hashing in the application, and `uspSetPassword` takes a finished PHC
string for exactly the same reason. The script remains the only route to the **first** administrator, and
deliberately not a manifest step.

### `database/_tests/010_phase0_instrumentation.sql`

The Phase 0 instrumentation probe. Creates `util.Phase0ProbeTarget` and `util.uspPhase0Probe` to
the conventions, then calls the procedure three ways — successfully, failing with no ambient
transaction, and failing inside a caller's open transaction — to prove that rule 8 records all
three. The third is the only placement that exercises the re-creation of a start row a rollback
destroyed, and it is visible in the result: `ReCreatedAfterRollback = 1`, with a gap in the identity
sequence where the lost row had been.

**Deliberately not in the install manifest.** It creates test fixtures, and a project cloning this
template should not inherit them. Run it by hand against a throwaway database. `T-111`.

### `database/_tests/020_tenancy_variant_trees.sql`

Builds the three variant tenant trees of DES §17 from script: `VARIANT1`, `VARIANT2` and `VARIANT3`,
three applications and 23 tenants between them, chosen so that all seven seeded tenant types are
exercised exactly once — which the file asserts, rather than leaving as a claim. `MERGE` throughout,
so it converges on a populated database.

It writes `auth.Tenant` directly rather than calling `auth.uspCreateTenant`. Two reasons, and the
second outlives the first: that procedure cannot be called before Phase 3, and the three **roots**
could never go through it in any case, because it refuses to create a root by design (50094, which is
`INV-02`).

### `database/_tests/030_tenancy_closure_reparent.sql`

The Phase 1 exit criterion that matters: the closure is correct after a **re-parenting**, not only
after a fresh build. It moves a populated subtree three times — one level deeper, to the root, and
back — and asserts after each move.

The middle move is the point. Re-rooting a subtree *replaces* ancestors rather than adding them, and
it retires four pairs, two of them for a grandchild nothing wrote to. An incremental algorithm gets
that case wrong, and the result looks well-formed: a scope grant at the old ancestor would still
reach a tenant no longer beneath it, with no symptom anywhere except in an authorization decision.
The round trip is identical to the baseline on `(ancestor, descendant, depth)`, and a second rebuild
is identical *including* `auditModifiedDateUtc` — which rules out a rebuild that rewrites every row
to the value it already held and destroys the audit trail on the way.

It also proves the rebuild fails **loudly**: a cycle raises 530, the single transaction's `CATCH`
leaves the previous closure whole rather than half-rebuilt, and the failure is recorded in
`logs.ExecutionLog` with `ReCreatedAfterRollback = 0`. A partially rebuilt closure is an
authorization table with rows missing.

**Run the two by hand, in either order, any number of times.** Each restores the shape the other
expects, which is deliberate: `020`'s `MERGE` restates every parent, so it puts back whatever `030`
moved, and `030` therefore never has to check whether it needs to move anything. A test that checks
whether it needs to do its work is a test that can report success without having done it.

**That claim was false for one pair of files until 2026-09-21, and the file now states the two rules
that make it true (`T-120`, `BL-074`).** `030` is ordered before `070` in the documented sequence, so
nobody had ever run it *after* `070` — and `070` does two things to the `VARIANT2` tree that `030` had
assumed nobody would. It adds two tenants, which broke four pair-count constants that had been
compared against every live pair in the application rather than against the nine tenants `020`
declares; the constants now measure a `@Declared` list, resolved nine-or-nothing so a short list
cannot quietly lower them. And it soft-deletes the organization tenant its previous run approved,
which matters because **`auth.vwTenantHierarchy` and `auth.TenantClosure` disagree about a
soft-deleted tenant on purpose** — the view drops it and its subtree, the closure keeps its pairs live
so `auth.udfIsTenantUsable` cannot fail open (`BL-020`) — and this file's load-bearing invariant
compares `SUM (Depth + 1)` over the view against `COUNT (*)` over the closure. Every count compared
against the view is now restricted to what the view can see. The result was seven `VIOLATED` rows on a
correct database, which is the worst thing a test can produce: a real report, in the right shape,
about nothing. `UI-45` was filed from the same finding, because a screen can be built on the same bad
assumption.

### `database/_tests/040_identity_and_authn.sql`

**Where the Phase 2 exit criteria are evidenced.** Builds its own fixture — one `AUTHTEST`
application, two tenants, a policy on the child only, six users, five credentials, one federated
link, one confirmed TOTP factor, four recovery codes — then runs 42 experiments and prints each as a
row with a severity, a status and the numbers it measured. It restates and resets its fixture on every
run and soft-deletes prior attempts and sessions, so it is re-runnable against a database it has
already been run against.

It reports against the criteria by name rather than leaving a reader to match assertions to a plan:
its closing roll-up counts how many observations exercised each exit criterion and how many failed.
Three sections are worth reading even if the test passes:

- **Section 12 is `frank`'s, end to end, and it is the newest.** He is refused `E-50109` in section 10b
  for want of a factor; section 12 takes that refusal, asserts `auth.udfResolveEnrolmentActor` returns
  his user id from it, enrols, re-sends, confirms, draws recovery codes, signs in, and re-keys onto a
  second key label and back — eleven observations covering every one of `E-50117` to `E-50123`. Until
  2026-09-20 this section was a `BLOCKED` row saying enrolment did not exist, and the file is worth
  reading for the change: the same numbering that recorded the lockout now records the way out.
- **What it still cannot test, stated in its own header.** Every `@SecretCiphertext` it passes is random
  bytes. A database test cannot tell a real ciphertext from noise, because the database holds no key —
  which is `G-07`'s decision working rather than a shortfall. `dave`'s factor is deliberately still
  inserted directly as `db_owner`, so the experiments that *consume* a factor cannot be disarmed by a
  defect in the ones that *create* one.
- **The `GAP` row for `G-21` is filed *because this test could not write an assertion*.** There is no
  trusted-issuer list, so nothing here can distinguish a wrong issuer from a right one.
- **Section 0 states a precondition about the harness itself:** nothing here wraps a procedure call in
  a transaction, and nothing may. `UI-27`.

### `database/_tests/050_authorization_and_session.sql`

**Where the Phase 3 exit criteria are evidenced.** Twenty-one observations came out as intended with
three notes and no failures, exit 0. Two criteria, and both could only be settled by experiment.

The first is `T-057`: does `auth.ProfilePermissionScope` equal the set derived from the live grants after
an **arbitrary** sequence of changes? Section 4 applies **fourteen mutations** and compares the
materialization against the set derived longhand from design §8.6 **in both directions after every one**
— `derived EXCEPT materialized` is authority a profile should have and does not (a false denial: the user
sees an empty screen and files a ticket reading "the system lost my data"), and the reverse is authority
it has and should not. Zero rows either way, fourteen times.

**The mutations are data and not fourteen copies of the same block**, and the reasoning is worth
borrowing: the comparison *is* the assertion, and fourteen hand-written copies of an assertion are
fourteen chances for one to be subtly weaker than the rest. One loop means the derived set is defined
exactly once, where a reviewer can check it against §8.6 line by line. **The sequence is deliberately not
tidy** — it revokes and re-grants, expires a grant that was already expired when it was made, edits a
role while two profiles hold it, retires a permission out from under a role, and deactivates a profile
and brings it back. "Arbitrary" in `T-057` means the result must not depend on the order, so the order is
chosen to be awkward.

The second is `T-058`, and **it is why section 5 has to be last.** The five identity keys are set
`@read_only = 1`, so a key cannot be re-set to a different value, cannot be re-set to the *same* value,
and cannot be set to `NULL` — `Msg 15664`, measured here. The moment section 5 succeeds this connection
is one fixture user wearing one profile for as long as it stays open, so no later experiment could set up
a different identity. A second call for the same profile returns silently with `UserProfileId` intact; a
second call for a *different* profile raises `E-50022` and changes nothing, which is the defence working
and is `UI-36`.

It also found two things the design had not written down. `BL-044`: the file tried to tag its own rows
through `auditDeletedBy` and watched the `AFTER UPDATE` trigger overwrite the tag — **the audit columns
are owned by the trigger, not the caller** (`UI-37`). And a revoked grant is **resurrected in place**
rather than re-inserted, because the filtered unique index refuses the duplicate with `Msg 2601`.

### `database/_tests/060_row_security.sql`

**Where the Phase 4 exit criteria are evidenced**, on live rows in two bound tables. Sixteen observations
as intended, three notes, no failures, exit 0. Its roll-up reports against the criteria by name: read in
scope and out 1/0, insert into the acting tenant and into others 3/0, update plus read-only row plus
tenant move 3/0, and `db_owner` with no context sees zero rows 1/0.

**It re-builds the policy before it tests anything, and that is the most transferable thing in the
file.** The predicates carry a literal list of permission ids, so a fixture that invents its own
`Data.Read` row and does not re-run the rebuild is testing a policy that has never heard of its
permissions — and **every assertion below would "pass" by denying everything.** Section 4 therefore execs
the rebuild after the fixture exists and prints the lists that ended up in the functions. This is exactly
the hazard a real project meets on the day it adds a permission: the catalogue changed, the policy did
not, and nothing complains. `UI-35`.

**And until 2026-09-21 that check could not have caught it (`T-121`, `BL-075`).** It looked for the
whole rendered id list inside the module definition with `CHARINDEX` — a list this file built with its
own `STRING_AGG`, in no stated order, and expected to match the one `120_rls_policy.sql` renders
ascending. Two `STRING_AGG` calls were being asked to agree on an order neither of them states. Once
the catalogue held six live `Data.Read` rows they stopped agreeing, and the file reported the policy
as **stale** while printing the fixture's own id inside the list it said was missing: the predicate
said `IN (1, 5, 26, 61, 96, 131)` and the test looked for `IN (61, 131, 96, 1, 5, 26)`. The false
alarm is not the worst of it — in that form the check could never have reported the case it exists
for, an id the predicate still enforces that is no longer a live permission. Section 4 now lifts the
list out of the definition and compares it against the live rows by `EXCEPT` in **both** directions,
with the fixture's own id asserted as a separate claim, because "the list is current" and "the list
contains the row the next twelve assertions depend on" are different statements. A rendered string was
the wrong instrument for a question about sets.

**The seeding needs the bypass key, and the file turns that into an assertion.** Once the policy is on,
`dbo` cannot insert into a tenant it is not acting for — that is the block predicate, and section 6 proves
it — so rows are planted with `BypassRowSecurity` set, and the key is cleared before a single assertion
runs. Section 5 *checks that it really is off*, because if it were left set every count below would be the
full count and the file would report a clean pass while proving nothing.

**Every refusal is expected by number, not merely as a failure.** `Msg 33504` is the block violation; a
refusal arriving as a check constraint, a foreign key or a permission error would be the right outcome
for the wrong reason and the matrix would be worthless. That discipline is what caught `BL-045`: the
tenant move in section 6g comes back as `Msg 547` because the composite foreign key breaks first, so
section 6g had to plant an *unassigned* case file to reach the block predicate at all.

Two further things it is worth knowing. **There is no delete predicate**, because this database has no
hard deletes — removal is an `UPDATE` and `BLOCK BEFORE UPDATE` governs it. A hard `DELETE` aimed at an
out-of-scope row would not be blocked; it would match nothing, because the filter has already hidden the
row. That is protection by *invisibility*, and it is worth knowing which of the two you are relying on.
And section 7 was **the first thing ever to reach the accepted path of
`auth.uspBeginMaintenanceSession`** — it creates a user `WITHOUT LOGIN`, puts it in `rlsBypassRole` and
impersonates it — which is how `BL-046` was found after the defect had survived two phases behind a probe
that could only reach the refusal branch.

### `database/_tests/070_variants_end_to_end.sql`

The Phase 6 exit criterion, executed: **all three variants of DES §17 built end to end through the
procedures.** `_tests/020` builds the three tenant *shapes* by writing `auth.Tenant` directly and says in
its own header that a later phase should switch to `auth.uspCreateTenant` because "that is a better test
than this one". This is that file. It takes one variant's skeleton and grows a whole working deployment on
it — catalogue, policy, an administrator, new tenants, users, profiles, role grants, self-service
registration and real case work — **using nothing but the shipped procedures once the irreducible bootstrap
is past.** All three variants **PASS**.

**One variant per run and four connections per run, and neither is a convenience.** `SESSION_CONTEXT` keys
are set with `@read_only = 1`, so they are fixed for the life of a connection; a second attempt raises
engine error 15664, which `auth.uspSetSessionContext` reports as `E-50022`. That is not a limitation of the
test, it is **the shape of the product: one connection may not serve two acting profiles** (`UI-06`,
`G-36`, `BL-057`). A test driving an administrator *and* a worker therefore cannot be one batch on one
connection — pretending otherwise would mean silently exercising whichever profile got there first — so the
file uses sqlcmd's `:connect` between stages, which is exactly what the application layer does between
requests.

**And signing in costs two connections, which this file learned by failing.** `auth.uspCompleteLogin` does
not choose a profile: it opens a session and nothing else, never mentions `IsDefault` and never sets session
context, so a freshly authenticated session is **profileless**. The acting hat is chosen afterwards by
`auth.uspSwitchProfile`, which establishes context — and therefore spends the connection it ran on. That is
the single most important fact in the file for anybody writing the UI, and it is why `UI-36` has to be read
before any data-access code is written.

**Run it with two switches or it does not run:** `-v Variant=VARIANT1|VARIANT2|VARIANT3`, and `-v Seed=`
**different on every run**, because the seed becomes a session token and a token is not reusable. Neither
value may contain a space (`UI-41`). It is otherwise idempotent — every write is a `MERGE` or an
existence-guarded call, and the case work is keyed on a case number derived from the variant.

### `database/_tests/080_error_catalogue.sql`

**Appendix B, executed.** A registry is a promise and nothing in it is a measurement; this file is the
measurement. Per number: put the database into the state the appendix says raises it, call the procedure the
appendix names, catch what comes out. **A probe passes when the number caught is the number promised, fails
when it differs, and fails just as loudly when nothing is raised at all** — because a registered refusal
that does not refuse is the worse of the two faults.

The ledger, measured three times and never recalculated: **122** numbers the shipped modules can throw,
**117** ever recorded, **96** raised on purpose by this file, **6** unobservable with a stated reason,
**none unaccounted** — 111/106/88 at v1.6, so the eleven numbers added on 2026-09-21 (`E-50068`,
`E-50097`, `E-50098`, `E-50124`, `E-50180`, `E-50220`–`E-50224`, `E-50230`) all became numbers something
actually raises, and the accounted-for list did not grow. Outside the
harvest: `50099`, plus the script-raised numbers `E-50080`/`50085`/`50086`/`50087` (from `900`) and
`E-50210`/`50211` (from `135`) — scripts are not modules, so they are not in `sys.sql_modules` to be
harvested.

**The harvest searches for `';THROW 5'` and not `'THROW 5'`, and that pickiness is the file's best idea.**
The looser pattern finds prose as well as code: this codebase's procedures explain their own refusals in
comment blocks that quote numbers, several of which the procedure does not raise. The leading semicolon is a
house convention — it protects the `THROW` from being parsed as a continuation of whatever preceded it — and
**no comment in this codebase writes one**. So the semicolon distinguishes a statement from a sentence about
a statement.

**A failed probe stops the run, and that is load-bearing rather than strict.** The file spans seven
connections and a table variable does not survive `:connect`, so each connection holds its own result table,
prints it, and throws. The coverage report is the *last* thing in the file and can only run if every
connection before it finished without throwing — so the report's figures are only ever printed on a run
where every probe passed. A coverage report that could print beside a failure would be `BL-064`'s shape: an
assertion that cannot fail.

`-v Seed=` must differ from every previous run against the same database, because the seed becomes two
session token hashes. A date and time with no spaces is the convention (`UI-41`).

### `database/_perf/T069_load_volumes.sql`, `T070_measure_predicates.sql`, `T071_measure_rebuilds.sql`, `T130_concurrency_harness.sql`, `T130_concurrency_driver.ps1`

The five scripts behind PERF-AUTH-001, and **they are not tests**: they print numbers rather than asserting
them, and a number needs a human to say whether it is acceptable. The two `T130` files are the exception
that proves the rule — the harness *does* assert, but only about itself, closing with a `RISK` / `ACTION` /
`SKIPPED` report whose pass criterion is `0 RISK` and **no `UNMEASURED` row**, and the driver refuses to
report a deadlock result at all unless its positive control deadlocks first. `T069` builds the population — 1,050
tenants, 5,000 profiles, 57,342 scope rows, 200,000 case files — `T070` measures the predicates and the two
authorization entry points, and `T071` measures the rebuilds and the closure.

**`T130_concurrency_harness.sql` and `T130_concurrency_driver.ps1` are `T-130`, closing `G-49`, and they are
two files because one language could not do it.** T-SQL cannot open a second connection, so everything
learnable from one session stayed where anyone with `sqlcmd` can re-run it — the role-change ladder (linear
to 1,000 profiles at ~275 ms each, **no table-level `X` or `S` lock at any step**) and the lock price of a
sign-in (about five key locks per session row). The driver does the rest over pooled `SqlClient`
connections: 128 real sign-ins on 16 at once (**428.5/sec, zero milliseconds of `LOCK` waiting**; what
accumulates is `WRITELOG` and `PAGELATCH`), a pooled connection proved to come back with `SESSION_CONTEXT`
**cleared**, and 160 switch-versus-deactivate pairs with **no deadlock against 80 in a positive control**.
Read PERF-AUTH-001 §9 for the numbers and §9.4 for why the control is the pass criterion rather than a
flourish. Two measurement traps are documented inside the harness because each produced a false zero
first: a `#temp` table is transactional, so a lock snapshot taken inside a rolled-back transaction is
rolled back with it; and `auth.uspRebuildProfilePermissionScope` is idempotent, so a "measurement" that
does not make a **real** role change measures the no-change path.

**Read PERF-AUTH-001 §1 before running them**, because the method is the part that makes the numbers mean
anything: **read counts are stable, microseconds vary by up to 20% between runs, so every argument rests on
logical reads.** §3.3 exists because an earlier draft forgot that and quoted a ratio that looked mild
(18%) instead of the one that was stable (42%).

They were run against a separate database, `testTemplateBoot`, built for the purpose and **left at 10,650
tenants** — which is 10× the design point and not the state any of the published figures were taken at.
Drop and rebuild it before measuring anything further; a run against the leftover database is a run against
a population nobody wrote down.

### `database/_scenarios/S1_load_agency.sql`, `S1_prove_duties.sql`

**The scenario 1 test, and a third kind of script.** `_tests/` holds fixtures — built to be asserted
against, then thrown away. `_perf/` holds measurements. These two hold a **population**: one state agency
over N counties, thirteen cohorts, 12,830 users and 30,490 profiles at 67 counties, and a proof that the
population can do its work. A population is something a demonstration, a training environment or the load
harness of `G-49` *uses* — and it was used exactly that way within the day: both `T-130` artefacts run
against `testTemplateS1` and its 103,358 profiles, because a concurrency measurement on a fixture with one
tenant of each kind would measure the fixture. That is why the loader is parameterised rather than
hard-coded and why it resumes instead of duplicating.

`S1_load_agency.sql` takes `-v AgencyCode`, `-v AgencyName`, `-v CountyCount`, `-v Wave` and `-v Seed`, so
the same file builds DEP over 67 counties and EPA over 100. Users are named
`<agency>.<wave>.<cohort>[.<county>].<serial>`, which is rigid on purpose: any row in any log traces back to
the sentence of `test_scenario_1.txt` that asked for it. Every insert is `NOT EXISTS`-guarded. **`-v Wave` is
the doubling mechanism** — a second wave adds users and profiles and *no tenants*. Its `-v Seed` only orders
the random county picks and writes no session token, so re-using it across waves is deliberate and gives
identical topology.

`S1_prove_duties.sql` needs a **fresh `-v Seed` and a fresh `-v RunLabel` every run**, because both become
session-token material, and `-v AgencyCode`/`-v Wave` must match the load being proved. 34 asserted
observations over 18 connections plus a 12-row evidence ledger; every check `THROW`s (59200–59227), so **the
pass criterion is the exit code** and not a report somebody can explain away. Eighteen connections for one
logical session is not stylistic: `sp_set_session_context @read_only = 1` cannot be re-set, so N profile
switches cost N + 1 connections (`UI-36`). Expect about 90 seconds, including up to two deliberate
31-second waits for a fresh TOTP step — that wait is `UI-47` and it is correct behaviour, not a workaround.

The file **used to** contain exactly one piece of direct DML, an `UPDATE` of
`auth.UserSession.ElevatedUntilUtc`, and that line *was* the finding of `G-48`. It is **gone**: `T-125`
built `auth.uspElevateSession`, and section 7 now performs a real step-up and asserts four things about it,
including that the persisted row matches the returned `OUTPUT` parameter. **There is no direct DML anywhere
in the file now**, which is the state a proof script should be in — it exercises the procedure surface and
nothing else. Full write-up in `docs/60-scenario-test-1.md`, whose §7 keeps all seven findings as written
with a closure paragraph under each.

### `tools/T040-PasswordVerification/`

A throwaway .NET 10 console harness — `T-040`, the one task in this project whose deliverable is not
SQL, with its own README. It does the half of `D-08` the database refuses to do: it writes a real
Argon2id verifier for `t040.real` with a fresh salt every run, then signs in through
`auth.uspGetLoginVerifier` and `auth.uspCompleteLogin` computing the digest **itself** and telling the
database only whether it matched.

**It exists because `_tests/040` cannot do this.** That file has to pass `@PasswordVerified` by hand,
so the one thing the design hangs on — that a real client can take the PHC string the database hands
back, derive a digest from it, and have the answer come out right — is untestable from inside T-SQL.
It also closes the other half of `T-042`: a client presented with the *derived dummy* for a name
nobody holds parses it with the same parser, spends the same Argon2id work, and reaches the same
`E-50106`.

The timing figures it prints are `INFO` and deliberately **not** part of pass or fail — a dev instance
with a cold cache moves them by more than anybody would be looking for. What they are for is catching
the gross error, a dummy that costs half or twice the work of a real verifier, which is the mistake a
naive implementation makes.

Seven observations, exit code 0. Run it with
`dotnet run --project tools/T040-PasswordVerification` — the server and database arguments default to
`MDE-55TT2J4` and `testTemplate`. It is **not** in the install manifest, it concludes every exchange
it opens and soft-deletes its own prior attempts on the way in (both lockout arms are windowed, so a
second run within fifteen minutes would otherwise inherit the first run's failures), and a project
cloning this template should not inherit it.

### The state of execution

**Phases 0 through 7 have been deployed and verified** against `MDE-55TT2J4\testTemplate` — Phases 0–2
on 2026-09-19 and 2026-09-20, Phases 3 through 7 on 2026-09-20. The manifest is now **39 steps**, and the
last full pass reported every step OK, nothing skipped, a second pass changing nothing, and
`Registered tables now unprotected: 2` from the policy unbind. Two further databases exist and are not the
working one: `testTemplateBoot`, built for the Phase 5 measurements and **left at 10,650 tenants**, and
`testTemplateFresh`, which proved this project's first clean-database deployment.

Then, against the converged database, all eight test files, the three measurement scripts and the console
harness:

| File | Measured | Evidences |
|---|---|---|
| `_tests/020`, `_tests/030` | pass — `030` at **23 as intended, 0 violations**, exit 0 (twenty on the three movements, three on the refused cycle) | The Phase 1 exit criteria — variant trees and the closure after a re-parenting. `030` had to be re-scoped to get there (`T-120`): it is the one file in the suite whose constants are a claim about *another* file's fixture |
| `_tests/040` | 42 as intended, 4 notes, 0 failed | Phase 2's four criteria |
| `_tests/050` | **22 as intended, 3 notes, 0 failed**, exit 0 | Phase 3's two — the materialization under fourteen mutations, and the read-only identity |
| `_tests/060` | **16 as intended, 3 notes, 0 failed**, exit 0 | Phase 4's three — the §10.3 matrix, the invisible table, and the maintenance window |
| `_tests/070` | **all three variants PASS**, once each | Phase 6's criterion — every variant of §17 built end to end through the procedures, from bootstrap onward |
| `_tests/080` | **131 throwable / 124 observed / 103 probed / 8 accounted / none unaccounted**, exit 0 | Phase 6's other criterion — Appendix B measured rather than asserted. Grew by nine numbers with `T-125`–`T-129`, and needed an eighth connection to do it: §12A drives the step-up family on a session wearing **no hat**, which `UI-06` means cannot share a contexted connection. **Not runnable against `testTemplateS1`** — `TEMPLATE`/`ROOT` there has no `auth.TenantAuthenticationPolicy` row, and the preflight now says so rather than leaving it to be discovered |
| `_perf/T069`–`T071` | figures, not assertions | `M3` and `D-07`: PERF-AUTH-001 is the record |
| `_perf/T130_concurrency_harness`, `T130_concurrency_driver.ps1` | **0 RISK / 2 ACTION / 1 SKIPPED**, no `UNMEASURED` row; and **3 findings, 3 OK** from the driver | `G-49`: contention, latency and deadlock behaviour under more than one connection — PERF-AUTH-001 §9 is the record. The driver's deadlock result counts only because its **positive control produced 80 deadlocks**; without that it reported a clean bill of health while unable to see one at all |
| `_scenarios/S1_load_agency`, `S1_prove_duties` | **four runs, all exit 0**, 34 asserted observations and 9/9 evidence checks each; then **two further runs after the inversion, exit 0 with 12/12** | `test_scenario_1.txt`: a named customer of ~12,830 users doing its work, and the seven gaps that found, **all seven since closed** — SCEN-AUTH-001 is the record |
| `tools/T040-PasswordVerification` | 7 observations, exit 0 | `D-08` across the client boundary, which cannot be proved inside it |

**The two Phase 6 tests need switches or they do not run.** `-v Seed=` must be **fresh on every run** for
both, because the seed becomes a session token and a token is not reusable; `_tests/070` additionally needs
`-v Variant=VARIANT1|VARIANT2|VARIANT3`, one run each. No `-v` value may contain a space, in any quoting
form (`UI-41`).

Build Log `BL-014` records the Phase 0 closure and `BL-015`–`BL-018` what its first run found;
`BL-019`–`BL-024` record Phase 1; `BL-025`–`BL-035` record Phase 2 and the `G-07` follow-on;
`BL-036`–`BL-049` record Phases 3 and 4; `BL-050`–`BL-066` record Phases 5, 6 and 7 and the closeout
that followed them; `BL-067`–`BL-073` record the gap-closing pass of 2026-09-21; and `BL-074`–`BL-075`
record the suite run that verified it, which are the only two entries on the sheet where neither the
design nor a shipped object was wrong. Of the six Phase 1 entries, one — `BL-023` — was a defect found
before it could do any damage, and one — `BL-024` — is a correction to a script that had already reached
Verified. Of the eleven from Phase 2, `BL-028` is a measurement rather than a decision, `BL-031` is a
hazard in the *client* found by reading the procedures' refusal paths, `BL-033` is the only entry
recording a decision that was not this project's to make, and `BL-035` is a defect the new test section
found in the code it was written to exercise. Of the fourteen from Phases 3 and 4, **none was found by
re-reading the design** — four are the design corrected by SQL Server or by a convention, four are
additions a working system needs, five were found by running something, and `BL-049` by querying the
catalog on a hunch.

**Three of the four things that were installed-but-incomplete are now complete**, and saying which is
more useful than saying "Phase 7 is done": the permission catalogue is **seeded** (`115`, 35 permissions and
14 roles per application, followed in the manifest by the policy rebuild it requires);
`150_auth_query_procedures.sql` holds **all four** procedures and its report has no `PENDING` rows; and
`090_dbo_application.sql` is exercised through its intended surface by `180`'s ten procedures and by
`_tests/070`'s case work. **One remains, and it is environmental rather than unfinished work:**
- **The deployment still runs on a `dev:` key reference** —
  `Authn.MfaKeyReferenceCurrent = dev:local/authn-mfa-kek#v1` — because the TPM-backed `cng:` key `G-07`
  decided on belongs to an application server that does not exist yet. Moving to it is a settings change
  and a rotation sweep, which is what the key-reference grammar is for.

**What is genuinely unwritten is one script.** `950_verify_deployment.sql` (`T-104`) is the whole of what
`database/` is missing — 36 of the 37 planned numbered scripts are on disk — and it owes three things named
elsewhere that would otherwise drift: `BL-029` owes it `170`'s schema-state query at verification time
rather than deployment time, `G-37` owes it the durable half of the deny-grant posture, and `G-31` needs
`125` and `130` re-ordered before its own amendment can be true. It is Phase 8's largest item, and `BL-065`
is the argument for it: **an installer that finishes with `EXIT=0` and no independent verification of what
it produced is a green report beside an unknown state.**

Eight tasks remain, `T-103`–`T-110`, all of Phase 8 — unchanged by the 2026-09-21 pass, whose seven tasks
(`T-113`–`T-119`) closed gap rows rather than plan rows. Three gaps block production go-live — `G-01`,
`G-14` and `G-37` — and `G-06` blocks Variant 3 specifically. `G-30` and `G-42` were on that list until
2026-09-21; `G-31` and `G-41`, both owed to this file, were not and still are not, because a missing
`DEFAULT` and a procedure ordering are correctness debts rather than go-live conditions.

Two items left the *previous* version of that list on 2026-09-20, and they are worth naming for the pattern
rather than the fact.
`FK_auth_UserSession_UserProfile` had been `PENDING` in a deployment report for five phases while the
design said it existed; `FK_auth_TenantDefaultRole_Role` had been `PENDING` for two. Both exist now, both
are `WITH CHECK` and trusted, and both reports can say `VIOLATION` next time. The second was found by
re-running the same catalog query minutes after the first, which is why `BL-049` is written up as one
process defect rather than two constraints: **a `PENDING` row in a green report is not a plan.** If you
are looking for more of these, the query is `SELECT` from `sys.foreign_keys` and the reading is any
report row whose only two states are "fine" and "not yet".

---

## 4. Conventions

### `.claude/skills/ponytail-sql-objects/`

The mandatory SQL Server conventions for this project: schema placement, the audit and
soft-delete column block, `DF_schema_table_field` constraint names, `MS_Description` on every
table and column, the object header block, full instrumentation on writing procedures, the SQL
Server 2022 floor *and ceiling*, and the per-database DDL change-logging subsystem.

| Path | What it is |
|---|---|
| `SKILL.md` | The rules. Ten non-negotiables, the naming scheme, the permission model, the re-runnability requirements. The authority |
| `README.md` | How to install and use it, the four scripts you run yourself, and a troubleshooting table worth reading before you need it |
| `templates/` | Table (plain and temporal), view, procedure (writing and read-only), object header, extended properties |
| `scripts/` | The four installers: extended properties, DDL change logging, execution logging, permissions |
| `references/` | The long forms: instrumentation, change logging, and what the skill does not ship |

**This copy has been de-referenced.** The skill came from another project and carried that
project's script paths, object names and estate references. Those are gone: the one example
object borrowed from elsewhere was renamed to a procedure over a table the skill itself defines,
the foreign script path in the `@@PROCID` exemption was replaced with a description of the rule,
the archaeology explaining what names *used to be* was removed, and the README now states plainly
that the worked examples belong to the skill and exist nowhere else.

The worked examples themselves were kept — `dbo.FacilitySource`, `dbo.Permit`,
`dbo.uspSoftDeleteFacilitySource`, `dbo.vwFacilitySource`. The skill's own README argues,
correctly, that a template with the concrete parts stripped out stops showing how the pattern is
applied. What was wrong was never the examples; it was the unexplained references to files the
reader does not have.

**The rules were not touched.** De-referencing a skill and revising its conventions are different
jobs, and doing both at once is how a convention quietly loosens.

### `.claude/hooks/validate-sql.py`

The convention gate. Rejects a script that creates an object without `SET XACT_ABORT ON` and
`SET QUOTED_IDENTIFIER ON`, a table missing any of the seven audit columns or its description, an
unguarded `CREATE`, a bad schema, a 2025-only construct, and a procedure whose header block sits
after a `GO` where `sys.sql_modules` will not store it.

Runs automatically on every write. Every script in `database/`, all four skill scripts, all **eight** files
under `database/_tests/`, the **three** under `database/_perf/` and the **two** under `database/_scenarios/` pass it.

**It gates `.sql` and nothing else**, which is worth knowing before relying on it: Markdown, Python and
`.ps1` files are not checked, so the four workbooks, the six documents and
`Install-TemplateDatabase.ps1` are governed by reading rather than by a hook. `BL-065` is what that
costs — three statements the installer printed were stale for phases, and no exit code was ever going to
catch them, because **an exit code does not check prose.**

It is worth knowing that the gate is a **participant** in the design and not only a check on it.
`G-20` existed because the hook forbids table-valued parameters where design §14.6 required them, and
the hook's reason was the stronger of the two — so the *design document changed*, in Phase 2, and
`T-045` was deleted rather than the hook being given an exception. That is the intended outcome of a
disagreement between the gate and a document: it belongs in `gaps.xlsx`, then in the document, and
never in a local exception.

---

## 5. Label conventions

Used across every document so they can point at each other precisely.

| Label | Meaning | Lives in |
|---|---|---|
| `§n` | Design section | DES-AUTH-001 |
| `P-nn` | Design principle | DES-AUTH-001 §3 |
| `D-nn` | Decision, with rejected alternatives | DES-AUTH-001 §4 |
| `INV-nn` | Invariant the database enforces | DES-AUTH-001 Appendix D |
| `E-nnnnn` | Application-visible error number | DES-AUTH-001 Appendix B |
| `A-nn`, `C-nn`, `PRE-nn`, `R-nn`, `F-nn`, `M-n` | Assumption, constraint, prerequisite, risk, finding, milestone | PLAN-AUTH-001 |
| `T-nnn` | Task | `implementation-tracking.xlsx` |
| `BL-nnn` | Build log entry | `build-and-traceability.xlsx` |
| `G-nn` | Gap | `gaps.xlsx` |
| `UI-nn` | UI gotcha | `ui-gotchas.xlsx` |

A label is defined in exactly one place and referenced from everywhere else. `G-04` in this
package means the schema-bound predicate runbook and nothing else — which is worth stating,
because the supplied demo domain arrived citing a `G-04` from a different register entirely
(`BL-008`).

---

## 6. What comes next

This package is the **database** design. Two things follow it:

1. **Implementation** — now **one** unwritten script, `950_verify_deployment.sql` (`T-104`), tracked in
   the implementation workbook. The database architect's project. Phases 0 through 7 are done and
   milestones **M1** through **M4** are all reached: a profile can be granted authority, the
   materialization is proved correct under arbitrary change, a tenant-scoped table returns only the rows
   the acting profile may see, the hot path is measured, and the three contract procedures the UI needs
   are frozen and handed off in UIH-AUTH-001. **Phase 8, verification, is next** — `T-103`–`T-110` — and
   the largest item in it is not a test but that one script: an installer that finishes with `EXIT=0` and
   no independent verification of what it produced is `BL-065` waiting to happen at deployment scale.
   Two smaller items are already named and waiting for it: `G-37`'s durable half, which needs `950` to
   *assert* the deny-grant posture rather than describe it, and `G-31`, which needs `125` and `130`
   re-ordered before its amendment can be true. The instruction attached to Phase 5 — plan at estimate,
   not at the 40% Phases 0–2 ran at — was **half right, and the half it got wrong is the useful half**.
   Phases 5 through 7 came in at **26.0 days against 35.5 estimated, 73%**: faster than the 94% of Phases
   3 and 4 but nowhere near the 40% of Phases 0–2, because by Phase 5 the design was being *executed*
   rather than *corrected*. Phase 8 should be planned at 73%, not at estimate and not at 40%, and the
   figure to watch is whether it slips back toward 94% — which would mean the verification phase is
   finding design errors, and that is exactly what a verification phase is for.
2. **The user interface template** — a separate project with its own design, plan and tracking,
   consuming this database as its contract. **It can start now.** Milestone M4 was reached on
   2026-09-20: `auth.uspGetProfileContext` and `auth.uspGetNavigationForProfile` are built in
   `150_auth_query_procedures.sql` and `auth.uspSwitchProfile` in `140_auth_profile_procedures.sql` — not
   in one file, which is why UIH-AUTH-001 exists — the error registry is measured
   rather than asserted (`_tests/080`), and the gotchas workbook runs to `UI-01`–`UI-54`.
   `docs/40-ui-handoff-m4.md` is that project's entry point and the only document it has to read
   before writing code; §10 of it carries the change-control rule that makes the freeze mean something
   — **element codes are added to, never renamed**. Three rows still deserve reading first because they
   decide architecture rather than detail: `UI-36`, which decides its connection handling (and which
   `G-36`/`BL-057` turned from advice into a hard constraint — a sign-in costs two connections and a
   profile switch spends the one it ran on); `UI-33`, which decides how it builds a tenant picker; and
   `UI-35`, which decides what it does after any change to the permission catalogue. A fourth, `UI-43`,
   decides its **build** rather than its architecture: the catalogue version has to be compiled in, so
   read it at build time from `config.ApplicationSetting` and pass it on every navigation call. The
   contract is at **v1.1** as of 2026-09-21 — the password surface §8 used to list as missing now
   exists — and §10's change-control rule was followed to get there, `BL-071` being the entry it
   requires.

**The dependency runs one way.** The UI project may not require a change to the authorization
model without that change coming back through DES-AUTH-001. The reason is `P-02`: the moment a
screen needs a role name, the model that makes role definition delegable to each organization has
been broken — and it is the requirement that the order in which an organization defines its roles
must have zero impact.
