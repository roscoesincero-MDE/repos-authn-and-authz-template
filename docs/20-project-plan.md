# Project Plan — Database Authentication and Authorization Template

**Document ID:** PLAN-AUTH-001
**Version:** 2.1
**Status:** Draft for review
**Date:** 2026-09-25
**Changed in 2.1 (2026-09-25):** Four defects were found downstream by the WellDrillersLicense build, carried back and **closed**: `G-52`–`G-55`, build log `BL-086`. For each, the test was written first and failed on an unfixed clean build.
- `G-52` (**Critical**): a refused sign-in was enrolment proof even for an account that already had a factor. The password alone could therefore issue working recovery codes for a TOTP account. `auth.udfResolveEnrolmentActor` is now first-factor only, and `_tests/040` §12m′ proves it.
- `G-53`: E-50061 and E-50066 were never raised by any test, so 080's coverage check failed on a clean build. The new `_tests/075_registration_probes.sql` raises both.
- `G-54`: the 900 root-policy note overflowed `NVARCHAR (1000)`, so every fresh bootstrap failed (Msg 2628).
- `G-55`: re-granting a revoked role through `auth.uspAssignRoleToProfile` always failed with E-50010. `trg_au_updt_UserProfileRole` now lets a resurrection re-stamp `GrantedUtc` and `GrantedByProfileId`, and `_tests/080` §8b″ proves it.
- `G-56` (BL-087): re-running 115 withdrew the View gates of elements another script had added, so they became visible to every profile. It also seeded the CaseFile demo menu without the demo domain. Gate withdrawal is now limited to 115's own elements, and the demo elements follow `dbo.CaseFile`. It was proved downstream on builds with and without the demo; the test was not written first.

010–080 now pass on a fresh build and on a re-run (`_tests/Build-Upstream.sh`).

**Changed in 2.0:** The seven gaps version 1.9 filed are **closed**, `G-45`–`G-51`, by `T-125`–`T-130`,
and the consequence for this plan is larger than seven rows: **Phases 0 through 7 are now complete in
full**, and the only work left in the workbook is Phase 8 Verification — eight tasks, `T-103`–`T-110`.
129 tasks, 109 person-days estimated, **74.25 actual, 121 Complete**. Phase 2 closes at 8.45 days against
17.25 estimated with `T-125`–`T-127` in it; Phase 0 at 4.75 against 7.5 with `T-128`; Phase 7 at 8.45
against 10 with `T-129`; and `T-130` is filed in **Phase 8**, where load work belongs, which is why Phase 8
already shows 1 of 9 complete before the phase begins. The `Critical` row that reopened Phase 2 one version
ago — nothing writes `auth.UserSession.ElevatedUntilUtc` — was closed the same day it was filed by
`auth.uspElevateSession`, and **`G-01` is now the only open `Critical` in the project**. Two things in this
plan's own terms are worth carrying forward. **First, the estimates were not the problem and neither was
the design** — every one of the seven was answered by an artefact, DES-AUTH-001 stays at v1.7, and the
seven came in at 5 actual days against 5 estimated. **Second, `G-49` closed as *measured* rather than
fixed**, and that is a category this plan did not previously have: nothing was broken, something was
unmeasured, and the deliverable is PERF-AUTH-001 §9 rather than a change to any shipped object. Its method
is the transferable part — the deadlock result is reported only because a **positive control** deadlocks on
purpose, and without that control the detector reported a clean bill of health while being structurally
incapable of seeing a deadlock at all
**Changed in 1.9:** A **scenario test** — the first time this plan has been answerable to a named
customer rather than to its own task list. `test_scenario_1.txt` describes one state agency over 67
counties and thirteen user cohorts, ~12,830 users holding ~30,490 profiles, and asks for the whole thing
four times: on the existing database, on a fresh one, on that one again with the users doubled and the
tenants deliberately held still, and once more with a second agency of 100 counties beside the first.
**All four runs pass at exit 0**, 34 asserted observations and 9 of 9 evidence checks each, ending at 171
tenants, 44,432 users, 103,352 profiles and 366,452 scope rows in a single database. Two scripts under a
new `database/_scenarios/`, one new document (`docs/60-scenario-test-1.md`, SCEN-AUTH-001), three tasks
added and closed (`T-122`–`T-124`), and **six tasks filed open against phases this plan had already
called complete** — `T-125`–`T-130`. That last number is the point of this version.

Nothing about the design changed, and nothing shipped was found to misbehave: every object did exactly
what its header said. What the scenario found is what **no object says** — and it found it by being
shaped like a customer instead of like a test. Two of the seven gaps were visible before a single row was
inserted, because the seed data has no role meaning *"can do the work"* and none meaning *"can assign
profiles"* (`G-46`, `G-47`), so the loader had to invent `CRUD_ACCESS` and `PROFILE_ASSIGNER` before it
could place a profile for any of the thirteen cohorts. Three more surfaced by a proof failing: the hat
menu cannot be built from the procedure surface at all (`G-51`), the profile-switch audit trail records
no session id (`G-50`), and — the one that reopens Phase 2 — **no procedure in this database writes
`auth.UserSession.ElevatedUntilUtc`** (`G-48`, `Critical`). The step-up challenge that guards every
privileged profile therefore cannot be satisfied: 271 sessions in `testTemplate` and 0 ever elevated,
2,490 users holding a privileged profile across the four runs, 169 of 169 tenant policies demanding
step-up, and the shipped default demanding it too. It hid for eight phases because **all five policy
fixtures in this repository set `RequireStepUpForPrivileged = 0`**, which is the kind of blind spot a
suite written alongside its subject is structurally unable to see. Phase 8's exit criterion of "no gap
open without an owner" now has six more owners, and one of them is `Critical`
**Changed in 1.8:** A verification pass, not a phase, and the only entry in this history where
nothing about the design or the shipped database changed. The 2026-09-21 gap-closing pass was
*proved* rather than asserted: a full thirty-nine-step redeployment of `MDE-55TT2J4\testTemplate`
end to end at **exit 0**, then the whole suite in the documented order — `010` through `080`, with
`070` run once per variant — every file **exit 0**, then `120_rls_policy.sql` re-run to put the
shipped policy back after `050` and `060` leave a development one naming their fixtures. **Two tasks
added and closed, `T-120` and `T-121`, at 0.7 person-days against 0.5**, and both are defects in
*tests*: `_tests/030` threw seven `VIOLATED` rows on a closure that was provably correct, and
`_tests/060` reported the row-security policy stale while printing the fixture's own permission id
inside the very list it claimed was missing. They are filed under **Phases 1 and 4** — the phases
whose exit-criteria tests they repair — so the totals move to **120 tasks and 100.5 person-days, 112
complete**, Phase 1 to 1.9 actual against 8.25 and Phase 4 to 7.6 against 8.25. Two Build Log entries
(`BL-074`, `BL-075`), one UI gotcha filed straight out of a test (`UI-45`), no new gap rows and no
closures: twenty-four of the forty-four
still Closed, `G-01`, `G-14` and `G-37` still the go-live list. DES-AUTH-001 stays at **v1.7** and
UIH-AUTH-001 at **v1.1**, because there was nothing to amend. **The reusable finding is the direction
of the failures.** Both tests failed *towards* alarm — they called a correct database broken — and a
test that does that is worse than one that never runs, because it teaches the next reader to explain
the report away, and the run after that is the one where the report is true. `_tests/030`'s cause is
the sharper lesson for this design: `auth.vwTenantHierarchy` hides a soft-deleted tenant *and its
subtree* while `auth.uspRebuildTenantClosure` deliberately keeps that tenant's closure pairs live, so
the two objects disagree **legitimately** — exactly as `BL-020` intends — and the test had reasoned
that they never could. One number this document quoted was also found stale and re-measured from
`135_audit_triggers.sql`'s own report rather than recalculated: the five-schema census is
**thirty-six triggers over thirty-seven tables**, not thirty-four over thirty-five, because the
gap-closing pass added `auth.TenantTrustedIssuer` and `auth.RegistrationAttempt`
**Changed in 1.7:** A gap-closing pass rather than a phase. **Nine gap rows closed** — `G-12`,
`G-18`, `G-21`, `G-24`, `G-27`, `G-30`, `G-32`, `G-42` and `G-43` — so **twenty-four of the
forty-four are Closed**, and one new row filed, `G-44`. Seven tasks added and closed, `T-113`–`T-119`,
at **7.0 person-days against 7.0 estimated** — the first batch in this project to land on its
estimate, which says more about the gap rows having specified the work in advance than about anybody's
judgement. They are **Phase 6** tasks, because Phase 6 is the phase whose gaps they close, so the
totals move to **118 tasks and 100 person-days, 110 complete**, and Phase 6 to 25.5 actual against
30.5. **No new script.** Seven procedures and two tables were added to eight existing ones:
`auth.uspSetPassword`, `auth.uspGetPasswordChangeContext`, `auth.uspChangePassword` and
`auth.uspExpireCredentials` (`110`); `auth.uspSetTenantAuthenticationPolicy` and
`auth.uspSetTenantDefaultRoles` (`125`); `auth.uspRecordRegistrationAttempt` (`155`);
`auth.TenantTrustedIssuer` (`035`) and `auth.RegistrationAttempt` (`080`). Eleven new error numbers
take Appendix B to `E-50230`, and the `_tests/080` ledger was **re-measured, not recalculated**: 122
numbers a shipped module can throw, 117 ever recorded, 96 raised on purpose, 6 unobservable with a
stated reason, **none unaccounted**. Seven Build Log entries (`BL-067`–`BL-073`) and two UI gotchas
(`UI-43`, `UI-44`). DES-AUTH-001 is at **v1.7** and UIH-AUTH-001 at **v1.1** — the first amendment to
the frozen `M4` contract, taken through its own §10 change-control rule, which is why `BL-071` exists.
**The go-live blocker list halved**: `G-30` and `G-42` are closed, leaving `G-01`, `G-14` and `G-37`,
all three from the design pass rather than from the build. `G-06` is **deliberately still open** after
work was done on it: the per-address registration throttle is one of its three controls and the other
two live outside this database, so closing the row would have claimed a protection that does not
exist. **Four of the seven Build Log entries exist because a gap row was wrong**, not because a
script was — `G-32` and Appendix B both named a procedure this template never built, `G-43` named a
permission that is not in Appendix A, `G-18` asked the *application* to assert a version the database
should refuse, and four artefacts had been quoting a settings count two revisions stale. A gap
register is a document too, and nothing executes a document
**Changed in 1.6:** Phases 5, 6 and 7 executed and complete on `MDE-55TT2J4\testTemplate`, with the
performance work measured on a separate `testTemplateBoot` built for the purpose. Thirty-four tasks
closed — `T-069`–`T-102` — at **26.0 person-days against 35.5 estimated**, which takes the project to
**103 of 111 tasks complete** and 57.3 person-days against 93. Both milestones in the range are
**reached**. `M3`: `D-07` is a **GO**, and the go/no-go rests on *logical reads*, not microseconds —
`docs/30-performance-measurements.md` (PERF-AUTH-001) is now the record for every performance number
this plan quotes, and the one figure that came back badly is not a predicate cost at all but
`G-39`, a rebuild surface 224 times cheaper used one way than the other. `M4`: `T-095` delivered
`docs/40-ui-handoff-m4.md` (UIH-AUTH-001) as one file rather than a pointer to six. Two tests carry
the Phase 6 exit criteria and both were re-run at this closeout rather than quoted from memory:
`database/_tests/070_variants_end_to_end.sql` once per variant, all three **PASS**, every variant
built from bootstrap through the procedures only; and `database/_tests/080_error_catalogue.sql`,
which does not assert the Appendix B registry but *measures* it — 111 numbers a shipped module can
throw, 106 ever recorded, 88 raised on purpose, 6 unobservable with a stated reason, **none
unaccounted**. Seventeen Build Log entries added (`BL-050`–`BL-066`), three UI gotchas
(`UI-40`–`UI-42`) and **twenty** new gaps (`G-24`–`G-43`) — the largest batch of the project. Nine of
the twenty were closed inside the phases that filed them; a sweep of every row whose Target phase was
5, 6 or 7 then closed `G-09` and `G-22`, which the measurements had already answered; and `BL-066`
closed `G-23` by finding that its own prediction had come true. So **fifteen of the forty-three are
Closed**, and three of the nine still open from this batch block production go-live: `G-30`, `G-37`
and `G-42`. DES-AUTH-001 is at **v1.6**,
sixteen sections amended, every amendment a rule the code already enforced or a number the
measurements already showed. **One exit criterion is carried forward rather than met**: Phase 7's
cites `950_verify_deployment.sql`, which is `T-104` and unwritten, so it moves to Phase 8 — that
script is the last numbered script absent from `database/`, which holds 36 of the 37 planned. Totals
unchanged at 111 tasks and 93 person-days
**Changed in 1.5:** Phases 3 and 4 executed and complete on `MDE-55TT2J4\testTemplate`. Twenty-five
tasks closed — `T-043`, `T-044` and `T-046`–`T-068` — at 19.1 person-days against 20.25 estimated,
evidenced by two new test files, `database/_tests/050_authorization_and_session.sql` (21 observations
as intended, 3 notes, 0 failures) and `database/_tests/060_row_security.sql` (16, 3, 0), both exit 0.
Eight scripts moved from drafted to verified — `050`, `055`, `060`, `065`, `105`, `120`, `150`, `165`
— and `030`, `035`, `040`, `070`, `085`, `100`, `170` and `Install-TemplateDatabase.ps1` were amended.
Fourteen Build Log entries added (`BL-036`–`BL-049`), seven UI gotchas (`UI-33`–`UI-39`, one of them
`Critical`), and two new gaps: `G-22`, the authorization hot path cannot instrument itself, targeted
at Phase 5; and `G-23`, a new `logs` table is writable by `applicationRole` until someone remembers to
deny it, targeted at Phase 8. `M2` is **reached** — a tenant cannot read another tenant's rows, and
that is now measured rather than designed. Two design corrections carried into DES-AUTH-001 v1.5:
`auth.uspSetSessionContext` takes `@SessionTokenHash` and the four table-valued functions are `tvf`,
not `udf`. Totals unchanged at 111 tasks and 93 person-days — nothing was added or deleted; `T-112`
had already re-based them
**Changed in 1.4:** `PRE-02` **met** and `G-07` closed, by a management decision recorded in
`additionalRequirements-T-041.txt`: application-side envelope encryption under a TPM-backed CNG key on
the application-layer server, secrets encrypted in `appsettings.secrets.json`, SQL Server Always
Encrypted rejected because external readers such as Power BI must keep reading these tables and a
template cannot know which columns to enrol. `T-041` is therefore **complete**, `R-03` is **closed**,
and the Phase 2 "what did not happen" section is rewritten as what then did. One task was added that
the plan never had: `T-112`, `112_auth_mfa_procedures.sql`, the enrolment surface itself — `T-041` was
scoped as an environment decision and the plan assumed enrolment fell out of it. Totals re-based to
111 tasks and 93 person-days. Five UI gotchas added (`UI-28`–`UI-32`) and three Build Log entries
(`BL-033`–`BL-035`)
**Changed in 1.3:** Phase 2 executed and complete on `MDE-55TT2J4\testTemplate`. All four exit
criteria evidenced, seventeen of eighteen tasks closed at 4.75 person-days against 14.25 estimated,
eight Build Log entries added (`BL-025`–`BL-032`), `G-19` and `G-20` closed by implementation, one
new gap (`G-21`, issuer allow-listing) and two new UI gotchas (`UI-26`, `UI-27`). `T-041` is
**blocked** by `G-07`, which is `R-03` arriving as predicted. Totals re-based to 110 tasks and 92
person-days, `T-045` having been deleted rather than re-scoped
**Changed in 1.2:** Phase 1 executed and complete on `MDE-55TT2J4\testTemplate`. Both exit criteria
evidenced, `T-014`–`T-024` closed at 1.5 person-days against 8 estimated, six Build Log entries
added (`BL-019`–`BL-024`) and one new gap (`G-20`, the §14.6 table-valued-parameter conflict, which
must be resolved before Phase 3 begins)
**Changed in 1.1:** Phase 0 executed and complete on `MDE-55TT2J4\testTemplate`. `PRE-01` closed,
`A-01` qualified, `M1` reached, `R-02` retired, totals re-based to 111 tasks and 92.5 person-days,
and the four findings of the first real deployment recorded (`BL-015`–`BL-018`, `G-19`)
**Implements:** DES-AUTH-001 (`docs/10-database-authn-authz-design.md`)
**Tracked in:** `workbooks/implementation-tracking.xlsx`

---

## 1. What this plan is for

DES-AUTH-001 describes a database. This plan describes the work of building it, in an order
that keeps the thing deployable at the end of every phase rather than only at the end.

Two properties of the work shape the plan more than anything else:

**It is a template, not an application.** The output is a script set plus documentation that a
project team clones. So "done" includes *someone who was not in the room can deploy this and
understand why it is shaped the way it is* — which is why documentation tasks appear inside
each phase rather than being swept into a phase of their own at the end.

**The security machinery is load-bearing from the first deployment.** Row-level security cannot
be retrofitted onto a populated database without a maintenance window (DES §21.3), and an
unregistered tenant-scoped table fails open (DES §10.1). The phase order below puts the
predicate in place before the demo domain, so that the worked example is built *under* the
security model rather than having it applied afterwards.

---

## 2. Scope

### In scope

- Every database artefact listed in the **Scripts** worksheet of
  `workbooks/build-and-traceability.xlsx`, in install order.
- Seed and reference data for all three application variants.
- The deployment verification script, which is a deliverable and not a convenience.
- Modification of the demo domain (`dbo.CaseFile`, `dbo.CaseNote`) to sit under the new model.
- De-referencing the `ponytail-sql-objects` skill so it carries no other project's names.
- Documentation: this plan, the design, the four workbooks, the documentation index.

### Out of scope

- The user interface. A separate project with its own plan, for which this one is a dependency
  (§8).
- Business domain tables beyond the demo domain.
- Entra tenant configuration, conditional access policies, and app registration.
- Key management for the TOTP secret — a prerequisite, not a deliverable. **Decided 2026-09-20**
  (`PRE-02`, `G-07` closed): the key lives on the application-layer server, and what this project
  delivers is the *convention* for naming it and the procedures that respect it — DES §6.4.
- Migration of any specific existing application. DES §18 gives the method; each conversion is
  its own piece of work.

---

## 3. Assumptions, constraints and prerequisites

### Assumptions

| | Assumption | If it is wrong |
|---|---|---|
| A-01 | SQL Server 2022 is the floor and the ceiling in every target environment. **Qualified in Phase 0:** the floor is enforced by `000_prerequisites.sql` and the ceiling is enforced only by the convention gate — the development instance is SQL Server 2025, so the above-major-16 warning is expected output on every deployment (`BL-018`) | The conventions skill's rule 6 breaks; `LEAST()` and the 2022 constructs in the templates need replacing |
| A-02 | The application connects as a single pooled login, not per user | DES §14.3 and the whole `SESSION_CONTEXT` design change; audit attribution would come free instead |
| A-03 | One database per application at the outset | `D-09` already accommodates consolidation later, at no rework cost |
| A-04 | Entra is the only federated identity provider | `auth.UserFederatedIdentity` carries `Issuer`, so a second provider is additive |
| A-05 | The team building the UI is a different team, starting after Phase 6 | Phase 6's deliverables are their contract; if they start earlier, Phase 6 moves forward |

### Constraints

| | Constraint | Source |
|---|---|---|
| C-01 | The UI calls stored procedures only | Management requirement |
| C-02 | Soft delete only; no hard `DELETE`, no `TRUNCATE`, no `DROP … CREATE` | `ponytail-sql-objects`, non-negotiable 3 |
| C-03 | Every script is re-runnable and converges | `ponytail-sql-objects`, non-negotiable 7 |
| C-04 | Every writing procedure is fully instrumented; every reading procedure error-instrumented | `ponytail-sql-objects`, non-negotiable 8 |
| C-05 | `MS_Description` on every table and every column | `ponytail-sql-objects`, non-negotiable 4 |
| C-06 | Changing a schema-bound security predicate requires an application-stopped window | DES §21.3, `G-04` |

### Prerequisites — these block Phase 0

| | Prerequisite | Owner |
|---|---|---|
| PRE-01 | ~~A SQL Server 2022 development instance, with `db_owner` on a throwaway database~~ **Met.** `MDE-55TT2J4`, SQL Server 2025 (17.0.1135.8, Standard Developer Edition); `000_prerequisites.sql` created `testTemplate` there on 2026-09-19 and pinned it to compatibility level 160. The instance is above the stated ceiling — see `A-01` and `BL-018` | DBA — closed |
| PRE-02 | ~~Decision on TOTP secret protection: Always Encrypted, or application-side envelope encryption with a vault key (`G-07`)~~ **Met, 2026-09-20, by management** — `additionalRequirements-T-041.txt`. Application-side envelope encryption under a TPM-backed CNG key on the application-layer server; secrets encrypted in `appsettings.secrets.json`; Always Encrypted rejected because external readers such as Power BI must keep reading these tables and a template cannot know which columns to enrol. `vault:` is reserved in the key-reference grammar as the seam for a self-hosted HashiCorp Vault. DES §6.4, `BL-033` | Management — closed |
| PRE-03 | ~~Confirmation of the database role names~~ **Decided.** `applicationRole`, `readOnlyRole`, `logsAuditReader`, `rlsBypassRole`, created by `005_schemas_and_roles.sql`. These are SQL Server *database* roles and are a different thing from the application role codes in `auth.Role`, which stay `UPPER_SNAKE_CASE` | DBA — closed |
| PRE-04 | An Entra app registration in a non-production tenant, for Phase 2 | Identity team |
| PRE-05 | Agreement that `Authz.AllowSelfGrant` stays `0` in every environment above development | Security architecture |

**PRE-02 was the one that genuinely blocked production** rather than merely development, and it is
closed. What a deployment now needs is not a decision but an environment: a TPM-backed CNG key on the
application-layer server and an encrypted `appsettings.secrets.json`. The development instance still
runs on a `dev:` key reference — `Authn.MfaKeyReferenceCurrent = dev:local/authn-mfa-kek#v1` — and
moving to `cng:` is a settings change and a rotation sweep, not a schema change. That is the whole
point of the key-reference grammar (DES §6.4). The remaining production blocker is `G-01`.

---

## 4. Phases

Effort is in person-days for one developer with SQL Server experience and one reviewer, and is a
**planning estimate to be re-based by the team** once Phase 0 has established the actual pace
against these conventions. The conventions are demanding — full instrumentation, descriptions on
every column, re-runnability — and first estimates against them are usually low by a third.

**Totals.** One hundred and twenty-nine tasks, 109 person-days, built bottom-up in
`workbooks/implementation-tracking.xlsx` and rolled up on its Phase Summary sheet. The phase
figures below are that roll-up, not an independent guess — if the two ever disagree, the
workbook is right and this document is stale. Phase 6 is **more than** a quarter of the work on its
own, which is the honest shape of it: that phase is where every administrative rule in the design
turns into a procedure with four failure branches, and it is also where the gap rows that outlived
the phase came home — `T-113`–`T-119` were added on 2026-09-21 and filed there rather than into
Phase 8, because a task belongs to the phase whose work it finishes and not to the week it was done
in. `T-120` and `T-121` were added the same day on the same rule and went the other way for the same
reason — into Phases 1 and 4, because each repairs that phase's own exit-criteria test, and neither
belongs to the verification pass that happened to find it.

**Pace after eight phases of the nine, and what the ratio did.** Phases 0 to 2 ran at roughly
two-fifths of estimate — 12.6 person-days actual against 30.5. Phases 3 and 4 ran at **19.4 against
20.5**, 95% rather than 40%. Phases 5 to 7 ran at **33.0 against 42.5**, which is 78% — it was 73%
until the 2026-09-21 gap-closing pass added 7.0 days to Phase 6 at exactly 7.0 estimated, and a batch
that lands on its estimate pulls a ratio *towards* 100% rather than away from it. The cumulative
figure is **65.0 against 93.5** for the eight phases executed, with Phase 8's seven days untouched.

Version 1.4 predicted the ratio would close as the work moved into rules rather than tables, and it
did, two phases early. Version 1.5 then said *plan the remaining phases at estimate, not at
two-fifths of it* — and at 73% that advice was right in direction and pessimistic in size, which is
the error worth making. The reason the ratio came back off 94% is not that the rules got easier: it
is that **Phase 5 is a measurement phase and measurement is fast when the answer is yes.** Three
`_perf` scripts and a document came in at 3.8 days against 6 because the model held; had the plan
shape come back a scan, `R-01` would have spent the whole six days and more. Phase 6, the only phase
estimated honestly from the start, came in at 18.5 against 23.5 on the day it closed — and fifteen
Build Log entries and twenty gaps is what that phase's 5 days of slack actually bought. **It then
spent the rest of that slack, and the arithmetic is the argument**: closing nine of those gaps cost
7.0 days, taking Phase 6 to 25.5 against 30.5, so the phase finished at 84% rather than 79%. The
slack was not saved; it was *deferred*, and it came due against the same phase. A phase that files
twenty gaps has not finished, whatever its exit criteria say.

**The one pattern that held across all eight phases.** The three phases that ran closest to estimate
are 3, 4 and 6 — 96%, 92% and 84% — and they are also the three that account for the largest share of
the seventy-five Build Log entries. They are the phases where the design stated *rules*. Where the design
stated tables it was complete, the work was transcription, and the phases ran at two-fifths;
where it stated a rule the rule was occasionally wrong, and a Build Log entry is what finding that
costs. Nothing in the pattern suggests a correction for Phase 8, which is verification and
documentation and therefore neither shape.

The count went 111 → 110 → 111 → 118 → 120 and no move was a re-estimate: `T-045` was **deleted** because
`G-20` established there is no table type to create; `T-112` was **added** because the `G-07` decision
made the enrolment surface writable and nothing in the original numbering held it; and `T-113`–`T-119`
were added on 2026-09-21 to close nine gap rows, none of which this plan had ever contained, because
all nine were filed during Phases 5 to 7 or while writing the `M4` handoff. Every move carries its
days with it — the half-day `T-045` held is gone rather than banked, `T-112`'s day is new work rather
than borrowed from `T-041`, and the seven new tasks' 7.0 days are this pass's own figures rather than
a re-based plan. `T-120` and `T-121` are the same kind of move for a different reason: they are not
work the plan failed to foresee but work the *suite* turned out to need, found on the day the suite
was run end to end to prove the pass, and their 0.7 days are actuals rather than an allowance.

**One thing found while appending them belongs here rather than only in the workbook.** The Phase
Summary roll-up formulas ranged over `Tasks!$B$2:$B$112` — *exactly* the last task row — so the first
appended task would have been counted in no phase at all, and Phase 6 would have under-reported by
seven while every total still looked healthy. The ranges now run to row 130. A range that merely
reaches the last row is one append away from lying, which is a thing to check in any workbook this
plan quotes.


### Phase 0 — Foundations and conventions baseline · ~7 days · **complete, 2026-09-19**

**Objective.** A database that has the conventions machinery installed and verified, before any
object of this design exists.

- Install `templates/extended-properties.sql`, `scripts/logdBChanges.sql`,
  `scripts/logExecutionLogging.sql`, `scripts/permissions.sql`, in that order, on a throwaway
  database — twice, from empty and then again, which is the exercise the skill's README asks for
  — done, against `MDE-55TT2J4\testTemplate`. Run **in place** from the skill folder; there is one
  copy of each script, not a copy under `database/`.
- Create the four database roles — done, in `005_schemas_and_roles.sql`.
- Create `000_prerequisites.sql` and `005_schemas_and_roles.sql` — done, and run: `testTemplate`
  was created on the first pass and reported as reused on the second.
- Establish the deployment runner and its `sqlcmd -I -C -b -v DbName=` discipline — done, and
  executed for the first time. It ran correctly end to end, including the named skip of `090`. No
  change to the script was needed *at the time*; Phase 1 found that the skip's probe tested one of
  the two tables `090` asserts, and widened it — `BL-023`.
- De-reference the `ponytail-sql-objects` skill (§6) — done.
- Prove rule 8 instrumentation with `database/_tests/010_phase0_instrumentation.sql` (`T-111`) —
  done. Deliberately outside the install manifest; it creates test fixtures a project cloning this
  template should not inherit.

**Exit criteria — all met.** `checkDbChangeLogging.sql` reads clean on a second run (19 OK/INFO
rows, no failures), and `logs.uspDdlAuditVerify` returns 7 OK plus one INFO watermark.
`logs.ExecutionLog` exists and `util.uspPhase0Probe` writes to it on all three paths: a successful
call, a failure with no ambient transaction, and a failure inside a caller's open transaction —
the last recorded with `ReCreatedAfterRollback = 1` and a gap in the identity sequence where the
rolled-back start row had been. A second run of every script reports no change:
`-VerifyIdempotent` exits 0 and its two passes differ only by the verification section appended
after pass 2. The skill contains no name from any other project.

**What the first run found.** Four things, all recorded in the Build Log, none of which required a
script to change:

- `permissions.sql` issues no grant and no deny on `SCHEMA::config` or `SCHEMA::util`, so both are
  invisible to `applicationRole` and `readOnlyRole` after a complete deployment, silently.
  `170_permissions.sql` must close `config` in Phase 8 — `G-19`, `BL-015`. **Closed early, in
  Phase 2**, because `110_auth_authn_procedures.sql` needed `config` readable to run at all; the
  deployment-time assertion half remains for Phase 8 — `BL-029`.
- State converges; the DDL event trail does not. Each pass appends about 45 rows to
  `logsData.DdlChange` even when nothing differs, because `CREATE OR ALTER` and the unconditional
  `GRANT`/`DENY` statements raise DDL events regardless — `BL-016`.
- `logs.uspDdlAuditVerify` forward-references `logs.uspRecordExecutionError`, so a first pass
  prints a deferred-resolution warning. Expected output; swapping the two installers would silence
  it and lose the recording of the second one's own DDL — `BL-017`.
- The development instance is SQL Server 2025, above the stated ceiling — `A-01`, `BL-018`.

**Why first, and why not skipped.** The skill's own README stated that its scripts had never been
run against a server. Discovering that on the day the authorization tables go in would have
confounded two sets of problems. Four findings for no script changes is what that separation
bought.

### Phase 1 — Tenancy model · ~8.25 days estimated, 1.9 actual · **complete, 2026-09-19; one test-integrity task added and closed 2026-09-21**

**Objective.** The hierarchy, and the ability to ask "is tenant T at or below tenant S" quickly
and correctly.

- `auth.Application`, `auth.TenantType`, `auth.Tenant`, `auth.TenantClosure` — done, in
  `030_auth_tenant.sql`, with four `AFTER UPDATE` audit triggers and 47 of 47 column descriptions.
- `auth.uspRebuildTenantClosure`, and the tenant mutation procedures that call it — done, in
  `125_auth_tenant_procedures.sql`: the rebuild plus `uspCreateTenant`, `uspUpdateTenant`,
  `uspDeactivateTenant` and `uspGetTenantTree`.
- `auth.vwTenantHierarchy`, with the full path from the root — done, in `095_auth_views.sql`, and
  `auth.udfIsTenantUsable` in `100_auth_functions.sql`.
- Test fixtures building all three variants' trees (DES §17) — done, in
  `database/_tests/020_tenancy_variant_trees.sql`: three applications, 23 tenants, and all seven
  tenant types exercised.

**Exit criteria — both met.** *All three trees build from script:* `_tests/020` builds `VARIANT1`,
`VARIANT2` and `VARIANT3` and asserts, per application, that `SUM (Depth + 1)` over
`auth.vwTenantHierarchy` equals `COUNT (*)` over `auth.TenantClosure` — 7, 27 and 26 — that no
closure pair crosses an application, and that all 23 tenants read as usable. *Closure is correct
after a re-parenting, not only after a fresh build:* `_tests/030` moves a populated subtree three
times — deeper, to the root, and back — and asserts after each move. The re-root retires four
pairs, two of them for a grandchild nothing wrote to, which is the case an incremental algorithm
gets wrong. The round trip is identical to the baseline on `(ancestor, descendant, depth)`, and a
second rebuild is identical *including* `auditModifiedDateUtc` — a stronger claim than "the same
answer", because it rules out a rebuild that rewrites every row to the value it already held and
destroys the audit trail with it. *`INV-02` holds:* asserted for all three applications, both
halves — one live tenant with a null parent, one tenant typed `Root`, and the two counts must
agree as well as each be 1.

**Also proven, beyond the stated criteria.** A cycle makes the rebuild fail loudly rather than
run away: `OPTION (MAXRECURSION 100)` raises 530, the single transaction's `CATCH` rolls back so
the previous closure is left whole rather than half-rebuilt, and the failure lands in
`logs.ExecutionLog` with `ReCreatedAfterRollback = 0` — rule 8 end to end on a real failure
rather than a probe's artificial one. A partially rebuilt closure is an authorization table with
rows missing, so "it fails, and leaves the old answer in place" is the behaviour worth asserting.

**What the phase found.** Six Build Log entries, `BL-019` through `BL-024`, and one new gap:

- `CK_auth_Tenant_RootHasNoParent` must read the tenant *type*, and a `CHECK` may only read its own
  row. Reaching the code through a scalar function was tried and **measured**: a function
  referenced by a `CHECK` cannot afterwards be `CREATE OR ALTER`ed — error 3729, with or without
  `SCHEMABINDING` — which breaks the re-runnability every script here requires. Hence a
  denormalised `TenantTypeCode` held true by a composite foreign key — `BL-019`.
- `auth.TenantClosure` deliberately does **not** filter soft-deleted tenants. Had it filtered, a
  deleted mid-tree tenant would vanish from its descendants' ancestor set and
  `auth.udfIsTenantUsable` would fail **open** for every program beneath a deleted administration.
  The closure records shape; the function decides usability — `BL-020`.
- The seven tenant types are seeded by `030_auth_tenant.sql`, not `115_seed_reference_data.sql`,
  because `auth.Tenant`'s composite foreign key cannot be satisfied until they exist — `BL-021`.
  The four tenancy audit triggers ship there too, because the audit defaults fire on `INSERT` only
  and `auth.uspRebuildTenantClosure` is all `UPDATE`s — `BL-022`.
- The runner's `Test-AuthSchemaPresent` tested `auth.Tenant` alone. The moment `030` created it,
  the probe would have answered YES while the true answer was "some", `090_dbo_application.sql`
  would have run instead of being skipped, and `-b` would have failed the whole deployment at the
  exact moment Phase 1 succeeded. A partial probe for an all-or-nothing dependency is a probe that
  reports YES while the answer is "some" — `BL-023`.
- DES §14.6 requires table-valued parameters for bulk role assignment; the conventions hook rejects
  `CREATE TYPE … AS TABLE` and `READONLY` outright. Both are in force and they contradict each
  other, so the author of `055_auth_role.sql` would meet it at the gate. `G-20`, to be resolved in
  the design document *before* Phase 3 begins rather than at the gate under time pressure.
  **Closed in Phase 2**, as intended and ahead of the phase that would have hit it: a JSON array
  shredded with `OPENJSON`, and `T-045` deleted — `BL-030`.
- **`BL-020` has a consequence for tests, found on 2026-09-21 and paid for by `T-120`.** Because the
  closure keeps a soft-deleted tenant's pairs and `auth.vwTenantHierarchy` drops that tenant together
  with its subtree, the two objects *disagree by design* the moment anything soft-deletes a tenant —
  and `_tests/030`'s load-bearing invariant compares `SUM (Depth + 1)` over the view against
  `COUNT (*)` over the closure. Run after `_tests/070`, which soft-deletes the organization tenant its
  previous run approved and adds two tenants to the `VARIANT2` tree, the file reported five stages
  `VIOLATED` while every independent assertion in the same run passed. Nothing was wrong with the
  database. The fix is two scoping rules stated in the file's own header: the four pair-count
  constants measure the **nine tenants `_tests/020` declares**, resolved nine-or-nothing, and every
  count compared against the view counts only what the view can see. The same asymmetry is now written
  up for the UI project as `UI-45`, because an administrator diagnosing a lockout from the hierarchy
  view is reading the one source that has already hidden the cause. `BL-074`.

**What did not happen, and why that is correct.** Four of the five tenancy procedures cannot be
*called* yet. They reference `auth.uspSetSessionContext` and `auth.uspDemandPermission`, so
deferred name resolution lets them install today and a call before Phase 3 fails with 2812. A
conditional gate around the permission demands was rejected: a permission check that is skipped
when its dependency is absent becomes a permission check that is skipped, which is finding `F-07`'s
shape. `auth.uspRebuildTenantClosure` takes no session token and demands nothing, so it is
callable, and that is what the fixtures use.

### Phase 2 — Identity and authentication · ~15.25 days estimated, 6.45 actual · **complete, 2026-09-20**

**Objective.** A person can prove who they are, three different ways, and a session exists.

- `auth.User` — done, in `040_auth_userprofile.sql`, which despite its name builds that table
  **only**; `auth.UserProfile` is Phase 3, `T-046` — `BL-025`.
- `auth.UserCredential`, `auth.PasswordHistory`, `auth.UserFederatedIdentity`,
  `auth.UserMfaFactor`, `auth.UserMfaRecoveryCode`, `auth.LoginAttempt` — done, in
  `045_auth_identity.sql`, with an audit trigger each. `auth.UserSession` — done, in
  `070_auth_session.sql`, whose `EndedUtc` is write-once at the trigger (`E-50010`).
- `auth.TenantAuthenticationPolicy` and `auth.udfResolveAuthPolicy` — done, in
  `035_auth_tenant_policy.sql` and `100_auth_functions.sql`: the upward walk that makes policy
  inherit, alongside `auth.udfIsUserUsable`.
- The authentication procedures — done, all seven, in `110_auth_authn_procedures.sql`:
  `uspGetLoginVerifier`, `uspRecordLoginFailure`, `uspCompleteLogin`, `uspVerifyMfa`,
  `uspBeginSsoLogin`, `uspCompleteSsoLogin`, `uspEndSession`.
- **The MFA enrolment surface — done, and not in the original list:** `112_auth_mfa_procedures.sql`,
  `T-112`, added on 2026-09-20 once the `G-07` decision made it writable. `uspEnrolMfaFactor`,
  `uspConfirmMfaFactor`, `uspIssueMfaRecoveryCodes` and `uspRotateMfaFactorKey`, with the two actor
  resolvers they depend on — `udfResolveSessionUser` and `udfResolveEnrolmentActor` — added to
  `100_auth_functions.sql`, because "who is calling" is one rule and belongs with the functions.
  The plan had `T-041` as an *environment* task — decide the protection,
  record the convention — and assumed the procedures fell out of it; they do not, so they are their
  own task and their own script. `BL-034`.
- `logs.AuthenticationEvent` — done, in `085_logs_auth_tables.sql`. `config.ApplicationSetting`
  and `config.TenantScopedTable` came forward from Phase 6 into `025_config_tables.sql` because
  the throttle thresholds and the dummy-verifier pepper had to be readable before `110` could
  exist.
- A throwaway .NET console harness that performs the password hashing half of `D-08` — done, in
  `tools/T040-PasswordVerification`, seven observations, computing real Argon2id digests against
  verifier strings this database issued.
- **Also built, and not in the original list:** `170_permissions.sql`, the whole-database
  permission model, because `G-19` came due here rather than in Phase 8. It is the last step of
  the installer and the only script that grants anything.

**Exit criteria — all four met.** Evidenced by `database/_tests/040_identity_and_authn.sql`, 42
observations intended and 0 failed, whose own roll-up exercises the criteria 3, 1, 2, 2 and 3 times
respectively with no failures. *All three routes authenticate:* local password (session 38, method
`LocalPassword`, lifetimes 60/15 taken from the child tenant's policy against shipped defaults of
480/60, so the inheritance cannot have agreed by accident), federated (session 43 for a user with
**zero** credential rows, so nothing about that route can be a password check in disguise), and the
platform-admin bypass (session 41, `IsBypassRoute = 1`, `MfaSatisfied = 1`). *An unknown user costs
the same work and yields the same message:* the dummy verifier is 97 characters against the real
one's 97, with an identical algorithm and cost prefix; it is **derived per name**, so the same
unknown name twice is identical and two unknown names differ, as two real accounts would; and both
a wrong password and an unknown name raise `E-50106` with byte-identical text and both cost a
concluded `Failure` attempt row. *Lockout fires per account and per address independently, in both
directions:* bob locked on exactly the fifth failure — not the sixth, because the attempt is
concluded before it is counted — while alice signed in **from the same address**; and twenty
failures from one address against twenty distinct names throttled the address (`E-50116`) while
locking no account and writing no state anywhere. *`INV-07` and `INV-08` hold:* the federated link
matched on `(Issuer, SubjectId)` with no email parameter anywhere in `uspCompleteSsoLogin`'s
signature — checked against `sys.parameters` rather than by reading the code — an unlinked subject
was refused `E-50113` and enrolled nobody, and the bypass route with a correct password and no
second factor was refused `E-50107` by the procedure **and** 547 by a `CHECK` constraint on a
direct `INSERT` as `db_owner`.

**Also proven, beyond the stated criteria.** A TOTP step outside the window and the same step
replayed inside it are both refused `E-50111`, deliberately the same number, the second by
`LastUsedTimeStep` and not by the clock. A recovery code is spent by `uspVerifyMfa` at the moment
it is accepted rather than on overall success — a code spent only at the end can be presented,
observed to work, and presented again. A spent code and a code that never existed give the same
answer. `INV-09` is checked **before** `INV-08`, so a non-administrator on the bypass route gets
`E-50108` and not `E-50107`, because "this route is not yours" is the more fundamental refusal. A
locked account is still issued a verifier at round trip 1 on purpose: refusing earlier would make
"this name is locked out", and therefore "this name exists", free to anybody willing to ask twice.
`AllowLocalPassword` defaults to 1 and `AllowFederated` to 0 — asymmetric because a password needs
only a credential row, while federation needs an identity provider somebody configured. And
`INV-11` is now *enforced* rather than satisfied: a `DENY` on the four table verbs on `SCHEMA::auth`
was measured to cost the procedures nothing, while a direct read refuses with 229.

**What the phase found.** Eleven Build Log entries, `BL-025` through `BL-035`, three gaps closed, one
new gap and seven new UI gotchas. The last three entries and five of the gotchas landed on 2026-09-20,
the day after the gate, when `G-07` was decided — they are recorded under this phase because that is
the work they belong to:

- `G-07` **closed, by management rather than by implementation** — the only decision in this project so
  far that was not this project's to make. Application-side envelope encryption; Always Encrypted
  rejected for template-shaped reasons (external readers, unknowable columns). It unblocked `T-041`,
  produced `T-112` and `112_auth_mfa_procedures.sql`, closed `R-03`, and produced five UI gotchas of
  its own, `UI-28` to `UI-32`, every one of them a consequence rather than a preference — `BL-033`,
  `BL-034`. DES §6.4 is the contract.
- A defect the *test* found, worth its own entry: `uspConfirmMfaFactor` and `uspRotateMfaFactorKey`
  each tested existence by whether a `SELECT` had assigned an `OUTPUT` parameter. A caller re-using one
  variable defeats that, and for the rotation sweep such a caller is the **intended** one — it would
  have logged `'MfaKeyRotated'` for a factor that does not exist. Found by writing the cheapest
  observation in the file, a plain repeat of a call that had already succeeded — `BL-035`.
- `G-19` **closed**: `170_permissions.sql` states every one of the seven user schemas explicitly.
  It departs from its own proposed resolution in one place, deliberately and on the record:
  `SCHEMA::config` is granted `SELECT` to both roles as the resolution said, and then
  `config.ApplicationSetting` is **denied** to both, because it holds the dummy-verifier pepper and
  DES §19.2 is worth more than the convenience. The named extension point is a filtered view over
  the non-sensitive rows, not built speculatively. The `950_verify_deployment.sql` half of the
  resolution is **deferred to Phase 8** with the report query already written and working as that
  file's section 5a — `BL-029`.
- `G-20` **closed**: DES §14.6 and §8.2 now specify an `NVARCHAR (MAX)` JSON array shredded with
  `OPENJSON` and gated by `ISJSON`, and `T-045` was **deleted** rather than re-scoped, because with
  no table type to create it had no content — `BL-030`.
- Permission precedence was **measured, not assumed**, before `170` committed to a model, and two
  of the three results contradict the intuition: a `DENY` on a table does not stop a procedure that
  reads it, because ownership chaining never consults the permission — but a `DENY` at schema level
  **beats** a `GRANT` at object level, so the column-level exception does not generalise. A blanket
  `DENY EXECUTE ON SCHEMA::util` killed an already-granted procedure, which is why the util section
  denies the four table verbs and leaves `EXECUTE` alone — `BL-028`.
- `G-21`, new: **nothing in the database constrains which issuer a federated sign-in may come
  from.** Any string in `@Issuer` that matches a stored link is accepted. This was found by the
  test being *unable to write an assertion* — section 9 can prove a wrong subject resolves to
  nobody and cannot say anything at all about a wrong issuer, because there is no trusted-issuer
  list to check one against. Medium, target Phase 3.
- `UI-27`, Critical: **never call these procedures inside an ambient transaction.** Every refusal
  path commits the failure record and the lockout increment and then re-raises; a caller holding a
  `TransactionScope` makes `XACT_STATE ()` non-zero, so the throw unwinds the *caller* and takes the
  committed evidence with it. Unlimited guesses, no trail, fails open silently — `BL-031`.
- `UI-26`, Critical: every sign-in failure must show the same message whatever the number, and
  `E-50116` is **not** an exception to that rule. `E-50116` was also missing from Appendix B of the
  design document entirely and has been added — `BL-032`.
- Two conventions findings worth carrying: `util.uspSetObjectDescription` rejects
  `@ObjectType = 'COLUMN'`, columns being described by passing table and column together
  (`BL-026`), and `USER` is a reserved word, so the table is always `auth.[User]` (`BL-027`).

**What did not happen at the gate, and what happened the day after.** At the Phase 2 gate on
2026-09-19, `T-041` — MFA enrolment and confirmation — was **blocked** by `G-07` and was not
implemented: the key that wraps a TOTP shared secret had nowhere decided to live, a procedure that
enrols a factor has to write that secret somewhere, and guessing would have been the expensive kind of
guess. That was recorded rather than smoothed over, including its cost — fixture user `frank` sat
under a policy requiring MFA, held no factor, was refused `E-50109`, and could not be got out of that
state by anybody, which was itself a passing assertion in the test.

On 2026-09-20 management resolved it (`additionalRequirements-T-041.txt`, `PRE-02`, `BL-033`) and the
work was done: `T-041` complete, `T-112` added and complete, `G-07` closed, `R-03` closed. `frank` now
enrols a first factor from his own `E-50109` refusal and signs in, which is section 12 of the test —
eleven observations covering `E-50117` through `E-50123`. Two things are worth keeping from how this
went. First, the blocked row was worth writing: the decision arrived because the block was visible and
named an owner, not in spite of it. Second, the test that had documented the lockout as permanent is
the same test that now documents the way out, in the same file and the same numbering — nothing was
deleted to make the phase look cleaner than it was.

**What still cannot be tested, stated plainly.** Every `@SecretCiphertext` in the test file is random
bytes. A database test cannot tell a real ciphertext from noise, because the database holds no key —
which is the decision working, not a shortfall. The encryption itself is verified where the
application is tested, and `dave`'s factor is deliberately still inserted directly as `db_owner` so
that the experiments which *consume* a factor cannot be disarmed by a defect in the ones that
*create* one.

**Risk, as it turned out.** This phase was expected to be the most likely to overrun — the only
cryptography and the only cross-boundary protocol — and it came in at a third of estimate. The
reason is `D-08`: because the database never computes a hash and only ever decides what a verified
password *entitles* you to, the cryptography was never in the database's half of the work at all.
The design decision that looked like a purity argument was a schedule decision.

### Phase 3 — Authorization model · ~13 days estimated (12.25 across the fifteen tasks), 11.8 actual · **complete, 2026-09-20**

**Objective.** Permissions, roles, profiles, grants, and the derived table the predicate reads.

- `auth.PermissionCategory` and `auth.Permission` — done, in `050_auth_permission.sql`, with
  `PermissionDescription` and a denormalised `PermissionCategoryCode` held honest by a composite
  foreign key, which is what lets `CK_auth_Permission_CodeMatchesCategory` be row-local. **The 35
  catalogue rows themselves are not here:** seeding is `T-089`, Phase 6 — and that is not neutral,
  because `120` resolves permission ids out of this table (see Phase 4's exit note).
- `auth.Role` and `auth.RolePermission` — done, in `055_auth_role.sql`. Half of `INV-04` became
  **structural** here rather than procedural: `FK_auth_Role_OwnerTenant` is composite and references
  an unfiltered `UX_auth_Tenant_Id_Application` added to `030_auth_tenant.sql` by guarded `ALTER`,
  so a role cannot be owned by a tenant in another application's tree even when the row arrives from
  the seed script or from SSMS. `055` refuses to install if that constraint is absent. `BL-040`.
- `auth.UserProfile` — done, in `040_auth_userprofile.sql` alongside the `auth.User` that landed in
  Phase 2 (`T-046`, `BL-025`). Gained `UX_auth_UserProfile_UserTenantName` on top of the design's
  index list, because two identically named profiles at one tenant are indistinguishable in the
  switcher — `BL-036`.
- `auth.UserProfileRole` — done, in `060_auth_profile_role.sql`: the grant, carrying its own
  `ScopeTenantId`, `GrantedByProfileId` and `ExpiresUtc`.
- `auth.ProfilePermissionScope` and `auth.uspRebuildProfilePermissionScope` — done, in
  `065_auth_effective_permission.sql`, single-profile and whole-database.
- `auth.udfHasPermission` and `auth.tvfPermissionScope` — done, in `100_auth_functions.sql`;
  `auth.uspDemandPermission` — done, in `150_auth_query_procedures.sql`, which asserts
  `logs.uspRecordAuthorizationDenial` exists and throws without it, so the gate cannot install in a
  state where it is unable to record a refusal.
- `auth.uspSetSessionContext` and `auth.uspClearSessionContext` — done, in
  `105_auth_session_procedures.sql`, including the three-way already-set branch (DES §14.3). The
  procedure takes **`@SessionTokenHash`**, not the token: the design's sketch was wrong and is
  corrected in `BL-043`.
- `logs.AuthorizationChange` and `logs.AuthorizationDenial` — the tables came with Phase 2's
  `085_logs_auth_tables.sql`; the three recorder procedures are done, in `165_logs_procedures.sql`.
- **Also built, and not in the original list:** the `tvf` rename. All four table-valued functions in
  `100` are `tvf`-prefixed, not `udf` — the prefix states what a function returns, and the design
  contradicted its own naming rule for the predicates. `BL-041`.

**Exit criteria — all met.** Evidenced by `database/_tests/050_authorization_and_session.sql`, exit
0, 21 observations as intended, 3 notes, **0 failures**. *Materialization equals derived:* fourteen
mutations — grant, revoke, re-grant, role permission added and removed, scope moved, expiry
backdated, profile deactivated and reactivated, permission retired and restored — and after every
one the materialized scope was compared with the set derived longhand from DES §8.6 in **both**
directions, so a missing row (a false denial, an empty screen) and an extra row (a false grant,
which nobody complains about) are separately detectable. The comparison is written longhand rather
than by reusing the procedure's own query, so it is able to disagree with it. *`INV-03` holds.* *A
second `uspSetSessionContext`:* the same profile returns silently, a different profile raises
`E-50022` and changes nothing.

**Also learned, and stronger than the contract.** The five identity keys are set `@read_only = 1`,
and such a key cannot be re-set to another value, re-set to the *same* value, or nulled — `Msg
15664`, measured on this instance. So "one connection, one profile" is not a policy the procedure
could relax; a connection pool that hands a pooled connection to a second user is a defect the
database catches. Session context is also **not transactional**: a `ROLLBACK` does not unset a key.
`UI-36`, and it is why the session-context section has to be the last section in the test file —
running it spends the connection's identity.

**Two things found that the design had not written down.** `auth.uspDemandPermission` records the
denial it raises, so a caller that opens a transaction *before* demanding the permission loses the
denial trail to its own rollback — the ordering in DES §9 is now a requirement with an acceptance
criterion in Phase 7, not a style preference (`BL-042`, DES §9.3). And the audit columns are owned by
the `AFTER UPDATE` trigger, which overwrites whatever a statement supplied, so a procedure cannot use
`auditDeletedBy` to record who asked for a soft delete or why; that goes in the `logs` trail
(`BL-044`, `UI-37`).

### Phase 4 — Row-level security · ~8.25 days estimated, 7.6 actual · **complete, 2026-09-20; one test-integrity task added and closed 2026-09-21**

**Objective.** The predicate, the policy, the registry, and the bypass.

- `config.TenantScopedTable` and `config.ApplicationSetting` — came forward into
  `025_config_tables.sql` in Phase 2; the registry's two live rows are `dbo.CaseFile` and
  `dbo.CaseNote`.
- `auth.tvfTenantReadPredicate`, `auth.tvfTenantInsertPredicate`,
  `auth.tvfTenantUpdatePredicate` — done, in `100_auth_functions.sql`, `WITH SCHEMABINDING`, every
  `SESSION_CONTEXT` read `TRY_CAST` so a predicate denies a row rather than failing a query.
- `auth.TenantAccessPolicy` — done, built from the registry by `120_rls_policy.sql`: four predicates
  per registered table, `FILTER` once and `BLOCK` three times. A registry row is treated as a claim
  rather than a fact — the rebuild verifies the `TenantId` column exists and reports
  `@TablesSkipped`.
- `auth.uspBeginMaintenanceSession`, `auth.uspEndMaintenanceSession` and `rlsBypassRole` — done, in
  `105_auth_session_procedures.sql` and `005_schemas_and_roles.sql`, with a
  `MaintenanceBypassEnded` event added so the bypass window has a closing time as well as an
  opening one.
- The permission-id literal substitution, and the assertion that keeps it honest — done. Two
  corrections: the substituted value is a **list**, because one permission code has one row per
  application and a single id would have denied three applications out of four; and an empty
  catalogue resolves to the sentinel `-1` rather than to an omitted clause, so a database where
  `115` has not run **denies everything** instead of granting everything. `BL-039`, DES §10.2,
  `UI-35`.
- **Also built, and not in the original list:** `auth.uspRebuildTenantAccessPolicy`
  `@Action = N'Rebuild' | N'Drop'`, and `Invoke-PolicyDrop` in `Install-TemplateDatabase.ps1`. A
  function a live policy references cannot be altered at all (`Msg 3729`), so **every second
  deployment of an existing database would have failed** without an unbind step. The design filed
  this as a caution in §21.3; it is a deployment blocker. `BL-038`, `UI-34`.
- **Also built:** the `logs`-side counterpart of `INV-11`. The conventions' own permission script
  grants all four table verbs on `SCHEMA::logs`, so the four audit trails were directly writable by
  `applicationRole` even though `SCHEMA::auth` was denied. `170_permissions.sql` now denies `INSERT`,
  `UPDATE` and `DELETE` on each trail table, object by object, and asserts all twelve.
  `BL-048`; the standing version of the problem was filed as `G-23`, **which came true in Phase 5**
  and was closed in the Phase 5–7 documentation pass by enumerating `sys.tables` instead of naming
  tables (`BL-066`).

**Exit criteria — all met.** Evidenced by `database/_tests/060_row_security.sql`, exit 0, 16
observations as intended, 3 notes, **0 failures**, across four case files and two notes sitting in
four tenants. Every cell of DES §10.3: read in scope and out (a profile scoped above sees three of
four rows), insert into the acting tenant and into two others (a sibling and a descendant, both
`Msg 33504`), update of a readable-but-not-writable row, and an attempt to move a row between
tenants. *A `db_owner` session with no context sees zero rows* — and it is in the test output, so
nobody meets it for the first time in production (`UI-18`).

**Two wrinkles worth carrying forward.** The tenant move is refused, but by the composite foreign
key with `Msg 547` **before** the block predicate is consulted, so the outer defence speaks the
wrong language and a UI mapping error numbers to messages must handle 547 on tenant-scoped tables
(`BL-045`, `UI-38`). And both maintenance procedures shipped with `logs.AuthenticationEvent.UserId`
and `UserName` NULL, which `CK_logs_AuthenticationEvent_Attributable` refuses — a defect that
survived two phases because nothing had ever reached their accepted path. Reaching it took a real
member of `rlsBypassRole`: a user `WITHOUT LOGIN`, created and dropped by the test. `BL-046`,
`UI-39`.

**One gap filed against the next phase.** `G-22`: the authorization hot path is the only unmeasured
path in the database, because a function cannot log and a per-row predicate must not try. `120`'s
closing report can say how many tables are protected and which permission ids are in the
predicates, and cannot say what any of it costs. Recorded now because the shape of the resolution
constrains Phase 5. **Closed there**, by `175_perf_instrumentation.sql` (`T-070`), in the shape this
paragraph predicted: the probe writes from the *procedure* and never from a function.

**One check in the exit-criteria test could not do its job, and that was only found by running it
(`T-121`, `BL-075`).** `UI-35` is the standing warning that the predicates carry the permission ids
as **literals**, so a catalogue change without a rebuild leaves them resolving the old list and
nothing complains. Section 4 of `_tests/060` exists to catch exactly that, and it caught it by
`CHARINDEX`ing a rendered id list — built by its own `STRING_AGG`, in no stated order — against the
deployed module definition, which `120_rls_policy.sql` renders ascending. Two `STRING_AGG` calls were
being asked to agree on an order neither of them states. Once the catalogue reached six `Data.Read`
rows they stopped agreeing: the predicate said `IN (1, 5, 26, 61, 96, 131)`, the test looked for
`IN (61, 131, 96, 1, 5, 26)`, and the run declared the policy stale while printing the fixture's own
id inside the list it said was missing. The false alarm is not the worst of it — in that form the
check could **never** have reported an id the predicate still enforces that is no longer a live
permission, which is the whole of `UI-35`. It now lifts the list out of the definition and compares
it with the live rows by `EXCEPT` in both directions, with the fixture's own id asserted separately.
A rendered string was the wrong instrument for a question about sets.

### Phase 5 — Performance validation and hardening · ~6 days estimated, 3.8 actual · **complete, 2026-09-20**

**Objective.** Evidence that the model is fast enough, gathered before anything is built on top
of it.

- Generate realistic volumes — done, `database/_perf/T069_load_volumes.sql`, on a **separate
  database**: `testTemplateBoot` at 1,050 tenants, 5,000 profiles, 57,342 expanded scope rows and
  200,000 case files, and later taken to **10,650 tenants** for `T-072`.
- Measure the predicate's effect — done, `_perf/T070_measure_predicates.sql`. Point read **8 logical
  reads against 3** unprotected. Range scan **1,007 against 6**. The large aggregate is where it
  shows: 1,002,655 reads for the in-scope shape and 1,392,655 for the broader one, against 1,405
  unprotected. `auth.udfHasPermission` is 7 reads, `auth.uspDemandPermission` 12.
- Measure `auth.uspRebuildProfilePermissionScope` — done, `_perf/T071_measure_rebuilds.sql`. One
  profile, 45.4 ms and 1,500 reads. A thousand single-profile calls, 40,555 ms. **All 5,000
  profiles in one call, 181 ms.**
- Measure `auth.uspRebuildTenantClosure` at the expected count and at ten times it — done, in the
  same file, which is why the tenant count on `testTemplateBoot` ends at 10,650 rather than 1,050.
- Confirm the plan shape — done, and this is the result that decides `D-07`. On **all three** access
  patterns: semi-joins 1, scope seeks 1, scope **scans 0**, closure seeks 1, closure **scans 0**. The
  predicate is a seek on the inner side of a semi-join at every volume measured, which is what the
  design claimed and had never shown.
- **Also built, and not in the original list:** the resolution of `G-22`, filed at the end of Phase 4
  precisely because it constrains this phase. The hot path now instruments itself by *sampling* —
  two settings seeded by `115` section 6 — and the probe's own cost was measured rather than
  assumed: the configuration read alone is **5 logical reads against the demand's own 12**, so 42% of
  a permission check in the measure this phase decided to argue from. On microseconds it flatters
  itself at 18%, and the reads figure is the one that survives a busier server. Either way it is the
  argument for **sampling** instead of logging — 42% of a check taken occasionally is a rounding error
  in aggregate, and an unconditional probe would have made this number the answer rather than a
  footnote. It is in the record, with both ratios and the reason for preferring one.
- **Also built:** `docs/30-performance-measurements.md` (PERF-AUTH-001). The plan said "numbers,
  written into the Build Log"; thirty numbers with plan shapes attached do not fit in a Build Log
  cell, and a number nobody can find again is a number that gets re-asserted from memory later.
  `BL-059` points at the document, and the document is the record.

**Exit criteria — met, with the method stated.** Microsecond figures on this hardware vary by up to
20% between runs and logical-read counts do not vary at all, so **every argument in PERF-AUTH-001
rests on reads** and the timings are reported as texture. `D-07` is a formal **GO** on that basis
(`M3`).

**The one number that came back badly is not a predicate cost.** It is `G-39`: the all-profiles
rebuild is **224 times** cheaper than the thousand single-profile calls that produce the same
result, and nothing in the procedure surface steers a caller towards it. The blunt instrument wins
and the API does not say so — a documentation and a signature problem, not a model problem.

**A caveat that travels with the GO.** `testTemplateBoot` was left standing at 10,650 tenants. Any
further predicate measurement must **drop and rebuild it first**, because figures taken against the
expanded tree are not comparable with the ones recorded here.

**The fallback was not needed.** The fully-expanded `(profile, permission, tenant)` table that
`D-07` rejected stays rejected, and with it the tenant-move invalidation cost. Keeping this phase
early is what made that a cheap conclusion rather than a cheap hope.

### Phase 6 — Administration, query and the UI authorization surface · ~30.5 days estimated, 25.5 actual · **complete, 2026-09-20; seven tasks added and closed 2026-09-21**

**Objective.** Everything the UI project needs in order to start.

- Tenant, user, profile and role procedures — done, in `125_auth_tenant_procedures.sql`,
  `130_auth_user_procedures.sql`, `140_auth_profile_procedures.sql` and
  `145_auth_role_procedures.sql`. `auth.uspAssignRoleToProfile` carries all four clauses of `INV-05`,
  the `INV-06` self-grant guard, **and the authority actually relied on**, recorded on the grant
  rather than re-derived later.
- `uspSwitchProfile`, with step-up — done, and it is the procedure that taught the phase its
  hardest lesson. **It threw `E-50022` on every call, after succeeding**: `sp_set_session_context`
  with `@read_only = 1` cannot be set twice on one connection, so re-establishing context after a
  switch is not merely unnecessary, it is impossible. It now returns its two result sets without
  touching context, and hands the navigation read the new profile explicitly instead of reading it
  back out of `SESSION_CONTEXT`. The consequence is a contract, not a defect: the switching
  connection is **spent**, and a sign-in costs two connections for the same reason. `BL-057`,
  `G-36`, DES §14.3.
- `auth.UiElement`, `auth.UiElementPermission`, `auth.uspGetNavigationForProfile`,
  `auth.uspGetProfileContext` — done, in `075_auth_ui_catalog.sql` and
  `150_auth_query_procedures.sql`, with `auth.uspCheckPermission` as the non-throwing counterpart of
  the demand.
- The registration procedures for Variant 3 — done, `155_auth_registration_procedures.sql`, and
  `auth.uspGrantTenantDefaultRoles` was **extracted** out of `auth.uspCreateProfile` to serve them.
  `auth.uspRegisterExternalUser` cannot call `uspCreateUser` or `uspCreateProfile` — both demand a
  permission and a stranger has no session to demand it of — so it writes the two rows directly; but
  it does not re-implement default-role resolution, because two implementations of that rule would
  diverge and only one of them would be tested. `BL-056`.
- `auth.vwProfilePermission` and the other views — done, `095_auth_views.sql`.
- `115_seed_reference_data.sql` — done. **Per application**, because `auth.Permission` and `auth.Role`
  are both `ApplicationId`-scoped (`D-09`): 35 permission codes in 7 categories, **14** baseline roles,
  44 role-permission rows, a 26-element starter UI catalogue with 50 element-permission rows, the
  application row, the registry rows and **the root tenant**. Tenant types are *not* seeded here —
  `030_auth_tenant.sql` owns them, and a second `MERGE` would be the place the two lists drift
  (`BL-021`).
- `900_bootstrap_first_admin.sql` — done, refusing to run if any profile exists (`E-50080`), taking
  the verifier through the **environment** rather than `-v` because a PHC string carries commas and
  equals signs (`UI-41`, `UI-42`), and defaulting it never.

**Three divergences worth reading before extending any of it.**

- **The root tenant moved and the policy did not.** `115` creates the root tenant; `900` *asserts*
  it and refuses with `E-50085` if it is absent — but `900` still writes the root **authentication
  policy**, because `uspCompleteLogin` fails closed to `RequireMfaForLocal = 1` and a bootstrap that
  wrote no policy would produce a first administrator who can never sign in. `BL-051`, `G-25`; the
  `RequireMfaForLocal = 0` it writes is `G-37`, and it blocks go-live.
- **Settings are seeded in three files with no overlap.** `025_config_tables.sql` seeds the
  **twenty-three** authentication, authorization and registration tunables; `115` section 6 seeds
  exactly **four**, including the two probe-sampling settings Phase 5 needed and the
  `Ui.CatalogueVersion` digest; and `175_perf_instrumentation.sql` seeds the probe burst count, the one
  key that is meaningless without the code in that file to read it. **Twenty-eight in the deployed
  database.** `BL-050`, and `BL-072` for the correction: the figures above were measured against
  `config.ApplicationSetting` on 2026-09-21 after four artefacts were found still saying "eighteen"
  and "three", two revisions after it stopped being true. A setting seeded in two places is a setting
  with two defaults and the second one to run wins silently — hence *no overlap*, asserted rather than
  intended. `Ui.CatalogueVersion` is the single deliberate exception to `115`'s own rule that it never
  overwrites an existing value, because it is a fact about the catalogue rather than an operator's
  tuning.
- **Two audit vocabularies, and the check constraints arbitrate.** The first draft wrote
  `UserCreate` and `UserDeactivate` to `logs.AuthorizationChange` and the `ChangeType` constraint
  **refused both**; they belong in `logs.DataChangeLog`. `ProfileSwitch`, conversely, was missing
  from the `EventType` vocabulary and was added, because a switch changes the acting tenant and is
  therefore an authentication event. `BL-054`, `BL-055`, `G-29`.

**Also built, and not in the original list.** `docs/40-ui-handoff-m4.md` (UIH-AUTH-001) — the `M4`
package as one file rather than a pointer to six, with full result-set column lists, the sign-in
wire sequence, the connection contract as five rules, and the error registry regrouped by *what the
UI should do* rather than by number (`BL-062`, `T-095`). And `database/_tests/080_error_catalogue.sql`,
which is more than the exit criterion asked for: **96** probes across **seven** connections — 91 when
the phase closed, nineteen more added on 2026-09-21 and some existing ones consolidated — and a
section that measures the registry against `sys.sql_modules` instead of asserting it.

**Exit criteria — both met, and both re-run at the Phase 5–7 closeout rather than quoted.**
`database/_tests/070_variants_end_to_end.sql`, once per variant, all three **PASS**: each variant
clones the catalogue (35/35, 17/17, 44/44), creates its tenants through `auth.uspCreateTenant` with
**zero** closure pairs crossing an application boundary, resolves *this* application's permission ids
into the predicates, and does real case work under row-level security at a tenant minutes old —
starting from bootstrap, through the procedures, with the direct table writes confined to the two
places the database has no procedure for and which the test names. `VARIANT3` additionally registers
an external organization, approves it and staffs it. `database/_tests/080_error_catalogue.sql`:
**122** numbers a shipped module can throw, **117** ever recorded, **96** raised on purpose, **6**
unobservable with a stated reason, **none unaccounted** — 111/106/88 when the phase closed, re-measured
on 2026-09-21 after eleven numbers were added, and the point of re-running it rather than adding to
the figures is that every one of the eleven became a number something actually raises. A registered
refusal that does not refuse is the worse of the two faults.

**Seven gaps filed from this phase, three of them blocking — and six of the seven are now closed.**
`G-30`, no step-up was demanded where no policy row exists; `G-42`, no shipped procedure wrote
`auth.UserCredential`, so after the bootstrap the only supported route to a password was the one the
bootstrap took; and `G-37`, above, **which is the one still open** and the only go-live blocker left
from this phase. Then `G-24` (no registration throttle), `G-27` (user permissions deliberately not
tenant-scoped), `G-32` (no number for a malformed element inside a well-formed bulk array) and `G-43`
(two per-tenant configuration tables with no procedure to write them). All six closed on 2026-09-21
under `T-113`–`T-119`, together with `G-12`, `G-18` and `G-21` from earlier phases.

**Four of the six were delivered differently from what their rows proposed, and in each case the row
was wrong rather than the implementer inventive.** `G-42` asked for two procedures and got four,
because `D-08` means the database can no more *compare* a password than receive one — so the
reuse check had to become a read procedure plus an argument, exactly as sign-in is
`uspGetLoginVerifier` plus a verdict. `G-43` asked for a `Tenant.Manage` permission that is not in
Appendix A and got `Tenant.Update`, with `Authz.RoleAssign` added to the default-roles writer because
a default-role list is a standing grant rather than a label; `Config.Manage` was considered and
rejected, because it would have made a per-tenant screen a platform-administrator screen. `G-18`
asked the *application* to assert the catalogue version at start-up and the **database** now refuses a
mismatch instead (`E-50230`), because a control the caller may skip is not a control and a catalogue
can be extended while an application is running. And `G-32` named `auth.uspAssignRolesToProfiles`,
which has never existed and never will — `INV-04`, `INV-05` and `INV-06` are each evaluated against
the grant in hand and a set-based `MERGE` over profiles could not check them — as did Appendix B's
`E-50046` row, for four phases, because nothing executes a document.

**`G-24` closed and `G-06` did not, and that pair is the honest part.**
`auth.uspRecordRegistrationAttempt` counts arrivals per address over `auth.RegistrationAttempt` and
both public entry points refuse a crossed threshold as `E-50068`; the arrival is recorded **before**
any other validation, because a malformed request is the cheapest flood to generate. That is one of
`G-06`'s three controls. The other two — edge rate limiting and a challenge on the form — are on the
far side of a network boundary this database does not reach, so `G-06` remains open and still blocks
Variant 3 go-live, stated in DES §16.4 under its own heading and in UIH-AUTH-001 §8 item 9 rather than
only in a spreadsheet cell.

**This is the phase whose exit criterion is another team's start condition**, and it held: no task was
added to it *before* the freeze, and the two documents it produced are both contracts rather than
commentary. Seven tasks were added after it, which is a different thing — they closed gaps the phase
had itself recorded, and one of them amended the frozen contract to v1.1 through the change-control
rule the contract carries.

### Phase 7 — Demo domain conversion and worked example · ~10 days estimated, 7.95 actual · **complete, 2026-09-20; three scenario-test tasks added and closed 2026-09-21, one filed open**

**Objective.** `dbo.CaseFile` and `dbo.CaseNote` demonstrating the pattern a real domain table
follows.

**Reopened once, on 2026-09-21, and closed again the same day.** `test_scenario_1.txt` arrived after this
phase had been signed off and belongs here rather than in Phase 8, because what it asks for is a *worked
example at customer scale*: a named agency, thirteen cohorts, 12,830 users, doing their jobs. `T-122` is
the loader, `T-123` the prover, `T-124` this phase's share of the write-up — 4.5 days estimated, 4.25
actual, all three Complete. `T-129` closed on 2026-09-21 and is described below; it was a small thing with an awkward
implication: `Data.Execute` is seeded, granted and enforced **nowhere**, so of the five verbs the
scenario spells out for CRUD — read, update, insert, delete and execute — this phase's demo domain can
only prove four. The permission exists in exactly one place in the codebase outside the seed script, and
that place is a comment.

- The missing `trg_au_updt_` triggers — done, `F-01` closed. Named to the conventions, `AFTER
  UPDATE`, set-based over `inserted`, and guarded so a trigger-driven update cannot recurse. The
  audit columns existed before this phase and **lied**.
- Audit attribution from `SESSION_CONTEXT('AppUser')` on insert as well as update — done, `F-02`
  closed, as a column `DEFAULT` so a row arriving by an unanticipated route is still attributed.
  Writing the strong version is what exposed `G-41`: every `auth` table defaults `auditCreatedBy` to
  a bare `ORIGINAL_LOGIN ()`, so **the schema holding the authorization state has the weaker
  attribution of the two**. Found by putting the two side by side, which is the only way it was ever
  going to be found.
- `TenantId` immutability, `E-50011` — done, by an `AFTER UPDATE` trigger *alongside* the `BLOCK
  AFTER UPDATE` predicate, because the predicate gives the caller `Msg 33504` and the trigger gives
  them a number and a sentence. The measured subtlety, now in Appendix B: **a declarative constraint
  on the same column wins the race**. Where a composite foreign key already pairs `TenantId` with
  another column the engine checks the key before any `AFTER` trigger fires and the caller sees `Msg
  547`, so `E-50011` is reachable only on a row whose composite keys are all `NULL` — which is
  exactly what `_tests/080` probes it with.
- `config.TenantScopedTable` registration and the policy applied — done, through
  `auth.uspRebuildTenantAccessPolicy`. These two rows are the **only** live registry rows, on
  purpose: a demonstration that protects everything demonstrates nothing about the registry.
- `180_dbo_application_procedures.sql` — done, as the reference implementation of DES §14:
  `@SessionTokenHash` first, context set, permission demanded, rule 8 `TRY`/`CATCH`, instrumentation
  inside the transaction. It installs at **manifest step 35, before `120_rls_policy.sql`**, which
  looks backwards and is right — deferred name resolution lets a procedure compile without its
  policy, while a bound policy freezes the shape of `dbo.CaseFile` and refuses the schema-bound
  change with error `3729`. The cost is a documented one-step window in which these procedures
  enforce authorization without row security. `BL-058`.
- The file's own header and comments — done. A demo domain whose comments describe a different
  design is worse than no demo domain.

**Also built, and not in the original list: `135_audit_triggers.sql`.** The plan asked for triggers
on the two demo tables and said nothing about the rest of the template, which had the same defect for
the same reason. The script takes the whole of `auth`, `config`, `dbo`, `logs` and `util` — **thirty-five
tables** as deployed — and requires an update trigger on **thirty-four** of them, which is exactly how
many exist. The file is **generated from the catalog** rather than hand-listed, so a table added
later gets a trigger by being a table and not by being remembered. It carries two script-raised
assertions: `E-50210` asks *does a trigger exist* for every table that needs one, and `E-50211` asks
*does it do the job* — triggers present but not stamping the full audit block. The second exists
because the first can pass on a trigger that does nothing. There is exactly **one exemption**,
`logs.ExecutionLog`, and it is a row in a table inside the script rather than a predicate in a
`WHERE` clause, so it appears in the report and has to justify itself: single-writer, and a trigger
there would fire inside every procedure's own instrumentation including the `CATCH` block, where an
error it raised would **replace the error being reported**.

**Exit criteria — one met, one carried.** A developer reading only `090_dbo_application.sql` and
`180_dbo_application_procedures.sql` has the worked example: what `TenantId` means, why there is no
`DELETE` anywhere, which triggers exist and why, which composite foreign keys are load-bearing for
`INV-12`, and the full §14 call shape. The other criterion says *the two tables pass
`950_verify_deployment.sql`* — and `950` is `T-104`, **unwritten**. That criterion is therefore
**carried into Phase 8** rather than claimed here; it is the only exit criterion in the project so
far that depends on an artefact from a later phase, which is a planning error worth naming rather
than quietly satisfying with a different test.

**Two gaps filed against Phase 8 from the demo domain, and both are about the *model*, not the
code.** `G-38`: `Data.SoftDelete`, `Data.Restore` and `Data.Approve` are all implemented as
`UPDATE`, so a single block predicate can only test `Data.Update` — which is why `DATA_STEWARD` and
`APPROVER` must carry it, and why trimming it to tidy up would break soft delete with an error
naming neither. `G-40`: **approval is not delegable across tenants**. A central approver given one
`AGENCY` profile reads every program's records correctly and fails on the first approval, because
the composite foreign keys demand a profile *at the row's own tenant*. Both are stated in DES v1.6
and both are settled when profiles are created, not when somebody first tries to approve something.

### Phase 8 — Verification, documentation and handoff · ~7 days

**Objective.** Someone who was not here can deploy it, understand it, and extend it.

- `950_verify_deployment.sql`, with every assertion in DES §21.4.
- A full deployment onto a clean database, from empty, twice.
- Fill in the Build Log for real — every divergence between this plan and what was built.
- Close out the Gaps workbook: which gaps were closed, which remain, which were added.
- Reconcile the Traceability worksheet: every design section maps to an artefact.
- Handoff package for the UI project (§8) — **delivered early**, at `T-095`, as
  `docs/40-ui-handoff-m4.md`. `M4` was another team's start condition, so it could not wait for the
  last phase; what remains here is reconciling it against whatever Phase 8 changes.

**What this phase inherits, stated so it is not discovered.** Three of its eight tasks are now
carrying work filed from earlier phases rather than only their own:

- **Phase 7's second exit criterion**, which cites `950_verify_deployment.sql` and therefore could
  not be met in Phase 7. `T-104` now owes two things: the assertions of DES §21.4, *and* the
  demo-domain checks Phase 7 was supposed to have passed.
- **`G-37`, which blocks go-live and is the reason `950` is more than a formality.** The bootstrap
  writes a root authentication policy with `RequireMfaForLocal = 0` so the first administrator can
  sign in and enrol a factor; policy inherits, so that row is the effective policy for every tenant
  beneath it that has not written its own. Until `950` asserts it has been raised to 1 **and fails
  when it has not**, the only control is a paragraph in DES §16.3, which is a fair description of how
  much it is worth.
- **Two gaps that are open because closing them is code and not prose**, down from six on
  2026-09-21: `G-31` (ten procedures re-ordered so the permission demand precedes argument validation
  — and the rule stated *after*, not before, or DES §13.2 becomes wrong in a new way) and `G-41` (a
  `DEFAULT` migration across every `auth` table). `G-30`, `G-32`, `G-42` and `G-43` were the other
  four and were paid under `T-113`–`T-119`; both survivors are correctness debts rather than go-live
  conditions, which is why they were the two left. Each already has its absence stated in the design
  section a reader would look in, so the documentation is paid for when the code arrives — and `G-32`
  proved why that ordering matters in the other direction too: its number had to be **raised** before
  it could be registered, because registering `E-50180` first would have put a permanently unaccounted
  row in the `_tests/080` ledger, which is a report that always fails.
- **`G-44`, filed on 2026-09-21 by a test's own cleanup.** Nothing deletes an
  `auth.TenantAuthenticationPolicy` row, so a tenant cannot be returned to inheriting its parent's
  policy; `_tests/050` had to reach past the procedure surface and hand-soft-delete one to keep
  measuring the no-policy path. `Low`, blocks nothing, and it is here because the way it was found is
  the argument for it: a test that cannot undo what it did through the shipped surface has found a
  missing procedure.
- **`G-48`, filed on 2026-09-21, `Critical`, and the second open gap of that severity.** Nothing writes
  `auth.UserSession.ElevatedUntilUtc`. `uspDemandPermission` refuses a privileged profile with `E-50052`
  and tells the caller to re-authenticate; there is no procedure to re-authenticate *into*. Measured, not
  inferred: 0 of 271 sessions in `testTemplate` have ever been elevated, 2,490 users hold a privileged
  profile across the scenario's four runs, and 169 of 169 tenant policies require step-up — as does the
  shipped default. Every platform administrator and every "can assign profiles" cohort in scenario 1 is
  locked out of the profile they exist to hold. `T-125` is the resolution, `auth.uspElevateSession`, and
  it is one day of work sitting in front of a whole class of user. **Do not close it by lowering
  `RequireStepUpForPrivileged`** — that is the workaround the five fixtures took accidentally, and it is
  the reason this was invisible until a customer-shaped population walked into it.
- **`G-51` and `G-50`, filed the same day against Phase 2, `High` both.** A session that has signed in
  but not yet chosen a profile cannot list the profiles it owns — there is no procedure for it — so **the
  hat menu, the first authenticated screen every one of the scenario's 12,830 users sees, cannot be built
  from the shipped surface**; worse, `uspDemandPermission` diagnoses that state as "a server-side defect,
  not a permission problem", which sends a UI developer looking for a bug that is not there. And every
  one of the 73 `ProfileSwitch` audit rows the prover produced carries `UserSessionId` NULL, so the trail
  that exists to answer *which session changed hats* cannot answer it. `T-126` and `T-127`, 1 day
  together.
- **`G-45`, `G-46`, `G-47` and `G-49`, filed the same day, `Medium`.** Two of them are seed data and are
  the reason the other five were findable at all: no seeded role means "can do the work" and none means
  "can assign profiles", so the loader had to invent `CRUD_ACCESS` and `PROFILE_ASSIGNER` from the
  permission pool. A fixture that builds its own profiles can never discover this; a population has no
  choice but to. `G-45` is `Data.Execute`, enforced nowhere. `G-49` is the honest limit on all four
  passing runs — every test in this repository is one serial `sqlcmd` session, so **nothing here has ever
  measured two users at once**, and "12,830 users work" is not among the things four green runs prove.
  `T-128`–`T-130`, 3 days, and `T-130` belongs in Phase 8 with the rest of the load work.

**Exit criteria.** Two consecutive clean deployments. `950_verify_deployment.sql` exits zero.
Every row of the Traceability worksheet resolves. No gap is open without an owner.

---

## 5. Milestones

| | Milestone | After | Meaning |
|---|---|---|---|
| M1 | Conventions baseline proven | Phase 0 | **Reached 2026-09-19.** The skill's scripts have been run against `MDE-55TT2J4\testTemplate`, twice, and work; the second pass changes nothing, and an instrumented procedure writes to `logs.ExecutionLog` on every path |
| M2 | Model is enforceable | Phase 4 | **Reached 2026-09-20.** A tenant cannot read another's rows, and the claim is now measured: `database/_tests/060_row_security.sql` walks every cell of DES §10.3 against four case files in four tenants, each refusal expected **by number**, and a `db_owner` connection with no session context sees zero of them. Two caveats travel with it and neither weakens the claim: the catalogue is unseeded until `T-089`, which makes the predicates deny *everything* rather than permit anything (`UI-35`), and no procedure is yet obliged to call `auth.uspDemandPermission` at step 5 (`G-05`, Phase 7) |
| M3 | Performance accepted | Phase 5 | **Reached 2026-09-20. `D-07` is a formal GO and the design is locked.** The derived-closure model was measured at 1,050 tenants and again at 10,650, and the plan shape holds at both: semi-joins 1, scope seeks 1, scope **scans 0**, closure seeks 1, closure **scans 0**, on all three access patterns. A protected point read costs **8 logical reads against 3**. The fully-expanded `(profile, permission, tenant)` alternative stays rejected, and with it the tenant-move invalidation cost. Two caveats travel with the GO and neither reverses it: the large aggregate is where the predicate is genuinely expensive — 1,002,655 reads against 1,405 — so a reporting path over a protected table should read through `rlsBypassRole` and filter explicitly rather than lean on the net; and `G-39`, the rebuild surface that is 224× cheaper used one way than the other, is an API problem rather than a model one. `docs/30-performance-measurements.md` is the record |
| M4 | UI contract frozen | Phase 6 | **Reached 2026-09-20, at `T-095`.** `docs/40-ui-handoff-m4.md` (UIH-AUTH-001) is the frozen surface: three contract procedures with full result-set column lists, the sign-in wire sequence, the connection contract as five rules, and the error registry regrouped by *what the UI should do* rather than by number. It is one document rather than a pointer to six, deliberately — a handoff assembled by reference is a handoff whose reader has to reconcile six versions. Frozen is not finished, and **v1.1 on 2026-09-21 is what that looks like when it works**: `G-42` meant the UI had no password-setting procedure to call, `110` now carries four, and §8 says so rather than being quietly edited. The amendment went through §10's change-control rule — a design change first, then a Build Log entry (`BL-071`), because an amendment that skipped it would have proved the rule optional on the first occasion it applied. `UI-40`–`UI-44` were all added after the document was written |
| M5 | Template complete | Phase 8 | Deployable by someone who was not here |

M2 and M3 were the two that carried a formal go/no-go, and both passed. M3 was the last point at
which reversing `D-07` would have been cheap, so it was taken as a decision rather than a reading:
the numbers were written into `docs/30-performance-measurements.md` first, the plan shapes attached,
and the GO recorded against them. `G-22` — filed at the end of Phase 4 precisely so that M3's
instrumentation was designed before the benchmarking rather than improvised during it — was resolved
in the phase it constrained, and the sampling probe's own cost was measured alongside everything
else rather than excluded from the figures it produced.

**`M5` is the only milestone left, and it now carries one thing the plan did not give it.** Phase 7's
`950` criterion is inherited, so `M5` is no longer *only* "deployable by someone who was not here" —
it is also the first point at which the demo domain's own exit criterion is satisfied by evidence
rather than by argument.

---

## 6. De-referencing the conventions skill

The `ponytail-sql-objects` skill was taken from another project and carries that project's
examples. The requirement is that it stand on its own so it can be dropped into any repository
without explaining which parts are illustration.

This is Phase 0 work, kept small deliberately:

- Remove named references to another estate's scripts, databases, servers and logins.
- Keep the worked examples (`dbo.FacilitySource`, `dbo.Permit`) — the skill's own README argues,
  correctly, that a template with the concrete parts stripped out stops showing how the pattern
  is applied. What changes is that they are labelled unambiguously as illustrations belonging to
  the skill, not as artefacts of some other project the reader is expected to know about.
- Remove the cross-references to files that do not exist in this repository, or restate what they
  demonstrate inline.

**What is deliberately not changed.** The rules. This is a de-referencing exercise, not a
revision of the conventions; altering a non-negotiable while removing a filename is how a
convention quietly loosens.

---

## 7. Findings carried in from the source material

Discovered while reading the existing artefacts. Each is a task in the tracking workbook.

| | Finding | Where | Consequence |
|---|---|---|---|
| F-01 | `090_dbo_application.sql` creates two plain tables and gives neither a `trg_au_updt_` trigger | the demo domain | The conventions require one on every plain table. Without it an `UPDATE` leaves `auditModifiedBy` and `auditModifiedDateUtc` at their insert-time values, and a soft delete records neither who nor when. The skill's own troubleshooting table lists this exact symptom |
| F-02 | `auditCreatedBy` defaults to `ORIGINAL_LOGIN ()` | every table built from the template | Under a pooled application login that is the application's name on every row. The `AFTER UPDATE` trigger already resolves `SESSION_CONTEXT('AppUser')` correctly; `INSERT` has no equivalent, so the procedures must set it — DES §14.4 |
| F-03 | The demo domain references `logs.DataChangeLog`, `config.TenantScopedTable`, `auth.Tenant` and `auth.UserProfile` as existing | file header and section 5 | They did not exist in this repository. This design defines all four, so the references become true rather than aspirational |
| F-04 | The demo domain's closing report queries `config.TenantScopedTable` | section 5 | Correct and useful — kept, and it is the origin of the registry-driven policy in DES §10.1 |
| F-05 | `950_verify_deployment.sql` is referenced but absent | demo domain header | Now a Phase 8 deliverable with an explicit assertion list |
| F-06 | Every documented `sqlcmd` line in the project, including the conventions skill's own README, omits **`-b`** | everywhere | Without it `sqlcmd` exits 0 even when the batch raised an error, so any scripted deployment loop reports success for a run that failed half way through. Found while writing the runner; corrected in the runner and in this repository's README. `BL-013` |
| F-07 | The conventions skill's documented install order runs `permissions.sql` before anything creates the roles it grants to | `references/external-dependencies.md` | Every grant is guarded on the principal existing, so the whole permission model would apply to nobody, silently. `005_schemas_and_roles.sql` now precedes it. `BL-012` |

F-01 and F-02 are the two that would have shipped silently. Neither raises an error; both produce
an audit trail that looks complete and is not.

**Both were closed in Phase 7, and both closed wider than the row describes.** `F-01` asked for two
triggers on the demo domain; `135_audit_triggers.sql` generates them from the catalog across five
schemas — thirty-six triggers over thirty-seven tables, re-measured from that script's own report on
2026-09-21 after the gap-closing pass added two tables — with one documented exemption that has to
justify itself in the report (`T-096`, `T-101`). `F-02` asked for attribution
on insert; it was done as a column `DEFAULT` so that a row arriving by a route nobody anticipated is
still attributed — and writing the strong expression next to the weak one is what surfaced `G-41`,
which is that every `auth` table still carries the bare `ORIGINAL_LOGIN ()`. So the finding is closed
where the plan pointed and *open* one schema over, in the schema that holds the authorization state.
`F-05` is the only one of the seven still open, and it is `T-104`.

---

## 8. Handoff to the user interface project

The UI project is a separate template with its own plan. This plan's obligation to it is a
contract, **delivered at M4 on 2026-09-20 as `docs/40-ui-handoff-m4.md` (UIH-AUTH-001)**. The table
below is the obligation; the handoff document is the discharge of it, and it is one file rather than
a pointer to these six rows, because a contract assembled by reference is a contract whose reader has
to reconcile six versions of it. Read the handoff; this table says what the handoff is answerable
for.

| Delivered | What it is for |
|---|---|
| `auth.uspGetProfileContext` | The persistent header the requirement asks for by name — user, profile, tenant, full tenant path |
| `auth.uspGetNavigationForProfile` | Screens, tabs and commands with `CanView` / `CanEdit`, filtered |
| `auth.uspSwitchProfile` | The profile switcher, returning new context and navigation in one round trip |
| DES Appendix B | The error-number registry the UI branches on |
| `workbooks/ui-gotchas.xlsx` | The things that will otherwise be found the hard way |
| DES §14 | The calling contract: session token first, `CommandType.StoredProcedure`, one connection one profile |

**Two gotchas decide design rather than describe behaviour, and they were flagged before M4 for that
reason.** `UI-36`, because "one connection, one profile" is enforced by a read-only session key and
not by a convention, so a data-access layer that keeps long-lived connections is illegal rather than
discouraged; and `UI-33`, because the function that answers "where does this profile have authority"
deliberately does not answer "where may they act today", so a tenant picker built from it offers
organizations the user will be refused at after the click. Both are cheap to honour now and expensive
to retrofit.

**Three things the UI project should know that the freeze does not soften.** The connection cost is
real and is not a defect: a sign-in costs two connections and a profile switch spends the one it was
called on, because `sp_set_session_context @read_only = 1` cannot be set twice on a connection
(`G-36`, `UI-36`, DES §14.3). Row-level security is the **net and not the `WHERE` clause** — every
query against a tenant-scoped table must still filter by tenant itself, or it is correct and slow
(`UI-40`, and `R-10` is what that costs at volume). And the catalogue version must be read at build
time and passed on every navigation call: `@ExpectedCatalogueVersion` is **optional in the signature
and mandatory in practice**, so a build that never passes it renders a menu without complaint and is
back in the state `G-18` was filed for, where a catalogue drift produces no error anywhere for anybody
(`UI-43`, `E-50230`). What is no longer on this list is the password surface — `G-42` closed on
2026-09-21 and `110` carries `uspSetPassword`, `uspGetPasswordChangeContext`, `uspChangePassword` and
`uspExpireCredentials` — but two properties of it belong here in its place, because they look like
defects and are not: the expiry count **goes negative** past the deadline and the warning **stays up**,
because `MustChangePassword` is set by a batched sweep and a header that went quiet in the interval
would go quiet at the one moment the user has to act (`UI-44`). UIH-AUTH-001 §8 records what is still
missing where the UI team will look rather than only here, and after this pass the largest entry on it
is `G-06`: no Variant 3 deployment should expose a public registration page in production until edge
rate limiting and a challenge exist.

**The dependency runs one way.** The UI project may not require a change to the authorization
model without that change coming back through this design. The reason is `P-02`: the moment a
screen needs a role name, the model that makes role definition delegable has been broken.

---

## 9. Risks

| | Risk | Likelihood | Impact | Response |
|---|---|---|---|---|
| R-01 | ~~RLS predicate performance forces `D-07` to be reversed~~ **Retired 2026-09-20** | — | — | It did not occur. Measured at 1,050 tenants and again at 10,650: scope scans 0, closure scans 0, a protected point read at 8 logical reads against 3, and `D-07` a formal GO at `M3` (`docs/30-performance-measurements.md`, `BL-059`). Putting Phase 5 before the bulk of the work is what made this a three-day answer instead of a Phase 8 discovery, and the response is retired rather than merely unused. What the register carries forward instead is the *shape* of the cost the measurements did find: the predicate is cheap per row and expensive per million, so a reporting path over a protected table is an `rlsBypassRole` conversation and not a tuning one — `R-10` |
| R-02 | ~~The conventions skill's scripts fail on first real execution~~ **Retired 2026-09-19** | — | — | They did not. All four installed clean on `MDE-55TT2J4\testTemplate` and converged on a second pass. The first run produced four Build Log entries (`BL-015`–`BL-018`) and no script changes |
| R-03 | TOTP key management (PRE-02) is unresolved at production | ~~Occurred 2026-09-19~~ **Closed 2026-09-20** | High | It occurred exactly as predicted and was resolved in a day. Management chose application-side envelope encryption under a TPM-backed CNG key (`BL-033`); `T-041` is complete, `T-112` built the enrolment surface, `G-07` is closed, and `frank` now enrols from his own refusal and signs in. What the risk register carries forward is not this risk but its residue: the key is machine-bound (`UI-28`), the secrets file's encryption flag is one-way (`UI-30`), and both are operational obligations on whoever runs the application server rather than anything this database can enforce |
| R-04 | A tenant-scoped table is added later without registration | Medium | **Critical** | Fails open. `950_verify_deployment.sql` catches it at deployment; `G-01` promotes it to a scheduled check |
| R-05 | The UI binds to role names despite `P-02` | High | High | `UI-02` is the first technical row of the gotchas workbook; a code review checklist item at M4 |
| R-06 | Schema-bound predicate change needs an outage nobody scheduled | ~~Medium~~ **Occurred 2026-09-20, on a developer machine** | Medium | It arrived earlier and smaller than the register predicted: not a production schema change, but the *second deployment of any existing database*, which `Msg 3729` refuses outright. `auth.uspRebuildTenantAccessPolicy @Action = N'Drop'` and `Invoke-PolicyDrop` make it a deployment step (`BL-038`, `UI-34`), and the unbind window is now stated rather than hidden. `G-04` stays open for the production case, and getting it into the operational runbook before first production deployment is still the response |
| R-09 | A new `logs` table is writable by the application because nothing enumerates them | Medium | High | **Materialised, then closed.** Filed 2026-09-20 as `G-23` after `BL-048` closed the immediate hole by naming the four trail tables — and `logs.PermissionProbe` (Phase 5) was then writable by `applicationRole` for three phases while `170_permissions.sql` reported no problems. Closed 2026-09-20 by `BL-066`: `170` §4 and §6e both enumerate `sys.tables` in `logs`, subtract an exemption list held as rows, and report per table plus a count. The `950_verify_deployment.sql` half is inherited by `T-104` |
| R-07 | ~~Scope creep in Phase 6 from the UI team starting early~~ **Retired 2026-09-20** | — | — | It did not occur. Phase 6 closed with the twenty-one tasks it started with, and `M4` was delivered as a freeze: one document, `docs/40-ui-handoff-m4.md`, with signatures and result-set columns rather than a promise to supply them. The register's response was "M4 is a freeze, not a checkpoint" and it held because the freeze was written down before anybody asked. Seven tasks joined the phase afterwards (`T-113`–`T-119`, 2026-09-21) and that is not this risk materialising late: they closed gap rows the phase had itself filed, and the one that touched the contract took it to v1.1 through §10's change-control rule rather than around it |
| R-08 | Four-eyes approval on privileged grants is assumed present | Low | High | It is not. `G-08` states so explicitly; confirm with the business before go-live rather than after an audit |
| R-10 | A reporting or export path is built over a protected table and the predicate is blamed for its cost | **High** | Medium | Filed 2026-09-20, out of the Phase 5 measurements rather than out of an incident. The predicate is cheap per row and expensive per million — 1,002,655 logical reads against 1,405 on the large aggregate — so the fix is never tuning: it is `rlsBypassRole` plus an explicit tenant filter, under `auth.uspBeginMaintenanceSession`, with the bypass window closed. High likelihood because Power BI already reads these tables directly (`BL-033`), and the first person to point it at `dbo.CaseFile` will meet this. `docs/30-performance-measurements.md` states the numbers so the conversation starts from them |
| R-11 | ~~Go-live on a deployment whose only password is the bootstrap's~~ **Retired 2026-09-21** | — | — | It did not occur, and it was retired by code rather than by argument. `G-42` is closed: `110_auth_authn_procedures.sql` carries `uspSetPassword` (an administrative act, `User.ResetCredential`), `uspGetPasswordChangeContext`, `uspChangePassword` (self-service, and it refuses an account with no password) and `uspExpireCredentials`, with `E-50220`–`E-50224` and `BL-067`. The reason this risk was Critical rather than High is worth keeping after the retirement: the workaround — writing the verifier directly — was available, undetectable and left no trail, so the gap could have been *survived* all the way into production instead of blocking there. That is the shape of risk this register is worst at catching, and `R-04` is the other instance of it |

R-04 is still the one to watch. It is the only risk in this table whose failure mode is silent,
permissive, and indistinguishable from correct operation — and Phase 4 found a second instance of
exactly that shape in a place the register was not looking, which is R-09.

**Three retirements and two additions at the Phase 5–7 closeout, and the pattern between them is the
point.** `R-01`, `R-02` and `R-07` are retired: the two that predicted *technology* would fail
(`R-01`, `R-02`) were wrong, and the one that predicted *people* would (`R-07`) was averted by
writing the freeze down in advance. `R-03` and `R-06` occurred exactly as written. The two new rows
are of a different kind from anything the register held before — `R-10` and `R-11` are both risks
that the system will be used *correctly and unsuccessfully*, by someone reading a screen that gives
them no reason to suspect a problem. That is the shape the register is now thin on, and Phase 8
should look for more of it rather than for more ways a script might fail.

**One risk the register did not carry and now must.** A stale permission-id list in the RLS
predicates is a silent *denial*: rows disappear for some profiles and not others, no error is raised
anywhere, and the symptom reaches a user as "I could see these records yesterday". It is not in the
table above because it is not a project risk — it is an operational one, permanent, and it belongs to
whoever changes `auth.Permission` after go-live. `UI-35` carries it at `Critical`, and the response is
one line: any change to the permission catalogue is followed by
`EXEC auth.uspRebuildTenantAccessPolicy @Action = N'Rebuild'`, as part of the migration rather than
after it.

---

## 10. How this plan relates to the workbooks

| Document | Holds | Changes when |
|---|---|---|
| DES-AUTH-001 | What is being built and why | A decision changes. Versioned — **v1.7** |
| This plan | Phases, milestones, risks | The shape of the work changes — **v1.7** |
| PERF-AUTH-001 (`docs/30-performance-measurements.md`) | The measured cost of the authorization model, with plan shapes | Only when re-measured. It is **the record** for every performance number quoted anywhere in this project |
| UIH-AUTH-001 (`docs/40-ui-handoff-m4.md`) | The frozen UI contract: signatures, result-set columns, the sign-in sequence, the connection rules | The surface changes, which after `M4` means a design change first — **v1.1**, and §10 requires a Build Log entry for every amendment |
| `implementation-tracking.xlsx` | Tasks, owners, status | Continuously. The living document |
| `build-and-traceability.xlsx` | Artefacts in install order, what changed while building, design-to-artefact map | As scripts are written |
| `gaps.xlsx` | What the design requires that no artefact provides | As gaps open and close |
| `ui-gotchas.xlsx` | What the UI team needs to know | As the model is exercised |

**The Build Log is the one to read before concluding that a script disagrees with the design.**
It exists because that conclusion is usually wrong and occasionally right, and the difference is
not visible from the script.

**And the gaps workbook is the one to re-read before extending the design.** The Phase 5–7 closeout
closed eight gaps, every one of them by amending the design rather than the code, and **not one of
them was found by re-reading the design**. Each was found by reconciling a row of that workbook
against the code it describes — a process which also turned up a shipped error message recommending
an action the database refuses, and a closing-report assertion that could not pass on any
multi-application database (both `BL-064`). A gap register is worth what its last reconciliation was
worth.

**The 2026-09-21 pass says the same thing about the register itself, from the other end.** Nine rows
closed, seven of them with code, and four of the seven Build Log entries exist because **the row was
wrong**: `G-32` and Appendix B both named a procedure that has never existed, `G-43` named a
permission that is not in Appendix A, `G-18` asked the application to assert something the database
should refuse, and four artefacts were quoting a settings count from two revisions earlier. None of
that was found by re-reading the gap rows either. It was found by trying to *implement* them, which
is the only reconciliation a proposed resolution ever really gets. So the rule has a second half: a
gap register is worth what its last reconciliation was worth, **and a proposed resolution is worth
nothing until somebody has tried to build it.**
