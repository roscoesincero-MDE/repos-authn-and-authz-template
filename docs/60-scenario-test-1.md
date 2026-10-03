# Scenario Test 1 — A State Agency, 67 Counties, and Thirteen Thousand Users

**Document ID:** SCEN-AUTH-001
**Version:** 1.0
**Status:** All four runs pass. Seven gaps found, one of them Critical
**Date:** 2026-09-21
**Covers:** Phase 7, tasks `T-122`–`T-124`; the gaps it found are `T-125`–`T-130`
**Run on:** `MDE-55TT2J4\testTemplate` and `MDE-55TT2J4\testTemplateS1`, SQL Server 2025 developer
instance, compatibility level 160
**Scripts:** `database/_scenarios/S1_load_agency.sql`, `database/_scenarios/S1_prove_duties.sql`
**Implements:** `test_scenario_1.txt`; DES-AUTH-001 §9.4–§9.6, §10.1–§10.3, §11.2, §15.2

---

## 1. What was asked

`test_scenario_1.txt` describes one customer in thirty-nine lines. A state agency, the Department of
Environmental Protection, oversees 67 counties. Thirteen paragraphs of users follow — read-only staff
who cannot switch profiles, read-only staff who can switch into all 67 counties, CRUD staff, CRUD
staff who can switch into all 67, platform administrators, three flavours of "can assign profiles",
twenty people who switch into ten randomly chosen counties, and then the county-side equivalents,
including twenty counties whose staff also work for one neighbour and ten whose staff also work for
ten. Agency staff sign in with Microsoft Entra SSO; the platform administrators and every county user
sign in with local credentials and 2FA.

Then it asks for the same test four times: on the existing `testTemplate`; on a new `testTemplate`
database; a third time on that second database with the user count doubled and the agency and county
counts unchanged; and a fourth time with a second agency, the Environmental Protection Agency, over
100 counties of its own.

Finally: *"Identify any gaps including items missing from seed data."*

**All four runs pass, exit 0.** Seven gaps were found, and §7 is the part of this document worth
reading. One of them is Critical and locks every administrator in the scenario out of the profile
they exist to hold.

This document is not a summary of the two scripts — they carry their own headers and are meant to be
read. It records what was run, what the numbers were, what was proved, and — at least as important —
what was *not*.

---

## 2. The two scripts

Neither is in the install manifest. They are scenario tools, run on demand against a database that is
already installed, and they are not fixtures: a fixture exists to be asserted against and thrown
away, while a population exists to be *used*, by a demonstration, a training environment or the load
harness that `G-49` asks for.

### `S1_load_agency.sql` — the population (`T-122`)

One agency over N county tenants, thirteen cohorts, every insert guarded by `NOT EXISTS` so that a
second run resumes and reports instead of duplicating. Parameterised by `-v AgencyCode`, `-v Wave`,
`-v Seed` and the county count, so the same file builds DEP over 67 counties and EPA over 100.

Users are named `<agency>.<wave>.<cohort>[.<county>].<serial>` — `dep.w1.d4.0001`,
`dep.w1.c2.003.0017` — so that any row in any log traces back to the sentence of
`test_scenario_1.txt` that asked for it. That is the whole reason the naming is rigid: a population
you cannot interrogate afterwards is a population you have to trust.

`-v Wave` is the doubling mechanism. A second wave adds users and profiles and **no tenants**, which
is exactly what the third run needs.

`-v Seed` here orders the random county picks and nothing else — it writes no session tokens — so
re-using it across waves is deliberate, and gives the two waves identical county topology.

### `S1_prove_duties.sql` — the proof (`T-123`)

About 1,510 lines, **18 connections**, **34 asserted observations**, and a closing **12-row evidence
ledger**. Every failure path `THROW`s (59200–59227) — the last three numbers were added when §7's
findings closed and the sections that proved them were inverted to assert the closures. Nothing is reported for a human to evaluate,
because *the pass criterion is the exit code* — a test that publishes its own findings is a test
somebody can explain away on a bad morning.

Eighteen connections for one logical session is not an accident of style. `sp_set_session_context
@read_only = 1` cannot be re-set (Msg 15664), so **one connection may not wear two hats**: N profile
switches cost N + 1 connections. The six-hop tour in §5 is six connections carrying one session, and
`UI-36` is where the UI team is told about it.

The file contains exactly **one** piece of direct DML — an `UPDATE` of
`auth.UserSession.ElevatedUntilUtc` — and that line *is* finding `G-48`.

---

## 3. The population, cohort by cohort

Measured on `testTemplateS1`, wave `w1`, not calculated:

| Cohort | `test_scenario_1.txt` says | Users | Profiles each | Profiles |
|---|---|---:|---:|---:|
| D1 | 10 read-only, no profile switching | 10 | 1 | 10 |
| D2 | 20 read-only who switch into all 67 counties, read-only there | 20 | 68 | 1,360 |
| D3 | 20 CRUD | 20 | 1 | 20 |
| D4 | 50 CRUD who switch into all 67 counties, CRUD there | 50 | 68 | 3,400 |
| D5 | 10 platform administrators | 10 | 1 | 10 |
| D6 | 10 who can assign profiles, read-only | 10 | 1 | 10 |
| D7 | 20 who can assign profiles, CRUD | 20 | 1 | 20 |
| D8 | 10 who can assign profiles and switch into all 67 counties | 10 | 68 | 680 |
| D9 | 20 CRUD who switch into 10 randomly chosen counties | 20 | 11 | 220 |
| **Agency** | | **170** | | **5,730** |
| C1 | 20 read-only per county | 1,340 | 1 | 1,340 |
| C2 | 50 CRUD per county | 3,350 | 1 | 3,350 |
| C3 | 10 administrators per county | 670 | 1 | 670 |
| C4 | 100 per county who switch between read-only and CRUD | 6,700 | 2 | 13,400 |
| C5 | 20 counties × 20 staff who also work for 1 neighbour | 400 | 4 | 1,600 |
| C6 | 10 counties × 20 staff who also work for 10 other counties | 200 | 22 | 4,400 |
| **Counties** | | **12,660** | | **24,760** |
| **Total** | | **12,830** | | **30,490** |

Sign-in mechanisms, also measured: **160** federated identities — every agency user except the ten
platform administrators, as the scenario specifies — and **12,670** password credentials each with a
confirmed TOTP factor, being the 12,660 county users plus those ten administrators.

Two modelling decisions are worth stating because the scenario's wording does not settle them.

**"Can assign profiles and have read-only access" is ONE profile, not two.** A profile is a bundle of
roles, so cohorts D6 and D7 hold a single profile carrying both `PROFILE_ASSIGNER` and the working
role. The alternative — two profiles requiring a switch to change activity — would have meant these
users could not assign a profile and do their own work in the same breath, which is not what the
sentence describes.

**C4's "switch between read-only and CRUD" is two profiles in one county**, which is what makes it a
switch at all; C5's "4 profiles, a pair for each county" is the scenario's own arithmetic, stated in
its own words, and the loader reproduces it exactly.

The 22 profiles of a C6 user are the reason this scenario is worth running. That person holds eleven
counties × two hats, and is precisely the user who will have two concurrent sessions — which is what
makes `G-50` matter rather than being a tidiness complaint.

---

## 4. The four runs

| # | Database | Load | Added | After the run | Prover |
|---|---|---|---|---|---|
| 1 | `testTemplate` (existing) | 4.4 s | 12,830 users / 30,490 profiles | 117 tenants, 12,855 users, 30,512 profiles, 107,895 scope rows | exit 0, 34 OK, 9/9 |
| 2 | `testTemplateS1` (new, 39/39 install, compat 160) | 3.776 s, 15/15 | 12,830 / 30,490 | 70 tenants, 12,830 users, 30,490 profiles, 206 closure, 107,740 scope | exit 0, 34 OK, 9/9 |
| 3 | `testTemplateS1`, `-v Wave=w2` | 4.755 s, 15/15 | +12,830 / +30,490, **0 tenants** | **70 tenants**, 25,661 users, 60,981 profiles, **206 closure**, 215,481 scope | exit 0, 34 OK, 9/9 |
| 4 | `testTemplateS1`, EPA over 100 counties | 6.423 s, 15/15 | 18,770 / 42,370 | 171 tenants, 44,432 users, 103,352 profiles, 508 closure, 366,452 scope | exit 0, 34 OK, 9/9 |

**Run 1** proved the load is safe on a database that already had five phases of fixtures in it — the
117 tenants and the 25 extra users are that pre-existing furniture, and the fact that nothing
collided is the result.

**Run 2** proved the load does not depend on any of it. `testTemplateS1` was built from the manifest,
39 scripts of 39, and the same population went in 0.6 s faster with all 15 load checks passing.

**Run 3 proves an absence, and the absence is the point.** A second wave of 12,830 users added 30,490
profiles and **no tenants and no closure rows** — 70 and 206 before, 70 and 206 after. That is what
tells you the profile fan-out is per-user and not per-tenant, and therefore that doubling the
*people* in an agency does not touch the tenancy structure at all. Scope rows roughly doubled, from
107,740 to 215,481, which is the cost of the users themselves.

The odd numbers in run 3 — 25,661 rather than 25,660 — are honest. `S1_prove_duties.sql` section 9
creates a user, as the scenario requires of its administrators, so each prover run leaves one behind.
25,661 = 12,830 × 2 + 1, and 60,981 = 30,490 × 2 + 1.

**Run 4 is the only run that could have failed in an interesting way.** With DEP over 67 counties and
EPA over 100 in one database, "an agency hat sees only its own subtree" stops being a tautology.
Before run 4 that claim passed *because there was nothing else in the table to see*. A cross-agency
assertion was added for it (§5, hop 6) and run in both directions; both hold. EPA's 18,770 users and
42,370 profiles matched hand arithmetic exactly, cohort by cohort, which is the only reason the
loader's own count can be trusted at all.

Timings scale with population and not with agency count: 3.8 s for 67 counties, 6.4 s for 100.

---

## 5. What the prover actually proves

Eighteen connections, in order:

| # | Connection | What it settles |
|---:|---|---|
| 1 | `db_owner` preflight | The agency tenant and six named sample users resolve, or 59200/59201 |
| 2 | County CRUD, local sign-in | `uspGetLoginVerifier` → `uspVerifyMfa` → `uspCompleteLogin` → `uspSwitchProfile`; MFA was **demanded** (59202) and **satisfied** (59203) |
| 3 | The CRUD hat | Create, update, add a note, read, soft-delete; the hat arrived (59204), the insert landed (59205), the soft delete took (59206) |
| 4–5 | A read-only user in a **different** county | Listing works; the insert is **refused** (59207, observed `E-50030`); and C001's live file is **invisible** from C002 (59208) |
| 6 | Entra SSO | `uspBeginSsoLogin` → `uspCompleteSsoLogin`, and the federated user holds **no password row** (59209) |
| 7–12 | The six-hop tour on ONE session | DEP → C005 → C010 → C020 → C030 → DEP. Each hop asserts its tenant (59210) and does real work. Hop 2 asserts the agency's file is now out of reach (59211). Hop 6 asserts all five tour files visible from the agency (59212), **cross-agency isolation** (59224), six `ProfileSwitch` events (59213), and — since `T-127` — that the count reached by **joining on `UserSessionId`** equals the count reached by correlating on name and time, with no orphans (59225) |
| 13 | The platform administrator | 14 privileged permissions (59214); signs in with 2FA; is refused `E-50052` (59215); then **a real step-up through `auth.uspElevateSession`**, asserting four things about it (59226); then the same switch succeeds. The `UPDATE` that used to stand in for the missing procedure is gone, and there is now **no direct DML anywhere in this file** |
| 14 | Administration | Creates a user, a profile and a role grant, lists profiles, deactivates the user |
| 15–17 | The eleven-county user | 22 profiles over 11 tenants (59218); the administrative lister still refuses a profileless session and the number is asserted to be **`E-50032` and not `E-50030`** (59223); `auth.uspListMyProfiles` then returns all 22 hats to that same hatless session (59227); refused a write on the default read-only hat (59219); switches to a CRUD hat elsewhere and writes there. Section 10 then asserts the no-switching cohort holds exactly **one** profile (59220) |
| 18 | The closing report | A **12**-row `#Evidence` ledger read under `BypassRowSecurity`, `THROW 59221` on any mismatch. Rows 10–12 are the whole-database form of the three closures: tour switches reachable by a join, orphaned switches anywhere in the run (**0**), and sessions elevated by a real second factor (**1**, where the gap measured 0 of 271) |

Two details in that table are worth pulling out.

**"Switch profiles multiple times a session" is proved literally.** Six switches — one at sign-in and
five hand-offs — carrying one logical session across five tenants, doing real work under each hat,
with the agency's own case file becoming unreachable the moment the session puts on a county hat and
reachable again when it returns.

**The cross-agency assertion is framed as an absence.** It asks that *no* `dbo.CaseFile` row outside
the acting agency's subtree be reachable, not that *n* rows inside it be. A leak is something
*appearing*, and a count of expected rows would not notice one.

**Three of those assertions are inverted from what they were on 2026-09-21.** Sections 6, 7 and 9 were
written to prove that `G-50`, `G-48` and `G-51` reproduced; all three are now closed, so each asserts
the *closure* instead. That is not a cosmetic edit, it is the reason the file still has a job: a test
written to prove a gap reproduces becomes a green light pointing the wrong way the moment the gap is
fixed. Two of the three inversions were deliberately written to assert a **behaviour** rather than an
artefact. Section 6 does not check that `UserSessionId` exists — it takes the same count twice, once by
joining and once by correlating, and requires the two to be *equal*, so dropping the column again makes
the joined count fall to zero while the other does not. Section 7 does not trust the `OUTPUT` parameter
of `auth.uspElevateSession` — it reads the row back and compares, because a procedure that returned a
time it had not persisted would leave `E-50052` exactly where it was and reopen `G-48` underneath a
passing test.

---

## 6. A sample, not a census

Ten named users stand for thirteen cohorts. This is stated here, in the script's header, and in the
gap register, because it is the one claim this test could be misread as making.

Signing 12,830 people in, one at a time, is 12,830 round trips and about nine hours — and it would
still be **serial**, which means it would still not test the thing a 13,000-user deployment actually
meets. Five things a serial sample cannot show were listed here when this document was written. `T-130`
has since measured four of them, and the answers are in `docs/30-performance-measurements.md` §9:

- **blocking on `auth.UserSession` writes when a thousand people sign in at 8:59** — measured. 128 real
  sign-ins over 16 simultaneous connections, 428.5 per second, p95 16.6 ms, and **zero milliseconds of
  `LOCK` waiting**. What accumulates is `WRITELOG` and `PAGELATCH`: the sign-in path contends on the
  transaction log and the page latch, not on other sessions.
- **lock escalation on `auth.ProfilePermissionScope` during a bulk role change** — measured. A ladder at
  100, 250, 500 and 1,000 profiles held 325, 806, 1,609 and 3,214 key locks and **no table-level `X` or
  `S` lock at any step**, staying linear at about 275 ms per profile. A rebuild for one profile does not
  stop the table for everybody else.
- **the read predicate's plan when the buffer pool is no longer warm for one tenant** — **still not
  measured**, and still the honest answer. Every figure in PERF-AUTH-001 is warm; see its §6.
- **deadlocks between a profile switch and a concurrent profile *deactivation*** — measured. 160
  transaction pairs in the deployed statement order produced **no deadlock**, against **80 deadlocks in
  a one-line variant run as a positive control**. The control is what makes the negative result
  evidence rather than a claim, and it earned its place: the first version of the detector could not
  see a deadlock at all and reported zero for both orders (`UI-53`).
- **the `sp_set_session_context` path under connection-pool reuse** — measured. A pooled connection
  comes back with `SESSION_CONTEXT` **cleared** and the read-only key settable again, so pooling is safe
  for the session identity (`UI-54`).

So the four passes mean *every code path the scenario names works*. They still do not mean "13,000
users work", and **`G-49` closed as measured rather than as fixed** — nothing was broken, something was
unmeasured. The sampling caveat above is unchanged and is not what `G-49` was about.

---

## 7. The seven gaps — **all seven closed, 2026-09-21**

Full rows, with evidence and the resolution notes written at closure, are in `workbooks/gaps.xlsx`.
Tasks `T-125`–`T-130` in `workbooks/implementation-tracking.xlsx` carried the work and are all
`Complete`; `BL-079`–`BL-085` in `workbooks/build-and-traceability.xlsx` record the builds.

| Gap | Severity | Closed by | The artefact |
|---|---|---|---|
| `G-48` | Critical | `T-125` | `auth.uspElevateSession` — the missing writer of `ElevatedUntilUtc` |
| `G-51` | High | `T-126` | `auth.uspListMyProfiles`, **and** `E-50032` split out of `E-50030` |
| `G-50` | High | `T-127` | `UserSessionId` on the `ProfileSwitch` and `MfaChallenged` rows |
| `G-46`, `G-47` | Medium | `T-128` | `CRUD_ACCESS` and `PROFILE_ASSIGNER` seeded; the loader now **asserts** them |
| `G-45` | Medium | `T-129` | `dbo.uspCloseApprovedCaseFiles`, the first module to demand `Data.Execute` |
| `G-49` | Medium | `T-130` | A SQL harness and a PowerShell driver — closed as *measured*, not as fixed |

**The seven write-ups below are left as they were written, in the present tense of the day they were
found, with a closure paragraph on each.** They are kept rather than rewritten because *how* a gap gets
found is the part of this document worth re-reading, and a finding rewritten into "there used to be a
problem and now there is not" teaches nobody anything. Read each one as a snapshot dated 2026-09-21,
followed by what was done about it the same day.

### `G-48` — Critical: nothing can satisfy the step-up challenge

`auth.uspSwitchProfile` refuses with `E-50052` when a privileged profile is requested by a session
that is not elevated. Elevation means `auth.UserSession.ElevatedUntilUtc` in the future. **No shipped
procedure writes that column.** Four modules mention it: `100` declares it, `uspSwitchProfile` reads
it, `110` (~line 1508) calls setting it *"Phase 5's business"*, and `140` (~line 1515) asserts that
`112` writes it — `112_auth_mfa_procedures.sql` has four procedures and never names it. Phase 5 built
the performance work and the writer was never written.

Measured: **271 sessions in `testTemplate`, 0 ever elevated.** On the four-run database, **2,490
users hold at least one privileged profile** (4,830 profiles) and **169 of 169** tenant policies
require step-up. `Authn.RequireStepUpForPrivilegedDefault` ships at `1` and the resolution ends in
`COALESCE (..., 1)`, so a deployment that writes no policy at all gets the strict behaviour.

Every platform administrator and every "can assign profiles" cohort in the scenario is locked out of
the profile they exist to hold. **It hid for the entire build because all five
`auth.TenantAuthenticationPolicy` fixtures in the repository set `RequireStepUpForPrivileged = 0`.**
The scenario's policies set it to `1`, which is the only reason it surfaced.

The prover proves the refusal, then does the workaround `UPDATE`, then proves the same switch
succeeding — so the missing piece is demonstrably *one procedure*, and everything around it works.
`T-125`, and `UI-48` tells the UI team to build the challenge now and **not** to reach for the
tenant-policy workaround.

**Closed by `T-125`.** `auth.uspElevateSession` in `112_auth_mfa_procedures.sql`: it takes a session
token hash and exactly one of a TOTP step or a recovery-code hash, verifies the factor against the
**session** rather than a login attempt, and sets `ElevatedUntilUtc` to a bounded window it returns as
an `OUTPUT` parameter. It demands no permission and takes no user id — the authority is the token plus a
factor the account already holds — which is what lets it run on a session wearing no hat at all, and it
must, because the hat is the thing being put on. Errors `E-50125`–`E-50129`. The prover's workaround
`UPDATE` is deleted and section 7 now performs a real step-up, asserting that the column was not
elevated before, is now, is in the future, and **matches the `OUTPUT`**. Two decisions are worth knowing
downstream: `E-50127`, "nothing enrolled of that type", is deliberately *not* counted as a failed
step-up, because counting it would let an unenrolled user lock their own session by asking politely; and
`E-50129` revokes **the session** and leaves **the account** unlocked, because a step-up brute force is
evidence about one stolen token and locking the account would hand whoever holds it a denial of service
against its owner. The advice `UI-48` gave while the gap was open — build the challenge now, it will not
need rewriting — turned out to be right; what `UI-48` now adds is `UI-50`, the rule that the elevation
and the retried switch need **fresh connections**, because the one that met `E-50052` is already
contexted and `UI-06` means it cannot be re-contexted.

### `G-51` — High: the hat menu cannot be built, and the refusal blames the server

A session is profileless by design until the user picks a profile. The only procedure that lists a
user's profiles, `auth.uspListProfilesForUser`, demands `Authz.ProfileRead` — its own header calls it
a list *"for a profile-administration screen"* — so a freshly signed-in session is refused
`E-50030`. Neither login procedure returns a profile list; `auth.uspGetProfileContext` returns the
*active* profile, of which there is not yet one. Measured twice, including a clean probe on
`dep.w1.c1.003.0001`.

So the **first authenticated screen in the application** — needed by all 12,830 users, roughly 4,000
of whom have more than one hat — must read `auth.UserProfile` and `auth.Tenant` directly: outside
`auth.udfIsTenantUsable`, outside the soft-delete filters, outside the instrumentation, outside the
denial trail.

The second half of the finding is arguably worse. The refusal says *"There is NO SESSION CONTEXT on
this connection … a server-side defect, not a permission problem."* Context **had** been established
and was legitimately profileless. The message infers "no context" from a `NULL UserProfileId` and
sends whoever reads the log hunting a defect that does not exist. `T-126`, `UI-46`.

**Closed by `T-126`, in both halves, because fixing either alone would have left a misleading
system.** `auth.uspListMyProfiles` in `140_auth_profile_procedures.sql` demands nothing, takes no user
id, and reads the caller's own hats out of the session row — the confinement is the session token, the
same trust `auth.uspSwitchProfile` already extends to a profileless session. It returns thirteen columns
including `IsSwitchable` and `SwitchBlockedReason`, which names the **tenant** first when both a profile
and its tenant are unusable, because reactivating a profile at a suspended county changes nothing and
sending the user to ask for the wrong remedy is worse than sending them to ask for nothing. `E-50166`
covers the narrow race where the session is readable one statement and gone the next; it exists because
the alternative is handing that caller an empty list, which reads as *"you have no profiles"* and sends
a support request to the wrong place. And `E-50032` is now split out of `E-50030` in
`auth.uspDemandPermission`, because the two need **opposite handling**: `E-50030` means this hat lacks
that verb and the remedy is a grant, `E-50032` means this user is wearing no hat and the remedy is a
chooser. A front end that merges them signs the user out at the exact moment it should be asking a
question. The administrative lister still demands `Authz.ProfileRead` and is still refused, which is
correct — and section 9 of the prover now asserts the **number** is `50032`, so merging the two cases
again fails the scenario. `UI-46` is rewritten from "the menu cannot be built" to how to build it.

### `G-50` — High: the profile-switch trail cannot be joined to a session

`auth.uspSwitchProfile`'s `INSERT` into `logs.AuthenticationEvent` omits `UserSessionId`, although it
has just validated the session token and is holding the row. **73 of 73** `ProfileSwitch` rows carry
`NULL`, against `LoginSucceeded`, `SessionStarted`, `SessionEnded`, `SessionRevoked`, `SsoSucceeded`
and `PasswordChanged`, which all carry it. The step-up `MfaChallenged` row has the same omission.

The unanswerable question is the one this scenario exists to ask: *"did this session switch profiles,
and how many times?"* It has to be inferred from `UserName` plus a window after
`auth.UserSession.StartedUtc`, which is ambiguous the moment one person has two concurrent sessions —
and the C6 user with 22 profiles is exactly that person. `DetailJson.previousUserProfileId` preserves
the *order* of a switch sequence; the *attribution* is lost. Two lines, `T-127`.

Found the honest way: the prover asserted six switches by joining on `UserSessionId`, got zero, and
the test was right to fail. The assertion was not relaxed — it was rewritten to correlate the way an
auditor is now forced to, and the file prints the gap on every run.

**Closed by `T-127`.** Two lines: `UserSessionId` added to both `INSERT`s. The audit the task called for
found no third site — every other `logs.AuthenticationEvent` writer already carried it. No schema
change and no migration, and **the 73 existing `NULL` rows stay `NULL`**: backfilling them would have
meant inferring a session from a user name and a time window, which is precisely the guess this gap was
filed about, so they are left as history and the regression check is *scoped to a run* instead. Section
6 of the prover now takes the count both ways — correlated and joined — and fails if they differ or if
any switch in the run is orphaned, with both numbers in the message. That equality, rather than the
presence of the column, is what keeps this closed.

### `G-46` and `G-47` — the seed data is missing its two commonest roles

This is the answer to *"items missing from seed data"*, and it was found before a single row was
inserted, because the loader could not express the scenario in seeded roles.

There is **no role meaning "can do the work"**. The closest approximation to the scenario's "CRUD
access" needs `CONTRIBUTOR` + `DATA_STEWARD` + `OPERATOR` together, and `DATA_STEWARD` drags in
`Data.Restore` — the power to *un-delete* — granted to a working-level profile as a side effect. The
loader had to create `CRUD_ACCESS` (`Data.Read`, `Insert`, `Update`, `SoftDelete`, `Execute`) to
place 30,490 profiles at all.

There is **no role meaning "can assign profiles"**. `ROLE_ADMIN` is the near miss and also carries
`Authz.ProfileDeactivate`, so granting it to the scenario's four assigner cohorts hands 680 people
per agency the one profile operation that takes somebody's access away. The loader created
`PROFILE_ASSIGNER`.

The pool is not too small; it is **specialised in the wrong direction** — several narrow roles and no
ordinary one. Every project built from this template will write these two roles, slightly
differently, which is divergence in the one place a template is supposed to buy convergence.
`T-128` seeds both, and then the loader's role block is deleted.

Why no earlier test found it: every fixture in `database/_tests/` builds the profiles it needs
directly and never asks whether the seed could have supplied them. **A fixture that constructs its
own roles cannot discover that the pool is missing one.**

**Closed by `T-128`.** Both roles are now in `115_seed_reference_data.sql`, and both are defined by what
they leave out. `CRUD_ACCESS` carries `Data.Read`, `Insert`, `Update`, `SoftDelete` and `Execute` and
**not `Data.Restore`**: un-deleting is the one verb that can resurrect a row somebody deliberately
removed, and it stays with `DATA_STEWARD`. `PROFILE_ASSIGNER` carries `Authz.ProfileCreate`,
`ProfileRead`, `ProfileUpdate` and `RoleAssign` and **not `Authz.RoleCreate` or `RoleUpdate`**, which
`ROLE_ADMIN` forced on anyone who needed only to hand roles out. The second half of the task is the part
that matters in a year: `S1_load_agency.sql` no longer *creates* either role when it is absent, it
**asserts** the template seeded them and fails loudly otherwise. A loader that creates what it needs is
a loader that hides the next omission of this kind — which is exactly the blindness described in the
paragraph above, with a helpful face on it.

### `G-45` — `Data.Execute` is seeded, granted, and enforced nowhere

The scenario defines its central cohort as a profile that can *"read, update, insert, delete (soft
delete), and execute"*. Four of those five verbs are proved end to end through the demo domain. The
fifth cannot be, because **no module demands `Data.Execute`** — the only file mentioning the string
outside the seed and the role grants is `logs.uspRecordAuthorizationDenial`, in a comment.

A permission no module demands is indistinguishable at run time from a permission that does not
exist, and a team copying this template will grant it believing it gates something. `T-129` is either
one demo-domain module that genuinely demands it, or a documented retirement of the permission — but
it cannot stay as it is, looking enforced and not being.

**Closed by `T-129`, with the first option**: `dbo.uspCloseApprovedCaseFiles` in
`180_dbo_application_procedures.sql`. It is a **batched sweep** rather than the per-row action the gap
imagined, and the choice is the substance of the close. A `dbo.uspRunCaseFileAction` would demand the
verb once per named row and prove nothing that `Data.Update` does not already prove; "execute" earns its
own verb only when the thing being executed is a **job**. So the procedure takes `@OlderThanDays` and
`@MaxCaseFiles`, closes every approved case file older than that at the acting tenant, and demands
`Data.Execute` through `auth.uspDemandPermission` like any other verb — refused for a profile without
it, permitted for one with it. `E-50208` bounds the arguments, and the batch ceiling is not timidity:
the sweep holds its locks on `dbo.CaseFile` for one transaction and that table holds every tenant's
rows, so a larger batch would stop every other tenant's work for that whole time. Callers loop until
zero comes back. `E-50209` is the self-check — the trail is written from the `UPDATE`'s `OUTPUT` clause,
and if the trail-row count is not the closed-row count the **whole batch rolls back**, because a
business row that changed with no trail entry is worse than a batch that did not run. One thing the work
revealed: **nothing seeded held `Data.Execute`**, so `_tests/080` had to add `OPERATOR` to its fixture —
without it the `E-50208` probe raised `E-50030` and would have asserted the exact opposite of the
requirement while passing.

### `G-49` — nothing has ever run concurrently

§6, in full. Filed as an open gap rather than rounded up.

**Closed by `T-130` as *measured*, not as fixed** — nothing was broken, something was unmeasured — and
in **two** artefacts, because one language could not do it. `database/_perf/T130_concurrency_harness.sql`
measures what a single session can learn about contention, and is re-runnable by anyone with `sqlcmd`:
the role-change ladder, the lock cost of a sign-in (about five key locks per session row), and a closing
`RISK` / `ACTION` / `SKIPPED` report that came out 0 / 2 / 1 with no `UNMEASURED` row.
`database/_perf/T130_concurrency_driver.ps1` does what T-SQL cannot, because T-SQL cannot open a second
connection: the sign-in storm, the pooling probe, and the deadlock pair. The numbers are in §6 above and
in PERF-AUTH-001 §9. Two things about the method are worth more than the numbers. **The positive control
is the pass criterion**, not a nicety: the same driver replays a one-line variant of the deadlock pair
and produces 80 deadlocks, and test D reports `INCONCLUSIVE` if it does not — because a deadlock test
that cannot see a deadlock reports success forever, which is exactly what this one did until the defect
now filed as `UI-53` was found. And **six defects in the driver were found before its output was
believed**, every one of them by refusing a plausible-looking number: "0 sign-ins, 128 errors numbered
-1" and "0 deadlocks in the control" turned out to share a single root cause. Three of the six generalise
to any .NET client and are now `UI-52`, `UI-53` and `UI-54`.

### How the closures were verified, and what was learned closing them

The two files that found these gaps are also what now defends them. `S1_prove_duties.sql` grew from
1,347 to 1,514 lines and runs green on `testTemplateS1` — exit 0, **0 violations, 12 of 12 evidence
checks** — and `database/_tests/080_error_catalogue.sql` grew to 3,240 lines and passes on
`testTemplate` with **131 throwable numbers, 103 raised on purpose, 8 accounted for with a reason and
none unaccounted for**. Three findings came out of writing those probes rather than out of the features:

- **`auth.[User]` has no `ApplicationId` column, and that is deliberate.** A probe that added one by
  analogy with the tenant lookup one line above failed to compile. Tenants are scoped to an
  application; **users are not**, and are identified by `UserName` alone across the whole database —
  which is exactly what lets one person hold hats in tenants belonging to different applications, the
  case this scenario's eleven-county user exists to exercise.
- **The `Authn.LockoutThreshold`-th failed step-up is the one that revokes, not the one after it.** A
  probe fired five refusals against a threshold of five and expected the sixth to raise `E-50129`; it
  got `E-50126`, the session having already gone. `auth.uspElevateSession` writes the `MfaFailed` row
  for the refusal it is *currently making* and then counts, so the count includes the attempt in hand.
  The probe now reads the threshold from config and loops one short of it, and the fact is `UI-51`.
- **`_tests/080` is not runnable against `testTemplateS1`, and the preflight now says why.**
  `TEMPLATE`/`ROOT` there has no `auth.TenantAuthenticationPolicy` row, because that estate was loaded
  under a root of its own and `900_bootstrap_first_admin.sql` — whose section 2a is the only thing that
  writes that row — never ran against it. The file **deliberately does not create one**: a root policy
  row governs every tenant that has none of its own, since `auth.udfResolveAuthPolicy` returns the
  nearest ancestor, so inventing one would change how unrelated tenants authenticate. A refusal that
  explains itself was the right outcome; a test that quietly provisions another database's root policy
  was not.

### One suspected gap was dropped

A previous pass had recorded that `auth.uspSetTenantAuthenticationPolicy` takes a
`@TrustedIssuersJson` parameter with no table behind it. It was re-read on 2026-09-21: the procedure
**does** write `auth.TenantTrustedIssuer`. The suspicion was a misreading and no row was filed.

---

## 8. What none of the seven is

**None of them is a design error.** The design was right everywhere this scenario touched it. What
was missing were *artefacts* — a writer for a column, a session id on a log row, a listing procedure,
a module behind a permission, two roles in a seed — and what was absent was a population large and
awkward enough to notice.

The seven divide cleanly by *how they were found*, and the division is the reusable part:

- **two before a single row was inserted**, because the loader could not name what the scenario asked
  for (`G-46`, `G-47`)
- **three by a proof failing** against a database where every object behaved exactly as written
  (`G-48`, `G-50`, `G-51`)
- **one by taking the scenario's own words literally** and discovering the fifth verb goes nowhere
  (`G-45`)
- **one by refusing to overclaim** what four serial passes prove (`G-49`)

`BL-076`–`BL-078` in `workbooks/build-and-traceability.xlsx` record this as a fourth way of finding
things, alongside writing code, running a test and taking a measurement: *loading a realistic
population*. `BL-079`–`BL-085` record what was built in answer, and the closure notes in
`workbooks/gaps.xlsx` name every place the delivered artefact **departed** from what the gap row
proposed — four of the seven did, and in each case the departure is the part worth reading.

Seven rows were added to the `Traceability` sheet when these gaps were filed, and **six of the seven
were `Partial` or `Gap`**. All six are now `Verified`, **updated in place rather than answered by a
second row** — a requirement with two rows has no status at all, because a reader finds whichever one
they reach first, so each of the six carries its closure underneath the reservation it originally
recorded. Exactly one row was *added* at closure, DES §15, concurrency: that requirement had no row
whatever, which is the whole reason `G-49` was findable. **There is no longer a single `Gap` row on
that sheet.**

The seventh moved the other way and is the model for the rest: DES §10.1 row-security confinement was
already `Verified`, and run 4 is the first test in which that assertion *could have failed*. A row
marked `Verified` against a fixture holding one tenant of each kind is verified against the easy case,
and that sheet should be read with this in mind everywhere it says `Verified` — including everywhere it
says so because of the work recorded above.

---

## 9. Running it again

Both scripts take `sqlcmd` with `-C` (mandatory), and no `-v` value may contain a space (`UI-41`).

```
REM 1. the population -- 67 counties under DEP, first wave
sqlcmd -S MDE-55TT2J4 -E -d testTemplateS1 -I -C -b -v DbName=testTemplateS1 ^
  -v AgencyCode=DEP -v AgencyName=Department_of_Environmental_Protection ^
  -v CountyCount=67 -v Wave=w1 -v Seed=s2dep1 ^
  -i database/_scenarios/S1_load_agency.sql

REM 2. the proof -- FRESH Seed and RunLabel every single run
sqlcmd -S MDE-55TT2J4 -E -d testTemplateS1 -I -C -b -h-1 -W -s"|" -v DbName=testTemplateS1 ^
  -v AgencyCode=DEP -v Wave=w1 -v Seed=s2prove3 -v RunLabel=S2R3 ^
  -i database/_scenarios/S1_prove_duties.sql
```

Three rules that are not optional:

1. **The prover needs a fresh `-v Seed` and a fresh `-v RunLabel` on every run**, because both become
   session-token material. The loader's seed is different in kind — it only orders the county picks —
   so re-using it across waves is correct and gives identical topology.
2. **`-v AgencyCode` and `-v Wave` must match the load being proved**, or the preflight fails at
   59200/59201 rather than proving the wrong population.
3. **Expect about 90 seconds**, including up to two deliberate 31-second waits for a fresh TOTP step.
   That wait is `UI-47` and it is the correct behaviour: a TOTP step may be spent once, ever, so a
   test that signs the same person in twice inside one 30-second window is refused, and fudging the
   step would test nothing.

Seeds and run labels already spent are listed in `workbooks/build-and-traceability.xlsx`
(`BL-078`; `T130R2` is the run that proved the three closures). One standing note for anyone returning
to performance work: **`testTemplateBoot` is still carrying 10,650 tenants** from the Phase 5
measurements and must be dropped and rebuilt before any further predicate timing.

The `T-130` concurrency artefacts run against the same loaded database, and the driver is **not**
`sqlcmd` and **not** `pwsh`:

```
sqlcmd -S MDE-55TT2J4 -E -d testTemplateS1 -I -C -b -v DbName=testTemplateS1 ^
  -i database/_perf/T130_concurrency_harness.sql

powershell.exe -NoProfile -ExecutionPolicy Bypass ^
  -File database/_perf/T130_concurrency_driver.ps1 -ServerInstance MDE-55TT2J4 -DatabaseName testTemplateS1
```

The harness makes **real role changes** to reach its ladder, so it changes
`auth.ProfilePermissionScope` for up to 1,000 profiles — that is not destructive, but it is not
read-only either, and it is the reason the file refuses to run against a database holding real data. The
driver signs real users in, which writes `auth.UserSession` and `logs.AuthenticationEvent` rows: 128 of
each per storm. Neither is in the install manifest.

---

## 10. Related documents

- `test_scenario_1.txt` — the request, in the customer's words
- `docs/10-database-authn-authz-design.md` — DES-AUTH-001, the design
- `docs/20-project-plan.md` — PLAN-AUTH-001, the plan
- `docs/30-performance-measurements.md` — PERF-AUTH-001, the serial Phase 5 numbers, and §9, the
  concurrency numbers that closed `G-49`
- `docs/40-ui-handoff-m4.md` — UIH-AUTH-001, the UI contract; `UI-46`–`UI-54` belong to it
- `workbooks/gaps.xlsx` — `G-45`–`G-51` in full, now `Closed`, each with the note written at closure
- `workbooks/implementation-tracking.xlsx` — `T-122`–`T-130`, all `Complete`
- `workbooks/build-and-traceability.xlsx` — the two `_scenarios/` rows and the two `_perf/T130_*` rows,
  `BL-076`–`BL-085`, and thirteen traceability rows
- `workbooks/ui-gotchas.xlsx` — `UI-46`–`UI-54`. `UI-46` and `UI-48` were **rewritten** on closure day:
  both described these gaps as open, and a gotcha that tells the UI team to work around something that
  has been fixed is worse than no gotcha at all
