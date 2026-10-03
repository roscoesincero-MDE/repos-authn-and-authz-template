# Performance Measurements — Row-Level Security and the Derived Caches

**Document ID:** PERF-AUTH-001
**Version:** 1.0
**Status:** Measured, and the go/no-go on `D-07` is recorded in §7
**Date:** 2026-09-20
**Covers:** Phase 5, tasks `T-069`–`T-074`
**Measured on:** `MDE-55TT2J4\testTemplateBoot`, SQL Server 2025 developer instance, compatibility
level 160, one connection, warm cache, nothing else running
**Scripts:** `database/_perf/T069_load_volumes.sql`, `database/_perf/T070_measure_predicates.sql`,
`database/_perf/T071_measure_rebuilds.sql`
**Implements:** DES-AUTH-001 §10.6, `D-07`; PLAN-AUTH-001 §5 (milestone `M3`)

---

## 1. What this document is, and what it is not

Phase 5 exists because `D-07` is a bet. The design rejected the fully-expanded
`(profile, permission, tenant)` table and chose instead to join two derived tables —
`auth.ProfilePermissionScope` and `auth.TenantClosure` — inside the row-level security predicate,
at read time, on every row. The bet is that the join is cheap enough. This document is the evidence
for or against it, and §7 is the decision.

It is **not** a tuning report. No index was added, no plan was hinted, and nothing was made faster
during the measurement — because a number that arrives after tuning answers a different question
("can this be made fast?") than the one `M3` asks ("is the design right?"). Two of the numbers below
are worse than the design implies, and they are reported as they came out.

Three honesty notes travel with every figure:

- **Logical reads are the number to argue from; milliseconds are not.** Elapsed time on a
  development instance with a warm cache and one connection is the least transferable measurement
  this project can produce. Logical reads are what the predicate makes the engine touch, they do not
  depend on the disk, and they will still be true on the production box.
- **Every figure includes the Rule 8 instrumentation.** Each procedure call below writes a
  `logs.ExecutionLog` row on entry and updates it on exit. That cost is not subtracted out, because
  a caller cannot subtract it out either.
- **The population is a generated shape, not real data.** `T069_load_volumes.sql` writes directly to
  the tables and bypasses the procedure surface entirely, so it proves nothing about the procedures —
  `_tests/070_variants_end_to_end.sql` is what does that. What it produces is a row population of
  the right order of magnitude and, more importantly, the right *shape*.

---

## 2. The population — `T-069`

| | Expected size | Ten times the tenants |
|---|---|---|
| Live tenants | 1,050 | 10,650 |
| `auth.TenantClosure` rows | 4,939 | 62,539 |
| Maximum depth | 4 | 5 |
| Users and profiles | 5,000 | 5,000 |
| `auth.ProfilePermissionScope` rows | 57,342 | 57,342 |
| `dbo.CaseFile` rows | 200,000 | 200,000 |
| `dbo.CaseNote` rows | 200,000 | 200,000 |

The tree is deliberately **wide and shallow** — 8 agencies, 5 divisions each, 5 programs each, 4
jurisdictions each — because that is what an agency hierarchy looks like, and because a deep narrow
tree would flatter the predicate: closure rows per tenant grow with depth, and a depth of 4 to 5 is
the realistic worst case DES §17 describes. No profile sits at the root, because a root profile sees
the whole closure and would be the best case rather than the expected one.

The shape was arrived at by measurement, and the first attempt being wrong is the part worth keeping:
four operational roles per profile *looks* like ten permissions and resolves to six, because the
baseline roles overlap heavily — `CONTRIBUTOR`, `EDITOR`, `OPERATOR` and `APPROVER` share `Data.Read`
and `Data.Update` between them — and `auth.ProfilePermissionScope` is keyed on
`(UserProfileId, PermissionId, ScopeTenantId)`, so a second role granting a permission the profile
already holds at the same scope adds no row at all. `USER_ADMIN` was added to the mix precisely
because its permissions are administrative and therefore disjoint. **Distinct permissions per profile
grows far more slowly than roles per profile**, which is a fact about this model that any capacity
estimate has to start from.

---

## 3. The predicate — `T-070`

The baseline is `dbo.PerfCaseFileNoRls`: the same columns, the same indexes, the same rows, not
registered in `config.TenantScopedTable` and therefore not bound by `TenantAccessPolicy`. Two tables,
one query shape, one difference. Neither `BypassRowSecurity = 1` nor `ALTER SECURITY POLICY … OFF`
would have done — the first leaves the predicate in the plan and measures the escape hatch, and the
second changes the plan for a reason other than the one being measured.

Profile A holds 9 scope rows at 1 scope tenant; profile B holds 15 at 2.

| Pattern | Protection | Calls | µs/call | Reads/call | Rows returned/call |
|---|---|---|---|---|---|
| Point read by primary key | RLS bound (A) | 2,000 | 13.5 | **8** | 1 |
| Point read by primary key | no RLS | 2,000 | 5.0 | **3** | 1 |
| Range scan, one tenant by status | RLS bound (A) | 500 | 371 | **1,007** | 200 |
| Range scan, one tenant by status | no RLS | 500 | 32 | **6** | 200 |
| Aggregate over everything visible | RLS bound (A) | 20 | 320,717 | **1,002,655** | 1,000 of 200,000 |
| Aggregate over everything visible | RLS bound (B) | 20 | 412,297 | **1,392,655** | 5,000 of 200,000 |
| Aggregate over everything visible | no RLS | 20 | 17,475 | **1,405** | 200,000 |
| `auth.udfHasPermission` — the decision alone | n/a | 5,000 | 24.8 | 7 | n/a |
| `auth.uspDemandPermission`, sampled probe OFF | n/a | 5,000 | 55.7 | 12 | n/a |
| The probe's config read, on its own | n/a | 5,000 | 10.1 | 5 | n/a |

### 3.1 The point read is the answer to the question `D-07` actually asked

**+5 logical reads and +8 µs.** A keyed read of one row costs 8 reads instead of 3. That is the shape
of every screen this template exists to serve — a form, a record, a detail pane — and on that shape
the predicate is free in any sense that matters.

### 3.2 The aggregate is 714× the reads, and the per-row constant is the whole story

Divide the reads by the rows the query *touched* rather than the rows it returned, and every RLS
figure in the table collapses onto one number:

| Pattern | Rows touched | Reads/call | Reads per row touched |
|---|---|---|---|
| Range scan, profile A (9 scope rows) | 200 | 1,007 | **5.03** |
| Aggregate, profile A (9 scope rows) | 200,000 | 1,002,655 | **5.01** |
| Aggregate, profile B (15 scope rows) | 200,000 | 1,392,655 | **6.96** |

**The predicate costs a flat five logical reads for every row the query touches, whether it admits
that row or rejects it.** The range scan touches 200 rows and all 200 are visible; the aggregate
touches 200,000 and 1,000 are visible; the per-row cost is identical to two decimal places. There is
no cheap path and no expensive path — there is one path, evaluated once per candidate row.

The second comparison gives the other coefficient. Profile B holds 15 scope rows against A's 9 and
pays 6.96 reads per row against 5.01 — so **the per-row constant rises with the size of the profile's
scope, not with the size of the result.** A user with authority in fifty organizations pays more per
row examined than one with authority in one, on every query, including the ones that return nothing.

Two things follow, and both are load-bearing:

- **A query that touches 200,000 rows to return 1,000 pays for all 200,000.** Row-level security is
  the net that catches a missing `WHERE` clause, not the mechanism that narrows the query. This is
  now `UI-40`, and it is the one performance fact the application layer has to internalise.
- **The 714× headline is a statement about the query, not about the predicate.** 1,002,655 reads
  against 1,405 is what happens when an unfiltered aggregate meets a five-read-per-row predicate. The
  same predicate on the same data costs 8 reads when the query is keyed.

### 3.3 The sampled probe costs about two-fifths of a permission check in reads, and that is the price of `G-22`

`auth.uspDemandPermission` costs 55.7 µs and 12 reads with sampling off; the config read the sampled
probe adds costs 10.1 µs and 5 reads on its own.

**Those two ratios disagree, and §1's rule decides which one to quote.** On elapsed time the probe is
18% of a permission check; on logical reads it is **5 of 12, or 42%**. Reads are the stable measure and
microseconds vary by up to 20% between runs, so **42% is the figure to carry** and the 18% is the figure
to distrust — a probe that reads five pages to record that something read twelve is not an 18%
overhead in any sense that survives a busier server. An earlier draft of this section led with the 18%
and put the reads in a parenthesis, which is exactly the inversion §1 exists to prevent.

It does not change the decision, and that is worth saying plainly rather than quietly: 42% of a
permission check, **sampled**, is a fraction of a percent of one in aggregate, and the whole reason the
probe is sampled rather than unconditional is that the unconditional version would have made this
number the answer instead of a footnote. `G-22` asked what the hot path costs to observe; it costs 5
reads per observation, and the sampling rate is the dial. `auth.udfHasPermission` on its own is 24.8 µs:
**less than half of `uspDemandPermission`**, so a procedure that needs a yes/no answer and not a
refusal should call the function, which is exactly what `auth.uspCheckPermission` does.

---

## 4. The plan shape — `T-073`

Read out of the plan cache as XML rather than eyeballed in an editor, and re-executed through
`sp_executesql` so that each statement is its own cache entry. The first attempt read the plans of
the statements §3 had already run, by marker comment, and returned nothing every time: an ad-hoc
batch's text could not be made to yield from `sys.dm_exec_query_stats` on this instance, while the
`CREATE TABLE` batch beside it cached perfectly — the worst way for a measurement to fail, silently
and as an empty result set.

| Pattern | Semi-joins | Scope seeks | Scope **scans** | Closure seeks | Closure **scans** | Avg reads |
|---|---|---|---|---|---|---|
| Point read, RLS bound | 1 | 1 | **0** | 1 | **0** | 8 |
| Range scan, RLS bound | 1 | 1 | **0** | 1 | **0** | 1,007 |
| Aggregate, RLS bound | 1 | 1 | **0** | 1 | **0** | 1,002,655 |
| Aggregate, unprotected baseline | 0 | 0 | 0 | 0 | 0 | 1,405 |

**This is exactly what DES §10.6 asserts.** The predicate folds in as a semi-join, both of its tables
are seeked, and neither is ever scanned. On this population a scan would have meant 57,342 or 4,939
rows read to decide a single row, and that is the failure mode `D-07` was afraid of. It did not
happen, on any of the three access patterns.

One caveat about the probe and not about the plan: the `OuterTableOp` column reports `Nested Loops`
for the point read, because the XQuery takes the first `RelOp` whose subtree names `[CaseFile]` and
the loop join sits above the seek. It is not evidence of a scan — `ScopeScans` and `ClosureScans` are
the columns that would show one, and they are zero.

---

## 5. The cache rebuilds — `T-071` and `T-072`

| Operation | Tree size | Calls | ms/call | Reads/call | Rows after |
|---|---|---|---|---|---|
| `uspRebuildProfilePermissionScope`, one profile | 1,050 tenants | 20 | 45.4 | 1,500 | 57,342 |
| `uspRebuildProfilePermissionScope`, 1,000 × one profile | 1,050 tenants | 1,000 | 40.6 | 1,470 | 57,342 |
| `uspRebuildProfilePermissionScope`, all profiles | 1,050 tenants | 1 | **181** | 299,616 | 57,342 |
| `uspRebuildTenantClosure` | 1,050 tenants | 5 | 39.4 | 51,590 | 4,939 |
| `uspRebuildTenantClosure` | 10,650 tenants | 3 | **791** | 924,657 | 62,539 |
| `uspRebuildProfilePermissionScope`, all profiles | 10,650 tenants | 1 | 166 | 44,733 | 57,342 |

The twenty single-profile calls are twenty *different* profiles rather than one profile twenty times,
because the population was built with a deliberate spread of scope shapes and a measurement should
sample that spread instead of measuring a warm cache.

### 5.1 One all-profiles rebuild is 224× cheaper than a thousand single-profile rebuilds

181 ms for all 5,000 profiles against 40,555 ms for 1,000 of them. The blunt instrument does five
times the work in a 224th of the time, and the reason is entirely per-call overhead: 40.6 ms and
1,470 reads per call, of which the actual scope computation for one profile is a small part — the
rest is a transaction, a session-context establishment, a permission demand and two
`logs.ExecutionLog` writes.

**This is a finding and not a curiosity.** `auth.uspRebuildProfilePermissionScope` takes a single
optional `@UserProfileId` and has no list parameter and no batch overload, so an administrative
operation that touches a thousand profiles — retiring a role, re-parenting a division — is being
quietly told by the procedure surface to pass `NULL` and rebuild everything. It is filed as `G-39`,
because a caller should not have to discover a 224× ratio in production, and because the honest fix
is either a documented instruction in DES §8.6 or a list parameter.

### 5.2 The closure rebuild grows faster than the tree

Ten times the tenants costs **20× the time** (39.4 ms → 791 ms) and 18× the reads, for 12.7× the
closure rows — depth went from 4 to 5, and closure rows per tenant grow with depth, so the row count
grew faster than the tenant count and the work grew faster again. 791 ms is still an acceptable
latency for a tenant move at 10,650 tenants, which is an order of magnitude above the expected
deployment, and it is the number `G-09` asked for.

What it also says: `auth.uspRebuildTenantClosure` has **no single-tenant variant**, so 791 ms is the
cost of *any* tenant move at that size, however small. That is the write cost DES §10.6 promised to
trade read cost for, now measured rather than asserted.

### 5.3 The second all-profiles rebuild is the no-change path

166 ms and 44,733 reads against the first call's 181 ms and 299,616. The time is within noise, as the
script predicted, but the reads are 6.7× lower — because the second call found the cache already
correct and its `MERGE` wrote nothing. The first figure is the cost of rebuilding, the second is the
cost of *proving there is nothing to rebuild*, and a scheduled sanity rebuild should be costed at the
second one.

---

## 6. What was not measured, and why

- **Concurrency — measured since, in §9.** Every figure in §§2–5 is a single connection, and when this
  section was written the note here read *"a claim about concurrency belongs to a load test this project
  does not own"*. It does own one now: `G-49` was filed for exactly this, and `T-130` closed it. §9
  carries the numbers. The reasoning that stood in for them was **right but unearned** — the predicate
  does take no lock a reader does not already take, and the rebuilds do run in short transactions — and
  §9 exists because "right but unearned" is not a measurement.
- **Cold cache.** Everything here is warm. On a cold cache the read counts are unchanged, which is
  most of why reads are the number reported.
- **The predicate under a maintenance session.** `auth.uspBeginMaintenanceSession` sets
  `BypassRowSecurity`, and §3 explains why measuring that path measures the escape hatch.
- **`dbo.CaseNote`.** 30,000 rows exist and the same predicate binds them; the case-file numbers are
  the ones reported, because a second table under the same policy tests nothing new.

---

## 7. The go/no-go on `D-07` — milestone `M3`

**GO. `D-07` stands, and the design is locked, with one documented constraint.**

The evidence, in the order it matters:

1. **The plan shape is exactly what the design asserts** — a semi-join with seeks on both inner
   tables, and not one scan on any of the three access patterns. The failure mode `D-07` was afraid
   of did not occur.
2. **The access pattern the template exists to serve is unaffected.** A keyed read costs +5 logical
   reads. Reversing `D-07` would buy back five reads per row on the pattern that is already fast.
3. **The write cost the design traded for is affordable and bounded** — 181 ms to rebuild every
   profile's scope, 39 ms for a tenant move at the expected size, 791 ms at ten times it. The
   expanded table `D-07` rejected would have had to be invalidated on every tenant move, and that
   invalidation is the cost this trade avoids.
4. **The one bad number is not a plan defect, and reversing `D-07` would barely dent it.** An
   unbounded aggregate over a 200,000-row protected table costs about 1 million logical reads, and
   §3.2 shows why: five reads per row touched, 200,000 rows touched. A fully-expanded
   `(profile, permission, tenant)` table would replace the scope-by-closure probe with a single seek
   and might halve that constant — it would not change the fact that the dominant term is *rows
   touched*, which is a property of the query. Paying the whole invalidation cost of the expanded
   table to turn a 1,000,000-read query into a 500,000-read query is not a trade worth making, and
   the query shape itself is one this template does not endorse: bulk reporting goes through Power BI
   against the tables directly (see `additionalRequirements-T-041.txt`, `UI-29`), not through an
   unfiltered aggregate under a user's profile.

**The constraint that goes with the GO, and it is a requirement rather than advice:** every query
against a tenant-scoped table must filter by tenant itself. Row-level security is the net that
catches the mistake, not the mechanism that narrows the query. Filed as `UI-40`, and it belongs in
the M4 handoff package rather than in a performance appendix nobody reads.

**Signed off against** PLAN-AUTH-001 §5 exit criteria: numbers recorded, plan shapes attached,
`D-07` confirmed. `M3` is reached, 2026-09-20.

---

## 8. Re-running any of this

The three scripts are ordered and the third one is destructive to the *measurement*, not to the
database:

```
sqlcmd -S 'MDE-55TT2J4' -E -d testTemplateBoot -I -C -b -i database/_perf/T069_load_volumes.sql
sqlcmd -S 'MDE-55TT2J4' -E -d testTemplateBoot -I -C -b -i database/_perf/T070_measure_predicates.sql
sqlcmd -S 'MDE-55TT2J4' -E -d testTemplateBoot -I -C -b -i database/_perf/T071_measure_rebuilds.sql
```

`T071` section 4 expands the tenant tree to roughly ten times its loaded size and **nothing in this
database hard-deletes**, so the expansion cannot be taken back. After it has run, the predicate
numbers of `T070` are no longer comparable: drop the database, redeploy, and reload before measuring
predicates again. That is why `T071` is last and why it says so on the way out.

None of the three is part of the install manifest, and none should ever be run against a database
that holds real data.

---

## 9. Concurrency — `T-130`, closing `G-49`

**Everything above this section is one connection at a time.** That was filed as `G-49` during the
scenario 1 test rather than argued away, and this section is the answer. It closed the gap as
**measured**, not as fixed: nothing in §§2–5 was wrong, and nothing needed changing as a result.

Two artefacts, because one language could not do the job. T-SQL cannot open a second connection, so
everything that *can* be learned from one session was measured where anyone with `sqlcmd` can re-run it,
and only the genuinely concurrent part went outside.

### 9.1 The bulk role change does not escalate — `T130_concurrency_harness.sql`

A ladder of real role changes through `auth.uspRebuildProfilePermissionScope`:

| Profiles | Elapsed | Per profile | Key locks on `auth.ProfilePermissionScope` | Table-level `X`/`S` lock |
|---:|---:|---:|---:|---|
| 100 | 20.3 s | 202 ms | 325 | **none** |
| 250 | 68.8 s | 275 ms | 806 | **none** |
| 500 | 137.4 s | 274 ms | 1,609 | **none** |
| 1,000 | 276.7 s | 277 ms | 3,214 | **none** |

**Linear, and never escalated.** The constant settles at about 275 ms per profile from 250 profiles
upward, and the lock count rises with it at roughly 3.2 key locks per profile — which is the point: a
role change for one profile does not take the table away from everybody else, so the bulk case is slow
in a way that is *tolerable* rather than blocking. The same file priced a sign-in in locks: 200
`auth.UserSession` rows in one transaction took 1,000 key locks, 15 page locks and one object-level
intent lock — about **five key locks per row**, and no escalation there either.

Two measurement traps are documented in the file because both produced a false zero first, and both
will catch the next person:

- **A `#temp` table is transactional.** A lock snapshot taken inside a transaction that is then rolled
  back is rolled back with it. The harness uses a table variable.
- **`auth.uspRebuildProfilePermissionScope` is idempotent.** A "measurement" that rebuilds an unchanged
  scope measures the no-change path, which §5.3 already covers. Every rung of the ladder makes a **real**
  role change first.

### 9.2 The sign-in storm does not block — `T130_concurrency_driver.ps1`

128 real sign-ins — `uspGetLoginVerifier` → `uspVerifyMfa` → `uspCompleteLogin` — over **16
simultaneous pooled connections**:

| | |
|---|---|
| Throughput | **428.5 sign-ins per second** (128 in 0.3 s) |
| Latency | p50 **6.3 ms**, p95 **16.6 ms**, max **30.3 ms** |
| Failures | **0** |
| `LOCK` waiting, instance-wide delta | **0 ms** |
| What did accumulate | `WRITELOG` 1,156 waits / 232 ms; `PAGELATCH_EX` 1,086 / 131 ms; `PAGELATCH_SH` 511 / 56 ms |

**The sign-in path contends on the transaction log and the page latch, not on other sessions.** That is
the answer to "a thousand people sign in at 8:59": the queue forms at the log, which is a hardware and
configuration question with well-known answers, and not at a row or a table, which would have been a
design question. Zero milliseconds of `LOCK` waiting across 128 concurrent sign-ins is the number to
quote.

### 9.3 Pooling is safe for the session identity

`sp_set_session_context @read_only = 1` cannot be overwritten on the same connection (`UI-36`), which
raises a fair worry about pooling in both directions: a recycled connection might still carry the
previous user's identity, or might refuse a new one. **Neither happens.** Test P takes a connection,
sets the context, returns it to the pool, takes it again, confirms the **same SPID**, and reads
`SESSION_CONTEXT` back **empty** — `sp_reset_connection` clears it wholesale and the read-only key is
settable exactly once again. Filed as `UI-54`, because this is a question that had been answered three
times from the documentation and never once from the instance.

### 9.4 The deadlock that was worried about does not happen — and the control is why that means anything

A profile switch and a concurrent profile *deactivation* touch the same rows in a plausibly conflicting
order. **160 transaction pairs in the deployed statement order: 0 deadlocks.** The same driver then
replays a one-line variant of the same pair and produces **80 deadlocks** in the same number of
attempts.

**The control is the pass criterion, not a flourish.** Test D reports `INCONCLUSIVE` unless the control
deadlocks, and that rule was written because of what happened without it: the first version of the
detector looked for error 1205 on the outer exception, PowerShell wraps a `SqlException` thrown by
`ExecuteNonQuery` in a `MethodInvocationException`, and so the detector was blind and reported "0
deadlocks" for both orders — a clean bill of health from a test that could not fail. Filed as `UI-53`,
and it matters beyond this harness: `UI-08` tells the UI team to branch on the error number, and this is
the mechanism that silently prevents it.

### 9.5 What this does not measure

- **Cold cache**, still. §6's second bullet stands unchanged; every number here is warm.
- **More than 16 connections**, and **one instance**. The storm is sized to demonstrate absence of
  blocking, not to find a saturation point, and a real capacity test belongs to the deployment rather
  than the template.
- **The read predicate under concurrency.** §3's figures are per-query logical reads, which do not
  change with concurrency; what would change is *waiting*, and the harness measured waiting on the
  write paths because those are the ones that take locks.

### 9.6 Re-running it

```
sqlcmd -S 'MDE-55TT2J4' -E -d testTemplateS1 -I -C -b -v DbName=testTemplateS1 ^
  -i database/_perf/T130_concurrency_harness.sql

powershell.exe -NoProfile -ExecutionPolicy Bypass ^
  -File database/_perf/T130_concurrency_driver.ps1 -ServerInstance MDE-55TT2J4 -DatabaseName testTemplateS1
```

`pwsh` is not installed on the development machine, so the driver is run with `powershell.exe`. Both
need a loaded database — they were run against `testTemplateS1` and its 103,358 profiles — and neither
is in the install manifest. The harness makes real role changes and the driver writes real sessions and
audit rows, so like the three scripts in §8, neither should ever be pointed at a database holding real
data. Unlike `T071`, though, **neither is destructive to the measurement**: both can be re-run against
the same database as many times as you like, and the harness prints a `RISK` / `ACTION` / `SKIPPED`
report each time whose pass criterion is `0 RISK` and no `UNMEASURED` row.
