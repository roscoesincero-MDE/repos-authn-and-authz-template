# Database Authentication and Authorization Design

**Document ID:** DES-AUTH-001
**Version:** 1.7
**Status:** Draft for review
**Date:** 2026-09-21
**Changed in 1.7:** Ten gaps were closed in one pass, and the shape of that pass is worth stating: eight
of them were **missing surfaces** rather than wrong designs, so most of what follows is this document
catching up with procedures that now exist. **Credential maintenance exists** — `auth.uspSetPassword`,
`auth.uspGetPasswordChangeContext`, `auth.uspChangePassword` and `auth.uspExpireCredentials` (§6.3, §7.1,
§16.2, error band `50220`–`50229`, `G-42`) — and with it the password lifetime, the expiry warning and
the reuse history that §6.3 previously described with nothing to implement them (`G-12`). **Tenant
configuration has a contract:** `auth.uspSetTenantAuthenticationPolicy` and
`auth.uspSetTenantDefaultRoles`, both validating the *combination* and both refusing before they write
anything (§7.2, §8.5, §11.5, `E-50097`, `E-50098`, `G-43`) — which is also what lets the step-up default
of §12.3 come from `config.ApplicationSetting` instead of from a column default of `0` (`G-30`). **A
federated sign-in is now constrained to a trusted issuer**, resolved by nearest ancestor and refused
before the redirect (§7.3, `E-50124`, `G-21`); **both registration forms are throttled per client
address** (§16.4, `E-50068`, `G-24`); and **navigation refuses a catalogue the build was not compiled
against** (§13.1, `E-50230`, `G-18`). `E-50180` occupies the band §14.5 had reserved for element-level
faults inside a well-formed JSON payload (`G-32`), and Appendix B's `50046` row is corrected: it named
`auth.uspAssignRolesToProfiles`, a procedure this template never built and never will, because
`INV-04`, `INV-05` and `INV-06` are each evaluated against the grant in hand. Two of the ten are
documentation by their own resolution — §11.4 gains the standing constraint that **`auth.[User]` holds
identity only**, and every attribute that does not identify a person belongs on a tenant-scoped table
(`G-27`); §16.4 records that `G-06` is **not** closed by the database throttle alone, because edge rate
limiting and a CAPTCHA on the public form are the application's and still block Variant 3 go-live. One
new gap was filed while closing these: **nothing removes a policy row once written** (`G-44`, §7.2).
**Changed in 1.6:** Phases 5, 6 and 7 measured the design, built the administrative surface and the
demonstration domain, and the amendments below divide cleanly into two kinds — **numbers this document
previously asserted without having measured them**, and **rules that turned out to live only in code**.
§10.6 is re-based on `docs/30-performance-measurements.md` (`PERF-AUTH-001`), which is now *the record*
for every figure, and states the methodological finding that governs the rest: **logical-read counts
are stable across runs and microsecond figures are not** — two runs on the same population returned
identical reads and times differing by up to 20%, so every argument in this design is made on reads. The
`D-07` verdict is a **GO** (§10.6, milestone M3), and §8.6 gains `G-39`: the one gap in this project that
exists because of a measurement rather than a defect — rebuilding all 5,000 profiles costs 181 ms while
rebuilding them one at a time costs 40.6 ms *each*, a **224×** difference, and no shipped procedure
takes the fast path. **Six rules are now stated that were previously enforced but unwritten.** §8.2
enumerates, column by column, exactly what `INV-10` refuses on a system role — the name and description
**are** editable, the permission set is not editable at all, and `IsAssignable` may be set back to 1 but
never cleared — and says which of the two enforcement points (trigger or procedure) holds each, because
a rule living only in a procedure is the rule a project will lose (`G-33`). §16.1 item 6 names both files
that seed `config.ApplicationSetting` and the rule behind the split: **a setting seeded in two places is
a setting with two defaults, and the second one to run wins silently** (`BL-050`). §16.3 step 2 corrects
the root tenant to `115` with `900` asserting it, gives the three constraints that pin the order, and
states that the root policy ships with `RequireMfaForLocal = 0` and **must be revisited** (`G-25`,
`G-37`, `BL-051`). §16.4 step 2 records that `auth.uspApproveOrganization` writes **no**
`auth.TenantDefaultRole` rows — defaults live once on the branch and are inherited, because copies
freeze each organization's set at its approval date (`BL-052`). §12.1, §14.1 and §14.2 correct the call
sketches to the real signatures, and §14.1 states once that `@SessionTokenHash` is a **hash** and the
plaintext token never reaches the database — four procedure headers were written from the old sketches
and were dead on their first statement (`G-26`, `BL-053`). §12.1 and §14.3 both state that a profile
switch **spends the connection that performed it**, and that a sign-in costs two: a read-only session
key cannot be re-pointed, engine error `15664`, surfaced as `E-50022` (`G-36`, `BL-057`). §10.3 gains
the two consequences of the block predicate that the permission catalogue pays for — `DATA_STEWARD` and
`APPROVER` must carry `Data.Update` because a soft delete and an approval *are* `UPDATE` statements
(`G-38`) — and the general rule that **any operation recording a profile against a row needs a profile
at that row's own tenant**, which makes approval non-delegable across tenants and is a provisioning
decision, not a runtime one (`G-40`, walked in §17.2). §14.4 states the **one** intended
`auditCreatedBy` default expression, because two are in use and the `auth` schema has the weaker one
(`G-41`). §15.5 says why a profile switch is an authentication event (`G-29`, `BL-055`) and that
organization approval deliberately has no `ChangeType` member (`BL-054`). §17.3 corrects `EXT_ORGS` to
**`EXTORG`** in both places and states the constraint the spelling stands for — a fixture copied the
wrong one straight out of this section (`G-34`). Three absences are now recorded where they will be
looked for rather than only in the gap register: no procedure writes `auth.UserCredential` (§16.2,
`G-42`), none writes `auth.TenantAuthenticationPolicy` or `auth.TenantDefaultRole` (§7.2, §8.5, `G-43`),
and a tree with no policy row demands no step-up anywhere, which is the template shipping its most
permissive setting by omission (§7.2, `G-30`)
**Changed in 1.5:** Phases 3 and 4 built the authorization tables, the functions, the session
procedures, the recorders and the row-level security policy, and every correction below came from
building or testing rather than from re-reading. **Two are renames the design had wrong:**
`auth.uspSetSessionContext` takes `@SessionTokenHash`, not `@SessionToken` — the plaintext token
never crosses into the database at all (`BL-043`) — and the four table-valued functions are `tvf`,
not `udf`, which the naming rule in Appendix C already implied (`BL-041`). §9 gains **§9.2**, what
`auth.tvfPermissionScope` deliberately does not answer, and **§9.3**, the requirement that step 5
precede `BEGIN TRANSACTION` so a denial is not rolled back with the work it denied (`BL-042`).
§10.2 is rewritten: the predicate exists in a readable form and a deployed form, the permission ids
are a **list** because one code has one row per application, and an unseeded catalogue resolves to
the sentinel `-1` and denies everything rather than granting everything (`BL-039`, `UI-35`). §10.3
records that a composite foreign key refuses a tenant move with `Msg 547` **before** the block
predicate is consulted (`BL-045`), §10.5 the `MaintenanceBypassEnded` event and why both events name
`ORIGINAL_LOGIN()`, §10.6 why the hot path cannot instrument itself (`G-22`). §15 states that the
audit columns are trigger-owned and unavailable to a caller (`BL-044`); §15.3 corrects the
`auth.UserSession` columns to two expiries and `LastSeenUtc`; §15.4 gains `PermissionDescription`,
`RoleDescription`, the composite foreign keys that make half of `INV-04` structural (`BL-040`) and
`UX_auth_UserProfile_UserTenantName` (`BL-036`); §15.5 the two `Attributable` constraints (`BL-046`,
`UI-39`). §19.3 closes the counterpart of `INV-11` in the `logs` schema, where the conventions'
schema grant made the audit trails directly writable (`BL-048`), and files `G-23` for the next table
that repeats it — **which it then did**, so §19.3 was amended again during the Phase 5–7
documentation pass: the denies and their assertion are both enumerated from `sys.tables` now, the
exemptions are rows, and the design rule that falls out of it is stated there (`BL-066`, `G-23`
closed). §21.1 states the twenty-eight-step install order and the four places it
departs from the file numbers on purpose; §21.3 is upgraded from a caution to a deployment blocker and names
`auth.uspRebuildTenantAccessPolicy @Action = N'Drop'` (`BL-038`, `UI-34`). §14.5 gains ranges
`50130`–`50139` and `50140`–`50149`; Appendix B registers `50047`, `50130`–`50135`, `50140`, `50141`
and corrects `50012`, which is raised by `auth.trg_au_updt_Role` and not by a procedure. Two rows of
§15 were corrected during the closeout rather than during the build, and they are the same defect twice:
**`FK_auth_UserSession_UserProfile` and `FK_auth_TenantDefaultRole_Role` had neither of them ever been
created** — five phases and two phases respectively after this document said they constrained
`ActiveUserProfileId` and `RoleId`. Both `ALTER`s were written out in comments addressed to the next
reader, and the deployment printed `PENDING` for both on every run, which is not a plan. Each is now a
guarded step in the install path of the file that owns the child table, and each report can say
`VIOLATION` once the excuse expires. §11.5, §15.2 and §15.3 record the mechanism; that the second was
found by the same catalog query minutes after the first is the reason it is written up as a process
defect rather than as two typos (`BL-049`)
**Changed in 1.4:** `G-07` **resolved, by management, and not the way §6.2 leaned.** SQL Server Always
Encrypted is rejected: external readers — Power BI reporting is the one named — must keep reading these
tables, and a template cannot know which columns a project will put in them, so there is no column list
to enrol and no driver requirement it can impose on every future reader. Protection is
**application-side envelope encryption** under a TPM-backed CNG key on the application-layer server,
with secrets held encrypted in `appsettings.secrets.json`. §6.2 is rewritten to record the decision and
the new **§6.4** states the whole contract: what the database holds, the `scheme:name#vN` grammar for
`KeyReference`, the settings that name the current key, key rotation, the `vault:` seam left for a
self-hosted HashiCorp Vault, and the first-factor enrolment window that answers the bootstrap paradox.
`E-50117`–`E-50123` are registered in Appendix B and §14.5's sign-in range row extended to cover them.
§19.4 no longer says a secret in this database blocks production. The enrolment surface itself is a new
script, `112_auth_mfa_procedures.sql`, which is `T-112` — the plan had `T-041` as an environment task
and assumed enrolment fell out of it
**Changed in 1.3:** `G-19` resolved — `170_permissions.sql` now states every schema for every role
and **fails** on a schema that is neither granted nor denied, which is what stops the next schema
repeating the hole silently. `SCHEMA::config` is granted `SELECT` to both reading roles and
`config.ApplicationSetting` is **denied** to both underneath it, because one row of that table is
`Authn.DummyVerifierPepper` and a caller who can read it can derive the dummy verifier for any name
and enumerate every account offline — §19.2 would not degrade, it would disappear. `INV-11` is now
enforced by an explicit `DENY` on `SCHEMA::auth` rather than by the absence of a grant; both were
measured against a real `applicationRole` member first, and the measurements are recorded in that
script's banner and in `BL-028`. `E-50116`, the per-address throttle refusal, is registered in
Appendix B — it was implemented in Phase 2 and was the one authentication number the appendix did
not carry. §15.3 corrects the `auth.UserMfaRecoveryCode` unique index to `(UserId, CodeHash)`
filtered, which is what was built and is the right key. `G-21` filed: nothing in the database
constrains **which** issuer a federated sign-in may come from
**Changed in 1.2:** `G-20` resolved — the bulk role-assignment payload is an `NVARCHAR (MAX)` JSON
array shredded with `OPENJSON`, **not** a table-valued parameter; §14.6, §8.2 and §20 item 2 say so
and `E-50046` is registered for a malformed payload. The authentication error numbers `50100`–`50115`
registered in Appendix B and given a range row in §14.5 **before** Phase 2 raised any of them
(`50116` followed in 1.3, after Phase 2 raised it).
`D-14` records that one sign-in exchange is one `auth.LoginAttempt` row, which is what gives the
second factor and the completion step something to bind to. §15.3 gains
`auth.UserMfaFactor.LastUsedTimeStep`, without which TOTP replay inside a single time step cannot be
detected, and the exchange columns on `auth.LoginAttempt`. §7.2 states which tenant's policy applies
at sign-in and what `auth.udfResolveAuthPolicy` returns. §7.4 names the `config.ApplicationSetting`
keys lockout reads. A stray duplicated heading line above Appendix C removed
**Changed in 1.1:** the tenancy error numbers `50090`–`50096` registered in Appendix B and given a
range row in §14.5, before Phase 1 raised any of them; §5.1 records that `auth.Tenant` carries a
denormalised `TenantTypeCode` so `CK_auth_Tenant_RootHasNoParent` is row-local; §16.1 states which
script seeds the seven tenant types
**Applies to:** SQL Server 2022 · .NET 10 · MVP presentation pattern · Dapper · stored procedures only
**Conventions:** `ponytail-sql-objects` (schema placement, audit block, soft delete, naming, instrumentation, change logging)

---

## How to read this document

This is a **template**. It describes one database design that is intended to be deployed
many times — once per application — and to be the authentication and authorization
foundation for three recognisably different kinds of web application. Nothing in it is
specific to a single system, and where a worked example is needed the demo domain
(`dbo.CaseFile`, `dbo.CaseNote`) supplies it.

Everything in this document is labelled so that other documents can point at it:

| Label | Meaning | Example |
|---|---|---|
| `§n` | Section | §7 Authentication |
| `P-nn` | Design principle — a rule the design holds itself to | `P-03` |
| `D-nn` | Decision, with the alternatives that were rejected and why | `D-07` |
| `INV-nn` | Invariant — a property enforced by the database, not by convention | `INV-04` |
| `E-nnnnn` | Application-visible error number raised by a procedure | `E-50042` |
| `G-nn` | Gap — something the design requires that no artefact yet provides | `G-06` |
| `UI-nn` | A gotcha the UI developer has to know about | `UI-11` |

`G-` items live in the Gaps workbook and `UI-` items in the UI Gotchas workbook; they are
referenced from here but not restated in full.

**A word on vocabulary, because the source requirements ask for it explicitly.** The
requirements use the word *role* throughout, including in places where the correct word is
*profile*. This document does not. §2 defines both, and after that the distinction is kept
rigorously: a user is assigned **profiles**; a profile contains **roles**; a role contains
**permissions**; a profile is bound to exactly one **tenant**. Where the source requirement
said "role" and meant "profile", the conformance walk-through in §17 says so.

---

## Contents

1. Scope, and the three application variants
2. Terminology
3. Design principles
4. Decisions, and what was rejected
5. The tenant model
6. Identity: users and credentials
7. Authentication
8. Authorization: permissions, roles, profiles
9. How a request is authorized, end to end
10. Row-level security
11. Administrative authority — who may grant what
12. Profile switching
13. The UI authorization surface: screens, tabs and commands
14. The stored-procedure contract for .NET 10 / Dapper
15. Data model reference
16. Seed data and bootstrapping
17. Conformance: every scenario in the requirements, walked through
18. Converting an existing Active Directory application
19. Security considerations
20. Performance and scale
21. Deployment and install order
22. Appendix A — permission catalogue
23. Appendix B — error number registry
24. Appendix C — naming conventions used here
25. Appendix D — invariants

---

## 1. Scope, and the three application variants

### 1.1 What this design covers

The database objects that answer four questions, and only those four:

1. **Who is this?** — authentication, credentials, sessions, multi-factor, federated sign-in.
2. **Who are they acting as right now?** — the active profile, and therefore the tenant.
3. **What may they do?** — the permission set derived from that profile's roles.
4. **Which rows may they see and change?** — row-level security driven by (2) and (3).

### 1.2 What this design does not cover

- The user interface. A separate project, using this database as its contract, designs the
  screens. §13 exists to give that project something to bind to, not to design it.
- Business workflow. `Data.Approve` exists as a permission; what approval *means* is the
  application's business.
- Network, host, and platform security; secret storage outside the database; certificate
  management.
- Identity provider configuration inside Microsoft Entra.

### 1.3 The three variants

The requirements describe three application shapes. They are not three designs — they are
three **configurations of one design**, and the table below is the whole of the difference.

| | **Variant 1** — Agency + subordinate jurisdictions | **Variant 2** — Agency-internal, by administration and program | **Variant 3** — Agency + external organizations |
|---|---|---|---|
| Who uses it | Agency staff and county staff | Agency staff only | Agency staff and external organizations; may be public-facing |
| Tenant tree | Root → Agency; Root → each county | Root → Agency → Administration → Program | Root → Agency → Administration; Root → each external organization |
| Agency staff sign in with | Entra SSO | Entra SSO | Local password + TOTP |
| Other users sign in with | Local password + TOTP | n/a | Local password + TOTP |
| Platform administrators | SSO **and** local password + TOTP | SSO **and** local password + TOTP | Local password + TOTP — no distinction from anyone else |
| New profile gets | the tenant's default role set — read-only | the tenant's default role set — read-only | read + insert + update, granted automatically at registration |
| Role assignment is delegated | yes, per county | no — agency IT assigns for everyone | yes, per organization, but the delegating role is granted manually by agency staff |

Everything else — the tables, the procedures, the predicates, the permission catalogue — is
identical in all three. A deployment differs only in its seed data (§16) and in its tenant
authentication policy rows (§7.2).

**This is the central claim of the design, and §17 is the evidence for it.** Every user in
every scenario in the source requirements is walked through the model there, with the
concrete rows that represent them.

---

## 2. Terminology

These six words carry the design. They are used precisely and never interchangeably.

### Tenant

An organizational unit that owns records and scopes authority: the agency, an administration
within it, a program within that, a county, an external organization. Tenants form a
**hierarchy** (§5). Every row of business data belongs to exactly one tenant.

A tenant is *not* a customer in the SaaS sense and *not* a database. All tenants share one
database and are separated by row-level security.

### User

A person. One row per human being, for the lifetime of that person's relationship with the
application. A user is **not** scoped to a tenant — the same person can act for several — and
this is what makes it possible for one individual to work for two counties without two
accounts.

### Permission

The atomic unit of authority: `Data.Insert`, `Authz.RoleAssign`, `User.Create`. Permissions are
defined by the application, are stable, and are the **only** thing application code ever tests.
There are about thirty of them (Appendix A). Application code never asks "does this user have
role X"; it asks "does this profile hold permission Y at tenant Z".

### Role

A named, reusable bundle of permissions, **owned by a tenant**. "Read-only", "Case Editor",
"County Role Administrator". Roles exist so that granting authority is a one-line
administrative act instead of thirty. A role has no ordering, no level, and no inherent
seniority — see `P-04`.

### Profile

The container a user is actually assigned, and the single most important object in this
design. A profile is:

> **a named pairing of one user with one tenant, carrying a set of role grants.**

A user may hold several profiles and **switches between them** (§12). Exactly one profile is
active at a time, and that profile alone determines what the user can do and see for the
duration of a request. The tenant on the profile is the **acting tenant**: it stamps every row
the user inserts and it is what the UI must display at all times (`UI-01`).

### Scope

The tenant at which a role grant takes effect, and by extension the subtree beneath it. A
grant of "Read-only at Root" reaches every tenant; a grant of "Read-only at Anne Arundel"
reaches Anne Arundel and anything below it. Scope is what lets one profile hold broad read
and narrow write at the same time (§8.4), which Variant 2 requires.

### The relationship, in one line

```
User ──< UserProfile >── Tenant            (a user has profiles; each profile names one acting tenant)
           │
           └──< UserProfileRole >── Role ──< RolePermission >── Permission
                      │
                      └── ScopeTenantId    (where this grant reaches)
```

---

## 3. Design principles

Each is a rule the rest of the document is accountable to. Where a later section appears to
break one, it says so and says why.

**P-01 — The database is the authority on authorization, not the application.**
The UI may cache a permission set to decide what to grey out, but every procedure re-derives
authority from the database on every call. A UI that forgets to check is a cosmetic bug, not a
security one.

**P-02 — Application code tests permissions, never roles.**
`Authz.RoleAssign`, never `IsInRole("Administrator")`. This is what makes roles freely
definable per tenant without any code change, and it is the direct answer to the requirement
that the order in which an organization defines its roles must have zero impact.

**P-03 — Permission families are disjoint.**
Holding every data permission confers no administrative authority; holding every administrative
permission confers no ability to read or write a single business row. The requirement's user
who "only assigns roles and can not do any data entry for anyone" is not a special case in this
design — it is the default consequence of the taxonomy.

**P-04 — Roles have no order, no level, and no numeric weight.**
There is no "role 4 is higher than role 2", no bitmask of permission bits, no seniority column.
Two organizations that define their roles in different orders produce identical authorization
outcomes. Any future feature that needs to rank roles must be raised as a design change, not
implemented as a column.

**P-05 — Tenancy comes from the profile, never from the role.**
A role named "Anne Arundel Editor" is a *label*; what makes a grant apply to Anne Arundel is
the profile's tenant and the grant's scope. This is why a user who holds identically-named
roles in two counties does not thereby gain cross-county authority.

**P-06 — Reading is scoped; writing is anchored.**
A profile may read across everything it has been granted read on. A profile may only *insert*
into its own acting tenant. Updating is scoped like reading but gated by the update permission.
§10.3 states this precisely; it is the rule that makes "he is guilty of a data entry error"
into a database-enforced outcome rather than a training problem.

**P-07 — No hard deletes, anywhere, including in the authorization tables.**
A revoked role grant is `IsDeleted = 1`, not a missing row. "Who had what authority on the
fourteenth of March" must remain answerable years later.

**P-08 — Every authorization change is logged as an event, separately from the row audit.**
The audit columns say a row changed. `logs.AuthorizationChange` says *who granted what to whom,
from which profile, and under what authority*. The second question is the one an auditor asks.

**P-09 — Authentication method is a property of the tenant, overridable per user.**
Not a property of the application, and not hard-coded. This is what lets one design serve a
variant where agency staff use SSO and counties do not, and a variant where nobody does.

**P-10 — The platform administrator distinction is an authentication capability, not a
grant of authority.**
It decides *how you may sign in*, not *what you may do*. See `D-05`; this is a deliberate and
consequential reading of the requirement.

**P-11 — Every access path is a stored procedure.**
Per the management requirement, and it is also what makes `P-01` affordable: there is exactly
one kind of place to put the check.

**P-12 — The design assumes the connection is the application, not the person.**
Dapper connects as a pooled application login. The person's identity travels in
`SESSION_CONTEXT`. Every consequence of this is spelled out in §14.3 and it is the single
largest source of implementation gotchas.

---

## 4. Decisions, and what was rejected

### D-01 — One tenant hierarchy, not one per application variant

**Decision.** A single adjacency-list hierarchy (`auth.Tenant.ParentTenantId`) with a
maintained transitive closure (`auth.TenantClosure`), typed by `auth.TenantType`.

**Why.** The three variants differ only in the *shape* of the tree — two levels in Variant 1,
four in Variant 2, two wide branches in Variant 3. A hierarchy covers all three without
conditional logic, and the requirement itself arrives at this conclusion ("this strongly
suggests that the tenant structure has a hierarchy where users can impact records below them").

**Rejected — a flat tenant list with an explicit cross-tenant grant table.** Expresses Variants
1 and 3 adequately and Variant 2 badly: "read on all other programs" becomes one row per
program per user, which is precisely the maintenance burden the requirement is trying to avoid.

**Rejected — `HIERARCHYID`.** Elegant for the tree itself, and poor for the query this design
actually runs ten thousand times a second, which is "is tenant T at or below tenant S". That is
a single seek against a closure table and a range scan with `IsDescendantOf`, which cannot use a
seek on the *ancestor* side. The closure table also survives a subtree being re-parented without
rewriting every descendant's key.

**Cost accepted.** The closure table must be maintained whenever the tree changes. It is
maintained by `auth.uspRebuildTenantClosure`, called from every tenant mutation procedure, and
verified by `950_verify_deployment.sql`. `G-02` covers the risk of it drifting.

### D-02 — A profile is bound to exactly one tenant

**Decision.** `auth.UserProfile` has one `TenantId`, NOT NULL. A user who works for two tenants
holds two profiles.

**Why.** It is the requirement, stated three separate ways: the county user who must not see
another county's records; the user who works for two counties and "will be switching profiles
between AA and BC when doing his task"; and the agency user whose data entry for a county is
invisible to that county because "he is not part of any profile involving AA". Making the
acting tenant single-valued turns all three from policy into structure.

It also gives the UI one unambiguous thing to display (`UI-01`), which the requirement
explicitly asks for.

**Rejected — a profile carrying a set of tenants.** Removes the need to switch, and removes with
it the guarantee the requirement is built on. If a profile spans Anne Arundel and Baltimore
City, then "which tenant does this new record belong to?" has no answer that the database can
enforce, and the data-entry error the requirement describes becomes undetectable rather than
prevented.

### D-03 — A role grant carries its own scope

**Decision.** `auth.UserProfileRole` has a nullable `ScopeTenantId`, defaulting to the profile's
tenant. A grant's permissions apply at that tenant and everything beneath it.

**Why.** Variant 2 needs one person to have write access to their own program and read access
to every program. With scope on the grant, that is one profile with two role grants — write
scoped at the program, read scoped at the agency. Without it, it is two profiles and constant
switching to do one job, which is the friction the requirement is trying to design away.

**This is the one place where a grant may reach outside the acting tenant's own subtree**, and
that is intentional. The safety property is not "scope is inside the profile's tenant" — it is
`INV-05`: *the granting administrator's authority must cover both the profile and the scope*.

**Rejected — deriving broad read from the tenant type** ("all agency programs may read all
agency programs"). Hard-codes policy into structure, and the first exception breaks it.

### D-04 — Permissions are flat and named; there is no permission hierarchy

**Decision.** `Data.Update` does not imply `Data.Read`. A profile that can update but not read
is a legal, if strange, configuration, and the seed roles simply never create one.

**Why.** Implication tables are the mechanism by which "the order roles were defined" starts to
matter again. They also make revocation unpredictable: revoking read from a user who holds
update leaves a question with no obvious right answer. Flat permissions have exactly one
meaning and revocation is subtraction.

**Cost accepted.** Role definitions are slightly more verbose — the "Editor" role names both
`Data.Read` and `Data.Update`. That verbosity is in seed data, written once.

### D-05 — "Platform administrator" is the name, and it is an authentication capability

**Decision.** The requirement offers "enterprise admin", "sys-admin" and "platform admin" and
asks for one to be chosen. **Platform Administrator**, stored as `auth.User.IsPlatformAdmin`.

**Why that name.** "Sys-admin" collides with SQL Server's own `sysadmin` server role, in a
document whose readers are writing SQL Server code — an ambiguity that will cause a real
misunderstanding in a code review. "Enterprise admin" collides with the Active Directory group
of that name, and these applications are being converted *from* Active Directory (§18).
"Platform administrator" collides with nothing in the stack.

**Why a user attribute and not a role.** Because of what the requirement says it does:
"sysadmin is a user that can use login/2fa to login in addition to the normal SSO login", and,
for Variant 3, "the sys-admin classification offers no distinction to other types of users"
precisely because that variant has no SSO. The distinction the requirement draws is *entirely*
about the available authentication routes. Modelling it as a role would imply it carries
authority, and it does not: a platform administrator with no profile can sign in and do
nothing at all.

Authority over the platform's own configuration — registering an application, rebuilding the
security cache — is a small set of permissions in the `Platform` family (Appendix A), granted
through an ordinary role like everything else. Holding them requires `IsPlatformAdmin` as well
(`INV-09`), which is the belt-and-braces part.

**Rejected — a `SYSADMIN` role.** See above; it conflates two independent things and makes the
Variant 3 statement ("offers no distinction") impossible to express.

### D-06 — Row-level security, not view-based filtering

**Decision.** SQL Server row-level security policies with `FILTER` and `BLOCK` predicates over
every tenant-scoped table, registered in `config.TenantScopedTable`.

**Why.** It cannot be forgotten. A view-based scheme depends on every query using the view, and
the failure mode of forgetting is silent cross-tenant disclosure. RLS is applied to the table,
so a procedure written next year by someone who has not read this document is still filtered.

**Cost accepted, and it is a real one.** RLS applies to `db_owner` and `sysadmin` too. A DBA
who connects and runs `SELECT * FROM dbo.CaseFile` with no session context sees **zero rows**,
and will reasonably conclude the data is gone. This surprises everyone exactly once. It is
`UI-18`, it is called out in §10.5, and the design provides a controlled, logged bypass for
maintenance and reporting rather than pretending the need does not exist.

### D-07 — A materialized effective-grant table, flattened over roles but not over tenants

**Decision.** `auth.ProfilePermissionScope (UserProfileId, PermissionId, ScopeTenantId)`,
maintained whenever a grant or a role definition changes. The RLS predicate joins it to
`auth.TenantClosure`.

**Why not resolve roles live in the predicate.** The predicate runs per row. Resolving
profile → role → permission live means three joins inside a security predicate, which the
optimizer will fold but which leaves the whole design hostage to a plan regression.

**Why not fully expand to (profile, permission, tenant).** That is the obvious next step and it
is worse. It multiplies by the size of the scope subtree — an agency profile with read at the
root, in an estate with two hundred tenants, becomes two hundred rows for one grant — and,
far more damaging, it means **re-parenting a single tenant invalidates the cache for every
profile in the system**. Keeping the closure join live costs one extra seek and makes tenant
moves a local operation.

**Cost accepted.** Two tables must be kept consistent with their sources.
`auth.uspRebuildProfilePermissionScope` rebuilds from scratch and is idempotent;
`950_verify_deployment.sql` compares materialized against derived and fails the build on a
mismatch. `G-03`.

### D-08 — Password verification is computed in the application and compared in the database

**Decision.** The database stores a PHC-format verifier string. `auth.uspGetLoginVerifier`
returns it; the application computes the hash with ASP.NET Core's hasher; the application then
calls `auth.uspCompleteLogin` or `auth.uspRecordLoginFailure`.

**Why.** SQL Server has no Argon2id and no PBKDF2 at a defensible iteration count. `HASHBYTES`
with a salt is not a password hash. Doing the KDF in .NET is the only option that produces a
credible verifier, and it does not violate the stored-procedure-only rule: the application is
still performing no data access of its own.

**The enumeration hazard, and what is done about it.** A procedure that returns "no such user"
tells an attacker which usernames exist. `auth.uspGetLoginVerifier` therefore returns a
**dummy verifier of the correct shape** for an unknown or disabled account, so the application
performs the same work and fails the same way. §19.2.

### D-09 — `ApplicationId` scopes roles, permissions and UI elements

**Decision.** `auth.Application`, referenced by `auth.Permission`, `auth.Role` and
`auth.UiElement`. A normal deployment has exactly one row.

**Why.** This is a template that a single organization will deploy many times, and some of
those deployments will eventually be consolidated. The column costs one predicate in role
resolution and nothing at all in the RLS hot path — the materialized scope table is already
per-profile, and a profile belongs to one application's tenant tree. Adding it later means
rewriting every unique key in the authorization schema.

**Cost accepted.** Seed data must name the application. `115_seed_reference_data.sql` does.

### D-10 — Profile switching is switching between your own profiles, never impersonating another user

**Decision.** `auth.uspSwitchProfile` will only activate a profile whose `UserId` is the
session's user.

**Why.** The requirement's examples are all of this shape — "for an MDE user to switch to an
Anne Arundel profile", "an Anne Arundel user can switch to another Anne Arundel profile to see
what a fellow Anne Arundel user can do". In every case the way the user acquires that view is by
*being given a profile*, which the requirement says explicitly: "E1 must be added to a profile
that has AA as a tenant and must switch to that profile".

True impersonation — acting as a different person — is a materially different feature with a
materially different audit obligation, and it is not required by anything in the source. It is
recorded as `G-11` rather than smuggled in.

---

## 5. The tenant model

### 5.1 Shape

```
                              ROOT  (TenantType = 'Root', exactly one per application)
                                │
        ┌───────────────────────┼────────────────────────┬─────────────────────┐
        │                       │                        │                     │
      Agency                 County A                 County B          External Org O1
   (TenantType='Agency')   ('Jurisdiction')        ('Jurisdiction')   ('ExternalOrganization')
        │
   ┌────┴─────┬──────────┬─────────┐
  Admin1    Admin2     Admin3     IT          (TenantType = 'Administration')
   │
 Program1  Program2                           (TenantType = 'Program')
```

Every variant is a pruning of this picture. Variant 1 uses Root, Agency and two
jurisdictions. Variant 2 uses Root, Agency, four administrations and their programs.
Variant 3 uses Root, Agency, its administrations, and a branch of external organizations.

**Why there is a root tenant at all.** Because "the agency can see everything" has to be
expressible as a scope, and a scope is a tenant. Without a root, "everything" would be a
special case in the predicate — a `NULL` meaning "no limit", or a magic `TenantId = 0` — and
special cases in a security predicate are where cross-tenant disclosure comes from. With a
root, "see everything" is an ordinary grant scoped at an ordinary tenant, evaluated by the
ordinary rule.

The root tenant owns no business data. `INV-01` enforces it.

**`auth.Tenant` carries `TenantTypeCode` as well as `TenantTypeId`.** The code is denormalised on
purpose, and the pair is proved correct by a composite foreign key against an unfiltered
`UNIQUE (TenantTypeId, TenantTypeCode)` on `auth.TenantType` — the same device
`dbo.CaseNote` uses for `(CaseFileId, TenantId)`. The reason is
`CK_auth_Tenant_RootHasNoParent`: it ties `ParentTenantId IS NULL` to the `Root` type, and a
`CHECK` constraint may only read its own row. Reaching the type code through a scalar function
was measured and rejected — a function referenced by a `CHECK` cannot afterwards be
`CREATE OR ALTER`ed (error 3729), which breaks the re-runnability every script in this build
requires. A trigger was rejected because it can be disabled and because the fixtures and the
bootstrap script insert as `db_owner`. `BL-019`.

### 5.2 Tenant type is descriptive, not functional

`auth.TenantType` exists so that the UI can label things correctly and so that reports can
group. **No authorization decision reads it.** A future requirement of the form "all
administrations may read each other" must be expressed as role grants, not as a rule about
the type. This is `P-04` applied to the tree: the moment the type drives authority, the shape
of one organization's tree starts affecting another's.

Seeded types: `Root`, `Agency`, `Administration`, `Program`, `Jurisdiction`,
`ExternalOrganization`, `Division`. The list is extensible and inert.

### 5.3 The closure table

`auth.TenantClosure (AncestorTenantId, DescendantTenantId, Depth)` holds one row for every
ancestor/descendant pair **including the self-pair at depth 0**. The self-pair is what makes
"at or below" a single predicate rather than "equal, or in the closure".

For the tree above, Anne Arundel contributes `(Root, AA, 1)` and `(AA, AA, 0)`. A grant scoped
at Anne Arundel matches rows whose tenant is Anne Arundel because of the depth-0 row, and any
future sub-unit of Anne Arundel because of the rows added when that sub-unit is created.

Maintained by `auth.uspRebuildTenantClosure`, which is a full rebuild inside one transaction
rather than an incremental patch. A full rebuild of a few thousand rows takes milliseconds, is
trivially correct, and converges after any sequence of changes — including a re-parenting that
an incremental algorithm would get wrong. Every tenant mutation procedure calls it.

### 5.4 Tenant deactivation

Tenants are soft-deleted like everything else, and deactivation cascades *logically*, not
physically: `auth.udfIsTenantUsable` reports a tenant unusable if it or **any ancestor** is
inactive or deleted. Sessions on a profile whose tenant becomes unusable are rejected at the
next `auth.uspSetSessionContext` call with `E-50021`.

The rows keep their `TenantId`. They simply become unreachable, which is the correct behaviour
for a jurisdiction that withdraws from the programme — the records must remain for the agency,
scoped at the root, to read.

---

## 6. Identity: users and credentials

### 6.1 One user, many ways to prove it

`auth.User` is the person. It carries no password, no tenant, and no authority. The three
credential tables hang off it:

| Table | Holds | Used by |
|---|---|---|
| `auth.UserCredential` | the local password verifier, in PHC string format | local sign-in |
| `auth.UserFederatedIdentity` | the Entra object identifier and issuer | SSO sign-in |
| `auth.UserMfaFactor` | TOTP shared secret (encrypted) and recovery codes | second factor |

A user may have all three at once. A platform administrator in Variant 1 does exactly that:
Entra for everyday work, and local password + TOTP for the bypass route.

**The Entra join key is the object identifier (`oid`), never the email address.** Email
addresses are reassigned when people leave and are changed when people marry; an `oid` is
stable for the lifetime of the directory object. A design that joins on email will, sooner or
later, hand one person's account to a different person. `INV-07`.

### 6.2 What the database stores, and what it must not

| Stored | Not stored |
|---|---|
| Password **verifier** — a one-way PHC string including algorithm, parameters and salt | The password, or anything from which it can be derived |
| TOTP secret, **encrypted by the application** — §6.4 | The TOTP secret in plaintext, and the key that would decrypt it |
| Recovery codes, hashed individually | Recovery codes in plaintext |
| Entra `oid` and issuer | Entra access or refresh tokens |
| Session identifier — a random 256-bit value, stored hashed | Any bearer token the application issues |

**The TOTP secret is the awkward one and the design says so plainly.** Unlike a password, it
has to be recoverable to be verified, so it cannot be hashed. It is therefore encrypted, and the
design's position throughout has been that the key must not live in the database: storing the seed
under a database-resident symmetric key protects against a stolen backup file and nothing else.

**The choice was `G-07`, and it has been made: application-side encryption.** Two candidates were
carried — SQL Server Always Encrypted with the column master key in a key vault, or application-side
envelope encryption with the key in a vault of some kind — because the decision depends on
estate-level key management that is outside this document. Management resolved it, and Always
Encrypted is **rejected**. The reason is one this document should have reached on its own, and it is
about being a *template*: external services have to read these tables — Power BI reporting is the one
named — and Always Encrypted puts a driver and a key-access requirement on every reader, present and
future. Worse for a template, enrolling a column requires knowing which column, and a template does
not know what a project will store. So the protection is **application-side envelope encryption**,
and the full contract is §6.4.

What that leaves in this table is unchanged in kind and sharper in wording: the database holds
`auth.UserMfaFactor.SecretCiphertext` as bytes it cannot interpret and `KeyReference` as a *label*
naming the key that would. It holds no key, at any point, under any role. A `db_owner` reading the
table sees ciphertext, and that is the property the decision buys.

### 6.3 Account state

`auth.User` carries `IsActive`, `IsLockedOut`, `LockoutEndUtc`, and `MustChangePassword`. These
are properties of the person and apply across every profile, which is the correct granularity:
suspending someone suspends them everywhere, immediately, without having to find every profile
they hold.

Deactivating a *profile* is the narrower act and is separate (§8.5).

**Password state is credential state and lives on `auth.UserCredential`** — `LastChangedUtc`,
`ExpiresUtc`, and the retired verifiers in `auth.PasswordHistory`. `MustChangePassword` is the one part
of it that sits on the user, because it is a demand made of the *person* rather than a property of the
verifier: an administrative reset sets it, and the next sign-in has to honour it whichever profile is
chosen.

Three settings govern the lifecycle, and all three ship at the value that asks nothing of a deployment
which has not decided:

| `config.ApplicationSetting` key | Ships as | What it does |
|---|---|---|
| `Authn.PasswordLifetimeDays` | `0` | how long a new or changed verifier lasts. `0` means it does not expire, which is the shipped position: forced rotation drives people to predictable variations, and a template that imposed one would be making a policy decision on a deployment's behalf |
| `Authn.PasswordExpiryWarningDays` | `14` | how far ahead of the deadline the page context starts warning |
| `Authn.PasswordHistoryDepth` | `5` | how many retired verifiers `auth.uspChangePassword` refuses to accept again (`E-50222`). `0` keeps no history and therefore has no reuse rule, and the procedure consults the depth *before* refusing, so a deployment that keeps none is not made to enforce one |

**The expiry is reported in the page context and not only at sign-in.** `auth.uspGetProfileContext`
returns `PasswordExpiresInDays` and `PasswordExpiryWarning` beside the display name, because the header
is the one surface a user sees on every page and "your password expires in three days" belongs there
rather than in a dialogue at the moment they are trying to do something else (`UI-01`). Two properties
of those columns are deliberate and are proved in `_tests/050` section 5: the count **goes negative**
after the deadline rather than clamping at zero, and the warning **stays up**. Both follow from
`auth.uspExpireCredentials` being a batched sweep (`@BatchSize`, `E-50224`) — the interval between a
deadline and the next sweep is real, and a header that went quiet in it would go quiet at the one moment
the user has to act.

**And the comparison that matters cannot be made here.** Reuse is the application's to decide, for the
same reason sign-in is (`D-08`): salted hashes cannot be compared by the engine.
`auth.uspGetPasswordChangeContext` hands out the live verifier and the retired ones, the application
compares, and `auth.uspChangePassword` takes the verdict as `@NewVerifierReusesHistory` and refuses on
it. The database enforces the *depth* and the *trail*; it does not pretend to enforce the comparison.
`G-12`, `G-42`.

### 6.4 Secret protection, key references, and first-factor enrolment

This section is the resolution of `G-07` and the contract the application must hold up. It is
written in two halves deliberately: what the **database** guarantees, which is testable, and what the
**application** must do, which is not testable from here and is therefore stated as an obligation
rather than a mechanism.

#### What the database holds

| Column | Holds | Never holds |
|---|---|---|
| `auth.UserMfaFactor.SecretCiphertext` `VARBINARY(MAX)` | whatever the application produced by encrypting the TOTP seed | the seed, and anything derived from it that a reader could use |
| `auth.UserMfaFactor.KeyReference` `NVARCHAR(256)` | a **label** naming the key that wraps this row's secret | key material, a thumbprint that grants access, or a path with a credential in it |
| `auth.UserMfaRecoveryCode.CodeHash` `VARBINARY(32)` | a hash, single use | the code |

`KeyReference` has a grammar, and it is enforced in the database by
`CK_auth_UserMfaFactor_KeyReferenceFormat` in `045_auth_identity.sql`:

```
scheme:name#vN
```

- `scheme` is one of **`cng`** (a Windows CNG key on the application-layer server — today's answer),
  **`vault`** (reserved, see below) or **`dev`** (a development key, for fixtures and local work).
- `name` identifies the key within that scheme.
- `#vN` is a version, one to four digits.
- Length 8 to 256, exactly one `:` and exactly one `#`, and no whitespace of any kind.

The grammar exists so that a key reference can be *read* by an operator and *compared* by the
database without either of them holding the key. The check is written with `LIKE`, `CHARINDEX` and
`LEN (REPLACE (...))` rather than a pattern engine, because the floor for this template is SQL Server
2022 and `regexp_like` is 2025.

Two `config.ApplicationSetting` rows carry the policy:

| Setting | Value on a dev instance | What reads it |
|---|---|---|
| `Authn.MfaKeyReferenceCurrent` | `dev:local/authn-mfa-kek#v1` | enrolment, which refuses any other label, and the rotation sweep, which is moving rows *onto* it |
| `Authn.MfaKeyReferenceSchemes` | `cng,vault,dev` | documentation of the accepted schemes; the constraint is the enforcement |

**Enrolment fails closed on the label.** `auth.uspEnrolMfaFactor` compares the `@KeyReference` it is
given against `Authn.MfaKeyReferenceCurrent` and raises `E-50118` if it differs — it does not accept a
plausible-looking label it has never heard of. This is the one place the database can catch a
misconfigured application server before a user depends on it, and a factor written under a key nobody
is holding any more is indistinguishable, later, from data loss.

#### What the application must do

Per management, the application's secrets live in **`appsettings.secrets.json`**, encrypted at rest on
the application-layer server. Today that file holds the SQL Server login password the application
connects with, an API identifier and an API key; the list is expected to grow, and nothing in this
design cares how long it is.

The file carries its own state flag:

```json
{ "Encrypted": false, ... }
```

The application validates every entry, and only if **all** of them work does it encrypt the contents
and rewrite the flag as `true`. A partially encrypted file is not a state this design permits: a file
that fails validation stays plaintext and stays flagged `false`, which is a diagnosable condition
rather than a silent one. The flip is one-way on that machine (`UI-30`).

The key that wraps those secrets, and the key-encrypting key of the envelope scheme protecting the
TOTP seeds, is a **TPM-backed CNG key on the application-layer server**. The web front end holds no
key and needs none: it never sees a secret and never calls the enrolment procedures. Envelope
encryption is the shape — a data key per secret, wrapped by the CNG key — because it is what allows a
re-key to rewrite wrapped data keys without ever holding a plaintext seed longer than the operation.

**The `vault:` scheme is a seam, deliberately unused.** If management later decides on a self-hosted
HashiCorp Vault, the intended change is a key-reference scheme and a provider implementation, and
nothing else: the grammar already admits `vault:secret/authn-mfa-kek#v1`, the constraint already
accepts it, `Authn.MfaKeyReferenceCurrent` is the one row that has to change, and
`auth.uspRotateMfaFactorKey` is the existing route from the old labels to the new ones. Leaving the
scheme in the grammar rather than "adding it when needed" is the cheap half of that decision; the
expensive half, a provider abstraction in the application, is the application's to keep.

**One consequence, stated because it is easy to be surprised by.** The TPM key is bound to that
machine. It does not survive a rebuild, a TPM clear or a move to new hardware, and the database will
not notice — it still holds every ciphertext and every label, all now unreadable, and the first
symptom is a user failing to sign in hours later. Escrow or a re-key **before** the maintenance, not
after. `UI-28`.

#### Key rotation

`auth.uspRotateMfaFactorKey` re-keys one live factor: the application decrypts under the old key,
re-encrypts under the new one, and passes both the new ciphertext and the new label. It is one factor
per call and is built to be driven by a sweep, which is why it refuses the cases a sweep gets wrong:

- a factor that does not exist or is not live — `E-50120`;
- a label equal to the row's current one, or a ciphertext byte-identical to the row's current one —
  `E-50123`, both meaning "this call would record a rotation that did not happen".

It is the one procedure in this section with **no** actor parameter — no session, no enrolment proof —
and that is deliberate rather than an omission. The caller has to be holding both the old and the new
key to produce a re-encrypted ciphertext at all, so requiring it to also hold a user's session would
prove nothing about the key and would make a key-management operation depend on somebody being signed
in. What guards it instead is `EXECUTE` permission and the refusals above.

A rotation **must** clear `LastUsedTimeStep` in the same statement that changes `SecretCiphertext`, and
the update trigger enforces it with `E-50010`. That is correct — the stored step belongs to a secret
that no longer exists — and it reopens a replay window of one TOTP step. That trade is `UI-32`.

#### The bootstrap: how an account that must have a factor gets its first one

A user under a policy requiring a second factor, holding no factor, is refused `E-50109` at
`auth.uspCompleteLogin`. With no session there is nothing to authorize an enrolment against, so
without a route in, the account is permanently unable to sign in. This is not hypothetical: it is the
state fixture user `authtest.frank` is in, by construction, in
`database/_tests/040_identity_and_authn.sql`.

The route in is the refusal itself. `auth.udfResolveEnrolmentActor` takes a `LoginAttemptId` and
returns the `UserId` only when **all** of these hold:

1. the attempt concluded as `Failure` with `FailureReason = 'MfaRequired'`;
2. `PasswordVerified = 1` on that row — which is why `uspCompleteLogin` writes `PasswordVerified`
   *before* it evaluates the MFA checks (`D-14`); and
3. the attempt concluded within `Authn.MfaEnrolmentWindowSeconds` (900 by default).

So the proof is a record the database wrote itself, about a password it verified itself, minutes ago.
`auth.uspEnrolMfaFactor` and `auth.uspIssueMfaRecoveryCodes` accept **either** a session-derived actor
**or** an enrolment attempt, never both and never neither (`E-50117`).

**The window grants an identity, not a permission**, and that distinction is what keeps it narrow.
An account that already holds a confirmed factor is refused `E-50119` no matter how valid the proof,
so the window is a route to a *first* factor only — it cannot be used to add a second factor, replace
an existing one, or re-key anything. An operator who does not want self-service enrolment sets
`Authn.MfaEnrolmentWindowSeconds` to `0`: the route closes, first factors become administrative, and
no code changes and nothing is redeployed. `UI-31` is the client-side half of this.

A factor does not count until it is confirmed. `uspEnrolMfaFactor` writes `IsConfirmed = 0` and
re-sending is idempotent — the same unconfirmed row comes back rather than a second one —
and `uspConfirmMfaFactor` requires one correct time step inside the window
(`Authn.TotpWindowSteps`) and deliberately does **not** spend it: `LastUsedTimeStep` stays `NULL`, so
the user's next code is the first one the replay defence has an opinion about.

---

## 7. Authentication

### 7.1 The routes

Three, and a deployment enables whichever it needs:

| Route | Procedure chain | Available to |
|---|---|---|
| **Federated (Entra SSO)** | `uspBeginSsoLogin` → application redirects → `uspCompleteSsoLogin` | users whose tenant policy permits it and who have a federated identity row |
| **Local password + TOTP** | `uspGetLoginVerifier` → application verifies → `uspVerifyMfa` → `uspCompleteLogin` | users whose tenant policy permits it |
| **Platform administrator bypass** | the local route, on a distinct endpoint, with `@IsBypassRoute = 1` | `IsPlatformAdmin = 1` users only, **always** with TOTP, logged at elevated severity |

The bypass route mirrors the pattern the requirement points at — a separate link on the sign-in
page that does not go through the corporate identity provider. Its value is that it still works
when the identity provider does not, which is exactly when an administrator needs to sign in.

**The bypass route is not a weaker route.** It requires a second factor unconditionally, even
where ordinary local sign-in has been configured not to. `INV-08`.

**A fourth thing a user can do at the sign-in page is enrol.** None of the three routes can issue a
session to an account that is required to hold a second factor and holds none — that is `E-50109` —
so the refusal itself is the proof `112_auth_mfa_procedures.sql` accepts for a first enrolment. It is
not a sign-in route and issues no session; it is §6.4.

**A fifth thing, and not a sign-in route either: changing the password.** `auth.uspChangePassword` takes
a live session and the application's report that the current password was proved in this exchange
(`@CurrentPasswordVerified`, `E-50221`), refuses a verifier that is not a PHC string (`E-50220`) or one
the application says repeats a retired one (`E-50222`), retires the old verifier into
`auth.PasswordHistory`, and clears `MustChangePassword`. `auth.uspSetPassword` is the administrative
counterpart: it demands `User.ResetCredential`, needs no old password, **forces
`MustChangePassword = 1`** so the reset cannot become a shared secret between an administrator and a
user, and is the only route to a *first* password on an account that has none — which is why asking
`uspChangePassword` to give a federated-only account its first password is `E-50223` rather than a
silent insert. Both follow `D-08` exactly: a PHC string arrives and this database never sees a password.
§6.3, §16.2, `G-42`.

**`D-14` — one sign-in exchange is one `auth.LoginAttempt` row.** Every chain above is more than one
round trip, and the steps need shared state: `uspVerifyMfa` has to know which sign-in it is a second
factor *for*, and `uspCompleteLogin` has to know whether the password was actually checked in *this*
exchange rather than in some earlier one. The first step of every chain —
`auth.uspGetLoginVerifier` or `auth.uspBeginSsoLogin` — therefore inserts one `auth.LoginAttempt`
row with `Outcome = 'VerifierIssued'` or `'SsoBegun'` and returns its `LoginAttemptId`; every later
step in the chain takes that identifier and updates the same row, concluding it as `'Success'` or
`'Failure'`. An exchange nobody concludes expires after
`config.ApplicationSetting` key `Authn.LoginExchangeTimeoutSeconds` and is never usable again.

The alternative was a separate login-ticket table. It was rejected because the row it would hold is
the row `auth.LoginAttempt` already has to hold anyway — §7.4 records every attempt whatever its
outcome — and two tables describing the same exchange is how a sign-in trail and a lockout counter
come to disagree about what happened.

**What this does and does not defend against, stated plainly.** The `LoginAttemptId` is an identity
value and the application login may pass any number it likes, so this is not a defence against a
compromised application credential — nothing at this layer is, because the password hash and the
TOTP comparison are both computed application-side by construction (`D-08`, §6.4), and §19.3 is
where that boundary is argued. What it does defend against is **replay**: a verifier issued for one
exchange cannot complete another, a concluded exchange cannot be reused, an expired one cannot be
resumed, and a TOTP time step accepted once is refused for ever (`auth.UserMfaFactor.LastUsedTimeStep`).
Those are the failures that occur without an attacker, which is why they are worth enforcing in the
one place that holds shared state.

### 7.2 Policy lives on the tenant

`auth.TenantAuthenticationPolicy` holds, per tenant: which methods are permitted, which is
preferred, whether a second factor is required for local sign-in, session lifetime, idle
timeout, and whether step-up authentication is demanded when switching into a privileged
profile (§12.3).

**Policy inherits down the tree.** A tenant with no policy row of its own uses its nearest
ancestor's. The agency sets one policy; its administrations and programs inherit it; a county
overrides it. This is resolved by `auth.udfResolveAuthPolicy`, which walks the closure table
upward and takes the lowest-depth match.

**`auth.udfResolveAuthPolicy` returns the identifier of the policy row that applies, not the policy
itself.** It is `udf`-prefixed, so by the naming rules it is scalar, and a policy is eight columns.
It takes a `@TenantId` and returns the `TenantAuthenticationPolicyId` of the nearest live policy at
or above that tenant, or `NULL` if the tree carries none; callers join
`auth.TenantAuthenticationPolicy` on the result. Returning the identifier rather than the eight
columns also means the resolution rule exists once: a caller that needed a ninth policy column later
would otherwise be tempted to re-walk the closure itself, and a second copy of a walk is a second
copy of the `IsDeleted` filter to get wrong.

**Which tenant's policy applies at sign-in.** Policy hangs off a tenant and a user does not, so the
sign-in procedures take the tenant explicitly: `@TenantCode` names the tenant whose sign-in page the
user arrived at, and when it is omitted the **application's root tenant** is used. This is the
correct granularity for all three variants — Variant 1 and 2 have one sign-in page and it belongs to
the root, Variant 3 gives each registered organization its own and passes its code. It is also the
only answer available before a profile exists: the active profile is chosen *after* authentication
(§12), so a design that resolved policy from the default profile's tenant would need the profile
before it had authenticated anyone.

This single table is what makes the three variants one design:

| Deployment | Policy rows |
|---|---|
| Variant 1 | Root: local + TOTP. Agency: federated preferred, local permitted only for platform administrators. Counties: inherit Root. |
| Variant 2 | Root: local + TOTP. Agency: federated preferred. Administrations and programs inherit the agency. |
| Variant 3 | Root only: local + TOTP, federated not permitted. Everything inherits. |

A per-user override exists (`auth.User.AuthPolicyOverrideJson`, `NVARCHAR(MAX)` with an
`ISJSON` check — the native `json` type is SQL Server 2025 and the floor here is 2022) for the
unavoidable exceptions: the contractor at an agency who has no directory account, the
administrator who needs local access to a tenant that otherwise forbids it.

**What happens when the tree carries no policy at all, and why the answer must not be `0`.**
`auth.udfResolveAuthPolicy` returns `NULL` when there is no live policy at or above a tenant, and each
caller then decides what a missing policy means. For the second factor the decision is already made
and made correctly: `auth.uspCompleteLogin` falls back to `RequireMfaForLocal = 1` and refuses the
sign-in, which is why the bootstrap must write a root policy or produce an administrator who can never
sign in (§16.3, `G-37`). For **step-up on a privileged switch** the fallback is `0`, which means a
deployment that has not written a single policy row demands no step-up anywhere — the template shipping
its most permissive setting by omission. That was `G-30`, and it is now resolved the only way that
survives a deployment nobody is supervising: `config.ApplicationSetting` key
`Authn.RequireStepUpForPrivilegedDefault` ships as `1`, and
`auth.uspSetTenantAuthenticationPolicy` seeds a new policy row from it whenever the caller expresses no
opinion — so a row created without an argument arrives with step-up demanded, and a deployment has to
*decide* to relax it in a row somebody can find. The column default of `0` stays what it always was, the
value a hand-written `INSERT` gets, and the asymmetry is deliberate: the setting governs the supported
route, and the unsupported one is not dressed up to look supported. `_tests/080` section 5g asserts the
seeded value rather than probing a refusal, because nothing refuses here — the gap was a default nobody
could set, not an argument nobody checked.

**Both this table and `auth.TenantDefaultRole` now have a writer, and both validate the combination
rather than the columns.** Until `G-43` was closed they were populated only by
`115_seed_reference_data.sql`, by `900_bootstrap_first_admin.sql`, or by an administrator in SSMS —
which made the part of the authorization surface a tenant administrator most obviously needs the part
with no contract, no permission demand and no `logs.AuthorizationChange` row.
`auth.uspSetTenantAuthenticationPolicy` (demanding `Tenant.Update` at the tenant) and
`auth.uspSetTenantDefaultRoles` (`Tenant.Update` **and** `Authz.RoleAssign`, because a default-role list
is a standing grant) are that contract, and three properties are what make them safe to expose:

- **Every argument is optional and `NULL` means leave alone**, so the row is merged first and validated
  as a whole. A policy permitting neither federated sign-in nor a local password describes a tenant
  nobody can enter and is refused rather than stored (`E-50097`); so is one that prefers a method it
  forbids, which would be a sign-in button that raises `E-50103` or `E-50104` when pressed. Closing a
  tenant is `auth.uspDeactivateTenant`, which is reversible and says so in `auth.vwTenantHierarchy`.
- **Nothing is written before the arguments are proved.** Every refusal in both procedures is raised
  ahead of `BEGIN TRANSACTION`, which is what lets `_tests/080` probe them against a real tenant and
  leave no row behind.
- **A default-role list is refused as a whole and names the first offender** (`E-50098`): an unknown
  code, a role whose owner tenant does not cover this one (`INV-04`), or a frozen role
  (`IsAssignable = 0`) that `auth.uspGrantTenantDefaultRoles` would skip silently — which is the worst
  of the three, because every new profile would then quietly not receive what the screen promised.

The policy procedure also owns the tenant's trusted-issuer list (`@TrustedIssuersJson`, §7.3): the two
belong in one call because "this tenant federates" and "with these providers" are one decision, and a
policy that permitted federation while naming no issuer would be the `G-21` hole re-opened at the
configuration layer.

**What still has no writer is a `DELETE`.** `auth.uspSetTenantAuthenticationPolicy` updates the row it
finds and nothing clears one, so a policy written at the wrong tenant can be corrected but not removed,
and "inherit from my parent again" is not a state any shipped call can reach. That is `G-44`, filed
while this gap was being closed; the workaround is a soft delete by hand, which is exactly what
`_tests/080` section 5g has to do to keep its own next run honest.

### 7.3 Sessions

`auth.UserSession` is the bridge between authentication and authorization. It carries the user,
the **active profile**, issue and expiry times, last-activity time, the authentication method
actually used, whether a second factor was satisfied, and the client address and user agent.

The session identifier is a 256-bit random value; the database stores only its SHA-256 hash, so
a leaked database backup does not yield usable session tokens. The application holds the raw
value in its own cookie.

Sessions end three ways: explicit sign-out (`uspEndSession`), absolute expiry, and idle timeout.
All three are soft — `IsDeleted = 1` with a reason — because "was this session still valid at
14:32" is an audit question.

**Which issuers a federated sign-in may come from.** `auth.TenantTrustedIssuer` names them, written by
`auth.uspSetTenantAuthenticationPolicy` (§7.2), and `auth.uspBeginSsoLogin` refuses an exchange whose
`@Issuer` is not on the list governing that tenant — or which names no issuer at all where a list exists
(`E-50124`). Four properties, each of which was a decision:

- **Nearest ancestor wins, whole.** The closest tenant at or above the one being signed in to that holds
  any live row owns the answer, and its list is *not* unioned with anything above it. A child that lists
  one issuer has therefore **narrowed** the set, which is the only reading under which delegating the
  list to an organization means anything.
- **A tree with no list is unconstrained, and that is the shipped state.** A template cannot know a
  deployment's issuers, and refusing every federated sign-in until somebody writes a row would be a
  template that does not start. The gap `G-21` described was that there was no way to constrain it *at
  all*, not that it shipped open.
- **The comparison is a string comparison against the token's `iss`.** That is why a stored issuer
  carrying leading or trailing whitespace is refused when it is written (`E-50180`) rather than trimmed
  for you: a value that can never match would silently refuse every sign-in it was added to permit, and
  the symptom would appear at the identity provider rather than here.
- **The refusal precedes the redirect.** An untrusted provider never authenticates anybody on this
  application's behalf, and a `PolicyResolutionFailed` row is committed to `logs.AuthenticationEvent`
  before the throw — a refusal nobody can see afterwards is a refusal nobody can distinguish from an
  outage.

`G-21`. `_tests/080` section 2 probes both the untrusted issuer and the `AllowFederated = 0` refusal it
sits behind.

### 7.4 Failed sign-ins

`auth.LoginAttempt` records every attempt, successful or not, with the outcome and the reason.
Lockout is by **user and by client address independently**: a threshold of failures against one
account locks that account, and a threshold from one address throttles the address regardless of
which accounts it is trying. The second is what stops credential stuffing, which the first does
not.

Thresholds and windows are `config.ApplicationSetting` rows, not constants, because an
externally-facing Variant 3 deployment and an internal Variant 2 deployment want different
numbers. `025_config_tables.sql` seeds them, and `auth.uspRecordLoginFailure` reads these five:

| Key | Default | Meaning |
|---|---|---|
| `Authn.LockoutThreshold` | `5` | Failures against one account, inside the window, that lock it |
| `Authn.LockoutWindowMinutes` | `15` | The window both counts are taken over |
| `Authn.LockoutDurationMinutes` | `15` | How long `auth.User.LockoutEndUtc` is set forward |
| `Authn.AddressThreshold` | `20` | Failures from one client address, inside the window, that throttle it |
| `Authn.AddressWindowMinutes` | `15` | The window the address count is taken over |

**The two counts are taken independently and neither is derived from the other.** The account count
filters on `UserName`; the address count filters on `ClientAddress` and ignores which accounts were
tried. A single query grouped by one of them cannot answer both questions, and the shape that looks
like it can — count the failures for this account *from this address* — is precisely the one that
lets credential stuffing through, because each account sees only one or two failures.

**An account lockout is a state change on `auth.User`; an address throttle is not.** There is no
table of throttled addresses: the address count is recomputed from `auth.LoginAttempt` on each
attempt, because an address is not an entity this design owns and a table of them is a table that
grows without bound and needs expiring. `auth.uspRecordLoginFailure` returns both counts and both
verdicts, so the application can refuse the next attempt without a second call.

---

## 8. Authorization: permissions, roles, profiles

### 8.1 Permissions

About thirty, in seven families (Appendix A has the full catalogue):

| Family | Covers | Example members |
|---|---|---|
| `Data` | business records | `Data.Read`, `Data.Insert`, `Data.Update`, `Data.SoftDelete`, `Data.Restore`, `Data.Export`, `Data.Execute`, `Data.Approve`, `Data.Reassign` |
| `User` | the person records | `User.Read`, `User.Create`, `User.Update`, `User.Deactivate`, `User.ResetCredential` |
| `Authz` | profiles and role grants | `Authz.ProfileRead`, `Authz.ProfileCreate`, `Authz.ProfileUpdate`, `Authz.ProfileDeactivate`, `Authz.RoleRead`, `Authz.RoleDefine`, `Authz.RoleAssign`, `Authz.RoleRevoke` |
| `Tenant` | the hierarchy | `Tenant.Read`, `Tenant.Create`, `Tenant.Update`, `Tenant.Deactivate` |
| `Config` | application configuration and the UI catalogue | `Config.Read`, `Config.Update`, `Config.UiCatalogUpdate` |
| `Audit` | the trails | `Audit.ReadAuthentication`, `Audit.ReadAuthorization`, `Audit.ReadDataChange` |
| `Platform` | the platform itself | `Platform.ManageApplications`, `Platform.RebuildSecurityCache`, `Platform.BypassRowSecurity` |

The requirement asks for separate roles for reading, inserting, updating, assigning roles,
creating users, updating users, and executing procedures, and asks for others to be added if
there are any. `Data.Read`, `Data.Insert`, `Data.Update`, `Authz.RoleAssign`, `User.Create`,
`User.Update` and `Data.Execute` are those seven. The additions are `Data.SoftDelete` and
`Data.Restore` (deleting is not updating, and this database soft-deletes), `Data.Export` (bulk
extraction is the disclosure path that read permission alone does not distinguish),
`Data.Approve` and `Data.Reassign` (decisions, which an auditor will want separable from edits),
`Authz.RoleDefine` (defining what a role *means* is a far larger authority than handing an
existing one out, and the requirement's delegated county administrators should generally not
have it), the `Tenant` family, the `Audit` family, and the `Config` family.

**`Data.Execute` needs one clarification.** It does not mean "may call stored procedures" —
every user calls stored procedures, because that is the only access path there is. It gates
procedures the application registers as *operations*: a batch recalculation, a bulk status
change, a nightly reconciliation triggered from a screen. The procedure checks it explicitly;
§14.2 shows how.

**Each permission carries its meaning in the row, not only in this document.**
`auth.Permission.PermissionDescription` holds the Appendix A sentence, and
`115_seed_reference_data.sql` writes it. Without it, the text beside a checkbox in a role editor
has to live in the UI project, every application built from this template re-types the same
thirty-five sentences, and they drift from Appendix A with nothing detecting it. `BL-037`.

`auth.PermissionCategory` carries the family. `auth.Permission` denormalises
`PermissionCategoryCode` alongside `PermissionCategoryId` and the composite foreign key covers
both, so a row cannot name one family by id and another by code — the same arrangement as
`TenantTypeCode` on `auth.Tenant` (§5.1).

### 8.2 Roles

`auth.Role` is owned by a tenant (`OwnerTenantId`) and scoped to an application. Its natural key
is `(ApplicationId, OwnerTenantId, RoleCode)`, filtered on `IsDeleted = 0`.

**Owner-tenant ownership is what makes role definition delegable without collision.** A role the
agency defines at the root is usable anywhere. A role Anne Arundel defines is usable only within
Anne Arundel. The rule is `INV-04`:

> A role R may be granted at scope S only if `R.OwnerTenantId` is an ancestor-or-self of S.

This also disposes of a trap the source requirements contain deliberately. In the Variant 1
narrative the agency's fourth role is called "D" and Anne Arundel's first role is called "D1",
while Baltimore City's role "E2" shares its name with an agency *user* called E2. Under this
design none of that matters in the slightest: `(Agency, 'D')` and `(AnneArundel, 'D1')` are
different rows in different scopes, user E2 is in a different table entirely, and no code
anywhere compares a role code to a literal.

**One half of `INV-04` is structural, not procedural.** `auth.Role.(OwnerTenantId, ApplicationId)`
is a composite foreign key onto `UX_auth_Tenant_Id_Application` — an *unfiltered* `UNIQUE
(TenantId, ApplicationId)` added to `auth.Tenant` by a guarded `ALTER` in `030_auth_tenant.sql`,
because a foreign key cannot reference a filtered index. A role whose owner tenant belongs to
another application is therefore unrepresentable, rather than merely refused by
`auth.uspAssignRoleToProfile`. That matters because a template ships with a bootstrap script, a
seed script and an administrator holding SSMS, and rows arrive by all three. The grant-side half of
`INV-04` — the scope check — remains procedural, because it depends on the closure.
`055_auth_role.sql` refuses to install if the constraint is absent. `BL-040`.

`auth.Role.RoleDescription` carries what the role is *for*, for the same reason
`auth.Permission.PermissionDescription` does. Both stay editable on a system role, because
`115_seed_reference_data.sql` converges the labels on every deployment while `INV-10` protects the
code, the flag and the row's existence. `BL-037`.

**`IsAssignable` is not `IsActive`.** `IsAssignable = 0` means the definition stands and existing
grants keep working, but no *new* grant may be made — a role being retired, or one composed for a
migration that should not spread. Revoking it from everyone would destroy the record of who held it
(`P-07`) and soft-deleting it would take "what did this role mean last March" with it, so neither
is the mechanism. The enforcement point is `auth.uspAssignRoleToProfile` and the number is
`E-50047`; an unassignable role is a perfectly legal row and nothing in `055_auth_role.sql` checks
it.

**`INV-10` does not mean "a system role is frozen", and the difference matters enough to enumerate.**
Saying only that a system role "may not be modified" is what `G-33` recorded, because the obvious
reading of that sentence is wrong in three places and a project writing its own maintenance
procedure would reimplement the wrong rule. Column by column, for a role with `IsSystemRole = 1`:

| Column | May it change? | Enforced by | Why |
|---|---|---|---|
| `RoleName`, `RoleDescription` | **Yes** | nothing — deliberately | A label is not a meaning. A deployment may reasonably want `PLATFORM_ADMIN` to read "System Administrator" on screen. `115_seed_reference_data.sql` converges the labels on every deployment anyway, so a local edit is understood to be transient. |
| `RoleCode` | No | `auth.trg_au_updt_Role` (`E-50012`) | The code is the identifier that `900_bootstrap_first_admin.sql` and Appendix A refer to by literal. |
| `IsSystemRole` | No | `auth.trg_au_updt_Role` (`E-50012`) | Nothing may promote its own role into the protected set, and nothing may demote a shipped one out of it. `auth.uspDefineRole` hard-codes `IsSystemRole = 0` for the same reason. |
| The row's existence (`IsDeleted`) | No | `auth.trg_au_updt_Role` (`E-50012`) | Appendix A documents these roles; a deployment that deletes one has a database Appendix A no longer describes. |
| The permission set (`auth.RolePermission`) | **No — not at all** | `auth.uspSetRolePermissions` (`E-50172`) | That set *is* the meaning Appendix A documents. There is no half of it that may safely move, so the procedure refuses the call outright rather than filtering it: not added to, not removed from, not emptied. |
| `IsAssignable` | **May be set back to 1; may never be cleared** | `auth.uspUpdateRole` (`E-50172`) — **and nothing else** | `900_bootstrap_first_admin.sql` grants five shipped roles **by code**, and an unassignable role refuses every new grant with `E-50047`. Freezing a shipped role therefore turns the *next* deployment's bootstrap into a failure nobody would connect back to the call that caused it. Setting it back to 1 restores the shipped state and is allowed. |

Two enforcement points with different reach, and the asymmetry is the part `G-33` says must be
written down. `auth.trg_au_updt_Role` is a trigger, so its three rules hold for SSMS, for a
migration script and for anything else that reaches the table — that is the point of putting them
there. The `IsAssignable` rule lives **only** in `auth.uspUpdateRole`, so a project that writes its
own role-maintenance procedure inherits nothing and can freeze a shipped role without being stopped.
**Where a rule lives only in a procedure, this design says so**, because that is the rule most
likely to be lost. `BL-064` records the further finding that came out of writing this down: the
refusal message for the permission-set case used to recommend freezing the role instead, which is
the one remedy `uspUpdateRole` refuses with the same number.

`auth.RolePermission` maps roles to permissions. Both tables are soft-deleted, so "what did this
role mean last March" is answerable.

**The bulk shapes take a JSON array.** `auth.uspSetRolePermissions` (the permission list of one
role) and `auth.uspAssignRolesToProfiles` (one role to many profiles, §20 item 2) each take a single
`@Payload NVARCHAR (MAX)` and shred it with `OPENJSON`, rejecting a malformed payload with
`E-50046` before they touch a table. `055_auth_role.sql` creates **no** table types; §14.6 `D-13`
gives the argument, and `G-20` records that it replaced an earlier table-valued-parameter design.
The `.claude/hooks/validate-sql.py` gate rejects `CREATE TYPE … AS TABLE` outright, so this is not
a preference a later script can quietly depart from.

### 8.3 Profiles

`auth.UserProfile` is `(UserId, TenantId, ProfileName, IsDefault, IsActive, …)`. A user may hold
many. `ProfileName` is what the user sees in the profile switcher and what the UI must display
(`UI-01`); it defaults to the tenant name but is editable, because a user with two profiles at
the same tenant needs to tell them apart.

`IsDefault` marks the profile activated at sign-in. Exactly one per user, enforced by a filtered
unique index (`INV-03`).

**`ProfileName` is unique per `(UserId, TenantId)` among live rows**, by a second filtered unique
index. The switcher of §12 is a list of names and nothing else, so two live hats called "Case
Worker" at one organization produce a list in which the right entry cannot be identified — and the
cost is not cosmetic, because picking the wrong one sets a different `ScopeTenantId` and therefore a
different set of visible rows. Uniqueness is per tenant and not per user, because the same person
legitimately has a "Case Worker" hat at two organizations. `BL-036`.

### 8.4 Role grants and their scope

`auth.UserProfileRole (UserProfileId, RoleId, ScopeTenantId, GrantedByProfileId, GrantedUtc, ExpiresUtc)`.

`ScopeTenantId` is where the grant reaches. It defaults to the profile's own tenant, which is
the common case and the one an administrator never has to think about. Setting it elsewhere is
what Variant 2 needs:

> A program officer's profile is bound to their program. It carries *Editor* scoped at the
> program — so their inserts and updates land there — and *Read-only* scoped at the agency, so
> they can see every other program's records without switching profile. One profile, two grants,
> exactly the authority the requirement describes.

`ExpiresUtc` supports time-boxed authority — the backup role-assigner who covers for two weeks.
It is nullable and normally null. An expired grant is filtered out at materialization time; the
row remains, because `P-07`.

### 8.5 Deactivating a profile versus deactivating a user

Deactivating a **user** stops that person signing in at all. Deactivating a **profile** removes
one hat: the person can still sign in and use their other profiles. Both are soft. A user with
no usable profile can authenticate successfully and then reach a screen that tells them so — an
outcome the UI must handle gracefully rather than crashing or, worse, defaulting to some
unscoped view (`UI-09`).

**`auth.TenantDefaultRole` is the other half of profile lifecycle, and it now has a writer.** It decides
what authority a *new* profile arrives with (§11.5), inherited down the tree so that one row on a branch
governs every tenant beneath it (§16.4) — which makes it exactly the configuration surface a tenant
administrator will reach for, and until `G-43` was closed changing it meant a `MERGE` in a seed script or
an `INSERT` in SSMS: no permission check and no trail, for a decision that silently applies to everybody
admitted afterwards. `auth.uspSetTenantDefaultRoles` is the contract — `Tenant.Update` **and**
`Authz.RoleAssign` at the tenant, because a default-role list is a standing grant rather than a label;
one `logs.AuthorizationChange` row per code added or removed; and the whole list refused rather than
partly applied when a code is unknown, out of the role's reach (`INV-04`) or frozen (`E-50098`). The
procedure is documented with its authentication-policy twin in §7.2, because the two tables had the same
shape of absence and were fixed in one pass.

**Changing the defaults changes nothing that already exists, and that is the intended reading.** The list
is resolved at profile creation by `auth.uspGrantTenantDefaultRoles` (§11.5) and never re-applied, so
editing it is a decision about who arrives next. Widening the authority of people already admitted is a
grant, which has its own permission, its own scope check and its own trail row — and conflating the two
would be a screen that quietly re-granted a role somebody had deliberately revoked.

### 8.6 The materialized effective grant

`auth.ProfilePermissionScope (UserProfileId, PermissionId, ScopeTenantId)` is the flattening of
profile → roles → permissions, with expired, deleted and inactive rows already removed. It is
**not** expanded over the tenant subtree — `D-07` says why.

It is rebuilt for one profile by `auth.uspRebuildProfilePermissionScope @UserProfileId`, called
from every procedure that changes a grant, a role definition, or a profile's state. The
whole-database rebuild (`@UserProfileId = NULL`) is for deployment and repair.

`IX_auth_ProfilePermissionScope_Lookup` is **filtered on `IsDeleted = 0`**, which makes the filter
load-bearing rather than decorative: a reader that omits `IsDeleted = 0` from its own `WHERE` clause
both misses the index and counts retired authority as live. Every reader in this design carries it,
including the row-security predicates. `BL-039`.

This table is the one piece of derived state in the design, and derived state drifts.
`950_verify_deployment.sql` recomputes it from source and fails the build on any difference;
`G-03` tracks making that a scheduled check rather than a deployment-time one.

**What has actually been proved about it.**
`database/_tests/050_authorization_and_session.sql` drives fourteen mutations — grants,
revocations, a re-grant, a role edited while two profiles hold it, a permission retired out from
under a role, an expiry, a profile deactivation and a user deactivation — and after *each* one
compares this table against the set derived longhand from the rules above, in **both** directions.
The two directions have different consequences and the test labels them: a missing row is a false
*denial*, which the user sees as an empty screen, and an extra row is a false *grant*, which nobody
reports. Fourteen exercised, none failed. The comparison is written out independently rather than
re-using the rebuild procedure's own query, which would only have proved the procedure consistent
with itself. Two constraints found by that test are worth knowing before writing a caller:
`CK_auth_UserProfileRole_Expiry` requires `ExpiresUtc > GrantedUtc`, so an already-expired grant is
expressed by backdating `GrantedUtc`; and the filtered uniqueness of a live grant means a revoked
grant must be resurrected **in place**, one row at a time, never re-inserted or restored wholesale
(`Msg 2601`).

---

## 9. How a request is authorized, end to end

One worked path, from the browser to the row. Every application request follows it.

```
 1. Browser sends its session cookie.
 2. Application resolves the cookie to a session identifier and opens a pooled connection
    as the application login.
 3. FIRST STATEMENT ON THE CONNECTION, ALWAYS:
        EXEC auth.uspSetSessionContext @SessionTokenHash = @hash;
    The procedure:
      - finds the live session by hash, checks expiry and idle timeout
      - loads the session's ActiveUserProfileId
      - checks the profile is active and not deleted
      - checks the profile's tenant is usable (itself and every ancestor)
      - checks the user is active and not locked out
      - sets SESSION_CONTEXT: UserId, UserProfileId, ActingTenantId, AppUser, ApplicationId
      - slides the idle window: LastSeenUtc and IdleExpiryUtc
    Any failure raises in the E-5002x range and nothing further runs.
 4. Application calls the business procedure, e.g. dbo.uspSaveCaseFile.
 5. The procedure checks the coarse permission it needs:
        EXEC auth.uspDemandPermission @PermissionCode = N'Data.Update', @TenantId = @TenantId;
    which raises E-50030 if the active profile does not hold it at that tenant.
 6. The procedure does its work. Row-level security filters and blocks underneath it (§10),
    so even a procedure that forgot step 5 cannot read or write another tenant's rows.
 7. The audit columns are stamped from SESSION_CONTEXT('AppUser'), not from ORIGINAL_LOGIN().
 8. Connection returns to the pool. sp_reset_connection clears SESSION_CONTEXT.
```

**Steps 5 and 6 are deliberately redundant.** Step 5 gives a clean, catchable error the UI can
render — "you do not have permission to update this case". Step 6 is the guarantee. A procedure
that skips step 5 produces a confusing empty result or a policy violation instead of a helpful
message, which is a bug; a procedure that could skip step 6 would be a vulnerability. They fail
differently on purpose.

**Step 3 takes the hash, not the token.** `auth.uspSetSessionContext` is declared
`@SessionTokenHash VARBINARY (32)` and the application hashes the token before it calls. The
sketch above originally read `@SessionToken` and said the procedure hashes it; that would have
made the plaintext token a parameter value, and parameter values reach query plans, extended
events and error text. The token never crosses the boundary into this database at all — only its
SHA-256 does, and `105_auth_session_procedures.sql` never writes even the hash to
`logs.ExecutionLog`, because inside the database the hash *is* the credential (`BL-043`). A hash
that is not 32 bytes is `E-50100`.

**Step 3 also slides the idle window, and that is the request log.** There is no per-request row
anywhere: `auth.UserSession.LastSeenUtc` and `IdleExpiryUtc` move forward by the tenant's
`IdleTimeoutMinutes`, capped at `AbsoluteExpiryUtc`. One narrow `UPDATE` of one row per request,
rather than an insert per request into a log nobody reads — which is also why the authorization
hot path reports nothing about itself (`G-22`).

### 9.1 The two permission questions

| Question | Answered by | Cost |
|---|---|---|
| "Does the active profile hold permission P at tenant T?" | `auth.udfHasPermission (@PermissionCode, @TenantId)` — scalar, inline-able | two index seeks |
| "Which tenants does the active profile hold permission P on?" | `auth.tvfPermissionScope (@PermissionCode)` — table-valued | one seek, one range scan |

The second is what a report uses to decide what to aggregate. It is **not** enough on its own to
populate a tenant picker — see §9.2.

### 9.2 What the scope function does not answer

`auth.tvfPermissionScope` answers exactly one question: which tenants does this profile hold this
permission on. It does not join `auth.udfIsTenantUsable`, so a tenant that has been deactivated —
or whose parent has — still comes back.

That is deliberate. Authority is a *grant*, and a grant survives a tenant being deactivated so
that it comes back intact when the tenant does; a function that silently dropped those rows would
make a suspension look like a revocation. But it means a picker built straight from this function
offers an organization the user cannot act for: they choose it, and `auth.uspSetSessionContext`
refuses with `E-50021` after the click.

So the rule for callers is: join `auth.udfIsTenantUsable` (or go through the tenant read
procedure) for anything a user **chooses from**; use the function unjoined when the question is
"does this person have authority here at all", for example when deciding whether a feature appears
at all. `UI-33`.

### 9.3 Step 5 comes before the transaction, not inside it

`auth.uspDemandPermission` records the denial it raises — that is the point of having a procedure
rather than an `IF` — and the record is written by the same procedure that throws. So a caller
that opens a transaction, then demands the permission, then lets the `;THROW` unwind to a
`ROLLBACK`, rolls the denial trail back with the work. The attempt leaves no trace anywhere. It
is invisible in exactly the case worth seeing: a profile repeatedly trying something it is not
entitled to do.

The ordering in step 5 is therefore a **requirement**, not a style preference. Authorize first,
`BEGIN TRANSACTION` second. Where a denial must survive a rollback that a caller already owns, the
recorder is called on a separate connection or the row is written after the rollback completes;
what must never happen is a denial whose only record shares a transaction with the statement it
denied. `BL-042`, and it is why the `180` domain procedures in Phase 7 have this ordering as an
acceptance criterion rather than a convention.

---

## 10. Row-level security

### 10.1 What is protected

Every table carrying a `TenantId`, registered in `config.TenantScopedTable`. Registration is
data, not code: `120_rls_policy.sql` reads the registry and adds a predicate for each registered
table. A new domain table is protected by adding a row and re-running that script.

**An unregistered tenant-scoped table returns every tenant's rows to every tenant.** That is the
single most dangerous failure mode in this design, and it fails *silently and permissively*,
which is the worst combination. Three things guard it:

1. `950_verify_deployment.sql` fails the build if any table in any registered schema has a
   `TenantId` column and no registry row.
2. The registry row is part of the same script that creates the table, by convention.
3. `G-01` tracks promoting check (1) to a scheduled job, because a table added by hand between
   deployments is exactly the case (1) does not catch.

### 10.2 The predicate

The predicate exists in two forms. `100_auth_functions.sql` installs the **readable** form, which
joins `auth.Permission` by code:

```sql
CREATE OR ALTER FUNCTION auth.tvfTenantReadPredicate (@TenantId INT)
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN
    SELECT 1 AS Allowed
     WHERE EXISTS (SELECT 1
                     FROM auth.ProfilePermissionScope AS pps
                     JOIN auth.Permission             AS p
                       ON p.PermissionId = pps.PermissionId
                     JOIN auth.TenantClosure          AS tc
                       ON tc.AncestorTenantId = pps.ScopeTenantId
                    WHERE pps.UserProfileId     = TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT)
                      AND pps.IsDeleted         = 0
                      AND tc.DescendantTenantId = @TenantId
                      AND tc.IsDeleted          = 0
                      AND p.IsDeleted           = 0
                      AND p.PermissionCode      = N'Data.Read')
        OR TRY_CAST (SESSION_CONTEXT (N'BypassRowSecurity') AS BIT) = 1;
```

`120_rls_policy.sql` then replaces the `auth.Permission` join with a literal list of ids and binds
the result: `AND pps.PermissionId IN (17, 84, 152)`. That is the form that runs in production.

Six things about it are load-bearing:

- **`WITH SCHEMABINDING` is mandatory** — RLS will not accept a predicate function without it.
  The consequence is that `auth.ProfilePermissionScope`, `auth.Permission` and
  `auth.TenantClosure` cannot be altered while any policy references the function — and neither
  can the function itself (`Msg 3729`). §21.3 gives the change procedure; it is a deployment
  blocker, not a caution.
- **The permission ids are literals resolved at deploy time**, not a lookup by code. A join to
  `auth.Permission` inside a per-row predicate is a third seek for a value that never changes.
- **The list is plural, not a single id.** `Data.Read` is not one row: the catalogue carries one
  permission row per `(PermissionCode, ApplicationId)`, so four applications give four `Data.Read`
  ids and the predicate must accept all of them. A single-id predicate would have denied three
  applications out of four (`BL-039`).
- **An empty catalogue resolves to the sentinel `-1`, not to an omitted clause.** Before
  `115_seed_reference_data.sql` has ever run, the generated predicate says
  `pps.PermissionId IN (-1)`, which no row satisfies, so every non-maintenance session sees
  nothing. Dropping the clause instead would have produced a predicate that *grants* every row to
  every profile. This fails closed by construction, and `120`'s closing report says `PENDING`
  rather than `OK` when it happens. The mirror image — ids that have **moved** since the predicate
  was built — is the dangerous case, because it is partial rather than total and raises no error at
  all: see `UI-35`, and re-run `120` (or
  `EXEC auth.uspRebuildTenantAccessPolicy @Action = N'Rebuild'`) after any change to
  `auth.Permission`. The report re-derives the expected list and `CHARINDEX`es it against the
  deployed definitions, so running the script is also the diagnosis.
- **`TRY_CAST`, not `CAST`.** A session with no context set yields `NULL`, which must produce
  "no rows", not a conversion error. A conversion error inside a security predicate surfaces as
  an unintelligible failure on an unrelated query.
- **The bypass is a session-context key, not a role test.** §10.5.

`IsDeleted = 0` appears three times and each one is a separate decision: a soft-deleted scope row
must stop granting, a soft-deleted closure edge must stop propagating, and a retired permission
must stop matching by code even while its row survives for the audit trail.

### 10.3 Filter and block, and why they differ

| Predicate | Operation | Tests |
|---|---|---|
| `FILTER` | `SELECT`, `UPDATE`, `DELETE` | `Data.Read` scope covers the row's tenant |
| `BLOCK AFTER INSERT` | `INSERT` | the row's tenant **equals `ActingTenantId`** *and* `Data.Insert` scope covers it |
| `BLOCK BEFORE UPDATE` | `UPDATE` | `Data.Update` scope covers the row's **existing** tenant |
| `BLOCK AFTER UPDATE` | `UPDATE` | `Data.Update` scope covers the row's **resulting** tenant |

**This asymmetry is `P-06` and it is the heart of the design.** Reading is scoped, so the agency
reads everything it has been granted. Inserting is anchored to the acting tenant, so a record
created while wearing the Anne Arundel profile *is* an Anne Arundel record and cannot be
anything else.

That is what turns the requirement's narrative into enforcement. The agency user who does data
entry intended for a county, while wearing an agency profile, creates agency-tenanted rows; the
county cannot see them; the requirement calls this a data entry error and this design makes it
one that is visible rather than one that silently succeeds. And the user with profiles in two
counties cannot create a Baltimore City record while wearing the Anne Arundel profile at all —
the insert is blocked, not merely mis-tenanted.

**A block violation is `Msg 33504`, always.** Not an empty result, not a custom error: the four
predicates above are bound as one `auth.TenantAccessPolicy`, and a `BLOCK` predicate returning no
rows aborts the statement with the same number whichever verb tripped it. A UI that branches on
error numbers needs 33504 mapped once, centrally (`UI-08`). The eight cells of the table above are
exercised individually in `database/_tests/060_row_security.sql` section 6, each refusal expected
**by number** rather than by "it failed".

**`TenantId` is immutable after insert.** Enforced in the `AFTER UPDATE` audit trigger on each
domain table with `E-50011`. The `BLOCK AFTER UPDATE` predicate is the second line of defence;
the trigger gives the better error message.

**On a real domain table the tenant move is usually refused by `Msg 547` first, and that is not a
bug to fix.** The demo tables — and any table following the convention — carry composite foreign
keys that include `TenantId`: `dbo.CaseFile (AssignedToProfileId, TenantId)` and
`dbo.CaseNote (CaseFileId, TenantId)`. An `UPDATE` that changes `TenantId` therefore breaks a
foreign key *before* the block predicate is ever evaluated, so what surfaces is a
referential-integrity failure and not the 33504 the matrix above describes. Two defences in a row,
and the outer one speaks the wrong language. Reaching the block predicate at all takes a row with
no composite-FK children and no assignment — which is what `_tests/060` section 6g has to plant.
The consequences for a caller: map `Msg 547` on tenant-scoped tables to "this record cannot be
moved to another organization" alongside 33504, and better, do not offer `TenantId` on an edit form
at all. `BL-045`, `UI-38`.

**The block predicate cannot tell a soft delete from an update, and the permission catalogue pays for
it.** `BLOCK AFTER UPDATE` is checked against one permission, and the verbs `Data.SoftDelete`,
`Data.Restore` and `Data.Approve` are all *implemented* as `UPDATE` statements — a soft delete sets
`IsDeleted = 1`, an approval sets `Status` and the approver columns. The predicate therefore tests
`Data.Update`, and the consequence propagates straight into the seed data: `DATA_STEWARD` and
`APPROVER` must **also** carry `Data.Update`, or the procedure's own permission check passes and the
statement it then issues is refused by row security with `Msg 33504`. That is why
`180_dbo_application_procedures.sql` closes with a report row counting the five `Data.*` verbs that
travel together, and it is `G-38`.

State it here as a consequence of the predicate rather than as a property of the roles, because the
roles look wrong when read on their own: `DATA_STEWARD` in §16.2 appears to grant editing authority it
was never meant to confer, and an administrator trimming `Data.Update` out of it to tidy up would
break soft delete entirely with an error naming neither. The alternative — widening the block predicate
to admit `Data.SoftDelete`, `Data.Restore` and `Data.Approve` as well as `Data.Update` — is the better
model, because then the permission a role carries would match the authority it needs. It is not taken
here because the predicate is a schema-bound object over every registered table, so changing it is the
drop-and-re-add of §21.3 and it is `G-04` territory. `INV-12` is what keeps the current arrangement
honest in the meantime: the procedures demand the *fine* verb, so a profile with `Data.Update` alone
still cannot soft-delete through the shipped surface (§10.4, `G-05`).

**Approval is not delegable across tenants, and that is a provisioning decision, not a runtime one.**
The rule is general and worth stating once at the model level:

> Any operation that records a *profile* against a row requires a profile **at that row's own
> tenant** — not merely a profile with authority reaching it.

`dbo.CaseFile` carries `FK_dbo_CaseFile_ApprovedBy_Tenant` and `FK_dbo_CaseFile_AssignedTo_Tenant` on
the composite `(ProfileId, TenantId)` pair, which is what makes the attribution *real*: the recorded
approver demonstrably held a profile at the organization whose record they approved, and no later
query has to take that on trust. The price is that a root-scoped administrator holding `Data.Approve`
over an entire subtree **cannot** approve a child tenant's case file from their root profile —
`E-50203`, raised deliberately by `dbo.uspApproveCaseFile` before the `UPDATE`, so the caller gets an
explanation instead of the `Msg 547` the foreign key would otherwise give them (Appendix B). They must
switch to a profile at that tenant, and §12.1 shows what the switch costs.

The part that must be decided early is the provisioning consequence, because it is settled when
profiles are created and not when somebody first tries to approve something: **an approver needs a
profile at every tenant whose records they approve.** A deployment that models central approvers as a
single root profile with wide scope will work for reading and filtering and fail on the first
approval, at which point the remedy is to create profiles across the subtree — a data-shape change,
under time pressure, for a constraint that was knowable on day one. `G-40`, and §17.2 walks the case.

### 10.4 What RLS cannot do, and what covers the difference

RLS sees rows, not intent. It cannot distinguish a soft delete from an ordinary update, because
both are `UPDATE … SET IsDeleted = 1`. It cannot tell an export from a read.

So the finer permissions — `Data.SoftDelete`, `Data.Restore`, `Data.Export`, `Data.Approve`,
`Data.Reassign`, `Data.Execute` — are enforced **only** in the stored procedures, by
`auth.uspDemandPermission`. A caller who reaches the table directly with `UPDATE` privileges can
soft-delete a row they merely hold `Data.Update` on.

This is a real limitation, stated rather than papered over. It is acceptable here because
`P-11` means there is no direct-table access path for the application: `applicationRole` holds
`SELECT, INSERT, UPDATE` on `SCHEMA::dbo` because the procedures need it through ownership
chaining, and the application login's only entry point is `EXECUTE` on named procedures. It is
recorded as `G-05` so that nobody later grants ad-hoc table access believing RLS covers it.

### 10.5 The bypass, and the DBA problem

RLS applies to `db_owner` and to `sysadmin`. A DBA who connects with SSMS and selects from a
protected table sees nothing at all — no error, no warning, an empty grid. Every person who
touches this database will hit this once, and several will conclude the data has been lost.

Pretending the need does not exist produces the worst outcome, which is someone disabling the
policy at three in the morning and not re-enabling it. So the design provides a controlled path:

- `auth.uspBeginMaintenanceSession` sets `SESSION_CONTEXT('BypassRowSecurity') = 1`.
- It requires membership of the `rlsBypassRole` database role, which no application login is
  a member of and which is granted to named human accounts only.
- It writes a `logs.AuthenticationEvent` row of type `MaintenanceBypass` **before** setting the
  key, so the record exists even if the session then fails.
- The key is not `read_only`, so it can be cleared, and `uspEndMaintenanceSession` clears it —
  reporting `@BypassCleared = 1` — and writes a matching `MaintenanceBypassEnded` event, so the
  trail carries the window's two ends and not just its opening.

**Both events name a person, and the rule for who is not obvious.**
`CK_logs_AuthenticationEvent_Attributable` requires `UserId` or `UserName` to be present, so an
event attributable to nobody is refused outright (`Msg 547`) — an audit trail of anonymous events
is not a trail. A maintenance session has no `UserId`, because the actor is a database principal
and not a row in `auth.User`. So `UserName` carries it, and both it and the separate `Actor` column
are set from `ORIGINAL_LOGIN()` — the **real** login, not `SUSER_SNAME()`. Recording the
impersonated name would let anyone who can `EXECUTE AS` open a bypass window under someone else's
name, which is the one thing this trail exists to prevent.

Both procedures shipped with both fields left NULL and the defect survived two phases, because the
only path anything exercised was the one that refuses a non-member before writing anything.
`BL-046`, `UI-39`; it was found by `database/_tests/060_row_security.sql` section 7, the first
thing ever to reach the accepted path through a real member of `rlsBypassRole`.

Reporting and ETL use the same door with their own service account. `UI-18` and §19.5.

### 10.6 Performance — measured

Everything in this section below the first two paragraphs is **measured, not predicted.** Phase 5
built the population, ran the numbers and recorded them here. The scripts are
`database/_perf/T069_load_volumes.sql`, `T070_measure_predicates.sql` and
`T071_measure_rebuilds.sql`; they are not in the install manifest and never run against a real
database — they run against a separate one, `testTemplateBoot`, because a measurement fixture sitting
in the working database is a row somebody will eventually mistake for real.

**`docs/30-performance-measurements.md` (`PERF-AUTH-001`) is the record; this section is the summary
that the design needs in order to be read on its own.** Where the two carry the same figure they now
agree, and reconciling them produced the one methodological note worth having: *the logical-read
counts are stable across runs and the microsecond figures are not.* Two runs of the same script on
the same population returned identical reads and times differing by up to 20%. So every argument
below is made on reads, and the times are reported for scale only. A design that rested on
microseconds would be a design that changed its mind when the machine was busy.

The predicate is two index seeks against two small tables. `auth.ProfilePermissionScope` is
roughly *profiles × permissions granted*; `auth.TenantClosure` is *nodes × average depth*. Both fit
in cache and stay there.

#### The population the numbers come from

1,050 live tenants in a five-level tree (8 agencies → 5 divisions → 5 programs → 4 jurisdictions),
4,939 closure rows at maximum depth 4, 5,000 users and 5,000 profiles spread across the 1,000
leaf-ish tenants, 26,255 role grants, **57,342 scope rows** — a median of 11 per profile, P95 of 15 —
and 200,000 rows each in `dbo.CaseFile` and `dbo.CaseNote`. One profile in four holds a second grant
at its parent tenant, so the population exercises the closure side of the join rather than
flattering it.

The baseline throughout is `dbo.PerfCaseFileNoRls` — a column-for-column copy of `dbo.CaseFile`,
same indexes, same 200,000 rows, not registered in `config.TenantScopedTable` and therefore not
bound by the policy. Comparing against `BypassRowSecurity = 1` would have measured the bypass, and
disabling the policy would have measured a different plan cache; an unprotected twin of the same
rows is the only honest baseline.

#### What the predicate costs

| Pattern | Iterations | µs per call | Logical reads per call | Against baseline |
|---|---|---|---|---|
| Point read by primary key, RLS bound | 2,000 | 13.5 | 8 | |
| Point read by primary key, baseline | 2,000 | 5.0 | 3 | **+5 reads** |
| Range scan, one tenant by status, RLS bound | 500 | 371 | 1,007 | |
| Range scan, one tenant by status, baseline | 500 | 32 | 6 | **168× reads** |
| Aggregate over everything visible, 1 scope tenant | 20 | 320,717 | 1,002,655 | |
| Aggregate over everything visible, 2 scope tenants | 20 | 412,297 | 1,392,655 | |
| Aggregate over everything visible, baseline | 20 | 17,475 | 1,405 | **714× reads** |
| `auth.udfHasPermission` alone | 5,000 | 24.8 | 7 | the decision itself |
| `auth.uspDemandPermission`, probe off | 5,000 | 55.7 | 12 | the whole call |

**The point read is the number that matters and it is fine.** Eight logical reads and 13.5 µs to
return one protected row is a cost the design can carry, and a point read by key is what the
application's procedures overwhelmingly issue.

**The aggregate is the number that matters and it is not fine.** Counting the thousand rows one
profile may see reads *a million pages*. The predicate is being evaluated per row of `dbo.CaseFile`
— all 200,000 of them — not once per query, and the answer degrades further as a profile's scope
widens: the two-scope-tenant profile pays 39% more than the one-scope-tenant profile for a query
returning five times as many rows.

#### The plan shape (`T-073`)

Read out of `sys.dm_exec_query_plan` rather than eyeballed. For all three RLS-bound shapes:

| | Semi-joins | Scope seeks | Scope **scans** | Closure seeks | Closure **scans** |
|---|---|---|---|---|---|
| Point read | 1 | 1 | **0** | 1 | **0** |
| Range scan | 1 | 1 | **0** | 1 | **0** |
| Aggregate | 1 | 1 | **0** | 1 | **0** |

**The asserted shape holds exactly.** The inline function folds in as a semi-join, both inner tables
are seeked, neither is ever scanned. This is the important negative result of Phase 5: the
million-page aggregate is **not** a missing index and **not** a plan regression, so no amount of
index tuning will fix it. The join is a nested loop and the predicate is driven once per candidate
row; the cost is the row count, and the only lever on it is not to write that query.

#### The rule that follows, and it is a rule for callers

> **Protected tables are for filtered access, not for aggregation.** Any query against a protected
> table must carry a predicate that an index can seek — a key, a tenant, a date range. A statement
> whose only filter is the RLS policy will read the whole table. Cross-tenant totals belong in a
> procedure that takes the tenant scope as an argument, not in a `SELECT COUNT (*)`.

#### The cost of keeping the caches (`T-071`, `T-072`)

| Operation | Tree | Calls | ms per call | Logical reads per call |
|---|---|---|---|---|
| `uspRebuildProfilePermissionScope`, one profile | 1,050 tenants | 20 | 45.4 | 1,500 |
| `uspRebuildProfilePermissionScope`, 1,000 × one profile | 1,050 tenants | 1,000 | 40.6 | 1,470 |
| `uspRebuildProfilePermissionScope`, all 5,000 profiles | 1,050 tenants | 1 | **181** | 299,616 |
| `uspRebuildTenantClosure` | 1,050 tenants, 4,939 rows | 5 | 39.4 | 51,590 |
| `uspRebuildTenantClosure` | 10,650 tenants, 62,539 rows | 3 | **791** | 924,657 |
| `uspRebuildProfilePermissionScope`, all profiles | 10,650 tenants | 1 | **166** | 44,733 |

Three findings, and the first one is a rule:

> **Above four profiles, rebuild all of them.** One all-profiles call costs 181 ms and rebuilds
> 5,000 profiles. One single-profile call costs 45 ms. So a thousand single-profile calls cost
> **40.6 seconds against 181 milliseconds for more work** — a factor of 224 — because the per-call
> cost is a transaction, a compile and two `logs.ExecutionLog` writes, and the actual work is
> negligible beside it. Administrative operations that touch more than about four profiles should
> call `auth.uspRebuildProfilePermissionScope` with `@UserProfileId = NULL`.

That rule is a rule for callers, and **no shipped procedure follows it**, because every administrative
procedure rebuilds the one profile it just changed. That is `G-39` — the only gap in this project that
exists because of a measurement rather than a defect or a documentation drift. Nothing is wrong,
nothing contradicts anything, and a bulk role assignment across a thousand profiles will still take
forty seconds where it could take a fifth of a second. `auth.uspRebuildEffectivePermissions` is the
fast shape and is reachable only by a platform administrator, so the fix is a caller-side one and is
deliberately left for the project that needs it.

Second: **the closure rebuild is sensitive to tree size and the scope rebuild is not.** Ten times
the tenants costs the closure rebuild 20× the time, but leaves the scope rebuild unchanged (181 ms →
166 ms; the read counts differ by more than the times do, which is plan and cache variance, not
work). That is `D-07` behaving exactly as designed: the scope table stores the *grant's* scope
tenant and not its expansion over descendants, so adding tenants cannot touch it. Had it been fully
expanded — the rejected alternative — this row would have grown with the tree, and re-parenting one
tenant would have invalidated the cache for every profile in the estate.

Third: **791 ms to rebuild the closure of a 10,650-tenant estate is acceptable**, and it is the cost
of *any* tenant move, however small, because the procedure takes no arguments and always rebuilds
everything. At the expected size it is 39 ms.

#### The `D-07` verdict (`T-074`, milestone M3)

**`D-07` is confirmed. The design ships as specified.** The materialized-but-not-expanded scope table
delivers what it promised: the predicate folds to a semi-join with seeks on both inner tables, the
point-read cost is 8 logical reads, and the write-side cost is insensitive to tree size in exactly
the dimension the rejected alternative would have been sensitive to. The million-page aggregate is a
real limit and is documented as a caller rule above rather than treated as a defect in `D-07`,
because the measured plan shape proves it is the row count and not the predicate structure.

Two conditions attach to that verdict, and they are the reason it is recorded here rather than
asserted:

1. The scope table must stay small. 57,342 rows at 5,000 profiles is 11 per profile; the numbers
   above do not license a design that grants sixty permissions to every profile.
2. `T-073`'s plan-shape check is not a one-off. `950_verify_deployment.sql` compares the
   materialized tables against their derived definitions; the plan shape deserves the same
   treatment on any release that touches `120_rls_policy.sql`.

#### The probe, and what it costs when it is switched off

**Measuring the predicate is harder than it looks, and that is `G-22`.** The predicates are
functions: a function cannot write to a table, and a schema-bound one must not try, so the single
code path that runs on every query in this database is the one path that reports nothing about
itself while every procedure around it logs. Per-call logging is not the answer either — the
predicate runs once per row per statement. `175_perf_instrumentation.sql` therefore ships the
measurement as a deliberate design: `logs.PermissionProbe`, an append-only table of burst
measurements; `logs.uspRecordPermissionProbe` to write one; `logs.uspPurgePermissionProbe` and
`logs.uspReportPermissionProbe` around it; `logs.vwPredicateFunctionStats` over
`sys.dm_exec_function_stats`; and a documented extended-events session. The functions themselves
stay silent.

The sample is taken by `auth.uspDemandPermission`'s *caller side* — the `-- 1b.` block — under
`Perf.PermissionProbeSampleRate`, which **ships at 0, meaning off.** 1,000 is the suggested
production value; 1 turns every call into a benchmark. It fires only when `@@TRANCOUNT = 0`, so it
can never extend a caller's transaction, and its `CATCH` swallows — the only swallowing `CATCH` in
the project — because a measurement must not fail an authorization.

**Its off-state cost was measured rather than assumed, which is the whole point:** the one
`config.ApplicationSetting` seek the disabled probe still performs costs **10.1 µs and 5 logical
reads per `auth.uspDemandPermission` call.** In reads — the measure PERF-AUTH-001 §1 says to argue
from, because microseconds vary by up to 20% between runs and reads do not — that is **5 of the
procedure's 12, or 42%**. In microseconds it looks milder, 18% of the procedure's own 55.7 µs, and the
mild-looking number is the one to distrust. It is not negligible, and the honest statement of the trade is
this: a deployment that will never sample should **delete the `-- 1b.` block from
`auth.uspDemandPermission`** and keep the rest of `175`, which costs nothing when unused. Everything
else in that script is inert until called.

---

## 11. Administrative authority — who may grant what

### 11.1 The invariant

This is the most consequential rule in the design, and it is one sentence.

> **INV-05.** A profile `G` may grant role `R` at scope `S` to profile `P` only if all of the
> following hold:
>
> 1. `G` holds `Authz.RoleAssign` at a tenant that is an ancestor-or-self of `P.TenantId`;
> 2. `G` holds `Authz.RoleAssign` at a tenant that is an ancestor-or-self of `S`;
> 3. `R.OwnerTenantId` is an ancestor-or-self of `S` (`INV-04`);
> 4. `R` belongs to the same application as `P`'s tenant tree.

Enforced in `auth.uspAssignRoleToProfile`, which raises `E-50040`, `E-50041`, `E-50042` and
`E-50043` respectively so that the UI can say which of the four failed.

Clause (1) is what confines a county's role administrator to that county's users. Clause (2) is
what stops that same administrator granting one of their users read access to a different
county — the interesting attack, and the one a naive implementation that only checks clause (1)
would allow.

### 11.2 A grantor need not hold what they grant

This looks wrong and is correct, because the requirement says so: the agency's role
administrator holds only the role-assigning role, does "no data entry for anyone", and
nonetheless assigns read and insert roles to others.

Separation of duty is the point. The person who decides who may edit records is an
administrative function, and requiring them to hold editing rights in order to hand them out
would *force* an over-privileged account into existence.

The requirement's other half — "he doesn't gain additional roles when he assigns them to
others" — needs nothing special: grants are explicit rows and nothing writes one for the
grantor.

### 11.3 The self-grant guard

The requirement does not raise it, and it is the obvious way to turn clause (1) of `INV-05` into
unlimited authority: a role administrator grants themselves every role in their own scope.

**`INV-06`: a profile may not grant a role to a profile belonging to its own user**, unless
overridden. `auth.uspAssignRoleToProfile` raises `E-50044`.

The override is `config.ApplicationSetting` key `Authz.AllowSelfGrant`, default `0`, and it
exists because bootstrapping needs it once (§16.3) and because a small deployment with a single
administrator may have no alternative. Turning it on is logged as a configuration change and
appears in the deployment verification report as a warning, permanently.

**`G-08` records what this design deliberately does not do**: require two administrators to
approve a privileged grant. Four-eyes on role assignment is the correct control for a system
handling regulatory decisions, and it is a workflow feature with a user interface, so it belongs
to the UI project rather than here. The database is ready for it — `auth.UserProfileRole` would
gain a pending state — but nothing implements it today.

### 11.4 Creating profiles and users

`Authz.ProfileCreate` is scoped exactly like `Authz.RoleAssign`: a profile may be created at
tenant `T` by an administrator holding it at an ancestor-or-self of `T`.

`User.Create` is different, and deliberately weaker, because a user is not tenant-scoped. Anyone
holding `User.Create` at any tenant may create a person record; what they cannot do is give that
person a profile anywhere outside their own authority. A person with no profile has no access to
anything, so creating one is harmless.

**A standing constraint on `auth.[User]`, and it is the whole of `G-27`'s resolution: the table holds
identity only.** `G-27` asked whether the user table should carry the attributes a real application
collects about a person — a job title, a telephone extension, an office, a supervisor, a hire date. The
answer is no, and the rule to apply when the question comes back in a project is this:

> **Any attribute that is not needed to *identify* a person belongs on a tenant-scoped table, not on
> `auth.[User]`.**

Three consequences, which are the reasons rather than restatements:

- **`auth.[User]` is deliberately outside row-level security.** It has no `TenantId` and it cannot have
  one, because one person legitimately holds profiles at several tenants (`D-02`). Every column added to
  it is therefore a column every tenant's administrators can read about every person in the database, and
  `Platform.BypassRowSecurity` is not needed to do it. A job title is harmless; a home address, a
  personnel number or a note about a disciplinary process is a disclosure the design cannot fence,
  because the fence is `TenantId` and there is not one here.
- **The attribute usually differs per hat anyway.** A person seconded from one program to another has two
  job titles and two supervisors, and the tenant-scoped row states which belongs to which. A single column
  on the user forces a choice nobody can make correctly and then reports it to everybody.
- **The identity set is small on purpose and is the one a directory can supply.** `UserName`,
  `DisplayName`, `Email`, the state flags of §6.3, and nothing else. §18.1 converts an Active Directory
  application cleanly precisely because that list is the list a directory already has; a template that had
  grown four HR columns would convert into four columns nobody can populate.

A project that wants person attributes adds its own table with a `TenantId`, registers it in
`config.TenantScopedTable`, and gets the predicate, the audit trigger and the permission checks the rest
of the design already provides. That is a smaller change than it sounds, and it is the difference between
an attribute nobody can leak and one everybody can read.

### 11.5 Default roles on profile creation

`auth.TenantDefaultRole (TenantId, RoleId)` names the roles granted automatically when a profile
is created at that tenant. Inherited from the nearest ancestor if absent.

This covers both halves of the requirement with one mechanism. The agency seeds read-only, so
"when users are created, their default role is the read-only roles". An external organization in
Variant 3 seeds read, insert and update, so its users "are automatically given insert, update,
and read rights so that someone at MDE does not have to manually do it for them" — while the
role-assigning role is left out of the default set and must be granted by hand by agency staff,
exactly as the requirement specifies.

**One procedure resolves this rule, and nothing else may.** `auth.uspGrantTenantDefaultRoles`
(`140_auth_profile_procedures.sql` §6) walks the ancestor chain, grants the resolved set, and writes one
`RoleGranted` trail row per role. It was **extracted from `auth.uspCreateProfile`** rather than written
fresh, because `155_auth_registration_procedures.sql` needs the same rule on a path where nobody is
authenticated — `auth.uspRegisterExternalUser` creates a profile for a user who has no session — and the
alternative was the same inheritance walk implemented twice. Two implementations of an inheritance rule
are two implementations that drift, and the one that drifts is the one nobody is testing. It is an
**internal helper: `applicationRole` has no `EXECUTE` on it**, asserted by `140`'s closing report, and it
deliberately does **not** rebuild the permission scope, so its callers rebuild once after the grant
rather than once per role. `BL-056`.

**And the list itself is now set by a procedure rather than by a seed script.**
`auth.uspSetTenantDefaultRoles` (§7.2, §8.5) is the writer: `Tenant.Update` and `Authz.RoleAssign` at the
tenant, one trail row per code added or removed, and `E-50098` for a code that could never be granted
from here. It replaces the state `G-43` recorded, in which the decision that governs everybody admitted
afterwards was an `INSERT` somebody made in SSMS.

The table is built in Phase 1 by `035_auth_tenant_policy.sql`, four manifest steps before `auth.Role`
exists, so `RoleId`'s foreign key cannot be declared with the column. It is added by a guarded
`ALTER` at the end of that file's section 2 — see §15.2 and `BL-049`. Until `auth.Role` is present the
constraint is genuinely absent and the deployment says so; once it is present and the key is not, the
report fails rather than advising.

---

## 12. Profile switching

### 12.1 What it is

Changing which of *your own* profiles is active on your session. Not impersonation (`D-10`).

`auth.uspSwitchProfile @SessionTokenHash VARBINARY (32), @TargetUserProfileId INT`:

1. Resolves the session and its user.
2. Rejects `E-50050` if the target profile is not that user's.
3. Rejects `E-50051` if the target profile is inactive, deleted, or its tenant is unusable.
4. Demands step-up authentication if policy requires it for the target (§12.3) — `E-50052`.
5. Updates `auth.UserSession.ActiveUserProfileId`.
6. Writes `logs.AuthenticationEvent` of type `ProfileSwitch` with both profile identifiers.
7. Returns the new profile context and navigation so the UI can repaint in one round trip.

**`@SessionTokenHash`, and it is a hash — the plaintext token never reaches the database.** Every
procedure in this design that authenticates its caller takes `@SessionTokenHash VARBINARY (32)` and
the *application* computes the `SHA2_256` before it calls. `auth.UserSession` stores only the hash
(§7.3), so a parameter carrying the token would oblige the database to hash it, which puts the
plaintext in a parameter that `logs.ExecutionLog`, a query-store sample or a profiler trace could
capture. Four procedure headers in this project were written from call sketches that said
`@SessionToken` and were dead on their first statement; that is `G-26`, and the correction is stated
here, once, for every sketch in §9, §12 and §14. `BL-053`. `UIH-AUTH-001` §3 says the same thing for
the UI project.

**The switch costs a connection, and the connection it costs is the one that called it.** This is the
most consequential operational fact in the section and it is not a defect:
`sp_set_session_context @read_only = 1` cannot be set twice on the same connection — the second
attempt fails with SQL Server error `15664`, surfaced as `E-50022` — so `auth.uspSwitchProfile`
deliberately does **not** re-establish session context after moving `ActiveUserProfileId`. The
calling connection is therefore **spent**: its context still names the *old* profile and no further
work may be done on it. The next request takes a fresh connection, calls
`auth.uspSetSessionContext` with the same session token hash, and lands on the new profile because
the *session row* now points there. `G-36`, `BL-057`, and §14.3 says it again from the pooling side
because that is where a reader looking for it will be. The same arithmetic means **a sign-in costs
two connections**, not one: the connection that authenticated has already set its context, so the
first real request of the session arrives on a different one. `UIH-AUTH-001` §4.3 and §5 state both
for the audience that pays for them. And `G-40` is where the bill is actually presented — approval is
not delegable across tenants (§10.3, Appendix B `E-50203`), so an administrator with authority over a
whole subtree pays a switch, and therefore a connection, for every child tenant's record they
approve.

### 12.2 Why it is a security feature and not a convenience

The requirement frames switching as convenience — letting an agency user see what a county user
sees without a second account. It is also the mechanism that makes single-tenant acting
*enforceable*. Because a profile names one tenant, and because inserts are anchored to it
(§10.3), the act of switching is the act of declaring which organization you are working for.
There is no other way to make that declaration, and therefore no way to omit it.

### 12.3 Step-up authentication

`auth.TenantAuthenticationPolicy.RequireStepUpForPrivileged` — when the target profile holds any
`Authz`, `User`, `Tenant` or `Platform` permission, switching into it demands a fresh second
factor.

Default **on** for tenants whose policy permits local sign-in, **off** where every sign-in is
federated and the identity provider is already enforcing conditional access. Both defaults are
overridable per tenant.

**Where "default" actually comes from, since a default that lives in prose is not a default.**
`auth.uspSetTenantAuthenticationPolicy` seeds `RequireStepUpForPrivileged` on a new policy row from
`config.ApplicationSetting` key `Authn.RequireStepUpForPrivilegedDefault`, which ships as `1`, whenever
the caller passes `NULL`. The column default stays `0` for a hand-written `INSERT`, and §7.2 explains why
that asymmetry is deliberate rather than an oversight. A deployment that federates everything therefore
sets the key to `0` once and gets the second row of the paragraph above; one that does nothing gets the
first. `G-30`.

### 12.4 What the application must throw away on a switch

Everything derived from the old profile: cached permission sets, navigation, tenant pickers,
in-progress form state that carries a `TenantId`, and any open connection with session context
already set. This is `UI-04`, and it is the most likely source of a cross-tenant defect in the
UI project — a half-repainted screen that submits a form built under the previous profile.

The database will refuse the insert (§10.3) rather than mis-file it, so the failure is a
confusing error rather than a disclosure. That is the correct outcome, and it is still a defect.

---

## 13. The UI authorization surface: screens, tabs and commands

The user interface does not exist yet. This section exists so that the project which builds it
has a database contract to bind to rather than a set of role names to hard-code, and so that
this design can be handed to that project as a dependency.

### 13.1 The catalogue

`auth.UiElement` is a hierarchy of navigable things:

| `ElementType` | Meaning | Example `ElementCode` |
|---|---|---|
| `Area` | a top-level section of the application | `Area.Cases` |
| `Screen` | a page | `Screen.CaseList` |
| `Tab` | a tab within a screen | `Tab.CaseNotes` |
| `Section` | a panel within a tab | `Section.CaseApproval` |
| `Command` | a button or menu item | `Command.ApproveCase` |

Each element has a parent, a sort order, a display label, and an application. Each is mapped to
the permissions that gate it by `auth.UiElementPermission (UiElementId, PermissionId, AccessMode)`
where `AccessMode` is `View` or `Edit`.

**An element with no permission row is visible to every authenticated profile.** That is the
right default for a home page and the wrong one for everything else, so
`950_verify_deployment.sql` lists unmapped elements as a warning.

**The catalogue is a published interface, so it carries a version and the database checks it.** A build
binds to element codes (§13.3), which means the catalogue is part of the contract between this database
and that build — and the failure mode of a mismatch is not an error but a *quiet wrongness*: a menu with
a screen the build cannot route to, or a command the build renders and the database has never heard of.
`config.ApplicationSetting` key `Ui.CatalogueVersion` is the stamp.

- **It is a digest, not a tunable.** `115_seed_reference_data.sql` computes it from the live
  `(ElementCode, PermissionCode, AccessMode)` triples and from nothing else — labels, sort orders and
  parentage are deliberately excluded, because renaming a menu item breaks no caller and must not
  invalidate anybody's build. The shape is `<elements>.<mappings>.<16 hex of SHA-256>`, so two of the
  three parts are readable by a human deciding whether to care.
- **It is the one setting the seed overwrites on a match.** Every other row in
  `config.ApplicationSetting` keeps an operator's value across a re-deployment, because an operator who
  tuned something meant it. This one is a *fact about the catalogue*: an operator editing it is editing
  the answer rather than the question, so `115` recomputes it and writes it.
- **The database raises the mismatch, not the application.** The build passes what it was compiled
  against as `auth.uspGetNavigationForProfile @ExpectedCatalogueVersion`, and a mismatch — or an absent
  key, or a blank argument — is `E-50230` with nothing returned. An assertion the caller may skip is not
  a control, which is the same argument `D-08` makes in the other direction about password verification.
- **It is checked before the session is resolved.** A build compiled against a different catalogue is
  wrong for every caller, so there is no point telling one of them that their session expired instead.

Extending the catalogue is therefore a two-step act: seed the elements, then re-run `115` so the version
is recomputed. A project that forgets the second step gets `E-50230` on the next page load rather than a
navigation tree with holes in it, which is the trade this stamp exists to make. `G-18`, and
`UIH-AUTH-001` §4.2 carries the obligation on the UI side: read the key at build time, compile it in, and
pass it on every call — omitting it is permitted and blank is refused, because a configuration that came
back empty must not become a silently unchecked assertion.

### 13.2 What the UI calls

`auth.uspGetNavigationForProfile` returns the whole tree for the active profile in one round
trip, with two computed columns per element:

| Column | Meaning |
|---|---|
| `CanView` | the profile holds at least one `View`-mode permission for this element at the acting tenant |
| `CanEdit` | the profile holds at least one `Edit`-mode permission for this element at the acting tenant |

Elements the profile cannot view are **omitted entirely**, not returned with `CanView = 0` — a
navigation payload that lists the screens you are not allowed to see is an information leak in
its own right, and one that is usually visible in the browser's network tab.

`CanEdit = 0` with `CanView = 1` is the read-only case, and it is the common one: the county
read-only user sees the case screen with every control disabled.

### 13.3 The rule the UI project must follow

> **Bind to element codes and the two booleans. Never to role names, never to tenant names,
> never to permission codes directly.**

`if (nav["Command.ApproveCase"].CanEdit)`, never `if (user.IsInRole("Approver"))`. A role rename
then has no effect on the UI, a permission can be added to a role without a deployment, and the
county that defines its own role structure does not need a UI change to be supported.

This is `P-02` reaching the presentation layer, and it is the single thing most likely to be got
wrong by a developer used to ASP.NET role attributes. `UI-02`.

### 13.4 The thing the requirement asks for by name

> *"I have seen UIs where your username or userid was not even displayed anywhere in the
> application. This oversight shouldn't be duplicated for newer applications."*

`auth.uspGetProfileContext` returns, in one row, everything needed for a persistent header:
display name, user name, profile name, tenant name, the tenant's full path from the root, the
tenant type label, whether more than one profile is available, and whether the session is on the
platform-administrator bypass route. It also carries the password state the header has to warn from —
`MustChangePassword`, `PasswordExpiresUtc`, `PasswordExpiresInDays` and `PasswordExpiryWarning` (§6.3,
`G-12`) — because the alternative is a second round trip on every page for a value that is almost always
"nothing to say".

**Thirty-two columns, one row, one result set, and the shape is pinned by a test.** `_tests/050`
section 5 loads the whole result set into a table it declares column by column, which means a column
inserted in the middle of that `SELECT` fails there instead of arriving unannounced in a front-end
sprint. That is the only reason to write out a shape this wide in a test, and it is a good one for a
procedure the UI calls on every page load.

The tenant *path* — "Root › Agency › Land Management › Hazardous Waste" — matters more than the
tenant name. In Variant 2 the program names are not unique-sounding, and a user with several
profiles needs to see which branch they are in, not just the leaf.

`UI-01` states the display obligation. It is the requirement's own "gotcha", and it is the first
row of the UI Gotchas workbook.

---

## 14. The stored-procedure contract for .NET 10 / Dapper

Management requires that the UI call only stored procedures, and the application uses Dapper
with the MVP pattern. That combination determines several things about how these procedures
must be written, and getting any of them wrong produces a defect that only appears under load.

### 14.1 Every procedure takes its own authentication context

```sql
EXEC dbo.uspSaveCaseFile
      @SessionTokenHash = @hash       -- always first
    , @CaseFileId       = @id
    , @Title            = @title;
```

The procedure's first act is `EXEC auth.uspSetSessionContext @SessionTokenHash = @hash`. It does
**not** assume a previous call on the same connection already set it.

**Why this is not optional.** Dapper hands out pooled connections. Two consecutive repository
calls in one controller action may or may not use the same physical connection, and the ordering
is not under the application's control. A procedure that relies on context set by an earlier call
works perfectly in development, where the pool has one connection and everything is serial, and
fails intermittently in production. `UI-05`.

**The parameter is `@SessionTokenHash VARBINARY (32)` and carries the `SHA2_256` of the token, never
the token.** The application hashes it; the database never sees the plaintext, holds only the hash in
`auth.UserSession.SessionTokenHash` (§7.3), and has nothing to compare it against if it is handed the
original. This is not a naming preference — see §12.1: a parameter carrying the raw token would put a
live credential somewhere `logs.ExecutionLog`, a Query Store sample or a profiler trace could pick it
up. The hash is **still** never written to `@KeyParameters` or `@Comments` in the execution log,
because it is a bearer value for the length of the session and rule 9 of the conventions skill forbids
credentials there whatever their encoding. `UI-16`, `G-26`.

### 14.2 Demanding a permission

```sql
EXEC auth.uspDemandPermission
      @PermissionCode = N'Data.Approve'
    , @TenantId       = @TenantId       -- the tenant of the row being acted on
    , @ObjectName     = @ProcName;      -- optional; recorded on the denial so a broken screen is findable
```

Raises `E-50030` with a message naming the permission and the tenant. Procedures call it once
per distinct authority they need, near the top, before any write.

For a read that returns a filtered set rather than acting on one row, there is nothing to demand
— RLS returns what the profile may see, and an empty result is the correct answer for a profile
with no read scope.

### 14.3 `SESSION_CONTEXT`, read-only keys, and pooling

`auth.uspSetSessionContext` sets its keys with `@read_only = 1`. That makes them immutable for
the life of the connection, which is what stops a later statement in the same batch — injected
or merely careless — from changing the acting tenant mid-request.

Four consequences, all of which will be met during implementation:

1. **Setting a read-only key twice fails, even with the same value.** So the procedure reads the
   existing value first: absent → set it; present and equal → return silently; present and
   different → raise `E-50022`. Without that check, the second legitimate procedure call on one
   connection fails.
2. **`sp_reset_connection` clears session context when the connection returns to the pool.** This
   is what makes the pattern safe at all, and it is why step 1's "present and equal" branch is
   about repeated calls within one request rather than across requests.
3. **One connection may not serve two profiles.** A background job iterating over profiles must
   close and reopen — or better, use a separate connection per profile. `E-50022` is what it
   gets if it does not. `UI-06`.
4. **A profile switch therefore spends the connection that performed it, and a sign-in spends two.**
   The read-only key cannot be re-pointed, so `auth.uspSwitchProfile` does not attempt it: it moves
   `auth.UserSession.ActiveUserProfileId` and returns, leaving the calling connection's context still
   naming the **old** profile. That connection must be returned to the pool, not reused — the next
   request opens a fresh one, calls `auth.uspSetSessionContext` with the same hash, and lands on the
   new profile. The same is true of authentication: the connection that signed in has already set its
   context, so the first real request of a session arrives on a different connection. This is not a
   bug to be worked around and it is not free either; it is what immutable context costs, and it is
   cheaper than a mutable acting tenant. `G-36`, `BL-057`, and §12.1 gives the same fact from the
   caller's side. `auth.uspSwitchProfile` used to re-establish context and raised `E-50022` on every
   call **after succeeding** — the underlying engine error is `15664` — which is how this was found.

### 14.4 Audit attribution

The conventions skill defaults `auditCreatedBy` to `ORIGINAL_LOGIN ()`. Under `P-12` that is the
**application's** login, identical for every user, and therefore useless as an audit trail.

The plain-table `AFTER UPDATE` trigger the skill ships already resolves the actor correctly:

```sql
COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N''), ORIGINAL_LOGIN ())
```

`INSERT` has no such trigger — the defaults fire and nothing corrects them. **So every procedure
that inserts must set `auditCreatedBy` explicitly** from `SESSION_CONTEXT('AppUser')`. The
`DEFAULT` remains as a backstop for a direct insert during maintenance, where the application
login genuinely is the actor.

This is easy to forget and produces a trail that looks complete and says nothing. It is `UI-17`
and it is a review checklist item in the project plan.

`SESSION_CONTEXT('AppUser')` is set to `<UserName>@<TenantCode>#<UserProfileId>` — the person,
the organization they were acting for, and the exact profile, in one string that fits
`NVARCHAR (255)` and is greppable.

**There is one intended `auditCreatedBy` default expression, and it is this one:**

```sql
DEFAULT (COALESCE (NULLIF (CAST (SESSION_CONTEXT (N'AppUser') AS NVARCHAR (255)), N''), ORIGINAL_LOGIN ()))
```

Stated as a single expression, in one place, so that a new table cannot pick the other one — because
**as built, two different defaults are in use and the difference falls along a schema boundary.**
Every `dbo` table carries the expression above. Every `auth` table carries a bare
`DEFAULT (ORIGINAL_LOGIN ())`, which under `P-12` resolves to the pooled application login and is
therefore the same string for every user in the system. The consequence is precise and unwelcome: a
row inserted into `auth.UserProfile`, `auth.Role` or `auth.UserProfileRole` by a procedure that does
**not** set `auditCreatedBy` explicitly records *the application* as its creator, so the authorization
tables — the ones an auditor will actually ask about — have the weaker attribution and the demo domain
has the stronger one. That is exactly backwards, and it is `G-41`.

Two mitigations are real and neither closes it. The shipped `auth` procedures do set
`auditCreatedBy` explicitly, so the default is a backstop rather than the normal path; and
`logs.AuthorizationChange` carries `ActorUserProfileId` and `ActorAuthorityTenantId` independently
(`P-08`), so the *authority* trail is intact even where the row's own audit column is not. What is
lost is attribution on any row that arrives by a route nobody anticipated — a maintenance insert, a
migration, a procedure a project writes later — which is precisely the population audit columns exist
for. The fix is a `DEFAULT` change on existing tables, so it is a migration rather than an edit and
must be done in one pass with a check that every `auth` table got it; until then this paragraph is
the statement of which expression is correct. The `AFTER UPDATE` triggers are not affected —
`auditModifiedBy` resolves the actor correctly on both schemas.

### 14.5 Errors the UI must handle

Every procedure raises with `THROW` and a branchable number (conventions rule 8), never
`RAISERROR` followed by `RETURN`. The application maps the number to a user-facing outcome:

| Range | Meaning | UI behaviour |
|---|---|---|
| `50020`–`50029` | session invalid, expired, profile or tenant unusable | sign the user out, return to sign-in |
| `50030`–`50039` | permission denied | show a permission message; do not sign out |
| `50040`–`50049` | administrative authority exceeded, or a malformed bulk payload | show which clause failed; `50046` is an application bug, so show a generic error and log |
| `50050`–`50059` | profile switching | return to the profile picker |
| `50010`–`50019` | immutability violations | a bug; show a generic error and log |
| `50090`–`50099` | tenancy request invalid — unknown parent, duplicate code, cycle, root protected; and, from `50097`, an authentication **policy** nobody could sign in under or a **default role** that cannot be granted (`G-43`) | show the message and let the user correct the form; **not** a sign-out and **not** a permission failure |
| `50100`–`50124` | sign-in failed — bad request, policy refusal, exchange invalid or expired, second factor missing or replayed, an **untrusted issuer** on the federated route (`50124`, `G-21`); and, from `50117`, second-factor **enrolment** refused | return to the sign-in page and show **one** generic failure message for every number in this range. The single exception is `50115`, account locked, which §19.2 permits naming because the password has already been verified by the time it can be raised |
| `50130`–`50139` | a recorder procedure in `165_logs_procedures.sql` was called with an argument it cannot record — unknown change type or operation, a row that names neither user nor profile nor role, malformed JSON, an empty permission code | **always an application bug, never user-facing.** Show a generic error and log. These are raised by the audit-trail writers, so reaching one means something tried to record an event it could not describe |
| `50140`–`50149` | row-level security deployment — `auth.uspRebuildTenantAccessPolicy` was given an `@Action` other than `Rebuild` or `Drop`, or the policy it rebuilt does not carry four enabled predicates for every registered table | a deployment failure, not a runtime one. No UI mapping: the database refuses to leave a tenant-scoped table half-protected, and the deployment stops |
| `50150`–`50159` | user maintenance — empty name, duplicate name, no such user, malformed override JSON, last platform administrator, platform administration requested at creation | show the message against the field and let the user correct the form. `50155` is an application bug (the flag is conferred only by `auth.uspGrantPlatformAdmin`), so show a generic error and log |
| `50160`–`50169` | profile maintenance — no such user or tenant, duplicate profile name for that user at that tenant, no such profile, the default flag cleared with no replacement, deactivating the active profile | show the message and let the user correct the form. `50165` is the one that wants a specific message: "switch profile first" |
| `50170`–`50179` | role definition and role granting — duplicate role code for that owner, no such role, a system role change `INV-10` forbids, an owner tenant outside the actor's authority, an unknown permission code in a payload, nothing to revoke, a grant that already exists | show the message. `50175` (nothing to revoke) and `50179` (grant already live) are the two a double-submitting UI will meet, and both should be treated as success by the caller rather than shown |
| `50180`–`50189` | **an element of a well-formed JSON array is not usable** — a permission code, a role code or a trusted issuer that is null, a number, blank, too long or carrying surrounding whitespace (`G-32`) | show the message: it names the ordinal and quotes the element, and the whole call was refused rather than partly applied. Whether it is user-facing depends on where the array came from — a permissions or default-roles screen the administrator filled in wants the sentence shown against the offending row, while an array the application assembled itself is a defect and should be logged |
| `50190`–`50199` | performance instrumentation — `175_perf_instrumentation.sql`'s probe recorder, purge or summary was called with an argument it cannot use | **never user-facing.** The probe is a measurement, not a feature: `50190`–`50193` are defects in the calling procedure, and `50194`–`50196` are operator arguments to a maintenance procedure. §10.6 |
| `50200`–`50209` | the `dbo` demonstration domain — duplicate case number at the tenant, not found *or* not yours, already approved, target profile not at the tenant, notes on a closed case, nothing to restore, empty title or note text | show the message and let the user correct the form. `50201` deliberately does not distinguish "not found" from "not yours", because row-level security has already removed the other tenant's rows before the procedure looks — §10.6 |
| `50210`–`50219` | audit-trigger assertion — `135_audit_triggers.sql` found a plain table with no `AFTER UPDATE` trigger | a deployment failure, not a runtime one. No UI mapping |
| `50220`–`50229` | **credential maintenance** — the new verifier is not a PHC string, the current password was not proved, the new password repeats a retired one, there is no password on the account to change, or a maintenance batch size is out of range (`G-42`, `G-12`) | `50222` (reuse) and `50223` (no password here) are the two the user should read: the first asks for a different password, the second means the account signs in through an identity provider and there is nothing to change. `50220` and `50221` are application defects — the database never receives a password and cannot hash or check one (`D-08`) — so show a generic error and log. `50224` is an operator argument to a batch job and never reaches a UI |
| `50230`–`50239` | **the UI element catalogue this build was compiled against is not the one in the database** (`G-18`) | not a user error and not recoverable in the session: show a maintenance page and log loudly. A build serving navigation from a catalogue it does not know is a build with missing screens or dead commands in it, which is exactly the failure §13.1's version stamp exists to make loud. The fix is a deployment — the matching build, or `115_seed_reference_data.sql` re-run if the catalogue was extended and the version never recomputed |

Appendix B is the registry. Adding a number means adding it there first.

**`50180`–`50189` was reserved for `G-32` and is now occupied by one number**, `E-50180`, which is the
element-level companion to `E-50046`: the array is an array, and its third element is a number. The
band stays open for the next payload that needs one.

**`50060`–`50089` is listed in Appendix B without a range row**, because it is split across
self-registration and bootstrap and every number in it belongs to a path with no ordinary UI: an
unauthenticated registration form or a deployment-time script. One number in it does want a UI
sentence — `E-50068`, the registration throttle of `G-24` — and §16.4 gives it: the same generic,
number-free refusal the sign-in throttle uses, because a message that named the count and the window
would be a rate limiter that published its own budget (`UI-26`).

**The `50100` range is the one range the UI must deliberately flatten.** Every other range above
wants its message shown, because telling the user which clause failed is how they fix it. Sign-in is
the opposite: the numbers exist so `auth.LoginAttempt` and `logs.AuthenticationEvent` can record
which failure it was, and so support can answer "why could she not sign in" from the trail. Mapping
them to distinct user-facing messages would undo §19.2 in the presentation layer after the database
had taken care to preserve it. `UI-26`.

**`50117`–`50123`, the enrolment numbers, are the one part of that range with a narrow exception, and
it is worth stating precisely.** They are raised inside the enrolment window of §6.4, so the caller has
already proved a password in the same exchange — which is exactly the condition §19.2 uses to permit
naming `50115`. On that reasoning a failed enrolment *confirmation* may say "that code did not match"
(`E-50111` from `auth.uspConfirmMfaFactor`), because an attacker who can reach it has the password
already and learns nothing about which accounts exist. Everything else in the enrolment set is an
application defect and not user-actionable — the wrong key label, both actor proofs at once, a factor
that is already confirmed, a malformed recovery-code batch — so those show a generic error and are
logged. `UI-31`.

### 14.6 Dapper specifics

- **`CommandType.StoredProcedure`, always.** Never `EXEC` inside a text command — that reopens
  the injection surface the procedure-only rule exists to close.
- **Multiple result sets** are used deliberately by `uspGetProfileContext` and
  `uspGetNavigationForProfile`; read them with `QueryMultiple` rather than making several calls.
- **`SET NOCOUNT ON`** in every procedure, per the conventions. Without it Dapper's
  `ExecuteScalar` can pick up a row count instead of the intended value.
- **A JSON array for bulk role assignment, not a table-valued parameter.** The bulk procedures take
  one `@Payload NVARCHAR (MAX)` holding a JSON array and shred it with `OPENJSON`, gated on the
  first line of the body by `IF ISJSON (@Payload, ARRAY) = 0 THROW 50046`. No `CREATE TYPE … AS
  TABLE` exists anywhere in this deployment, and none should be added. `D-13` below records why, and
  `G-20` records that this replaced an earlier TVP design.

  From Dapper this is *simpler*, not harder: `new { Payload = JsonSerializer.Serialize(items) }`
  against a `NVARCHAR (MAX)` parameter, rather than building a `DataTable` whose column order,
  column names and types must match a type declared in a SQL file. Pass `DbType.String` with
  `size: -1` so Dapper does not infer `NVARCHAR (4000)` and silently truncate a large batch.

  **`D-13` — why not a TVP.** A TVP is the faster shape for very large batches and this design does
  not have very large batches: the bulk path exists so that granting one role to the forty profiles
  of a county is one transaction instead of forty, which is tens of rows, not millions. Against that
  it costs three things. First, a table type's `EXECUTE` permission is **separate** from the
  procedure's, so a deployment that grants the procedure and not the type produces a procedure the
  application may call and cannot pass arguments to — and because every grant in this project is
  guarded on the principal existing, a missing type grant is silently skipped rather than reported.
  Second, a table type cannot be altered; changing one column means dropping it, which means
  dropping every procedure that references it, which is not a re-runnable deployment. Third,
  `READONLY` is mandatory and easily forgotten, and the error it produces names neither the
  parameter nor the reason. A JSON string has one permission — the procedure's — no separate object
  to version, and a validation failure that names itself.
- **Transactions belong in the procedure, not in `TransactionScope`.** A distributed transaction
  escalation across a pooled connection with session context is a class of failure nobody should
  have to debug.

---

## 15. Data model reference

Every table carries the seven standard audit columns (`IsDeleted`, `auditDeletedBy`,
`auditDeletedDateUtc`, `auditCreatedBy`, `auditCreatedDateUtc`, `auditModifiedBy`,
`auditModifiedDateUtc`), a `PK_<schema>_<Table>` primary key, `DF_<schema>_<Table>_<Column>`
default constraints, `MS_Description` on the table and every column, and a
`trg_au_updt_<Table>` `AFTER UPDATE` trigger. Those are not repeated below.

All datetime columns are `DATETIME2 (3)`. All `*By` audit columns are `NVARCHAR (255)`.
`RowHistory` is **off** for every table here — the authorization trail is carried by
`logs.AuthorizationChange` as an event stream, which answers "who granted what, when, under what
authority" better than a row-version history of the grant table would, and does so without the
temporal machinery. `D-11`.

**The audit columns are owned by the trigger, not by the caller.** `trg_au_updt_<Table>` sets
`auditModifiedBy`, `auditModifiedDateUtc`, `auditDeletedBy` and `auditDeletedDateUtc` from
`SUSER_SNAME()` and `SYSUTCDATETIME()`, overwriting whatever the statement supplied. That is what
makes them trustworthy — a value a caller can write is a value a caller can falsify — and it means
a procedure cannot use them to record anything of its own. A soft delete that wants to say *who*
asked for it, or *why*, or on whose ticket, must write that into the `logs` trail; the audit columns
answer exactly one question, "which login touched this row", and nothing else. `BL-044`, `UI-37`.

### 15.1 `config` — configuration

| Table | Key columns | Purpose |
|---|---|---|
| `config.ApplicationSetting` | `SettingKey` (unique, filtered), `SettingValue` `NVARCHAR(4000)`, `ValueKind`, `IsSensitive` | Lockout thresholds, session lifetimes, `Authz.AllowSelfGrant`, and everything else that must be tunable without a deployment |
| `config.TenantScopedTable` | `SchemaName`, `TableName` (unique together, filtered), `TenantColumnName`, `IsActive` | The registry `120_rls_policy.sql` reads. An unregistered tenant table is unprotected — §10.1 |

### 15.2 `auth` — tenancy

| Table | Key columns | Notes |
|---|---|---|
| `auth.Application` | `ApplicationCode` (unique, filtered), `ApplicationName`, `IsActive` | One row in a normal deployment. `D-09` |
| `auth.TenantType` | `TenantTypeCode` (unique, filtered), `TenantTypeName`, `SortOrder` | Descriptive only. No authorization decision reads it — §5.2 |
| `auth.Tenant` | `ApplicationId`, `TenantCode`, `TenantName`, `TenantTypeId`, `ParentTenantId` (self FK, NULL only for the root), `IsActive` | Unique on `(ApplicationId, TenantCode)` filtered. `CK_auth_Tenant_RootHasNoParent` ties `ParentTenantId IS NULL` to the `Root` type |
| `auth.TenantClosure` | `AncestorTenantId`, `DescendantTenantId`, `Depth` | PK on the pair. Includes the depth-0 self row. Rebuilt whole — §5.3 |
| `auth.TenantAuthenticationPolicy` | `TenantId` (unique, filtered), `AllowFederated`, `AllowLocalPassword`, `RequireMfaForLocal`, `PreferredMethod`, `SessionLifetimeMinutes`, `IdleTimeoutMinutes`, `RequireStepUpForPrivileged` | Inherited from the nearest ancestor — §7.2 |
| `auth.TenantDefaultRole` | `TenantId`, `RoleId` | Roles granted automatically on profile creation — §11.5. `RoleId`'s foreign key is **not** in the `CREATE TABLE`: `auth.Role` installs at manifest step 13 and this table is built at step 9, so `035_auth_tenant_policy.sql` adds `FK_auth_TenantDefaultRole_Role` itself at the end of its section 2, guarded on `auth.Role` existing rather than on the phase, and `WITH CHECK`. Its closing report has three states — `OK`, `PENDING` only while `auth.Role` is absent, and `VIOLATION` once the parent exists and the key does not. `BL-049` |

### 15.3 `auth` — identity

| Table | Key columns | Notes |
|---|---|---|
| `auth.User` | `UserName` (unique, filtered), `DisplayName`, `Email`, `IsActive`, `IsPlatformAdmin`, `IsLockedOut`, `LockoutEndUtc`, `MustChangePassword`, `AuthPolicyOverrideJson` | Not tenant-scoped, by design — §6.1. The JSON column is `NVARCHAR (MAX)` with an `ISJSON` check; the native `json` type is 2025-only |
| `auth.UserCredential` | `UserId`, `CredentialType`, `VerifierPhc` `NVARCHAR(512)`, `LastChangedUtc`, `ExpiresUtc` | One live row per `(UserId, CredentialType)`, filtered. PHC string carries algorithm, parameters and salt |
| `auth.PasswordHistory` | `UserId`, `VerifierPhc`, `RetiredUtc` | Reuse prevention. Depth is a `config.ApplicationSetting` |
| `auth.UserFederatedIdentity` | `UserId`, `Issuer`, `SubjectId` | Unique on `(Issuer, SubjectId)` filtered. `SubjectId` is the Entra `oid`, never the email — `INV-07` |
| `auth.UserMfaFactor` | `UserId`, `FactorType`, `SecretCiphertext` `VARBINARY(MAX)`, `KeyReference`, `IsConfirmed`, `LastUsedUtc`, `LastUsedTimeStep` `BIGINT` | `KeyReference` **names** the key and never holds it, so a rotation is traceable and a stolen backup is not a key. The grammar is `scheme:name#vN`, enforced by `CK_auth_UserMfaFactor_KeyReferenceFormat` — §6.4. See below for why the time step is a separate column from `LastUsedUtc` |
| `auth.UserMfaRecoveryCode` | `UserId`, `CodeHash` `VARBINARY(32)`, `UsedUtc` | Hashed individually; single use. The unique filtered index is on **`(UserId, CodeHash)`**, not on `CodeHash` alone: a hash is unique per user, and a database-wide unique index would let one user's code collide with another's and refuse a legitimate code generation. Two users independently generating the same recovery string is astronomically unlikely and would be a support incident nobody could diagnose |
| `auth.LoginAttempt` | `ApplicationId`, `UserName`, `UserId` (nullable — unknown users), `PolicyTenantId`, `ClientAddress`, `AuthenticationMethod`, `IsBypassRoute`, `Outcome`, `FailureReason`, `PasswordVerified`, `MfaSatisfied`, `AttemptedUtc`, `ConcludedUtc` | `UserName` rather than only `UserId` so attempts against non-existent accounts are still recorded. One row per **exchange**, not per round trip — `D-14`. Indexed for both lockout questions — §7.4 |
| `auth.UserSession` | `SessionTokenHash` `VARBINARY(32)` (unique, filtered), `UserId`, `LoginAttemptId`, `ApplicationId`, `ActiveUserProfileId`, `AuthenticationMethod`, `MfaSatisfied`, `IsBypassRoute`, `StartedUtc`, `AbsoluteExpiryUtc`, `IdleExpiryUtc`, `LastSeenUtc`, `ElevatedUntilUtc`, `EndedUtc`, `EndReason` | Only the hash is stored — §7.3. `LoginAttemptId` is the link back to the exchange that produced it — `D-14`. **Two expiries, not one:** `AbsoluteExpiryUtc` is when the session dies whatever happens, `IdleExpiryUtc` is when it dies if nothing more arrives. Only `LastSeenUtc`, `IdleExpiryUtc`, `ElevatedUntilUtc`, `ActiveUserProfileId` and the ending columns are mutable; the rest raise `E-50010` from the trigger, because moving a live session to another user is impersonation with no sign-in and extending `AbsoluteExpiryUtc` defeats the one limit activity cannot extend. **`FK_auth_UserSession_UserProfile` is added by a conditional `ALTER` rather than declared in the `CREATE TABLE`**, because this table installs at manifest step 16 and `auth.UserProfile` at step 10 of a phase that may not have run: `070_auth_session.sql` adds it `WITH CHECK` as soon as the parent exists, and its closing report has three states — `OK`, `PENDING` only while `auth.UserProfile` is absent, and **`VIOLATION`** once the parent exists and the key does not. It had exactly two states for five phases, so it printed `PENDING` on every deployment and nobody acted — `BL-049` |

**Why `auth.UserMfaFactor` carries a time step as well as a timestamp.** `LastUsedUtc` answers "when
did this factor last work", which is a support question. It cannot answer "has this code already been
used", which is a security question, because a TOTP code is valid for a whole time step — thirty
seconds by default — and two verifications a second apart have two different `LastUsedUtc` values and
the same code. Storing the accepted **time step** and refusing any step less than or equal to it is
what makes a captured code single-use. Both columns exist because they answer different questions;
collapsing them into one loses whichever answer the comparison is not written for.

### 15.4 `auth` — authorization

| Table | Key columns | Notes |
|---|---|---|
| `auth.PermissionCategory` | `CategoryCode` (unique, filtered), `CategoryName`, `SortOrder` | The seven families — §8.1. Also carries `UX_auth_PermissionCategory_Id_Code`, the unfiltered pair `auth.Permission`'s composite foreign key references |
| `auth.Permission` | `ApplicationId`, `PermissionCode`, `PermissionCategoryId`, `PermissionCategoryCode`, `PermissionName`, `PermissionDescription`, `IsTenantScoped` | Unique on `(ApplicationId, PermissionCode)` filtered. `IsTenantScoped = 0` for the `Platform` family, which is evaluated without a tenant. `PermissionCategoryCode` is **denormalised on purpose** and kept honest by `FK_auth_Permission_PermissionCategory` on the pair `(PermissionCategoryId, PermissionCategoryCode)`, which is what lets `CK_auth_Permission_CodeMatchesCategory` be row-local — the code must read `<Category>.<Verb>` with exactly one dot, checkable without a subquery. `PermissionDescription` carries the meaning in the row, not only in this document — `BL-037` |
| `auth.Role` | `ApplicationId`, `OwnerTenantId`, `RoleCode`, `RoleName`, `RoleDescription`, `IsAssignable`, `IsSystemRole` | `UX_auth_Role_Code` is unique on `(ApplicationId, OwnerTenantId, RoleCode)` filtered — the natural key, scoped to the owner, which is what lets two tenants each define `REVIEWER`. `UX_auth_Role_Id_Application` is the unfiltered pair `auth.RolePermission` and `FK_auth_Role_OwnerTenant` reference. `IsSystemRole` protects the seeded roles from edit — `INV-10`, `E-50012` from the trigger; `IsAssignable` is a separate flag and not a synonym for active — §8.2 |
| `auth.RolePermission` | `RoleId`, `PermissionId` | Unique on the pair, filtered. Both foreign keys are composite and carry `ApplicationId`, so a role cannot be given a permission belonging to another application — the structural half of `INV-04`, `BL-040` |
| `auth.UserProfile` | `UserId`, `TenantId`, `ProfileName`, `IsDefault`, `IsActive` | `UX_auth_UserProfile_Id_Tenant` is unique on `(UserProfileId, TenantId)` **unfiltered** so domain tables can carry the composite foreign key that stops cross-tenant assignment; it is a table constraint rather than a filtered index precisely because a foreign key cannot reference a filtered one. `UX_auth_UserProfile_Default`: one `IsDefault` per user, filtered — `INV-03`. `UX_auth_UserProfile_UserTenantName`: unique on `(UserId, TenantId, ProfileName)` among live rows, because two identically named profiles at one tenant are indistinguishable in the switcher — `BL-036` |
| `auth.UserProfileRole` | `UserProfileId`, `RoleId`, `ScopeTenantId`, `GrantedByProfileId`, `GrantedUtc`, `ExpiresUtc` | Unique on `(UserProfileId, RoleId, ScopeTenantId)` filtered. `GrantedByProfileId` is the audit anchor — §11 |
| `auth.ProfilePermissionScope` | `UserProfileId`, `PermissionId`, `ScopeTenantId` | **Derived.** PK on all three; a covering index leads with `(UserProfileId, PermissionId)`. Rebuilt by procedure — `D-07` |
| `auth.UiElement` | `ApplicationId`, `ElementCode`, `ElementType`, `ParentUiElementId`, `DisplayLabel`, `SortOrder` | Unique on `(ApplicationId, ElementCode)` filtered — §13.1 |
| `auth.UiElementPermission` | `UiElementId`, `PermissionId`, `AccessMode` | `AccessMode IN ('View','Edit')` |
| `auth.OrganizationRegistration` | `ApplicationId`, `ProposedTenantCode`, `OrganizationName`, `ContactEmail`, `Status`, `ReviewedByProfileId`, `TenantId` | Variant 3 self-service onboarding — §16.4 |

### 15.5 `logs` — the trails

| Table | Key columns | Notes |
|---|---|---|
| `logs.AuthenticationEvent` | `EventUtc`, `EventType`, `EventSeverity`, `ApplicationId`, `UserId`, `UserName`, `LoginAttemptId`, `UserSessionId`, `ClientAddress`, `Actor`, `DetailJson` | `EventType` is a **closed set** and covers `SignIn`, `SignOut`, `MfaChallenge`, `ProfileSwitch`, `StepUp`, `MaintenanceBypass`, `MaintenanceBypassEnded`, `Lockout`. `UserName` is the name *involved*, real account or not; `Actor` is who *caused* it — the acting profile from `SESSION_CONTEXT('AppUser')` where there is one, otherwise `ORIGINAL_LOGIN()`. For a self-service action the two agree; for an administrative revoke they do not, and that distinction is the whole point. See below for `CK_logs_AuthenticationEvent_Attributable` |
| `logs.AuthorizationChange` | `ChangeType`, `TargetUserId`, `TargetUserProfileId`, `RoleId`, `ScopeTenantId`, `ActorUserProfileId`, `ActorAuthorityTenantId`, `OccurredUtc`, `DetailJson` | **`P-08`.** The `ActorAuthorityTenantId` records *which* grant of `Authz.RoleAssign` was relied on, which is what makes a later review of a disputed grant possible |
| `logs.AuthorizationDenial` | `UserProfileId`, `PermissionCode`, `TenantId`, `ObjectName`, `OccurredUtc` | Denials only. A sudden rise means a misconfigured role or an attack; either is worth a dashboard |
| `logs.DataChangeLog` | `SchemaName`, `TableName`, `KeyJson`, `Operation`, `ChangedColumnsJson`, `ActorUserProfileId`, `OccurredUtc` | Row-level business audit, referenced by the demo domain. Written by the domain procedures, not by a generic trigger — `D-12` |
| `logs.ExecutionLog` | as shipped by the conventions skill | Procedure instrumentation, rule 8 |

**A profile switch is an authentication event, which is why a table about signing in carries a row
about changing hats.** `ProfileSwitch` is in the `EventType` set because the switch changes the
**acting tenant** — every permission the next request resolves, and every row RLS lets it see, is
decided by the profile that switch selected. It is a re-authentication in everything but the
credential: §12.3 may demand a step-up factor for it, and §12.4 requires the application to discard
everything it had cached about the old profile. A trail that recorded sign-in and sign-out but not
the switches in between would show one identity holding one authority for the length of a session,
which for a multi-profile user is simply false. `ProfileSwitch` was published in this list four
phases before `auth.uspSwitchProfile` tried to write it and was refused by the vocabulary's own
`CHECK` constraint, which had never been widened to match — `G-29`, `BL-055`.

**`logs.AuthorizationChange.ChangeType` is a closed set of exactly sixteen values**, listed in the
column's `MS_Description` and enforced by `CK_logs_AuthorizationChange_ChangeType`. Two consequences
that look like defects and are not:

- **Some members have no writer.** They are in the set anyway, because widening a closed vocabulary
  on a live database costs an `ALTER` in three files and the drop-and-re-add dance of §21.3. Shipping
  the vocabulary a phase early is cheaper than growing it a phase late.
- **Organization approval is not in it, and does not get a trail row here.** There is no member for
  "organization admitted", and `auth.uspApproveOrganization` deliberately writes none —
  the `auth.OrganizationRegistration` row *is* the audit record, since `Status`, `ReviewedUtc`,
  `ReviewedByProfileId`, `ReviewNote` and `TenantId` together say who admitted whom, when and to
  what, and `IX_auth_OrganizationRegistration_Queue` reads it back. The tenant's own creation is
  logged by `auth.uspCreateTenant`. This is the one place in the authorization surface where a change
  of consequence is not in this table, and it is stated here rather than left to be discovered. A
  project that would rather have one trail than two adds `OrganizationApproved` and
  `OrganizationRejected` to the vocabulary and has that procedure write them; nothing else changes.

Two verbs that are *not* candidates for this table at all are `UserCreate` and `UserDeactivate`.
Creating or deactivating a *user* is an identity change, not an authority change — the vocabulary
refused them, correctly, and they go to `logs.DataChangeLog` through `logs.uspRecordDataChange`.
`BL-054`.

**Every event must name someone, and that is a `CHECK` constraint rather than a convention.**
`CK_logs_AuthenticationEvent_Attributable` requires `UserId` **or** `UserName` to be present, and
`CK_logs_AuthorizationChange_Attributable` requires one of `TargetUserId`, `TargetUserProfileId` or
`RoleId`. A row that names none of them is refused with `Msg 547` and not written, because a trail
of events attributable to nobody is not a trail — it is noise that makes the real entries harder to
find.

It is easy to trip, and the cases where it trips are the cases worth recording: a maintenance
bypass, a sign-in attempt for an address that does not exist, a token that resolved to nothing. The
answer is never to leave both fields empty to mean "unknown" — supply a `UserName`: the login,
`ORIGINAL_LOGIN()` under impersonation, or the address that was attempted. The database's own
maintenance procedures shipped with both fields NULL and the defect survived two phases, because
nothing had ever reached their accepted path. `BL-046`, `UI-39`, and §10.5.

**`D-12` — why `logs.DataChangeLog` is written by procedures rather than by a generic audit
trigger.** A trigger that serialises `inserted` and `deleted` to JSON on every table is
attractive and costs a write on every write. Since `P-11` guarantees every change arrives
through a procedure, the procedure can log the columns that actually matter, with business
meaning attached, at a fraction of the cost. The trade is that a change made outside a procedure
is unlogged — which `logs.DdlChange` and the permission model make visible, and which
`950_verify_deployment.sql` asserts by checking that no login outside `db_owner` holds direct
`INSERT`/`UPDATE` on `dbo` other than through `applicationRole`.

### 15.6 Views

| View | Returns |
|---|---|
| `auth.vwTenantHierarchy` | every tenant with its full path from the root, depth, and type label |
| `auth.vwUserProfile` | profiles with user, tenant, path, and grant count, filtered `IsDeleted = 0` |
| `auth.vwProfilePermission` | the resolved permission set per profile, with the role that supplied each — the "why does this person have this" view |
| `auth.vwRoleDefinition` | roles with owner tenant and their permission list |
| `logs.vwAuthorizationTrail` | `logs.AuthorizationChange` joined to names, for the audit screen |

---

## 16. Seed data and bootstrapping

### 16.1 What is seeded

`115_seed_reference_data.sql`, by `MERGE` so it converges on a populated database:

1. `auth.Application` — one row. `030_auth_tenant.sql` seeds no application: the template ships
   with none, and the test fixtures create their own.
2. `auth.TenantType` — **seeded by `030_auth_tenant.sql`, not here.** Phase 1 cannot build a tenant
   tree before the types exist, and `auth.Tenant`'s composite foreign key makes the `Root` row a
   structural prerequisite rather than reference data. `115` must not re-seed them; its `MERGE`
   would be harmless but the duplication is the thing that drifts. `BL-021`.
3. `auth.PermissionCategory` and `auth.Permission` — the full catalogue (Appendix A). **These
   are code, not configuration**: they are referenced by literal in the RLS predicate and by code
   in the procedures, so they are seeded, `IsSystemRole`-equivalent, and never edited by an
   administrator. **`050_auth_permission.sql` builds the tables and seeds none of the rows**, which
   is not a neutral state: `120_rls_policy.sql` resolves its permission ids from this table, finds
   none, substitutes the sentinel `-1`, and every predicate then denies every non-maintenance
   session. A deployment that skips `115` therefore comes up fail-closed rather than fail-open —
   the right direction and the wrong experience (§10.2, `UI-35`). Re-run `115` **and then** `120`;
   seeding the catalogue without rebuilding the policy leaves the predicates on the sentinel.
4. `auth.Role` and `auth.RolePermission` — the baseline roles below, owned by the root tenant so
   they are assignable anywhere (`INV-04`).
5. `auth.UiElement` and `auth.UiElementPermission` — a starter catalogue covering the demo
   domain, for the UI project to extend.
6. `config.ApplicationSetting` — the tunables, with defaults. **Seeded in two files, with no
   overlap, and the split is load-bearing.** `025_config_tables.sql` seeds the twenty-three
   authentication, authorization and registration tunables; `115` §6 seeds four, and
   `175_perf_instrumentation.sql` seeds the one that is meaningless without the code in that file
   (`Perf.PermissionProbeBurstCount`). The reason is the same
   fail-closed argument as `auth.Permission` in item 3, running the other way:
   `110_auth_session_procedures.sql` and `112_auth_authn_procedures.sql` *read* those twenty-three keys,
   they install **before** `115`, and they fail closed when a key is missing — so a deployment that
   stopped after `112` would have procedures that refuse everything for want of a row that had not
   been written yet. The twenty-three therefore arrive with the table — which is why the settings added
   in 1.7 went there and not here: `Authn.PasswordLifetimeDays`, `Authn.PasswordExpiryWarningDays` and
   `Authn.PasswordHistoryDepth` are read by `110`'s credential procedures (`G-12`, `G-42`),
   `Authn.RequireStepUpForPrivilegedDefault` by `125`'s policy writer (`G-30`), and
   `Registration.ThrottleThreshold` and `Registration.ThrottleWindowMinutes` by `155`'s registration
   throttle (`G-24`). `Ui.CatalogueVersion` is the exception that proves the rule and lives in `115`,
   because it is a digest **of** what `115` seeds (§13.1, `G-18`). Which leaves the rule that matters
   more than the split:

   > **A setting seeded in two places is a setting with two defaults, and the second one to run wins
   > silently.**

   There is no `MERGE` semantics that rescues you from that — both converge, and whichever ran last
   is the value the deployment ends up with. So the two files partition the keys and never share one.
   A project adding a tunable puts it in exactly one of them, and puts it in `025` if anything
   installed before `115` reads it. `BL-050`.
7. `config.TenantScopedTable` — the demo domain tables. **Seeded by `025_config_tables.sql`, not
   here**, for the same reason as `auth.TenantType`: `120_rls_policy.sql` reads this registry to
   decide what to protect, and it runs on every deployment including one where `115` has not. The
   two live rows are `dbo.CaseFile` and `dbo.CaseNote`. A project adding a tenant-scoped table adds
   a row here in the same script that creates the table, then rebuilds the policy.

### 16.2 The baseline roles

Owned by the root tenant, `IsSystemRole = 1`, deliberately single-purpose so that a tenant
administrator composes authority by granting several rather than by asking for a new role:

| `RoleCode` | Permissions |
|---|---|
| `READ_ONLY` | `Data.Read` |
| `CONTRIBUTOR` | `Data.Read`, `Data.Insert` |
| `EDITOR` | `Data.Read`, `Data.Update` |
| `DATA_STEWARD` | `Data.Read`, `Data.SoftDelete`, `Data.Restore` |
| `OPERATOR` | `Data.Read`, `Data.Execute` |
| `APPROVER` | `Data.Read`, `Data.Approve`, `Data.Reassign` |
| `EXPORTER` | `Data.Read`, `Data.Export` |
| `USER_ADMIN` | the `User` family |
| `ROLE_ADMIN` | `Authz.RoleRead`, `Authz.RoleAssign`, `Authz.RoleRevoke`, `Authz.ProfileRead`, `Authz.ProfileCreate`, `Authz.ProfileUpdate`, `Authz.ProfileDeactivate` |
| `ROLE_ARCHITECT` | `Authz.RoleDefine`, `Authz.RoleRead` |
| `TENANT_ADMIN` | the `Tenant` family |
| `AUDITOR` | the `Audit` family |
| `CONFIG_ADMIN` | the `Config` family |
| `PLATFORM_ADMIN` | the `Platform` family — requires `IsPlatformAdmin` as well (`INV-09`) |

`CONTRIBUTOR` and `EDITOR` include `Data.Read` because `D-04` gives permissions no implication
and a contributor who cannot read is useless. The seed data is where that convenience belongs —
not in the evaluation rules.

**Writing a credential after the bootstrap: the four procedures `G-42` was filed for.** Until it was
closed, `auth.UserCredential` was created by `900_bootstrap_first_admin.sql` for exactly one account and
by nothing else, so the only supported route to a password was the one the bootstrap took. There are now
four, in `110_auth_authn_procedures.sql`:

| Procedure | Demands | Does |
|---|---|---|
| `auth.uspSetPassword` | `User.ResetCredential` | the administrative reset. Inserts a credential where there is none, retires an existing verifier into `auth.PasswordHistory`, and **forces `MustChangePassword = 1`** — a reset an administrator performed must not become a password the two of them share |
| `auth.uspGetPasswordChangeContext` | a live session, its own user | hands the application the live verifier and the retired ones, plus the expiry state and `Authn.PasswordHistoryDepth`, so the comparison can be made where the hashing is (`D-08`) |
| `auth.uspChangePassword` | a live session, its own user, and `@CurrentPasswordVerified = 1` | the self-service change. Retires the old verifier, refuses a reported reuse (`E-50222`), clears `MustChangePassword`, and refuses outright on an account with no password at all (`E-50223`) |
| `auth.uspExpireCredentials` | no session — a maintenance job | the batched sweep that sets `MustChangePassword` on accounts past `ExpiresUtc`. `@BatchSize` is bounded (`E-50224`) because an unbatched sweep holds locks on `auth.[User]` long enough to block sign-in |

All four take a PHC string the application computed and none of them sees a password, exactly as sign-in
does (`D-08`, §6.2). `User.ResetCredential` was in Appendix A from the start and was demanded by nothing
until now, which is what made the gap easy to miss: the permission existed, the trail had a `ChangeType`
for it, and the procedure did not. `UIH-AUTH-001` §8 item 1 recorded the same absence from the UI side.

### 16.3 Bootstrapping the first administrator

The chicken-and-egg problem: `INV-05` requires a granting profile, and on an empty database there
is none.

`900_bootstrap_first_admin.sql` is the only script that writes authorization rows without one. It:

1. Refuses to run if any `auth.UserProfile` row already exists — so it can never be used to
   quietly add a second back door.
2. **Asserts** the root tenant — it does not create it — and writes the root authentication
   **policy**. `115_seed_reference_data.sql` creates the root tenant and the baseline roles; `900`
   checks the tenant is there and refuses with `E-50085` if it is not, then writes the one policy row
   the tree inherits. This division used to be written the other way round and the correction is
   `G-25`.
3. Creates one user with `IsPlatformAdmin = 1` and a local credential that is
   `MustChangePassword = 1`.
4. Creates one profile at the root and grants `PLATFORM_ADMIN`, `ROLE_ADMIN`, `USER_ADMIN`,
   `TENANT_ADMIN` and `ROLE_ARCHITECT`.
5. Writes `logs.AuthorizationChange` rows attributed to `ActorUserProfileId = NULL` with a
   `DetailJson` of `{"bootstrap":true}` — so the trail explains the discontinuity rather than
   simply starting mid-story.
6. Prints the account name and requires the password to be supplied via `-v`, never defaulted.

The second and subsequent administrators are created through the ordinary procedures by the
first, which is what makes clause 1 safe to enforce so strictly.

**Why step 2 splits the way it does, stated because the next person to tidy the install order will
otherwise reverse it.** Three forces pin it:

- `auth.Role.OwnerTenantId` is `NOT NULL` and part of a composite foreign key, so the baseline roles
  cannot be seeded before the root tenant exists. `115` seeds the roles, therefore `115` must own the
  tenant.
- `900` grants five of those roles **by code**, so it needs them already present, and refuses with
  `E-50087` if they are not. That is what makes `900` the later script rather than the earlier one.
- The **policy** nevertheless stays in `900`, not `115`, and this is the clause that looks
  gratuitous and is not. `auth.uspCompleteLogin` fails closed to `RequireMfaForLocal = 1`. A
  bootstrap that writes no policy row therefore produces an administrator who **can never sign in** —
  the account exists, the grants are correct, and the first factor is refused for want of a second
  the deployment has no way to enrol. `900` is the script that creates the account, so `900` is the
  script that must guarantee the account is usable. `G-37`, `BL-051`.

**And the root policy that `900` writes has `RequireMfaForLocal = 0`, which is the permissive
setting, on the tenant that is the ancestor of every other tenant.** That is deliberate and it is
also a live obligation, so it is stated here rather than left in a `PRINT` nobody re-reads: the value
exists so that the first administrator can complete a first sign-in and enrol a factor (§6.4, "the
bootstrap"). **It must be revisited before the deployment holds anything real** — because policy
inherits (§7.2), a root row left at `0` is the effective policy for every tenant beneath it that has
not written its own. `G-37` proposes the durable fix: `950_verify_deployment.sql` asserts the root
policy has `RequireMfaForLocal = 1` and **fails**, so the requirement is enforced by the same
mechanism that checks everything else. Until `950` is written (`T-104`), this paragraph is the
control, which is a fair description of how much it is worth.

### 16.4 Variant 3 self-registration

An external organization registers itself:

1. `auth.uspRegisterOrganization` writes an `auth.OrganizationRegistration` row with
   `Status = 'Pending'`. No tenant is created.
2. An agency user holding `Tenant.Create` calls `auth.uspApproveOrganization`, which creates the
   tenant under the external-organizations branch (`EXTORG` — §17.3) and sets `Status = 'Approved'`.
   It writes **no** `auth.TenantDefaultRole` rows. The default set — `READ_ONLY`, `CONTRIBUTOR`,
   `EDITOR` — is configured **once, on the branch**, and every organization beneath it inherits it by
   the ordinary resolution rule of §11.5.
3. Users of that organization register with `auth.uspRegisterExternalUser`, which creates the
   user, the profile at the organization's tenant, and grants the default role set
   automatically — satisfying the requirement that "someone at MDE does not have to manually do
   it for them".
4. `ROLE_ADMIN` is **not** in the default set. An agency user grants it by hand, which is exactly
   what the requirement specifies.

**Inherited, not copied, and the difference is the whole point.** Copying the branch's defaults onto
each organization at approval time would *freeze* each organization's default set at the date it
happened to be approved. A year later the agency decides new external users should also get
`EXPORTER`; with inheritance that is one row on `EXTORG` and it is true for all of them, and with
copies it is true for nobody already admitted and true for everybody admitted afterwards — a
difference nobody chose, visible only as "why do O1's new users get less than O4's". Onboarding a
fourth organization therefore requires no configuration at all, which is the property §17.3 claims.
`BL-052`.

`ROLE_ADMIN` is deliberately absent from the branch's defaults for the reason step 4 gives, and its
absence is configuration rather than code: a deployment that wants external organizations to
administer their own roles adds it to `EXTORG` and gets exactly that, everywhere, at once.

Step 2 is a deliberate human gate. Self-service tenant creation in a public-facing application is
how an attacker gets a tenant of their own and an approved-looking identity.

**Steps 1 and 3 are the only entry points in this design with no session behind them, and they are
throttled per client address.** `auth.uspRecordRegistrationAttempt` records every arrival in
`auth.RegistrationAttempt` and returns the verdict in the same call, as `@AddressThrottled` — one round
trip, so the count and the decision taken on it cannot disagree. Over the threshold is `E-50068`. Five
properties, each chosen:

- **The arrival is recorded before any other validation.** A malformed request is the cheapest flood to
  generate, so a refused request has to spend the budget too, or the limit protects nothing.
- **One budget, both forms.** `uspRegisterOrganization` and `uspRegisterExternalUser` share the counter,
  so an attacker cannot get a second allowance by switching pages.
- **Per address, and it lapses on its own.** `Registration.ThrottleThreshold` (ships at `10`) inside
  `Registration.ThrottleWindowMinutes` (ships at `60`). There is no unlock step, because there is no
  account to unlock: this is the registration counterpart of `E-50116`, the per-address arm of the
  sign-in throttle (§7.4), and neither names an account.
- **The message carries no numbers.** The count, the threshold and the window go to `@Comments` and
  `logs.ExecutionLog`, where an operator can read them; a refusal that published its own budget would
  tell an attacker exactly how long to wait (`UI-26`).
- **Attempt rows are kept.** They are the evidence for "we were flooded on Tuesday", so they are soft
  data with an audit trail and not a counter somebody resets.

That is `G-24`, and it is the database half of `G-06`.

**`G-06` is not closed by the throttle, and this is the paragraph that says so.** A public registration
form in a production deployment needs two things this database cannot provide and must not pretend to:

1. **Rate limiting at the edge** — the gateway or the application — because a flood that reaches the
   database has already cost a connection, a transaction and a row per attempt. `E-50068` is the backstop
   that makes the abuse *visible and bounded*; it is not the first line.
2. **A challenge on the public form** — CAPTCHA or equivalent — because the throttle counts addresses and
   a botnet has many. A challenge is the only control at this layer that costs the attacker more than it
   costs the deployment.

Both are the application project's, both are recorded in `UIH-AUTH-001` §8 item 9, and **`G-06` therefore
stays open and continues to block Variant 3 production go-live.** A template that closed it on the
strength of a per-address counter would be telling a project it was protected when the protection it
needs is on the other side of a network boundary.

---

## 17. Conformance: every scenario in the requirements, walked through

This section is the evidence for the claim in §1.3. Every user described in the source
requirements appears below with the actual rows that represent them, and with the requirement
sentence each one is there to satisfy.

The requirements name roles with letters — A, B, C, D for one organization, D1 to D4 for
another, E1 to E4 for a third — and reuse some of those letters for users. That reuse is
deliberate on the requirement's part and it is the point of `P-04`. Below, role letters are
shown as the requirement wrote them, with the baseline role they map to in brackets.

### 17.1 Variant 1 — agency with subordinate jurisdictions

**Tenants.** `ROOT` › `AGENCY`; `ROOT` › `ANNE_ARUNDEL`; `ROOT` › `BALTIMORE_CITY`.

**Roles.** The agency uses the root-owned baseline roles. Anne Arundel and Baltimore City each
define their own, owned by their own tenant — which is why the agency's role "D" and Anne
Arundel's role "D1" never collide, and why Baltimore City's role "E2" is unrelated to the agency
*user* called E2.

| Req. user | Profile(s) — acting tenant | Role grants, as `role @ scope` | Satisfies |
|---|---|---|---|
| **A** | `AGENCY` | A [`READ_ONLY`] @ `ROOT` | read-only, sees all records |
| **B** | `AGENCY` | A [`READ_ONLY`] @ `ROOT`, B [`CONTRIBUTOR`] @ `AGENCY` | "can also insert records. He also has roles A" |
| **C** | `AGENCY` | A @ `ROOT`, B @ `AGENCY`, C [`EDITOR`] @ `AGENCY` | "can also update records. He also has roles A and B" |
| **D** | `AGENCY` | D [`ROLE_ADMIN`] @ `ROOT` — **and nothing else** | "can not do any data entry for anyone. The only tables he has any impact on are tables used for authorization" |
| **E1** | `AGENCY` | A @ `ROOT`, B @ `AGENCY`, C @ `AGENCY`, D @ `ROOT` | "has roles A, B, C, and D" |
| **E2** | `AGENCY` | same as E1, plus `auth.User.IsPlatformAdmin = 1` | "and he is a system-wide admin" |
| **F** | `ANNE_ARUNDEL` | D1 [`ROLE_ADMIN`, AA-owned] @ `ANNE_ARUNDEL` | "can only affect users who also work for Anne Arundel" |
| **G** | `ANNE_ARUNDEL` | D2 [`READ_ONLY`] @ `ANNE_ARUNDEL` | read-only, Anne Arundel records only |
| **H** | `ANNE_ARUNDEL` | D2 @ `ANNE_ARUNDEL`, D3 [`CONTRIBUTOR`] @ `ANNE_ARUNDEL` | "he insert records. He also has role D2" |
| **I** | `ANNE_ARUNDEL` | D1 @ `ANNE_ARUNDEL`, D2 @ `ANNE_ARUNDEL`, D4 [`EDITOR`] @ `ANNE_ARUNDEL` | "update records. He also has role D1 and D2" |
| **J** | `ANNE_ARUNDEL` | D1, D2, D3, D4 @ `ANNE_ARUNDEL` | "has D1, D2, D3, and D4" |
| **K** | `BALTIMORE_CITY` | E2 [`ROLE_ADMIN`, BC-owned] @ `BALTIMORE_CITY` | "provided the other user is also from Baltimore City" |
| **L** | `BALTIMORE_CITY` | E1, E2, E3, E4 @ `BALTIMORE_CITY` | "assign roles, read, insert, and update" |
| **M** | **two:** `ANNE_ARUNDEL` *and* `BALTIMORE_CITY` | on each profile: F1 [`READ_ONLY`], F2 [`CONTRIBUTOR`], F3 [`EDITOR`] @ that profile's tenant | "will be switching profiles between AA and BC when doing his task" |

*The requirement writes user L's roles as "E1, E2, E4, and E4" and then glosses them as "assign
roles, read, insert, and update" — four distinct capabilities. Read here as E1 through E4.*

**The four claims the requirement makes about this arrangement, and where each is enforced:**

| Requirement | Enforced by |
|---|---|
| "Users of Anne Arundel can only see Anne Arundel records" | G's only read grant is scoped at `ANNE_ARUNDEL`; `auth.TenantClosure` contains no row making `BALTIMORE_CITY` or `AGENCY` a descendant of it. The RLS `FILTER` predicate returns nothing for those rows — §10.2 |
| "Roles F1, F2, and F3 are actually meaningless" for user M | Correct, and structurally so: M's authority over Anne Arundel comes from *which profile is active*, not from the role names. `P-05` |
| "If he added records under his BC profile that was actually meant for AA, he is guilty of a data entry error" | The insert succeeds and is stamped `BALTIMORE_CITY` by the `BLOCK AFTER INSERT` predicate. It is a genuine data-entry error, visible in `logs.DataChangeLog`, and not a security failure — §10.3 |
| "If E1 performs data entry impacting AA records, the AA users will not be able to see them" | E1's acting tenant is `AGENCY`, so the rows are stamped `AGENCY`. Anne Arundel's read scope does not cover `AGENCY`. The remedy the requirement gives — "E1 must be added to a profile that has AA as a tenant and must switch to that profile" — is exactly `auth.uspCreateProfile` followed by `auth.uspSwitchProfile` |

**Authentication.** `AGENCY` policy: federated preferred, local permitted only for
`IsPlatformAdmin` users. `ROOT` policy (inherited by both counties): local password + TOTP,
federated not permitted. E2 therefore has both an `auth.UserFederatedIdentity` row and an
`auth.UserCredential` row; A through E1 have only the former; F through M only the latter.

### 17.2 Variant 2 — agency-internal, by administration and program

**Tenants.** `ROOT` › `AGENCY` › {`LMA`, `WSA`, `ARA`, `IT`}; `LMA` › `HAZ_WASTE`;
`WSA` › `WASTEWATER_PERMITS`; `ARA` › `RAD_HEALTH`.

**Roles.** R1 (assign roles) → `ROLE_ADMIN`; R2 (read) → `READ_ONLY`; R3 (update) → `EDITOR`;
R4 (insert) → `CONTRIBUTOR`.

| Req. user | Profile(s) | Role grants | Satisfies |
|---|---|---|---|
| **A** — LMA, Hazardous Waste | `HAZ_WASTE` | R4 @ `HAZ_WASTE`, R3 @ `HAZ_WASTE`, R2 @ `AGENCY` | "read, insert, and update but only in programs they work in… read for all other programs" |
| **B** — WSA, Wastewater Permits | `WASTEWATER_PERMITS` | R4 @ `WASTEWATER_PERMITS`, R3 @ `WASTEWATER_PERMITS`, R2 @ `AGENCY` | same |
| **C** — ARA/RHP *and* LMA/Hazardous Waste | **two:** `RAD_HEALTH` and `HAZ_WASTE` | on each: R4 and R3 @ that profile's tenant; R2 @ `AGENCY` on both | "User C works in Radiological Health Program… User C also does work for the Hazardous Waste Program" |
| **D** — IT | `IT` | R1 @ `AGENCY`, R2 @ `AGENCY` | "User D's job is to assign roles to users" |
| **E** — IT, sys-admin | `IT` | R1 @ `AGENCY`, R2 @ `AGENCY`, plus `IsPlatformAdmin = 1` | "User E is D's backup so he too can assign roles when D is not present" |

**This variant is why `D-03` exists.** Users A, B and C each hold a *narrow write* grant and a
*broad read* grant inside a single profile. Without scope on the grant, "read for all other
programs" would require a second profile and constant switching to do one job. With it, A signs
in once, sees every program's records, and can only write to their own.

Note that user C still needs two profiles — not because of read scope, but because C writes in
two programs and `P-06` anchors inserts to the acting tenant. That is the correct outcome: when
C files a record, the database records which programme C was working for.

**And this variant is where `G-40` will be felt, so it is walked here rather than left in §10.3.**
Suppose the agency adds a central approver: one person who reviews records from every program. The
obvious provisioning is one profile at `AGENCY` with `APPROVER` scoped at `AGENCY` — broad authority,
one hat, nothing to switch. Reads work: the filter predicate resolves `AGENCY` scope through the
closure and every program's records are visible. **The first approval fails**, with `E-50203`, because
`dbo.CaseFile.ApprovedByProfileId` is half of a composite foreign key onto `(ProfileId, TenantId)` and
the approver has no profile at `HAZ_WASTE`. Authority reaching a tenant is not the same as a profile
being *at* it, and only the second can be recorded.

So the central approver needs a profile at **every** program whose records they approve — five here,
and one more each time a program is added — and switches between them, at a connection apiece
(§12.1). Two things follow. The provisioning decision belongs in the deployment's user model on day
one, not in whatever incident discovers it. And a reviewer who finds that shape unacceptable should
change the *model*, not the constraint: record approval in a separate table keyed by
`(CaseFileId, ApproverProfileId)` with its own tenant column, and the composite key is satisfied by
the approver's own tenant rather than the record's. That is a domain change and the demonstration
domain deliberately does not make it, because the version here is the one that shows the constraint.

**Authentication.** `AGENCY` policy: federated preferred; local permitted for `IsPlatformAdmin`.
Administrations and programs inherit it, so no policy rows exist below `AGENCY` at all.

### 17.3 Variant 3 — agency and external organizations

**Tenants.** `ROOT` › `AGENCY` › {`LMA`, `WSA`, `ARA`, `IT`}; `ROOT` › `EXTORG` ›
{`ORG_O1`, `ORG_O2`, `ORG_O3`}.

| Req. user | Profile(s) | Role grants | Satisfies |
|---|---|---|---|
| **A** — LMA | `LMA` | `READ_ONLY` @ `ROOT`, plus data roles @ `LMA` | "Users of MDE can see everyone's records, provided they were given a role that has read rights" |
| **B** — WSA | `WSA` | as A, at `WSA` | same |
| **C** — ARA | `ARA` | as A, at `ARA` | same |
| **D** — IT | `IT` | `ROLE_ADMIN` @ `ROOT`, `READ_ONLY` @ `ROOT` | "User D's job is to assign roles to users" — including to external organization users, which `ROOT` scope permits |
| **E** — IT, sys-admin | `IT` | as D, plus `IsPlatformAdmin = 1` | "User E is D's backup" |
| **F1, F2** — O1 | `ORG_O1` | `READ_ONLY`, `CONTRIBUTOR`, `EDITOR` @ `ORG_O1` — granted automatically at registration | "automatically given insert, update, and read rights so that someone at MDE does not have to manually do it for them" |
| **G1, G2** — O2 | `ORG_O2` | same, at `ORG_O2` | same |
| **H** — O3 | `ORG_O3` | same, at `ORG_O3` | same |
| *any of the above, later* | their own org | `ROLE_ADMIN` @ their org — **granted by hand by D or E** | "Roles that allow them to assign roles to other users within their organization are manually added by a MDE user, D and E" |

**Authentication.** One policy row, on `ROOT`: local password + TOTP, federated not permitted.
Everything inherits it, including the agency.

**And this is where `D-05` pays for itself.** The requirement says of this variant: *"the
'sys-admin' classification offers no distinction to other types of users. This differs from
application 1 and 2 where a sys-admin user has two authentication options."* Because
`IsPlatformAdmin` is modelled as an authentication capability rather than a bundle of authority,
that sentence needs no special handling at all — user E signs in exactly as everyone else does,
because there is no SSO here for the bypass route to bypass. A design that had made "sys-admin"
a role would have had to explain why that role does nothing in this variant.

The automatic grant in row F1/F2 comes from `auth.TenantDefaultRole` on `EXTORG`, inherited by
each organization (§11.5) — so onboarding a fourth organization requires no new configuration.

**The branch code is not a name this document may choose, and both lines above used to spell it
`EXT_ORGS`.** That was `G-34`, and it is worth more than the two characters it cost. The rule:

> Every registration-accepting application must code its external-organization branch tenant with
> the **value of `config.ApplicationSetting` key `Registration.ExternalBranchTenantCode`** — which
> `115_seed_reference_data.sql` seeds as `EXTORG`.

The setting is **global** while the tenant code is **per application**, so a deployment that seeds
one branch code and a fixture that seeds another disagree *silently* until someone actually submits
a registration — at which point `auth.uspApproveOrganization` cannot resolve the branch and raises
`E-50067`, calling it a configuration fault, which it is. `155_auth_registration_procedures.sql`
closes with a report row that resolves the setting against every live application and names the ones
where it does not resolve, so the check is not left to this document. But the document is what people
build from: `_tests/020_tenancy_variant_trees.sql` copied `EXT_ORGS` out of this very section, and
had that spelling reached a deployment rather than a fixture, `VARIANT3` would have accepted
registrations happily and been unable to approve a single one.

### 17.4 Requirements that apply to every variant

| Requirement | Where it is satisfied |
|---|---|
| "When users are created, their default role is the read-only roles" | `auth.TenantDefaultRole` seeded with `READ_ONLY` at `ROOT`; inherited everywhere except where a tenant overrides it — §11.5 |
| "Read, update, and insert are separate roles. Roles that assign users with roles is also a separate role… Role that can create users is a separate role. Role that can update users is a separate role" | Appendix A: `Data.Read`, `Data.Update`, `Data.Insert`, `Authz.RoleAssign`, `User.Create`, `User.Update` are six distinct permissions in three distinct families — `P-03` |
| "We can have a role that can execute procedures" | `Data.Execute` — §8.1, with the clarification that it gates registered operations, not the calling of procedures in general |
| "If there are other types of roles, add them" | Nine further permissions, listed with their justification in §8.1 |
| "The order of how roles were defined should have zero impact" | `P-04`. Roles are keyed by `(ApplicationId, OwnerTenantId, RoleCode)` with no ordinal, no level and no bitmask; no code compares a role code to a literal |
| "Users are actually assigned profiles where those profiles contain not only the tenant they belong in but also their roles" | `auth.UserProfile` + `auth.UserProfileRole` — §2, §8.3, §8.4 |
| "Users can have more than 1 role within a profile as well as more than 1 profile" | Both are one-to-many; no unique constraint prevents either |
| "This is a 'gotcha' for UI development… the UI must somehow clearly indicate to the user which tenant he is working for and what profile he is using" | `auth.uspGetProfileContext` returns the full tenant path and profile name for a persistent header — §13.4, `UI-01` |
| "Sysadmin is a user that can use login/2fa to login in addition to the normal SSO login" | `auth.User.IsPlatformAdmin` + the bypass route — §7.1, `D-05` |
| "Based on profile, users will have access to certain screens or tabs" | `auth.UiElement` + `auth.uspGetNavigationForProfile` — §13 |
| "The UI only calls stored procedures" | `P-11`; `applicationRole` holds no direct table `EXECUTE` path, and §14 is the calling contract |

---

## 18. Converting an existing Active Directory application

The stated goal includes converting applications that currently use Active Directory for both
authentication *and* authorization. Those two halves convert very differently, and the order
matters.

### 18.1 Authentication converts cleanly

AD group membership is not used for authentication — the directory is. Moving from on-premises
AD or ADFS to Entra is a configuration change in the identity provider plus one
`auth.UserFederatedIdentity` row per user, keyed on the Entra `oid`.

The migration step that matters is **matching existing accounts to directory objects**. Match on
`userPrincipalName` once, during migration, under human review; then store the `oid` and never
match on a name again (`INV-07`).

### 18.2 Authorization does not convert cleanly, and should not be made to

The tempting shortcut is to map each AD group to a role and be done. It fails for a specific
reason: **an AD group carries no tenant**. `MDE-CaseSystem-Editors` says what its members may do
and says nothing about whose records they may do it to. Every such group has an implicit scope
that lives in someone's memory or in the application's code.

So the conversion is a three-column exercise, done once per application, by people who know the
system:

| AD group | → Role (what) | → Scope (whose records) |
|---|---|---|
| `App-Readers` | `READ_ONLY` | `ROOT`? or `AGENCY`? — **this is the question the group does not answer** |
| `App-County-AA-Editors` | `EDITOR` | `ANNE_ARUNDEL` |
| `App-Admins` | `ROLE_ADMIN` + `USER_ADMIN` | `ROOT` |

The middle column is mechanical. The right-hand column is the actual work, and it is where
latent over-privilege gets discovered — a group that everyone believed was agency-scoped turning
out to be used by a county team as well.

### 18.3 Suggested sequence

1. Inventory groups and their real membership. Membership, not intent.
2. Fill in the scope column, with the business owner present.
3. Build the tenant tree and seed roles.
4. Create users and profiles from the inventory, with **read-only grants only**.
5. Run both systems, comparing what the old application would allow against
   `auth.vwProfilePermission`. Differences are findings, not defects, until triaged.
6. Add the write and administrative grants.
7. Turn off the AD authorization path.

Step 4's read-only restriction is what makes step 5 safe to run in production.

### 18.4 What is deliberately not provided

An automated AD-group-to-role importer. `G-10`. The scope column cannot be derived from the
directory, so an importer would either demand it as input — at which point it is a spreadsheet
load, which the tracking workbook covers as a task — or guess it, which is how an application
ends up granting county editors agency-wide authority on day one.

---

## 19. Security considerations

### 19.1 The threats this design addresses

| Threat | Control |
|---|---|
| A user reads another tenant's records | RLS `FILTER` predicate on every registered table — §10.2 |
| A user writes a record attributed to another tenant | RLS `BLOCK AFTER INSERT`, anchored to the acting tenant — §10.3 |
| A delegated administrator extends authority beyond their organization | `INV-05` clauses 1 and 2 — §11.1 |
| A delegated administrator grants themselves authority | `INV-06`, the self-grant guard — §11.3 |
| A procedure author forgets to check a permission | RLS still applies; the failure is a bad error message, not a disclosure — §9 |
| A new domain table is added without protection | `950_verify_deployment.sql` and `G-01` — §10.1 |
| Stolen database backup yields usable sessions or passwords | Sessions stored as hashes, passwords as PHC verifiers — §6.2. The TOTP seed is application ciphertext under a key held outside the database, so the backup yields it no second factor either — §6.4 |
| Credential stuffing | Per-address throttling independent of per-account lockout — §7.4 |
| Username enumeration at sign-in | Dummy verifier of correct shape for unknown accounts — `D-08` |
| Identity provider outage locks out administrators | The platform-administrator bypass route, always with a second factor — §7.1 |
| Authority changed without a trace | `logs.AuthorizationChange`, including which grant the actor relied on — `P-08` |
| A row's tenant is changed after the fact | `TenantId` immutable, `E-50011`, plus `BLOCK AFTER UPDATE` — §10.3 |

### 19.2 Sign-in, in detail

The application must perform the same work whether or not the account exists. That means:

1. `auth.uspGetLoginVerifier` returns a verifier for every input. For an unknown, deleted,
   inactive or locked account it returns a **dummy PHC string** with the same algorithm and
   parameters as a real one, and a flag the application does not branch on until after hashing.
2. The application computes the hash unconditionally.
3. Failure messages are identical across "no such user", "wrong password", "account disabled"
   and "account locked".
4. `auth.LoginAttempt` records the true reason. The user is told nothing; the audit trail is
   told everything.

The one place this is relaxed is lockout notification, where telling a legitimate user their
account is locked is worth more than the enumeration signal — and by then they have already
passed the password check. `E-50115` is that one number; every other number in the `50100` range
maps to one identical message (§14.5, `UI-26`).

**The dummy verifier is derived from the user name, not a constant.** A single fixed dummy string
satisfies the letter of step 1 and reintroduces the leak at a different address: an attacker who
enrols one account learns the constant, and from then on any response equal to it identifies a
non-existent user, in one round trip, without hashing anything. `auth.uspGetLoginVerifier` therefore
builds the dummy from a per-install pepper and the submitted name —
`HASHBYTES ('SHA2_256', pepper + name)` for the salt field and a second, domain-separated hash for
the digest field — substituted into a PHC template that carries the **same algorithm and
parameters** as a real verifier. The result is stable for a given name, different for every name,
never equal to a real verifier, and indistinguishable from one without the pepper. Both the pepper
and the template are `config.ApplicationSetting` rows so the parameters can be raised in step with
the real ones; the pepper is marked `IsSensitive = 1`.

**The salt length must match, not merely be present.** Argon2id with a 16-byte salt produces a
22-character base64 salt field; a `SHA2_256` hash base64-encoded produces 44. A length difference in
the returned string is an enumeration signal as usable as the flag, so the template records how many
characters of each hash to take. `025_config_tables.sql` seeds a template matching the parameters the
T-040 harness uses, and changing the production parameters means changing it.

### 19.3 What a compromised application login can do

The application connects as a single pooled login in `applicationRole`. If that credential leaks, the
attacker can call every procedure `applicationRole` may execute — but every one of them demands a valid
session token, and session tokens are stored hashed.

They also hold `SELECT, INSERT, UPDATE` on `SCHEMA::dbo` through the schema grant the conventions
require. **With no session context set, RLS returns nothing and blocks every insert.** That is
worth stating plainly because it is the strongest single argument for `D-06` over view-based
filtering: the schema-level grant that the conventions mandate would otherwise be a complete
bypass.

What they can do is read the `auth` and `logs` schemas if those grants exist. They should not:
`170_permissions.sql` grants `applicationRole` `EXECUTE` on named `auth` procedures and **no table-level
access to `auth` at all**, relying on ownership chaining. `INV-11`.

`INV-11` is now enforced rather than merely satisfied, and the difference matters. It used to hold
because nothing had granted `applicationRole` any table access — which is not the same as holding, since
it would have stopped being true the first time somebody added a convenience `SELECT` to get a page
working. `170_permissions.sql` therefore issues an explicit
`DENY SELECT, INSERT, UPDATE, DELETE ON SCHEMA::auth TO applicationRole`. Measured against a real
member of the role: the eleven authentication procedures are unaffected, because ownership chaining
does not consult the permission at all, while a direct `SELECT` from `auth.[User]` is refused `229`.

The deny has a price, and it is intended. Because a `DENY` at schema level beats a `GRANT` at object
level — also measured — this forecloses ever granting `applicationRole` `SELECT` on an individual
`auth` table *or view*, including the views in §15.6. Every read the application makes of identity
data must go through a procedure, which is where tenant filtering and the audit trail live. A future
requirement for a cheap read is a requirement for a procedure, not a reason to revoke this.

**The `logs` schema had the same hole and it was open longer, because nobody had written the
invariant down.** `INV-11` names `SCHEMA::auth`. The conventions' own `scripts/permissions.sql`
grants `SELECT, INSERT, UPDATE, DELETE` on `SCHEMA::logs` to `applicationRole` — the framework
writes `logs.ExecutionLog` from the application side, so the grant has a real purpose — and that
grant is inherited by **every** table in the schema, including the four audit trails
`logs.AuthenticationEvent`, `logs.AuthorizationChange`, `logs.AuthorizationDenial` and
`logs.DataChangeLog`. So while `085_logs_auth_tables.sql` correctly said nothing is granted on the
trail tables themselves — and the trails are written only through the recorder procedures in
`165_logs_procedures.sql`, by ownership chaining — a compromised application login could have
inserted a forged record or deleted a real one directly, through the schema grant. Two statements,
both true, neither sufficient.

`170_permissions.sql` now issues an object-level
`DENY INSERT, UPDATE, DELETE` on every table in the schema bar one — each one asserted by the
script's closing report — and leaves `SELECT` alone, since reading one's own audit trail is a
legitimate application need. The recorder procedures are unaffected: ownership chaining does not
consult the permission. `SELECT` on `SCHEMA::logs` stays, and `logs.ExecutionLog` keeps all four
verbs, because that is the one table the framework genuinely writes directly. `BL-048`.

**That was the wrong shape, it was said so at the time, and it failed anyway.** `G-23` recorded the
problem in writing: the rule is inherited and permissive, the exception is enumerated and
restrictive, so the next table added to `logs` is writable by the application by default and `170`'s
report will still say twelve of twelve OK next to it — *a green report beside an ungoverned table,
which is the worst available shape for a control.* `175_perf_instrumentation.sql` then added
`logs.PermissionProbe` in Phase 5. Measured as deployed, an `applicationRole` member held `INSERT`,
`UPDATE` and `DELETE` on it for the whole of Phases 5 to 7 while the four trails were correctly
denied, and `170` printed "no problems found" on every deployment. `D-07` is taken on the contents
of that table, so a table the application can insert rows into is a decision nobody can audit.

**Both halves are now inverted, and that is the rule for this schema from here on.**
`170_permissions.sql` §4 enumerates `sys.tables` in `logs`, subtracts an exemption list held as
**rows with their reasons attached**, and issues `DENY INSERT, UPDATE, DELETE` on everything else;
§6e enumerates the same way and reports `EXEMPT`, `OK` or `VIOLATED` per table, plus a count row so
that an enumeration over an empty schema cannot pass as a clean one. `logs.ExecutionLog` is the one
exemption, because the framework genuinely writes it from the application side. A table added in a
later phase by somebody who never opens `170` is governed by it regardless. `BL-066`, and `G-23` is
closed.

**The generalisation belongs in this section rather than in the Build Log, because it is a design
rule.** `G-23` did not prevent what `G-23` predicted: the warning asked a future reader to act at a
moment nobody could name, and the author of the new table was not reading the permission script.
**Where a control covers a set that can grow, derive the set from the catalog and hold the exemptions
as data.** This design now does that in three places — every schema (`G-19`, §19.3), every audit
trigger (`135_audit_triggers.sql`, with `logs.ExecutionLog` exempt for the same single-writer
reason), and every `logs` table. The corollary is that an enumerated control needs a **count**
assertion beside it, because an enumeration over an empty set is an assertion that cannot fail.

### 19.4 Secrets

**No secret in this design is recoverable from the database alone.** That sentence used to carry an
exception — the TOTP seed — and `G-07` is why it no longer does. The seed is encrypted by the
application under a key the database has no access to and cannot name beyond a label, so a reader with
`db_owner`, a stolen backup, or both, has ciphertext and a string that says which key they do not have
(§6.4). Connection strings, signing keys and the key-encrypting key live outside the database: on the
application-layer server, in `appsettings.secrets.json` encrypted at rest and under a TPM-backed CNG
key. That is management's decision and it is recorded in `BL-033`.

What remains, and is the honest residual rather than a gap, is that the application server *is* the
boundary. Anything able to run code as the application on that machine can use the TPM key, which is
what a TPM-backed key is for: it protects against the key being *copied* elsewhere, not against misuse
in place. §19.3 is where that boundary is argued in full.

One secret does live in the database, and the permission model is what protects it.
`config.ApplicationSetting` holds `Authn.DummyVerifierPepper`, and the whole of §19.2 rests on it: the
dummy verifier returned for a user name nobody holds is derived from the pepper, so a caller who can
read the pepper can compute the expected dummy for any name and compare it with what round trip 1
returned. That caller enumerates every account in the database with no requests beyond the ones it was
already making. The defence does not degrade — it disappears.

So `170_permissions.sql` grants `SELECT` on `SCHEMA::config` to `applicationRole` and `readOnlyRole`,
because settings are operational values a monitoring query has a legitimate reason to read, and then
**denies `config.ApplicationSetting` to both** underneath that grant. The procedures keep reading it
through ownership chaining. SQL Server permissions cannot express "every row except that one", so the
seam for saying it properly is the `IsSensitive` column the table already carries: a view filtered to
`IsSensitive = 0`, granted to both roles, with the table denied under it. That view is deliberately not
built yet — nothing has asked to read a setting directly — and when something does, the answer is the
view and **not** a revoke of the two denies.

### 19.5 The bypass is a deliberate, logged weakness

`Platform.BypassRowSecurity` and `rlsBypassRole` exist because the alternative — no supported
way for a DBA or a reporting process to see the data — reliably produces an unsupported one.
Every use writes an event before it takes effect, no application login holds it, and the
deployment verification lists every member of the role by name in its report.

---

## 20. Performance and scale

| Dimension | Expected | Note |
|---|---|---|
| Tenants | tens to low thousands | Closure table is `nodes × average depth` |
| Users | thousands to tens of thousands | |
| Profiles | 1.2 × users, typically | Only the two-organization and two-programme cases need more than one |
| `auth.ProfilePermissionScope` | profiles × permissions granted | ~50 000 rows at 5 000 profiles. Fits in cache |
| RLS predicate cost | two index seeks | Folded into the outer plan as a semi-join |

Three things to watch, all of which are tasks rather than assumptions:

1. **Large scans over protected tables.** The predicate can push a plan towards nested loops. To
   be benchmarked against realistic volumes before the design is locked.
2. **`auth.uspRebuildProfilePermissionScope` under bulk grant.** Rebuilding per profile inside a
   loop over a thousand profiles is a thousand transactions. The bulk path takes a JSON array of
   profile identifiers, shreds it with `OPENJSON`, and rebuilds once — §14.6 `D-13`, `G-20`.
3. **`auth.TenantClosure` rebuild during business hours.** A full rebuild takes a schema-level
   lock for a few milliseconds at these volumes, but it is called from tenant mutation
   procedures, which are themselves rare. If tenant creation ever becomes frequent — Variant 3
   self-registration at scale — this becomes an incremental update. `G-09`.

---

## 21. Deployment and install order

### 21.1 Order

The full artefact list, in install order, is the **Scripts** worksheet of the Build and
Traceability workbook. It is not duplicated here, because a list that exists in two places
diverges. The shape of it:

```
000–025   prerequisites, schemas, roles, the conventions skill's four installers, config tables
030–085   the auth and logs tables, in dependency order
165        the three trail recorders   ── far out of number: six later scripts assert them
090       the demo domain
095–100   views and functions, including the three schema-bound RLS predicates
110, 112   authentication, then the MFA enrolment surface
105        session context   ── after 110: it calls auth.uspEndSession
115        seed reference data
125–160   the tenancy, user, profile, role, registration and platform procedures
150        auth.uspDemandPermission
180        demo domain procedures   ── before 120, and its report says UNBOUND until 120 runs
120        the row-level security policy  ── binds LAST, after everything it constrains
175        the performance probe and predicate statistics
135        the standing audit-trigger assertion   ── creates nothing; sees everything
170        permissions   ── the last word on who may read what
900       bootstrap the first administrator   ── run once, by hand, never in an automated pipeline
950       verify deployment
```

**Install order is not build order, and the executable statement of it is
`database/Install-TemplateDatabase.ps1`.** Its manifest is **thirty-nine steps** — six of them the
conventions skill's own and two of them not yet written — and the table below is every place it
departs from the file numbers on purpose. The file numbers record what a script *depends on to be
written*; the manifest records what has to *exist at deploy time*, and the two disagree wherever a
procedure reads a setting, asserts another procedure, or would be frozen by a policy that has already
bound:

| Out of order | Why |
|---|---|
| `025_config_tables.sql` runs **before every `auth` table** (step 7) | `110`'s procedures read lockout and lifetime settings out of `config.ApplicationSetting`, and `120` builds the policy from `config.TenantScopedTable`. This is the plainest case of install order not being build order: `025` was built in Phase 4 and installs seventh |
| `100_auth_functions.sql` runs **after** `065` (step 23), not with the Phase 1 scripts | `auth.tvfPermissionScope` and all three RLS predicates read `auth.ProfilePermissionScope` |
| `165_logs_procedures.sql` runs at **step 20**, immediately after the `logs` tables and **before every procedure script** | the least cosmetic ordering in the manifest. **Six** scripts assert its three recorders at install time and throw without them — `125`, `130`, `140`, `145`, `160`, and `150`, the last because `auth.uspDemandPermission` writes the denial trail. It sat at 33 until **the first clean-database build in the project's history stopped at step 29 saying so**, which is the whole argument for building one. Step 20 is the *earliest* point it can go, and therefore the point at which no later reordering can break it again. `BL-058` |
| `105_auth_session_procedures.sql` runs **after** `110` and `112` (step 26) | it calls `auth.uspEndSession`, which `110` creates. `105` only *warns* about the absence — deferred name resolution installs it either way — so the cost of getting this wrong is a warning in a transcript that looks like a defect and is not |
| `115_seed_reference_data.sql` runs at **step 27**, after the authentication procedures | and it must precede `120`: `120` resolves `Data.Read` to an integer and bakes it into three schema-bound predicates, so on an unseeded database it finds nothing, substitutes `-1` and denies everything (§10.2, `UI-35`). It also owns the application, the root tenant and the five roles `900` grants by code (`E-50086`, `E-50087`) |
| `150_auth_query_procedures.sql` runs at **step 34**, after `155` and `160` | and `140_auth_profile_procedures.sql`, at step 30, **calls it at run time** — `auth.uspSwitchProfile` returns the new profile's navigation through `auth.uspGetNavigationForProfile`. That is safe only because the call site is wrapped in an `OBJECT_ID` guard; a deployment stopping between the two gets a switch that returns one result set short rather than one that throws. Do not remove the guard to tidy it up |
| `180_dbo_application_procedures.sql` runs at **step 35, before `120`** | it looks backwards and is not. `120` cannot run first without paying for it: a bound policy freezes both the shape of `dbo.CaseFile` and the schema-bound predicate functions (error `3729`, §21.3). The cost is a **documented one-step window** in which those ten procedures enforce their own permission demands **and nothing else** — every tenant's rows visible to every profile, `P-06` not in force. `180`'s closing report prints `UNBOUND` while the window is open, which is why **a deployment that stops at step 35 must not be treated as a deployment** |
| `120_rls_policy.sql` runs **fourth from last** (step 36) | it binds the predicates, so every script that creates or alters an object the policy touches — `030`, `065`, `090`, `100` — must have finished. Binding late has a second benefit: no other script's closing report can be silently emptied by a predicate that denies the deploying session (`UI-18`) |
| `175_perf_instrumentation.sql` runs at **step 37**, after `150` | and the dependency runs the opposite way from every other pair here. `175` needs `150` to have **run**, not to install — its own closing report reads `sys.sql_modules` to confirm `auth.uspDemandPermission` contains the probe block, and would otherwise report a correct deployment as `NOT WIRED`. The reverse dependency, `150` calling `logs.uspRecordPermissionProbe`, is a run-time `OBJECT_ID` guard **deliberately**, so `150` installs and works on a database where `175` was never run and the probe simply never fires. That is a supported configuration for anyone who does not want a measurement table. `G-22` |
| `135_audit_triggers.sql` runs at **step 38** and creates nothing at all | it is a standing assertion — every table carrying the audit block must have an update trigger that maintains it, or `E-50211` stops the install. It goes this late because it must see *every* table, including `logs.PermissionProbe`, which step 37 creates; and because an assertion is worth most when it runs after the last thing that could have broken what it asserts |
| `170_permissions.sql` runs **last** (step 39) | it names objects across every schema and a `GRANT` or `DENY` on a missing object is an error rather than a skip. It is also why `175` goes in front of it rather than behind: `170` having the last word on who may read what is worth more than ending the manifest on the number it started the decade with |

`900_bootstrap_first_admin.sql` is **not** a manifest step, deliberately: the manifest is idempotent
by construction and the bootstrap refuses to run twice, so it runs after the last pass, once, and only
when a credential was supplied. `950_verify_deployment.sql` is not in the manifest because it is not
yet written (`T-104`) — the one project script still outstanding, and the installer says so on every
run rather than leaving the absence to be inferred.

`120` sits fourth from last for two reasons and only the first is in the table above: it reads
`config.TenantScopedTable` and resolves permission codes to the literals the predicate uses, so both
the tables and the seed data must exist first — and once it has run, the policy is live, so any
later script's own verification queries run *through* the predicates and come back silently empty
for a deploying session with no context (`UI-18`). Binding last keeps the rest of the deployment
readable.

**And a second deployment cannot simply repeat the first.** `Invoke-PolicyDrop` runs before step 1
on every pass, because once `120` has bound the policy the predicate functions cannot be altered at
all — §21.3.

### 21.2 Two scripts of this design come first, then the conventions skill's own

`000_prerequisites.sql` and `005_schemas_and_roles.sql`, then
`templates/extended-properties.sql`, then `scripts/logdBChanges.sql`, then
`scripts/logExecutionLogging.sql`, then `scripts/permissions.sql`.

The first two lead because there has to be a database to deploy into and the four database roles
have to exist before anything grants to them. **Every grant in this project is guarded on the
principal existing, so a role that has not been created yet is a silently skipped grant** — the
object deploys, the script reports success, and nobody can execute it. The conventions skill's
documented order assumes the roles are already a fact of the estate; here the deployment creates
them, so it has to create them first. Build Log `BL-012`.

After those two, nothing else of this design deploys before the skill's installers, because every
table wants `util.uspSetObjectDescription` and every instrumented procedure wants
`logs.ExecutionLog`.

### 21.3 Changing a schema-bound object

`auth.ProfilePermissionScope`, `auth.Permission` and `auth.TenantClosure` are referenced by a
`SCHEMABINDING` predicate function that a security policy depends on — and so, transitively, are
`auth.Tenant`, `auth.UserProfile`, and the protected tables `dbo.CaseFile` and `dbo.CaseNote`
themselves.

**This is a deployment blocker, not a caution, and it was filed as the latter.** A function a live
security policy references cannot be altered *at all*:

```
Msg 3729: Cannot ALTER 'auth.tvfTenantReadPredicate' because it is being referenced
          by object 'TenantAccessPolicy'.
```

So on any database where row-level security is already on, re-running `100_auth_functions.sql`
fails — and so does anything else touching a bound object. A developer refreshing a local database
meets this on their **second** deployment, never their first, and the error text names a function,
which sends most people to the wrong file. `BL-038`, `UI-34`.

The procedure, and it is a procedure rather than DDL:

1. `EXEC auth.uspRebuildTenantAccessPolicy @Action = N'Drop';`
2. Make the change — re-run whichever scripts are involved.
3. `EXEC auth.uspRebuildTenantAccessPolicy @Action = N'Rebuild';`

Both actions report `@TablesBound` and `@TablesSkipped` as OUTPUT parameters, so "it worked" is a
number and not an absence of errors. An `@Action` that is neither value is `E-50140`; a rebuild that
does not end with four enabled predicates for every registered table is `E-50141`, which fails the
deployment rather than leaving a table half-protected.

`Install-TemplateDatabase.ps1` does exactly this: `Invoke-PolicyDrop` before step 1 of every pass —
guarded, so it is a no-op on a database where `120` has never run — and the rebuild at step 27. Do
not drop the policy with DDL, and do not disable it and leave it disabled.

**Between steps 1 and 3 the tenant-scoped tables are unprotected.** That is stated rather than
hidden: the change window must be a maintenance window with the application stopped, on a
maintenance connection, and finished — not a rolling deployment. This is the single largest
operational constraint the design imposes and it is `G-04`.

### 21.4 Verification

`950_verify_deployment.sql` is not optional and is not decorative. It asserts:

- every table with a `TenantId` in a registered schema has a `config.TenantScopedTable` row
- every registered table is covered by a predicate in the live policy, and the policy is `ON`
- the permission-id literals in the predicate function still match `auth.Permission`
- `auth.ProfilePermissionScope` recomputed from source equals the materialized table
- `auth.TenantClosure` recomputed from the adjacency list equals the materialized table
- exactly one root tenant, and it owns no business rows
- every `auth` and `logs` table has its `trg_au_updt_` trigger, enabled
- `applicationRole` holds no table-level permission on `SCHEMA::auth`
- **every schema in the database appears in the permission report with either a grant or a stated deny** — `G-19`
- every member of `rlsBypassRole`, by name, as a report
- `Authz.AllowSelfGrant` is `0`, as a warning if it is not
- `MS_Description` present on every table and column

It exits non-zero on any failure, so a pipeline stops.

The "every schema is stated" assertion is the one item above that already runs somewhere else.
`170_permissions.sql` carries it and fails on an unstated schema, which is what closes `G-19` at
deployment time; this script is where it belongs permanently, because a deployment-time check cannot
catch an ad-hoc `REVOKE` made afterwards. The query is written once, in `170`, and will be lifted here
rather than reinvented — `BL-029` tracks that debt so it is a known transfer and not a rediscovery.

---

## 22. Appendix A — permission catalogue

`IsTenantScoped = 0` means the permission is evaluated without a tenant; everything else is
evaluated at a tenant and honours scope.

| Code | Family | Tenant-scoped | Meaning |
|---|---|---|---|
| `Data.Read` | Data | yes | See business rows. Drives the RLS `FILTER` predicate |
| `Data.Insert` | Data | yes | Create rows, anchored to the acting tenant |
| `Data.Update` | Data | yes | Modify existing rows |
| `Data.SoftDelete` | Data | yes | Set `IsDeleted = 1`. Enforced in procedures only — §10.4 |
| `Data.Restore` | Data | yes | Clear `IsDeleted`. Separate from delete on purpose |
| `Data.Export` | Data | yes | Bulk extraction. The disclosure path read alone does not distinguish |
| `Data.Execute` | Data | yes | Run a registered operation — a batch job, a recalculation |
| `Data.Approve` | Data | yes | Make a decision recorded on a record |
| `Data.Reassign` | Data | yes | Change who a record is assigned to |
| `User.Read` | User | yes | See person records |
| `User.Create` | User | yes | Create a person. Grants no profile anywhere — §11.4 |
| `User.Update` | User | yes | Change person details |
| `User.Deactivate` | User | yes | Stop a person signing in at all |
| `User.ResetCredential` | User | yes | Force a password reset or re-enrol a second factor |
| `Authz.ProfileRead` | Authz | yes | See profiles and their grants |
| `Authz.ProfileCreate` | Authz | yes | Create a profile at a tenant |
| `Authz.ProfileUpdate` | Authz | yes | Rename or re-default a profile |
| `Authz.ProfileDeactivate` | Authz | yes | Remove one hat without removing the person |
| `Authz.RoleRead` | Authz | yes | See role definitions |
| `Authz.RoleDefine` | Authz | yes | Create or change what a role *means*. Much larger than assigning one |
| `Authz.RoleAssign` | Authz | yes | Grant a role to a profile — `INV-05` |
| `Authz.RoleRevoke` | Authz | yes | Withdraw a grant |
| `Tenant.Read` | Tenant | yes | See the hierarchy |
| `Tenant.Create` | Tenant | yes | Add a tenant beneath one you administer |
| `Tenant.Update` | Tenant | yes | Rename or re-parent |
| `Tenant.Deactivate` | Tenant | yes | Make a subtree unusable |
| `Config.Read` | Config | yes | Read application settings |
| `Config.Update` | Config | yes | Change them |
| `Config.UiCatalogUpdate` | Config | yes | Change the screen and tab catalogue |
| `Audit.ReadAuthentication` | Audit | yes | `logs.AuthenticationEvent` |
| `Audit.ReadAuthorization` | Audit | yes | `logs.AuthorizationChange` and `logs.AuthorizationDenial` |
| `Audit.ReadDataChange` | Audit | yes | `logs.DataChangeLog` |
| `Platform.ManageApplications` | Platform | **no** | Register or retire an application |
| `Platform.RebuildSecurityCache` | Platform | **no** | Force a rebuild of the derived tables |
| `Platform.BypassRowSecurity` | Platform | **no** | Open a maintenance session — §10.5 |

Thirty-five permissions. The seven the requirement names explicitly are `Data.Read`,
`Data.Insert`, `Data.Update`, `Data.Execute`, `Authz.RoleAssign`, `User.Create` and
`User.Update`; §8.1 justifies each addition.

---

## 23. Appendix B — error number registry

Every number here is raised with `THROW` so a caller can branch on it. Adding a number means
adding it here first.

Three things about this registry are worth knowing before reading it, because `_tests/080_error_catalogue.sql`
measures the registry against the database and all three came out of that measurement:

- **Not every number is a caller's to catch.** `E-50080`, `E-50085`–`E-50087`, `E-50210` and `E-50211`
  are raised by *scripts* — `900_bootstrap_first_admin.sql` and `135_audit_triggers.sql` — and are
  install-time refusals. No application will ever see one, no test probes one, and the install is what
  proves them.
- **Two numbers are unreachable and are registered anyway.** `E-50043` and `E-50096` sit behind an
  earlier clause that shadows them. Each row says so, and says why the clause stays.
- **The house idiom is `;THROW <number>`, leading semicolon and all.** `_tests/080` harvests the
  reachable set out of `sys.sql_modules` by looking for exactly that string, so a module that writes
  `THROW` without the semicolon is invisible to the coverage report. One does — `util.uspPhase0Probe`
  and its `E-50099`, which exists to be thrown on purpose — and the report names it rather than
  silently missing it.

| Number | Raised by | Meaning |
|---|---|---|
| `50010` | `AFTER UPDATE` triggers in `dbo` and `auth` | An immutable column was changed |
| `50011` | domain `AFTER UPDATE` triggers | `TenantId` was changed after insert. **A declarative constraint on the same column wins the race:** where a composite foreign key already pairs `TenantId` with another column — `FK_dbo_CaseFile_AssignedToProfile`, `FK_dbo_CaseFile_ApprovedBy_Tenant` — the engine checks the key before any `AFTER` trigger fires, so the caller sees `Msg 547` rather than this number. `E-50011` is reachable only on a row whose composite keys are all `NULL`, which is what `_tests/080` probes it with. A trigger is the backstop for the columns no constraint covers, not the first line |
| `50012` | `auth.trg_au_updt_Role` | An attempt to modify a system role — `INV-10`. Raised by the **trigger**, not by a procedure, so it holds for the seed script and for an administrator holding SSMS as well. `RoleName` and `RoleDescription` stay editable; the code, the `IsSystemRole` flag and the row's existence do not |
| `50020` | `auth.uspSetSessionContext` | No such session, or it has ended |
| `50021` | `auth.uspSetSessionContext` | Session valid but the profile or its tenant is unusable |
| `50022` | `auth.uspSetSessionContext` | Session context already set for a different profile on this connection — §14.3 |
| `50023` | `auth.uspSetSessionContext` | Session expired, or idle beyond the tenant's timeout |
| `50024` | `auth.uspSetSessionContext` | The user is inactive or locked out |
| `50030` | `auth.uspDemandPermission` | Permission denied at the named tenant |
| `50031` | `auth.uspDemandPermission`, `auth.uspCheckPermission` | Permission code does not exist in this application. **`auth.uspCheckPermission` raises it too, and that is not a contradiction of its "non-throwing" description** — it returns `0` for *not held* and throws for *not a permission*, because a caller that asks about `Data.Raed` wants to be told, not told no. §13.2 |
| `50032` | `auth.uspDemandPermission` | **The session is authenticated but is wearing no profile, so there is no hat for a permission to be held by — `G-51`, §13.2.** Split out of `E-50030` by `T-126` because the two need opposite handling: `E-50030` means *this hat does not carry that verb* and the remedy is a grant; this means *this user has chosen no hat yet, or the one they were wearing was deactivated under them* and the remedy is `auth.uspListMyProfiles` and a profile chooser. A UI that treats them alike sends an administrator hunting for a missing grant that was never the problem, and signs the user out when it should be offering them a choice. Recorded in `logs.AuthorizationDenial` like any other denial, and **the user is not signed out** — §14.5 |
| `50040` | `auth.uspAssignRoleToProfile` | Actor lacks `Authz.RoleAssign` over the target profile's tenant — `INV-05` (1) |
| `50041` | `auth.uspAssignRoleToProfile` | Actor lacks `Authz.RoleAssign` over the requested scope — `INV-05` (2) |
| `50042` | `auth.uspAssignRoleToProfile` | Role's owning tenant does not cover the requested scope — `INV-04` |
| `50043` | `auth.uspAssignRoleToProfile` | Role and target profile belong to different applications. **Unreachable as built, and left registered deliberately.** `E-50042` is evaluated first and a role in another application cannot cover a scope in this one, so every cross-application grant is refused as an `INV-04` failure before this clause is reached. The number stays in the registry because the clause is the one that would state the *reason* if the ordering ever changed — `_tests/080` records it as accounted-for rather than probing it |
| `50044` | `auth.uspAssignRoleToProfile` | Self-grant refused — `INV-06` |
| `50045` | `auth.uspCreateProfile` | Actor lacks `Authz.ProfileCreate` over the requested tenant |
| `50046` | `auth.uspSetRolePermissions`, `auth.uspSetTenantAuthenticationPolicy`, `auth.uspSetTenantDefaultRoles`, `auth.uspIssueMfaRecoveryCodes` | The bulk payload is not a JSON array — `ISJSON (@Payload, ARRAY) = 0`. `D-13`, `G-20`. **This row named `auth.uspAssignRolesToProfiles` until `G-32` was closed, and that procedure does not exist and never did** — bulk role assignment is `auth.uspAssignRoleToProfile` one grant at a time, because `INV-04`, `INV-05` and `INV-06` are each evaluated against the grant in hand. The four sites above are every array payload the template ships: a role's permission list, a tenant's trusted issuers, a tenant's default roles, and a batch of MFA recovery-code hashes. Element-level faults inside a well-formed array are `E-50180`, not this number |
| `50047` | `auth.uspAssignRoleToProfile` | The role is `IsAssignable = 0`. The definition stands and existing grants keep working; no *new* grant may be made — §8.2. Distinct from an inactive or deleted role, and distinct from an authority failure, because the caller's authority is not the problem |
| `50050` | `auth.uspSwitchProfile` | Target profile does not belong to the session's user — `D-10` |
| `50051` | `auth.uspSwitchProfile` | Target profile inactive, deleted, or its tenant unusable |
| `50052` | `auth.uspSwitchProfile` | Step-up authentication required and not satisfied |
| `50060` | `auth.uspApproveOrganization` | Registration already processed |
| `50061` | `auth.uspRegisterExternalUser` | Organization not approved, or its tenant unusable |
| `50062` | `auth.uspRegisterOrganization`, `auth.uspRegisterExternalUser` | **An argument on an unauthenticated entry point is missing, blank or malformed.** Four sites raise it, and they are one number on purpose: both registration procedures take input from someone with no session, so every argument is validated before anything is written and the caller gets one number to branch on. (1) `uspRegisterOrganization` — `@OrganizationName`, `@ProposedTenantCode` or `@ContactEmail` empty or whitespace. (2) `uspRegisterOrganization` — `@ApplicationCode` names no live, active application; that is a *deployment* fault rather than something the registrant did, and it is reported as a bad argument rather than as a missing tenant so an anonymous caller learns nothing about which application codes exist. (3) `uspRegisterExternalUser` — `@RegistrationId`, `@UserName`, `@DisplayName`, `@Email` or the verifier empty or whitespace. (4) `uspRegisterExternalUser` — `@Email` is not shaped like an address (`LEN < 3` or no `_@_`); a shape test and not a validity test, because only a delivered message proves an address |
| `50063` | `auth.uspRegisterOrganization` | A `Pending` registration already exists for that proposed tenant code. Deliberately **not** keyed on the contact email: one organization may correct its contact, and two organizations may share an agent |
| `50064` | `auth.uspApproveOrganization`, `auth.uspRegisterExternalUser` | No such registration, or it has been deleted |
| `50065` | `auth.uspApproveOrganization` | The proposed tenant code is already a live tenant in this application. Caught here rather than letting `auth.uspCreateTenant` raise `E-50092`, so the message names the registration |
| `50066` | `auth.uspRegisterExternalUser` | `@UserName` is already in use. Raised on the **self-service** path, where it is not an enumeration signal the caller did not already have — they are choosing their own name |
| `50067` | `auth.uspApproveOrganization` | The external-organizations branch named by `config.ApplicationSetting` key `Registration.ExternalBranchTenantCode` does not exist in this application, or is unusable. A configuration fault, not a caller fault — §16.4 |
| `50068` | `auth.uspRegisterOrganization`, `auth.uspRegisterExternalUser` | **Too many registration arrivals from this client address inside the window — `G-24`, §16.4.** The per-address arm of the sign-in throttle (`E-50116`) applied to the two procedures that take input from someone with no session at all. `Registration.ThrottleThreshold` and `Registration.ThrottleWindowMinutes` are the settings; both procedures share one budget, so an attacker cannot get a second allowance by switching forms. The arrival is recorded by `auth.uspRecordRegistrationAttempt` **before** any other validation, which means a *refused* request still spends the budget — that is the point, since the cheapest flood is a thousand malformed ones. The message deliberately carries **no** numbers: the count, the threshold and the window go to `@Comments` and `logs.ExecutionLog`, where an operator can read them and a caller cannot (`UI-26`). This is the database half of `G-06` only; rate limiting at the edge and a CAPTCHA on the public form are still the application's, and §16.4 says so |
| `50070` | `auth.uspBeginMaintenanceSession` | Caller is not a member of `rlsBypassRole` |
| `50080` | `900_bootstrap_first_admin.sql` | Profiles already exist; bootstrap refused |
| `50081` | `auth.uspGrantPlatformAdmin`, `auth.uspRevokePlatformAdmin` | No such user, or the user is deleted |
| `50082` | `auth.uspRevokePlatformAdmin` | The revoke would leave the application with no live platform administrator. `INV-09` makes `Platform.BypassRowSecurity` and the bypass sign-in route unreachable without one, so this is the number that stops a deployment locking itself out |
| `50083` | `auth.uspRebuildEffectivePermissions` | `@UserProfileId` was supplied and names no live profile. `NULL` means "every profile" and is not an error — §8.6 |
| `50084` | `auth.uspGrantPlatformAdmin`, `auth.uspRevokePlatformAdmin` | The acting user's own `IsPlatformAdmin` is `0`. Holding `Platform.ManageApplications` is not sufficient: the capability is an **authentication** capability (`D-05`, `INV-09`), so only a platform administrator may confer it — or take it away. The **revoke** raises it as well, which widens what this registry originally said (`G-35`): the two procedures are one capability and an asymmetry would mean an administrator could be unmade by someone who could not have made them. It is raised **before** `auth.uspDemandPermission`, so a caller without the flag gets this number rather than `E-50030`, and the message names the flag rather than a permission |
| `50085` | `900_bootstrap_first_admin.sql` | `-v AdminVerifierPhc=` was not supplied, or was left at the refusal sentinel. §16.3 requires the credential on the command line and forbids a default |
| `50086` | `900_bootstrap_first_admin.sql` | `-v AppCode=` names no application, and `115_seed_reference_data.sql` seeds exactly one — so this means `115` has not run |
| `50087` | `900_bootstrap_first_admin.sql` | One or more of the five roles §16.3 step 4 grants is missing. The bootstrap will not create a profile it cannot make useful; run `115_seed_reference_data.sql` first |
| `50090` | `auth.uspCreateTenant` | Parent tenant not found, deleted, or unusable — `§5.4` |
| `50091` | `auth.uspCreateTenant` | Unknown tenant type code |
| `50092` | `auth.uspCreateTenant`, `auth.uspUpdateTenant` | `TenantCode` already used in this application |
| `50093` | `auth.uspUpdateTenant`, `auth.uspDeactivateTenant`, `auth.uspGetTenantTree` | Tenant not found or deleted |
| `50094` | `auth.uspCreateTenant`, `auth.uspUpdateTenant`, `auth.uspDeactivateTenant` | The root tenant cannot be created here, re-parented, or deactivated — `INV-02` |
| `50095` | `auth.uspUpdateTenant` | Re-parenting would place the tenant beneath its own descendant |
| `50096` | `auth.uspUpdateTenant` | The proposed parent belongs to a different application. **Unreachable as built, and left registered deliberately.** `uspUpdateTenant` demands `Tenancy.Manage` at the *proposed parent* before it compares applications, and authority cannot be held over a tenant in another application, so every cross-application re-parent is refused as `E-50030`. That ordering is the id-enumeration defence of `D-11` and is not a defect — `_tests/080` records this number as accounted-for rather than probing it |
| `50097` | `auth.uspSetTenantAuthenticationPolicy` | **The proposed policy is one nobody could sign in under. Four clauses, one number, four messages — `G-43`, §7.2.** (1) `@PreferredMethod` is neither `Federated` nor `LocalPassword`. (2) `AllowFederated` and `AllowLocalPassword` would both be `0`, which describes a tenant with no way in; closing a tenant is `auth.uspDeactivateTenant`, which is reversible and visible in `auth.vwTenantHierarchy`. (3) The preferred method is the forbidden one — a button that raises `E-50103` or `E-50104` when pressed. (4) `SessionLifetimeMinutes` or `IdleTimeoutMinutes` outside 1–43,200, or an idle window longer than the absolute lifetime, which can never take effect because `auth.uspTouchSession` ends the session on the absolute expiry first. All four restate a `CHECK` constraint on purpose (`_PreferredMethod`, `_PreferredIsAllowed`, `_Lifetimes`): the constraint would refuse with `Msg 547` naming itself, and this names the value and the alternative. Every clause is evaluated against the **merged** row — `NULL` means leave alone — and all four throw **before** `BEGIN TRANSACTION`, so a refused call creates no policy row |
| `50098` | `auth.uspSetTenantDefaultRoles` | A code in `@RoleCodesJson` cannot be a default role at this tenant — `G-43`, §11.5. Three reasons, one number: it names no live role in this application; the role's owner tenant does not cover this tenant, so `INV-04` would refuse every grant made from it; or the role is `IsAssignable = 0`, in which case `auth.uspGrantTenantDefaultRoles` would skip it silently and every new profile would quietly not receive what the screen promised. Only the **first** offending code is named, and the whole call is refused rather than partly applied — a default-role list that half-applied is one nobody could reason about afterwards. Thaw a frozen role with `auth.uspUpdateRole @IsAssignable = 1`, or list a different one |
| `50100` | `auth.uspGetLoginVerifier`, `auth.uspBeginSsoLogin` | `@UserName` or `@SubjectId` was empty or whitespace. Raised **before** any lookup, so it is not an enumeration signal |
| `50101` | `auth.uspGetLoginVerifier`, `auth.uspBeginSsoLogin` | Unknown, inactive or deleted application code |
| `50102` | `auth.uspGetLoginVerifier`, `auth.uspBeginSsoLogin` | `@TenantCode` does not exist in this application, or the tenant is unusable — `auth.udfIsTenantUsable` |
| `50103` | `auth.uspGetLoginVerifier` | The resolved tenant policy does not permit local password sign-in — §7.2 |
| `50104` | `auth.uspBeginSsoLogin` | The resolved tenant policy does not permit federated sign-in — §7.2 |
| `50105` | `auth.uspCompleteLogin`, `auth.uspCompleteSsoLogin`, `auth.uspVerifyMfa`, `auth.uspRecordLoginFailure` | No such sign-in exchange, or it has already concluded, or it has expired — `D-14` |
| `50106` | `auth.uspCompleteLogin` | The password was not verified in this exchange |
| `50107` | `auth.uspCompleteLogin` | The bypass route was used with no satisfied second factor — `INV-08` |
| `50108` | `auth.uspCompleteLogin` | The bypass route was used by a user whose `IsPlatformAdmin` is `0` — §7.1 |
| `50109` | `auth.uspCompleteLogin` | The tenant policy requires a second factor for local sign-in and none was satisfied |
| `50110` | `auth.uspVerifyMfa` | No confirmed second factor is enrolled for this user |
| `50111` | `auth.uspVerifyMfa` | The time step is outside the permitted window, or is not greater than `LastUsedTimeStep` — replay |
| `50112` | `auth.uspVerifyMfa` | The recovery code is unknown, or has already been used |
| `50113` | `auth.uspCompleteSsoLogin` | No live federated identity matches this `(Issuer, SubjectId)` — `INV-07` |
| `50114` | `auth.uspEndSession` | No such session, or it has already ended |
| `50115` | `auth.uspCompleteLogin`, `auth.uspCompleteSsoLogin` | The account is deleted, inactive, or locked out. Raised only **after** the credential has been verified, which is what makes naming it acceptable — §19.2 |
| `50116` | `auth.uspGetLoginVerifier`, `auth.uspBeginSsoLogin` | The client address has exceeded the per-address failure threshold inside the window and is throttled — §11.5. Raised at round trip 1, **before** any account is named, which is what distinguishes it from `50115`: it says nothing about whether the account exists. It is the per-address arm of the lockout pair, and it is the number an attacker spreading guesses across many names meets first |
| `50117` | `auth.uspEnrolMfaFactor`, `auth.uspConfirmMfaFactor`, `auth.uspIssueMfaRecoveryCodes` | Neither `@SessionTokenHash` nor `@BootstrapLoginAttemptId` was supplied, or **both** were. Neither means there is nobody to attribute the enrolment to; both means two answers to "who is calling", and the procedure will not choose between them — §6.4 |
| `50118` | `auth.uspEnrolMfaFactor` | `@KeyReference` is not `Authn.MfaKeyReferenceCurrent`, or the setting itself is missing or empty. Fails **closed**: a factor written under a label this deployment has retired is invisible until the retired key is gone and every factor stops decrypting at once — §6.4 |
| `50119` | `auth.uspEnrolMfaFactor` | The account already holds a confirmed factor of that type. This is what makes the enrolment window a route to a **first** factor only, and therefore an identity rather than a permission — §6.4 |
| `50120` | `auth.uspConfirmMfaFactor`, `auth.uspRotateMfaFactorKey` | There is nothing to act on: no unconfirmed factor of that type to confirm — deliberately not saying whether nothing was enrolled or it is already confirmed — or, for the rotation, no live factor with that identifier. A double-submitted confirmation lands here and the caller should treat it as success |
| `50121` | `auth.uspIssueMfaRecoveryCodes` | The recovery-code batch is malformed: more codes than `Authn.MfaRecoveryCodeCount` permits, a non-string element, a string that is not 64 hexadecimal characters, or a duplicate hash. `E-50046` covers "not a JSON array at all" |
| `50122` | `auth.uspEnrolMfaFactor`, `auth.uspConfirmMfaFactor`, `auth.uspIssueMfaRecoveryCodes` | The `@BootstrapLoginAttemptId` is not usable as enrolment proof. It must be a `Failure` with `FailureReason = 'MfaRequired'` and `PasswordVerified = 1`, inside `Authn.MfaEnrolmentWindowSeconds`. A window of `0` closes the route entirely and is a configuration choice, not a fault — §6.4 |
| `50123` | `auth.uspRotateMfaFactorKey` | The re-key would record a rotation that did not happen: the new label equals the row's current label, or the new ciphertext is byte-identical to the row's current ciphertext. Refused rather than logged as a rotation, because a sweep that reports success without changing anything is worse than one that stops — §6.4 |
| `50124` | `auth.uspBeginSsoLogin` | **The issuer named is not on the trusted-issuer list that governs this tenant, or no issuer was named at all — `G-21`, §7.3.** The list is resolved by nearest ancestor: the closest tenant at or above the requested one that holds any live `auth.TenantTrustedIssuer` row owns the answer whole, and a tenant whose ancestors hold no list at all is unconstrained, so this number is not raised there. The comparison is a string comparison against the token's `iss`, which is why `E-50180` refuses a stored issuer carrying leading or trailing whitespace: a value that can never match would silently refuse every sign-in it was added to permit. Refused **before** the redirect rather than after the identity provider has already authenticated somebody, and a `PolicyResolutionFailed` row in `logs.AuthenticationEvent` is committed before the throw |
| `50125` | `auth.uspElevateSession` | An argument cannot be used, in one of four ways, and all of them are raised **before the session is read** so that a caller with a malformed request learns nothing about which sessions exist: `@SessionTokenHash` is not exactly 32 bytes; neither or both of `@TimeStep` and `@RecoveryCodeHash` were supplied; `@FactorType` is not `Totp` or `@TimeStep` is not a positive step number (a Unix time in *seconds* is the mistake this catches); or `@RecoveryCodeHash` is not 32 bytes. **Exactly one route, never both** — both together would mean a failed code silently spending a recovery code, and neither means there is nothing to verify and no reason to elevate. The token and the code themselves are never parameters, for the reason `D-08` gives about passwords — §6.5 |
| `50126` | `auth.uspElevateSession` | There is no live, unexpired session for that token hash, or the account it belongs to is no longer usable. Absent, ended, idle-expired, absolutely expired and deactivated are one answer for the same reason `E-50020` conflates them: they are five facts about an account the caller may not own. A step-up re-proves the second factor for a session that **already exists** and cannot create one, so the remedy is to sign in, not to retry. Raised a second time at the end of the procedure if the session was ended by another connection *while* the factor was being verified — and in that case nothing was elevated **and nothing was spent**, because the spend and the elevation are one transaction |
| `50127` | `auth.uspElevateSession` | The account has no confirmed factor of `@FactorType`, so there is nothing for the reported step to have been verified against. Enrol and confirm one — `auth.uspEnrolMfaFactor` then `auth.uspConfirmMfaFactor` — from a session that does not itself need elevating. **Not counted as a failed step-up**: no factor was presented, so there is nothing to throttle, and counting it would let an unenrolled user lock their own session by asking politely |
| `50128` | `auth.uspElevateSession` | The second factor was refused, so the session has not been elevated. A TOTP step must be within `Authn.TotpWindowSteps` of the server's own step **and strictly later than the last step this factor accepted** (replay of an observed code is refused by that second condition alone); a recovery code must be one this account holds and has not spent. Raised again if another connection spent that step or that code between the check and the update, because a second row for one presentation would read as a second code. *Which* of those it was is in `logs.AuthenticationEvent`, where a reviewer can read it and a caller cannot — §6.5 |
| `50129` | `auth.uspElevateSession` | `Authn.LockoutThreshold` failed step-ups have been counted against **this session** inside `Authn.LockoutWindowMinutes`, so the session is revoked. **The account is deliberately not locked**: a step-up brute force is evidence about one stolen token, and locking the account would let whoever holds that token deny service to its owner — the opposite of what the throttle is for. The remedy is to sign in again, which the legitimate owner can do and the thief cannot — §6.5 |
| `50130` | `logs.uspRecordAuthorizationChange` | `@ChangeType` is not one of the sixteen values `CK_logs_AuthorizationChange_ChangeType` permits. The vocabulary is closed on purpose: a trail whose types are open is a trail nobody can query. Always a defect in the calling procedure |
| `50131` | `logs.uspRecordAuthorizationChange` | The row names neither a user, a profile nor a role, so nobody could ever review it — `CK_logs_AuthorizationChange_Attributable`. One of the three is enough; a change naming none is unreviewable. §15.5 |
| `50132` | `logs.uspRecordAuthorizationChange`, `logs.uspRecordAuthorizationDenial`, `logs.uspRecordDataChange` | A JSON argument was supplied and is not valid JSON — `@DetailJson` or `@ChangedColumnsJson`. `NULL` is the correct value for "nothing to add"; an empty string or a fragment is not. These columns carry the **shape** of a change and never the material |
| `50133` | `logs.uspRecordAuthorizationDenial` | `@PermissionCode` is required and was empty or whitespace. A denial that does not say which permission was refused is a row count. The code is deliberately not validated against `auth.Permission`, so a denial of a permission that has since been retired still records |
| `50134` | `logs.uspRecordDataChange` | The row this entry claims to describe cannot be identified: `@SchemaName` or `@TableName` was empty, or `@KeyJson` was missing or not valid JSON. All three are mandatory |
| `50135` | `logs.uspRecordDataChange` | `@Operation` must be `Insert`, `Update`, `SoftDelete` or `Restore`. The last two are deliberately **not** `Update` although the statement is the same one — §10.4 makes them different permissions, so the trail must be able to tell them apart |
| `50140` | `auth.uspRebuildTenantAccessPolicy` | `@Action` must be `N'Rebuild'` or `N'Drop'` — §21.3 |
| `50141` | `auth.uspRebuildTenantAccessPolicy` | The rebuilt policy does not carry four enabled predicates for every registered table. Raised **after** the rebuild, as the procedure's own check on its own work, so a deployment stops rather than leaving a tenant-scoped table half-protected |
| `50150` | `auth.uspCreateUser` | `@UserName` or `@DisplayName` was empty or whitespace |
| `50151` | `auth.uspCreateUser` | `@UserName` is already in use by a live user. `UX_auth_User_UserName` still guarantees it under a race; this number is what lets the UI say so |
| `50152` | `auth.uspUpdateUser`, `auth.uspDeactivateUser`, `auth.uspGetUser` | No such user, or the user is deleted |
| `50153` | `auth.uspCreateUser`, `auth.uspUpdateUser` | `@AuthPolicyOverrideJson` was supplied and is not valid JSON. `NULL` means "no override"; an empty string is not the same thing and is refused |
| `50154` | `auth.uspDeactivateUser` | The user is the last live platform administrator. The pair of `E-50082` on the capability side — deactivating the account achieves the same lock-out as revoking the flag, so it is refused the same way |
| `50155` | `auth.uspCreateUser` | `@IsPlatformAdmin = 1` was requested. Platform administration is conferred by `auth.uspGrantPlatformAdmin` and nowhere else, so that one grant is the only row in the trail anybody has to read — and so `E-50084`'s "only a platform administrator may confer it" cannot be walked around by creating the account instead |
| `50160` | `auth.uspCreateProfile` | No such user, or the user is deleted. Checked before the tenant, because the actor chose the user and can act on the answer |
| `50161` | `auth.uspCreateProfile` | The tenant does not exist, is deleted, or is unusable because it or a tenant above it is inactive — §5.4 |
| `50162` | `auth.uspCreateProfile`, `auth.uspUpdateProfile` | A live profile of that name already exists for this user at this tenant — `UX_auth_UserProfile_UserTenantName`, `BL-036`. Two identically named hats are indistinguishable in the switcher, and picking the wrong one sets a different `ScopeTenantId` |
| `50163` | `auth.uspUpdateProfile`, `auth.uspDeactivateProfile`, `auth.uspListProfilesForUser` | No such profile, or it is deleted |
| `50164` | `auth.uspUpdateProfile` | `@IsDefault = 0` was requested on the user's current default. `INV-03` is "exactly one", not "at most one": a user with no default has no profile to activate at sign-in. Make another profile the default instead — the procedure moves the flag for you when `@IsDefault = 1` |
| `50165` | `auth.uspDeactivateProfile` | The profile is the one currently active on the calling session. Deactivating the hat you are wearing leaves a live session whose context can never be re-established (`E-50021` on the next call) and no error that says why. Switch first — §12 |
| `50166` | `auth.uspListMyProfiles` | The session was readable one statement ago, through `auth.uspSetSessionContext`, and is not readable now: it was ended, expired or had its profile deactivated under it between the two reads. A race, and a narrow one, and it exists because the alternative is worse — a caller in that window would otherwise be handed an **empty list**, which reads as "you have no profiles" and sends a support request to the wrong place. Nothing is wrong with the call; sign in again and do not retry — §14.5 |
| `50170` | `auth.uspDefineRole` | `RoleCode` is already in use for that owner tenant in that application — `UX_auth_Role_Code`. Scoped to the owner on purpose, so two tenants may each define `REVIEWER` |
| `50171` | `auth.uspUpdateRole`, `auth.uspSetRolePermissions`, `auth.uspRevokeRoleFromProfile`, `auth.uspAssignRoleToProfile` | No such role, or it is deleted |
| `50172` | `auth.uspUpdateRole`, `auth.uspSetRolePermissions` | The role is `IsSystemRole = 1` and the requested change is one `INV-10` forbids. Raised by the **procedure** so the message can name the role and say which column was refused; `E-50012` from `auth.trg_au_updt_Role` is the backstop that also holds for SSMS. `RoleName` and `RoleDescription` are permitted here exactly as they are there, and `auth.uspSetRolePermissions` is refused outright — a system role's permission list is Appendix A |
| `50173` | `auth.uspDefineRole` | The proposed `@OwnerTenantId` does not exist, is deleted, or is unusable |
| `50174` | `auth.uspSetRolePermissions` | A permission code in the payload does not exist in the role's application. Refused as a whole; a partially applied permission list is a role nobody can reason about |
| `50175` | `auth.uspRevokeRoleFromProfile` | There is no live grant of that role at that scope to revoke. A double-submitted revoke lands here and the caller should treat it as success |
| `50176` | `auth.uspDefineRole`, `auth.uspUpdateRole` | The role's owner tenant is outside the actor's authority: `Authz.RoleDefine` is held at no ancestor-or-self of `@OwnerTenantId`. `INV-04` makes a role assignable anywhere at or below its owner, so choosing the owner *is* choosing the reach — and choosing a reach you do not have is the `INV-05` clause-2 attack wearing a different hat |
| `50177` | `auth.uspAssignRoleToProfile` | The target profile does not exist, is deleted, or is inactive. Distinct from `E-50040`: the actor's authority is not the problem |
| `50178` | `auth.uspAssignRoleToProfile` | `@ScopeTenantId` does not exist, is deleted, or is unusable. A grant at an unusable scope is authority nobody can exercise and nothing reports |
| `50179` | `auth.uspAssignRoleToProfile` | A live grant of that `(profile, role, scope)` already exists. The procedure resurrects a **revoked** grant in place rather than re-inserting it — `UX_auth_UserProfileRole_Grant` is filtered, so an insert over a soft-deleted row raises `Msg 2601` (§8.6) — and refuses when the grant is already live rather than re-stamping `GrantedUtc` and losing when the authority was actually conferred |
| `50180` | `auth.uspSetRolePermissions`, `auth.uspSetTenantAuthenticationPolicy`, `auth.uspSetTenantDefaultRoles` | **An ELEMENT of a well-formed JSON array is not usable — `G-32`.** `E-50046` answers *is this an array at all*; this answers *the array is fine and its third element is a number*. The message names the ordinal, says what is wrong with that element in words (null, a number, a boolean, a nested array, an object, blank, too long, or carrying leading or trailing whitespace) and quotes the element itself. Only the **first** offending element is named, and the whole call is refused rather than partly applied: a payload that skipped its null element would set a role to a smaller permission set than the caller listed and report success. The three payloads differ in what they accept — permission codes and role codes are non-empty strings within their column widths, while a trusted issuer is additionally refused for surrounding whitespace, because `auth.uspBeginSsoLogin` compares it as a string (`E-50124`) |
| `50190` | `logs.uspRecordPermissionProbe` | `@PermissionCode` is required and was empty — `CK_logs_PermissionProbe_PermissionCode`. A probe of a code that does not exist in `auth.Permission` is legitimate and is deliberately **not** validated against it, but a probe of no code measures nothing and could not be grouped with anything. Always a defect in the calling procedure |
| `50191` | `logs.uspRecordPermissionProbe` | `@BurstCount` must be between 2 and 10,000 — `CK_logs_PermissionProbe_BurstCount`. Below 2 the measurement is below the resolution of the system clock, which is about one millisecond on Windows and is the entire reason the burst exists. Above 10,000 the probe has stopped being a sample and become the workload. `Perf.PermissionProbeBurstCount` is the setting the caller should read |
| `50192` | `logs.uspRecordPermissionProbe` | `@TotalMicroseconds` must be present and not negative — `CK_logs_PermissionProbe_TotalMicroseconds`. A negative elapsed time means the clock moved backwards during the burst, which happens on a virtual machine whose host adjusts time, and a row recording it would poison every average taken from the table |
| `50193` | `logs.uspRecordPermissionProbe` | `@DetailJson` was supplied and is not valid JSON — `CK_logs_PermissionProbe_DetailJson`. It carries the **shape** of the measurement and never the material. `NULL` is correct when there is nothing to add |
| `50194` | `logs.uspPurgePermissionProbe` | The retention could not be resolved to a usable number of days. A `NULL` or a `0` is refused rather than interpreted, because `0` would mean "expire every sample ever taken" and is almost always an unset variable. Pass `-1` to expire the whole table deliberately; nobody types `-1` by accident |
| `50195` | `logs.uspPurgePermissionProbe` | `@BatchSize` must be between 1 and 1,000,000. The batching is not a tuning nicety: a single `UPDATE` over a month of samples escalates to a table lock and blocks `auth.uspDemandPermission`, which is the procedure that *writes* the samples — so an unbatched purge degrades the thing it is measuring |
| `50196` | `logs.uspReportPermissionProbe` | `@BucketMinutes` must be between 1 and 1,440. Below 1 `DATE_BUCKET` has no width to bucket by; above a day the time-series result set has fewer rows than the summary and stops being a time series. 60 is the default and 15 is the useful one during an incident |
| `50200` | `dbo.uspCreateCaseFile` | `@CaseNumber` is already used at this tenant. Unique per tenant, not per database: two organizations legitimately number their own cases from 1 |
| `50201` | every `dbo` procedure in `180_dbo_application_procedures.sql` | No such case file, or no such note. **"Not found" and "not yours" are deliberately the same number**, because row-level security has already removed the other tenant's rows before the procedure looks — the procedure genuinely cannot tell, and a design that could tell would be one that read around the predicate |
| `50202` | `dbo.uspApproveCaseFile` | The case file is already approved. `ApprovedUtc` is written once; a second approval by a second person would overwrite who decided |
| `50203` | `dbo.uspReassignCaseFile`, `dbo.uspApproveCaseFile` | **A profile is being attached to a case file at a tenant that is not the case file's own.** Two sites, one rule. (1) The reassignment: the target profile is not at the case file's tenant, or is unusable. (2) The approval: the *acting* profile is not at the case file's tenant — the approver's tenant is compared to the row's before anything is written, because `FK_dbo_CaseFile_ApprovedBy_Tenant` is on the composite pair and a mismatch would otherwise surface as `Msg 547` from the `UPDATE`. In both cases the composite foreign key guarantees the tenant half structurally and this is the number that *explains* it, in the caller's terms, before the engine refuses in its own. The consequence is worth stating plainly: **approval is not delegable across tenants.** An administrator with `Data.Approve` over a whole subtree still cannot approve a child tenant's case file from a root profile; they must switch to a profile at that tenant (`G-40`), and the switch costs a connection (`G-36`) |
| `50204` | `dbo.uspAddCaseNote` | The case file is closed. Notes on a closed case are the common request and the answer is to reopen it deliberately, which is an `Data.Update` |
| `50205` | `dbo.uspRestoreCaseFile` | The row is not deleted, so there is nothing to restore. `Data.Restore` is a separate permission from `Data.SoftDelete` (Appendix A) and this keeps the trail honest about which one was exercised |
| `50206` | `dbo.uspCreateCaseFile`, `dbo.uspUpdateCaseFile`, `dbo.uspAddCaseNote` | `@Title` or `@NoteText` was empty or whitespace |
| `50207` | `dbo.uspUpdateCaseFile` | `@Status` is not one of the six the demonstration domain defines (`Draft`, `Open`, `Pending`, `Approved`, `Rejected`, `Closed`). Validated in the procedure as well as by `CK_dbo_CaseFile_Status`, for the same reason as `E-50203`: the check constraint would refuse with `Msg 547` and name a constraint, this names the value and lists the alternatives. A template's demonstration domain is the place a project starts editing, so the enumeration is stated in two places on purpose |
| `50208` | `dbo.uspCloseApprovedCaseFiles` | An argument is outside its bounds: `@OlderThanDays` is negative (a date in the future, which would close nothing) or past ten years (almost certainly a units mistake — months or hours where days were meant), or `@MaxCaseFiles` is outside its batch limits. The batch ceiling is not timidity: the sweep holds its locks on `dbo.CaseFile` for the length of one transaction and that table holds every tenant's rows, so a bigger batch would stop every other tenant's work for that whole time. Call it repeatedly until `@CaseFilesClosed` comes back `0` instead. Nothing was changed. Added with the procedure itself by `T-129`, which gave `Data.Execute` its first holder and its first demander — `G-45` |
| `50209` | `dbo.uspCloseApprovedCaseFiles` | The sweep closed *n* case files and wrote a number of `logs.DataChangeLog` rows that is not *n*, so **the whole batch is rolled back**. A business row that changed with no trail entry is worse than a batch that did not run, and a set-based writer that silently under-logs is the exact failure the notes on `logs.uspRecordDataChange` warn about — the trail is written from the `UPDATE`'s `OUTPUT` clause, so the two counts agree or the procedure refuses. No caller can provoke it and none should try: it is a self-check, and reaching it means the `OUTPUT` clause has been edited |
| `50210` | `135_audit_triggers.sql` | One or more plain tables carry no `trg_au_updt_<Table>` `AFTER UPDATE` trigger. The script creates nothing: every table's trigger ships beside the table (`BL-022`), so `135`'s job is to **assert** the set is complete and fail the deployment if it is not — `G-23`. `logs.ExecutionLog` is the single documented exemption, by the conventions skill's "only writer" test |
| `50211` | `135_audit_triggers.sql` | The triggers are all present but one or more of them does not stamp the full audit block. `E-50210` asks *does a trigger exist*; this asks *does it do the job* — a trigger that fires and leaves `auditModifiedUtc` alone is worse than a missing one, because the absence is invisible in the data. Like `E-50210` it is raised by the **script** rather than by a module, so it is an install-time refusal no caller can meet and no `_tests` file probes it; the install proves it |
| `50220` | `auth.uspSetPassword`, `auth.uspChangePassword` | `@NewVerifierPhc` is not a PHC string — `G-42`, `D-08`, §19.2. It must start with `$`, name its algorithm and carry its own salt and digest (`$argon2id$v=19$m=...$<salt>$<hash>`); a bare hex digest, a plaintext password or a blank string is refused. The same shape `CK_auth_UserCredential_VerifierPhc` enforces, tested in the procedure so the caller gets a number to branch on and a sentence to read instead of `Msg 547` naming a column. **This database never receives a password and cannot hash one**, so a caller that reaches this number has a defect in its own credential pipeline |
| `50221` | `auth.uspChangePassword` | `@CurrentPasswordVerified` was not `1` — `G-42`. The same contract `auth.uspCompleteLogin`'s `@PasswordVerified` carries, for the same reason: the application proves the current password and reports it, because the database cannot check one. Refused rather than ignored — "change my password" without that proof is the whole of account takeover in one call. An administrative reset that legitimately does not have the old password is `auth.uspSetPassword`, which demands `User.ResetCredential` |
| `50222` | `auth.uspChangePassword` | The new verifier reuses one of the retired ones — `G-42`, §6.3. The comparison is the **application's**: salted hashes cannot be compared by the engine, so `auth.uspGetPasswordChangeContext` hands out the history and the caller reports the verdict in `@NewVerifierReusesHistory`. The depth is `Authn.PasswordHistoryDepth`, and it is consulted **before** the refusal: a deployment keeping no history (`0`) cannot have a reuse policy, and refusing on a caller's report of a rule nobody configured would be a control nobody asked for |
| `50223` | `auth.uspChangePassword` | There is no live password credential on this account, so there is nothing to change — `G-42`, §7.1. A federated-only user signs in through an identity provider and has no verifier here. Giving such an account its **first** password is an administrative act rather than a self-service one, because the person at the keyboard has proved nothing about a password that does not exist: `auth.uspSetPassword`, `User.ResetCredential` |
| `50224` | `auth.uspExpireCredentials` | `@BatchSize` is outside 1–100,000 — `G-12`. An operator argument to a maintenance job, never user-facing. `0` would loop forever doing nothing (the job repeats until `@UsersFlagged` comes back `0`) and a larger batch would hold locks on `auth.[User]` long enough to block sign-in. Probed by nothing and asserted by `110_auth_authn_procedures.sql`'s own closing report at install time |
| `50230` | `auth.uspGetNavigationForProfile` | `@ExpectedCatalogueVersion` does not match `config.ApplicationSetting` key `Ui.CatalogueVersion` — `G-18`, §13.1. Raised **before** the session is resolved, because a build compiled against a different catalogue is wrong for every caller and there is no point telling one of them their session expired instead. Nothing is returned: navigation built from a catalogue the build does not know has missing screens or dead commands in it. Either deploy the matching build, or re-run `115_seed_reference_data.sql` if the catalogue was extended and the version was never recomputed. `150_auth_query_procedures.sql`'s closing report raises it at install time as well, which is why `_tests/080` sees the number twice and says so |

---

## 24. Appendix C — naming conventions used here

Inherited wholesale from `ponytail-sql-objects`. Restated only where this design adds something.

| Thing | Convention | Example |
|---|---|---|
| Schemas | `auth` authn/authz · `dbo` user data · `logs` logging · `config` configuration · `util` utilities | |
| Tables | PascalCase, unprefixed, singular | `auth.UserProfile` |
| Views | `vw` prefix | `auth.vwProfilePermission` |
| Procedures | `usp` prefix | `auth.uspAssignRoleToProfile` |
| Scalar functions | `udf` prefix | `auth.udfHasPermission` |
| Table-valued functions | `tvf` prefix | `auth.tvfPermissionScope` |
| RLS predicate functions | `tvf` prefix, `…Predicate` suffix | `auth.tvfTenantReadPredicate` |
| Security policies | `<Purpose>Policy` | `auth.TenantAccessPolicy` |
| Triggers | `trg_au_updt_<Table>` | `auth.trg_au_updt_UserProfile` |
| Permission codes | `<Family>.<Verb>`, PascalCase both halves | `Authz.RoleAssign` |
| Role codes | `UPPER_SNAKE_CASE` | `ROLE_ADMIN` |
| Tenant codes | `UPPER_SNAKE_CASE` | `ANNE_ARUNDEL` |
| UI element codes | `<Type>.<Name>` | `Command.ApproveCase` |
| Session context keys | PascalCase, no prefix | `UserProfileId` |

Permission codes are PascalCase and role codes are upper snake case on purpose: the two appear
side by side constantly, in seed data and in review, and being able to tell them apart at a
glance is worth the inconsistency.

**The RLS predicate row is a correction.** Earlier drafts of this document named the predicates
`udfTenantReadPredicate` and so on, which contradicted the rule two rows above it: the prefix states
what a function *returns*, and a predicate function returns a table. All four table-valued functions
in `100_auth_functions.sql` are therefore `tvf` — `tvfPermissionScope`, `tvfTenantReadPredicate`,
`tvfTenantInsertPredicate`, `tvfTenantUpdatePredicate` — and the six scalar functions in the same
file keep `udf`. `BL-041`. A `udf`-prefixed name in any older document or workbook row refers to the
same object under its former name.

---


---

## 25. Appendix D — invariants

An invariant is a property the **database** enforces, by constraint, trigger, predicate or
procedure. Not a convention, not a code review item. Each names where it is enforced, so a
reviewer can check it exists rather than trusting that it does.

| | Invariant | Enforced by |
|---|---|---|
| `INV-01` | The root tenant owns no business rows | `950_verify_deployment.sql`; the `BLOCK AFTER INSERT` predicate cannot prevent it because the root is a legal acting tenant for administrative profiles, so this is a verification check rather than a constraint |
| `INV-02` | Exactly one root tenant per application, and only the root has a null parent | `CK_auth_Tenant_RootHasNoParent`; a filtered unique index on `(ApplicationId)` where `ParentTenantId IS NULL` |
| `INV-03` | Exactly one default profile per user | Filtered unique index on `(UserId)` where `IsDefault = 1 AND IsDeleted = 0` |
| `INV-04` | A role may be granted only at a scope its owning tenant covers | `auth.uspAssignRoleToProfile`, `E-50042` |
| `INV-05` | A grant requires the actor's `Authz.RoleAssign` to cover both the target profile's tenant and the grant's scope | `auth.uspAssignRoleToProfile`, `E-50040` and `E-50041` |
| `INV-06` | A profile may not grant a role to a profile of its own user | `auth.uspAssignRoleToProfile`, `E-50044`, overridable by `Authz.AllowSelfGrant` |
| `INV-07` | Federated identities join on the issuer's subject identifier, never on an email address | Unique index on `(Issuer, SubjectId)`; no unique index on email |
| `INV-08` | The platform-administrator bypass route always requires a second factor | `auth.uspCompleteLogin` rejects `@IsBypassRoute = 1` with `MfaSatisfied = 0` |
| `INV-09` | A `Platform` permission takes effect only for a user with `IsPlatformAdmin = 1` | `auth.udfHasPermission` tests both |
| `INV-10` | Seeded system roles cannot be edited or deleted by an administrator | `auth.uspUpdateRole` and `auth.uspSetRolePermissions`, `E-50012` |
| `INV-11` | `applicationRole` holds no table-level permission on `SCHEMA::auth` | `170_permissions.sql` grants only `EXECUTE` on named procedures; `950_verify_deployment.sql` asserts it |
| `INV-12` | A row's `TenantId` never changes after insert | Domain `AFTER UPDATE` triggers, `E-50011`; `BLOCK AFTER UPDATE` predicate as backstop |
| `INV-13` | Every registered tenant-scoped table is covered by a live predicate | `950_verify_deployment.sql` |
| `INV-14` | Authorization rows are never hard-deleted | No `DELETE` grant on `SCHEMA::auth`; `P-07` |

---

*End of DES-AUTH-001.*
