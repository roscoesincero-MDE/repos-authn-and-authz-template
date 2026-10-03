# UI Handoff Package — the contract the database offers the application layer

**Document ID:** UIH-AUTH-001
**Version:** 1.1
**Status:** Frozen at `M4`, 2026-09-20; amended 2026-09-21 under §10 — see **What changed in 1.1**
**Covers:** Phase 6, task `T-095`; PLAN-AUTH-001 §8 and milestone `M4`
**Audience:** the UI project, which is a separate template with its own plan
**Implements:** DES-AUTH-001 §12, §13, §14, §23 (Appendix B)

**What changed in 1.1.** Three of the absences §8 declared have been filled, and filling them changed
two signatures in §4 — which is exactly the case §10 says requires a version bump here, a Build Log row
and a DES amendment, so this is that bump. `auth.uspGetProfileContext` gained three password columns —
`PasswordExpiresUtc`, `PasswordExpiresInDays`, `PasswordExpiryWarning` — and they sit **beside
`MustChangePassword` in the middle of the result set**, not at the end, so this is a version bump rather
than §10's additive exception: a caller reading by ordinal has to be rebuilt, and a caller reading by name
does not (§4.1, `G-12`); `auth.uspGetNavigationForProfile` gained `@ExpectedCatalogueVersion`, an
**optional** argument that is nevertheless one every build should pass (§4.2, `G-18`); credential
maintenance exists (§8 item 1, `G-42`); and tenant policy and default roles now have procedures (§8
item 2, `G-43`). §6 carries the new numbers. One absence is **newly stated** rather than filled: the
edge controls a public registration form needs, which are the UI project's and which `G-06` stays open
for (§8 item 9).

---

## 1. What this document is

PLAN-AUTH-001 §8 says: *"The UI project is a separate template with its own plan. This plan's
obligation to it is a contract, delivered at `M4`."* This is that contract, and it is deliberately one
file rather than a pointer to six.

It is the **whole** surface the application layer is entitled to use. If something a screen needs is
not in here, it is either a gap to file or a procedure that has not been written — it is not an
invitation to go around the surface. Three prohibitions make that concrete, and they are the reason
the contract exists at all:

- **The application layer never reads `auth.ProfilePermissionScope`, `auth.TenantClosure` or
  `auth.EffectivePermission` directly.** They are derived caches. Read them and you have bound the UI
  to a shape `D-07` explicitly reserves the right to change.
- **The application layer never touches an `auth` table at all.** Not even `SELECT`. This is `INV-11`,
  and `170_permissions.sql` turns it from an absence into a catalog row:
  `DENY SELECT, INSERT, UPDATE, DELETE ON SCHEMA::auth TO applicationRole`. `EXECUTE` is granted
  procedure by procedure, beside each procedure, and a `DENY` on a table does not stop a procedure that
  reads it — that was measured, and it is the whole mechanism. Every read and every write of identity,
  tenancy or authorization state goes through a procedure, because the procedures are where the
  invariants, the authorization demand and the audit trail live.
- **`SCHEMA::dbo` is the deliberate exception, and it is narrower than it looks.** `applicationRole`
  holds `SELECT`, `INSERT` and `UPDATE` on `dbo`, because the demonstration domain is the one place a
  project is expected to reach tables directly — with row-level security, rather than `INV-11`, doing
  the containment. Note what is **not** granted: `DELETE`. Deletion in this design is a soft-delete
  `UPDATE`, and the absence of that verb is what makes it one. Reaching `dbo` directly also means
  `UI-40` and `UI-17` are now yours: filter by tenant yourself, and stamp `auditCreatedBy` yourself.
- **The application layer never decides authorization itself.** It may *ask* — `auth.uspCheckPermission`
  exists precisely so a screen can grey out a button — but the answer is not a licence. The procedure
  that does the work demands the permission again, on its own, at the tenant it is actually writing to.
  A UI check is a courtesy to the user; the demand is the security.

---

## 2. The six deliverables PLAN §8 names

| Deliverable | Where it is | Frozen? |
|---|---|---|
| `auth.uspGetProfileContext` | `database/150_auth_query_procedures.sql`; §4.1 below | Yes |
| `auth.uspGetNavigationForProfile` | `database/150_auth_query_procedures.sql`; §4.2 below | Yes |
| `auth.uspSwitchProfile` | `database/140_auth_profile_procedures.sql`; §4.3 below | Yes |
| DES Appendix B — the error registry | `docs/10-database-authn-authz-design.md` §23; §6 below is the UI subset | Yes |
| `workbooks/ui-gotchas.xlsx` | 42 rows; §7 below names the ones that are not optional | Living |
| DES §14 — the calling contract | `docs/10-database-authn-authz-design.md` §14; §5 below is the operative summary | Yes |

"Frozen" means the signature and the result-set column list will not change without a version bump on
this document and an entry in `workbooks/build-and-traceability.xlsx`. Columns may be **added** at the
end of a result set; nothing will be removed or reordered. Select by name, not by ordinal.

---

## 3. Signing in — the wire sequence

Sign-in is a **two-round-trip exchange** (`D-14`), and the split is not incidental: the database never
sees a password, and the application layer never decides whether a password matched a user it was
allowed to ask about.

```
round trip 1   auth.uspGetLoginVerifier  @ApplicationCode, @UserName, @ClientAddress
                                        [, @TenantCode] [, @UserAgent]
                                        → @LoginAttemptId, @VerifierPhc, @RequiresMfa

   the application layer verifies the password against @VerifierPhc, in its own process

round trip 2a  auth.uspCompleteLogin     @LoginAttemptId, @PasswordVerified = 1, @SessionTokenHash
                                        [, @IsBypassRoute]
                                        → @UserSessionId, @UserId, @MustChangePassword
                                        , @AbsoluteExpiryUtc, @IdleExpiryUtc

round trip 2b  auth.uspRecordLoginFailure @LoginAttemptId [, @FailureReason]
                                         → @AccountFailureCount, @AddressFailureCount
                                         , @AccountLockedOut, @AddressThrottled

  if @RequiresMfa = 1, between them:
               auth.uspVerifyMfa         @LoginAttemptId [, @TimeStep] [, @RecoveryCodeHash]
                                        [, @FactorType = 'Totp'] → @MfaSatisfied
```

Five things about this sequence are load-bearing:

1. **An unknown user name does not fail.** `uspGetLoginVerifier` returns a *derived dummy* verifier for
   a name it cannot find, so round trip 1 looks identical whether the account exists or not. The UI
   must therefore not treat a returned `@VerifierPhc` as proof the account exists, and must not have a
   "no such user" message. The number that says the account was bad is `E-50115`, raised by
   `uspCompleteLogin` **after** the credential verified — which is what makes naming it acceptable.
2. **Calling `uspRecordLoginFailure` is mandatory on a mismatch**, not optional bookkeeping. It is the
   only thing that advances the lockout counters (`Authn.LockoutThreshold` = 5,
   `Authn.LockoutWindowMinutes` = 15, `Authn.LockoutDurationMinutes` = 15). A UI that silently retries
   without recording the failure has disabled lockout.
3. **`@SessionTokenHash` is a hash, and the application layer holds the token.** The database is given
   `VARBINARY (32)` and never the token itself, so a database compromise does not yield usable
   sessions. The naming is a known wart (`G-26`): the parameter is on almost every procedure in the
   surface and it always means *the hash of the session token*, never the token.
4. **`@ClientAddress` is required and is throttled on.** `E-50116` is raised at round trip 1, before
   any account is named, when an address exceeds its per-address failure threshold. Pass the real
   client address — a UI that passes the web server's own address has collapsed every user in the
   deployment into one throttling bucket.
5. **`@MustChangePassword = 1` is a routing instruction.** The session is real and usable; the UI must
   send the user to a change-password screen before anything else.

Signing out is `auth.uspEndSession @SessionTokenHash` — or `@UserId`, which ends every session that
user holds, which is what an administrator's "sign this person out everywhere" button calls.

---

## 4. The three contract procedures

### 4.1 `auth.uspGetProfileContext` — everything a page header needs, in one round trip

```sql
EXEC auth.uspGetProfileContext @SessionTokenHash = @Hash;
```

One row. Call it once per page load and cache it for the life of the request; do not call it per
control.

| Group | Columns |
|---|---|
| The user | `UserId`, `UserName`, `DisplayName`, `Email`, `IsPlatformAdmin`, `MustChangePassword` |
| The password (added in 1.1) | `PasswordExpiresUtc`, `PasswordExpiresInDays`, `PasswordExpiryWarning` |
| The profile | `UserProfileId`, `ProfileName`, `IsDefaultProfile` |
| The acting tenant | `ActingTenantId`, `ActingTenantCode`, `ActingTenantName`, `ActingTenantPath`, `ActingTenantTypeCode`, `ActingTenantTypeName`, `ActingTenantDepth` |
| The application | `RootTenantId`, `ApplicationCode`, `AppUser` |
| The session | `UserSessionId`, `SessionStartedUtc`, `SessionLastSeenUtc`, `AbsoluteExpiryUtc`, `IdleExpiryUtc`, `ElevatedUntilUtc`, `MfaSatisfied`, `AuthenticationMethod`, `IsBypassRoute` |
| Navigation affordance | `SwitchableProfileCount` |

`SwitchableProfileCount` is there so the UI can decide whether to render a profile switcher at all
without a second query — one profile means no switcher, and that is the common case.

`ElevatedUntilUtc` is the step-up window. It is a timestamp and not a flag, so the UI can show the
user how long they have and can re-prompt before an action fails rather than after.

`ActingTenantPath` is the materialised path and is the right thing to render as a breadcrumb. It is
**not** a permission statement: a profile at a tenant does not necessarily hold anything there.

**The three password columns are for the header, and they behave in one way worth knowing.** Bind the
warning to `PasswordExpiryWarning` — a `BIT` the database computes from `ExpiresUtc` and
`config.ApplicationSetting` key `Authn.PasswordExpiryWarningDays` — and render
`PasswordExpiresInDays` as the number. Do **not** recompute the window in the application: the setting
is the deployment's and the arithmetic is already done. Two deliberate properties: after the deadline
`PasswordExpiresInDays` goes **negative** and the warning **stays 1**, because the flag that forces a
change is set by a batched sweep and the interval between the deadline and the next sweep is real. All
three columns are `NULL` on an account with no password — a federated-only user — and a header that
treats `NULL` as "expired" will nag people who have nothing to change (`E-50223` is what they would meet
if they tried). DES §6.3, `G-12`.

### 4.2 `auth.uspGetNavigationForProfile` — the menu, already filtered

```sql
EXEC auth.uspGetNavigationForProfile @SessionTokenHash        = @Hash
                                   ,@ElementCodePrefix      = NULL   -- optional subtree filter
                                   ,@AssumeUserProfileId    = NULL   -- optional preview, see below
                                   ,@ExpectedCatalogueVersion = NULL; -- added in 1.1 -- PASS IT
```

**`@ExpectedCatalogueVersion` is optional in the signature and mandatory in practice.** Read
`config.ApplicationSetting` key `Ui.CatalogueVersion` **at build time**, compile it into the
application, and pass that constant on every call. If it does not match the value the database holds,
the call returns nothing and raises `E-50230` — which is the point: a build that binds to element codes
(§4.2, `UI-02`) is a build the catalogue is an interface *to*, and a mismatch otherwise shows up as a
menu with missing screens or a command the database has never heard of, silently, in production. Passing
`NULL` keeps the old behaviour and is the wrong choice for anything but a diagnostic script — and a
**blank** string is not the same as omitting it: whitespace is refused, because a deployment whose
configuration key came back empty must not thereby become a silently unchecked one. The stamp is a digest
of the `(ElementCode, PermissionCode, AccessMode)` triples and nothing else, so renaming a display label
or re-ordering a menu does not invalidate a build. DES §13.1, `G-18`.

Columns: `UiElementId`, `ElementCode`, `ElementType`, `ParentUiElementId`, `DisplayLabel`,
`SortOrder`, `Depth`, `CanView`, `CanEdit`, `ActingTenantId`. Ordered by `Depth`, `SortOrder`,
`ElementCode`, so a single pass over the result set builds the tree.

**`CanView` is the constant `1` on every row, and that is the design rather than a defect.** The
filtering *is* the security: an element the profile may not see is not in the result set. A UI that
branches on `CanView` is writing dead code. The column exists so that the shape of the result set does
not change if a future requirement introduces a visible-but-disabled element, and so that
`CanView`/`CanEdit` read as a pair.

`CanEdit` **does** vary, and it is the one to bind a control's enabled state to.

`@AssumeUserProfileId` renders the menu *another* of the same user's profiles would see, without
switching to it. It is what makes a profile switcher previewable, and it is restricted to the calling
user's own profiles — it is not an impersonation feature.

### 4.3 `auth.uspSwitchProfile` — changing the acting tenant

```sql
EXEC auth.uspSwitchProfile @SessionTokenHash    = @Hash
                          ,@TargetUserProfileId = @ProfileId;
```

**Two result sets.** The first is the switch outcome: `UserProfileId`, `UserId`, `ProfileName`,
`IsDefault`, `TenantId`, `TenantCode`, `TenantName`, `TenantTypeCode`, `PreviousProfileId`,
`SwitchedUtc`, `StepUpWasRequired`, `ElevatedUntilUtc`, `AppUser`. The second is the navigation for
the profile just switched to — the same columns as §4.2 — so a switch costs one round trip and not
two.

The second set is guarded by `OBJECT_ID` so that `140` deploys before `150` exists. In a fully
installed database it is always present; a UI should nonetheless advance to the second result set
defensively rather than assume it.

**The hard part, and it is the thing most likely to cost the UI project a day:** `uspSwitchProfile`
deliberately does **not** re-establish session context on the connection it ran on. The switch is
recorded against the session, not against the connection. So:

- The connection that called `uspSwitchProfile` is **spent**. It has context for the *old* profile and
  the session now names the new one; the next `auth.uspSetSessionContext` on it raises `E-50022`.
  Return it to the pool only after resetting it, or discard it.
- The *next* request picks up a fresh connection, calls `uspSetSessionContext`, and lands on the new
  profile with no further work.
- `StepUpWasRequired = 1` with a successful switch means the step-up was satisfied from the existing
  elevation window. `E-50052` means it was not, and the UI must run the MFA challenge and retry.

---

## 5. The calling contract — DES §14, operatively

**Every request, on every connection, before anything else:**

```sql
EXEC auth.uspSetSessionContext @SessionTokenHash = @Hash;   -- → @UserId, @UserProfileId, @ActingTenantId OUTPUT
```

and on the way out, if the connection is being returned to a pool:

```sql
EXEC auth.uspClearSessionContext;
```

This is not a performance nicety. `auth.uspSetSessionContext` is what populates
`SESSION_CONTEXT (N'UserProfileId')`, and that is what the row-level security predicate reads. **A
connection with no session context sees no rows in any tenant-scoped table** — not an error, no rows.
That failure mode looks exactly like "the data is missing", which is why it is called out here.

Five rules follow, and they are the whole of the connection contract:

1. **One profile per connection, one connection per request.** `E-50022` is raised when a connection
   that already has context for one profile is asked to establish context for another. It is a
   deliberate refusal, not a limitation: silently re-pointing a live connection at a different tenant
   is how cross-tenant data leaks get written.
2. **Always clear before returning to the pool.** ADO.NET connection pooling does not reset
   `SESSION_CONTEXT`. Skip `uspClearSessionContext` and the next request to draw that connection
   inherits the previous user's profile. `uspSetSessionContext` will refuse with `E-50022` if the
   profile differs — but if it happens to be the *same* profile, there is no refusal and no error, and
   the bug is invisible until the day the profiles differ.
3. **A sign-in costs two connections.** The connection that authenticated is not the connection that
   serves the first page. See §4.3.
4. **`SET NOCOUNT ON` is on in every procedure**, so row counts are not part of the contract. Read the
   result sets and the `OUTPUT` parameters.
5. **The instrumentation is inside the transaction.** Every procedure writes a `logs.ExecutionLog` row
   on entry and updates it on exit. `logs.ExecutionLog` is exempt from the audit triggers and from
   soft delete; it is the one table the application layer may read freely for diagnostics and the one
   it must never write.

---

## 6. The error numbers a UI has to branch on

Appendix B (DES §23) is the registry and is authoritative. This is the subset that reaches a screen,
grouped by what the UI should actually *do* — which is the axis Appendix B does not organise by.

**Send the user back to sign in.**

| Number | Means |
|---|---|
| `50020` | No such session, or it has ended |
| `50023` | Session expired, or idle beyond the tenant's timeout |
| `50024` | The user is inactive or locked out |
| `50114` | `uspEndSession` found no live session — already signed out |

**Show a sign-in failure, with no detail about why.**

| Number | Means |
|---|---|
| `50100` | User name empty — a UI validation the UI should have caught |
| `50101` | Unknown, inactive or deleted application code — a **deployment** fault |
| `50102` | `@TenantCode` unknown or its tenant unusable |
| `50103` | The tenant's policy forbids local password sign-in |
| `50104` | The tenant's policy forbids federated sign-in |
| `50124` | The issuer named is not trusted by the tenant, or none was named where a list exists — a **deployment** fault, not the user's |
| `50105` | The sign-in exchange is unknown, concluded or expired — restart from round trip 1 |
| `50115` | The account is deleted, inactive or locked out |
| `50116` | The client address is throttled — this one deserves its own message and a wait |
| `50068` | The client address is throttled on the **registration** forms (`uspRegisterOrganization`, `uspRegisterExternalUser`). Same treatment as `50116`: say so, ask them to wait, show no numbers |

**Password change and reset (added in 1.1).**

| Number | Means | Show |
|---|---|---|
| `50220` | The verifier is not a PHC string | nothing to the user — an application defect. Log it: the hashing is the application's and this says it produced something the database will not store |
| `50221` | `@CurrentPasswordVerified` was not `1` | nothing to the user — an application defect. The current password must be proved in the same exchange |
| `50222` | The new password repeats a retired one | **show it.** "That password has been used before"; `Authn.PasswordHistoryDepth` is how many are remembered |
| `50223` | There is no password on this account to change | **show it.** The account signs in through an identity provider; there is nothing to change, and a first password is an administrative act (`auth.uspSetPassword`) |

**The catalogue does not match this build (added in 1.1).**

| Number | Means | Show |
|---|---|---|
| `50230` | `@ExpectedCatalogueVersion` is not the value in the database | a maintenance page, and log loudly. Not user-recoverable and not session-related: the fix is a deployment (§4.2) |

**Prompt for a second factor.**

| Number | Means |
|---|---|
| `50052` | Step-up required for this profile switch and not satisfied |
| `50109` | The tenant policy requires a second factor and none was satisfied |
| `50110` | No confirmed factor is enrolled — route to enrolment, not to a challenge |
| `50111` | Time step outside the window, or replayed |
| `50112` | Recovery code unknown or already used |

**Refuse the action and say so plainly.** These are the ones a user can act on.

| Number | Means |
|---|---|
| `50030` | Permission denied at the named tenant. **The catch-all.** See the note below |
| `50032` | The session is wearing **no profile**, so there is no hat to hold a permission. Show the profile chooser; **do not sign the user out.** `50030` is a missing grant, this is a missing hat — see the second note below |
| `50040`, `50041` | The actor lacks `Authz.RoleAssign` over the target profile's tenant, or over the requested scope |
| `50042` | The role's owning tenant does not cover the requested scope |
| `50044` | Self-grant refused |
| `50045` | The actor lacks `Authz.ProfileCreate` over the requested tenant |
| `50047` | The role is not assignable — the definition stands, no new grant may be made |
| `50050`, `50051` | The target profile is not this user's, or is unusable |
| `50070` | Not a member of `rlsBypassRole` |
| `50084` | The actor's own `IsPlatformAdmin` is `0`. No permission substitutes for it |
| `50094`, `50095` | Tenant-hierarchy refusals — see Appendix B |
| `50202`–`50208` | Domain refusals in the demonstration `dbo` surface |

**The profile chooser, and the step-up.** Both arrived with `T-125` and `T-126`. The step-up family is what a
UI meets when it asks to re-prove a second factor for a session that already exists — an elevation, not a sign-in, so
none of these numbers means "start again from the login form" unless the row says so.

| Number | Means | Show |
|---|---|---|
| `50032` | No profile on this session | The profile chooser. If the list comes back empty the user's profiles were deactivated under them, and the honest message is "your access has been changed, speak to an administrator" — not a login form |
| `50166` | The session vanished between the context call and the profile read | "Please sign in again." A race, not a fault, and not retryable — the session is gone |
| `50125` | The step-up request is malformed | Nothing. A UI that can reach this has a bug in its own call: a hash that is not 32 bytes, both a step and a recovery code, or neither |
| `50126` | No live session for that token | The login form. A step-up cannot create a session |
| `50127` | Nothing enrolled to re-prove | The enrolment flow, not the code box. This is **not** counted as a failed attempt, so the user has lost nothing |
| `50128` | The code or recovery code was refused | "That code was not accepted." Say nothing about *why* — the reason is in `logs.AuthenticationEvent` for a reviewer, and the difference between "outside the window" and "already used" is information an attacker would enjoy. Offer one more try |
| `50129` | Too many failed step-ups — **the session has been revoked** | "For your security this session has ended. Please sign in again." The account is **not** locked, so the sign-in will work; say so, because a user who believes they are locked out will call the help desk |

**Treat as a bug and log it; do not show the text to a user.**

| Number | Means |
|---|---|
| `50010`, `50011`, `50012` | An immutable column, a `TenantId`, or a system role was modified |
| `50021` | The session is valid but its profile or tenant is unusable — a data-state problem |
| `50022` | Connection context collision. **Almost always a pooling bug.** §5 rule 2 |
| `50031` | The permission code does not exist in this application — a typo in the UI's own constant |
| `50046` | A bulk payload was not a JSON array |
| `50083` | `uspRebuildEffectivePermissions` was asked to rebuild a profile that does not exist |
| `50209` | `uspCloseApprovedCaseFiles` closed rows and wrote a mismatched number of trail rows, and rolled the batch back. Nothing was changed; the sweep is broken |
| `50080`, `50085`–`50087`, `50210`, `50211` | Install-time refusals. A UI will never see one |

**The note on `E-50030`, because it is the number a UI will see most.** The tenancy and user
procedures demand permission *before* validating their arguments. That is deliberate — validating
first would let an unauthorized caller distinguish "that tenant does not exist" from "you may not
touch that tenant", which is an id-enumeration oracle (`D-11`). The consequence for the UI is that a
bad id and a missing permission are indistinguishable at the surface, and the message must therefore
not promise which one it was. `logs.ExecutionLog` and `logs.PermissionProbe` are where an
administrator finds out.

**Two numbers are registered and unreachable** — `E-50043` and `E-50096`, each shadowed by an earlier
clause. Do not write a branch for them.

---

## 7. The gotchas that are not optional

`workbooks/ui-gotchas.xlsx` holds 42 rows and the UI project should read all of them. Seven are
requirements rather than advice, and they are the ones this handoff is answerable for:

- **`UI-40` — every query against a tenant-scoped table must filter by tenant itself.** Row-level
  security is the net that catches the mistake, not the mechanism that narrows the query. This is the
  one constraint attached to the `D-07` go/no-go: the predicate costs a flat ~5 logical reads for every
  row the query *touches*, admitted or rejected, so an unfiltered aggregate over 200,000 rows pays for
  all 200,000 to return 1,000. Measured, with the plan shapes, in `docs/30-performance-measurements.md`
  §3.2. It bites hardest on `dbo`, where the UI reads tables directly.
- **`UI-05` and `UI-06` — one connection cannot serve two profiles, and every call sets its own
  session context.** §5 rules 1 and 2. These two are the difference between a working deployment and
  an intermittent cross-tenant leak, and they are the reason `E-50022` exists.
- **`UI-03` — an element you cannot view is *absent* from the navigation payload, not present with
  `CanView = 0`.** §4.2. A UI that filters on `CanView` is writing dead code.
- **`UI-08` and `UI-26` — branch on the error number, never on the message; and every sign-in failure
  shows the same message whatever the number.** §6 is organised to make the first one cheap. The second
  is not a UX preference: a differentiated message is an account-enumeration oracle with a friendly
  face.
- **`UI-23` — do not cache the permission set beyond the current request.** A role grant, a
  re-parenting or a profile switch invalidates it, and the caches behind `auth.udfHasPermission` are
  rebuilt by procedures the UI does not observe.
- **`UI-17` — `auditCreatedBy` must be set explicitly on every insert.** The `DEFAULT` reads
  `SESSION_CONTEXT` and will not save a caller who forgot.
- **`UI-18` — an empty grid is row-level security, not data loss.** The single most expensive hour a
  new developer on this template will spend. §5 says why: no context, no rows, no error.

Three more are worth naming because they are easy to read past: `UI-10` (hide the switcher for a
single-profile user — `SwitchableProfileCount` in §4.1 is there for exactly that — but never hide the
tenant), `UI-15` (a profile switch can be interrupted by a step-up challenge; `ElevatedUntilUtc` is a
timestamp, so re-prompt before the window closes rather than after an action has been refused), and
`UI-29` (every external reader, Power BI included, sees ciphertext in the encrypted columns and no
query will ever change that — see §8 item 3).

---

## 8. What is **not** delivered, and where the boundary is

This is the honest half of the contract. Each of these is a real absence, not an oversight to be
discovered in sprint 3.

1. ~~**Nothing writes `auth.UserCredential`.**~~ **Delivered in 1.1 (`G-42`).** Four procedures in
   `110_auth_authn_procedures.sql`: `auth.uspSetPassword` (administrative reset, demands
   `User.ResetCredential`, forces `MustChangePassword = 1`), `auth.uspGetPasswordChangeContext` (hands
   the application the live and retired verifiers so the comparison happens where the hashing does),
   `auth.uspChangePassword` (self-service; takes `@CurrentPasswordVerified`, retires the old verifier,
   clears the flag) and `auth.uspExpireCredentials` (the batched sweep). **What is still the
   application's** is unchanged and is the part that cannot move: the hashing parameters, the PHC string
   itself, and the reuse comparison — `D-08` means this database never receives a password and cannot
   hash or compare one. See §6 for the four numbers these raise.
2. ~~**`auth.TenantAuthenticationPolicy` and `auth.TenantDefaultRole` have no procedure.**~~
   **Delivered in 1.1 (`G-43`).** `auth.uspSetTenantAuthenticationPolicy` (`Tenant.Update` at the tenant;
   also owns the tenant's trusted-issuer list) and `auth.uspSetTenantDefaultRoles` (`Tenant.Update` and
   `Authz.RoleAssign`). Both take every argument as optional with `NULL` meaning *leave alone*, both
   validate the merged result rather than the columns, and both refuse before writing anything —
   `E-50097` for a policy nobody could sign in under, `E-50098` for a default role that could never be
   granted, `E-50180` for a malformed element in either JSON array. **One thing a screen still cannot
   do:** remove a policy row. Nothing deletes one, so "inherit from my parent again" is not an available
   state — `G-44`, and a UI should not offer a button for it.
3. **Secrets are not the database's problem, by requirement.** `appsettings.secrets.json` is encrypted
   in the application layer against a TPM-backed CNG key on the application-layer server. The database
   never holds the key and never sees plaintext, and the web front-end server needs neither. The hooks
   for a self-hosted HashiCorp Vault are left in place should management choose one later. See
   `additionalRequirements-T-041.txt`.
4. **No pagination contract.** `uspGetNavigationForProfile` returns a whole menu because a menu is
   small. Nothing in this surface pages a result set, and `UI-40` is why a UI must not rely on the
   database to bound a list for it.
5. **No localisation.** `DisplayLabel` is a single `NVARCHAR` column on `auth.UiElement`. Multiple
   languages mean either a side table the UI owns or a column set this design does not have.
6. **`dbo.CaseFile` and `dbo.CaseNote` are a demonstration, not a domain.** They exist so the template
   can prove the predicate binds something, and they are the first two tables a project deletes. The
   pattern to copy is the registration in `config.TenantScopedTable` plus the composite foreign keys
   on `(TenantId, …)` — not the columns.
7. **No concurrency measurement.** Every performance figure in `docs/30-performance-measurements.md`
   is a single connection. "No contention observed" is not a measurement, and a load test is not this
   project's to own.
8. **Approval is not delegable across tenants.** `E-50203` from `dbo.uspApproveCaseFile` means the
   approver's profile must be *at* the case file's own tenant, because
   `FK_dbo_CaseFile_ApprovedBy_Tenant` is on the composite pair. An administrator with authority over
   a whole subtree still has to switch profiles to approve a child tenant's record — two round trips,
   and `G-40` is the gap that records the cost. `G-36` is the second half of the bill: the switch itself
   spends the connection (§4.3).
9. **The public registration form needs two controls this database cannot provide, and `G-06` stays open
   for them.** `E-50068` throttles both registration procedures per client address, records every
   arrival — including the refused ones, since a malformed request is the cheapest flood to generate —
   and shares one budget across both forms (DES §16.4). That is a backstop that makes abuse visible and
   bounded. It is **not** the first line, and the two that are belong to the application project:
   **(a)** rate limiting at the gateway or in the application, because a flood that reaches the database
   has already cost a connection, a transaction and a row per attempt; and **(b)** a challenge on the
   public form — CAPTCHA or equivalent — because the throttle counts addresses and a botnet has many.
   Until both exist, Variant 3 should not go to production with a publicly reachable registration page.
   This item is why `G-06` is not closed by the database work that closed `G-24`.

---

## 9. Verifying any of this against a live database

The contract is executable. `database/_tests/` holds eight files and two of them are the ones to read
as worked examples rather than as tests:

```
sqlcmd -S 'MDE-55TT2J4' -E -d testTemplate -I -C -b -v DbName=testTemplate \
       -i database/_tests/070_variants_end_to_end.sql
sqlcmd -S 'MDE-55TT2J4' -E -d testTemplate -I -C -b -v DbName=testTemplate -v Seed=ui-1 \
       -i database/_tests/080_error_catalogue.sql
```

`070_variants_end_to_end.sql` walks the full sequence — register, approve, sign in, switch profile,
read, write — across every application variant, and is the closest thing to sample code this project
ships. `080_error_catalogue.sql` raises 96 of the registered numbers on purpose, across seven
connections, and its section 14 measures the registry against `sys.sql_modules` rather than asserting
it: 122 numbers a shipped module can throw, 117 ever observed, 96 raised by this file, 6 throwable but
unobservable with a written reason, none unaccounted for. If a UI needs to know what a number looks
like in flight, that file raises it — including every number added in 1.1.

Both are ordinary `sqlcmd` runs, and two measured facts about `sqlcmd` will save time
(`UI-41`, `UI-42`): a `-v` value **cannot contain a space** in any quoting form, and `-v` is resolved
*before* the process environment — so a value with spaces, commas or `$` characters (a PHC string, for
instance) travels intact as an environment variable and not as `-v`.

---

## 10. Change control

This document is frozen at `M4`. Changing any signature or result-set column list in §4 requires a
version bump here, a row in `workbooks/build-and-traceability.xlsx`, and a corresponding amendment in
DES-AUTH-001. Additive columns at the end of a result set are the one exception and still get the
Build Log row.

The registry in §6 tracks DES §23; if the two ever disagree, §23 wins and this document has a bug.

**`auth.UiElement.ElementCode` is a published interface, and this is the paragraph that makes it one.**
Gap `G-18` filed the absence of a version or migration story for the catalogue against this handoff, and
`M4` was reached without it, so the honest thing is to state what the freeze does and does not cover.
What it covers: **element codes are added to, never renamed.** A rename is a silent break — the
application binds to the code (`UI-02`), so a renamed element does not fail, it simply stops appearing
for everybody, with nothing in any log and no error to branch on. Adding an element is free; removing one
is a `IsDeleted = 1` and a note; renaming one is a breaking change that must go through the same route as
a signature change above.

What `G-18` stayed open for is **delivered in 1.1**, and it went further than the proposal.
`config.ApplicationSetting` key `Ui.CatalogueVersion` is a digest of the live
`(ElementCode, PermissionCode, AccessMode)` triples that `115_seed_reference_data.sql` recomputes on
every run, and `auth.uspGetNavigationForProfile @ExpectedCatalogueVersion` (§4.2) refuses a mismatch with
`E-50230`. The proposal was a key the application reads and asserts for itself; what shipped has the
**database** raise the refusal, because an assertion the caller may skip is not a control.

The rule in the paragraph above still holds, and the stamp is why it is now enforceable rather than
merely stated: a renamed element code **changes the digest**, so the next call from an unchanged build
raises `E-50230` instead of quietly dropping a menu item for everybody. What the stamp does not do is
say *which* code moved — it is a digest, not a diff — so the discipline stays: **codes are added to,
never renamed**, and a removal is `IsDeleted = 1` with a note. A deployment that extends the catalogue
re-runs `115_seed_reference_data.sql` so the version is recomputed, and ships the new constant with the
build that expects it.
