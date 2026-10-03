# T-040 — the two-round-trip password verification, proved from the client side

A small console program that signs in against `auth.uspGetLoginVerifier` and `auth.uspCompleteLogin` the way a real
application would: it computes **Argon2id itself**, against a verifier string the database issued, and tells the
database only whether the digest matched.

## Why it exists

Decision **D-08** says the database never sees a password and never computes a digest. That means
`database/_tests/040_identity_and_authn.sql` — which is otherwise the complete Phase 2 test — has to pass
`@PasswordVerified = 1` or `0` by hand, and therefore cannot test the one thing the design hangs on: that a real client
can take the PHC string the database hands back, derive a digest from it, and have the answer come out right.

This harness is that test. It also closes the other half of **T-042**: it proves that a client presented with the
*derived dummy* for a user name nobody holds cannot tell the difference — it parses with the same parser, spends the same
Argon2id work, and reaches the same `E-50106`.

## What it does

| # | Step | What is asserted |
|---|------|------------------|
| 1 | Assert the `AUTHTEST` fixture and read `Authn.DummyVerifierPhcTemplate` | the template still names `argon2id` with the parameters this harness uses |
| 2 | Write a real Argon2id verifier for `t040.real`, and reset its lockout state | a fresh salt and digest every run, so nothing depends on a constant |
| 3 | Correct password, both round trips | the returned string is the stored one, the digest matches, a session is issued |
| 4 | One character wrong | no match, no session, `E-50106` |
| 5 | A name nobody holds | the dummy parses identically, no match, **the same** `E-50106` |
| 6 | Time five derivations and five round trips for each | reported, not scored — see below |

It ends the session it opened, concludes every exchange it started, and soft-deletes its own previous attempts on the
way in, for the reason the SQL test file argues at length: both lockout arms are windowed, so a second run inside
fifteen minutes would otherwise inherit the first run's failures.

## What it deliberately does not claim

The timing numbers are printed as `INFO` and are **not** part of the pass or fail. A dev instance with a cold cache
moves them by more than the difference anybody would be looking for, and a real timing study needs thousands of samples
on a quiet machine. What the measurement is actually for is catching the gross failure — a dummy that costs half the
work of a real verifier, or twice it — which is the mistake a naive implementation makes.

The reason the derived dummy is not exploitable is not the ratio printed here. It is that both paths are microseconds of
work inside a millisecond of round trip, and that the dummy is the same length, the same algorithm and the same cost
parameters as a real verifier, so the client's own 40 ms of Argon2id dominates either way.

## Running it

```
dotnet run --project tools/T040-PasswordVerification -- --server MDE-55TT2J4 --database testTemplate
```

Both arguments default to the values above. Exit code is `0` if every observation held and `1` otherwise, so it can go
straight into a build. It authenticates with Windows integrated security and needs **db_owner**, because it writes an
`auth.UserCredential` row directly — setting a password is Phase 4's procedure and does not exist yet.

`database/_tests/040_identity_and_authn.sql` must have been run at least once first: it builds the `AUTHTEST`
application, its two tenants and the authentication policy this harness signs in against. The harness asserts that
fixture rather than creating it, so a passing run means the deployment is right and not that the harness patched it.

## Dependencies, and the one judgement call in them

* `Microsoft.Data.SqlClient` — unavoidable; .NET has shipped no in-box SQL client since .NET Framework.
* `Konscious.Security.Cryptography.Argon2` — a judgement call. .NET ships PBKDF2 and not Argon2id, so the
  dependency-free version of this harness would prove the shape of the exchange with the wrong algorithm in it, and say
  nothing about whether `m=19456,t=2,p=1` really produces the 22- and 43-character fields
  `Authn.DummyVerifierPhcTemplate` claims. For a throwaway harness that trade is easy. A production application should
  make its own decision about which implementation it trusts; what it must not do is change the cost parameters without
  changing that template, because the dummy has to keep looking like the real thing.

`bin/` and `obj/` are build output and are not part of the template.
