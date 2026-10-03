/***********************************************************************************************************************
Script:         100_auth_functions.sql
Purpose:        The auth schema's functions.  Ten of them, and each one is the SINGLE definition of a rule that would
                otherwise be copied into every procedure or predicate that needs it:
                  auth.udfIsTenantUsable        -- is this tenant usable (Phase 1, T-019, section 5.4)
                  auth.udfIsUserUsable          -- is this person usable (Phase 2, T-025, section 6.3)
                  auth.udfResolveAuthPolicy     -- which policy applies to this tenant (Phase 2, T-032, section 7.2)
                  auth.udfResolveSessionUser    -- whose live session is this token hash (Phase 2, T-041, section 6.4)
                  auth.udfResolveEnrolmentActor -- which refused exchange may enrol a first factor (T-041, section 6.4)
                  auth.udfHasPermission         -- may the session hold this permission here (T-050, section 9.1)
                  auth.tvfPermissionScope       -- where does the session hold this permission (T-051, section 9.1)
                  auth.tvfTenantReadPredicate   -- RLS FILTER, Data.Read (Phase 4, T-061, section 10.2)
                  auth.tvfTenantInsertPredicate -- RLS BLOCK AFTER INSERT, Data.Insert (T-062, section 10.3)
                  auth.tvfTenantUpdatePredicate -- RLS BLOCK BEFORE/AFTER UPDATE, Data.Update (T-063, section 10.3)
Target:         SQL Server 2022.
Run as:         db_owner in the target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/100_auth_functions.sql
Idempotent:     Yes.  CREATE OR ALTER throughout.  Creates nothing that holds state.
Depends on:     database/025_config_tables.sql, database/030_auth_tenant.sql, database/035_auth_tenant_policy.sql,
                database/040_auth_userprofile.sql, database/045_auth_identity.sql, database/050_auth_permission.sql,
                database/065_auth_effective_permission.sql, database/070_auth_session.sql,
                templates/extended-properties.sql.
Implements:     T-019, T-032, T-041, T-050, T-051, T-061, T-062, T-063.  DES-AUTH-001 sections 5.4, 6.3, 6.4, 7.2, 9.1,
                10.2 and 10.3.  See docs/10-database-authn-authz-design.md.
To retarget:    Pass it per run:  sqlcmd -d <database> -v DbName=<database>.  There is no in-file default.

WHY THESE ARE FUNCTIONS AND NOT REPEATED PREDICATES
--------------------------------------------------
Each one encodes a rule with a soft-delete filter, a nullable column, or a tree walk in it -- which is to say, a rule
with somewhere for a second copy to be subtly wrong.  Worse, every one of them fails OPEN when it is got wrong: a
missing IsDeleted = 0 admits a deleted tenant, a mis-negated lockout expression admits a locked-out user, and a policy
lookup that takes the first row rather than the nearest one applies the wrong tenant's rules.

A permissive failure in an authentication check is invisible, because the thing that happens is that a sign-in succeeds.
So the rule is written once and the procedures call it.

ALL OF THEM ARE SINGLE-STATEMENT, AND ONLY THE THREE PREDICATES ARE SCHEMA-BOUND
-------------------------------------------------------------------------------
One RETURN, no variable assignment, no multi-statement body -- so Froid inlines them (SQL Server 2019 and later) and
calling one in a WHERE clause or a predicate costs nothing over writing the expression out.  Adding a second statement
to any of them silently turns it back into a per-row function call on the authentication path.

WITH SCHEMABINDING is used only by the three RLS predicate functions (sections 10.2, 10.3 and 21.3), where the engine
requires it -- a security policy will not bind a function that is not schema-bound, because the whole point is that the
tables underneath the predicate cannot be altered out from under it.  Binding the other seven would freeze auth.Tenant,
auth.User, auth.TenantAuthenticationPolicy and auth.Permission against any later ALTER, and the cost would be paid by
whoever next needs to widen a column.

That binding has a consequence worth knowing before it bites.  auth.ProfilePermissionScope and auth.TenantClosure now
carry a schema-bound reference from each of the three predicates -- and auth.Permission does too, in the form THIS file
creates (see section 8's note on the two forms).  Altering any of those columns means dropping the security policies in
120_rls_policy.sql first, and re-running 120 afterwards.

THE FOURTH AND FIFTH ARRIVED WITH T-041, AND BETWEEN THEM THEY ANSWER ONE QUESTION
--------------------------------------------------------------------------------
112_auth_mfa_procedures.sql has to answer "who is asking" three times -- enrolling a factor, confirming one, and issuing
recovery codes -- and there are exactly two acceptable answers.

auth.udfResolveSessionUser is the ordinary one: the user who holds this live session.  Three copies of a liveness test
with four conditions in it (not ended, not deleted, not past its absolute expiry, not past its idle expiry) is three
chances to omit one, and omitting any of them fails OPEN -- an expired session would be allowed to enrol a second factor.

auth.udfResolveEnrolmentActor is the awkward one, and it exists because of a genuine paradox in the design rather than
for convenience.  A user under a policy with RequireMfaForLocal = 1 and no confirmed factor cannot obtain a session at
all: auth.uspCompleteLogin refuses the exchange (E-50109).  So the session route cannot reach the one person who most
needs to enrol.  What that function accepts instead is the exchange the database itself just refused, carrying
PasswordVerified = 1 that auth.uspCompleteLogin wrote, within a configured window -- a record of a past assertion, not a
new one.  It grants an IDENTITY and not a permission: its callers still refuse to touch an account that already has a
confirmed factor, so the window is a route to a first factor and to nothing else.

Both are written once, here, next to the three other rules that fail open when they are got wrong.

THE LAST FIVE ARRIVED WITH PHASES 3 AND 4, AND THEY ALL READ THE SAME TWO TABLES
------------------------------------------------------------------------------
auth.udfHasPermission and auth.tvfPermissionScope (T-050, T-051) are the two questions a procedure asks about authority:
"may this session do X here" and "where may this session do X".  The three predicate functions (T-061 to T-063) are the
same question again, asked by the engine, once per row.

All five read auth.ProfilePermissionScope -- the materialized (profile, permission, scope tenant) set built by
auth.uspRebuildProfilePermissionScope in 065_auth_effective_permission.sql -- and expand it down auth.TenantClosure.
That is the whole authorization model: a grant is held AT a tenant and reaches EVERY tenant beneath it, so the reach is a
range scan on the closure rather than a recursive walk at decision time.  The earlier drafts of this file called that
table auth.EffectiveGrant; it is auth.ProfilePermissionScope, and nothing named EffectiveGrant exists.

THE THREE PREDICATES ARE NAMED tvf, NOT udf, AND THE DESIGN DOCUMENT SAID OTHERWISE.  Sections 10.2, 10.3 and 21.3 all
called them auth.udfTenantReadPredicate and so on.  They are inline TABLE-valued functions -- they must be, because a
security policy binds nothing else -- and the house convention (SKILL.md) reserves udf for scalars and tvf for
table-valued, which the SQL gate enforces on write.  The convention wins: a reader who sees udf and expects a scalar
writes  WHERE auth.udfTenantReadPredicate (TenantId) = 1  and gets a parse error, and the prefix is the only clue
available at the call site.  The design document has been corrected to match.  BL-041.

Two things are deliberately NOT here.  The permissions enforced only in procedures -- Data.SoftDelete, Data.Restore,
Data.Export, Data.Approve, Data.Reassign, Data.Execute (section 10.4, G-05) -- have no predicate because no predicate
could express them: RLS sees a row, not an intent, and a soft delete is an UPDATE that the FILTER predicate has already
allowed.  And the security policies themselves are not here: they live in 120_rls_policy.sql, because binding a policy to
a table is a decision about WHICH tables are tenant-scoped, and that is configuration (config.TenantScopedTable) rather
than a function.
***********************************************************************************************************************/

:on error exit

-- THE TARGET DATABASE IS SUPPLIED ON THE COMMAND LINE AND HAS NO DEFAULT.  There is deliberately no `:setvar DbName`
-- line: measured on sqlcmd 17, a :setvar in the file OVERRIDES -v rather than acting as a fallback for its absence.

SET XACT_ABORT ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;
GO


-- *** 0. Assert the target and the parents ***
IF DB_NAME () <> N'$(DbName)'
BEGIN
    DECLARE @Mismatch NVARCHAR (2000) =
        N'Target mismatch. Connected to [' + DB_NAME () + N'] but this file is configured for [$(DbName)]. '
      + N'Either connect with  -d $(DbName)  or override the file with  -v DbName=' + DB_NAME ()
      + N'. Nothing has been changed.';

    THROW 50000, @Mismatch, 1;
END
GO

USE [$(DbName)];
GO

IF OBJECT_ID (N'auth.Tenant', N'U') IS NULL OR OBJECT_ID (N'auth.TenantClosure', N'U') IS NULL
BEGIN
    -- Built into a variable because THROW takes a constant or a variable, never an expression.
    DECLARE @Msg NVARCHAR (2000) =
        N'auth.Tenant or auth.TenantClosure is missing. Run database/030_auth_tenant.sql first.';

    THROW 50000, @Msg, 1;
END
GO

-- Added in Phase 2, and asserted rather than gated.  A conditional IF OBJECT_ID (...) around the creation of
-- auth.udfIsUserUsable would let this file succeed on a Phase 1 database while quietly installing two of the three
-- functions -- which is finding F-07's shape, and the reason the runner has a manifest in install order instead.
IF OBJECT_ID (N'auth.User', N'U') IS NULL OR OBJECT_ID (N'auth.TenantAuthenticationPolicy', N'U') IS NULL
BEGIN
    DECLARE @MsgPhase2 NVARCHAR (2000) =
        N'auth.User or auth.TenantAuthenticationPolicy is missing. Run database/035_auth_tenant_policy.sql and '
      + N'database/040_auth_userprofile.sql first. Nothing has been changed.';

    THROW 50000, @MsgPhase2, 1;
END
GO

-- Added with T-041, and asserted for a harder reason than the others: a scalar function has NO deferred name resolution.
-- CREATE FUNCTION over a missing table fails outright, so without this assertion the failure a reader sees is error 208
-- naming auth.UserSession from inside a CREATE, with nothing to say which script was supposed to have made it.
IF OBJECT_ID (N'auth.UserSession', N'U') IS NULL
   OR OBJECT_ID (N'auth.LoginAttempt', N'U') IS NULL
   OR OBJECT_ID (N'config.ApplicationSetting', N'U') IS NULL
BEGIN
    DECLARE @MsgSession NVARCHAR (2000) =
        N'auth.UserSession, auth.LoginAttempt or config.ApplicationSetting is missing. Run '
      + N'database/025_config_tables.sql, database/045_auth_identity.sql and database/070_auth_session.sql first -- '
      + N'auth.udfResolveSessionUser and auth.udfResolveEnrolmentActor read them, and a scalar function binds its tables '
      + N'at CREATE time rather than at call time. Nothing has been changed.';

    THROW 50000, @MsgSession, 1;
END
GO

-- Added with T-050.  Same reason as the block above, and it applies to WITH SCHEMABINDING even more strictly than to a
-- scalar function: a schema-bound function CANNOT be created over a missing table under any circumstances, so the three
-- RLS predicates would fail with error 208 naming auth.ProfilePermissionScope and no clue which script owns it.
IF OBJECT_ID (N'auth.Permission', N'U') IS NULL
   OR OBJECT_ID (N'auth.ProfilePermissionScope', N'U') IS NULL
   OR OBJECT_ID (N'auth.UserProfile', N'U') IS NULL
BEGIN
    DECLARE @MsgPhase3 NVARCHAR (2000) =
        N'auth.Permission, auth.ProfilePermissionScope or auth.UserProfile is missing. Run '
      + N'database/040_auth_userprofile.sql, database/050_auth_permission.sql and '
      + N'database/065_auth_effective_permission.sql first -- the five authorization functions read them, and the three '
      + N'RLS predicates are WITH SCHEMABINDING, which binds at CREATE time and cannot be deferred. Nothing has been '
      + N'changed.';

    THROW 50000, @MsgPhase3, 1;
END
GO


-- *** 1. auth.udfIsTenantUsable ***
/***********************************************************************************************************************
ObjectName:   auth.udfIsTenantUsable
Author:       rsincero
CreateDate:   2026-09-19
========================================================================================================================
Description:

Returns 1 when the tenant may be used as an acting tenant, and 0 otherwise.  Section 5.4: a tenant is unusable if IT is
inactive or deleted, OR IF ANY TENANT ABOVE IT IS.  Deactivating an administration therefore makes every program under it
unusable without a single write to any of them, and reactivating it restores them -- which is the reason deactivation is
not cascaded down the tree.

The single definition of usability in this database.  auth.uspSetSessionContext raises 50021 on a 0 from here,
auth.uspCreateTenant raises 50090, and auth.uspGetTenantTree reports it per node.

========================================================================================================================
Notes:

IT FAILS CLOSED, IN THREE SEPARATE WAYS, AND EACH ONE IS DELIBERATE.

  1. A tenant that does not exist returns 0, because its depth-0 self row does not exist either.
  2. A tenant whose closure has never been built returns 0 -- so a database where auth.uspRebuildTenantClosure has not
     run yet refuses every sign-in rather than accepting them unchecked.
  3. A NULL argument returns 0 rather than NULL, because EXISTS on a NULL comparison is false.  A caller writing
     IF auth.udfIsTenantUsable (@MaybeNull) = 0 gets the refusal it would want, not an unevaluated branch.

Compare the alternative: reading auth.Tenant.IsActive directly would answer only about the node, and the ancestor that
was deactivated would go unnoticed.  That failure is silent and permissive, which is the one kind this design refuses to
accept anywhere.

IT READS THE CLOSURE, NOT THE PARENT EDGES, and the closure deliberately contains soft-deleted tenants (BL-020).  If the
closure had been built over live tenants only, a deleted mid-tree tenant would vanish from its descendants' ancestor set
and this function would return 1 for a program under a deleted administration -- failing OPEN.  The closure records
shape; this function decides usability.  That division is the whole reason the closure does not filter.

ONE STATEMENT, NO SCHEMABINDING, NO MULTI-STATEMENT BODY.  A single RETURN of a CASE over two EXISTS subqueries, so
Froid inlines it (SQL Server 2019 and later) and it costs nothing extra in a predicate or a WHERE clause.  A
multi-statement body, or a variable assignment, would defeat inlining and put a function call on the request path.

WITH SCHEMABINDING is deliberately NOT used.  It would freeze auth.Tenant and auth.TenantClosure against any later
ALTER, and this design schema-binds only the three RLS predicate functions (section 21.3) where the engine requires it.
The cost of binding here would be paid in Phase 2, by whoever needs to widen a column.

========================================================================================================================
Example Usage and Performance:

select auth.udfIsTenantUsable (4);
select v.TenantCode, auth.udfIsTenantUsable (v.TenantId) as IsUsable from auth.vwTenantHierarchy as v;

Two seeks on IX_auth_TenantClosure_Descendant plus a key lookup per ancestor.  Inlined, so in a set-based query it
becomes part of the surrounding plan rather than a per-row invocation.

========================================================================================================================
Modification History:

Date:		2026-09-19
Author:		rsincero
Ticket:		T-019
Description:
Created.  Phase 1.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER FUNCTION auth.udfIsTenantUsable (@TenantId INT)
RETURNS BIT
AS
BEGIN
    -- One statement, so Froid inlines it.  See the notes before adding a second.
    RETURN CASE
               WHEN EXISTS (SELECT 1
                              FROM auth.TenantClosure AS c
                             WHERE c.DescendantTenantId = @TenantId
                               AND c.AncestorTenantId   = @TenantId
                               AND c.Depth    = 0
                               AND c.IsDeleted = 0)
                AND NOT EXISTS (SELECT 1
                                  FROM auth.TenantClosure AS c
                                  JOIN auth.Tenant        AS t ON t.TenantId = c.AncestorTenantId
                                 WHERE c.DescendantTenantId = @TenantId
                                   AND c.IsDeleted = 0
                                   AND (t.IsActive = 0 OR t.IsDeleted = 1))
               THEN CAST (1 AS BIT)
               ELSE CAST (0 AS BIT)
           END;
END;
GO


-- *** 2. auth.udfIsUserUsable ***
/***********************************************************************************************************************
ObjectName:   auth.udfIsUserUsable
Author:       rsincero
CreateDate:   2026-09-19
========================================================================================================================
Description:

Returns 1 when the person may sign in and hold a session, and 0 otherwise.  The user-side counterpart of
auth.udfIsTenantUsable, and the SINGLE copy of the effective-lockout expression:

    locked  =  IsLockedOut = 1 AND (LockoutEndUtc IS NULL OR LockoutEndUtc > SYSUTCDATETIME ())

usable  =  the row exists, IsDeleted = 0, IsActive = 1, and NOT locked.

========================================================================================================================
Notes:

THE NEGATION IS THE WHOLE POINT, AND IT IS WHERE A SECOND COPY WOULD GO WRONG.  The negation of "locked" is

    IsLockedOut = 0  OR  (LockoutEndUtc IS NOT NULL AND LockoutEndUtc <= SYSUTCDATETIME ())

and the tempting short version -- IsLockedOut = 0 OR LockoutEndUtc <= SYSUTCDATETIME () -- is WRONG in the case that
matters most: an administrative lock has LockoutEndUtc IS NULL, so the comparison is NULL, so the OR is not true, so
the clause happens to behave correctly here but behaves the opposite way the moment somebody rewrites it as
NOT (LockoutEndUtc > SYSUTCDATETIME ()).  NULL handling that depends on which way round the author wrote it is exactly
what a single definition exists to remove.

WHY LAPSED LOCKS ARE NOT TIDIED UP.  A user whose LockoutEndUtc has passed is usable again the moment the clock passes
it -- no write, no job, no sweep.  auth.uspCompleteLogin clears the flag lazily on the next successful sign-in.  A
background job that cleared lapsed locks would be a job that has to be running for authentication to be correct, and
the trail is more useful with the lapsed lock left in place.  See 040_auth_userprofile.sql.

IT FAILS CLOSED, in the same three ways: an absent user returns 0, a soft-deleted user returns 0, and a NULL argument
returns 0 rather than NULL, because EXISTS over a NULL comparison is false.

IsPlatformAdmin IS NOT CONSULTED HERE.  Usability and authority are different questions: INV-09 is a check on what a
platform administrator may do, not on whether they may sign in.  Mixing them would mean a function called "is usable"
that returned 0 for a perfectly ordinary user, which is the kind of surprise that gets worked around rather than read.

========================================================================================================================
Example Usage and Performance:

select auth.udfIsUserUsable (1);
select u.UserName, auth.udfIsUserUsable (u.UserId) as IsUsable from auth.[User] as u where u.IsDeleted = 0;

One clustered-index seek.  Inlined, so in a set-based query it becomes part of the surrounding plan.

========================================================================================================================
Modification History:

Date:		2026-09-19
Author:		rsincero
Ticket:		T-025
Description:
Created.  Phase 2.  The single copy of the effective-lockout expression, promised by 040_auth_userprofile.sql.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER FUNCTION auth.udfIsUserUsable (@UserId INT)
RETURNS BIT
AS
BEGIN
    -- One statement, so Froid inlines it.  See the notes before adding a second.
    RETURN CASE
               WHEN EXISTS (SELECT 1
                              FROM auth.[User] AS u
                             WHERE u.UserId    = @UserId
                               AND u.IsDeleted = 0
                               AND u.IsActive  = 1
                               AND (u.IsLockedOut = 0
                                 OR (u.LockoutEndUtc IS NOT NULL AND u.LockoutEndUtc <= SYSUTCDATETIME ())))
               THEN CAST (1 AS BIT)
               ELSE CAST (0 AS BIT)
           END;
END;
GO


-- *** 3. auth.udfResolveAuthPolicy ***
/***********************************************************************************************************************
ObjectName:   auth.udfResolveAuthPolicy
Author:       rsincero
CreateDate:   2026-09-19
========================================================================================================================
Description:

Returns the TenantAuthenticationPolicyId of the policy that applies to @TenantId -- the NEAREST live policy at or above
it in the tenant tree -- or NULL when no tenant at or above it has one.  Section 7.2.

IT RETURNS AN IDENTIFIER, NOT A POLICY.  The udf prefix means scalar, and a scalar function cannot return eight columns.
The caller reads the row it names:

    declare @PolicyId int = auth.udfResolveAuthPolicy (@TenantId);
    select AllowFederated, AllowLocalPassword, RequireMfaForLocal, PreferredMethod
      from auth.TenantAuthenticationPolicy where TenantAuthenticationPolicyId = @PolicyId;

A table-valued tvfResolveAuthPolicy returning the whole row was the alternative and was rejected: every caller needs a
different subset of the columns, a tvf cannot be used in a scalar comparison, and the identifier is the thing that gets
recorded on auth.LoginAttempt.PolicyTenantId's sibling columns anyway.

========================================================================================================================
Notes:

NULL IS A REAL ANSWER AND IT MEANS "NO POLICY ROW APPLIES", NOT "DENY".  Most tenants have no policy row; a small
deployment may have none at all.  The caller's job is to fall back to the shipped defaults in config.ApplicationSetting
(Authn.*), and auth.uspGetLoginVerifier does exactly that.  That is why this function does NOT invent a synthetic
default here: a fabricated identifier would point at no row, and a caller that forgot to check would silently read zero
columns and treat them as false -- which would disable local password sign-in for the whole estate.

NEAREST, NOT FIRST.  ORDER BY c.Depth with TOP (1): depth 0 is the tenant's own policy, depth 1 its parent's, and so on.
Taking any matching ancestor rather than the closest one would apply a grandparent's rules over a parent's override,
which is the same failure as a CSS rule losing to a less specific one -- correct-looking and wrong in the only cases
anybody bothered to configure.

IT READS THE CLOSURE, so it inherits the closure's property that a soft-deleted mid-tree tenant is STILL in the
ancestor set (BL-020).  That is deliberate here too: a deleted administration's policy should keep applying to the
programs beneath it until somebody deals with them, because the alternative is that deleting one row silently relaxes
the sign-in rules for everything underneath.  Whether those tenants are usable at all is auth.udfIsTenantUsable's
question, and the sign-in path asks both.

The policy row itself must be live -- p.IsDeleted = 0.  A deleted POLICY is a policy somebody retired on purpose, and
the next one up should apply.

========================================================================================================================
Example Usage and Performance:

select auth.udfResolveAuthPolicy (4);
select t.TenantCode, auth.udfResolveAuthPolicy (t.TenantId) from auth.Tenant as t where t.IsDeleted = 0;

A seek on IX_auth_TenantClosure_Descendant, a key lookup per ancestor and a seek on UX_auth_TenantAuthenticationPolicy_
Tenant.  The ancestor chain is the depth of the tree, which section 5 expects to be small.

========================================================================================================================
Modification History:

Date:		2026-09-19
Author:		rsincero
Ticket:		T-032
Description:
Created.  Phase 2.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER FUNCTION auth.udfResolveAuthPolicy (@TenantId INT)
RETURNS INT
AS
BEGIN
    -- One statement, so Froid inlines it.  TOP (1) with ORDER BY Depth is "nearest", not "any" -- see the notes.
    RETURN (SELECT TOP (1) p.TenantAuthenticationPolicyId
              FROM auth.TenantClosure                AS c
              JOIN auth.TenantAuthenticationPolicy   AS p ON p.TenantId  = c.AncestorTenantId
                                                         AND p.IsDeleted = 0
             WHERE c.DescendantTenantId = @TenantId
               AND c.IsDeleted          = 0
             ORDER BY c.Depth ASC);
END;
GO


-- *** 4. auth.udfResolveSessionUser ***
/***********************************************************************************************************************
ObjectName:   auth.udfResolveSessionUser
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Returns the UserId that holds the LIVE session whose token hash is @SessionTokenHash, or NULL when no live session has
that hash.  Section 6.4.  The single definition of session liveness for the callers that need to know WHO is asking
rather than merely whether somebody is:

    live  =  EndedUtc IS NULL
             AND IsDeleted = 0
             AND AbsoluteExpiryUtc > SYSUTCDATETIME ()
             AND IdleExpiryUtc     > SYSUTCDATETIME ()

The caller passes the HASH, never the token.  auth.UserSession stores SHA-256 of the session token and the template
never holds the token itself, so a function taking the token would have to hash it -- and then two callers would
disagree about which encoding was hashed.  The application hashes; this resolves.

========================================================================================================================
Notes:

WHY THIS IS A FUNCTION AND NOT FOUR LINES IN EACH PROCEDURE.  112_auth_mfa_procedures.sql asks "who is asking" three
times: enrolling a factor, confirming one, and issuing recovery codes.  Four conditions written out three times is three
chances to omit one, and every omission fails OPEN -- an ended or expired session would be allowed to enrol a second
factor on somebody's account, which is precisely the operation an attacker with a stale token wants.

IT DOES NOT TOUCH THE SESSION.  Resolving is a read: LastSeenUtc and IdleExpiryUtc are not slid forward here.  A scalar
function cannot write, which is the point -- sliding the idle window is a decision about what counts as activity, and it
belongs to auth.uspTouchSession where it can be read in one place.  So resolving a session repeatedly does NOT keep it
alive, and a session whose idle window lapses mid-enrolment is correctly refused on the next call.

IT DOES NOT CONSULT auth.udfIsUserUsable, AND THAT IS DELIBERATE.  A user who was locked out AFTER their session began
still has a live session row, and this returns their id.  The two questions are separate on purpose: "whose session is
this" is a fact, "may they act" is a policy, and the procedures in 112 ask both -- so the refusal the caller sees names
the real reason (E-50115 account unusable) instead of the misleading "no live session" (E-50114).  Folding the usability
test in here would collapse two different refusals into one and make a support call unanswerable.

IT FAILS CLOSED: an unknown hash returns NULL, a NULL hash returns NULL (the = comparison is never true), and an ended,
deleted or expired session returns NULL.  There is no branch in which an unrecognised token produces a user.

MFA IS NOT PART OF LIVENESS.  A session with MfaSatisfied = 0 is still a live session, and this returns its user.  That
matters for the half-authenticated states section 6.4 allows; a caller that requires a fully authenticated session tests
MfaSatisfied itself, because a function that silently required it would break the enrolment flow that exists to get a
factor onto the account in the first place.

========================================================================================================================
Example Usage and Performance:

select auth.udfResolveSessionUser (0x00);
select auth.udfResolveSessionUser (s.SessionTokenHash) from auth.UserSession as s where s.EndedUtc is null;

One seek on UX_auth_UserSession_TokenHash, which is the unique filtered index on the hash, plus a key lookup for the
four liveness columns.  One statement and no SCHEMABINDING, so Froid inlines it.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-041
Description:
Created.  Phase 2.  The single definition of "who holds this live session", needed three times by
112_auth_mfa_procedures.sql.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER FUNCTION auth.udfResolveSessionUser (@SessionTokenHash VARBINARY (32))
RETURNS INT
AS
BEGIN
    -- One statement, so Froid inlines it.  All four liveness conditions, in one place -- see the notes.
    RETURN (SELECT s.UserId
              FROM auth.UserSession AS s
             WHERE s.SessionTokenHash  = @SessionTokenHash
               AND s.EndedUtc         IS NULL
               AND s.IsDeleted         = 0
               AND s.AbsoluteExpiryUtc > SYSUTCDATETIME ()
               AND s.IdleExpiryUtc     > SYSUTCDATETIME ());
END;
GO


-- *** 5. auth.udfResolveEnrolmentActor ***
/***********************************************************************************************************************
ObjectName:   auth.udfResolveEnrolmentActor
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Returns the UserId a JUST-REFUSED sign-in exchange may act as, for the sole purpose of enrolling a first second factor,
or NULL.  Section 6.4, task T-041.  The other half of "who is asking" -- auth.udfResolveSessionUser answers it for
somebody who already has a session, and this answers it for somebody who cannot get one.

An exchange qualifies only when ALL of these hold:

    the row exists and is live
    Outcome         = 'Failure'
    FailureReason   = 'MfaRequired'
    PasswordVerified = 1
    AttemptedUtc is within Authn.MfaEnrolmentWindowSeconds of now
    the account held NO confirmed factor when the exchange was made (G-52, BL-086)

========================================================================================================================
Notes:

WHY THIS EXISTS AT ALL -- THE ENROLMENT BOOTSTRAP PARADOX.  A user under a policy with RequireMfaForLocal = 1 who has no
confirmed factor cannot sign in: auth.uspCompleteLogin refuses the exchange with E-50109.  No session means no
session-based self-service page, so the ordinary enrolment route cannot reach the one person who most needs it.  Before
T-041 that was not a theoretical hole -- the test fixture user `frank` sits under exactly such a policy and was
permanently unable to sign in.

The alternatives were worse.  An administrative-only enrolment route makes every new user a service-desk ticket and
guarantees that somebody will relax the policy instead.  A parameter saying "trust me, this is user 7" moves the
authentication decision into the application, which is the one thing this schema exists to prevent.

WHAT MAKES IT SAFE IS THAT THE DATABASE WROTE THE PROOF ITSELF.  PasswordVerified = 1 on that row was written by
auth.uspCompleteLogin after the application reported a correct password, in the same exchange, and auth.LoginAttempt's
trigger makes the column immutable and a terminal Outcome final (D-14).  So the row is durable, database-issued evidence
that whoever holds this LoginAttemptId knew the password minutes ago.  Nothing here trusts a new assertion; it reads a
record of an old one.

IT IS DELIBERATELY NOT LIMITED TO THE E-50109 REFUSAL.  'MfaRequired' is also written when INV-08 refuses the
platform-administrator bypass route without a second factor (E-50107), and that caller is in the same position for the
same reason -- correct password, no factor, no way in.  Excluding it would mean a platform administrator with no factor
could never use the route the factor is required for.

WHAT IT DOES *NOT* AUTHORISE, and this is the part to keep in view.  It returns an identity, not a permission, and only
for an account that had no confirmed factor when the exchange was made -- so this window can never add to or replace a
working authenticator, which would be account takeover with nothing but the password.  It is a route to a FIRST factor
and nothing else.  G-52, BL-086: this used to be left to the callers, and they did not hold it -- auth.uspEnrolMfaFactor
refuses only a confirmed factor OF THE SAME TYPE (E-50119), and auth.uspIssueMfaRecoveryCodes REQUIRES a confirmed
factor.  So anybody holding the password of an account with a TOTP factor could sign in, be refused MfaRequired, and
spend that refusal on a batch of recovery codes that satisfy the MFA they do not have.  The rule now lives here, once.
Factors confirmed AFTER the exchange do not count against it, so the one visit still runs enrol, confirm, recovery codes.

SETTING THE WINDOW TO 0 TURNS IT OFF.  DATEADD (SECOND, 0, AttemptedUtc) > now is false for every row, so a deployment
that wants enrolment to be an administrative act sets Authn.MfaEnrolmentWindowSeconds to 0 and gets that with no code
change.  The shipped 900 seconds is fifteen minutes: long enough to install an authenticator app, short enough that a
LoginAttemptId captured from a log is stale by the time anybody reads it.

IT FAILS CLOSED: an unknown id, a pending exchange, a successful one, a failure for any other reason, a failure with no
verified password, a lapsed window and NULL all return NULL.

========================================================================================================================
Example Usage and Performance:

select auth.udfResolveEnrolmentActor (42);

One clustered-index seek on auth.LoginAttempt and one seek on UX_config_ApplicationSetting_SettingKey.  One statement,
so Froid inlines it.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-041
Description:
Created.  Phase 2.  The bootstrap half of "who is asking", so that a user whose policy requires MFA is not locked out of
the only operation that would let them comply.

-----------------------------------------------------------------------------------------------------------------------

Date:		2026-09-25
Author:		rsincero
Ticket:		G-52
Description:
Returns NULL when the account held a confirmed factor when the exchange was made (ConfirmedUtc at or before
AttemptedUtc).  Closes recovery codes, or a factor of another type, for anybody holding only the password.  _tests/040
12m' proves it.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER FUNCTION auth.udfResolveEnrolmentActor (@LoginAttemptId BIGINT)
RETURNS INT
AS
BEGIN
    -- One statement, so Froid inlines it.  The COALESCE default matches the shipped Authn.MfaEnrolmentWindowSeconds, so
    -- a deleted setting row degrades to the documented value rather than to NULL -- which would make the whole
    -- comparison NULL and, since NULL is not true, would fail closed anyway.  Both ways are safe; this one is legible.
    RETURN (SELECT a.UserId
              FROM auth.LoginAttempt AS a
             WHERE a.LoginAttemptId   = @LoginAttemptId
               AND a.IsDeleted        = 0
               AND a.Outcome          = 'Failure'
               AND a.FailureReason    = 'MfaRequired'
               AND a.PasswordVerified = 1
               -- G-52, BL-086: a first factor only.  See the notes.
               AND NOT EXISTS (SELECT 1 FROM auth.UserMfaFactor AS f
                                WHERE f.UserId = a.UserId AND f.IsDeleted = 0
                                  AND f.IsConfirmed = 1 AND f.ConfirmedUtc <= a.AttemptedUtc)
               AND DATEADD (SECOND
                          , COALESCE (TRY_CAST ((SELECT s.SettingValue
                                                   FROM config.ApplicationSetting AS s
                                                  WHERE s.SettingKey = N'Authn.MfaEnrolmentWindowSeconds'
                                                    AND s.IsDeleted  = 0) AS INT), 900)
                          , a.AttemptedUtc) > SYSUTCDATETIME ());
END;
GO


-- *** 6. auth.udfHasPermission ***
/***********************************************************************************************************************
ObjectName:   auth.udfHasPermission
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Returns 1 when the ACTIVE PROFILE -- SESSION_CONTEXT ('UserProfileId'), not a parameter -- holds @PermissionCode at
@TenantId, and 0 otherwise.  The first of the two permission questions in section 9.1, and the one
auth.uspDemandPermission asks before it raises E-50030.

A permission is held at @TenantId when a live auth.ProfilePermissionScope row for the profile names the permission and
its ScopeTenantId is @TenantId or any tenant ABOVE it.  Two extra rules apply:

    IsTenantScoped = 0    @TenantId is IGNORED.  The permission is not about a tenant.
    Platform family       auth.[User].IsPlatformAdmin must also be 1.  INV-09.

========================================================================================================================
Notes:

THE PROFILE IS NOT A PARAMETER, AND THAT IS THE POINT.  A signature of (@UserProfileId, @PermissionCode, @TenantId) would
let any caller ask the question about anybody, and the first caller in a hurry would pass the profile it was handed by
the application rather than the one the database authenticated.  Reading the session context means the answer is about
whoever auth.uspSetSessionContext said is asking, and a caller cannot get that wrong by passing the wrong argument.

The cost is that this returns 0 on a connection with no session context, which is the correct direction to fail: no
session, no authority.  A maintenance session (section 10.5) is not an exception -- BypassRowSecurity suppresses the RLS
predicates, deliberately NOT this function, because a DBA reading rows is a different act from a DBA exercising an
application permission they were never granted.  E-50030 is the right answer there.

@TenantId IS IGNORED WHEN THE PERMISSION IS NOT TENANT-SCOPED, RATHER THAN REQUIRED TO BE NULL.  The three Platform
permissions (appendix A) are the only unscoped ones shipped, and their callers are platform-wide operations that have no
tenant to pass.  Demanding NULL would make every such call site carry a special case; accepting and ignoring whatever
arrives means auth.uspDemandPermission can pass @TenantId through unconditionally.  The scope row still has to exist, so
this is not a free pass -- see 050_auth_permission.sql, "IsTenantScoped = 0 IS NOT A SYNONYM FOR 'GRANTED TO EVERYBODY'".

INV-09 IS A SECOND, INDEPENDENT CONDITION AND IT IS KEYED ON THE FAMILY, NOT ON IsTenantScoped.  A Platform permission
requires BOTH a scope row AND IsPlatformAdmin = 1, so removing the flag from a user revokes the platform authority
without touching a single grant -- which is what makes the flag worth having.  The test is
PermissionCategoryCode <> N'Platform' because CK_auth_Permission_PlatformIsNotTenantScoped only forces the implication
one way: every Platform permission is unscoped, but a project is free to add an unscoped permission in another family,
and that one must not silently acquire the platform-admin requirement.

The user's IsDeleted and IsActive are checked inside that test and nowhere else.  This function is not a liveness check
-- auth.uspSetSessionContext already refused a deleted or inactive user, and asking again on every permission test would
be three more seeks for an answer that cannot have changed inside a request.  IsPlatformAdmin is different: it is read
here as AUTHORITY, and authority carried by a row that has since been deactivated is not authority.

THERE IS NO ApplicationId FILTER, AND IT IS NOT AN OMISSION.  Permission codes repeat across applications -- 'Data.Read'
exists once per row in auth.Application -- so a lookup BY CODE alone would look ambiguous.  It is not, because the join
runs the other way: the PermissionId comes from the profile's own scope row, and BL-040 pinned that row to one
application through composite foreign keys (profile -> tenant -> application, role -> application, permission ->
application).  A profile therefore cannot hold a scope row naming another application's permission, so matching on code
cannot produce a false positive.  Filtering on SESSION_CONTEXT ('ApplicationId') as well would add a second way to fail
closed -- an unset key -- in exchange for nothing.

========================================================================================================================
Example Usage and Performance:

-- inside a procedure, after auth.uspSetSessionContext
if auth.udfHasPermission (N'Data.Update', @TenantId) = 0
    ;throw 50030, N'...', 1;

select auth.udfHasPermission (N'Platform.ManageApplications', null);

Section 9.1 costs it at two index seeks and that is what it does: a seek on
IX_auth_ProfilePermissionScope_Lookup for the profile, and a seek on the TenantClosure descendant index for the reach.
The auth.Permission join is a third seek on a table of 35 rows per application that is always in cache.  One statement,
no SCHEMABINDING, so Froid inlines it and calling it in a WHERE clause costs no more than writing the EXISTS out.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-050
Description:
Created.  Phase 3.  The first of the two permission questions of section 9.1.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER FUNCTION auth.udfHasPermission (@PermissionCode NVARCHAR (100), @TenantId INT)
RETURNS BIT
AS
BEGIN
    -- One statement, so Froid inlines it.  EXISTS rather than COUNT: eight of the sixteen baseline roles carry
    -- Data.Read (D-04), so a profile can hold the same permission at the same tenant by several routes, and the
    -- question is whether there is one.
    RETURN CASE
               WHEN EXISTS (SELECT 1
                              FROM auth.ProfilePermissionScope AS pps
                              JOIN auth.Permission             AS p
                                ON p.PermissionId = pps.PermissionId
                             WHERE pps.UserProfileId = TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT)
                               AND pps.IsDeleted     = 0
                               AND p.IsDeleted       = 0
                               AND p.PermissionCode  = @PermissionCode
                               -- The reach.  A grant held at a tenant reaches every tenant beneath it, and the closure
                               -- makes that a seek.  tc.IsDeleted = 0 is mandatory (BL-039): the closure deliberately
                               -- retains rows for soft-deleted tenants.
                               AND (p.IsTenantScoped = 0
                                    OR EXISTS (SELECT 1
                                                 FROM auth.TenantClosure AS tc
                                                WHERE tc.AncestorTenantId   = pps.ScopeTenantId
                                                  AND tc.DescendantTenantId = @TenantId
                                                  AND tc.IsDeleted          = 0))
                               -- INV-09, and only for the Platform family.
                               AND (p.PermissionCategoryCode <> N'Platform'
                                    OR EXISTS (SELECT 1
                                                 FROM auth.UserProfile AS up
                                                 JOIN auth.[User]      AS u
                                                   ON u.UserId = up.UserId
                                                WHERE up.UserProfileId  = pps.UserProfileId
                                                  AND up.IsDeleted      = 0
                                                  AND u.IsDeleted       = 0
                                                  AND u.IsActive        = 1
                                                  AND u.IsPlatformAdmin = 1)))
               THEN 1
               ELSE 0
           END;
END;
GO


-- *** 7. auth.tvfPermissionScope ***
/***********************************************************************************************************************
ObjectName:   auth.tvfPermissionScope
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

Returns one row per tenant at which the ACTIVE PROFILE holds @PermissionCode -- the expansion of its grants down the
tenant tree.  The second of the two permission questions in section 9.1: not "may I, here" but "where may I".

This is what the UI reads to populate a tenant picker (UI-04) and what a report reads to decide what it may aggregate.
An empty result is a real answer: the profile holds that permission nowhere.

========================================================================================================================
Notes:

IT RETURNS THE DESCENDANTS, NOT THE GRANTS.  auth.ProfilePermissionScope holds the tenant a grant was made AT, and
deliberately does not expand it over the subtree (D-07) -- a hundred-tenant subtree would otherwise multiply every row
by a hundred and every reparenting would rewrite thousands.  The expansion happens here, at read time, as one range scan
of auth.TenantClosure.  So a profile granted CONTRIBUTOR at a state agency gets every program under that agency back
from this function while auth.ProfilePermissionScope holds exactly one row.

SELECT DISTINCT IS LOAD-BEARING, for the same reason it is in auth.uspRebuildProfilePermissionScope.  Seven of the
sixteen baseline roles include Data.Read (D-04) and a profile commonly holds two of them at overlapping scopes, so the
un-DISTINCT result would list a tenant once per route.  A picker built from that shows duplicates; a report built from it
double-counts, which is worse because nothing looks wrong.

TenantId AND NOTHING ELSE.  The obvious additions -- the tenant's code and name for the picker, or the ScopeTenantId the
authority came from -- are all more useful than they look and all wrong here.  Names would bind this function to
auth.Tenant's column widths for callers that only want ids, and ScopeTenantId defeats the DISTINCT: a tenant reachable by
two grants comes back twice again.  A picker joins auth.Tenant, or better, auth.vwTenantHierarchy, which already carries
the path.

IT DOES NOT FILTER ON TENANT USABABILITY, AND THAT IS CONSISTENT RATHER THAN CARELESS.  A deactivated tenant, or one
under a deactivated ancestor, still appears here.  It has to: the RLS read predicate (section 10.2) does not test
usability either, so a function that filtered it out would disagree with the rows the engine actually returns, and the UI
would show an empty grid for a tenant it never offered.  A picker that wants to hide or grey out unusable tenants filters
with auth.udfIsTenantUsable, which is inlined and costs a seek.  Recorded as a UI gotcha rather than fixed here.

NON-TENANT-SCOPED PERMISSIONS RETURN NO ROWS.  IsTenantScoped = 1 is in the WHERE clause because "which tenants does the
profile hold Platform.ManageApplications on" has no answer -- the permission is not about tenants.  Asking this function
about one gets an empty set, and the correct question is auth.udfHasPermission (@PermissionCode, NULL).  Anything else
would mean inventing a tenant list for an authority that is not tenanted, and a caller would then filter by it.

========================================================================================================================
Example Usage and Performance:

select t.TenantId, t.TenantCode, t.TenantName
  from auth.tvfPermissionScope (N'Data.Read') as s
  join auth.Tenant             as t on t.TenantId = s.TenantId
 where t.IsDeleted = 0
 order by t.TenantName;

Section 9.1 costs it at one seek and one range scan, which is what it does: a seek on
IX_auth_ProfilePermissionScope_Lookup for the profile's rows, then a range scan of IX_auth_TenantClosure_Descendant per
scope tenant.  An inline table-valued function, so the optimizer folds it into the calling query rather than materializing
it.  No SCHEMABINDING -- this one is called by procedures and views, never by a security policy.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-051
Description:
Created.  Phase 3.  The second of the two permission questions of section 9.1.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER FUNCTION auth.tvfPermissionScope (@PermissionCode NVARCHAR (100))
RETURNS TABLE
AS
RETURN
    SELECT DISTINCT tc.DescendantTenantId AS TenantId
      FROM auth.ProfilePermissionScope AS pps
      JOIN auth.Permission             AS p
        ON p.PermissionId = pps.PermissionId
      JOIN auth.TenantClosure          AS tc
        ON tc.AncestorTenantId = pps.ScopeTenantId
     WHERE pps.UserProfileId = TRY_CAST (SESSION_CONTEXT (N'UserProfileId') AS INT)
       AND pps.IsDeleted     = 0
       AND p.IsDeleted       = 0
       AND p.PermissionCode  = @PermissionCode
       AND p.IsTenantScoped  = 1
       AND tc.IsDeleted      = 0;
GO


-- *** 8. auth.tvfTenantReadPredicate ***
/***********************************************************************************************************************
ObjectName:   auth.tvfTenantReadPredicate
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

The FILTER predicate of section 10.2.  Returns one row when the active profile holds Data.Read at @TenantId, or when the
session is a maintenance session, and no rows otherwise.  120_rls_policy.sql binds it as the FILTER PREDICATE of every
table registered in config.TenantScopedTable, where it governs SELECT, UPDATE and DELETE.

No rows means the engine silently drops the row.  That is what makes tenant isolation a property of the database rather
than a promise made by each procedure.

========================================================================================================================
Notes:

THIS FILE CREATES THE REFERENCE FORM.  120_rls_policy.sql RE-CREATES THE FAST FORM.  Two forms, same meaning, and the
difference is one join:

    here          ... JOIN auth.Permission AS p ... AND p.PermissionCode = N'Data.Read'
    in 120        ... AND pps.PermissionId IN (11, 46, 81, 116)     -- resolved at deploy time

Section 10.2 requires the second: a join to auth.Permission inside a predicate that runs once per row is a third seek for
a value that never changes between deployments.  So why does this file ship the first?

Because 100_auth_functions.sql has to be runnable on its own.  A predicate is bound to live policies; re-running this
file re-creates the function bodies underneath them, and whatever this file writes is in force from that moment until
120 runs again.  The three candidates were a form that denies everything (safe, but re-running one script would black out
a working database until somebody noticed the other one), a form that hard-codes ids (a lie in a file that cannot know
them), and this -- a slower predicate that means exactly the same thing.  A deployment that runs 100 and forgets 120 is
correct and a little slower.  That is the only one of the three failure modes anybody can live with.

The id list is an IN LIST AND NOT A SINGLE LITERAL, which is where section 10.2's published snippet is wrong for this
template.  'Data.Read' is not one permission: it is one permission PER APPLICATION, and the dev database has four live
applications, so the same predicate has to accept any of four ids.  A single PermissionId = 1 would isolate every
application but one.  BL-039.

pps.IsDeleted = 0 AND tc.IsDeleted = 0 ARE BOTH MANDATORY AND BOTH ARE MISSING FROM THE PUBLISHED SNIPPET.  BL-039 again.
Omitting the first honours revoked authority, because auth.uspRebuildProfilePermissionScope retires a scope row by soft
delete and leaves it in place.  Omitting the second is subtler and worse: IX_auth_TenantClosure_Descendant is FILTERED on
IsDeleted = 0, so a predicate without that term cannot use it and the reach becomes a scan -- on top of honouring the
ancestry of deleted tenants.  The filtered index is, in effect, the proof that the term belongs there.

TRY_CAST AND NOT CAST, on both keys.  A connection that has not called auth.uspSetSessionContext yields NULL from
SESSION_CONTEXT, NULL = anything is not true, and the predicate returns no rows -- the fail-closed direction.  CAST would
raise a conversion error from inside a security predicate, which surfaces as an unintelligible failure on an unrelated
query and sends the reader to the wrong file entirely.

THE BYPASS IS A SESSION-CONTEXT KEY AND NOT A ROLE TEST.  IS_ROLEMEMBER ('rlsBypassRole') = 1 in this predicate would
mean every DBA connection sees everything all the time and no record exists that it happened.  Requiring the key means
the bypass is an ACT: auth.uspBeginMaintenanceSession checks the role, writes a logs.AuthenticationEvent row BEFORE it
sets the key, and uspEndMaintenanceSession clears it.  Section 10.5.

========================================================================================================================
Example Usage and Performance:

-- as 120_rls_policy.sql binds it
add filter predicate auth.tvfTenantReadPredicate (TenantId) on dbo.CaseFile;

-- and to see what the current session would be allowed
select * from auth.tvfTenantReadPredicate (7);

Section 10.6: two seeks against two small tables, both of which stay in cache.  WITH SCHEMABINDING is mandatory for a
policy to bind it, and the consequence is that auth.ProfilePermissionScope, auth.TenantClosure and auth.Permission cannot
be altered while a policy references this -- section 21.3 gives the change procedure.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-061
Description:
Created.  Phase 4, in the reference form.  120_rls_policy.sql re-creates it with the permission ids resolved.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
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
GO


-- *** 9. auth.tvfTenantInsertPredicate ***
/***********************************************************************************************************************
ObjectName:   auth.tvfTenantInsertPredicate
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

The BLOCK AFTER INSERT predicate of section 10.3.  Returns one row when the tenant being written EQUALS the session's
ActingTenantId and the active profile holds Data.Insert there, or when the session is a maintenance session.  No rows
means the INSERT is refused -- error 33504, not a silent drop.

========================================================================================================================
Notes:

EQUALS, NOT COVERS, AND THAT ASYMMETRY IS P-06.  The read predicate asks whether the row's tenant is anywhere in the
profile's reach.  This one asks whether it IS the tenant the profile is currently wearing, and then, separately, whether
the profile holds Data.Insert over it.  Reading is scoped; writing is anchored.

That single difference is what turns the requirement's narrative into enforcement.  A user of a state agency who does
data entry intended for a county, while wearing the agency profile, creates AGENCY-tenanted rows -- the county cannot see
them, which the requirement calls a data entry error, and this design makes it one somebody notices instead of one that
silently succeeds.  And a user holding profiles in two counties cannot create a Baltimore City row while wearing the Anne
Arundel profile at all: the insert is blocked outright rather than mis-tenanted.

Without the equality test, an agency profile could insert directly into any county beneath it, and the tenant on a row
would record where the user had authority rather than who they were acting as.  Every attribution question afterwards --
who entered this, on whose behalf, under whose authority -- would be unanswerable from the data.

THE Data.Insert TEST IS STILL A REACH TEST, and it is not redundant.  ActingTenantId is only the tenant the session is
wearing; whether the profile may WRITE there is a separate fact, and the authority may have been granted higher up the
tree.  A profile wearing a program office and holding CONTRIBUTOR at the agency above it passes both halves.  A profile
wearing a program office and holding only READ_ONLY passes the first and fails the second.

WHY A BLOCK AND NOT A FILTER.  A FILTER predicate on an INSERT would let the row be written and then hide it from the
writer, which is the worst available outcome: the application reports success, the row exists, nobody can read it, and
the next INSERT of the same natural key fails on a unique constraint against a row the session cannot see.  A BLOCK
refuses.

IT IS NOT THE ONLY THING GUARDING THE TENANT ON A ROW.  TenantId is immutable after insert (E-50011, in each domain
table's AFTER UPDATE trigger) and DF constraints default it from the acting tenant.  This predicate is the line that
holds when a procedure passes a tenant explicitly.

========================================================================================================================
Example Usage and Performance:

-- as 120_rls_policy.sql binds it
add block predicate auth.tvfTenantInsertPredicate (TenantId) on dbo.CaseFile after insert;

One equality against a session key, then the same two seeks as the read predicate.  WITH SCHEMABINDING, as a policy
requires.  120_rls_policy.sql re-creates it with the Data.Insert ids resolved to literals -- see section 8's note on the
two forms.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-062
Description:
Created.  Phase 4, in the reference form.  The anchored half of P-06.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER FUNCTION auth.tvfTenantInsertPredicate (@TenantId INT)
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN
    SELECT 1 AS Allowed
     -- Both halves, and the order matters only to the reader: the equality is the rule that surprises people, so it
     -- comes first.
     WHERE (@TenantId = TRY_CAST (SESSION_CONTEXT (N'ActingTenantId') AS INT)
            AND EXISTS (SELECT 1
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
                           AND p.PermissionCode      = N'Data.Insert'))
        OR TRY_CAST (SESSION_CONTEXT (N'BypassRowSecurity') AS BIT) = 1;
GO


-- *** 10. auth.tvfTenantUpdatePredicate ***
/***********************************************************************************************************************
ObjectName:   auth.tvfTenantUpdatePredicate
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

The BLOCK BEFORE UPDATE and BLOCK AFTER UPDATE predicate of section 10.3.  Returns one row when the active profile holds
Data.Update at @TenantId, or when the session is a maintenance session.  120_rls_policy.sql binds the SAME function
twice on every registered table, and the two bindings ask about different tenants.

========================================================================================================================
Notes:

ONE FUNCTION, TWO BINDINGS, TWO QUESTIONS.  BEFORE UPDATE is handed the row's EXISTING tenant and AFTER UPDATE is handed
the tenant the row would END UP with.  The predicate itself does not know or care which it is looking at; the policy
supplies the tenant, and requiring Data.Update on both means a profile can neither edit a row it may not write nor move
one into a tenant it may not write.

Both bindings are needed and neither is sufficient.  BEFORE alone would let a profile push a row it may edit into a
tenant it has no authority over -- authority laundering, and it destroys the row.  AFTER alone would let a profile that
holds Data.Update only at tenant B rewrite a row belonging to tenant A as long as the result landed in B.

IT IS DELIBERATELY SYMMETRIC, UNLIKE THE INSERT PREDICATE.  Neither binding tests ActingTenantId, and the reason is that
an UPDATE is not an act of creation: a profile with authority over an agency that legitimately reaches several programs
edits their rows without changing hats, which is the ordinary case and the whole reason authority is scoped down a tree.
Anchoring an update to the acting tenant would make every cross-program correction a profile switch, and the pressure
that produced would be relieved by granting somebody a broader profile -- a worse outcome than allowing the edit.

WHAT THIS DOES NOT COVER, AND IT IS SECTION 10.4.  A soft delete is UPDATE ... SET IsDeleted = 1, so RLS cannot tell it
from any other edit, and a caller holding Data.Update can soft-delete a row it holds no Data.SoftDelete on as far as
these predicates are concerned.  Data.SoftDelete, Data.Restore, Data.Export, Data.Approve, Data.Reassign and Data.Execute
are enforced ONLY in procedures, by auth.uspDemandPermission.  That is a real limitation and G-05 records it so nobody
later grants ad-hoc table access believing RLS covers the difference.  It is acceptable only because P-11 means the
application has no direct-table path: EXECUTE on named procedures and nothing else.

Note also that the FILTER predicate (section 8) governs UPDATE and DELETE as well, so a row outside the profile's read
scope is invisible to an UPDATE statement before either of these bindings is consulted.  This one is about rows the
profile can see.

========================================================================================================================
Example Usage and Performance:

-- as 120_rls_policy.sql binds it, twice
add block predicate auth.tvfTenantUpdatePredicate (TenantId) on dbo.CaseFile before update;
add block predicate auth.tvfTenantUpdatePredicate (TenantId) on dbo.CaseFile after update;

The same two seeks as the read predicate, evaluated twice per updated row -- against two tables that fit in cache.
WITH SCHEMABINDING, as a policy requires.  120_rls_policy.sql re-creates it with the Data.Update ids resolved to
literals.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-063
Description:
Created.  Phase 4, in the reference form.  Bound twice, before and after, so a row can be neither edited nor moved
outside the profile's write authority.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER FUNCTION auth.tvfTenantUpdatePredicate (@TenantId INT)
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
                      AND p.PermissionCode      = N'Data.Update')
        OR TRY_CAST (SESSION_CONTEXT (N'BypassRowSecurity') AS BIT) = 1;
GO


-- *** 11. Descriptions ***
IF OBJECT_ID (N'util.uspSetObjectDescription', N'P') IS NOT NULL
BEGIN
    -- Built into a variable first, because an EXEC argument takes a constant or a variable and never an expression: a
    -- concatenation in the parameter position is a parse error (102, near '+'), exactly as it is for THROW.
    DECLARE @Description NVARCHAR (3750) =
        N'The single definition of tenant usability. Section 5.4: 1 only when the tenant and EVERY '
      + N'tenant above it are active and undeleted. Reads auth.TenantClosure, which deliberately '
      + N'contains soft-deleted tenants -- had the closure been built over live rows only, a deleted '
      + N'mid-tree tenant would vanish from its descendants'' ancestor set and this would return 1 for '
      + N'a program under a deleted administration, failing OPEN. Fails CLOSED in three ways: an '
      + N'absent tenant, an unbuilt closure and a NULL argument all return 0. One statement and no '
      + N'SCHEMABINDING, so Froid inlines it and it costs nothing in a predicate.';

    EXEC util.uspSetObjectDescription
          @SchemaName  = N'auth'
        , @ObjectType  = N'FUNCTION'
        , @ObjectName  = N'udfIsTenantUsable'
        , @Description = @Description;

    DECLARE @UserDescription NVARCHAR (3750) =
        N'The single definition of user usability, and the single copy of the effective-lockout '
      + N'expression: 1 only when the row exists, IsDeleted = 0, IsActive = 1, and the user is not '
      + N'effectively locked -- IsLockedOut = 1 AND (LockoutEndUtc IS NULL OR LockoutEndUtc > now). '
      + N'A second copy of that negation is where a NULL LockoutEndUtc (an administrative lock held '
      + N'until somebody clears it) gets admitted by accident. Lapsed locks are NOT tidied up on a '
      + N'schedule: the user is usable again when the clock passes the end, and auth.uspCompleteLogin '
      + N'clears the flag lazily. Fails CLOSED on an absent user, a deleted user and NULL. Does NOT '
      + N'consult IsPlatformAdmin -- usability and authority are different questions, and INV-09 is '
      + N'about the second. One statement, no SCHEMABINDING, so Froid inlines it.';

    EXEC util.uspSetObjectDescription
          @SchemaName  = N'auth'
        , @ObjectType  = N'FUNCTION'
        , @ObjectName  = N'udfIsUserUsable'
        , @Description = @UserDescription;

    DECLARE @PolicyDescription NVARCHAR (3750) =
        N'Returns the TenantAuthenticationPolicyId of the NEAREST live policy at or above @TenantId, '
      + N'or NULL when no tenant at or above it has one -- section 7.2. An identifier and not the '
      + N'policy itself, because udf means scalar; the caller reads the row it names. NULL is a real '
      + N'answer meaning "no policy row applies", NOT "deny": most tenants have no policy row, and '
      + N'the caller falls back to the Authn.* defaults in config.ApplicationSetting. A synthetic '
      + N'default returned here would point at no row, and a caller that forgot to check would read '
      + N'zero columns as false and disable local sign-in for the estate. NEAREST, not first: '
      + N'ORDER BY Depth with TOP (1), so a parent override beats a grandparent. Reads the closure, '
      + N'which keeps soft-deleted mid-tree tenants in the ancestor set (BL-020) -- deleting one '
      + N'tenant row must not silently relax the sign-in rules beneath it. The POLICY row itself '
      + N'must be live. One statement, no SCHEMABINDING, so Froid inlines it.';

    EXEC util.uspSetObjectDescription
          @SchemaName  = N'auth'
        , @ObjectType  = N'FUNCTION'
        , @ObjectName  = N'udfResolveAuthPolicy'
        , @Description = @PolicyDescription;

    DECLARE @SessionDescription NVARCHAR (3750) =
        N'Returns the UserId holding the LIVE session whose token hash is the argument, or NULL -- '
      + N'section 6.4, task T-041. The single definition of session liveness for callers that need to '
      + N'know WHO is asking: EndedUtc IS NULL AND IsDeleted = 0 AND AbsoluteExpiryUtc > now AND '
      + N'IdleExpiryUtc > now. All four in one place because 112_auth_mfa_procedures.sql asks the '
      + N'question three times, and every omitted condition fails OPEN -- a stale token enrolling a '
      + N'second factor on somebody else''s account. Takes the HASH, never the token: the application '
      + N'hashes, this resolves, so two callers cannot disagree about the encoding. Does NOT slide '
      + N'LastSeenUtc or IdleExpiryUtc -- a scalar function cannot write, so resolving a session '
      + N'repeatedly does not keep it alive; auth.uspTouchSession owns that decision. Does NOT consult '
      + N'auth.udfIsUserUsable: "whose session is this" is a fact and "may they act" is a policy, and '
      + N'the callers ask both so the refusal names the real reason (E-50115) rather than E-50114. '
      + N'Does NOT require MfaSatisfied -- the enrolment flow exists to get a factor onto an account '
      + N'that has none. Fails CLOSED on an unknown hash, on NULL and on any expired, ended or deleted '
      + N'session. One statement, no SCHEMABINDING, so Froid inlines it.';

    EXEC util.uspSetObjectDescription
          @SchemaName  = N'auth'
        , @ObjectType  = N'FUNCTION'
        , @ObjectName  = N'udfResolveSessionUser'
        , @Description = @SessionDescription;

    DECLARE @EnrolmentDescription NVARCHAR (3750) =
        N'Returns the UserId that a JUST-REFUSED sign-in exchange may act as, for the sole purpose of '
      + N'enrolling a FIRST second factor, or NULL -- section 6.4, task T-041. The bootstrap half of '
      + N'"who is asking": udfResolveSessionUser answers it for somebody who has a session, this '
      + N'answers it for somebody whose policy will not let them get one. Qualifies only when the row '
      + N'is live, Outcome = ''Failure'', FailureReason = ''MfaRequired'', PasswordVerified = 1, and '
      + N'AttemptedUtc is within Authn.MfaEnrolmentWindowSeconds of now. What makes it safe is that '
      + N'the DATABASE wrote the proof: uspCompleteLogin set PasswordVerified = 1 in that exchange, '
      + N'the column is immutable and a terminal Outcome is final (D-14), so this reads a record of a '
      + N'past assertion rather than trusting a new one. It returns an IDENTITY, NOT A PERMISSION: '
      + N'every caller in 112_auth_mfa_procedures.sql also refuses when a CONFIRMED factor already '
      + N'exists (E-50119), so the window can never replace a working authenticator. Includes the '
      + N'E-50107 bypass refusal, which writes the same reason and leaves the caller in the same '
      + N'position. Setting the window to 0 disables the route with no code change. Fails CLOSED on an '
      + N'unknown id, a pending or successful exchange, any other failure reason, a lapsed window and '
      + N'NULL. One statement, no SCHEMABINDING, so Froid inlines it.';

    EXEC util.uspSetObjectDescription
          @SchemaName  = N'auth'
        , @ObjectType  = N'FUNCTION'
        , @ObjectName  = N'udfResolveEnrolmentActor'
        , @Description = @EnrolmentDescription;

    DECLARE @HasPermissionDescription NVARCHAR (3750) =
        N'Returns 1 when the ACTIVE PROFILE -- SESSION_CONTEXT (''UserProfileId''), not a parameter -- '
      + N'holds @PermissionCode at @TenantId. The first of the two permission questions of section '
      + N'9.1, and what auth.uspDemandPermission asks before raising E-50030. The profile is not a '
      + N'parameter on purpose: a signature taking one would let a caller pass the profile the '
      + N'APPLICATION handed it rather than the one the database authenticated. Held means a live '
      + N'auth.ProfilePermissionScope row names the permission at @TenantId or at any tenant ABOVE it '
      + N'(the reach is a seek on auth.TenantClosure, and tc.IsDeleted = 0 is mandatory -- the closure '
      + N'retains soft-deleted tenants). Two extra rules: IsTenantScoped = 0 means @TenantId is '
      + N'IGNORED rather than required to be NULL, and the Platform family additionally requires '
      + N'auth.User.IsPlatformAdmin = 1 (INV-09) -- keyed on the family, not on IsTenantScoped, so a '
      + N'project''s own unscoped permission does not silently inherit the platform-admin test. No '
      + N'ApplicationId filter is needed: the PermissionId comes from the profile''s own scope row, '
      + N'which BL-040 pinned to one application, so matching by code cannot cross applications. '
      + N'BypassRowSecurity does NOT affect it -- reading rows and exercising a permission are '
      + N'different acts. Fails CLOSED with no session context. One statement, so Froid inlines it.';

    EXEC util.uspSetObjectDescription
          @SchemaName  = N'auth'
        , @ObjectType  = N'FUNCTION'
        , @ObjectName  = N'udfHasPermission'
        , @Description = @HasPermissionDescription;

    DECLARE @ScopeDescription NVARCHAR (3750) =
        N'Returns one row per tenant at which the ACTIVE PROFILE holds @PermissionCode -- the second '
      + N'permission question of section 9.1, "where may I" rather than "may I here". What the UI '
      + N'reads for a tenant picker (UI-04) and a report reads to decide what it may aggregate. It '
      + N'returns the DESCENDANTS, not the grants: auth.ProfilePermissionScope stores the tenant a '
      + N'grant was made AT and deliberately does not expand it (D-07), so the expansion happens here '
      + N'as one range scan of auth.TenantClosure. SELECT DISTINCT is load-bearing -- seven of the '
      + N'sixteen baseline roles carry Data.Read (D-04), so a tenant is commonly reachable by more '
      + N'than one route, and duplicates would make a picker look broken and a report double-count. '
      + N'TenantId and nothing else: names would bind it to auth.Tenant''s columns and ScopeTenantId '
      + N'would defeat the DISTINCT, so a caller joins auth.Tenant or auth.vwTenantHierarchy. It does '
      + N'NOT filter on tenant usability, because the RLS read predicate does not either and the two '
      + N'must agree about which rows exist; a picker that wants to hide unusable tenants filters with '
      + N'auth.udfIsTenantUsable. A non-tenant-scoped permission returns NO rows -- ask '
      + N'auth.udfHasPermission (@PermissionCode, NULL) instead. Inline, so it folds into the caller.';

    EXEC util.uspSetObjectDescription
          @SchemaName  = N'auth'
        , @ObjectType  = N'FUNCTION'
        , @ObjectName  = N'tvfPermissionScope'
        , @Description = @ScopeDescription;

    DECLARE @ReadPredicateDescription NVARCHAR (3750) =
        N'The RLS FILTER predicate of section 10.2, bound by 120_rls_policy.sql to every table '
      + N'registered in config.TenantScopedTable, where it governs SELECT, UPDATE and DELETE. Returns '
      + N'a row when the active profile holds Data.Read at @TenantId, or when the session is a '
      + N'maintenance session. No rows means the engine silently drops the row, which is what makes '
      + N'tenant isolation a property of the database rather than a promise made by each procedure. '
      + N'THIS FILE CREATES THE REFERENCE FORM, which joins auth.Permission and tests PermissionCode; '
      + N'120_rls_policy.sql re-creates it with the ids resolved to literals, as section 10.2 requires '
      + N'(a join per row for a value that never changes). The reference form exists so that '
      + N're-running 100 alone leaves a working database that is merely slower, rather than one that '
      + N'denies everything until 120 runs again. The id list is an IN list and not a single literal, '
      + N'because Data.Read exists once PER APPLICATION -- BL-039, which also owns the two IsDeleted = '
      + N'0 terms the published snippet omits (the second is what lets the filtered closure index be '
      + N'used at all). TRY_CAST not CAST: no session context must mean no rows, not a conversion '
      + N'error raised from inside a security predicate. The bypass is a session-context key and not '
      + N'a role test, so using it is an ACT that leaves a logs.AuthenticationEvent row -- section '
      + N'10.5. WITH SCHEMABINDING is mandatory; section 21.3 gives the column-change procedure.';

    EXEC util.uspSetObjectDescription
          @SchemaName  = N'auth'
        , @ObjectType  = N'FUNCTION'
        , @ObjectName  = N'tvfTenantReadPredicate'
        , @Description = @ReadPredicateDescription;

    DECLARE @InsertPredicateDescription NVARCHAR (3750) =
        N'The RLS BLOCK AFTER INSERT predicate of section 10.3. Returns a row when the tenant being '
      + N'written EQUALS the session''s ActingTenantId AND the active profile holds Data.Insert there, '
      + N'or when the session is a maintenance session; no rows refuses the INSERT with error 33504. '
      + N'EQUALS, not COVERS, and that asymmetry is P-06: reading is scoped, writing is anchored. It '
      + N'is what turns the requirement''s narrative into enforcement -- an agency user doing data '
      + N'entry intended for a county, while wearing the agency profile, creates AGENCY rows the '
      + N'county cannot see (a data entry error somebody notices, rather than one that silently '
      + N'succeeds), and a user with profiles in two counties cannot create a Baltimore City row while '
      + N'wearing Anne Arundel at all. Without the equality the TenantId on a row would record where '
      + N'the user had authority rather than who they were acting as, and every later attribution '
      + N'question would be unanswerable. The Data.Insert reach test is separate and not redundant: '
      + N'the authority may be granted higher up the tree than the tenant being worn. A BLOCK and not '
      + N'a FILTER, because a filtered INSERT would succeed, vanish, and then collide with itself on a '
      + N'unique constraint against a row the session cannot see. Reference form here, literals in '
      + N'120_rls_policy.sql. WITH SCHEMABINDING.';

    EXEC util.uspSetObjectDescription
          @SchemaName  = N'auth'
        , @ObjectType  = N'FUNCTION'
        , @ObjectName  = N'tvfTenantInsertPredicate'
        , @Description = @InsertPredicateDescription;

    DECLARE @UpdatePredicateDescription NVARCHAR (3750) =
        N'The RLS BLOCK BEFORE UPDATE and BLOCK AFTER UPDATE predicate of section 10.3. Returns a row '
      + N'when the active profile holds Data.Update at @TenantId, or when the session is a maintenance '
      + N'session. ONE function, TWO bindings, TWO questions: BEFORE is handed the row''s EXISTING '
      + N'tenant and AFTER the tenant it would END UP with. Both are needed and neither is sufficient '
      + N'-- BEFORE alone would let a profile push a row it may edit into a tenant it has no authority '
      + N'over, and AFTER alone would let a profile holding Data.Update only at B rewrite an A row as '
      + N'long as the result landed in B. Deliberately symmetric, unlike the insert predicate: '
      + N'neither binding tests ActingTenantId, because an UPDATE is not an act of creation and '
      + N'anchoring one would turn every cross-program correction into a profile switch -- pressure '
      + N'that gets relieved by granting somebody a broader profile, which is worse. What it CANNOT '
      + N'cover is section 10.4: a soft delete is UPDATE SET IsDeleted = 1 and RLS sees rows, not '
      + N'intent, so Data.SoftDelete, Data.Restore, Data.Export, Data.Approve, Data.Reassign and '
      + N'Data.Execute are enforced ONLY in procedures (G-05). Acceptable only because P-11 leaves the '
      + N'application no direct-table path. Reference form here, literals in 120. WITH SCHEMABINDING.';

    EXEC util.uspSetObjectDescription
          @SchemaName  = N'auth'
        , @ObjectType  = N'FUNCTION'
        , @ObjectName  = N'tvfTenantUpdatePredicate'
        , @Description = @UpdatePredicateDescription;
END
ELSE
BEGIN
    PRINT N'util.uspSetObjectDescription is absent, so no descriptions were set. Run templates/extended-properties.sql '
        + N'and then re-run this file to add them.';
END
GO


-- *** 12. Grants ***
-- Nothing here, and that is INV-11.  applicationRole holds no access to SCHEMA::auth.  These functions are reached by
-- ownership chaining from the procedures that call them, which is the only path the application has into tenancy or
-- identity.  170_permissions.sql states the absence as a schema-level DENY so the catalog shows a decision -- G-19.
--
-- The three RLS predicates need no grant either, and it is worth stating rather than leaving to the rule above: a
-- predicate bound by CREATE SECURITY POLICY is evaluated by the ENGINE and not by the caller, so SELECT permission on the
-- function is never checked.  Granting it would add nothing except a way for a caller to run the predicate directly and
-- enumerate which tenants it may read -- a question auth.tvfPermissionScope already answers, through a procedure, for the
-- profile that is actually asking.


-- *** 13. Closing report ***
DECLARE @Report TABLE
(
    RowNo    INT IDENTITY (1, 1) PRIMARY KEY,
    Severity INT             NOT NULL,
    Status   VARCHAR (10)    NOT NULL,
    Item     NVARCHAR (200)  NOT NULL,
    Detail   NVARCHAR (1000)     NULL
);

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (N'auth.udfIsTenantUsable', N'FN') IS NULL THEN 1 ELSE 4 END
     , CASE WHEN OBJECT_ID (N'auth.udfIsTenantUsable', N'FN') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Function auth.udfIsTenantUsable'
     , N'Section 5.4. The single definition of tenant usability, read by the session procedures, the tenant procedures '
     + N'and the row-level security predicate.';

-- Fail-closed, asserted rather than asserted-in-a-comment.  A tenant id that cannot exist must return 0; if this ever
-- returns 1, every sign-in check downstream is decorative.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN auth.udfIsTenantUsable (-1) = 0 THEN 4 ELSE 1 END
     , CASE WHEN auth.udfIsTenantUsable (-1) = 0 THEN 'OK'  ELSE 'VIOLATED' END
     , N'auth.udfIsTenantUsable fails closed on an absent tenant'
     , N'Called with -1, which cannot be a TenantId. Anything but 0 means the function has stopped requiring the '
     + N'depth-0 self row, and every usability check in the database has quietly become permissive.';

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN auth.udfIsTenantUsable (NULL) = 0 THEN 4 ELSE 1 END
     , CASE WHEN auth.udfIsTenantUsable (NULL) = 0 THEN 'OK'  ELSE 'VIOLATED' END
     , N'auth.udfIsTenantUsable fails closed on NULL'
     , N'A caller comparing the result to 0 must get its refusal rather than an unevaluated branch.';

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (N'auth.udfIsUserUsable', N'FN') IS NULL THEN 1 ELSE 4 END
     , CASE WHEN OBJECT_ID (N'auth.udfIsUserUsable', N'FN') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Function auth.udfIsUserUsable'
     , N'Section 6.3. The single copy of the effective-lockout expression, promised by 040_auth_userprofile.sql.';

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN auth.udfIsUserUsable (-1) = 0 AND auth.udfIsUserUsable (NULL) = 0 THEN 4 ELSE 1 END
     , CASE WHEN auth.udfIsUserUsable (-1) = 0 AND auth.udfIsUserUsable (NULL) = 0 THEN 'OK' ELSE 'VIOLATED' END
     , N'auth.udfIsUserUsable fails closed on an absent user and on NULL'
     , N'Called with -1, which cannot be a UserId, and with NULL. Anything but 0 from either means the function has '
     + N'stopped requiring the row to exist, and every usability check on the sign-in path has quietly become '
     + N'permissive -- which is a failure nobody notices, because what happens is that a sign-in succeeds.';

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (N'auth.udfResolveAuthPolicy', N'FN') IS NULL THEN 1 ELSE 4 END
     , CASE WHEN OBJECT_ID (N'auth.udfResolveAuthPolicy', N'FN') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Function auth.udfResolveAuthPolicy'
     , N'Section 7.2, task T-032. Returns the identifier of the nearest live policy at or above a tenant, or NULL.';

-- NULL here means "no policy applies", which is the shipped state of a deployment that has configured none.  The check
-- is that an impossible tenant produces NULL rather than an identifier: a fabricated default would point at no row.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN auth.udfResolveAuthPolicy (-1) IS NULL THEN 4 ELSE 1 END
     , CASE WHEN auth.udfResolveAuthPolicy (-1) IS NULL THEN 'OK' ELSE 'VIOLATED' END
     , N'auth.udfResolveAuthPolicy returns NULL for a tenant that cannot exist'
     , N'Called with -1. An identifier here would be an identifier pointing at no row, and a caller that did not check '
     + N'would read zero columns and treat them as false -- disabling local password sign-in for the whole estate.';

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (N'auth.udfResolveSessionUser', N'FN') IS NULL THEN 1 ELSE 4 END
     , CASE WHEN OBJECT_ID (N'auth.udfResolveSessionUser', N'FN') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Function auth.udfResolveSessionUser'
     , N'Section 6.4, task T-041. The single definition of session liveness for callers that need the user id -- all '
     + N'four conditions in one place, because 112_auth_mfa_procedures.sql asks the question three times.';

-- The only fail-closed check here that matters: a hash nobody issued must produce NULL.  A UserId from an unrecognised
-- token would mean every procedure in 112 accepts a forged actor, and the symptom is a successful enrolment.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN auth.udfResolveSessionUser (0x00) IS NULL
             AND auth.udfResolveSessionUser (NULL) IS NULL THEN 4 ELSE 1 END
     , CASE WHEN auth.udfResolveSessionUser (0x00) IS NULL
             AND auth.udfResolveSessionUser (NULL) IS NULL THEN 'OK' ELSE 'VIOLATED' END
     , N'auth.udfResolveSessionUser fails closed on an unissued hash and on NULL'
     , N'Called with 0x00, which is not 32 bytes and so cannot be a stored hash, and with NULL. A UserId from either '
     + N'means the liveness test has stopped requiring the row to match, and every actor check in '
     + N'112_auth_mfa_procedures.sql accepts a forged session -- a failure whose symptom is that enrolment WORKS.';

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (N'auth.udfResolveEnrolmentActor', N'FN') IS NULL THEN 1 ELSE 4 END
     , CASE WHEN OBJECT_ID (N'auth.udfResolveEnrolmentActor', N'FN') IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Function auth.udfResolveEnrolmentActor'
     , N'Section 6.4, task T-041. The bootstrap half of "who is asking": which just-refused exchange may enrol a first '
     + N'factor. Without it, a user under a policy requiring MFA and holding no factor can never sign in.';

-- Fail-closed, and the stakes here are higher than for the others: this function is the ONLY thing that lets a caller
-- act without a session, so a version that accepted an id it should not have is a route into any account.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN auth.udfResolveEnrolmentActor (-1) IS NULL
             AND auth.udfResolveEnrolmentActor (NULL) IS NULL THEN 4 ELSE 1 END
     , CASE WHEN auth.udfResolveEnrolmentActor (-1) IS NULL
             AND auth.udfResolveEnrolmentActor (NULL) IS NULL THEN 'OK' ELSE 'VIOLATED' END
     , N'auth.udfResolveEnrolmentActor fails closed on an impossible exchange and on NULL'
     , N'Called with -1, which cannot be a LoginAttemptId, and with NULL. A UserId from either means the one route in '
     + N'this database that acts without a live session has stopped checking which exchange it was handed.';

-- Whether the bootstrap route is even enabled here.  A deployment that set the window to 0 has made first-factor
-- enrolment an administrative act, which is a legitimate choice and one a later reader should not have to infer.
INSERT @Report (Severity, Status, Item, Detail)
SELECT 3, 'INFO', N'Bootstrap enrolment window'
     , CASE WHEN COALESCE (TRY_CAST ((SELECT s.SettingValue FROM config.ApplicationSetting AS s
                                       WHERE s.SettingKey = N'Authn.MfaEnrolmentWindowSeconds'
                                         AND s.IsDeleted  = 0) AS INT), 900) = 0
            THEN N'Authn.MfaEnrolmentWindowSeconds is 0, so auth.udfResolveEnrolmentActor returns NULL for every '
               + N'exchange and first-factor enrolment is an administrative act in this deployment. A legitimate '
               + N'choice -- recorded here so it is not mistaken for a defect.'
            ELSE N'Authn.MfaEnrolmentWindowSeconds is '
               + CAST (COALESCE (TRY_CAST ((SELECT s.SettingValue FROM config.ApplicationSetting AS s
                                             WHERE s.SettingKey = N'Authn.MfaEnrolmentWindowSeconds'
                                               AND s.IsDeleted  = 0) AS INT), 900) AS NVARCHAR (10))
               + N' second(s). A sign-in refused with E-50109 or E-50107 may enrol a FIRST factor for that long, '
               + N'and only for an account that held no confirmed factor when it was refused.'
       END;

INSERT @Report (Severity, Status, Item, Detail)
SELECT 3, 'INFO', N'Policy rows available to resolve'
     , CASE WHEN COUNT (*) = 0
            THEN N'None. Expected, and not a problem: most tenants have no policy row and a small deployment may have '
               + N'none at all. auth.udfResolveAuthPolicy returns NULL and the sign-in path falls back to the Authn.* '
               + N'defaults in config.ApplicationSetting -- section 7.2.'
            ELSE CAST (COUNT (*) AS NVARCHAR (10)) + N' live policy row(s). Each applies to its own tenant and to '
               + N'every tenant beneath it that has no nearer policy.'
       END
  FROM auth.TenantAuthenticationPolicy
 WHERE IsDeleted = 0;

-- The five authorization functions, added in Phases 3 and 4.  Listed from a VALUES set rather than one INSERT each,
-- because there is nothing to say about any of them individually that the Detail column does not say.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN OBJECT_ID (x.FunctionName) IS NULL THEN 1 ELSE 4 END
     , CASE WHEN OBJECT_ID (x.FunctionName) IS NULL THEN 'MISSING' ELSE 'OK' END
     , N'Function ' + x.FunctionName
     , x.Detail
  FROM (VALUES (N'auth.udfHasPermission'
              , N'Section 9.1, task T-050. "Does the active profile hold permission P at tenant T?" -- what '
              + N'auth.uspDemandPermission asks before it raises E-50030.')
             , (N'auth.tvfPermissionScope'
              , N'Section 9.1, task T-051. "Which tenants does the active profile hold permission P on?" -- the tenant '
              + N'picker and the report aggregation.')
             , (N'auth.tvfTenantReadPredicate'
              , N'Section 10.2, task T-061. The FILTER predicate: SELECT, UPDATE and DELETE. In the reference form '
              + N'that tests PermissionCode; 120_rls_policy.sql re-creates it with the ids as literals.')
             , (N'auth.tvfTenantInsertPredicate'
              , N'Section 10.3, task T-062. BLOCK AFTER INSERT, and the anchored half of P-06 -- the row''s tenant '
              + N'must EQUAL ActingTenantId, not merely be within reach.')
             , (N'auth.tvfTenantUpdatePredicate'
              , N'Section 10.3, task T-063. Bound twice, BEFORE and AFTER UPDATE, so a row can be neither edited nor '
              + N'moved outside the profile''s write authority.')) AS x (FunctionName, Detail);

-- WITH SCHEMABINDING, asserted from the catalog rather than trusted to the text above.  A security policy will not bind
-- a function that is not schema-bound, so without this the failure arrives in 120_rls_policy.sql as error 33507 about a
-- function this file believes it created correctly.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 3 THEN 4 ELSE 1 END
     , CASE WHEN COUNT (*) = 3 THEN 'OK' ELSE 'VIOLATED' END
     , N'The three RLS predicates are WITH SCHEMABINDING'
     , CAST (COUNT (*) AS NVARCHAR (10)) + N' of 3 are schema-bound. A policy binds nothing else, so anything but 3 '
     + N'means 120_rls_policy.sql will fail -- and until it does, the tables it should have protected are not.'
  FROM sys.sql_modules AS m
 WHERE m.is_schema_bound = 1
   AND m.object_id IN (OBJECT_ID (N'auth.tvfTenantReadPredicate')
                     , OBJECT_ID (N'auth.tvfTenantInsertPredicate')
                     , OBJECT_ID (N'auth.tvfTenantUpdatePredicate'));

-- Fail-closed, and this is the one assertion in this file whose failure would be a data breach rather than an outage.
-- sqlcmd sets no session context, so every one of these four calls is being made by nobody at all.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN auth.udfHasPermission (N'Data.Read', 1) = 0
             AND auth.udfHasPermission (N'Data.Read', NULL) = 0
             AND NOT EXISTS (SELECT 1 FROM auth.tvfPermissionScope (N'Data.Read'))
             AND NOT EXISTS (SELECT 1 FROM auth.tvfTenantReadPredicate (1))
             AND NOT EXISTS (SELECT 1 FROM auth.tvfTenantInsertPredicate (1))
             AND NOT EXISTS (SELECT 1 FROM auth.tvfTenantUpdatePredicate (1)) THEN 4 ELSE 1 END
     , CASE WHEN auth.udfHasPermission (N'Data.Read', 1) = 0
             AND auth.udfHasPermission (N'Data.Read', NULL) = 0
             AND NOT EXISTS (SELECT 1 FROM auth.tvfPermissionScope (N'Data.Read'))
             AND NOT EXISTS (SELECT 1 FROM auth.tvfTenantReadPredicate (1))
             AND NOT EXISTS (SELECT 1 FROM auth.tvfTenantInsertPredicate (1))
             AND NOT EXISTS (SELECT 1 FROM auth.tvfTenantUpdatePredicate (1)) THEN 'OK' ELSE 'VIOLATED' END
     , N'All five authorization functions fail closed with no session context'
     , N'This connection has called no auth.uspSetSessionContext, so SESSION_CONTEXT (''UserProfileId'') is NULL and '
     + N'every one of these must refuse. A 1 from auth.udfHasPermission, or a row from any of the three predicates, '
     + N'means an unauthenticated connection has authority over tenant 1 -- and for the FILTER predicate it means every '
     + N'protected table is readable by anybody who can open a connection.';

-- Whether the catalogue the five functions read is populated yet.  On a first install this file runs BEFORE
-- 115_seed_reference_data.sql, so an empty answer here is expected and is not a defect: the predicates deny everything
-- until the permissions exist, which is the right direction to be wrong in.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 0 THEN 4 ELSE 3 END
     , CASE WHEN COUNT (*) = 0 THEN 'OK' ELSE 'PENDING' END
     , N'Data.Read, Data.Insert and Data.Update exist for every live application'
     , CASE WHEN COUNT (*) = 0
            THEN N'All three permissions the RLS predicates test are present for every live application, so '
               + N'120_rls_policy.sql has ids to resolve.'
            ELSE CAST (COUNT (*) AS NVARCHAR (10)) + N' (application, permission) pair(s) are missing. Expected on a '
               + N'first install -- 115_seed_reference_data.sql seeds the 35 permissions of appendix A for every live '
               + N'application and runs after this file. Until then the three predicates match nothing and every '
               + N'protected table denies every row, which is the safe direction. 120_rls_policy.sql asserts the same '
               + N'thing and refuses to build a policy on an empty catalogue (T-065).'
       END
  FROM auth.Application AS a
 CROSS JOIN (VALUES (N'Data.Read'), (N'Data.Insert'), (N'Data.Update')) AS c (PermissionCode)
 WHERE a.IsDeleted = 0
   AND NOT EXISTS (SELECT 1
                     FROM auth.Permission AS p
                    WHERE p.ApplicationId   = a.ApplicationId
                      AND p.PermissionCode  = c.PermissionCode
                      AND p.IsDeleted       = 0);

-- The two forms, stated in the transcript so that a reader who profiles the predicate and finds three seeks where
-- section 10.2 promised two knows which script to run rather than which function to rewrite.
INSERT @Report (Severity, Status, Item, Detail)
SELECT 3, 'INFO', N'The three predicates are in the REFERENCE form'
     , N'They join auth.Permission and test PermissionCode, which is one seek per row more than section 10.2 allows. '
     + N'120_rls_policy.sql re-creates them with the permission ids as literals and asserts the list still matches '
     + N'(T-065). Re-running THIS file alone reverts them to the slower form, which is correct and slower -- never '
     + N'permissive -- and re-running 120 restores the fast form. That trade is why this file does not ship a '
     + N'deny-everything placeholder: a deployment that forgot one script would otherwise black out a live database.';

IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
    PRINT N'auth functions: PROBLEMS found. Read the report below before running the next script.';
ELSE
    PRINT N'auth functions: no problems found. A PENDING row means 115_seed_reference_data.sql has not run yet.';

PRINT N'';

SELECT Severity, Status, Item, Detail
  FROM @Report
 ORDER BY Severity, RowNo;
GO
