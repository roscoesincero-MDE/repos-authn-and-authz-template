/***********************************************************************************************************************
Script:         095_auth_views.sql
Purpose:        The reporting views over the authentication and authorization model.  Five of them: auth.vwTenantHierarchy
                (the tenant tree with a readable path), auth.vwUserProfile (who has which hat, where),
                auth.vwProfilePermission (where each authority was granted), auth.vwRoleDefinition (what a role actually
                means) and logs.vwAuthorizationTrail (grants and refusals as one time-ordered stream).
Target:         SQL Server 2022.
Run as:         db_owner in the target database.
Run with:       sqlcmd -S <server> -d <database> -v DbName=<database> -I -C -b -i database/095_auth_views.sql
Idempotent:     Yes.  CREATE OR ALTER throughout.  Creates nothing that holds state.
Depends on:     database/030_auth_tenant.sql, database/040_auth_userprofile.sql, database/055_auth_role.sql,
                database/065_auth_effective_permission.sql, database/085_logs_auth_tables.sql,
                templates/extended-properties.sql.
Implements:     T-020, T-088.  DES-AUTH-001 sections 5.1, 15.4 and 15.6.  See docs/10-database-authn-authz-design.md.
To retarget:    Pass it per run:  sqlcmd -d <database> -v DbName=<database>.  There is no in-file default.

THIS FILE WAS PARTIAL FOR FIVE PHASES, AND THE RECORD OF THAT IS WORTH KEEPING
------------------------------------------------------------------------------
Phase 1 installed one view of the five.  The other four read auth.UserProfile, auth.Role, auth.RolePermission,
auth.ProfilePermissionScope and the two logs trail tables, and a view binds every name in its body at CREATE time -- so
writing them in Phase 1 would have failed at deploy rather than at first call, and the file reported them as PENDING in
its own closing report until the tables arrived.  T-088 completes it.

ONE OF THE FIVE IS IN THE logs SCHEMA, and it is here rather than in 085_logs_auth_tables.sql for the same reason the
other four were late: logs.vwAuthorizationTrail resolves ids against auth.Role, auth.[User] and auth.vwTenantHierarchy,
and putting it beside its tables would make 085 depend on objects that install after it.  The TABLES stay in 085.  Only
this presentation of them is here.

READ THESE VIEWS FOR "WHERE DID THE AUTHORITY COME FROM", NEVER FOR "MAY THIS PROFILE ACT HERE"
----------------------------------------------------------------------------------------------
auth.vwProfilePermission lists GRANT POINTS.  A row means the profile holds that permission at that tenant AND therefore
at every tenant beneath it, and the downward expansion is applied by auth.udfHasPermission through auth.TenantClosure
rather than stored anywhere.  An access-review screen that filters this view on a tenant id will under-report, badly and
silently.  The question "may this profile act on tenant X" has exactly two correct answers in this database:
auth.udfHasPermission and auth.tvfPermissionScope.  §10.6 is the measurement that says relying on them is affordable.

THE ONE THING THIS VIEW DELIBERATELY DOES NOT DO
------------------------------------------------
It does not report usability, and the omission is an install-order consequence rather than a preference.  The Scripts
sheet installs this file at position 20 and database/100_auth_functions.sql -- which defines auth.udfIsTenantUsable --
at position 21.  CREATE VIEW resolves every name in its body immediately, so a reference to that function here would
fail with 208 on a first deployment and the whole build would stop.

Duplicating the usability logic in the view was considered and rejected: two copies of a security-relevant rule drift,
and the copy that drifts is the one nobody is testing.  So the function stays the single definition and
auth.uspGetTenantTree -- a PROCEDURE, which gets deferred name resolution and therefore does not care about install
order -- selects it as a column over this view.  That is the shape the UI binds to.

A useful by-product: this view computes Depth by walking the parent edges, which is an INDEPENDENT calculation from the
one auth.uspRebuildTenantClosure stores.  database/_tests/030_tenancy_closure_reparent.sql compares the two, which is a
cross-check no single object could give.  It holds only while no tenant is soft-deleted, because this view filters them
out and the closure deliberately does not.
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

-- ONE ASSERTION PER TABLE AND THE MESSAGE NAMES THE FILE, because a view binds every name at CREATE time and the error
-- SQL Server would otherwise give -- 208, "invalid object name" -- names the object but not the script that makes it.
DECLARE @Parents TABLE
(
    RowNo      INT IDENTITY (1, 1) PRIMARY KEY,
    ObjectName NVARCHAR (300) NOT NULL,
    SourceFile NVARCHAR (100) NOT NULL
);

INSERT @Parents (ObjectName, SourceFile)
VALUES (N'auth.Tenant',                  N'database/030_auth_tenant.sql')
     , (N'auth.TenantType',              N'database/030_auth_tenant.sql')
     , (N'auth.User',                    N'database/035_auth_user.sql')
     , (N'auth.UserProfile',             N'database/040_auth_userprofile.sql')
     , (N'auth.Role',                    N'database/055_auth_role.sql')
     , (N'auth.RolePermission',          N'database/055_auth_role.sql')
     , (N'auth.Permission',              N'database/050_auth_permission.sql')
     , (N'auth.ProfilePermissionScope',  N'database/065_auth_effective_permission.sql')
     , (N'logs.AuthorizationChange',     N'database/085_logs_auth_tables.sql')
     , (N'logs.AuthorizationDenial',     N'database/085_logs_auth_tables.sql');

IF EXISTS (SELECT 1 FROM @Parents AS p WHERE OBJECT_ID (p.ObjectName, N'U') IS NULL)
BEGIN
    -- Built into a variable because THROW takes a constant or a variable, never an expression.
    DECLARE @Msg NVARCHAR (2000) =
        N'This file cannot be installed yet. Missing: '
      + (SELECT STRING_AGG (p.ObjectName + N' (' + p.SourceFile + N')', N'; ')
           FROM @Parents AS p
          WHERE OBJECT_ID (p.ObjectName, N'U') IS NULL)
      + N'. A view resolves every name in its body at CREATE time, so this file cannot be installed ahead of the tables '
      + N'it reads. Nothing has been changed.';

    THROW 50000, @Msg, 1;
END
GO


-- *** 1. auth.vwTenantHierarchy ***
/***********************************************************************************************************************
ObjectName:   auth.vwTenantHierarchy
Author:       rsincero
CreateDate:   2026-09-19
========================================================================================================================
Description:

The tenant tree, one row per live tenant, with the path from its root written out, the depth below that root, and the
tenant type label.  What an administration screen binds to when it draws the tree, and what a report groups by when it
needs "which agency is this under" without a recursive query of its own.

Live tenants only: the recursion filters IsDeleted = 0 at both ends.

========================================================================================================================
Notes:

RECURSION DEPTH.  A view cannot carry OPTION (MAXRECURSION), so this runs at the server default of 100 levels.  That is
not a limitation worth working around -- a tenant tree 100 deep is a data-entry accident, and the error it produces (530,
"the statement terminated, maximum recursion 100 has been exhausted") is a far better outcome than silently returning
part of a hierarchy to a security screen.  auth.uspRebuildTenantClosure states the same limit explicitly for the same
reason.

TenantPath IS NVARCHAR (4000) AND THE CONCATENATION IS CAST TO IT EXPLICITLY.  In a recursive CTE the anchor member fixes
the column's type, so without the CAST the anchor's NVARCHAR (50) would be the width of every level and each step would
silently truncate.  This is the classic recursive-CTE defect and it does not raise an error; it returns short strings.

THE PATH USES ' / ' AS ITS SEPARATOR, not '\' or '.', because a tenant code may not contain a space (see
CK_auth_Tenant_TenantCode), which makes the separator unambiguous when a screen splits the path back apart.

WHY NOT STRING_AGG OVER THE CLOSURE.  It would need the closure to be built -- this view works on a database where
auth.uspRebuildTenantClosure has never run -- and it would need a per-level ORDER BY the closure does not store.  The
Depth this view computes is deliberately independent of the closure's; see the file header.

SOFT-DELETED TENANTS DISAPPEAR WITH THEIR SUBTREES.  A deleted tenant is excluded, and because the recursion walks
parent edges, so is everything beneath it -- the children are not re-rooted or orphaned into a second tree.  That is the
right answer for a display and the wrong one for a scope test, which is why auth.udfIsTenantUsable reads the closure
instead.

========================================================================================================================
Example Usage and Performance:

select TenantCode, TenantPath, Depth from auth.vwTenantHierarchy where ApplicationId = 2 order by TenantPath;

Seeks IX_auth_Tenant_Parent once per level.  Intended for administration screens and reports, not for the request path:
an authorization decision reads auth.TenantClosure, which is a seek.

========================================================================================================================
Modification History:

Date:		2026-09-19
Author:		rsincero
Ticket:		T-020
Description:
Created.  Phase 1.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER VIEW auth.vwTenantHierarchy
AS
WITH tree AS
(
    -- Anchor: the roots.  One per application, which UX_auth_Tenant_ApplicationRoot guarantees -- so this member
    -- returns exactly as many rows as there are live applications with a tree.
    SELECT t.TenantId
         , t.ApplicationId
         , t.TenantCode
         , t.TenantName
         , t.TenantTypeId
         , t.TenantTypeCode
         , t.ParentTenantId
         , t.IsActive
         , RootTenantId   = t.TenantId
         , Depth          = 0
         , TenantPath     = CAST (t.TenantCode AS NVARCHAR (4000))
         -- Carried down the recursion so a screen can grey out a node whose ancestor is inactive without asking a
         -- second question.  NOT a usability verdict: auth.udfIsTenantUsable is the one definition of that, and it
         -- reads auth.Tenant through the closure so soft deletes count too.
         , AnyAncestorInactive = CAST (0 AS BIT)
      FROM auth.Tenant AS t
     WHERE t.ParentTenantId IS NULL
       AND t.IsDeleted = 0

    UNION ALL

    -- Recursive member: children of what we have, one level per iteration.
    SELECT c.TenantId
         , c.ApplicationId
         , c.TenantCode
         , c.TenantName
         , c.TenantTypeId
         , c.TenantTypeCode
         , c.ParentTenantId
         , c.IsActive
         , RootTenantId   = p.RootTenantId
         , Depth          = p.Depth + 1
         -- The CAST on the anchor is what allows this to grow; see the notes.
         , TenantPath     = CAST (p.TenantPath + N' / ' + c.TenantCode AS NVARCHAR (4000))
         , AnyAncestorInactive = CASE WHEN p.IsActive = 0 OR p.AnyAncestorInactive = 1
                                     THEN CAST (1 AS BIT) ELSE CAST (0 AS BIT) END
      FROM tree        AS p
      JOIN auth.Tenant AS c ON c.ParentTenantId = p.TenantId
     WHERE c.IsDeleted = 0
)
SELECT tr.TenantId
     , tr.ApplicationId
     , a.ApplicationCode
     , tr.TenantCode
     , tr.TenantName
     , tr.TenantTypeId
     , tr.TenantTypeCode
     -- The label, from the type table, so a screen does not have to translate the code itself.
     , TenantTypeName = tt.TenantTypeName
     , tr.ParentTenantId
     , tr.RootTenantId
     , tr.Depth
     , tr.TenantPath
     , tr.IsActive
     , tr.AnyAncestorInactive
  FROM tree                AS tr
  JOIN auth.Application    AS a  ON a.ApplicationId = tr.ApplicationId
  -- INNER JOIN on the type is safe and deliberate: FK_auth_Tenant_TenantType makes the row exist, and a soft-deleted
  -- type would still be found -- the type table's filtered unique index governs new codes, not old references.
  JOIN auth.TenantType     AS tt ON tt.TenantTypeId = tr.TenantTypeId;
GO


-- *** 2. auth.vwUserProfile ***
/***********************************************************************************************************************
ObjectName:   auth.vwUserProfile
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

One row per live user profile with the user, the tenant and the tenant's path already resolved.  The dimension an
administration grid binds to and a report joins to, so that neither has to know that a profile's application comes from
its tenant rather than from itself.

========================================================================================================================
Notes:

IT COMPUTES NO USABILITY VERDICT, for the reason the file header gives at length: auth.udfIsUserUsable and
auth.udfIsTenantUsable are defined in 100_auth_functions.sql, which installs AFTER this file, and a view resolves every
name at CREATE time.  TenantIsActive and AnyAncestorInactive are carried through from auth.vwTenantHierarchy so a grid can
grey a row out, and they are NOT the verdict -- they ignore soft deletes, which the hierarchy view has already excluded.
A screen that needs the verdict selects the function over this view; a procedure may, because it gets deferred
resolution.

ApplicationId AND ApplicationCode COME FROM THE TENANT.  auth.UserProfile has no ApplicationId column -- deliberately,
because a profile belongs to a tenant and a tenant belongs to exactly one application, so storing it twice would create a
pair that can disagree.  This view is where that indirection stops being the caller's problem.

NO ROLE OR PERMISSION COUNTS.  Adding them would put a correlated aggregate on every row of what is otherwise a seek-
friendly dimension, and the two callers that want counts -- auth.uspListProfilesForUser and auth.uspListAssignableRoles --
already compute their own, scoped to the actor.  A count here would be unscoped, which is worse than absent.

========================================================================================================================
Example Usage and Performance:

select UserName, ProfileName, TenantPath from auth.vwUserProfile where ApplicationCode = N'TEMPLATE' order by UserName;

Two seeks plus the hierarchy view's recursion.  A reporting view, not a request-path object.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-088
Description:
Created.  Phase 6.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER VIEW auth.vwUserProfile
AS
SELECT up.UserProfileId
     , up.UserId
     , u.UserName
     , u.DisplayName
     , u.Email
     , u.IsActive           AS UserIsActive
     , u.IsLockedOut
     , u.LockoutEndUtc
     , u.MustChangePassword
     , u.IsPlatformAdmin
     , up.ProfileName
     , up.IsDefault
     , up.IsActive          AS ProfileIsActive
     , up.TenantId
     , th.TenantCode
     , th.TenantName
     , th.TenantTypeCode
     , th.TenantTypeName
     , th.TenantPath
     , th.Depth             AS TenantDepth
     , th.RootTenantId
     , th.IsActive          AS TenantIsActive
     , th.AnyAncestorInactive
     -- From the tenant, never from the profile: see the notes.
     , th.ApplicationId
     , th.ApplicationCode
     -- The string auth.uspSetSessionContext puts in SESSION_CONTEXT('AppUser') and every audit column therefore carries.
     -- Reproduced here so a report can join a row's auditCreatedBy back to the profile that wrote it without the caller
     -- re-deriving a format it would eventually get wrong.
     , CONCAT (u.UserName, N'@', th.TenantCode, N'#', up.UserProfileId) AS AppUser
     , up.auditCreatedDateUtc  AS ProfileCreatedUtc
     , up.auditModifiedDateUtc AS ProfileModifiedUtc
  FROM auth.UserProfile         AS up
 INNER JOIN auth.[User]         AS u  ON u.UserId    = up.UserId
                                     AND u.IsDeleted = 0
 -- INNER, not LEFT: a profile whose tenant this view cannot see is a profile in a soft-deleted tenant or beneath one,
 -- and it must not appear on an administration grid as a row with an empty tenant. The hierarchy view drops deleted
 -- tenants WITH their subtrees, so the omission is inherited rather than restated here.
 INNER JOIN auth.vwTenantHierarchy AS th ON th.TenantId = up.TenantId
 WHERE up.IsDeleted = 0;
GO


-- *** 3. auth.vwProfilePermission ***
/***********************************************************************************************************************
ObjectName:   auth.vwProfilePermission
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

One row per GRANT POINT in auth.ProfilePermissionScope, with the profile, the permission and the scope tenant resolved to
names.  "Who has what, and where was it given" for an access review.  Section 15.6.

========================================================================================================================
Notes:

THESE ARE GRANT POINTS, NOT THE EFFECTIVE SET, and confusing the two is the mistake this view is most likely to invite.
A row here says the profile holds the permission AT ScopeTenantId AND THEREFORE AT EVERY TENANT BENEATH IT -- that
downward expansion lives in auth.TenantClosure and is applied by auth.udfHasPermission, not stored.  So an access review
that wants "can this profile act on tenant X" must ask auth.udfHasPermission or auth.tvfPermissionScope; this view
answers the different and equally necessary question "where did the authority come from".  Materialising the expansion
here would multiply a few thousand grants into millions of rows to say nothing new.

THE DESIGN CALLS THE TABLE auth.EffectiveGrant AND THE DATABASE CALLS IT auth.ProfilePermissionScope.  The built name
won, because "effective" is exactly the word that would make a reader expect the expanded set; the deviation is recorded
in the build log.

THE ROLE THAT CAUSED THE GRANT IS NOT A COLUMN, because by the time a row reaches auth.ProfilePermissionScope it may have
been caused by several -- the table is a set, rebuilt by auth.uspRebuildProfilePermissionScope, and two roles granting
the same permission at the same tenant produce ONE row. auth.vwRoleDefinition and auth.UserProfileRole answer "through
which role"; logs.vwAuthorizationTrail answers "who granted it and when".

========================================================================================================================
Example Usage and Performance:

select UserName, PermissionCode, ScopeTenantPath from auth.vwProfilePermission where UserProfileId = 42;

Seeks the scope table's primary key.  A reporting view.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-088
Description:
Created.  Phase 6.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER VIEW auth.vwProfilePermission
AS
SELECT pps.UserProfileId
     , up.UserId
     , u.UserName
     , u.DisplayName
     , up.ProfileName
     , up.TenantId          AS ProfileTenantId
     , pt.TenantCode        AS ProfileTenantCode
     , pt.TenantPath        AS ProfileTenantPath
     , pps.PermissionId
     , p.PermissionCode
     , p.PermissionName
     , p.PermissionCategoryCode
     , p.IsTenantScoped
     , pps.ScopeTenantId
     , st.TenantCode        AS ScopeTenantCode
     , st.TenantName        AS ScopeTenantName
     , st.TenantPath        AS ScopeTenantPath
     , st.Depth             AS ScopeTenantDepth
     -- 0 = granted at the profile's own tenant; positive = granted above it and inherited downward. The single most
     -- useful number on an access-review screen, because a grant several levels up is the one nobody remembers making.
     , st.Depth - pt.Depth  AS ScopeLevelsAboveProfile
     , p.ApplicationId
     , pps.auditCreatedBy   AS ScopeRebuiltBy
     , pps.auditModifiedDateUtc AS ScopeRebuiltUtc
  FROM auth.ProfilePermissionScope AS pps
 INNER JOIN auth.UserProfile       AS up ON up.UserProfileId = pps.UserProfileId
                                       AND up.IsDeleted      = 0
 INNER JOIN auth.[User]            AS u  ON u.UserId         = up.UserId
                                       AND u.IsDeleted       = 0
 INNER JOIN auth.Permission        AS p  ON p.PermissionId   = pps.PermissionId
                                       AND p.IsDeleted       = 0
 INNER JOIN auth.vwTenantHierarchy AS pt ON pt.TenantId      = up.TenantId
 INNER JOIN auth.vwTenantHierarchy AS st ON st.TenantId      = pps.ScopeTenantId
 WHERE pps.IsDeleted = 0;
GO


-- *** 4. auth.vwRoleDefinition ***
/***********************************************************************************************************************
ObjectName:   auth.vwRoleDefinition
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

What each role actually means: one row per role-permission pair, with the owning tenant and the permission category
resolved.  Section 15.6.  The artefact an auditor reads instead of a role name.

========================================================================================================================
Notes:

A ROLE WITH NO PERMISSIONS APPEARS, with NULLs in the permission columns, and that is the whole reason the join is LEFT.
auth.uspDefineRole creates every role EMPTY and auth.uspSetRolePermissions fills it, so an empty role is a normal
intermediate state -- and an empty role that stayed empty is exactly the finding an access review is looking for.  An
INNER JOIN would hide it, which is the failure mode of every role report that only lists what exists.

PermissionCount AND IsEmpty ARE REPEATED ON EVERY ROW OF A ROLE, which is redundant by design: a grid grouping by role
needs the count in the group header, and a window function costs nothing here while a second view would have to be kept
in step with this one.

SYSTEM ROLES ARE NOT FILTERED OUT.  IsSystemRole is a column so a report can separate the 19 shipped roles from the
ones a project defined, and the shipped ones are the ones most worth checking -- trg_au_updt_Role freezes their code,
their flag and their existence but explicitly permits their NAME and DESCRIPTION to be edited, so a system role's label
on a screen is not evidence of what it grants.  This view is.

THE OWNER TENANT IS WHERE THE ROLE MAY BE ASSIGNED FROM, not where it applies.  auth.uspAssignRoleToProfile requires the
scope tenant to be at or beneath OwnerTenantId (INV-05 clause 3), so OwnerTenantPath read together with
OwnerIsRootOwned is the answer to "how widely can this role be handed out".

========================================================================================================================
Example Usage and Performance:

select RoleCode, PermissionCode from auth.vwRoleDefinition where OwnerTenantCode = N'ROOT' order by RoleCode;
select distinct RoleCode from auth.vwRoleDefinition where IsEmpty = 1;

Scans auth.Role, seeks auth.RolePermission per role.  A reporting view.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-088
Description:
Created.  Phase 6.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER VIEW auth.vwRoleDefinition
AS
SELECT r.RoleId
     , r.RoleCode
     , r.RoleName
     , r.RoleDescription
     , r.IsAssignable
     , r.IsSystemRole
     , r.ApplicationId
     , th.ApplicationCode
     , r.OwnerTenantId
     , th.TenantCode        AS OwnerTenantCode
     , th.TenantName        AS OwnerTenantName
     , th.TenantPath        AS OwnerTenantPath
     , th.Depth             AS OwnerTenantDepth
     -- Depth 0 is a root tenant, and a role owned there can be assigned anywhere in the application.
     , CAST (CASE WHEN th.Depth = 0 THEN 1 ELSE 0 END AS BIT) AS OwnerIsRootOwned
     , rp.RolePermissionId
     , rp.PermissionId
     , p.PermissionCode
     , p.PermissionName
     , p.PermissionCategoryCode
     , p.IsTenantScoped
     -- Counted over the role, so the number is right in a group header without a second query. COUNT (rp.PermissionId)
     -- and not COUNT (*): on an empty role the LEFT JOIN yields one row with a NULL permission, and COUNT (*) would
     -- report that role as holding one permission.
     , COUNT (rp.PermissionId) OVER (PARTITION BY r.RoleId) AS PermissionCount
     , CAST (CASE WHEN rp.PermissionId IS NULL THEN 1 ELSE 0 END AS BIT) AS IsEmpty
     , r.auditCreatedBy     AS RoleCreatedBy
     , r.auditCreatedDateUtc AS RoleCreatedUtc
  FROM auth.Role                    AS r
 -- LEFT: an empty role is a normal state and the most interesting row an access review can find. See the notes.
  LEFT JOIN auth.RolePermission     AS rp ON rp.RoleId       = r.RoleId
                                         AND rp.IsDeleted    = 0
  LEFT JOIN auth.Permission         AS p  ON p.PermissionId  = rp.PermissionId
                                         AND p.IsDeleted     = 0
 -- INNER on the owner: a role whose owning tenant has been soft-deleted is unassignable and reporting it with a blank
 -- owner would invite somebody to try.
 INNER JOIN auth.vwTenantHierarchy  AS th ON th.TenantId     = r.OwnerTenantId
 WHERE r.IsDeleted = 0;
GO


-- *** 5. logs.vwAuthorizationTrail ***
/***********************************************************************************************************************
ObjectName:   logs.vwAuthorizationTrail
Author:       rsincero
CreateDate:   2026-09-20
========================================================================================================================
Description:

logs.AuthorizationChange and logs.AuthorizationDenial as ONE time-ordered stream, with users, roles and tenants resolved
to names.  "What happened to authorization in this system, in order."  Sections 15.4 and 15.6.

========================================================================================================================
Notes:

WHY A logs VIEW LIVES IN 095_auth_views.sql.  Because it resolves ids against auth.[User], auth.Role and
auth.vwTenantHierarchy, and a view binds every name at CREATE time.  Putting it in 085_logs_auth_tables.sql would make
that file depend on auth.Role and on the hierarchy view, inverting an install order that currently runs one way only.
The trail's TABLES stay in 085 where the rest of the logs schema lives; only this presentation of them is here.

THE TWO STREAMS ANSWER DIFFERENT QUESTIONS AND ARE STILL WORTH INTERLEAVING.  A denial says somebody tried and could not;
a change says somebody's authority moved.  Read separately, each is half a story -- a burst of denials followed by a
grant is the single most important pattern an access review can see, and it is invisible in either table alone.

EventKind IS THE DISCRIMINATOR AND EventId IS ONLY UNIQUE WITHIN IT.  Both tables have their own IDENTITY, so
(EventKind, EventId) is the key and EventId alone is not.  A screen paging this view must order by OccurredUtc and then
by EventKind and EventId, which is why the notes say so rather than leaving a paging bug to be found later.

Subject IS A DELIBERATELY LOSSY SINGLE COLUMN.  A change names a role and a target profile; a denial names a permission
code and an object.  Squeezing both into one nullable set of columns would produce a view nobody could read, so the
specific columns are kept AND a short human-readable Subject is provided for a merged timeline.  DetailJson is carried
through untouched for anything the columns drop.

IsDeleted = 0 IS FILTERED EVEN THOUGH NOTHING SHOULD EVER SOFT-DELETE A TRAIL ROW.  The filter is not a feature; it is
consistency with every other read in this database, so that a future 950_verify_deployment.sql check for "a view that
forgot the soft-delete predicate" does not have to carve out an exception.  If a row IS ever deleted here, that is a
finding, and it is found by querying the table -- not by this view quietly showing it.

NO GRANTS, like everything else in this file.  A denial trail readable by the application login is a map of what the
application is not allowed to do.  logs.uspReportAuthorizationTrail is the granted path.

========================================================================================================================
Example Usage and Performance:

select top 200 * from logs.vwAuthorizationTrail order by OccurredUtc desc, EventKind, EventId desc;
select * from logs.vwAuthorizationTrail where TenantCode = N'ROOT' and OccurredUtc >= dateadd (day, -7, sysutcdatetime ());

Two scans and a concatenation.  Sized for an access review, not for a dashboard refreshing every minute.

========================================================================================================================
Modification History:

Date:		2026-09-20
Author:		rsincero
Ticket:		T-088
Description:
Created.  Phase 6.

-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/
CREATE OR ALTER VIEW logs.vwAuthorizationTrail
AS
SELECT EventKind              = CAST (N'Change' AS NVARCHAR (10))
     , EventId                = ac.AuthorizationChangeId
     , ac.OccurredUtc
     , EventName              = CAST (ac.ChangeType AS NVARCHAR (40))
     , ac.ActorUserProfileId
     -- LEFT all the way down the actor chain: the bootstrap writes ActorUserProfileId = NULL because there is no profile
     -- yet, and that NULL is the point of the row rather than a defect in it (900_bootstrap_first_admin.sql).
     , ActorUserName          = au.UserName
     , ActorProfileName       = ap.ProfileName
     , ac.ActorAuthorityTenantId
     , ActorAuthorityTenantCode = aat.TenantCode
     , ac.TargetUserId
     , ac.TargetUserProfileId
     , TargetUserName         = tu.UserName
     , TargetProfileName      = tp.ProfileName
     , ac.RoleId
     , RoleCode               = r.RoleCode
     , RoleName               = r.RoleName
     , TenantId               = ac.ScopeTenantId
     , TenantCode             = st.TenantCode
     , TenantPath             = st.TenantPath
     , PermissionCode         = CAST (NULL AS NVARCHAR (200))
     , ObjectName             = CAST (NULL AS NVARCHAR (256))
     -- The lossy merged label. Built from what a change row actually has, in the order a reader scans it.
     , Subject                = CONCAT (ac.ChangeType
                                      , COALESCE (N' role=' + r.RoleCode, N'')
                                      , COALESCE (N' target=' + tu.UserName, N'')
                                      , COALESCE (N' at=' + st.TenantCode, N''))
     , ac.DetailJson
     , RecordedBy             = ac.auditCreatedBy
  FROM logs.AuthorizationChange     AS ac
  LEFT JOIN auth.UserProfile        AS ap  ON ap.UserProfileId = ac.ActorUserProfileId
  LEFT JOIN auth.[User]             AS au  ON au.UserId        = ap.UserId
  LEFT JOIN auth.UserProfile        AS tp  ON tp.UserProfileId = ac.TargetUserProfileId
  -- The target user is read from the change row's own TargetUserId when it has one, and from the target profile
  -- otherwise: a ProfileCreated row names the user before any profile id can be reported, and a RoleGranted row names
  -- the profile. COALESCE in the join predicate keeps one LEFT JOIN where two would need a second alias and a
  -- second nullable column nobody would know which of to read.
  LEFT JOIN auth.[User]             AS tu  ON tu.UserId        = COALESCE (ac.TargetUserId, tp.UserId)
  LEFT JOIN auth.Role               AS r   ON r.RoleId         = ac.RoleId
  LEFT JOIN auth.vwTenantHierarchy  AS st  ON st.TenantId      = ac.ScopeTenantId
  LEFT JOIN auth.vwTenantHierarchy  AS aat ON aat.TenantId     = ac.ActorAuthorityTenantId
 WHERE ac.IsDeleted = 0

UNION ALL

SELECT EventKind              = CAST (N'Denial' AS NVARCHAR (10))
     , EventId                = ad.AuthorizationDenialId
     , ad.OccurredUtc
     , EventName              = CAST (N'PermissionDenied' AS NVARCHAR (40))
     -- A denial records the profile that was refused, and that profile IS the actor: it is the one who tried. There is
     -- no separate target, which is the structural difference between the two halves of this view.
     , ActorUserProfileId     = ad.UserProfileId
     , ActorUserName          = du.UserName
     , ActorProfileName       = dp.ProfileName
     , ActorAuthorityTenantId = CAST (NULL AS INT)
     , ActorAuthorityTenantCode = CAST (NULL AS NVARCHAR (50))
     , TargetUserId           = CAST (NULL AS INT)
     , TargetUserProfileId    = CAST (NULL AS INT)
     , TargetUserName         = CAST (NULL AS NVARCHAR (256))
     , TargetProfileName      = CAST (NULL AS NVARCHAR (256))
     , RoleId                 = CAST (NULL AS INT)
     , RoleCode               = CAST (NULL AS NVARCHAR (200))
     , RoleName               = CAST (NULL AS NVARCHAR (400))
     , TenantId               = ad.TenantId
     , TenantCode             = dt.TenantCode
     , TenantPath             = dt.TenantPath
     , ad.PermissionCode
     , ad.ObjectName
     , Subject                = CONCAT (N'PermissionDenied ', ad.PermissionCode
                                      , COALESCE (N' at=' + dt.TenantCode, N'')
                                      , COALESCE (N' in=' + ad.ObjectName, N''))
     , ad.DetailJson
     , RecordedBy             = ad.auditCreatedBy
  FROM logs.AuthorizationDenial     AS ad
  -- LEFT, and this is the important one: auth.uspDemandPermission records a denial with a NULL UserProfileId when there
  -- was no session context at all, and that NULL is the finding. An INNER JOIN here would hide exactly the rows an
  -- access review most needs -- somebody reached a guarded procedure without authenticating.
  LEFT JOIN auth.UserProfile        AS dp ON dp.UserProfileId = ad.UserProfileId
  LEFT JOIN auth.[User]             AS du ON du.UserId        = dp.UserId
  -- LEFT on the tenant too: a denial's TenantId is sanitized rather than validated, so it may name a tenant that never
  -- existed. Dropping the row would lose the attempt.
  LEFT JOIN auth.vwTenantHierarchy  AS dt ON dt.TenantId      = ad.TenantId
 WHERE ad.IsDeleted = 0;
GO


-- *** 6. Descriptions ***
IF OBJECT_ID (N'util.uspSetObjectDescription', N'P') IS NOT NULL
BEGIN
    DECLARE @Descriptions TABLE
    (
        RowNo       INT IDENTITY (1, 1) PRIMARY KEY,
        SchemaName  SYSNAME         NOT NULL,
        ObjectType  SYSNAME         NOT NULL,
        ObjectName  SYSNAME         NOT NULL,
        ColumnName  SYSNAME             NULL,
        Description NVARCHAR (3750) NOT NULL
    );

    INSERT @Descriptions (SchemaName, ObjectType, ObjectName, ColumnName, Description)
    VALUES
      (N'auth', N'VIEW', N'vwTenantHierarchy', NULL
     , N'The tenant tree with a readable path from the root, a depth, and the type label. Live tenants only. Section '
     + N'15.6. Deliberately carries NO usability column: auth.udfIsTenantUsable is defined in '
     + N'100_auth_functions.sql, which installs AFTER this file, and a view resolves its references at CREATE time. '
     + N'auth.uspGetTenantTree selects the function over this view instead, because a procedure gets deferred '
     + N'resolution. Duplicating the usability rule here was rejected: two copies of a security rule drift, and the '
     + N'copy that drifts is the one nobody tests.')
    , (N'auth', N'VIEW', N'vwTenantHierarchy', N'RootTenantId'
     , N'The root of this tenant''s tree, carried down the recursion. Equal to TenantId on a root. Answers "which '
     + N'organization is this under" without a recursive query of the caller''s own.')
    , (N'auth', N'VIEW', N'vwTenantHierarchy', N'Depth'
     , N'Levels below the root; 0 on a root. Computed here by walking parent edges, which is INDEPENDENT of the Depth '
     + N'auth.uspRebuildTenantClosure stores -- _tests/030_tenancy_closure_reparent.sql compares the two, which is a '
     + N'cross-check no single object could give. The two agree only while no tenant is soft-deleted, because this view '
     + N'excludes them and the closure deliberately does not.')
    , (N'auth', N'VIEW', N'vwTenantHierarchy', N'TenantPath'
     , N'The tenant codes from the root down, joined with a space-slash-space. NVARCHAR (4000) and CAST explicitly in '
     + N'both members of the recursive CTE: the anchor fixes the column type, so without the CAST every level would be '
     + N'NVARCHAR (50) wide and each step would truncate silently rather than raise. The separator contains spaces '
     + N'because CK_auth_Tenant_TenantCode forbids them in a code, which makes splitting the path back apart '
     + N'unambiguous.')
    , (N'auth', N'VIEW', N'vwTenantHierarchy', N'AnyAncestorInactive'
     , N'1 = some tenant above this one has IsActive = 0, so a screen can grey the node out without asking a second '
     + N'question. NOT a usability verdict and must not be used as one: it ignores soft deletes, because the view '
     + N'excludes deleted tenants and their whole subtrees. auth.udfIsTenantUsable is the single definition of '
     + N'usability and reads the closure, where deleted tenants are still present.')
    , (N'auth', N'VIEW', N'vwUserProfile', NULL
     , N'One row per live user profile with the user, the tenant and the tenant''s path resolved. Section 15.6. '
     + N'ApplicationId and ApplicationCode come FROM THE TENANT -- auth.UserProfile has no ApplicationId column, '
     + N'deliberately, because storing it twice would create a pair that can disagree. Carries TenantIsActive and '
     + N'AnyAncestorInactive so a grid can grey a row out, but computes NO usability verdict: auth.udfIsUserUsable and '
     + N'auth.udfIsTenantUsable are defined in 100_auth_functions.sql, which installs after this file, and a view binds '
     + N'every name at CREATE time. No role or permission counts, because a count here would be unscoped. The AppUser '
     + N'column reproduces the SESSION_CONTEXT(''AppUser'') format so a report can join an audit column back to the '
     + N'profile that wrote it.')
    , (N'auth', N'VIEW', N'vwProfilePermission', NULL
     , N'One row per GRANT POINT in auth.ProfilePermissionScope with profile, permission and scope tenant resolved. '
     + N'Section 15.6. THESE ARE GRANT POINTS, NOT THE EFFECTIVE SET: a row says the profile holds the permission at '
     + N'ScopeTenantId and therefore at every tenant beneath it, and that downward expansion lives in '
     + N'auth.TenantClosure and is applied by auth.udfHasPermission rather than stored. Ask auth.udfHasPermission for '
     + N'"can this profile act on tenant X"; ask this view for "where did the authority come from". '
     + N'ScopeLevelsAboveProfile is 0 for a grant at the profile''s own tenant and positive for one inherited from '
     + N'above -- the grant nobody remembers making. The role that caused the row is not a column, because the table is '
     + N'a rebuilt SET and two roles granting the same permission at the same tenant produce one row. The design calls '
     + N'the table auth.EffectiveGrant; the built name won, because "effective" is the word that would make a reader '
     + N'expect the expanded set.')
    , (N'auth', N'VIEW', N'vwRoleDefinition', NULL
     , N'One row per role-permission pair with the owning tenant and permission category resolved -- what an auditor '
     + N'reads instead of a role name. Section 15.6. A ROLE WITH NO PERMISSIONS APPEARS, with NULLs in the permission '
     + N'columns, which is why the join is LEFT: auth.uspDefineRole creates every role empty, so an empty role is a '
     + N'normal state and one that stayed empty is the finding. PermissionCount uses COUNT (rp.PermissionId), not '
     + N'COUNT (*), so an empty role counts 0 rather than 1. System roles are NOT filtered out -- trg_au_updt_Role '
     + N'freezes their code, flag and existence but permits their name and description to be edited, so a system '
     + N'role''s label is not evidence of what it grants. OwnerTenantPath with OwnerIsRootOwned answers "how widely can '
     + N'this role be handed out", because INV-05 clause 3 requires the scope to be at or beneath the owner.')
    , (N'logs', N'VIEW', N'vwAuthorizationTrail', NULL
     , N'logs.AuthorizationChange and logs.AuthorizationDenial as ONE time-ordered stream with users, roles and tenants '
     + N'resolved. Sections 15.4 and 15.6. A burst of denials followed by a grant is the most important pattern an '
     + N'access review can see and it is invisible in either table alone. (EventKind, EventId) is the key -- both '
     + N'tables have their own IDENTITY, so a paging screen must order by OccurredUtc, EventKind, EventId. Subject is a '
     + N'deliberately lossy merged label; the specific columns and DetailJson carry what it drops. Every join is LEFT, '
     + N'and the one that matters is the denial''s profile: auth.uspDemandPermission records a NULL UserProfileId when '
     + N'there was no session context at all, and an INNER JOIN would hide exactly those rows. Lives in '
     + N'095_auth_views.sql rather than 085_logs_auth_tables.sql because it binds auth.Role and auth.vwTenantHierarchy '
     + N'at CREATE time. Not granted: a denial trail readable by the application login is a map of what the application '
     + N'is not allowed to do.');

    DECLARE @RowNo       INT = 1
          , @MaxRowNo    INT = (SELECT MAX (RowNo) FROM @Descriptions)
          , @SchemaName  SYSNAME
          , @ObjectType  SYSNAME
          , @ObjectName  SYSNAME
          , @ColumnName  SYSNAME
          , @Description NVARCHAR (3750);

    WHILE @RowNo <= @MaxRowNo
    BEGIN
        SELECT @SchemaName  = SchemaName
             , @ObjectType  = ObjectType
             , @ObjectName  = ObjectName
             , @ColumnName  = ColumnName
             , @Description = Description
          FROM @Descriptions
         WHERE RowNo = @RowNo;

        EXEC util.uspSetObjectDescription @SchemaName  = @SchemaName
                                        , @ObjectType  = @ObjectType
                                        , @ObjectName  = @ObjectName
                                        , @Description = @Description
                                        , @ColumnName  = @ColumnName;

        SET @RowNo += 1;
    END;
END
ELSE
BEGIN
    PRINT N'util.uspSetObjectDescription is absent, so no descriptions were set. Run templates/extended-properties.sql '
        + N'and then re-run this file to add them.';
END
GO


-- *** 7. Grants ***
-- Nothing here, on any of the five, and that is INV-11.  applicationRole holds no access to SCHEMA::auth -- not to the
-- tables and not to these views.  The application reads the tree through auth.uspGetTenantTree, which demands
-- Tenant.Read first and reaches the view by ownership chaining.  A SELECT granted here would let the application
-- enumerate every tenant, every profile, every grant and every denial in every application variant with no permission
-- check at all, and nothing would report it.
--
-- These views exist for REPORTING -- readOnlyRole on a reporting connection, Power BI, an access review -- and that
-- access is granted per project, at the schema level, by whoever owns the reporting decision.  The template does not
-- presume it: logs.vwAuthorizationTrail in particular is a map of what the application cannot do, which is a different
-- sensitivity from the tree.


-- *** 8. Closing report ***
DECLARE @Report TABLE
(
    RowNo    INT IDENTITY (1, 1) PRIMARY KEY,
    Severity INT             NOT NULL,
    Status   VARCHAR (10)    NOT NULL,
    Item     NVARCHAR (200)  NOT NULL,
    Detail   NVARCHAR (1000)     NULL
);

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 5 THEN 4 ELSE 1 END
     , CASE WHEN COUNT (*) = 5 THEN 'OK' ELSE 'MISSING' END
     , N'All five views section 15.6 names exist'
     , CONCAT (COUNT (*), N' of 5: auth.vwTenantHierarchy, auth.vwUserProfile, auth.vwProfilePermission, '
             , N'auth.vwRoleDefinition, logs.vwAuthorizationTrail. The design calls the third view''s table '
             , N'auth.EffectiveGrant; the database calls it auth.ProfilePermissionScope, deliberately.')
  FROM (VALUES (N'auth.vwTenantHierarchy')
             , (N'auth.vwUserProfile')
             , (N'auth.vwProfilePermission')
             , (N'auth.vwRoleDefinition')
             , (N'logs.vwAuthorizationTrail')) AS x (ViewName)
 WHERE OBJECT_ID (x.ViewName, N'V') IS NOT NULL;

-- EVERY ONE OF THE FOUR NEW VIEWS IS SELECTED FROM, not merely checked for existence.  A view compiles at CREATE time
-- against names, but a type mismatch across a UNION ALL and a column widened past its CAST are RUNTIME failures -- and
-- logs.vwAuthorizationTrail is a UNION ALL of two tables with different shapes, which is exactly where that bites.  On an
-- empty database this costs nothing and still proves the shapes agree.
INSERT @Report (Severity, Status, Item, Detail)
SELECT 4, 'OK'
     , N'The five views all execute, with their row counts'
     , CONCAT (N'vwTenantHierarchy ', (SELECT COUNT (*) FROM auth.vwTenantHierarchy)
             , N' live tenant(s), deepest path ', (SELECT COALESCE (MAX (Depth), 0) FROM auth.vwTenantHierarchy)
             , N' below a root; vwUserProfile ', (SELECT COUNT (*) FROM auth.vwUserProfile)
             , N' profile(s); vwProfilePermission ', (SELECT COUNT (*) FROM auth.vwProfilePermission)
             , N' grant point(s); vwRoleDefinition ', (SELECT COUNT (*) FROM auth.vwRoleDefinition)
             , N' row(s) of which ', (SELECT COUNT (*) FROM auth.vwRoleDefinition WHERE IsEmpty = 1)
             , N' are roles holding no permissions; vwAuthorizationTrail '
             , (SELECT COUNT (*) FROM logs.vwAuthorizationTrail), N' event(s). Zeros are expected until '
             , N'115_seed_reference_data.sql and 900_bootstrap_first_admin.sql have run.');

-- THE EMPTY-ROLE CASE IS ASSERTED, not assumed, because it is the one thing about auth.vwRoleDefinition that a later
-- "tidy up the joins" edit would silently break: turning the LEFT JOIN into an INNER would still compile, still run, and
-- quietly stop reporting every role that grants nothing.  115_seed_reference_data.sql ships 19 system roles and gives
-- them their permissions, so on a seeded database the count below should be 0 -- but the SHAPE has to hold either way.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.RolesInView = x.RolesInTable THEN 4 ELSE 1 END
     , CASE WHEN x.RolesInView = x.RolesInTable THEN 'OK' ELSE 'VIOLATED' END
     , N'auth.vwRoleDefinition reports every role, including those with no permissions'
     , CONCAT (x.RolesInView, N' distinct role(s) in the view against ', x.RolesInTable
             , N' live role(s) whose owning tenant is visible. They must match: a role with no permission rows appears '
             , N'with NULLs because the join is LEFT, and an empty role that stayed empty is the finding an access '
             , N'review is looking for. If these ever disagree, somebody made the join INNER.')
  FROM (SELECT RolesInView  = (SELECT COUNT (DISTINCT RoleId) FROM auth.vwRoleDefinition)
             , RolesInTable = (SELECT COUNT (*)
                                 FROM auth.Role AS r
                                INNER JOIN auth.vwTenantHierarchy AS th ON th.TenantId = r.OwnerTenantId
                                WHERE r.IsDeleted = 0)) AS x;

-- The denial rows with a NULL UserProfileId -- there are some, because 150_auth_query_procedures.sql writes three every
-- time it deploys -- must survive into the trail view.  This is the LEFT JOIN that matters most in this file and the one
-- an optimisation would remove first.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN x.InTable = x.InView THEN 4 ELSE 1 END
     , CASE WHEN x.InTable = x.InView THEN 'OK' ELSE 'VIOLATED' END
     , N'logs.vwAuthorizationTrail keeps denials that have no profile'
     , CONCAT (x.InView, N' of ', x.InTable, N' denial row(s) with a NULL UserProfileId reach the view. They must all '
             , N'reach it: auth.uspDemandPermission records that NULL when a guarded procedure was called with no '
             , N'session context at all, which is the single most important row in the trail, and an INNER JOIN to '
             , N'auth.UserProfile would hide exactly those. Zero of zero is a pass on a database where nothing has been '
             , N'refused yet.')
  FROM (SELECT InTable = (SELECT COUNT (*) FROM logs.AuthorizationDenial WHERE UserProfileId IS NULL AND IsDeleted = 0)
             , InView  = (SELECT COUNT (*) FROM logs.vwAuthorizationTrail
                           WHERE EventKind = N'Denial' AND ActorUserProfileId IS NULL)) AS x;

INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 5 THEN 4 ELSE 2 END
     , CASE WHEN COUNT (*) = 5 THEN 'OK' ELSE 'INCOMPLETE' END
     , N'MS_Description on all five views'
     , CONCAT (COUNT (*), N' of 5 views carry an object-level description. Conventions rule 4. The column-level '
             , N'descriptions on auth.vwTenantHierarchy are counted separately by 950_verify_deployment.sql.')
  FROM sys.extended_properties AS ep
 WHERE ep.class    = 1
   AND ep.minor_id = 0
   AND ep.name     = N'MS_Description'
   AND ep.major_id IN (OBJECT_ID (N'auth.vwTenantHierarchy')
                     , OBJECT_ID (N'auth.vwUserProfile')
                     , OBJECT_ID (N'auth.vwProfilePermission')
                     , OBJECT_ID (N'auth.vwRoleDefinition')
                     , OBJECT_ID (N'logs.vwAuthorizationTrail'));

-- INV-11 stated as a test rather than as a comment.  Nothing in this file is granted, and the absence has to be checked
-- because a GRANT SELECT ON SCHEMA::auth made somewhere else would silently cover all five.
INSERT @Report (Severity, Status, Item, Detail)
SELECT CASE WHEN COUNT (*) = 0 THEN 4 ELSE 2 END
     , CASE WHEN COUNT (*) = 0 THEN 'OK' ELSE 'REVIEW' END
     , N'No SELECT granted on any of the five views to applicationRole'
     , CONCAT (COUNT (*), N' grant(s) found; 0 is correct. INV-11. The application reaches what it needs through '
             , N'procedures by ownership chaining. Reporting access is granted per project by whoever owns the '
             , N'reporting decision -- the template does not presume it, and logs.vwAuthorizationTrail in particular is '
             , N'a map of what the application is not allowed to do.')
  FROM sys.database_permissions       AS p
 INNER JOIN sys.database_principals   AS dp ON dp.principal_id = p.grantee_principal_id
 WHERE p.class           = 1
   AND p.permission_name = N'SELECT'
   AND p.state           IN (N'G', N'W')
   AND dp.name           = N'applicationRole'
   AND p.major_id        IN (OBJECT_ID (N'auth.vwTenantHierarchy')
                           , OBJECT_ID (N'auth.vwUserProfile')
                           , OBJECT_ID (N'auth.vwProfilePermission')
                           , OBJECT_ID (N'auth.vwRoleDefinition')
                           , OBJECT_ID (N'logs.vwAuthorizationTrail'));

IF EXISTS (SELECT 1 FROM @Report WHERE Severity <= 2)
    PRINT N'auth views: PROBLEMS found. Read the report below before running the next script.';
ELSE
    PRINT N'auth views: no problems found.';

PRINT N'';

SELECT Severity, Status, Item, Detail
  FROM @Report
 ORDER BY Severity, RowNo;
GO
