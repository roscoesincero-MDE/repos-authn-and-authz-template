"""Add UI-33 to UI-39 -- the Phase 3 and Phase 4 gotchas -- to ui-gotchas.xlsx."""
import copy
from openpyxl import load_workbook

WB = 'workbooks/ui-gotchas.xlsx'


def build_rows(sec):
    """sec is the section-sign glyph already used in the Design ref column."""
    d = lambda s: s.replace('$', sec)
    return [
        ('UI-33', 'Forms',
         'auth.tvfPermissionScope tells you where authority is RECORDED, not where it can be used today',
         d('The function answers one question exactly: which tenants does this profile hold this permission on. It does '
           'NOT join auth.udfIsTenantUsable, so a tenant that has been deactivated, or whose parent has, still comes '
           'back. Build a tenant picker straight from it and the user is offered an organization they cannot act for; '
           'they pick it, and auth.uspSetSessionContext refuses with E-50021 after the click. The list looked '
           'authoritative because it came from the authorization layer.'),
         d('Join auth.udfIsTenantUsable (or call the tenant read procedure) when you are building anything a user '
           'CHOOSES from. Use tvfPermissionScope unjoined when you are answering "does this person have authority here '
           'at all" -- for example when deciding whether to show a feature at all. The two questions have different '
           'answers on purpose: authority survives a deactivation so that it comes back intact when the tenant does.'),
         d('DES $9.2; T-051; BL-041'),
         'Medium', 'Open', None,
         'Added at the end of Phase 3, when auth.tvfPermissionScope was written. The omission is deliberate and is '
         'stated in the function\'s own banner; this row is here because the caller is who pays for it.'),

        ('UI-34', 'Troubleshooting',
         'Re-running a database script can fail with error 3729 -- the security policy is holding the functions',
         d('Msg 3729, "Cannot ALTER \'auth.tvfTenantReadPredicate\' because it is being referenced by object '
           '\'TenantAccessPolicy\'". The three predicates are WITH SCHEMABINDING, and a function a live security policy '
           'references cannot be altered at all. So on any database where row-level security is already on, '
           're-running 100_auth_functions.sql fails -- and so does anything else that touches a bound object. A '
           'developer refreshing a local database hits this on their SECOND deployment, never their first, which is the '
           'worst moment to meet it.'),
         d('Use database/Install-TemplateDatabase.ps1, which unbinds the policy before every pass and rebuilds it at '
           'step 27. If you are running one script by hand, run EXEC auth.uspRebuildTenantAccessPolicy @Action = '
           'N\'Drop\' first and EXEC auth.uspRebuildTenantAccessPolicy @Action = N\'Rebuild\' afterwards. Do not drop '
           'the policy with DDL and do not disable it and leave it disabled: between the drop and the rebuild the '
           'tenant-scoped tables are UNPROTECTED, so do it on a maintenance connection and finish the job.'),
         d('DES $21.3; BL-038'),
         'High', 'Open', None,
         'Added at the end of Phase 4. Not the UI team\'s code, but it is the UI team\'s local database -- and the error '
         'text names a function, which sends most people to the wrong file.'),

        ('UI-35', 'Authorization',
         'A stale permission-id list in the predicates is a SILENT DENIAL -- rows vanish and nothing raises an error',
         d('A security predicate is schema-bound and cannot join auth.Permission by code, so 120_rls_policy.sql '
           'substitutes the permission IDS into the predicate as literals -- "pps.PermissionId IN (7, 19, 33)". Add a '
           'permission, retire one, or deploy the catalogue to a fresh database in a different order, and the ids move '
           'while the predicate does not. Nothing fails: the predicate simply matches fewer rows, so screens come back '
           'partially or entirely empty for some profiles and not others. With the catalogue not seeded at all the list '
           'resolves to the sentinel -1 and EVERY row is denied, which at least fails closed and loudly enough to '
           'notice.'),
         d('Any change to auth.Permission is followed by re-running 120_rls_policy.sql -- or by EXEC '
           'auth.uspRebuildTenantAccessPolicy @Action = N\'Rebuild\', which is what re-running it does. Treat it as '
           'part of the migration, not as a follow-up. When a user reports "I could see these records yesterday", check '
           'this before checking the grants: 120\'s closing report re-derives the list and compares it with what is '
           'deployed, so running the script is also the diagnosis.'),
         d('DES $10.2; BL-039; T-065'),
         'Critical', 'Open', None,
         'Added at the end of Phase 4, and cited by ID in database/_tests/060_row_security.sql, which has to re-run the '
         'rebuild after building its own fixture for exactly this reason -- otherwise every assertion in the file would '
         '"pass" by denying everything.'),

        ('UI-36', 'Data access',
         'The session identity is read-only once set, and it is NOT transactional',
         d('auth.uspSetSessionContext sets its five identity keys with @read_only = 1. Such a key cannot be re-set to '
           'another value, cannot be re-set to the SAME value, and cannot be set to NULL -- that last one is Msg 15664. '
           'Two consequences bite in opposite directions. A pooled connection that has served one profile CANNOT serve '
           'another: a second call for a different profile raises E-50022 and changes nothing (which is the defence '
           'working). And session context does not participate in transactions: a ROLLBACK does not unset a key, so a '
           'failed unit of work leaves the identity behind on that connection.'),
         d('Open a connection, set context, do the work, close the connection. Do not cache a connection across '
           'requests or across users, do not try to "reset" the context -- auth.uspClearSessionContext clears '
           'BypassRowSecurity and reports the rest, which is all it can do -- and do not assume a rollback undid the '
           'identity. If your data-access layer keeps long-lived connections, this is the row that decides its design.'),
         d('DES $14.3; T-053, T-054; UI-06'),
         'High', 'Open', None,
         'Added at the end of Phase 3. Verified by database/_tests/050_authorization_and_session.sql section 5, which '
         'has to be the LAST section in the file because running it spends the connection\'s identity. Msg 15664 was '
         'measured on this instance, not quoted.'),

        ('UI-37', 'Data access',
         'You cannot stamp auditDeletedBy yourself -- the AFTER UPDATE trigger owns it',
         d('Every table carries an AFTER UPDATE trigger that sets auditModifiedBy and auditDeletedBy from '
           'SUSER_SNAME(), overwriting whatever the statement supplied. So a soft delete that tries to record WHO asked '
           'for it, or WHY, by writing into the audit columns silently loses it: the row ends up naming the '
           'application\'s SQL login, which it was going to name anyway.'),
         d('Anything a caller needs to say about a deletion -- a reason, a ticket reference, an end user who is not the '
           'connection\'s login -- goes into the logs trail the procedure writes, never into the audit columns. Read '
           'the audit columns as "which login touched this row", which is exactly what they are for; a value a caller '
           'could write is a value a caller could falsify.'),
         d('DES $15.2; BL-044; conventions: the seven audit columns'),
         'Medium', 'Open', None,
         'Added at the end of Phase 3, found by _tests/050 trying to tag its own rows through auditDeletedBy and '
         'watching the trigger overwrite the tag. Every table gains this trigger in Phase 7 (135_audit_triggers.sql), '
         'so it will be true everywhere.'),

        ('UI-38', 'Forms',
         'Moving a record to another organization fails with Msg 547, not with an authorization error',
         d('The demo domain -- and any table that follows it -- carries composite foreign keys that include TenantId: '
           'dbo.CaseFile (AssignedToProfileId, TenantId) and dbo.CaseNote (CaseFileId, TenantId). An UPDATE that '
           'changes TenantId therefore breaks a foreign key BEFORE the block predicate is ever evaluated, so the error '
           'is a referential-integrity failure (Msg 547) and not the block violation (Msg 33504) the access matrix '
           'describes. Two defences in a row, and the outer one speaks the wrong language.'),
         d('If you branch on error numbers -- and UI-08 says you should -- map Msg 547 on these tables to "this record '
           'cannot be moved to another organization", alongside 33504. Better: do not offer a TenantId on an edit form '
           'at all (UI-14 says the same about inserts). A record belongs to the organization it was created for; '
           'moving it is a data-migration operation, not a user action.'),
         d('DES $10.3; BL-045; T-067'),
         'Medium', 'Open', None,
         'Added at the end of Phase 4, found by _tests/060 section 6g, which had to plant an UNASSIGNED case file to '
         'reach the block predicate at all.'),

        ('UI-39', 'Logging',
         'An authentication-event row must name someone -- a fully anonymous event is refused',
         d('CK_logs_AuthenticationEvent_Attributable requires UserId or UserName to be present. A procedure that '
           'records an event with both NULL fails with Msg 547, and the event is not written. This is deliberate: an '
           'audit trail of events attributable to nobody is not a trail. It is also easy to trip, because the cases '
           'where the actor is hardest to name -- a maintenance bypass, a sign-in attempt for an address that does not '
           'exist, a token that resolved to nothing -- are exactly the cases worth recording.'),
         d('When you cannot supply a UserId, supply a UserName: the login, ORIGINAL_LOGIN() under impersonation, or the '
           'address that was attempted. Never leave both empty to represent "unknown". The database\'s own maintenance '
           'procedures shipped with this defect and it survived two phases, because the only path that exercised them '
           'was the one that refuses the caller before writing anything -- so if you are writing a caller that records '
           'events, test the ACCEPTED path explicitly.'),
         d('DES $10.5, $15.5; BL-046'),
         'Medium', 'Open', None,
         'Added at the end of Phase 4. Found by database/_tests/060_row_security.sql section 7, which was the first '
         'thing ever to reach the accepted path of auth.uspBeginMaintenanceSession.'),
    ]


def main():
    wb = load_workbook(WB)
    ws = wb['Gotchas']
    tpl = ws.max_row                                  # UI-32
    sec = ws.cell(row=tpl, column=6).value[4]         # the glyph already in use
    rows = build_rows(sec)
    at = tpl + 1
    for i, vals in enumerate(rows):
        rn = at + i
        for j, v in enumerate(vals):
            ws.cell(row=rn, column=j + 1).value = v
        for c in range(1, 11):
            ws.cell(row=rn, column=c)._style = copy.copy(ws.cell(row=tpl, column=c)._style)
        ws.row_dimensions[rn].height = ws.row_dimensions[tpl].height

    if ws.auto_filter.ref:
        head, tail = ws.auto_filter.ref.split(':')
        lastcol = ''.join(ch for ch in tail if ch.isalpha())
        ws.auto_filter.ref = '%s:%s%d' % (head, lastcol, at + len(rows) - 1)

    lg = wb['Legend']
    lg.cell(row=4, column=2).value = (
        'Thirty-nine things about this database that will otherwise be found the hard way, by a developer writing a '
        '.NET 10 application with the MVP pattern, Dapper, and stored procedures only. Each row names the gotcha, why '
        'it bites, and what to do instead.'
    )
    lg.cell(row=22, column=2).value = "Seven of these are not the UI team's code, and are listed here anyway"
    lg.cell(row=23, column=2).value = (
        lg.cell(row=23, column=2).value.rstrip() +
        ' UI-34 and UI-35 joined that list at the end of Phase 4 and belong to whoever deploys: error 3729 when a '
        'script is re-run against a database that already has row-level security on, and a permission-id list in the '
        'predicates that goes stale the moment the catalogue changes. Both are here because the symptom lands on a '
        'developer or a user -- a script that will not deploy, or records that were visible yesterday -- while the fix '
        'is one command in the database.'
    )
    lg.cell(row=28, column=2).value = (
        'Thirty-nine entries as of 2026-09-20, against DES-AUTH-001 v1.5. UI-26 and UI-27 were added after Phase 2 '
        'built the authentication procedures, and UI-22 was rewritten when G-20 closed -- it had been telling you to '
        'check a grant on a type that will never exist. UI-28 to UI-32 were added when gap G-07 closed: management '
        'chose application-side encryption over SQL Server Always Encrypted, and every one of those five rows is a '
        'consequence of that choice rather than a preference -- a key bound to one machine, ciphertext for every '
        'external reader, a one-way flag in appsettings.secrets.json, first-factor enrolment out of a refused sign-in, '
        'and a replay window that reopens for one TOTP step after a re-key.\n\n'
        'UI-33 TO UI-39 WERE ADDED WHEN PHASES 3 AND 4 BUILT AUTHORIZATION AND ROW-LEVEL SECURITY, and none of the '
        'seven came from reading the design: six were found by a test file or a deployment failing, and the seventh '
        '(UI-33) by writing a function and noticing what it deliberately does not answer. Two deserve reading before '
        'any data-access code is written -- UI-35, because a stale permission-id list makes rows disappear with no '
        'error at all, and UI-36, because it decides whether your connection handling is legal. Add rows as the UI '
        'project finds more.'
    )
    wb.save(WB)
    print('gotchas added', len(rows), 'filter', ws.auto_filter.ref, 'sec glyph', repr(sec))


if __name__ == '__main__':
    main()
