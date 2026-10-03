"""Append Build Log entries BL-036 to BL-048 (Phases 3 and 4) to build-and-traceability.xlsx."""
import copy
from openpyxl import load_workbook

WB = 'workbooks/build-and-traceability.xlsx'
D = '2026-09-20'

ROWS = [
    ('BL-036', D,
     '040_auth_userprofile.sql',
     'DES section 15.4 (auth.UserProfile); INV-03',
     'Section 15.4 lists ProfileName as the label a person picks between their own hats, and states one uniqueness '
     'rule for the table: one default profile per user.',
     'A second filtered unique index, UX_auth_UserProfile_UserTenantName on (UserId, TenantId, ProfileName) WHERE '
     'IsDeleted = 0, alongside UX_auth_UserProfile_Default. Two live profiles for one person at one tenant may not '
     'share a name; a soft-deleted one does not block the name coming back.',
     'The profile switcher in DES section 12 is a list of names and nothing else. Two hats called "Case Worker" at the '
     'same organization produce a list where the right choice cannot be identified, and the consequence is not '
     'cosmetic: picking the wrong one sets a different ScopeTenantId and therefore a different set of visible rows. '
     'Uniqueness per (UserId, TenantId) rather than per user, because the same person legitimately has a "Case Worker" '
     'hat at two organizations.',
     'Opus 5',
     'Yes -- DES section 15.4 gains the second index in v1.5'),

    ('BL-037', D,
     '050_auth_permission.sql, 055_auth_role.sql',
     'DES section 15.4 (auth.Permission, auth.Role); Appendix A',
     'Appendix A gives each of the 35 permissions a code and a one-line meaning in the DOCUMENT, and section 15.4 '
     'gives auth.Permission the code, the category and IsTenantScoped. Nothing carries the meaning into the database. '
     'auth.Role is the same shape.',
     'A PermissionDescription NVARCHAR (400) NULL column on auth.Permission and a Description NVARCHAR (400) NULL '
     'column on auth.Role, both seeded from Appendix A text by 115_seed_reference_data.sql when it runs.',
     'Without them, the sentence a UI shows next to a checkbox in the role editor has to live in the UI project, and '
     'the same 35 sentences get re-typed by every application built on this template -- at which point they diverge '
     'from Appendix A and nothing detects it. A description in the row is also what makes the permission catalogue '
     'legible to an administrator reading it in SSMS, which is how most people will first meet it. NULLable rather '
     'than NOT NULL, because a project adding its own permission should not be blocked from inserting it while it '
     'works out the wording.',
     'Opus 5',
     'Yes -- DES section 15.4 gains both columns in v1.5; Appendix A text is the source'),

    ('BL-038', D,
     '120_rls_policy.sql; Install-TemplateDatabase.ps1',
     'DES sections 10.1 and 21.3',
     'Section 10.1 gives the policy as a CREATE SECURITY POLICY statement with one FILTER and three BLOCK predicates '
     'per tenant-scoped table, and section 21.3 warns that a policy-bound function cannot be altered.',
     'The policy is built by a procedure, auth.uspRebuildTenantAccessPolicy, with @Action = N\'Rebuild\' or '
     'N\'Drop\' and @TablesBound / @TablesSkipped OUTPUT parameters. It reads config.TenantScopedTable, verifies each '
     'registered table really has a TenantId column of the right type, and generates the policy. '
     'Install-TemplateDatabase.ps1 calls @Action = N\'Drop\' before EVERY pass and rebuilds at step 27.',
     'The warning in 21.3 is not a caution, it is a deployment blocker: with the policy bound, re-running '
     '100_auth_functions.sql fails at error 3729, so every SECOND deployment of an existing database would have died '
     'at step 21 of 28. A drop-then-rebuild needs a supported way to drop, and inline DDL in a numbered script cannot '
     'offer one to the installer -- so the drop had to become an object. The procedure also removes the second reason '
     'the inline form was fragile: the list of protected tables is data in config.TenantScopedTable, not a hand-edited '
     'CREATE statement that a project has to remember to extend. The cost is honest and is written into the runner: '
     'between the drop and step 27 the tables are UNPROTECTED, which is why the drop happens on a maintenance '
     'connection during a deployment and never as an operational step.',
     'Opus 5',
     'Yes -- DES section 21.3 names the procedure and the @Action values in v1.5'),

    ('BL-039', D,
     '100_auth_functions.sql, 120_rls_policy.sql, 065_auth_effective_permission.sql',
     'DES section 10.2 (the predicate definitions)',
     'Section 10.2 wrote the predicate body as a join from auth.ProfilePermissionScope to auth.Permission on '
     'PermissionCode = N\'Data.Read\', and did not carry IsDeleted = 0 into the predicate\'s WHERE clause.',
     'The predicates are SCHEMABINDING and cannot join a table by a code they resolve at run time, so 120_rls_policy.sql '
     'substitutes a LITERAL LIST of permission ids -- pps.PermissionId IN (7, 19, 33) -- resolved from the catalogue at '
     'build time, with the sentinel -1 when the catalogue is empty. Every read of auth.ProfilePermissionScope, in the '
     'predicates and everywhere else, carries IsDeleted = 0.',
     'A list and not a single id because a database serving four applications holds FOUR rows whose PermissionCode is '
     'Data.Read, one per application: a single id would protect one application and fail OPEN for the other three. '
     'IsDeleted = 0 because IX_auth_ProfilePermissionScope_Lookup is a filtered index -- omitting the filter both '
     'misses the index and counts retired authority as live. The substitution introduces its own failure mode, a list '
     'that no longer matches the catalogue, which is a SILENT DENIAL rather than an error (UI-35); the closing report '
     'of 120 therefore re-derives the list and compares it against the deployed definition, and the empty-catalogue '
     'case resolves to -1 so that the failure is closed rather than open.',
     'Opus 5',
     'Yes -- DES section 10.2 rewritten in v1.5 with the literal list and both IsDeleted filters'),

    ('BL-040', D,
     '030_auth_tenant.sql (amended), 055_auth_role.sql',
     'DES section 8.2 (auth.Role); INV-04',
     'INV-04 requires that a role and the profile it is granted to belong to the same application. The design leaves '
     'the enforcement to the procedures that write auth.Role and auth.UserProfileRole.',
     'A composite foreign key. auth.Role.(OwnerTenantId, ApplicationId) references an UNFILTERED UNIQUE constraint '
     'UX_auth_Tenant_Id_Application (TenantId, ApplicationId), added to auth.Tenant by a guarded ALTER in '
     '030_auth_tenant.sql. 055_auth_role.sql THROWs at install time if that constraint is absent rather than creating '
     'a table that cannot enforce its own invariant.',
     'A procedure check holds only for rows that go through the procedure, and a template that ships with a bootstrap '
     'script, a seed script and an administrator with SSMS will see rows that do not. The constraint makes a '
     'cross-application grant unrepresentable. It is UNFILTERED because a foreign key cannot reference a filtered '
     'index, which is the same reason UX_auth_TenantType_Id_Code and UX_auth_UserProfile_Id_Tenant exist -- three '
     'instances of one pattern, now stated once in the design. Added by ALTER rather than folded into CREATE TABLE so '
     'that a database deployed before Phase 3 gains it on a re-run.',
     'Opus 5',
     'Yes -- DES section 8.2 and section 15.4 describe the composite FK in v1.5'),

    ('BL-041', D,
     '100_auth_functions.sql; DES sections 10.2, 10.3, 21.3 and Appendix C',
     'DES sections 9.2 and 10.2 (function names)',
     'The design named four objects udfPermissionScope, udfTenantReadPredicate, udfTenantInsertPredicate and '
     'udfTenantUpdatePredicate.',
     'All four are named tvf: auth.tvfPermissionScope, auth.tvfTenantReadPredicate, auth.tvfTenantInsertPredicate, '
     'auth.tvfTenantUpdatePredicate. The design document was corrected in four places including Appendix C, not the '
     'code.',
     'The house convention reserves udf for scalar functions and tvf for table-valued ones, and the SQL gate enforces '
     'it -- the files would not pass validation under the design\'s names. All four are inline table-valued by '
     'necessity: a security predicate must return a row set. Correcting the document rather than the code is the '
     'general rule this project follows when a convention and a draft disagree, because the convention is checked '
     'mechanically on every file and the document is checked by whoever remembers to read it.',
     'Opus 5',
     'Yes -- renamed in DES sections 10.2, 10.3, 21.3 and Appendix C in v1.5'),

    ('BL-042', D,
     '150_auth_query_procedures.sql, 165_logs_procedures.sql',
     'DES sections 9.3 and 14.2 (authorization denials are recorded)',
     'Every authorization refusal writes a logs.AuthorizationDenial row and then raises E-50030 or E-50031. The '
     'design treats the trail row as unconditional.',
     'It is not unconditional, and the script says so where a reader will find it. auth.uspDemandPermission writes the '
     'denial through logs.uspRecordAuthorizationDenial and then THROWs; if the caller had a transaction open, the '
     'rollback the throw provokes takes the trail row with it. No autonomous transaction was invented to work around '
     'it.',
     'The alternatives were a loopback connection or a queue table written outside the transaction, and both buy '
     'durability of an audit row at the price of a new failure mode in the authorization path -- the thing that must '
     'never fail. The design already prevents the loss by ordering: section 9 authorizes at step 5, BEFORE any '
     'transaction opens, so a denial in a compliant caller is never inside one. Recording the limitation is what makes '
     'that ordering a requirement instead of a habit, and every procedure in this database follows it.',
     'Opus 5',
     'Yes -- DES section 9.3 states the ordering requirement and its reason in v1.5'),

    ('BL-043', D,
     '105_auth_session_procedures.sql',
     'DES section 9.1 (auth.uspSetSessionContext); section 15.4 (auth.UserSession)',
     'The design sketched auth.uspSetSessionContext @SessionToken NVARCHAR (200), and section 15.4 named the session '
     'column LastActivityUtc.',
     'The procedure takes @SessionTokenHash VARBINARY (32) and the column is LastSeenUtc, matching '
     '070_auth_session.sql, which has stored only the hash since Phase 2.',
     'The raw token never crosses this boundary. It is minted by the application, hashed there, and only the hash is '
     'ever sent to the database -- a token in a procedure parameter would appear in Query Store, in an execution plan '
     'and in any trace anyone turns on, which is exactly the exposure hashing was adopted to prevent. LastSeenUtc is '
     'the smaller half of the entry: the design had two names for one column, and the table shipped first, so the '
     'document was corrected.',
     'Opus 5',
     'Yes -- DES section 9.1 takes @SessionTokenHash and section 15.4 says LastSeenUtc in v1.5'),

    ('BL-044', D,
     'database/_tests/050_authorization_and_session.sql; 135_audit_triggers.sql (future)',
     'conventions: the seven audit columns; DES section 15.2',
     'auditDeletedBy records who soft-deleted a row, and a caller that performs the soft delete can set it.',
     'It cannot, once the AFTER UPDATE trigger exists. trg_au_updt_UserProfileRole sets auditModifiedBy and '
     'auditDeletedBy from SUSER_SNAME() on every UPDATE, overwriting whatever the statement supplied. The test was '
     'rewritten to identify its own rows by their grant keys rather than by a marker it had hoped to leave in '
     'auditDeletedBy.',
     'Recorded because the trigger is right and the expectation was wrong: the audit columns answer "which login '
     'touched this row", and a caller that could write them could also lie in them. Anything a caller needs to say '
     'ABOUT a deletion -- a reason, a ticket, an actor other than the connection\'s login -- belongs in the logs trail '
     'that the procedure writes, not in the audit columns of the row. Worth a Build Log entry rather than a comment '
     'because 135_audit_triggers.sql will put the same trigger on every table in the database, so every future test '
     'and every future procedure meets this.',
     'Opus 5',
     'Yes -- DES section 15.2 states that the audit columns are trigger-owned in v1.5'),

    ('BL-045', D,
     'database/_tests/060_row_security.sql; 090_dbo_application.sql',
     'DES section 10.3 (the access matrix)',
     'The matrix says an attempt to MOVE a row to another tenant is refused by the BLOCK predicate, and the test '
     'expects Msg 33504.',
     'It is refused, but by a foreign key: the composite FKs on dbo.CaseFile (AssignedToProfileId, TenantId) and '
     'dbo.CaseNote (CaseFileId, TenantId) fail with Msg 547 BEFORE the block predicate is ever evaluated. The test '
     'plants an UNASSIGNED case file specifically so that section 6g can reach the predicate and observe 33504.',
     'Two defences in a row, and the outer one is the wrong error for a UI to show -- which is the reportable part: a '
     'tenant move surfaces as a referential-integrity failure, not as an authorization failure, so a caller mapping '
     'error numbers to messages must handle 547 on these tables as "that row cannot be moved". The layering is '
     'deliberate and stays: the FK makes most moves unrepresentable regardless of session context, and the predicate '
     'catches the rest. The test had to be written around it to prove the predicate works at all, which is exactly the '
     'sort of thing a test file discovers and a design review does not.',
     'Opus 5',
     'Yes -- DES section 10.3 notes Msg 547 ahead of Msg 33504 for rows with composite FKs in v1.5'),

    ('BL-046', D,
     '105_auth_session_procedures.sql; found by database/_tests/060_row_security.sql',
     'DES section 10.5 (the maintenance bypass); section 15.5',
     'auth.uspBeginMaintenanceSession writes a logs.AuthenticationEvent row of type MaintenanceBypass before it sets '
     'the bypass key, so that a bypass cannot exist without a trail.',
     'Both maintenance procedures wrote that row with UserId and UserName NULL, which '
     'CK_logs_AuthenticationEvent_Attributable refuses with Msg 547 -- so the ACCEPTED path of both procedures had '
     'never worked. Fixed: both write the acting principal into UserName, ORIGINAL_LOGIN() so the trail names the real '
     'login under EXECUTE AS. uspEndMaintenanceSession also gained its MaintenanceBypassEnded row.',
     'The defect is ordinary; how it survived is the entry. The deployment probe inside 105 exercised only the REFUSAL '
     'path, because the deploying login is not a member of rlsBypassRole -- so every run reported success while the '
     'only path that matters had never executed. It took a test that creates a user WITHOUT LOGIN, puts it in the '
     'role and impersonates it to reach the code at all. A probe that can only reach the failure branch of a '
     'permission gate is a probe that proves the gate, not the procedure, and this database has several of them.',
     'Opus 5',
     'No -- an implementation defect; DES section 10.5 gains the MaintenanceBypassEnded event and the UserName rule in '
     'v1.5'),

    ('BL-047', D,
     '170_permissions.sql',
     'DES section 13 (the four roles); INV-11',
     'rlsBypassRole exists to be empty of data permissions: membership in it is the credential, the bypass key is the '
     'mechanism, and nothing is granted to it. 170_permissions.sql asserted exactly that -- zero permissions -- and '
     'passed for two phases.',
     'It stopped being true in Phase 4, and the assertion FAILED the deployment: 105_auth_session_procedures.sql '
     'grants EXECUTE on auth.uspBeginMaintenanceSession and auth.uspEndMaintenanceSession to rlsBypassRole, because '
     'the supported way to raise the bypass is to call a procedure that writes the trail first. The assertion was '
     'rewritten to "exactly those two EXECUTE grants and nothing else", counting both the expected grants and any '
     'others.',
     'Kept because of what the failure demonstrates about assertions of ABSENCE. "Nothing is granted" is the cheapest '
     'and most brittle form: the next correct change breaks it, and the temptation is to delete the check. The useful '
     'form names what may be there and fails on anything else, which is strictly stronger than the original -- it '
     'would now catch a fifth grant, which the old form would also have caught, AND it documents why the two are '
     'legitimate, which the old form could not. The two-permission state was found by the catalog, not by reading '
     '105: the file that grants a permission and the file that asserts the permission model are different files, and '
     'only the second one runs last.',
     'Opus 5',
     'Yes -- DES section 13 lists the two grants rlsBypassRole legitimately holds in v1.5'),

    ('BL-048', D,
     '170_permissions.sql; .claude/skills/ponytail-sql-objects/scripts/permissions.sql (not modified); '
     '085_logs_auth_tables.sql',
     'DES section 13; 085 section 8 (who may write the trails)',
     '085 section 8 states that applicationRole reaches the audit trails only through the recorder procedures in 165, '
     'by ownership chaining, and that nothing is granted on the tables themselves.',
     'The conventions skill\'s own permissions.sql, install step 6, runs GRANT SELECT, INSERT, UPDATE, DELETE ON '
     'SCHEMA::logs TO applicationRole -- so the three authorization trails and logs.AuthenticationEvent were directly '
     'writable by the application login from the moment they were created in the logs schema. 170_permissions.sql now '
     'carries a section 4 that DENIES INSERT, UPDATE and DELETE on those four tables, object by object, and asserts '
     'all twelve denies in its closing report.',
     'NARROWED rather than revoked, and each boundary is a decision. The schema grant stays because it is the '
     'conventions script\'s and this template does not fork it. SELECT stays because logsAuditReader is not the only '
     'legitimate reader and nothing is leaked by reading a trail the caller could have written. logs.ExecutionLog '
     'stays fully writable because the framework\'s own logging procedures write it from the application side, and '
     'denying it would break the convention that makes every script in this database observable. An impersonation '
     'probe confirmed both halves before the file was committed: a direct UPDATE by an applicationRole member now '
     'fails with 229, and the same write inside auth.uspRecordLoginFailure still succeeds through ownership chaining. '
     'The report carries a NOTE row saying plainly that the FIFTH logs table anyone adds will repeat this hole, '
     'because the schema grant is inherited and the denies are not.',
     'Opus 5',
     'Yes -- DES section 13 records the object-level denies and their rationale in v1.5'),
]

TRAILER = (
    "This sheet fills as scripts are written. Forty-eight entries so far: eight from the design pass, sixteen from "
    "Phases 0 and 1, eleven from Phase 2, and thirteen from Phases 3 and 4. Three of the forty-eight are '"
    "the design was right and the implementation was wrong' -- BL-035, BL-046 and the fix half of BL-044 -- and they "
    "are kept for the same reason as the rest: the interesting part is not the mistake, it is how it survived until "
    "something ran. The Phase 3 and 4 entries fall into three groups. Four are the design being corrected by a "
    "convention or by SQL Server itself (BL-039, BL-041, BL-043 and BL-038, where error 3729 turned a warning in "
    "section 21.3 into a deployment blocker). Four are additions the design did not ask for and a working system needs "
    "(BL-036, BL-037, BL-040 and the object-level denies of BL-048). Five were found by running something: BL-042 and "
    "BL-047 by a script failing, BL-044 and BL-045 by a test file being written, BL-046 by a test reaching a path no "
    "probe could reach. Nothing here was found by re-reading the design."
)


def main():
    wb = load_workbook(WB)
    ws = wb['Build Log']
    tpl = 36                                  # BL-035, the last existing entry
    at = tpl + 1
    ws.insert_rows(at, amount=len(ROWS))
    for i, vals in enumerate(ROWS):
        rn = at + i
        for j, v in enumerate(vals):
            ws.cell(row=rn, column=j + 1).value = v
        for c in range(1, 10):
            ws.cell(row=rn, column=c)._style = copy.copy(ws.cell(row=tpl, column=c)._style)
        ws.row_dimensions[rn].height = ws.row_dimensions[tpl].height

    if ws.auto_filter.ref:
        head, tail = ws.auto_filter.ref.split(':')
        lastcol = ''.join(ch for ch in tail if ch.isalpha())
        lastrow = int(''.join(ch for ch in tail if ch.isdigit())) + len(ROWS)
        ws.auto_filter.ref = '%s:%s%d' % (head, lastcol, lastrow)

    # the roll-up note moved down by len(ROWS)
    note_row = 38 + len(ROWS)
    assert str(ws.cell(row=note_row, column=2).value).startswith('This sheet fills'), \
        ws.cell(row=note_row, column=2).value
    ws.cell(row=note_row, column=2).value = TRAILER

    wb.save(WB)
    print('build log rows added:', len(ROWS), 'filter', ws.auto_filter.ref, 'note row', note_row)


if __name__ == '__main__':
    main()
