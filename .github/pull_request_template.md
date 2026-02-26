## Summary
- 
- 
- 

_Snippet reference: `docs/PR_TEMPLATE_SNIPPETS.md` (ultra-short / short / full)_

## Background
- Why now:
- Problem:

## Changes
- 

## Scope
- [ ] Backend
- [ ] UI
- [ ] Sync
- [ ] Security
- [ ] Docs/Workflow

## Verification
- [ ] Build passes locally
- [ ] Key scenario tested manually
- [ ] Run sync log checker: `docs\check_sync_log_keys_samples.cmd both`
- [ ] If this PR touches log checker/workflow/docs, run: `docs\check_sync_log_keys_samples.cmd fail_name_resolution_host`
- [ ] If this PR touches sync errors, confirm `name_not_resolved` logs (`sync_failure` / `reason`) include `host=`
- [ ] If this PR touches auth/secret handling, verify no sensitive markers in logs (`token=`, `bearer=`, `authorization=`)
- [ ] If this PR touches packaging/install, confirm no packaged/unpackaged conflict (`0x80073cfb`) and refer to `docs/windows_app_install_troubleshooting.md`

## Risk / Impact
- User impact:
- Operational impact:
- Compatibility impact:

## Rollback
- Revert commit(s):
- Data migration side effects:
- Runtime flag/env fallback:

## Reviewer Checklist
- [ ] Summary/Background are clear and testable
- [ ] Verification steps are reproducible
- [ ] Log format compatibility is considered (`key=value`)
- [ ] Rollback path is concrete
