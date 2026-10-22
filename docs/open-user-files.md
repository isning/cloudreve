# Open user files

In **Dashboard → Users**, open an existing user's details and choose **Open user
files**. The native link opens that user's personal root in a new tab. The
current administrator remains signed in; the original details and unsaved draft
stay in their tab. The action never submits the form or signs in as the target.

The link uses the successfully loaded account's encoded ID, independently of
editable nickname/email fields and the numeric dashboard ID. It is unavailable
while details are loading/reloading or saving, for an unsaved account, or after
a load failure. Retry loads the current account again; a failed save retains its
draft. Responses belonging to an earlier target, dialog opening or login cannot
update the current details or enable an old destination.

The file manager identifies the target by its persisted nickname. Focus the root
breadcrumb to read the complete name and encoded ID; this also distinguishes
same-name accounts and provides a fallback when the nickname is absent. Target
identity remains through child navigation, search, the directory tree, pagination,
refresh and copied deep links. Choosing **My Files** deliberately returns to the
administrator's own root. A saved share shortcut enters the ordinary share view.

## Native behavior and limits

This entry reuses the existing URI and HTTP interfaces, scopes and capabilities.
Available create/upload, rename, copy/move, delete, metadata and ACL actions keep
their normal rules. For example, storage-policy binding remains owner-only; this
entry does not add access to another user's trash. Creating/uploading in the
target tree preserves the target's ownership, storage-policy selection and quota
accounting. Existing audit events name the actual administrator and actual file.
Opening a directory adds no new audit category.

First access may lazily create a missing personal root. An active account's
pending onboarding snapshot follows normal initialization once. An administrator
opening an already existing foreign root does not consume a pending snapshot;
the target's own later access still does so. Inactive/banned accounts retain the
native administrative personal-drive exception: a missing root is created empty,
without activation or consuming the pending snapshot. Legacy accounts without
eligibility receive no backfill. Removed shortcuts from a completed snapshot are
not reinstalled by opening the account again.

Missing/deleted users return native errors. There is no fallback to the
administrator's own files. Share passwords, expiry, incarnation identity and ACLs
remain enforced; personal-drive administrative access does not revive an invalid
share. Copied locations contain no credentials and grant no authority to ordinary
or anonymous users, including users named in an ACL.

Session recovery keeps the same-origin target and subpath through the normal
login flow and then uses the account actually signed in. Native request-time
checks and final owner fences apply after administrator demotion/disablement or
target deletion. A denied foreign listing or matching tree authorization request
invalidates the old actionable list, selection and menus. Already admitted
requests and already issued provider URLs retain their existing native lifetime;
this feature adds no new cancellation or credential mechanism.

## Verification

`assets/tests/open-user-files.test.mjs` executes the production dialog, form,
breadcrumb and URI modules with controlled rendering, session and HTTP boundaries.
`assets/tests/filemanager.test.mjs` also exercises native Redux navigation,
capabilities and cache-generation behavior. Run with the existing frontend setup:

```bash
cd assets
node --test tests/*.test.mjs
pnpm run build
```

The controller acceptance uses production routing, real Ent and a disposable
SeaweedFS S3 fixture. Configure the existing integration environment explicitly;
without it storage fixtures are skipped rather than counted as acceptance:

```bash
export CLOUDREVE_STORAGE_INTEGRATION=1
export CLOUDREVE_S3_TEST_SERVER=/absolute/path/to/weed
go test -race ./routers/controllers -run '^TestOpenUserFiles(Native|Management|Root|Revocation)' -count=1
```

The tests check actual content, ownership, entities/policy, quota, audit, denied
requests with cached context hints, and controlled mutations paused before final
authorization. They also verify missing-account create/upload/lock errors without
panics. The same controller tests support the repository's existing PostgreSQL,
MySQL and MariaDB fixture configuration (`OIDC_TEST_DRIVER`/`OIDC_TEST_DSN`).

For a real browser, build/package the frontend using the upstream assets archive
layout, then run the opt-in `TestOpenUserFilesBrowserRuntime` with
`CLOUDREVE_OPEN_USER_FILES_BROWSER_DIR` pointing to an ignored local directory.
It serves production UI/HTTP and disposable persistence/storage, writes temporary
credentials with mode 0600, and shuts down on interrupt. Never publish those
credentials. Exercise: edit a nickname without saving, activate the new-tab link
by keyboard, inspect the persisted target, open `support/child/readme.txt` in the
native editor, return to the draft, refresh/copy the child URL, return to My Files,
and follow the saved share. Repeat the same seam at mobile width, with long/empty
and same-name identities, light/dark themes, Chinese/English and a locale relying
on English fallback. Login recovery must retain the child location while an
ordinary login remains denied.

No new endpoint, permission mode, session, schema, queue or dependency is added.
The frontend remains an independent repository; commit it before recording its
submodule revision in a backend commit, using the existing build/release process.
