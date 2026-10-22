# Default share shortcuts

Administrators can configure **Default share shortcuts** in **Settings → User
session**. Search using the numeric ID from the administrator share list, select
up to 100 links and save. Unavailable saved selections remain visible until
explicitly removed. Removing a recommendation does not delete users' shortcuts.

## New accounts

Ordinary registration, OIDC/Logto first signup and administrator-created accounts
capture the default list when the account is created. When the personal file
system is initialized, native share shortcuts appear in **My files**. The
snapshot remains fixed even if settings change before the first login. An
inactive account retains its pending snapshot until activation.

These entries are links, not copies of shared files. Source ownership, storage,
quota, ACLs and link lifecycle remain unchanged. Password-protected or otherwise
restricted sources do not expose protected names or embed passwords in redirects.
Opening them still uses the native gates. Deleted, expired or structurally
unavailable links are skipped; database errors roll back initialization and can
be retried. Existing installations without a snapshot receive no automatic
backfill.

Users can rename, move or delete their shortcuts. Login, list refresh, group
changes, identity linking and later settings changes do not reinstall them.

## Adding current recommendations

Signed-in users can choose **Settings → Preferences → Add site default shares**.
This explicitly adds the administrator's **current** recommendations, including
for old accounts. It does not restore the account's historical onboarding list.

Only currently public, valid and browsable links qualify. Password-protected,
revoked, expired and create-only links are skipped. The server checks current
configuration and authorization again inside the write transaction. Removed
recommendations cannot be added by a stale request; newly configured links can
be added on the next request.

Existing root shortcuts are detected throughout the user's active personal file
system, including renamed, moved or manually saved entries. Different links to
the same source remain independent. A deleted shortcut may be added again;
entries in the trash are preserved and do not count as active shortcuts. No
existing files are overwritten, moved or removed. Filename conflicts receive a
safe suffix. The result reports only added, already present and skipped counts.

## Interfaces and persistence

The administrator setting `default_symbolics` retains the existing JSON array of
positive numeric dashboard IDs. Public hashed IDs are not interchangeable with
these IDs. The additive `default_symbolics_identities` setting binds configured
IDs to their original creation times; user JSON stores automatic eligibility,
the immutable candidate snapshot and its completion state. Older users lacking
this state remain ineligible for automatic installation. No Ent table or schema
version is added. These lifecycle rules are fork policy, not a claim about
private Pro database compatibility.

`POST /api/v4/user/setting/default-shares` accepts no target IDs or account
selection. It requires native login plus `UserInfo.Read`, `UserInfo.Write` and
`Files.Write` scopes. It returns the native `code/msg/data` envelope with
`added`, `existing` and `skipped` counts. Treat nonzero business codes as errors,
even with HTTP 200. It grants no new access to share content.

Provisioning serializes with existing owner fences; explicit installation also
serializes with configuration saves. Shortcut writes, completion and native
audit records commit together. File notifications publish after commit. Stable
identity checks reject reuse of a configured or installed share's numeric ID.
Already issued provider URLs retain their native expiry behavior.

## Verification

The primary seam is the real production HTTP router, native authentication and
Ent. Reuse the existing disposable SeaweedFS fixture by setting
`CLOUDREVE_STORAGE_INTEGRATION=1` and `CLOUDREVE_S3_TEST_SERVER` to an owned `weed`
executable, then run:

```sh
go test -race -count=1 -timeout=8m ./routers/controllers -run '^TestDefaultShares'
go test -race ./inventory ./pkg/filemanager/manager ./pkg/filemanager/workflows ./pkg/queue
go build ./...
```

Use the existing `OIDC_TEST_DRIVER=postgres|mysql` and `OIDC_TEST_DSN` conventions
for disposable PostgreSQL, MySQL or MariaDB instances. Never use production
credentials or databases. In the independent frontend repository run
`node --test tests/*.test.mjs` and `pnpm run build`.

`TestDefaultSharesBrowserRuntime` is opt-in with
`CLOUDREVE_DEFAULT_SHARES_BROWSER_DIR`. It serves the embedded production frontend
and native backend at loopback port 5212 and writes disposable credentials to an
ignored 0600 file. Stop the owned fixture with SIGINT after browser acceptance.
The upstream CI, build helpers and container entrypoint are unchanged.
