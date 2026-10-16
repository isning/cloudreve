# File permissions and automatic share discovery

This feature extends [writable sharing](writable-sharing.md) through the existing
community frontend, share navigator, JSON properties, native HTTP APIs and Ent.
It adds permission management, optional ACL-based **Shared with me**, and
current-permission checks for live events, deferred operations and final writes.
There is no new ACL table or owner-independent filesystem.

## Compatibility boundary

The official [permission concepts](https://docs.cloudreve.org/en/usage/concept#file-permission),
[Boolsets](https://docs.cloudreve.org/en/api/boolset),
[set API](https://cloudrevev4.apifox.cn/set-permission-306544347e0.md),
[clear API](https://cloudrevev4.apifox.cn/delete-permission-setting-306554896e0.md)
and [PermissionSetting schema](https://cloudrevev4.apifox.cn/permissionsetting-164028472d0.md)
confirm the six operation bits, explicit ACLs, nearest-ancestor inheritance,
link-root overrides and owner/admin management. Official
[4.19 release notes](https://github.com/cloudreve/cloudreve/releases/tag/4.19.0)
and [issue 3553](https://github.com/cloudreve/cloudreve/issues/3553), together with
the publicly served Pro 4.19.1 client, establish the `shared_with_me_acl` setting.
The client describes ACL mode as accessible valid share links, including public
links. Its navigation continues through ordinary share URIs.

The exact private Pro matcher, discovery DTO, protected-link enumeration,
delegation/transfer edge cases and event authorization were not measured.
The policies below are this fork's explicit behavior. `permission_context`,
virtual catalog identities and data-free SSE `refresh` are additive CCSN
extensions. No claim is made about importing private Pro database layouts.
Unverified group bits 15/16 are not enabled.

## Managing permissions

Owners and administrators can open **Permissions** from a file/folder action
menu or Details. A mixed selection supports atomic replacement and clearing.
An inherited editor requires explicit opt-in before saving; inspecting or
cancelling does not create an ACL. Clearing removes only the selected objects'
settings, preserving descendants' explicit rules. Available user/group names
are shown alongside opaque IDs; unresolved subjects survive unrelated edits.

The editor checks every selected object's identity when loading and before
replacing or clearing permissions. A missing, replaced or no longer manageable
target closes the editor without submitting the batch. Ordinary list refreshes
preserve drafts for unchanged objects; temporary request failures allow retry.
The final write also carries the original object IDs, so a replacement after
the editor's last check cannot receive the old object's draft. An identity
conflict closes the editor and reloads the current list.

| Bit | Operation | Example mask |
| --- | --- | --- |
| 0 | Read content; also permits listing for legacy clients | `AQ==` |
| 1 | Update existing content and permitted metadata | `Ag==` |
| 2 | Create new objects | `BA==` |
| 3 | Delete | `CA==` |
| 4 | Create an independent delegated share | `EA==` |
| 5 | List names/details without reading originals | `IA==` |

Read-only is `IQ==`; all six bits are `Pw==`; explicit denial is `AA==`.
A missing rule differs from an explicit zero. Within one ACL, matching uses a
named user, named group, same/other group relative to the actual file owner,
then `everyone`. Anonymous users use `anonymous`, then `everyone`. A matched
zero stops fallback. An explicit empty object retains the existing full-access
fallback; an unset legacy share retains read-only defaults. These exact
precedence/default choices are fork policy.

Inside a share, the nearest explicit child/ancestor ACL replaces inherited
permissions. The link replaces its root's file ACL, including single-file
shares; it does not intersect every descendant with the root mask. Independent
links establish independent roots. Actual owners and administrators retain
full access. A link creator retains the existing root-management exception;
that does not make the creator an owner of foreign descendants. Update/share
grants do not permit editing file ACLs. Ordinary users still cannot open another
user's `my` filesystem just because an ACL names them.

Native group permissions for creating/visiting shares still apply. Group bit 14
controls assigning new elevated anonymous grants; switching it off preserves
existing grants and permits their retention or reduction. Private collection
(`BA==`) stays create-only: known URLs accept new submissions, while existing
submissions remain hidden and cannot be read, overwritten, renamed or deleted.
New-file creation and overwriting are checked separately.

## Public HTTP interfaces

All paths are relative to `/api/v4`. Native authentication, scopes and the
`code/msg/data` envelope remain authoritative; nonzero business codes are
failures even with HTTP 200.

| Interface | Behavior |
| --- | --- |
| `POST /file/permission` | `{uris, setting}` replaces explicit ACLs; 1–1000 targets; duplicate objects deduplicated; whole batch atomic |
| `DELETE /file/permission` | `{uris}` restores inheritance on selected targets |
| `GET /file/info?uri=...&extended=true` | Owner/admin `extended_info.permissions` is the explicit setting; optional `permission_context` explains this entry |
| Ordinary file responses | Singular `permission` is the current viewer's effective mask, intersected with native operation capabilities in clients |
| `GET /file?uri=cloudreve://shared_with_me` | Manual shortcuts by default; authorized virtual link entries when ACL mode is enabled |
| `GET /file/events?uri=...` | Native authenticated directory SSE; requires a valid UUID `X-Cr-Client-Id` |

Both permission write methods accept an optional CCSN `expected_ids` array of
encoded file IDs, aligned one-to-one with `uris`, including repeated inputs.
The editor supplies these original identities. The server checks the entire
selection under its existing canonical locks and owner-fenced transaction,
before changing any rule or adding an audit row. A replaced target or conflicting
duplicate expectation returns native business code 409; malformed IDs or a count
mismatch return 40001. Omitted or null expectations keep the legacy URI-based
contract. This is an object-identity precondition and does not authorize access
or act as an ACL revision check.

ACL maps use public hashed user/group IDs and Base64 masks. Invalid kinds,
malformed masks, unknown bits, more than 256 named rules, null settings or
oversized target batches are rejected without partial mutation. Unknown but
well-formed subject IDs round-trip. No-change saves create no false ACL activity.

The optional manager-only `permission_context` identifies the CCSN extension,
source category, safe source URI, matched rule, effective mask and whether the
answer depends on the entry. Share references stay inside that share and omit
passwords. A personal view with independent links does not claim a single
global grant. Ordinary recipients receive only their effective permissions.

## Configuring Shared with me

In **Admin → File system**, select manual shortcut mode or ACL mode. The existing
setting key is `shared_with_me_acl`, stored as `"0"`/`"1"`; absence means manual
mode. Native admin settings update supports this additive key on old databases.
The explorer configuration exposes the corresponding boolean. Switching modes
does not delete saved shortcuts.

ACL mode lists currently accessible valid links, including `everyone` grants,
with one stable virtual entry per link. Two links to one file remain distinct.
Create-only links are excluded from automatic read/list discovery. Password
links can appear as locked, minimal entries but require the native password
flow; discovery never inserts a password into their redirect. Existing purchase
and other link gates remain in force.

Entries use the original share URI, not a canonical owner path. They are neither
owned files nor writable shortcuts; their menu offers entry/link navigation.
Single-file links open the native single-file view. Expired/exhausted/deleted
links, invalid source ancestry, trash, inactive owners/creators and current group
restrictions are checked before access. A saved catalog row or shortcut grants
no independent authority.

A request scans at most 1000 candidates in batches of 100. Sparse grants may return
an empty page with a continuation. The frontend automatically continues up to
four pages, then offers **Continue finding shares**. Cursors are encrypted and
bound to the account, mode, filters and sort context; they expose no denied IDs
or global counts. Name/creation-time sort in both directions and supported
native name/type filters are available. Unsupported catalog sorts/filters are
rejected; saved manual-only sorting is normalized in ACL mode without rewriting
its preference. Results under concurrent writes are weakly consistent; refresh
rechecks current authority. No whole-site ACL index is materialized.

## Revocation, events and background work

Final writes reopen the original access entry using current actor, group, link,
file and ancestor permissions under owner-row transaction fences. This includes
share delegation, upload completion, metadata/version mutations and recursive
operations. Recursive work keeps the native group traversal limit. Owner view
updates merge fresh properties, preserving concurrent ACL changes. Audit changes
remain in the same transaction and file events publish only after commit.

Deleting share links rechecks the acting account's active status and current
group inside the fenced transaction. A demoted administrator cannot commit a
pending deletion of another owner's link. A mixed batch fails atomically if any
link is no longer manageable; creators and actual file owners retain their
ordinary management rights. Context-free inventory cleanup remains trusted.
An active administrator retains native personal-filesystem ACL management for
inactive owners. This exception uses the current actor at the transaction fence
and does not revive an inactive owner's share link.

Same-owner moves/copies preserve explicit ACLs and recompute inheritance.
Cross-owner transfers discard source ACLs and pending-upload capabilities; the
receiver retains ownership, capacity accounting and storage preference. Exact
pending-upload cancellation and accepted receiver-owned housekeeping remain
possible after link revocation or worker restart.

Original downloads, thumbnails, archives, versions, supported WebDAV roots and
WOPI writes use current context-specific grants. A provider thumbnail path that
signs the original requires read permission; list-only access may use an
independent thumbnail entity. It cannot fall back to an original-object URL.
Already issued provider URLs remain valid until their native expiry; changing
one ACL does not revoke every independent delegated link or permanent capability.

SSE filtering runs before queueing and again before send/replay. Shared events
reveal only currently listable identities/paths. Historical deleted or hidden
locations are not sent; visible rename/move arrivals can be represented as
creates. Every 30 seconds, a still-authorized shared subscriber receives
`event: refresh` with `{}` and the normal heartbeat, independently of hidden
mutations. The frontend reconciles an authorized listing, coalescing reloads.
Root/account/group denial ends an existing stream; native JWT expiry has its own
exact timer. Authorization failures clear cached list/tree/actions; account and
directory generations discard stale requests. Successful listings also reconcile
selected files and explicit menu targets by path and object identity, updating
their grants and discarding missing or recreated objects. Appended pages preserve
earlier selections. Native HTTP 200 authentication/service error envelopes retry
SSE after five seconds with current credentials; list reloads still clear revoked
roots and cancel their subscriptions.

Desktop and mobile Details share one authorization-snapshot controller, binding
the account, target object and accepted list.
Refreshing a list immediately invalidates old sidebar actions while current
extended information loads. Editors for the same target stay mounted, preserving
permission and property drafts while save controls are disabled. Confirmed
account/object changes or denial discard that editor. Permission downgrades
update property, version and entity-download actions; denied or recreated targets
close the sidebar. Replies and save callbacks from earlier views cannot restore
old grants. A local thumbnail-failure hint survives detail revalidation for the
same object and content version, preventing failed thumbnails from repeatedly
invalidating the list. A fresh HTTP listing or new content allows a retry.
SSE subscribes only after the current path's listing is accepted, and deep-link
viewer/readme completion uses that accepted listing rather than a superseded
request promise.

Resume keys bind account, bearer credential, client UUID, original entry and
canonical root. Active duplicates cannot take over a stream. Offline history is
current-authorized on replay and bounded: 16 channel slots, 256 pending events,
256 persisted rows per context, 4096 per user and 64 in-memory contexts per user.
Overflow collapses to a data-free refresh. Recent durable history survives restart;
legacy incompatible resume keys cannot adopt it. Diagnostics use reason codes,
request correlation and opaque subscriber IDs; filtered payloads and detached
SQL path arguments are omitted. Password-bearing URI query strings are excluded
from HTTP request logs.

## Verification and maintenance

The primary seam is the public native HTTP/SSE router, real Ent, a disposable
S3 service and independently restartable application/workers. Browser acceptance
supplements it; database tests boot existing installations twice. SQLite,
PostgreSQL, MySQL 8.4 and MariaDB 11.4 were exercised. This is an explicit local
matrix, not a new CI guarantee. No schema/version marker is introduced; old JSON
ACLs, explicit zeros, empty settings, shortcuts and the absent-mode default survive.

Provide `weed` or set `CLOUDREVE_S3_TEST_SERVER` to a SeaweedFS executable and set
`CLOUDREVE_STORAGE_INTEGRATION=1` so storage acceptance cannot silently skip:

```sh
go test -race -count=1 -timeout=15m ./routers/controllers -run '^TestFilePermissions'
go test -race -count=1 -timeout=8m ./routers/controllers -run '^TestWritableShare'
go generate ./ent
git diff --exit-code -- ent
```

From the independent frontend repository, run
`node --test tests/*.test.mjs` for
configuration/list ordering, revocation during tree loads, cache invalidation,
share pagination, action-target reconciliation, sidebar response ordering,
deep-link navigation and SSE recovery/cleanup. These checks execute production
thunks, URI/permission handling, Redux reducers, event and navigation hooks and
desktop and mobile sidebar components with controlled HTTP promises and timers.
The component harness also covers delayed request-code initialization through
the router import cycle. Native browser checks additionally hold a successful
HTTP response across root revocation,
verify that an accessible root drops denied children and cached actions on
refresh, invalidate Details actions after downgrading or denying a child,
preserve an unchanged target's editor draft while a real refresh response is held,
and open a deep-linked native viewer when the first real listing is delayed.
They also recover a native HTTP
200/401 event subscription without changing the account, path or root.
Native SSE regressions preserve owner/admin rename and delete events, then
verify descendant filtering after an administrator loses that role. Native
share-deletion regressions pause single and mixed-batch requests before the
transaction fence, demote or disable the
actor, and verify denial without partial deletion, alongside normal owner,
creator and trusted cleanup paths.
Native ACL checks also preserve administration of inactive owners through
personal URIs while rejecting stale administrator roles and disabled actors,
including an owner disabled during a request through a share URI.

For external databases, use the existing `OIDC_TEST_DRIVER=postgres|mysql` and
`OIDC_TEST_DSN` fixture convention with a disposable server/account allowed to
create isolated test databases. MariaDB uses the native MySQL driver. Do not
point these integration fixtures at production data.

`TestFilePermissionsBrowserRuntime` is opt-in via
`CLOUDREVE_PERMISSION_BROWSER_DIR`. It serves the production embedded frontend
and writes disposable fixture credentials to a 0600 ignored file. The optional
`CLOUDREVE_PERMISSION_BROWSER_ORIGIN` supports a separate community dev server.
`TestStorageRuntimeImageWorkflow` accepts `CLOUDREVE_STORAGE_IMAGE` plus the
optional `CLOUDREVE_CONTAINER_ENGINE`; it verifies packaged native authentication,
ACL discovery, permitted/denied real S3 bytes, relocation and graceful application
shutdown. Use the unchanged official Dockerfile and matching versioned frontend.

One local race-enabled scale sample over 1100 denied candidates scanned 1000 rows
in 354 ms with 69 Ent queries and a 5.48 MB allocation delta. The public-link sample
returned 10 entries after 100 prefetched candidates in 47 ms with 14 queries and
0.69 MB allocated. These are one-shot local observations, not throughput promises.

The frontend's native Vite production build succeeds. TypeScript retains 114
pre-existing errors; focused ESLint comparison reports no added findings after
this feature. Whole-repository Go testing is not globally green: unchanged
legacy tests in `pkg/conf`, `pkg/cache` and `pkg/request` reference removed APIs
or obsolete signatures. These exceptions are recorded separately from the
feature's required HTTP/race/database/browser/image checks; no rule is disabled
and unrelated tests are not rewritten to conceal them.

Frontend code remains in the independent `assets` repository and the backend
records its commit through the existing submodule. No upstream CI, Dockerfile,
build helper or container entrypoint is changed. Local validation uses a
`4.19.1-ccsn-dev` build identifier; it creates no release tag. The next explicitly
requested release can use `4.19.1-ccsn.1` (then increment the CCSN suffix), as
already agreed. This implementation does not push, publish an image or deploy.
