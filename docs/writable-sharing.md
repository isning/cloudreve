# Writable shares and anonymous collection

This fork independently implements the public Cloudreve Pro writable-sharing
contract, using the community frontend and the existing file manager, upload
drivers and share URLs. References include the official [share create API](https://cloudrevev4.apifox.cn/create-share-link-306853462e0.md),
[share info API](https://cloudrevev4.apifox.cn/get-share-link-info-306869986e0.md),
[permission setting schema](https://cloudrevev4.apifox.cn/permissionsetting-164028472d0.md),
[file permission documentation](https://docs.cloudreve.org/en/usage/concept#file-permission),
[Boolset definitions](https://docs.cloudreve.org/en/api/boolset), and the publicly
served Pro 4.19.1 frontend. Compatibility refers to these public interfaces;
private Pro storage layouts and imports of Pro permission databases are not
part of this implementation.

## Using it

The ordinary share dialog offers read-only access, authenticated collaboration,
public collaboration, and private collection. Advanced permissions can select
individual users and groups. File owners and administrators can change child
permissions through **View details → Permissions**, or restore inheritance.
See [file permissions and automatic discovery](file-permissions.md) for batch
management, ACL-based Shared with me, and current-permission event handling.

Public collaboration permits anonymous upload, rename, overwrite and deletion.
Enable group permission 14, **Give anonymous visitors permissions beyond read**,
for users who should create these links. Changing that group permission does
not revoke previously assigned anonymous grants. Group permission 2 still
controls creating links; group permission 7 controls visiting other people's
shares and takes precedence over ACL grants. File owners, share creators and
administrators retain their management access.

**Private collection is an extension of this fork.** The official public client
confirms anonymous upload but does not offer a private dropbox preset. The
extension uses the ordinary ACL representation (`BA==`, create only). Visitors
can submit new files and directory uploads. They receive an empty navigational
listing and cannot inspect, download, overwrite, rename or delete submissions,
including their own completed files. Native filename-conflict checks still
apply. There are no new registration forms, per-visitor folders, receipt IDs or
visitor-account sessions.

## Wire contract

All endpoints are relative to `/api/v4`, retain native authentication/scopes and
return the native `code`, `msg`, `data` envelope. A nonzero business code is an
error even when the transport status is HTTP 200.

| Interface | Contract |
| --- | --- |
| `PUT /share`, `POST /share/{id}` | Existing body plus `permissions: PermissionSetting`; return the share URL |
| `GET /share/info/{id}` | `permissions` is the visitor's effective Boolset; `permission_setting` is the manager's full ACL |
| File response | `permission` is the effective Boolset; `extended_info.permissions` is the explicit file ACL for owner/admin |
| `POST /file/permission` | `{uris: string[], setting: PermissionSetting}`; owner/admin only |
| `DELETE /file/permission` | `{uris: string[]}`; clear the explicit ACL and restore inheritance |
| `GET /user/search?keyword=...` | Existing authenticated user picker |
| `GET /group/list` | Authenticated group picker, exposing public IDs and names only |
| Native upload APIs and callbacks | Existing share URI, upload session, relay/direct upload and cancellation protocols |

```typescript
interface PermissionSetting {
  user_explicit?: Record<string, string>;
  group_explicit?: Record<string, string>;
  same_group?: string;
  other?: string;
  anonymous?: string;
  everyone?: string;
}
```

Map keys are public hashed user/group IDs. Values are Base64 Boolsets, with
bits 0 through 5 representing **read, update, create, delete, share, list**.
Read also permits listing, preserving compatibility with older five-bit
clients. New links and legacy links with no ACL default to read+list (`IQ==`).
Read-only clients that omit permissions when editing preserve an existing ACL.

Matching chooses a named user, then a named group, then same/other group, then
`everyone`. Anonymous visitors use `anonymous`, falling back to `everyone`.
Same/other group compares against the actual file owner's group. Missing
`everyone` means all six permissions (`Pw==`); an explicitly present `AA==`
means no access. Matching precedence is an independent implementation inferred
from the public permission editor's audience ordering; the private Pro matcher
was not measured. Inputs reject unknown bits, malformed IDs and oversized rule
maps.

A child inherits its nearest explicit file or ancestor ACL. The link ACL
replaces the shared root's file ACL, including single-file shares. File owners
and administrators bypass file ACLs; writable visitors cannot edit the ACL
itself. Permissions and capabilities are checked for each target and descendant
operation, including copy/move, versions, thumbnails and content editors.
Single-file links expose only that file; their artificial navigational parent
cannot authorize creating siblings or sharing the real parent directory.

## Ownership and lifecycle

Uploads remain owned by the receiving **file owner**, use that owner's policy
and quota, and preserve the visitor as entity creator/audit actor. Anonymous
actors have no public account identity. Upload storage paths are generated
from the receiver's canonical directory, avoiding collisions between share
links. A visitor's personal quota or preferred policy does not redirect shared
uploads. Cross-owner copies preserve existing physical entities, while future
versions use the destination's policy preference; moves account for both
owners transactionally.
Media metadata and indexing jobs use the receiver's identity and canonical
file paths, so deleting a share does not strand those jobs after a restart.

The share permission allows authenticated visitors to create independent links
in their own name. The underlying files retain their original owner. This fork
allows the original file owner, share creator or administrator to manage a
delegated link. The file's share-management dialog lists its links with their
actual creators. Deleting an originating link does not cascade to independent
links created through it; the file owner can revoke those separately. These
management/lifecycle rules are explicit fork policy: public Pro sources do not
fully specify delegated-link revocation behavior.
Deleting a delegating account removes that account's links while preserving the
receiving owner's files and links.

Each share request rechecks the link, expiry, password, group access and current
ACL. Share navigation does not restore cached authorization from context hints.
Upload start distinguishes creating a new file from replacing an existing one;
the latter requires update permission. Relay chunks and final callbacks recheck
the uploader, live file/entity/session tuple and current permissions before
committing. ACL changes prevent later requests and completion; they cannot
recall already issued provider URLs before those URLs expire.

An anonymous upload UUID authorizes that single upload and must be kept private.
It is omitted from metadata returned to other visitors. Authenticated uploads
also bind the initiating account; a different account cannot cancel them.
Cancellation can remove only the matching pending entity, without requiring
general delete access. It remains possible after link revocation or expiry.
Persisted timeout tasks belong to the receiver and use the durable file ID and
canonical owner path, so cleanup survives deleted links and worker restarts.
Cancellation and completion serialize their pending-entity mutation; stale
timeout tasks cannot delete committed content.
If a provider abort fails after database cleanup, the unreferenced entity's
still-pending UUID permits a later abort retry. A completed entity has no pending
UUID and cannot authorize provider cancellation.

## Storage and verification

ACLs reuse the existing JSON file/share properties. No new Ent tables or schema
version changes are required. Missing properties retain existing personal-file
access and read-only share behavior. ACL mutations emit audit event 9 in the
same transaction; existing audit flags and file-activity redaction apply.

Uploads use the common native driver interface. Local relay and direct/relay S3
paths have end-to-end regression coverage. Other drivers retain their native
upload and callback protocols; their individual external services were not
exercised by this acceptance run.

The principal boundary is the production HTTP router with native authentication,
real Ent and a disposable S3 service. Set `CLOUDREVE_STORAGE_INTEGRATION=1` and
`CLOUDREVE_S3_TEST_SERVER=/path/to/weed`, then run:

```sh
go test -race -count=1 -timeout=30m ./routers/controllers -run '^(TestWritableShare|TestAudit|TestStorage)'
go test -race ./inventory ./pkg/queue ./pkg/filemanager/manager ./pkg/filemanager/workflows
go build ./...
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -o .scratch/writable-sharing-armv7 .
```

The existing `OIDC_TEST_DRIVER` / `OIDC_TEST_DSN` fixtures can target an owned
PostgreSQL or MySQL database. Local acceptance uses SQLite; those database
servers were not exercised here. Frontend work remains in the independent
`assets` submodule, built with its native `pnpm run build`. Upstream release
and CI components are unchanged.
