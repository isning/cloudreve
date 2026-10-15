# Audit logs and file activity

This extension independently implements the public Cloudreve Pro event contract
in this fork. The references are the [official activity API](https://cloudrevev4.apifox.cn/list-file-activities-300250878e0),
its activity/LogEntry schemas, and the publicly served Pro 4.19.1 client's
administrative request/response shapes. Private Pro database layouts and
imports of existing Pro audit databases are outside this contract.

## Configuration and storage

The existing administrator **Settings → Events** page controls the two Pro
settings: `audit_enabled_flags` (Base64 Boolset, event number equals bit index)
and `audit_record_ip` (`1` or `0`). This implementation initially enables all
62 known event numbers and IP recording; these are local defaults, not a claim
about Pro's defaults. Set all flags off to stop recording. Changes take effect
across replicas without restarting them.

The startup migration creates `audit_logs`, `audit_archives`, and
`audit_archive_items`. It preserves existing accounts, storage, upstream schema
version markers and administrator settings. Back up the database before any
application upgrade. Event IDs retain their historical actor/object identifiers
when accounts, files, versions or shares are removed. Linked objects are
projected only while they exist; credentials and entity encryption metadata are
never embedded in audit responses.

File mutations record their event inside their inventory transaction. Account,
share, WebDAV credential and OAuth grant mutations do the same. Migration
events commit with the migration journal; archive/extraction events commit
with the native task's first completed transition. Failed writes therefore do
not produce successful mutation records. Read events mean an authorized access
or download URL was issued; they do not prove that every byte reached a client.

Archive and extraction tasks save the consumed source file IDs and canonical
paths in their durable state. Renaming or reusing a source path cannot redirect
the completion event to another file. Tasks already past source consumption
before this upgrade have no such snapshot; their completion records retain the
historical path without guessing an object association. Stale worker updates
cannot reopen completed audited tasks or emit their completion events again.
Completion and its audit records commit before temporary files are cleaned up
or success is counted. Failed completion commits retry in the current worker
without repeating finished I/O; shutdown preserves pending state and temporary
recovery files for the native restart flow.

The 0–61 catalog is shared with Pro. Existing fork operations emit the matching
events, including native/OIDC login, security changes, files, shares, versions,
storage migration, WebDAV, OAuth, mail and startup. [File ACL changes](writable-sharing.md)
emit event 9. Event numbers belonging to
other Pro modules (payments, memberships and abuse reports) are reserved;
enabling a flag does not add those unrelated modules.

## Public interfaces

All ordinary endpoints use the native `code`, `msg`, `data` response envelope.

| Method | `/api/v4` path | Purpose |
| --- | --- | --- |
| POST | `/admin/event` | One-based pagination, ID/time ordering, actor/IP/category/correlation/file filters |
| GET | `/admin/event/{id}` | Administrative event detail |
| POST | `/admin/event/batch/delete` | Permanently remove selected numeric IDs |
| POST | `/admin/event/cleanup` | Remove events through `not_after`, optionally restricted by categories |
| POST | `/admin/event/archive` | Export date/category snapshot; returns `id`, `url`, `expires` |
| GET | `/admin/event/archive/{id}/status` | `pending`, `completed` or `failed` |
| DELETE | `/admin/event/archive/{id}` | Remove exactly the records in a completed, unexpired export |
| GET | `/file/activities` | Authorized per-file cursor history and filters |

Administrative reads require native administrator access and `Admin.Read`;
mutations additionally require `Admin.Write`. File activities resolve the URI
through the normal file navigator and require an authenticated owner or update
permission. Read-only shares cannot expose history. History applies to the
selected object, not an unrestricted recursive folder feed. IPs, user agents,
authentication details and administrative payloads are excluded from this
response. Inaccessible path references become `redacted`. Deleted versions
lose their version links.

Activity filters are empty/all, `my`, `updates`, and `reads`. This implementation
treats download, share view and direct-link access as reads. Cursor tokens use
HMAC authentication, bind the file, viewer, filter and direction, and fix the
upper event ID so later writes do not shift existing pages.

## Export and retention

Export uses gzip-compressed NDJSON, streamed in bounded batches. This format
is an independent choice: the public client does not prescribe an archive
format. No replica-local persistent volume or in-memory export job is needed.
The one-use download URL expires after one hour; it is a capability URL because
Pro downloads through an iframe without a bearer header. Its random token is
stored as a hash, omitted from request logs, and checked together with the
export creator's current administrator status.

Only a fully written export can be purged. Explicit archive membership protects
concurrent and later records from deletion. A disconnected or failed export
cannot authorize deletion. The browser asks for a separate confirmation after
the operator has saved and verified the downloaded file. No automatic retention
deletion is enabled; use cleanup or export/purge according to your retention
policy. Expired export metadata is reclaimed when the next export is created.

## Verification

The main regression boundary is the native HTTP API with real Ent and a
disposable S3 service. Set `CLOUDREVE_STORAGE_INTEGRATION=1` and
`CLOUDREVE_S3_TEST_SERVER=/path/to/weed`, then run:

```sh
go test -count=1 -timeout=10m ./routers/controllers -run '^TestAudit'
go test -count=1 ./inventory -run '^TestAudit'
go test -race ./inventory ./pkg/queue ./pkg/filemanager/workflows
go build ./...
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -o .scratch/audit-armv7 .
```

As with the existing storage tests, `OIDC_TEST_DRIVER` and `OIDC_TEST_DSN` can
select an owned PostgreSQL/MySQL test database. The frontend remains the
independent `assets` Git submodule. Build it with its normal `pnpm run build`;
continue using the upstream release workflow.

Acceptance checks on 2026-10-15 covered SQLite migrations, real S3 HTTP flows,
archive-worker restarts, native/OIDC/Logto authentication regressions, desktop
and mobile browser flows, frontend build/lint, and native/ARMv7 Go builds. The
frontend's existing 114 TypeScript diagnostics were compared against its pinned
baseline with the same compiler; this change adds none. PostgreSQL/MySQL test
helpers are available above, but those database servers were not exercised in
this local acceptance run.
