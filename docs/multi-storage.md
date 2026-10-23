# Multiple storage policies and relocation

This community fork supports ordered group storage grants, per-upload selection,
directory placement and relocation of existing file entities. Keep the pinned
`assets` submodule: its source lives in the separate `isning/cloudreve-frontend`
fork. Build it with `bash .build/build-assets.sh <version>`, then build the
backend. Backend and frontend must be deployed together.

## Configure and use

1. Create ordinary Cloudreve storage policies with working read/write/delete
   credentials. For S3, configure the endpoint, region, bucket and addressing
   mode for your provider. Store production credentials through the normal
   administrator settings; examples below contain no credentials.
2. Edit a user group, select **Available storage policies**, and order them. The
   first entry is the automatic default. Enable **Relocate storage policy** only
   for groups permitted to move existing content.
3. Members can select a policy in the upload dialog, or use **Bind storage
   policy** on an owned ordinary folder. Explicit upload selection wins;
   automatic placement uses the file's future preference, then the nearest
   bound ancestor, then the first current grant. An invalid/revoked preference
   falls back to that first grant. A database or provider failure is an error,
   never a reason to silently write into another bucket.
4. **Relocate storage policy** moves existing content to the selected policy.
   Follow **Background Tasks** for the native task's progress and result.
   Personal-root relocation is an explicit rule of this project. Root binding,
   foreign/shared/trash/symbolic-folder binding are unavailable.

Binding controls future writes; relocation controls existing entity bytes.
Relocation does **not** alter file preferences or directory bindings. Uploading
again into a folder bound to A still uses A after its existing files moved to B.
An already-issued native upload retains its accepted destination and expiration,
even if the group grants change before completion.

## HTTP compatibility

Member-facing policy IDs are Cloudreve encoded IDs, not administrator numeric
IDs. Public policy descriptors omit provider credentials.

| Operation | Public endpoint | Payload or result |
| --- | --- | --- |
| Available policies | `GET /api/v4/user/setting/policies` | Ordered safe policy descriptors |
| Bind owned ordinary folder | `PATCH /api/v4/file/policy` | `{"uri":"cloudreve://my/folder","policy_id":"<encoded-id>"}` |
| Create upload session | `PUT /api/v4/file/upload` | Existing native fields plus optional `policy_id`; omitted/null/empty means automatic |
| Relocate | `POST /api/v4/workflow/reloacte` | `{"src":["cloudreve://my/folder"],"dst_policy_id":"<encoded-id>"}` |

`reloacte` intentionally retains the official client's spelling. Existing native
workflow APIs provide task history, stages and progress. The admin group save
adds a **project extension**, sibling `policy_ids` next to `group`, containing
ordered numeric IDs: `{"group":{...},"policy_ids":[1,2]}`. It rejects null, empty,
duplicate or unknown lists. Legacy saves omitting this field preserve grants;
a legacy default change makes its new default first while retaining other
valid grants. This implementation does not promise import/export or direct
migration of Cloudreve Pro databases.

## What moves and what remains

The worker snapshots the complete accepted recursive scope before its first
provider I/O. Overlapping selections are deduplicated. Later additions are not
in that snapshot. Every selected file version, thumbnail and Live Photo
companion moves as raw bytes; encryption metadata and original ciphertext are
preserved. Destination encryption settings do not re-encrypt the content.
Length and SHA-256 readback verify the new object before references switch.

File IDs, names, logical size, timestamps, version counts, share/permanent-link
identity and logical storage usage remain unchanged. If unselected copies share
an Entity, only selected references move to a new Entity; version Entity IDs
can therefore change. Clients must reopen file/version details rather than
reuse old Entity IDs or provider URLs. Current file downloads, thumbnails,
versions and permanent links resolve the committed location. Previously issued
provider URLs remain subject to that provider's expiry and source collection;
they have no unlimited lifetime guarantee after relocation.

## Recovery and operations

Native queues resume durable work on restart. Temporary credential/provider
errors use bounded automatic retries; an administrator can repair credentials
or ACLs through existing settings. Each attempt has its own server-owned key
and fenced claim. Fully verified committed files stay committed if other
items fail: a failed task can represent partial success. Inspect its completed,
failed and byte counters and the surviving files before submitting a new task.
There is no public relocation cancellation or manual retry control.

Compensation has independent durable records and native maintenance jobs.
Deleting terminal task history or an account does not discard unfinished
cleanup, nor can restart recreate a deleted file/account. Old sources are
collected only when no current physical alias/reference or active migration
reader requires them. Completed migration reads retain their exact acknowledgement in the originating process and retry temporary SQL failures. Graceful shutdown drains these acknowledgements before closing SQL. A crash before acknowledgement can still leave a conservatively unfinished reader; replacement startup or lease expiry is not proof that another reader has stopped. Failed targets are deleted only at exact server-owned
attempt locations. An unknown write can finish late; its journal stays pending
and is checked repeatedly even after an earlier absence/delete. Physical policy
edits/deletion remain blocked while this dependency is unresolved; credential
rotation is allowed. Do not manually discard these records to release a guard.

Run one active **master**. The fencing protections cover worker recovery and
competing claims; they do not claim supported multi-master deployment or slave
relocation. In Kubernetes use a single master replica with durable database and
configuration, and keep its native queues enabled. S3 stores objects; it does
not replace the SQL database. Follow the site's normal database backup and
upgrade procedures. Schema additions are automatic, additive and restartable.

## Verification and known boundaries

The implementation uses generic Cloudreve driver Put/read/delete operations.
Local acceptance exercises real SeaweedFS S3 4.47 with independent buckets,
S3-to-local relocation, native HTTP/authentication, raw encrypted/media bytes,
worker restart, late writes, permission changes, shared references and cleanup.
These results are not certification of every Cloudreve driver or every S3
provider; test your endpoint and lifecycle rules before rollout.

Database acceptance uses real SQLite plus PostgreSQL 17.11, MySQL 8.4.11 and
MariaDB 11.4.12 for grants, upgrades, transaction recovery and competing workers.
CI declares its own pinned database image versions separately. Production
browser checks use the built community frontend; HTTP-boundary UI regressions
and native backend/S3 browser workflows are distinct gates. Run the storage
verification stages documented in `docs/multi-storage-release.md`.

Existing source-pinned upstream TypeScript/test exceptions remain explicit;
new diagnostics are rejected. No Pro database parity, multi-master guarantee,
provider URL lease, or public cancel/manual-retry behavior is implied.
