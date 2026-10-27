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
duplicate or unknown lists; the system anonymous group may keep an empty list.
Creating a group requires this list. Updates omitting it preserve current
grants. An ordinary group left unassigned by an upgrade can still edit other
settings without adding a storage grant. The upstream default field and edge are derived from its first entry,
and changing those display fields does not change authorization. Copying a group
loads its current detail and preserves the complete ordered list. Storage-policy
cards, details and save responses expose all directly assigned live groups
through the existing `edges.groups` field, including secondary policies.
This implementation does not promise import/export or direct
migration of Cloudreve Pro databases.

## Upgrade existing installations

The storage extension's versioned startup migration (`storage_extension_schema_v10`)
backfills a valid legacy single-policy default only when that group has no
ordered grants. Existing lists and their order are preserved; the upstream
default is synchronized to the first entry. Deleted groups and deleted policies
do not receive new grants. Obsolete grants retained by previously deleted groups
are released. A group with no valid destination stays unassigned.
The data changes and completion marker commit together. Failed migrations can
be retried; completed migrations do not replay after grants are removed.

After upgrade, ordered grants are the sole authority for available destinations,
group associations and grant-related deletion checks. Runtime requests do not
fall back to an old default. New installations use the native initialization
followed by this same migration. The existing v3 importer also writes its
selected default into the grant table. Group writes and policy deletion share
transactional lifecycle locks, including current-row reads on MySQL/MariaDB.
Deletion repeats the entity-use check under its policy lock, including completed
uploads committed after the HTTP precheck. Unchanged group updates also return
current transaction rows before writing canonical grants.
Group deletion rechecks membership under its exclusive group fence. Native signup
and administrator account writes hold the current destination group's shared
fence until commit; existing accounts take their user lock first and read the
previous account currently in that transaction, including pending caller rows.
Unchanged saves use the same current existence check. Deletion retains
pending and committed members without taking user locks after the group fence.
The existing occupied-group error code and translated member count are preserved.
Operations spanning multiple policies acquire locks by numeric ID, including
pool conversion, group assignment and relocation. Dependency checks after those
locks use current rows so earlier transaction snapshots cannot permit unsafe
pool conversion.
Storage-policy and group administration use native read-committed transactions
to avoid InnoDB gap-lock cycles between independent edits. Inherited transactions
retain their caller's options.
Storage-policy configuration writers first acquire one native settings-row lock,
then the policy locks. This serializes administrative membership changes, including
empty pools and conversions inside inherited transactions; upload placement does
not acquire this configuration lock. Callers composing policy configuration writes
in a transaction must perform them before other policy-locking operations.
New pools also skip deletion of nonexistent memberships. Share creation checks
its creator's current active status under the same owner lock.
Binding, upload acceptance and relocation planning/commit revalidate the current
owner group, canonical grant and pool membership under the lifecycle locks. This
final check also applies to inherited transactions whose ordinary reads retain an
older snapshot.
MySQL/MariaDB planning metadata uses a native Ent client with a separate bounded
connection pool when inheriting an older transaction view. Server clients reserve
four connections for nonlocking metadata within the existing total budget of 100;
the transaction pool uses the remaining 96. Closing the native client closes both
pools. This keeps copy and upload planning independent of occupied transaction
connections. SQLite reuses its transaction's sole connection.
A selected pool and its concrete member are revalidated
together, so a changed pool cannot authorize its former child through another pool.
Authorization fences for file writes recheck the current status of authenticated actors
and share owners under the existing owner locks, then shared-locks the complete
current group set in numeric order before policy locks. Native administrators retain access to
inactive owners through their personal filesystem; share entries require active owners.
Final permission navigation reads current links, file ACLs and account/group
metadata in that same transaction. Share creation collects source and existing
link creators before acquiring the sorted owner locks;
ordinary browsing keeps its existing query behavior.
Lifecycle locks verify existence through current reads, including rows committed
after an inherited transaction's snapshot and unchanged native updates.
Unchanged group, policy, share and folder-preference saves resolve typed native
not-found results through a current read in the accepting transaction; other
database errors propagate. Folder binding also reads its target and ancestry
currently under the owner fence.
Copy locks the complete recursive policy set in numeric order, then the complete
entity set in numeric order, before copying any layer. Policy locks are shared.
Physical object gates follow in sorted key order, including distinct entities
that alias the same objects through native imports.
Retirement checks use the current source associations; obsolete planning
references only contribute locks.
Retired preferences remain copyable; reference locks do not grant a destination
for future writes.
Copy enumerates current file rows under the owner fence. Reference planning
expands the same directory frontier in both the pending transaction view and
committed server metadata before locking entities; SQLite stays on its accepting
connection. Final source, entity,
metadata and object-gate reads use current rows in that same transaction.
Reference planning uses pages of at most 500 rows and locking precedes recursive permission navigation,
so InnoDB range locks are acquired after the complete entity set. Native current
permissions still decide whether the planned operation may proceed. The native
traversal validates the file count limit against the effective transaction scope
before copy writes, including when the caller owns the transaction;
obsolete reference metadata does not count as copied files. Permission checks and
copy traversal preserve the root slices used to remove cross-owner move sources.
Upload preparation takes its native path lock and owner fence before reading
current placement ancestry, including native thumbnail permission bypasses.
Upload acceptance and copy reservation use the receiving owner's current user
and group quota under those fences, including after cached navigation or an
inherited transaction snapshot. Quota changes apply immediately to new writes.
Writable shares charge the receiving owner. Recursive copies and cross-owner
moves validate their complete current byte budget before inserting destination
rows or reserving storage, so quota rejection leaves caller-owned work intact.
Pending directory bindings remain visible; committed
bindings and folders are not hidden by an inherited snapshot. Grant lists remain
planning metadata, with acceptance checked in the original transaction.
Physical imports resolve their policy inside that same accepting transaction,
including cache misses on SQLite's single connection.
Accepted placement keeps current node metadata and uses the same current policy
when creating its entity. Share deletion rechecks current actor, group and link
ownership after acquiring its owner locks.
Share lock planning retains pending rows and supplements snapshot-missing IDs
from committed metadata on MySQL/MariaDB, including transaction-bound clients.
Those metadata reads never authorize deletion or change transaction ownership.
Share creation similarly supplements snapshot-missing source-owner metadata,
then validates the source again under the current owner fence. Its initial
lookup inherits the caller transaction, including pending folders on SQLite.
View changes merge current properties so they preserve concurrently updated ACLs,
including inside an inherited transaction.
Administrative group associations are loaded freshly and do not enter the
shared storage-policy cache.

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
reader requires them. Under the physical object gate, both pending transaction
dependencies and latest committed dependencies prevent deletion. These reads
take no entity or policy locks after that gate. Pending removals can conservatively
defer collection until a later native maintenance pass.
Completed migration reads retain their exact acknowledgement in the originating
process and retry temporary SQL failures. Graceful shutdown drains these
acknowledgements before closing SQL. A crash before acknowledgement can still
leave a conservatively unfinished reader; replacement startup or lease expiry
is not proof that another reader has stopped.
Failed targets are deleted only at exact server-owned
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
