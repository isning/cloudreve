# Storage delivery gates

Use Go from `go.mod`, Python 3, Node22 and pnpm10.34.6. Keep `assets` checked out
at the backend's committed submodule revision. Build frontend assets before Go
compilation. All credentials and object data in the gates are disposable fixtures.

```sh
python3 scripts/build-frontend.py --stage all
go generate ./ent
git diff --exit-code -- ent
python3 scripts/verify.py --stage frontend
go build ./...
```

Provision owned tools using Nix (source revision is pinned):

```sh
mkdir -p .scratch/multi-storage
nix build --impure -f scripts/storage-tools.nix -o .scratch/multi-storage/tools
export CLOUDREVE_S3_TEST_SERVER="$PWD/.scratch/multi-storage/tools/bin/weed"
export PATH="$PWD/.scratch/multi-storage/tools/bin:$PATH"
python3 scripts/verify-storage.py --stage native
```

For shorter independent jobs use `--shards 4 --shard 0` through shard3. Stable
name hashes partition the native cases; no tests are silently quarantined.
Services bind loopback and use temporary credentials, buckets and files. Do not
run browser gates concurrently: the owned production-bundle server uses43181.

Set `OIDC_TEST_DRIVER=postgres` or `mysql` and `OIDC_TEST_DSN` via your operator's
secret mechanism for a disposable service, then run:

```sh
python3 scripts/verify.py --stage database
python3 scripts/verify-storage.py --stage database
```

These create fresh databases and include prior-schema startup/upgrades,
authentication/permission parity, transaction/fencing, shared versions and
restart recovery. MySQL and MariaDB both use `mysql`. Never point them at a
production application database. The DSN is not printed by the runners.

For production frontend HTTP-boundary regressions, install the frozen browser
lockfile and provision Chromium as documented in `oidc-release.md`, then:

```sh
pnpm --dir scripts/e2e test
python3 scripts/verify-storage.py --stage browser
```

The second command launches production native HTTP/Ent/queues with real S3,
then logs in through the actual frontend. It does not replay business responses.
Use `CLOUDREVE_FRONTEND_BUILD` only if testing the exact pinned standalone build;
otherwise the server uses `assets/build`. On NixOS provide a working
`CHROMIUM_EXECUTABLE`; CI provisions Playwright Chromium. Traces, JUnit, owned
configuration and build artifacts stay under ignored `.scratch` directories.

The image gate accepts an already-built local runtime image:

```sh
export CLOUDREVE_STORAGE_IMAGE='<local-image-tag>'
export CLOUDREVE_CONTAINER_ENGINE='docker'
python3 scripts/verify-storage.py --stage image
```

It starts the packaged application with a disposable database/configuration and
owned S3; uploads through public HTTP, relocates, queries native task state and
reads back bytes. The existing version/startup gate remains separate. Native
image execution requires loopback access to the host S3 fixture. Containers have
an exact workspace label and are stopped gracefully. No global prune is needed.

CI integrates native shards, database acceptance, native browser and runtime
image acceptance before the existing tag publication path. Workflow changes
are local until explicitly pushed; local acceptance does not mean hosted CI,
arm64 runtime or production deployment has run. Existing upstream source-pinned
exceptions remain unchanged; the frontend rejects any added TypeScript diagnostic.
