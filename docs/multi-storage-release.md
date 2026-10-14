# Storage build and release checks

Use the existing upstream build entrypoint and GoReleaser configuration, as
described in `oidc-release.md`. The frontend is pinned by the `assets` submodule.

```sh
git submodule update --init --recursive
bash .build/build-assets.sh 4.14.0-multi-storage.2
go build ./...
go generate ./ent
git diff --exit-code -- ent
```

Native HTTP, Ent, storage and worker regression tests use `go test`. Provision an
owned S3 test service using the pinned Nix tool definition:

```sh
mkdir -p .scratch/multi-storage
nix build --impure -f scripts/storage-tools.nix -o .scratch/multi-storage/tools
export CLOUDREVE_S3_TEST_SERVER="$PWD/.scratch/multi-storage/tools/bin/weed"
export CLOUDREVE_STORAGE_INTEGRATION=1
export TMPDIR="$PWD/.scratch/tmp"
mkdir -p "$TMPDIR"
go test -v -race -count=1 -timeout=60m ./routers/controllers -run '^TestStorage'
```

Tests create disposable loopback services, buckets, databases and worker
processes. `CLOUDREVE_STORAGE_INTEGRATION=1` makes missing S3 tooling a failure.
The database tests accept `OIDC_TEST_DRIVER=postgres` or `mysql` and
`OIDC_TEST_DSN` for an owned disposable database; MariaDB uses the MySQL driver.

The single GitHub Actions entrypoint is `.github/workflows/release.yml`. It uses
native Go tests for authentication and the database matrix, and distributes the
S3 storage cases across four jobs. Tag pushes publish through the official
GoReleaser action after all required checks pass. Azure Pipelines continues to
use the same `.goreleaser.yaml` and `.build/build-assets.sh` entrypoints.

The native runtime image test can also inspect an already-built local image:

```sh
export CLOUDREVE_STORAGE_IMAGE='<local-image-tag>'
export CLOUDREVE_CONTAINER_ENGINE=docker
go test -v -race -count=1 -timeout=5m ./routers/controllers -run '^TestStorageRuntimeImageWorkflow$'
```

This test starts the packaged application, uploads through public HTTP,
relocates files, queries task state and reads back S3 bytes. Containers carry an
exact workspace label and stop gracefully. It requires loopback access from the
container to the owned S3 fixture.
