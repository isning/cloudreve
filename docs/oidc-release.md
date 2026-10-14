# Building and releasing

The release configuration is `.goreleaser.yaml`, shared with the upstream Azure
Pipelines entrypoint. `.build/build-assets.sh` builds the pinned `assets` submodule
and packages it into `application/statics/assets.zip`. The fork uses pnpm with its
existing lockfile; Node.js 22, pnpm 10.34.6 and Go matching `go.mod` are required.

```sh
git submodule update --init --recursive
bash .build/build-assets.sh 4.14.0-oidc.2
go build ./...
go test -race -count=1 -timeout=10m ./pkg/oidc ./pkg/auth ./pkg/authpolicy ./pkg/setting ./inventory ./application/dependency ./middleware ./routers/controllers ./service/user ./service/basic ./service/oauth
go generate ./ent
git diff --exit-code -- ent
```

OIDC regression tests live in the existing Go packages and use the native Go test
runner. The feature test target above covers authentication, persistence and
HTTP integration. Repository-wide `go test ./...` also encounters inherited
cache/config/request tests that reference legacy APIs; it is not advertised as
passing by this feature target.

Database tests also run against disposable PostgreSQL, MySQL and MariaDB services.
For a local owned test service, set `OIDC_TEST_DRIVER` to `postgres` or `mysql`, and
supply `OIDC_TEST_DSN` securely:

```sh
go test -race -count=1 -timeout=15m ./routers/controllers ./inventory -run 'TestOpenID|TestLogto|TestManagedAccount|TestExternalAuth'
```

GitHub Actions runs the frontend build, native Go tests, Ent generation check and
database matrix. The same workflow runs native storage tests against real S3,
including migration, recovery and database upgrade checks. All checks gate the
GoReleaser publishing job in `release.yml`. For tag pushes, the official
GoReleaser action invokes the same
release configuration after these checks pass. It builds the upstream binary
targets, archives and AMD64/ARM64 Docker images, then publishes to GHCR.

```sh
export GHCR_IMAGE=ghcr.io/isning/cloudreve
goreleaser check
goreleaser release --timeout 60m -p 4
```

Publishing requires a release tag, a GHCR login and `GITHUB_TOKEN` with repository
release and package publishing permissions. GitHub Actions uses its automatic
workflow token. Azure Pipelines uses its configured `GITHUB_TOKEN`, `GITHUB_USER`
and `GHCR_IMAGE` variables. The configuration keeps upstream draft-release and
version-tag behavior. Consumers can pin `ghcr.io/isning/cloudreve:<tag>` by digest.
