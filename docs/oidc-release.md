# OIDC release gates and reproducible delivery

This follow-up closes the three requested engineering gates: independent review, repeatable quality checks, and fresh-checkout source delivery. Local gates have passed. The GitHub workflow is ready to execute when these changes are published to an Actions-enabled repository; a hosted CI run and production deployment are not claimed.

## Independent review

Separate reviewers inspected the implementation against the pinned upstream bases, including new backend source and the frontend submodule. See the [standards/security review](reviews/oidc-standards-security.md) and [specification review](reviews/oidc-spec.md). Confirmed findings were corrected:

- Effective `secret_key` environment/bootstrap logs now redact the actual setting name. Synthetic-key regressions failed before correction and passed afterward.
- A verified pending MFA challenge extends only its navigation context by five minutes. Context is checked before submitting MFA and retained across an in-flight response. Both browser regressions failed on the previous production bundle and pass on the corrected bundle.
- Required HTTP provider identifiers are presence-aware: omitted/null identifiers cannot default to provider 0; explicit configured provider 0 still works. Rejected requests do not consume transactions.
- The administrator editor fetches the exact effective callback URI using the same backend construction as Prepare, including environment overrides, host selection and base paths.
- Production wiring explicitly supplies the provider HTTP transport. Separate-process JIT races now verify one owner/account, no orphan users and no merging of an existing local email account.

This is independent source review with regression testing inside the project, not external penetration-test certification.

## Local gates

Prerequisites: Go matching `go.mod`, Node.js 22, Python 3 and pnpm. The frontend and browser lockfiles pin pnpm to 10.34.6. From the repository root:

```sh
python3 scripts/build-frontend.py --stage all
python3 scripts/verify.py --stage backend
python3 scripts/test_release_tools.py
```

The backend gate builds every production package, runs all nonquarantined packages with the race detector, and vets the affected authentication/application packages. For PostgreSQL, MySQL or MariaDB, supply `OIDC_TEST_DRIVER=postgres` or `mysql` and `OIDC_TEST_DSN` securely, then run:

```sh
python3 scripts/verify.py --stage database
```

Use a disposable operator-owned database service. The tests create fresh databases; do not target an application database. The readiness helper checks an authenticated connection without printing the DSN. MySQL and MariaDB both use driver `mysql`.

Browser regressions execute the actual production bundle with controlled public HTTP responses. Backend protocol/Ent/JWT behavior has separate real HTTP/database gates; these browser tests do not claim a live production IdP:

```sh
cd scripts/e2e
pnpm install --frozen-lockfile --ignore-scripts
PLAYWRIGHT_BROWSERS_PATH="$PWD/../../.scratch/oidc-pro/tmp/playwright" pnpm exec playwright install chromium
PLAYWRIGHT_BROWSERS_PATH="$PWD/../../.scratch/oidc-pro/tmp/playwright" pnpm test
```

On NixOS, use Nix Chromium:

```sh
cd scripts/e2e
nix shell nixpkgs#chromium --command bash -c 'CHROMIUM_EXECUTABLE="$(command -v chromium)" pnpm test'
```

The test server binds loopback port 43181. Browser contexts are isolated, service workers are blocked, and synthetic-fixture traces/screenshots/JUnit stay under `.scratch/oidc-pro/tmp`. No production session is imported.

## CI and release integration

`.github/workflows/oidc-quality.yml` uses read-only repository permissions and commit-pinned actions. Its frontend job builds and tests the real bundle, then supplies that artifact to backend and PostgreSQL/MySQL/MariaDB jobs. Fresh jobs therefore do not depend on an ignored local ZIP. It also checks Ent regeneration and tests the fail-closed gate/submodule helpers.

GoReleaser uses the same verified asset builder and runs the backend gate. The existing Azure `Default` self-hosted pool must provide Python 3 and pnpm; an explicit prerequisite step checks them before release. No alternative package-manager installation method is introduced. Branch protection and hosted execution remain repository administration tasks, separate from committing the workflow.

## Bounded upstream exceptions

`verification/upstream-baseline.json` records the original backend/frontend bases. CI and build commands cannot regenerate it automatically.

- Exactly the original cache/config/request test file sets and SHA-256 hashes are quarantined because they reference removed APIs. Editing or adding tests in those package roots blocks the gate until the quarantine is resolved. Production packages still build; other packages and subpackages still run.
- TypeScript exceptions use file, diagnostic code, message, count and a source-content anchor from the original frontend. Fewer errors pass. New errors, changed anchors, duplicated errors and unparsed/global compiler errors fail. A fresh original-source baseline with the same declared dependencies has 127 diagnostics; the extension has 121, with zero additions.
- The inherited `service/admin/node.go` unkeyed-literal vet warning remains outside the affected-package vet gate. Raw `go test ./...` and frontend `build-prod` are still not advertised as green.

Review baseline updates as source changes. Fixing the inherited problems permits removing exceptions; silently accepting current output is unsupported.

## Fresh-checkout delivery

The community frontend lives in its own fork, referenced by `.gitmodules`. The backend's `assets` gitlink pins the reviewed frontend commit. Git bundles, source patches, planning tickets and runtime evidence stay local.

```sh
git clone --recurse-submodules <your-backend-repository>
cd <your-backend-repository>
python3 scripts/build-frontend.py --stage all
go build .
```

Cloning without `--recurse-submodules` also works: the builder initializes the standard submodule from its configured remote. It refuses a nonempty uninitialized directory, dirty source or an initialized revision different from the gitlink; it never replaces unexpected local work. To update an existing checkout deliberately, preserve frontend changes first and run `git submodule update --init -- assets`.

Publish frontend updates to the frontend fork first, then record the reviewed revision using `git add assets` in the backend and rerun the release gates. Keep the original frontend repository as an `upstream` remote in that separate checkout when following upstream. No frontend export script or backend source bundle is required.

`--stage build` and `--stage package` support separate reruns. Provenance pins the frontend commit, lockfile and quality baseline; packaging rejects stale/unrecorded builds. ZIP entries have fixed timestamps, permissions and order; the archive is CRC-checked and replaced atomically. `--version` sets the release asset version without editing frontend source metadata.

## Follow-up results

Local verification on 2026-10-11 passed:

- Independent review regressions and all nonquarantined backend tests with the race detector.
- Complete authentication/migration gates on PostgreSQL 17.6, MySQL 8.4.6 and MariaDB 11.4.13, including separate-process JIT races.
- Fifteen production-bundle browser regressions and ten gate/bootstrap regressions.
- GitHub workflow linting, source whitespace checks, and backend compilation from an actual fresh local Git clone with no initialized frontend or ignored asset ZIP.
- The original bundle-based fresh-clone recovery and deterministic packaging checks passed before the source-delivery route changed to a standard remote submodule. Standard-submodule fixture recovery and all ten revised gate/submodule regressions passed after the change; remote fresh-clone verification will be recorded after frontend publication.

Frontend commit: `9c30d08a7112b9b08b163896a626d249a95cb5f7`. The frontend runtime source did not change during the move to standard submodule delivery.

The review reports retain their historical evidence, including the earlier local bundle route. That route is superseded by the standard submodule described above. Planning tickets and detailed runtime logs remain local. Production HTTPS/proxy, backup recovery and sustained-operation verification belong to the separately identified deployment gate.
