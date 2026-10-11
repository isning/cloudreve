# OIDC standards and security review

Reviewed 2026-10-11 against backend base `9f1e0b8333f5c7304a09e1dcb3f9c170dddd63f3` and frontend base `19da0fe1ecd40971fafa813983d769fdce41573c` (implementation commit `81b3aaea1274ad673ed72d959f730b6b4113e7c4`, plus authorized audit fixes). The review included tracked diffs and new untracked source; a tracked-only diff would omit most of this implementation.

The accepted implementation specification, `docs/oidc.md`, and existing implementation evidence supplied the intended behavior. Findings below came from source inspection and targeted reproductions; existing test names and ticket status were not treated as proof of correctness. No external Git state was changed or runtime credentials inspected.

## Result

Two confirmed defects were found and fixed with the coordinating agent's approval. No unresolved authentication blocker was identified in this review slice. This is a bounded source review, not a claim that all providers, platforms or attack classes have been exhaustively tested. Broader CI, frontend browser coverage and portable delivery are owned by the coordinating agent.

## Confirmed findings and corrections

### S1 — High: effective encryption/signing key was excluded from redaction

Affected original locations: `pkg/setting/adapters.go:72`, `inventory/migration.go:87,96`, and the misleading fixture at `routers/controllers/openid_logging_test.go:54`.

Both logging guards checked `secretKey`; the actual setting is `secret_key` (`pkg/setting/provider.go:742`, `inventory/setting.go:539`). Consequently a real `CR_SETTING_secret_key` override was printed by normal environment-override logging. A `CR_SETTING_DEFAULT_secret_key` bootstrap override was likewise printed, and normal bootstrap SQL for that setting was not excluded from debug logs. The old test used the unused spelling and therefore passed without exercising the effective key.

The existing native JWT service and the new OIDC payload codec both receive this effective key from dependency wiring. A reader of these logs could obtain JWT signing material and, with access to persisted payloads, decrypt provider secrets, nonce/PKCE material and logout ID tokens. The underlying generic logging exposure predated OIDC, but this implementation's added redaction and claimed verification failed to protect the key now also used by OIDC.

Correction: recognize `secret_key` in runtime override logging, bootstrap override logging and bootstrap SQL suppression; retain the old spelling for compatibility. Correct the bootstrap regression to use the effective setting and add `TestOpenIDEffectiveEncryptionKeyOverrideIsRedacted`, which verifies both the effective returned value and the absence of that synthetic value from captured logs.

Reproduction evidence: both targeted regressions failed before the guard correction (`.scratch/oidc-pro/redaction-before.log`) and passed afterward (`.scratch/oidc-pro/redaction-after.log`). Tests use synthetic overrides and a disposable database. The full failing log remains ignored because it contains normal disposable bootstrap SQL; it is not appropriate for publication.

### S2 — Medium: provider editor advertised a different redirect URI

Affected original location: `assets/src/component/Admin/Settings/UserSession/OpenIDProviderEditor.tsx:53`.

The editor constructed the advertised registration URI from `window.location.origin`. Authorization instead used the effective configured site URL, including configuration/environment precedence, request-Host selection and a possible base path. An administrator visiting through an alternate origin or scheme could register the displayed URI and then receive an IdP redirect mismatch for the actual login. Reading raw database `siteURL` in the frontend would still be wrong under effective overrides.

Correction: `Runtime.CallbackURL` is the single callback construction path and is also used by `Prepare`. An administrator-only, AdminWrite-scoped `GET /api/v4/admin/tool/oidc/callback/:provider_id` exposes the exact effective URI for that request. The editor fetches it, shows the returned value, and displays loading/error state when unavailable. It supports unsaved provider IDs without initiating authentication or exposing provider credentials.

`TestOpenIDCallbackProjectionMatchesEffectiveAuthorization` compares the new projection directly with the authorization URL's `redirect_uri` under a runtime environment override. It covers an unmatched administrative host falling back to the canonical origin, a matching alternate host/port, preserved base paths, unsaved IDs and invalid identifiers. The existing privileged-boundary test now rejects anonymous callers and an OAuth token lacking AdminWrite on the new endpoint. Browser coverage is delegated to the coordinating agent.

## Security boundaries independently inspected

| Boundary | Source assessment |
| --- | --- |
| Browser intent | Prepare generates independent random state, nonce and browser proof. State/proof are hashed in persistent transactions; proof cookies are HttpOnly and per state. Foreign proof is rejected before consumption. Linking target UID comes from the prepared transaction, with an explicit conflicting active bearer rejected. |
| Replay and network boundary | Conditional transaction consumption commits before code exchange; the database controls one-shot completion across processes. Provider endpoints, callback and configuration digest come from the encrypted prepared snapshot. |
| Provider identity | ID-token verification checks signature, issuer, audience and expiry through the verifier; protocol code additionally checks nonce, subject, authorized party and optional access-token hash. UserInfo `sub` must equal verified ID-token `sub`; mapped subject must remain identical. |
| Ownership and JIT | Identity key includes provider ID, exact issuer and subject, and the stored original values are checked. Email is never used to merge accounts. JIT user and identity writes share a transaction and bypass first-user admin elevation. Unique constraints and retained unlinked/deleted identities prevent implicit reassignment. |
| MFA and managed accounts | External MFA retains encrypted provider/logout context, expires, is bound to browser proof and reserves at most five attempts per challenge. Final native issuance reloads an active user. Shared policy blocks managed password establishment/recovery and passkey creation; local login boundaries reject managed accounts. Release requires the explicit administrator operation. |
| Native session roots | Marked external refresh requires an existing matching unrevoked root and decryptable material. Conditional monotonic expiry updates prevent a revoked root from being extended. Logout persists revocation and clears sensitive payload before returning a provider redirect. Ordinary native and application OAuth roots remain separate. |
| Lifecycle races | Association, unlink and user deletion lock the same user row before identity mutation. Last usable managed binding is checked under that lock. Deletion tombstones identities, consumes transactions and revokes roots inside the existing deletion transaction. |
| Configuration lifecycle | Provider reads bypass process-local settings cache. Stable IDs and nondecreasing next ID are checked against the locked stored registry on writes. Pending authentication/MFA compare configuration digests. Unsupported provider data is preserved by the raw save/editor path rather than exposed for login. |
| Network and logs | Provider HTTP requests have time and response limits and reject cross-origin redirects. Discovery is administrator-scoped. Protocol failures sanitize external error bodies. Callback queries are omitted from access logs and stripped by the frontend; S1 closes the effective key redaction gap. |
| Migration coordination | Extension migration runs independently of the upstream version marker and writes completion last. SQLite uses a file lock; PostgreSQL/MySQL use a pinned connection for advisory/named locks. Additive DDL/bootstrap permits retries without replacing existing provider configuration. |
| Frontend navigation | Per-tab, per-state return context preserves the outer application OAuth request. Local return validation blocks external origins and callback recursion; linking callbacks compare their prepared account. The coordinating review handles additional terminal-state and browser regression improvements. |

## Standards and accepted limitations

The protocol package depends on typed application ports and protocol libraries; Ent, Gin, native JWT and settings remain in adapters. Handwritten changes are concentrated at authentication, settings, lifecycle and startup boundaries. Generated Ent files were inspected for schema consistency rather than reviewed as handwritten duplication. New identifiers/comments are English and ordinary credential policy remains backward compatible.

No material Fowler-style smell was promoted to a finding: the small adapters carry real boundary work, and spreading identity or credential policy back into controllers would weaken the current design. The callback defect was corrected by sharing one runtime construction path instead of duplicating configuration precedence in the UI.

HTTP provider URLs, administrator-controlled discovery targets, advertised-only S256, initial-only group mapping and native access-token behavior match the accepted scope. Durable logout gates the external refresh family; existing access JWTs retain their normal expiry. This review does not silently add provider-wide session invalidation, continuous group synchronization or production IdP/network restrictions.

## Verification performed by this reviewer

The following targeted command passed after the corrections:

```sh
TMPDIR="$PWD/.scratch/oidc-pro/tmp" go test ./routers/controllers \
  -run 'TestOpenID(CallbackProjectionMatchesEffectiveAuthorization|PrivilegedEndpointsEnforcePermissions|BootstrapDefaultsAreRedacted|EffectiveEncryptionKeyOverrideIsRedacted)$' \
  -count=1
```

Result: `ok github.com/cloudreve/Cloudreve/v4/routers/controllers`, recorded in `.scratch/oidc-pro/standards-security-regression.log`. The redaction regressions were separately observed failing before the correction. Edited Go files were formatted with gofmt; the frontend diff whitespace check passed. The coordinating agent owns the final whole-tree whitespace check, race/database/browser suites, build and refreshed delivery artifacts. No claim is made here that the inherited full Go or frontend TypeScript trees are green.

## Delivery and CI follow-up review

The coordinating agent requested a separate read-only review of `scripts/{bootstrap-frontend,export-frontend,build-frontend,verify,serve-frontend}.py`, `scripts/db-ready/main.go`, `.github/workflows/oidc-quality.yml`, `frontend/manifest.json`, `.build/build-assets.sh` and `azure-pipelines.yml`. Findings were reported while that agent was still implementing the delivery gates.

| Finding | Concrete scenario and disposition |
| --- | --- |
| D1 — High: clean CI jobs lacked embedded assets | `application/statics/statics.go` embeds ignored `assets.zip`. Original backend/database jobs checked out source and ran Go commands without producing that file; the independent frontend job did not share its filesystem. The backend gate's `go build ./...` and controller compilation would therefore fail on clean runners. The coordinating agent corrected the workflow to make frontend the producer and added a dependency/download of the actual verified asset archive for backend and database jobs. Inspection confirmed that wiring; remote CI execution is not claimed. |
| D2 — Medium: Azure did not establish pnpm prerequisite — resolved by explicit environment contract | The GoReleaser asset hook now uses Python and pnpm, while the original Azure job only established Node/Go. Node provisioning alone does not establish pnpm. The existing `Default` self-hosted pool now has an explicit Python/pnpm prerequisite, documented in `docs/oidc-release.md`, and Azure checks their availability before release. pnpm invokes the pinned 10.34.6 version. No prohibited npm/corepack provisioning was introduced. GitHub provisions pnpm through its pinned setup action. Actual execution on the user's Azure pool is not claimed. |
| D3 — Medium: TypeScript gate ignored unlocated compiler errors — fixed and independently retested | `verify.py` originally parsed only `path(line,column): error TSxxxx: ...`; an allowed file diagnostic plus a global TS2688 was wrongly accepted. It now counts all compiler error headers and refuses any not represented by parsed file diagnostics. The real regression rejects the reproduced global-error mixture, duplicates, changed anchors and fatal compiler failures while accepting unchanged or removed diagnostics. All ten gate/bootstrap regressions were independently rerun successfully. |
| D4 — Bounded rerun limitation: packaging accepted stale build provenance — fixed | Package-only reruns now require recorded build provenance matching the current frontend commit, delivery manifest bundle SHA, frontend lockfile SHA and quality-baseline SHA; uncommitted frontend source also rejects the operation. Build checks its inputs again after Vite before writing provenance. Missing or stale provenance fails before publishing the archive. Independent inspection confirmed these checks; the coordinating agent owns the negative stale-package execution. |

Independent source-delivery checks found that bundle SHA-256 matched the manifest and assets HEAD matched pinned frontend commit `9c30d08a7112b9b08b163896a626d249a95cb5f7`. Bootstrap refuses a dirty checkout and refuses replacement of an unexpected committed revision; it verifies the bundle prerequisite and fetched revision before checking out. No concrete local-change overwrite or manifest trust defect was identified for trusted repository metadata.

All six quarantined Go test hashes matched both the original backend base content and current files. Every one of the 127 permitted TypeScript diagnostic source anchors existed in the original frontend base; no new OIDC-only source anchor had entered the exception set. The coordinating agent reports 121 current diagnostics and zero additions under the same dependencies. These checks support the bounded inherited-exception design; they do not claim that disabling the compiler's strictness or editing the baseline itself would be caught as a new diagnostic.

The shared release hook now applies the explicit TypeScript comparison before Vite packaging rather than calling an unrestricted build as its only check. GitHub provisions pinned pnpm; loopback browser serving and database readiness avoid logging callback queries or DSNs. Deterministic archive metadata and refusal of build symlinks are appropriate. This follow-up reviewer did not edit the scripts/CI, run remote workflows, provision tools, mutate remote state or write outside the workspace.

Final read-only recheck confirmed commit-pinned GitHub actions, frontend artifact production followed by dependent download, and the shared GoReleaser backend gate. Bundle digest, recorded provenance commit/bundle/lockfile/baseline digests and the final embedded ZIP digest all matched the delivery document. Independently rerun helper results are recorded in `.scratch/oidc-pro/tmp/independent-release-tools.log`. Whole-tree whitespace checking passed. No remaining concrete blocking source or gate issue was found; hosted workflow execution and the self-hosted Azure environment remain unexecuted boundaries of this local review.

## Publication layout update

The subsequent publication task replaces the earlier bundle transport with a standard `assets` submodule referencing a separate frontend fork. No Git bundle, source patch or planning artifact is published in the backend. The earlier bundle/provenance review above remains a historical review of that snapshot. Current build provenance pins the gitlink, frontend lockfile and source-bound quality baseline; the revised submodule helper uses ordinary Git initialization and refuses dirty, nonempty or unexpected existing frontend revisions. The coordinating agent reran the ten revised helper tests; remote fresh-clone verification follows frontend publication.
