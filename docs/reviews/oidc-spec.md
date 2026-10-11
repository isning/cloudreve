# OIDC release specification review

Reviewed on 2026-10-11 against the accepted local specification at `.wayfinder/maps/oidc-pro/implementation-spec.md`. The implementation-evidence document was supporting information, not the review authority. This review independently read the implementation and exercised selected application and startup tests. No tracker setup, remote Git action, actual secret capture, or implementation mutation occurred during initial diagnosis. The parent subsequently authorized the narrow MFA navigation correction recorded below.

Backend review base: `9f1e0b8333f5c7304a09e1dcb3f9c170dddd63f3`; implementation was an uncommitted working tree, including untracked extension source and tests. Frontend review base: `19da0fe1ecd40971fafa813983d769fdce41573c`; initial implementation commit: `81b3aaea1274ad673ed72d959f730b6b4113e7c4` (`feat(auth): support community OIDC and Logto authentication`). The backend base diff and frontend base-to-HEAD history were both inspected. Final release revisions and browser results belong to the release report.

## Findings

### S1 — Shared effective encryption/signing key was logged under its real setting name

**Priority: high. Status: corrected during release review; targeted backend regression passed.**

Specification decision 25, line 115: “配置环境覆盖日志及callback query精确脱敏” and “Sensitive标注不能替代SQL参数日志处理。”

At initial review, `pkg/setting/adapters.go:72` and `inventory/migration.go:87,96` checked `secretKey`; the actual setting read by `pkg/setting/provider.go:742` is `secret_key`. Setting the real `CR_SETTING_secret_key` environment override logged its value. Initial default override handling also logged the real `CR_SETTING_DEFAULT_secret_key` value, and default creation did not suppress SQL arguments for that key. This exposes the key used by external encrypted state and native authentication. The earlier bootstrap test used the ineffective spelling and could pass while the actual path leaked.

Reproduction: use a harmless sentinel as the real setting's override and capture the existing logger/debug SQL sink; assert the sentinel is absent from output. Never use a deployment key for this regression. The parent corrected the real key checks and the tests at `routers/controllers/openid_logging_test.go:41,64`. The independently run effective-key and full external debug-log regressions passed. The final implementation includes both spellings in the redaction predicates.

### S2 — Valid pending MFA could outlive its frontend navigation context

**Priority: medium. Status: corrected under parent authorization; focused browser regression delegated to the release verification step.**

Specification decision 21, line 111: “最终重查active用户并原子完成，不丢失上下文或重新签一个无来源root。” Decision 29, line 119: “按本次state保存经校验的站内目的地；MFA成功后才消费。”

Originally, `assets/src/session/openid.ts:9,30,37` expired navigation context ten minutes after Prepare. `pkg/oidc/mfa.go:35` creates a new five-minute pending-MFA transaction after the provider exchange. A provider flow completing after nine minutes could legitimately complete MFA until minute fourteen; the frontend rejected its return context at minute ten. Worse, the callback submitted MFA before reading the context, allowing the server to consume the challenge and issue a native session that the frontend then discarded.

Reproduction: start with a nearly expired per-state context, receive the verified `203` challenge, advance browser time beyond the original ten-minute deadline but within the pending MFA deadline, and submit a valid OTP. The original callback loses the login/OAuth destination. Independently, expire the navigation context before submission and check that no MFA request is sent.

The authorized change at `assets/src/session/openid.ts:46` extends only that transaction's context by five minutes after verified `203`. `OpenIDCallback.tsx:44,60,62,79` retains the context validated before each network request and checks it before MFA submission. This also avoids dropping a valid completion when the request itself crosses a local expiry boundary. Whitespace checks passed; the parent owns the new browser test and frontend release commit.

### S3 — Missing provider identifier can default to the valid legacy instance 0

**Priority: low. Status: corrected under parent authorization; regression failed before the fix and passed afterward.**

Specification API table, line 129: “必填provider_id、code、session_id；session_id为callback state”. Decision 6, line 96: “保留实际配置中的旧0/1/2标识”.

At review, `pkg/oidc/flow.go:11` defines `ProviderID` as an integer without presence information. `routers/controllers/openid.go:51` binds this type directly. With a real configured provider 0 and a valid matching transaction/proof, omitting `provider_id` is equivalent to explicitly providing 0. Prepare has the analogous ambiguity at `pkg/oidc/types.go:90` and `routers/controllers/openid.go:26`. Browser proof, transaction ownership and signature verification still apply; this is required-field contract drift, not an ownership bypass.

Regression: prepare a real configured instance 0, submit its callback with no provider identifier and expect a parameter error without consuming state, then submit the same callback with explicit 0 and expect normal success. Use presence-aware HTTP DTO validation; a plain `required` validator on an integer would incorrectly reject the legitimate legacy 0.

Implemented local HTTP DTOs with required nonnegative integer pointers at `routers/controllers/openid.go:27,57`. Explicit 0 remains valid; missing, null and negative inputs are rejected before side effects. The runtime's typed interface is unchanged. `routers/controllers/openid_release_contract_test.go:19` checks both endpoints against a real configured provider 0. It failed on the original implementation, then passed in 0.125s after correction, including successful completion of the same transaction following the rejected callbacks.

### S4 — Production HTTP composition is only partially implemented

**Priority: informational. Status: corrected under parent authorization; no demonstrated release behavior failure preceded the correction.**

Specification decision 3, line 93: “HTTP client与transport在composition层注入”.

`oidc.Options.HTTP` supports injection, and tests exercise actual external HTTP. At initial review, production `application/dependency/oidc.go:15` omitted the HTTP field, so `pkg/oidc/transport.go:45` chose the default transport inside the protocol module. Composition now explicitly supplies a standard `http.Client` with the shared default transport. The protocol retains its existing bounds and redirect checks, and remains independent of inventory, native authentication, settings, services, dependency and Gin. No extra networking layer was introduced.

### S5 — The promised concurrent onboarding case lacks a dedicated regression

**Priority: validation gap. Status: closed with a new independently run cross-process HTTP regression on SQLite with the race detector; matrix rerun owned by parent.**

Testing decision 8 states: “并发同身份开户只能产生一个用户关联”; testing decision 11 states: “持久状态并发测试使用独立连接/实例，不能用单进程锁或SQLite单连接伪证跨进程安全。”

The reviewed test tree covers concurrent consumption of one callback, two last-association removals, deletion against association and cross-process callback/revocation. No test specifically starts two separately prepared authorization transactions for the same previously unseen identity and races their JIT account creation. `inventory/external_auth_account.go:14` does place user creation and identity insertion in one outer transaction; the identity-key unique constraint prevents a second identity insert and rolls back the losing account. This is missing promised behavioral verification, not a demonstrated duplicate-account defect.

Recommended regression: issue two independent transactions against the same subject with automatic account creation enabled, complete them concurrently through independent application/database connections, then check there is exactly one new user and one identity, no orphan user, and no ownership overwrite. Run it on the database matrix; two calls consuming the same transaction cannot establish this property.

Added `TestOpenIDConcurrentJITAcrossProcessesPreservesOneAccount` at `routers/controllers/openid_release_contract_test.go:67`. Both callback requests use actual HTTP; one targets the parent application server, the other an independent subprocess with separate Ent pool, runtime, JWT bridge and default cache. A gate in the external UserInfo fixture waits for both independent flows before releasing them; database/protocol stores are not mocked or locked by the test. The new-account case requires exactly one additional managed user in group 2 and one identity, no orphan account, and the same identity owner/source in every successful token. The losing callback may either observe the newly committed binding and authenticate that same account or fail without credentials; the accepted requirement constrains ownership and account count rather than requiring both racing requests to succeed. An existing-email variant requires both flows to reject without any identity/root and keeps the original local credentials and group intact. Existing first-user onboarding coverage separately verifies bootstrap suppression.

## Requirement coverage and review outcome

| Accepted requirements | Independently inspected implementation and conclusion |
| --- | --- |
| Stable multi-instance settings, Pro wrapper/string contract, unknown entries, Logto | `pkg/oidc/provider.go`, `logto.go`, settings adapters/admin save, frontend `SSOSettings` and `OpenIDProviderEditor`: monotonic identifiers, opaque save preservation, whitelist public projection, default/extra scopes and Logto string connector adaptation are present. S3 and S4 record the narrow corrections above. |
| ID-token/UserInfo identity, verified subject, initial group mapping | `protocol.go`, `profile.go`: signature/issuer/audience/expiry/nonce and authorized-party checks precede profile use; UserInfo requires matching `sub`; mapped subject must equal the verified token's subject; arrays/objects cannot drive group mapping; existing login does not resync profile/group. |
| Independent browser transactions, configuration reload, one-time finish | `runtime.go`, `flow.go`, encrypted payload and inventory transaction adapter: per-state browser proof, stable callback, config digest, expiry and conditional single-row consumption precede external exchange. A wrong proof cannot consume legitimate state. Provider settings bypass process-local configuration cache. |
| Ownership, JIT, uniqueness, managed facts, unlink and deletion | All `inventory/external_auth*.go`, Ent source schemas and changed user/delete adapters: identity and user/provider slot constraints, one outer onboarding transaction, bootstrap suppression, explicit tombstones, user-row lifecycle locks and deletion detachment/revocation are present. No upsert ownership transfer was found. |
| Managed local credentials and admin rescue | `pkg/authpolicy`, inventory final password/passkey checks, user services and protected release route: managed status is a persisted fact separate from empty passwords; reset/update/register are rejected; rescue explicitly clears the fact; regular empty-password users retain recovery. |
| MFA/native issuance/persistence errors/refresh/logout | Runtime MFA/session, native adapter, JWT source preservation and HTTP dispatch: active account rechecks, source-bearing root, persisted sessions before delivering JWTs, failed/missing/corrupt root rejection, monotonic CAS expiry, durable revoke-before-redirect and logout snapshots are present. S2 fixes frontend context lifetime. |
| Startup, extension migration and database compatibility | Dependency startup, independent schema/bootstrap marker, actual SQLite file locks and PostgreSQL/MySQL advisory locks: additive old-version upgrade and retry paths are present. Tests construct the genuine previous schema and exercise real failed DDL and process coordination. |
| Community frontend/native experience/OAuth | First/password-stage instance buttons, callback, security settings, SessionManager/thunks and per-tab state storage are integrated; binding does not replace the native login, OAuth query restoration continues normal consent, callback errors are terminal, and provider logout accepts the trusted service result. Root release verification supplies independent live browser coverage. |

No unrequested QQ adapter, implicit provider 2 alias, email merge, recurring group sync, IdP token substitution, Pro flag change, back-channel logout, or global access-token database check was found. The large generated Ent changes are inspected separately from handwritten extension code. The earlier specification's “本次规格发布” restriction describes its planning publication phase; the subsequent authorized implementation/release task controls the current work.

## Independent verification

Ran the following selected checks with real application fixtures and default SQLite, without copying the earlier evidence's conclusions:

```sh
go test ./routers/controllers ./inventory -run 'TestOpenID(RejectsInvalidProviderProofs|ForeignBrowserDoesNotConsumeTransaction|ManagedConcurrentUnlinkProtectsLastUsableIdentity|DeletionCompetingWithAssociationCannotLeaveOwnership|PersistenceFailureNeverReturnsCredentials|RefreshAndLogoutRaceRetainsMaximumExpiry|PasswordResetCompletionHonorsCurrentPolicy|HotReloadRejectsPreparedState|CredentialsStayOutOfDebugLogs|EffectiveEncryptionKeyOverrideIsRedacted)|TestExternalAuth(UpgradePreservesLegacyDatabase|FailedDDLCanResumeWithoutLosingData|MigrationCoordinatesProcesses)' -count=1
git -C assets diff --check
```

Result: controller tests passed in 4.469s; inventory tests passed in 0.456s; frontend whitespace check passed. The additional provider-0 contract regression failed before correction and passed in 0.125s afterward. This reviewer did not independently claim a fresh full database matrix, frontend production build, or live IdP/browser run. Those checks are owned by the separate release verification/delivery steps. Prior evidence and tests on disk are not substituted for checks actually run here. S1 and S3 have independently passing regressions; S2 requires the parent browser result; S4 is resolved by explicit production injection.

After S3/S4 changes, also ran `go test ./routers/controllers ./inventory ./application/dependency ./pkg/oidc -run 'Test(OpenID|Logto|ExternalAuth|Managed)' -count=1`: controllers passed in 12.613s; inventory passed in 0.524s; dependency and protocol packages compiled. At this point the parent-owned CI diff had one trailing-whitespace line and was notified; frontend whitespace checks were clean.

After adding S5's regression, ran `GIN_MODE=test go test -race ./routers/controllers -run '^TestOpenID(ProviderIdentifierIsRequiredAndExplicitZeroIsValid|ConcurrentJITAcrossProcessesPreservesOneAccount)$' -count=1`: passed in 3.956s, including the independently executed child processes. The first run exposed a stale fixture user object from the pre-existing bootstrap update; the test now records fresh persisted baseline account facts before the race. This was a test expectation correction, not an implementation defect. Final parent/backend and frontend whitespace checks passed.
