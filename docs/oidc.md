# Community OIDC and Logto authentication

This extension implements the accepted Pro-compatible configuration and public API contract on the community backend and frontend. It does not enable the Pro flag, implement QQ login, infer undocumented private Pro formats, or migrate existing Pro identities automatically.

## Configure a provider

Open **Admin → Settings → User session → Single sign-on**. Add an OIDC or Logto instance, complete its fields, then enable and save it. Multiple instances of the same type are supported. Identifiers are permanent; deleting an instance never makes its identifier reusable.

For standard OIDC, provide a client ID and secret, import the discovery document, and register this exact redirect URI at the identity provider:

```text
<configured Cloudreve site URL>/callback/openid/<provider ID>
```

For Logto, create a traditional web application and provide its endpoint, application ID and application secret. The adapter discovers the endpoint's `/oidc` issuer. Register the callback above and, for provider logout, register the configured Cloudreve site URL as a post-logout redirect URI.

Additional scopes use a comma-separated string. Authorization always includes `openid email profile`; additional scopes are trimmed and deduplicated. Logto's `direct_sso` string is forwarded as `direct_sign_in` (for example, `social:<connector>` or `sso:<connector>`). Its optional account hint becomes `login_hint`. These parameters do not establish identity or prove an email address.

The setting remains a JSON **string**, under `external_login_providers`:

```json
{
  "version": 1,
  "next_id": 4,
  "providers": [
    {
      "id": 3,
      "type": "oidc",
      "enabled": false,
      "config": {
        "client_id": "YOUR_CLIENT_ID",
        "client_secret": "YOUR_CLIENT_SECRET",
        "display_name": "Example identity provider",
        "scope": "",
        "direct_sign_in": false
      },
      "wellknown": {}
    }
  ]
}
```

Import discovery before enabling this example. `wellknown` is a sibling of `config`. Previously configured IDs 0, 1 and 2 remain real instances; new IDs start at 3. Unsupported entries are preserved opaquely and cannot authenticate. Keep secrets out of source-controlled configuration. Existing `CR_SETTING_` overrides retain priority; `CR_SETTING_DEFAULT_` supplies bootstrap defaults.

## Accounts and sessions

With automatic account creation disabled, users sign in locally and associate their external identity from **Settings → Password and security**. Identity ownership is `(provider ID, exact issuer, verified subject)`, never email. An existing binding can authenticate without an email claim. A successful association updates the association list and keeps the current native session.

The `direct_sign_in` **boolean** enables initial account creation. It is independent of Logto's similarly named authorization parameter. Creation requires a valid unique email and creates the user, initial group, managed flag and identity in one database transaction. It cannot merge an existing local account or bootstrap an administrator. Name, avatar and scalar group mapping apply only at creation; later logins preserve local edits. Claim selectors use GJSON paths, with defaults `sub`, `email`, `name` and `picture`. A mapped subject must equal the verified ID-token subject. Group mappings use claim-value strings as keys and numeric Cloudreve group IDs as values; arrays and objects are rejected. The target group is checked again during creation.

Managed accounts cannot establish or use local passwords/passkeys or use ordinary email recovery. Existing passkey listings and local TOTP remain available. Administrators must explicitly select **Release managed account** before local credential rescue. Release neither sets a password nor fabricates an identity binding. `passwordless` indicates an actually empty password; clients use `credential_capabilities` to decide which operations are available.

External login completes through Cloudreve's existing SessionManager and native token pair. Local TOTP is still required when enabled. The refresh token marks its source as `openid`; its root record must exist, match the user, remain valid and be unrevoked. Login and refresh persist their records before returning credentials. Logout persists root revocation and clears its private payload before returning an optional provider logout URL. Other accounts and application OAuth roots remain independent. Revocation is retained until the maximum expiry already signed for that root.

Unlinking preserves identity history and releases the user's provider slot. A historical unlinked identity needs fresh local and provider proof to re-associate; JIT cannot bypass that history. Deleted-user identities are sealed and cannot transfer to a recreated email or reused UID. A managed account cannot remove its last usable enabled binding. Disabled or removed providers still appear as stale associations and can be removed by their owner.

## Public API

All paths below use `/api/v4`; errors use the existing Cloudreve response envelope.

| Endpoint | Request / result |
| --- | --- |
| `GET /site/config/login` | Public `login_providers` projection: ID, type, name, icon, enabled |
| `GET /session/prepare?email=…` | Associated usable `openid_providers` IDs and actual local login capabilities |
| `PUT /session/openid` | `{provider, hint?, linking?}` → authorization URL string; linking needs the local session |
| `POST /session/openid` | `{provider_id, code, session_id}` → native user/token, successful binding with no data, or `203` with a string MFA challenge |
| `POST /session/token/2fa` | Existing `{otp, session_id}`; external challenges retain their browser proof |
| `POST /session/token/refresh` | Existing `{refresh_token}` → native token pair |
| `DELETE /session/token` | Existing `{refresh_token}` → optional logout URL string, or empty string |
| `DELETE /session/openid/:provider_id` | Unlink the current user's binding; no data on success |
| `GET /user/setting` | Authoritative `open_id`, `linked_at`, `passwordless`, `credential_capabilities` |
| `GET /admin/tool/oidc?endpoint=…` | AdminWrite discovery tool; returns a JSON string |
| `GET /admin/tool/oidc/callback/:provider_id` | AdminWrite projection of the exact effective callback URI, including unsaved IDs |
| `POST /admin/user/:id/release-managed` | Explicit AdminWrite rescue operation; no data on success |

Authorization transactions use an encrypted server snapshot, nonce, a per-state HttpOnly browser-proof cookie and S256 when advertised. A transaction is consumed atomically before external code exchange. ID-token signatures, issuer, audience, authorized party, expiry, nonce and subject are validated; `at_hash` is checked when present. UserInfo must contain the same subject. Provider network requests have bounded time/response size and reject cross-origin redirects. Callback query parameters are removed from the address bar and omitted from access logs.

Browser return state lives per tab and per authorization state. It retains the original application OAuth request, including state and PKCE, through local MFA. The existing application consent/code/token flow remains responsible for the outer authorization. Callback cancellation clears only its matching context. A binding callback after the active account changes is rejected without switching accounts.

## Upgrade and follow upstream

Handwritten protocol logic lives in `pkg/oidc`, with typed ports and no Gin, Ent, native-auth or settings imports. `inventory/external_auth*.go` implements persistence and account lifecycle; `pkg/auth/oidc_session.go` bridges native authentication. HTTP transport is in `routers/controllers/openid.go`; `application/dependency/oidc.go` wires a single long-lived runtime. Policy is shared through `pkg/authpolicy`.

The Ent sources are `ent/schema/{externalidentity,openidtransaction,openidsession}.go` plus the User managed flag and edges. Regenerate with `go generate ./ent`; do not hand-edit generated files. Existing backend hooks are concentrated in startup/dependency wiring, route registration, refresh/logout/MFA dispatch, user credential/deletion paths and settings/public projections.

Startup runs the independent additive `oidc_extension_schema_v1` extension even when the official backend version has not changed. It preserves official version markers and existing settings, adds the three tables and managed column, and publishes completion only after successful DDL/bootstrap. SQLite uses an OS file lock beside the database, PostgreSQL uses a pinned advisory lock, and MySQL/MariaDB use a pinned named lock. Failed or partial initialization can be retried. All instances must share the database, configured site URL and nonempty effective Cloudreve secret key. Restarting with a changed key invalidates pending authentication and protected external refresh material. An empty encryption key rejects OIDC preparation/refresh without requiring an external record for ordinary native refresh.

The community frontend is maintained in the `assets` submodule. Clone with
`--recurse-submodules`; the backend records the frontend revision in its Git tree.
The upstream `.build/build-assets.sh` entrypoint builds and packages the frontend
for `.goreleaser.yaml`. The fork uses its existing pnpm lockfile.

```sh
bash .build/build-assets.sh 4.14.0-oidc.2
go build .
go test -race ./pkg/oidc ./pkg/authpolicy ./inventory ./routers/controllers
```

`application/statics/assets.zip` is an ignored build artifact. Publish frontend
changes in the frontend fork and update the backend submodule revision before
building a release. Regenerate Ent with `go generate ./ent` when schemas change.

Database regression tests use `OIDC_TEST_DRIVER=postgres` or `mysql` and
`OIDC_TEST_DSN`. Use an owned disposable test service with permission to create
test databases. MySQL and MariaDB use driver `mysql`; default tests use SQLite.
Migration and multi-instance tests launch independent processes.

See [building and releasing](oidc-release.md) for the shared release entrypoints.
