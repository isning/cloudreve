import { test, expect, type Page } from "@playwright/test";

// The browser executes the real production bundle. Only the public HTTP boundary
// is controlled here; protocol, Ent and native JWT behavior have separate Go gates.
const prefix = "cloudreve:openid:return:";
const user = {
  id: "alice",
  nickname: "Alice",
  email: "alice@example.test",
  created_at: "2026-01-01T00:00:00Z",
  language: "en-US",
  group: { id: "normal", name: "Users", permission: "AAAAAAAAAAA=" },
};
const token = {
  access_token: "synthetic-access",
  refresh_token: "synthetic-refresh",
  access_expires: "2099-01-01T00:00:00Z",
  refresh_expires: "2099-01-01T00:00:00Z",
};
const login = { user, token };
const providers = [
  { id: 3, type: "oidc", name: "Fixture OIDC", enabled: true },
  { id: 4, type: "logto", name: "Fixture Logto", enabled: true },
];

async function setup(
  page: Page,
  contexts: Record<string, unknown> = {},
  current?: string,
) {
  const calls: {
    path: string;
    method: string;
    body: any;
    authorization?: string;
  }[] = [];
  await page.addInitScript(
    ({ contexts, current, prefix, login }) => {
      for (const [state, context] of Object.entries(contexts)) {
        if (!sessionStorage.getItem(prefix + state))
          sessionStorage.setItem(prefix + state, JSON.stringify(context));
      }
      localStorage.setItem("i18nextLng", "en-US");
      if (current && !localStorage.getItem("cloudreve_session")) {
        localStorage.setItem(
          "cloudreve_session",
          JSON.stringify({
            current,
            sessions: {
              [current]: {
                ...login,
                user: {
                  ...login.user,
                  id: current,
                  group: {
                    ...login.user.group,
                    permission:
                      current === "admin"
                        ? "AQ=="
                        : login.user.group.permission,
                  },
                },
                settings: { preferred_dark_mode: true },
              },
              other: {
                ...login,
                user: { ...login.user, id: "other" },
                settings: {},
              },
            },
            anonymousSettings: {},
          }),
        );
      }
    },
    { contexts, current, prefix, login },
  );
  await page.route("**/api/v4/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname.replace("/api/v4", "");
    const body = request.postDataJSON();
    calls.push({
      path,
      method: request.method(),
      body,
      authorization: request.headers()["authorization"],
    });
    let data: any = {};
    if (path.startsWith("/site/config/"))
      data = {
        title: "Cloudreve test",
        default_theme: "#3f51b5",
        themes: "#3f51b5",
        login_providers: providers,
        register_enabled: true,
        authn: true,
        user: current
          ? {
              ...user,
              id: current,
              group: {
                ...user.group,
                permission:
                  current === "admin" ? "AQ==" : user.group.permission,
              },
            }
          : undefined,
      };
    else if (path.startsWith("/session/oauth/app/"))
      data = {
        name: "Fixture app",
        client_id: "fixture",
        scopes: ["openid"],
        consented_scopes: [],
      };
    else if (path === "/user/capacity") data = { total: 1000000, used: 0 };
    else if (path === "/user/setting")
      data = {
        open_id: [{ provider: 3, linked_at: "2026-01-01T00:00:00Z" }],
        passwordless: true,
        credential_capabilities: {
          password_update: false,
          password_reset: false,
          passkey_register: false,
          reason: "managed",
        },
        passkeys: [],
        oauth_grants: [],
      };
    else if (path === "/admin/settings")
      data = Object.fromEntries(
        (body?.keys ?? []).map((key: string) => [
          key,
          key === "external_login_providers"
            ? JSON.stringify({
                version: 1,
                next_id: 4,
                providers: [
                  {
                    id: 3,
                    type: "oidc",
                    enabled: true,
                    config: {
                      display_name: "Fixture OIDC",
                      client_id: "fixture",
                      client_secret: "synthetic-test-only",
                    },
                    wellknown: {
                      issuer: "https://idp.example.test",
                      authorization_endpoint:
                        "https://idp.example.test/authorize",
                      token_endpoint: "https://idp.example.test/token",
                      jwks_uri: "https://idp.example.test/jwks",
                    },
                  },
                ],
              })
            : "0",
        ]),
      );
    else if (path === "/admin/group")
      data = {
        groups: [],
        pagination: { page: 0, total_items: 0, page_size: 50 },
      };
    else if (path === "/file")
      data = {
        files: [],
        pagination: { page: 0, page_size: 50, total_items: 0 },
        parent: { id: "root", type: 1, name: "Root", path: "/", props: {} },
        props: {},
      };
    await route.fulfill({ json: { code: 0, data } });
  });
  return calls;
}
function context(provider = 3, extras: object = {}) {
  return {
    provider,
    linking: false,
    returnTo: "/session?redirect=%2Fhome",
    expires: Date.now() + 600_000,
    ...extras,
  };
}
async function override(page: Page, path: string, data: unknown, code = 0) {
  await page.route("**/api/v4" + path, (route) =>
    route.fulfill({
      json: { code, data, msg: code ? "Synthetic rejection" : "" },
    }),
  );
}
async function otp(page: Page) {
  const fields = page.getByRole("textbox");
  await expect(fields).toHaveCount(6);
  for (let index = 0; index < 6; index++)
    await fields.nth(index).fill(String(index + 1));
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
}
async function saved(page: Page, state: string) {
  return page.evaluate(
    (key) => JSON.parse(sessionStorage.getItem(key) ?? "null"),
    prefix + state,
  );
}

test("public login entries preserve the original outer OAuth request", async ({
  page,
}) => {
  await setup(page);
  await override(
    page,
    "/session/openid",
    "http://127.0.0.1:43181/fixture-idp?state=begin-state",
  );
  const outer =
    "/session/authorize?client_id=fixture&redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback&state=outer&scope=openid&code_challenge=outer-pkce&code_challenge_method=S256";
  await page.goto(outer);
  await page.getByRole("button", { name: /Fixture OIDC/ }).click();
  await expect(page).toHaveURL(/fixture-idp/);
  expect((await saved(page, "begin-state")).returnTo).toBe(outer);
  expect((await saved(page, "begin-state")).provider).toBe(3);
});

test("callback login persists the native session and removes only its own context", async ({
  page,
}) => {
  await setup(page, { good: context(), other: context(4) });
  await override(page, "/session/openid", login);
  await page.goto("/callback/openid/3?code=synthetic-code&state=good");
  await expect(page).toHaveURL(/\/session\?redirect=/);
  const session = await page.evaluate(() =>
    JSON.parse(localStorage.getItem("cloudreve_session") ?? "null"),
  );
  expect(session.current).toBe("alice");
  expect(session.sessions.alice.token.refresh_token).toBe(token.refresh_token);
  expect(await saved(page, "good")).toBeNull();
  expect(await saved(page, "other")).not.toBeNull();
});

for (const failure of [
  "missing context",
  "wrong provider",
  "ambiguous state",
  "cancelled",
  "expired context",
]) {
  test(
    "rejects " + failure + " before exchanging any authorization code",
    async ({ page }) => {
      const contexts =
        failure === "missing context"
          ? { other: context(4) }
          : {
              bad: context(
                failure === "wrong provider" ? 4 : 3,
                failure === "expired context"
                  ? { expires: Date.now() - 1 }
                  : {},
              ),
              other: context(4),
            };
      const calls = await setup(page, contexts);
      let query = "code=synthetic-code&state=bad";
      if (failure === "ambiguous state") query += "&state=duplicate";
      if (failure === "cancelled") query = "error=access_denied&state=bad";
      await page.goto("/callback/openid/3?" + query);
      await expect(page.getByRole("alert")).toBeVisible();
      expect(
        calls.filter((call) => call.path === "/session/openid"),
      ).toHaveLength(0);
      await expect(page).toHaveURL("http://127.0.0.1:43181/callback/openid/3");
      expect(await saved(page, "other")).not.toBeNull();
    },
  );
}

test("account switch rejects a pending association without replacing local sessions", async ({
  page,
}) => {
  const calls = await setup(
    page,
    {
      link: context(3, {
        linking: true,
        userID: "alice",
        returnTo: "/setting",
      }),
    },
    "bob",
  );
  await page.goto("/callback/openid/3?code=synthetic-code&state=link");
  await expect(page.getByRole("alert")).toContainText("active account changed");
  expect(calls.filter((call) => call.path === "/session/openid")).toHaveLength(
    0,
  );
  const session = await page.evaluate(() =>
    JSON.parse(localStorage.getItem("cloudreve_session")!),
  );
  expect(session.current).toBe("bob");
  expect(session.sessions.other).toBeDefined();
});

test("late IdP completion extends MFA context and restores outer OAuth after original expiry", async ({
  page,
}) => {
  const outer =
    "/session/authorize?client_id=fixture&redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback&state=outer-mfa&scope=openid&code_challenge=mfa-pkce&code_challenge_method=S256";
  await setup(page, {
    mfa: context(3, { expires: Date.now() + 3_000, returnTo: outer }),
    other: context(4),
  });
  await override(page, "/session/openid", "oim_synthetic-challenge", 203);
  await override(page, "/session/token/2fa", login);
  await page.goto("/callback/openid/3?code=synthetic-code&state=mfa");
  await expect(page.getByRole("textbox")).toHaveCount(6);
  expect((await saved(page, "mfa")).expires - Date.now()).toBeGreaterThan(
    240_000,
  );
  // Shift only the browser clock after the original expiry; no slow wall-clock wait.
  await page.evaluate(() => {
    const real = Date.now.bind(Date);
    Date.now = () => real() + 60_000;
  });
  await otp(page);
  await expect(page).toHaveURL("http://127.0.0.1:43181" + outer);
  expect(await saved(page, "mfa")).toBeNull();
  expect(await saved(page, "other")).not.toBeNull();
  expect(
    await page.evaluate(
      () => JSON.parse(localStorage.getItem("cloudreve_session")!).current,
    ),
  ).toBe("alice");
});

test("expired MFA navigation never consumes the server challenge", async ({
  page,
}) => {
  let attempts = 0;
  await setup(page, { mfa: context() });
  await override(page, "/session/openid", "oim_synthetic-challenge", 203);
  await page.route("**/api/v4/session/token/2fa", async (route) => {
    attempts++;
    await route.fulfill({ json: { code: 0, data: login } });
  });
  await page.goto("/callback/openid/3?code=synthetic-code&state=mfa");
  await expect(page.getByRole("textbox")).toHaveCount(6);
  await page.evaluate((key) => {
    const value = JSON.parse(sessionStorage.getItem(key)!);
    value.expires = Date.now() - 1;
    sessionStorage.setItem(key, JSON.stringify(value));
  }, prefix + "mfa");
  await otp(page);
  await expect(page.getByRole("alert")).toContainText("expired");
  expect(attempts).toBe(0);
});

test("anonymous OpenID failure preserves an existing native session", async ({
  page,
}) => {
  await setup(page, { bad: context() }, "alice");
  await override(page, "/session/openid", undefined, 40020);
  await page.goto("/callback/openid/3?code=synthetic-code&state=bad");
  await expect(page.getByRole("alert")).toBeVisible();
  const session = await page.evaluate(() =>
    JSON.parse(localStorage.getItem("cloudreve_session")!),
  );
  expect(session.current).toBe("alice");
  expect(session.sessions.alice.signedOut).not.toBe(true);
  expect(session.sessions.other).toBeDefined();
});

test("successful no-data association preserves credentials and other accounts", async ({
  page,
}) => {
  await setup(
    page,
    {
      link: context(3, {
        linking: true,
        userID: "alice",
        returnTo: "/session?linked=true",
      }),
    },
    "alice",
  );
  await override(page, "/session/openid", undefined);
  await page.goto("/callback/openid/3?code=synthetic-code&state=link");
  await expect(page).toHaveURL(/\/session\?linked=true/);
  const session = await page.evaluate(() =>
    JSON.parse(localStorage.getItem("cloudreve_session")!),
  );
  expect(session.sessions.alice.token).toEqual(token);
  expect(session.sessions.other).toBeDefined();
  expect(await saved(page, "link")).toBeNull();
});

test("untrusted saved return URL normalizes to an internal destination", async ({
  page,
}) => {
  await setup(page, {
    safe: context(3, { returnTo: "https://attacker.invalid/" }),
  });
  await override(page, "/session/openid", login);
  await page.goto("/callback/openid/3?code=synthetic-code&state=safe");
  await expect(page).toHaveURL(/\/home$/);
  expect(new URL(page.url()).origin).toBe("http://127.0.0.1:43181");
});

test("managed security controls reject last unlink while preserving the account", async ({
  page,
}) => {
  await setup(page, {}, "alice");
  await override(page, "/session/openid/3", undefined, 40001);
  await page.goto("/settings?tab=security");
  await expect(
    page.getByText("This account is managed by external sign in.", {
      exact: false,
    }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Add a passkey" }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: /Reset password/i }),
  ).toHaveCount(0);
  await page.getByRole("button", { name: "Unlink", exact: true }).click();
  await expect(page.getByRole("dialog")).toContainText(
    "Unlink this external identity?",
  );
  await page
    .getByRole("dialog")
    .getByRole("button", { name: /confirm|ok/i })
    .click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Unlink", exact: true }),
  ).toBeEnabled();
  expect(
    await page.evaluate(
      () => JSON.parse(localStorage.getItem("cloudreve_session")!).current,
    ),
  ).toBe("alice");
});

test("admin provider editor displays the effective callback rather than the browser origin", async ({
  page,
}) => {
  await setup(page, {}, "admin");
  const callback = "https://canonical.example.test/cloudreve/callback/openid/3";
  await override(page, "/admin/tool/oidc/callback/3", callback);
  await page.goto("/admin/settings?tab=userSession");
  await page.getByRole("button", { name: /Fixture OIDC.*#3/ }).click();
  await expect(page.getByText(callback, { exact: true })).toBeVisible();
  await expect(
    page.getByRole("textbox", { name: /^Client secret/ }),
  ).toHaveAttribute("type", "password");
});
