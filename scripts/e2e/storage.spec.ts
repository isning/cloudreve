import { test, expect, Route } from "@playwright/test";

// Production frontend, controlled public HTTP boundary. Backend/S3 behavior is
// verified independently by the native-auth Go storage integration suite.
test("administrator saves and reopens a group with two available policies", async ({ page }) => {
  const user = { id: "admin", nickname: "Administrator", email: "admin@example.test", created_at: "2026-01-01T00:00:00Z", language: "en-US", group: { id: "admins", name: "Administrators", permission: "AQ==" } };
  await page.addInitScript((user) => {
    localStorage.setItem("i18nextLng", "en-US");
    localStorage.setItem("cloudreve_session", JSON.stringify({current: "admin", sessions: {admin: {user, token: {access_token: "synthetic-access", refresh_token: "synthetic-refresh", access_expires: "2099-01-01T00:00:00Z", refresh_expires: "2099-01-01T00:00:00Z"}, settings: {preferred_dark_mode: true}}}, anonymousSettings: {}}));
  }, user);
  let ids = [1];
  let saved: any;
  let group: any = { id: 2, name: "Storage members", permissions: "AA==", max_storage: 1000000, edges: {storage_policies: {id: 1, name: "Bucket A", type: "s3"}}, settings: {max_walked_files: 10000, trash_retention: 60} };
  await page.route("**/api/v4/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname.replace("/api/v4", "");
    let data: any = {};
    if (path.startsWith("/site/config/")) data = {title: "Cloudreve storage test", default_theme: "#3f51b5", themes: "#3f51b5", user};
    else if (path === "/user/capacity") data = {total: 1000000, used: 0};
    else if (path === "/admin/group/2") {
      if (request.method() === "PUT") {
        saved = request.postDataJSON();
        ids = saved.policy_ids;
        group = {...saved.group, edges: {storage_policies: {id: ids[0], name: "Bucket A", type: "s3"}}};
      }
      data = {...group, group, policy_ids: ids, total_users: 1};
    } else if (path === "/admin/policy") data = {policies: [{id: 1, name: "Bucket A", type: "s3"}, {id: 2, name: "Bucket B", type: "s3"}], pagination: {total_items: 2, page_size: 1000, page: 0}};
    else if (path === "/admin/group") data = {groups: [group], pagination: {total_items: 1, page_size: 50, page: 0}};
    else if (path === "/file") data = {files: [], parent: {id: "root", type: 1, name: "Root", path: "/", props: {}}, props: {}, pagination: {page: 0, page_size: 50, total_items: 0}};
    await route.fulfill({json: {code: 0, data}});
  });
  await page.goto("/admin/group/2");
  const policies = page.getByRole("combobox", {name: "Available storage policies"});
  await expect(policies).toBeVisible();
  await policies.click();
  await page.getByRole("option", {name: /Bucket B/}).click();
  await page.keyboard.press("Escape");
  await page.getByRole("button", {name: /save/i, exact: true}).click();
  await expect.poll(() => saved?.policy_ids).toEqual([1, 2]);
  expect(saved.group.edges.storage_policies.id).toBe(1);
  await page.reload();
  await expect(policies).toContainText("Bucket A");
  await expect(policies).toContainText("Bucket B");
  await page.getByRole("button", {name: "Move Bucket B up"}).click();
  await page.getByRole("button", {name: /save/i, exact: true}).click();
  await expect.poll(() => saved?.policy_ids).toEqual([2, 1]);
  expect(saved.group.edges.storage_policies.id).toBe(2);
  await page.reload();
  await expect(policies).toContainText("Bucket B · Default");
  const rejectSave = async (route: Route) => {
    if (route.request().method() === "PUT") {
      await route.fulfill({json: {code: 40001, msg: "Invalid storage policy assignment"}});
    } else await route.fallback();
  };
  await page.route("**/api/v4/admin/group/2", rejectSave);
  await policies.click();
  await page.getByRole("option", {name: /Bucket A/}).click();
  await page.keyboard.press("Escape");
  await page.getByRole("button", {name: /save/i, exact: true}).click();
  await expect(page.getByText("Invalid storage policy assignment")).toBeVisible();
  await page.reload();
  await expect(policies).toContainText("Bucket A");
  await expect(policies).toContainText("Bucket B · Default");
  await page.unroute("**/api/v4/admin/group/2", rejectSave);
  await policies.click();
  await page.getByRole("option", {name: /Bucket A/}).click();
  await page.keyboard.press("Escape");
  await page.getByRole("button", {name: /save/i, exact: true}).click();
  await expect.poll(() => saved?.policy_ids).toEqual([2]);
});
