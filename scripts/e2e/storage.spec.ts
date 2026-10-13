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
    else if (path === "/user/setting/policies") data = [];
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
  const migration=page.getByRole("checkbox",{name:"Relocate storage policy",exact:true});
  await migration.check();
  await page.getByRole("button",{name:/save/i,exact:true}).click();
  await expect.poll(()=>Buffer.from(saved?.group.permissions??"","base64")[1]&4).toBe(4);
  expect(saved.policy_ids).toEqual([1,2]);
  await page.reload();
  await expect(migration).toBeChecked();
  await migration.uncheck();
  await page.getByRole("button",{name:/save/i,exact:true}).click();
  await expect.poll(()=>Buffer.from(saved?.group.permissions??"","base64")[1]&4).toBe(0);
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

test("member selects second policy and completes browser multipart upload", async ({page}) => {
  const user={id:"member",nickname:"Member",email:"member@example.test",created_at:"2026-01-01T00:00:00Z",language:"en-US",group:{id:"members",name:"Members",permission:"AA=="}};
  await page.addInitScript((user)=>{
    localStorage.setItem("i18nextLng","en-US");
    localStorage.setItem("cloudreve_session",JSON.stringify({current:"member",sessions:{member:{user,token:{access_token:"synthetic-access",refresh_token:"synthetic-refresh",access_expires:"2099-01-01T00:00:00Z",refresh_expires:"2099-01-01T00:00:00Z"},settings:{preferred_dark_mode:true}}},anonymousSettings:{}}));
  },user);
  const policies=[{id:"policy-a",name:"Bucket A",type:"s3",max_size:1,allowed_suffix:["bin"]},{id:"policy-b",name:"Bucket B",type:"s3",max_size:0}];
  let upload:any;
  let bytes:Buffer|undefined;
  let completed=false;
  let rejectFirstUpload=true;
  let binding:any;
  const folder={id:"bound-folder",type:1,name:"Bound folder",path:"cloudreve://my/bound",owned:true,capability:"/////w==",metadata:{},size:0,created_at:"2026-01-01T00:00:00Z",updated_at:"2026-01-01T00:00:00Z"};
  await page.route("**/storage-test/**",async route=>{
    if(route.request().method()==="PUT") {
      bytes=route.request().postDataBuffer()??undefined;
      await route.fulfill({status:200,headers:{ETag:'"synthetic-etag"'}});
    } else await route.fulfill({contentType:"application/xml",body:'<CompleteMultipartUploadResult><ETag>"synthetic-etag"</ETag></CompleteMultipartUploadResult>'});
  });
  await page.route("**/api/v4/**",async route=>{
    const req=route.request();
    const path=new URL(req.url()).pathname.replace("/api/v4","");
    let data:any={};
    if(path.startsWith("/site/config/")) data={title:"Storage browser",default_theme:"#3f51b5",themes:"#3f51b5",user,icons:"[]",viewers:"{}"};
    else if(path==="/user/capacity") data={total:1000000,used:0};
    else if(path==="/user/setting/policies") data=policies;
    else if(path==="/file") data={files:[folder],parent:{id:"root",type:1,name:"Root",path:"cloudreve://my/",owned:true,capability:"/////w==",metadata:{}},props:{capability:"/////w=="},pagination:{page:0,page_size:50,total_items:1},storage_policy:policies[0]};
    else if(path==="/file/policy" && req.method()==="PATCH") binding=req.postDataJSON();
    else if(path==="/file/upload"&&req.method()==="PUT") {
      upload=req.postDataJSON();
      if(rejectFirstUpload) {
        rejectFirstUpload=false;
        await route.fulfill({json:{code:50001,msg:"Chosen storage is unavailable"}});
        return;
      }
      data={session_id:"synthetic-session",expires:Math.floor(Date.now()/1000)+600,chunk_size:5242880,upload_urls:["http://127.0.0.1:43181/storage-test/part"],completeURL:"http://127.0.0.1:43181/storage-test/complete",callback_secret:"synthetic-callback",storage_policy:policies[1],uri:upload.uri};
    } else if(path.startsWith("/callback/s3/")) completed=true;
    await route.fulfill({json:{code:0,data}});
  });
  await page.goto("/home");
  await page.getByRole("button",{name:"New",exact:true}).click();
  await page.getByRole("menuitem",{name:"Upload files",exact:true}).click();
  const dialog=page.getByRole("dialog");
  await expect(dialog.getByRole("combobox",{name:"Storage policy"})).toBeVisible();
  await dialog.getByRole("combobox",{name:"Storage policy"}).click();
  await page.getByRole("option",{name:"Bucket B",exact:true}).click();
  const chooser=page.waitForEvent("filechooser");
  await dialog.getByRole("button",{name:"Choose files"}).click();
  await (await chooser).setFiles({name:"browser.txt",mimeType:"text/plain",buffer:Buffer.from("browser chooses B beyond A size/suffix")});
  await expect.poll(()=>upload?.policy_id).toBe("policy-b");
  await expect(page.getByText("Chosen storage is unavailable", {exact:false}).first()).toBeVisible();
  await page.getByRole("button", {name:"Retry", exact:true}).click();
  await expect.poll(()=>completed).toBe(true);
  expect(bytes?.toString()).toBe("browser chooses B beyond A size/suffix");
  await page.getByText("browser.txt", {exact:true}).first().click();
  await expect(page.getByText("Bucket B", {exact:true})).toBeVisible();
  // Automatic requests omit the explicit policy and accept the authoritative
  // credential even when the directory descriptor has stricter constraints.
  await page.getByRole("button", {name: "Close", exact: true}).click();
  await page.getByText("Bound folder", {exact:true}).first().click({button:"right"});
  await page.getByRole("menuitem", {name:"Bind storage policy", exact:true}).click();
  const bindDialog=page.getByRole("dialog");
  await bindDialog.getByRole("combobox",{name:"Storage policy"}).click();
  await page.getByRole("option",{name:"Bucket B",exact:true}).click();
  await bindDialog.getByRole("button",{name:"Save",exact:true}).click();
  await expect.poll(()=>binding?.policy_id).toBe("policy-b");
  expect(new URL(binding.uri).username).toBe("member");
  await page.getByRole("button", {name: "New", exact: true}).click();
  await page.getByRole("menuitem", {name: "Upload files", exact: true}).click();
  await dialog.getByRole("combobox", {name: "Storage policy"}).click();
  await page.getByRole("option", {name: "Automatic", exact: true}).click();
  const automaticChooser = page.waitForEvent("filechooser");
  await dialog.getByRole("button", {name: "Choose files"}).click();
  await (await automaticChooser).setFiles({name:"automatic.txt",mimeType:"text/plain",buffer:Buffer.from("automatic server choice")});
  await expect.poll(() => upload?.uri).toContain("automatic.txt");
  expect(upload).not.toHaveProperty("policy_id");
  await expect.poll(() => bytes?.toString()).toBe("automatic server choice");

  await page.route("**/api/v4/user/setting/policies", route => route.fulfill({json:{code:0,data:[]}}));
  await page.reload();
  await page.getByRole("button", {name: "New", exact: true}).click();
  await page.getByRole("menuitem", {name: "Upload files", exact: true}).click();
  await expect(dialog.getByText("No available storage policies")).toBeVisible();
  await expect(dialog.getByRole("button", {name: "Choose files"})).toBeDisabled();
});

for (const outcome of ["selected", "late", "empty", "failed"]) {
  test(`account switch isolates upload destinations (${outcome})`, async ({page}) => {
    const a={id:"account-a",nickname:"Alice",email:"alice@example.test",created_at:"2026-01-01T00:00:00Z",language:"en-US",group:{id:"members",name:"Members",permission:"AA=="}};
    const b={...a,id:"account-b",nickname:"Bob",email:"bob@example.test"};
    const token=(id:string)=>({access_token:`synthetic-${id}-access`,refresh_token:`synthetic-${id}-refresh`,access_expires:"2099-01-01T00:00:00Z",refresh_expires:"2099-01-01T00:00:00Z"});
    await page.addInitScript(({a,token})=>{
      localStorage.setItem("i18nextLng","en-US");
      localStorage.setItem("cloudreve_session",JSON.stringify({current:a.id,sessions:{[a.id]:{user:a,token,settings:{preferred_dark_mode:true}}},anonymousSettings:{}}));
    },{a,token:token(a.id)});
    const policyA={id:"a-only",name:"Alice only",type:"s3",max_size:0};
    const policyB={id:"b-only",name:"Bob only",type:"s3",max_size:0};
    let current=a;
    let aRequests=0;
    let bRequests=0;
    let upload:any;
    let releaseA!:()=>void;
    const delayedA=new Promise<void>(resolve=>{releaseA=resolve;});
    await page.route("**/account-storage/**",route=>route.fulfill({status:200,headers:{ETag:'"synthetic-etag"'},body:"<CompleteMultipartUploadResult/>"}));
    await page.route("**/api/v4/**",async route=>{
      const req=route.request();
      const path=new URL(req.url()).pathname.replace("/api/v4","");
      let data:any={};
      if(path.startsWith("/site/config/")) data={title:"Accounts",default_theme:"#3f51b5",themes:"#3f51b5",icons:"[]",viewers:"{}",user:current,register_enabled:false};
      else if(path==="/session/prepare") data={password_enabled:true,webauthn_enabled:false,sso_enabled:false,qq_enabled:false};
      else if(path==="/session/token" && req.method()==="POST") { current=b; data={user:b,token:token(b.id)}; }
      else if(path==="/session/token" && req.method()==="DELETE") data=null;
      else if(path==="/user/capacity") data={total:1000000,used:0};
      else if(path==="/user/setting/policies") {
        if(req.headers().authorization===`Bearer ${token(a.id).access_token}`) {
          aRequests++;
          if(outcome!=="selected") await delayedA;
          data=[policyA];
        } else {
          expect(req.headers().authorization).toBe(`Bearer ${token(b.id).access_token}`);
          bRequests++;
          if(outcome==="failed") { await route.fulfill({json:{code:50001,msg:"Current account destinations unavailable"}}); return; }
          data=outcome==="empty"?[]:[policyB];
        }
      } else if(path==="/file") data={files:[],parent:{id:`root-${current.id}`,type:1,name:"Root",path:"cloudreve://my/",owned:true,capability:"/////w==",metadata:{}},props:{capability:"/////w=="},pagination:{page:0,page_size:50,total_items:0},storage_policy:current.id===a.id?policyA:policyB};
      else if(path==="/file/upload" && req.method()==="PUT") {
        expect(req.headers().authorization).toBe(`Bearer ${token(b.id).access_token}`);
        upload=req.postDataJSON();
        data={session_id:"synthetic-b-session",expires:Math.floor(Date.now()/1000)+600,chunk_size:5242880,upload_urls:["http://127.0.0.1:43181/account-storage/part"],completeURL:"http://127.0.0.1:43181/account-storage/complete",callback_secret:"synthetic-b-callback",storage_policy:policyB,uri:upload.uri};
      }
      await route.fulfill({json:{code:0,data}});
    });
    try {
      await page.goto("/home");
      await expect.poll(()=>aRequests).toBeGreaterThan(0);
      if(outcome==="selected") {
        await page.getByRole("button",{name:"New",exact:true}).click();
        await page.getByRole("menuitem",{name:"Upload files",exact:true}).click();
        await page.getByRole("dialog").getByRole("combobox",{name:"Storage policy"}).click();
        await page.getByRole("option",{name:"Alice only",exact:true}).click();
        await page.getByRole("dialog").getByRole("button",{name:"Cancel",exact:true}).click();
      }
      await page.getByRole("button").filter({has:page.locator(".MuiAvatar-root")}).first().click();
      await page.getByRole("menuitem",{name:"Sign out",exact:true}).click();
      await page.locator("input[name=email]").fill(b.email);
      await page.getByRole("button",{name:"Next",exact:true}).click();
      await page.locator("input[name=password]").fill("synthetic-password");
      await page.getByRole("button",{name:"Sign in",exact:true}).click();
      await expect(page).toHaveURL(/\/home/);
      await expect.poll(()=>bRequests).toBeGreaterThan(0);
      releaseA();
      await page.getByRole("button",{name:"New",exact:true}).click();
      await page.getByRole("menuitem",{name:"Upload files",exact:true}).click();
      const dialog=page.getByRole("dialog");
      if(outcome==="empty" || outcome==="failed") {
        await expect(dialog.getByText("No available storage policies")).toBeVisible();
        await expect(dialog.getByRole("button",{name:"Choose files"})).toBeDisabled();
        await expect(dialog.getByText("Alice only")).toHaveCount(0);
      } else {
        const choice=dialog.getByRole("combobox",{name:"Storage policy"});
        await expect(choice).toHaveText("Automatic");
        await choice.click();
        await expect(page.getByRole("option",{name:"Bob only",exact:true})).toBeVisible();
        await expect(page.getByRole("option",{name:"Alice only",exact:true})).toHaveCount(0);
        await page.getByRole("option",{name:"Automatic",exact:true}).click();
        const chooser=page.waitForEvent("filechooser");
        await dialog.getByRole("button",{name:"Choose files",exact:true}).click();
        await (await chooser).setFiles({name:"bob.txt",mimeType:"text/plain",buffer:Buffer.from("Bob's fresh automatic placement")});
        await expect.poll(()=>upload?.uri).toContain("bob.txt");
        expect(upload).not.toHaveProperty("policy_id");
      }
    } finally { releaseA(); }
  });
}
