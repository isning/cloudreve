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

for (const resume of [false,true]) {
  test(`binding refreshes current automatic placement and preserves issued A (${resume?"resume":"queued"})`,async ({page})=>{
    const user={id:"member",nickname:"Member",email:"member@example.test",created_at:"2026-01-01T00:00:00Z",language:"en-US",group:{id:"members",name:"Members",permission:"AA=="}};
    await page.addInitScript(user=>{
      localStorage.setItem("i18nextLng","en-US");
      localStorage.setItem("cloudreve_session",JSON.stringify({current:user.id,sessions:{[user.id]:{user,token:{access_token:"synthetic-access",refresh_token:"synthetic-refresh",access_expires:"2099-01-01T00:00:00Z",refresh_expires:"2099-01-01T00:00:00Z"},settings:{preferred_dark_mode:true,concurrent_limit:1}}},anonymousSettings:{}}));
    },user);
    const policies=[{id:"policy-a",name:"Bucket A",type:"s3",max_size:0},{id:"policy-b",name:"Bucket B",type:"s3",max_size:0}];
    const folder={id:"bound",type:1,name:"bound",path:"cloudreve://my/bound",owned:true,capability:"/////w==",metadata:{},created_at:"2026-01-01T00:00:00Z",updated_at:"2026-01-01T00:00:00Z"};
    let bound=false;
    let oldStarted=false;
    let allowOld=!resume;
    let releaseOld!:()=>void;
    const oldBarrier=new Promise<void>(resolve=>{releaseOld=resolve;});
    const sessions:any[]=[];
    const callbacks:string[]=[];
    const bytes:Record<string,string>={};
    await page.route("**/binding-storage/**",async route=>{
      const path=new URL(route.request().url()).pathname;
      if(path.endsWith("/a-part")) { oldStarted=true; await oldBarrier; if(!allowOld) { await route.abort("failed"); return; } }
      if(route.request().method()==="PUT") bytes[path]=route.request().postDataBuffer()?.toString()??"";
      await route.fulfill({status:200,headers:{ETag:'"synthetic-etag"'},contentType:"application/xml",body:'<CompleteMultipartUploadResult><ETag>"synthetic-etag"</ETag></CompleteMultipartUploadResult>'});
    });
    await page.route("**/api/v4/**",async route=>{
      const req=route.request();
      const path=new URL(req.url()).pathname.replace("/api/v4","");
      let data:any={};
      if(path.startsWith("/site/config/")) data={title:"Bindings",default_theme:"#3f51b5",themes:"#3f51b5",icons:"[]",viewers:"{}",user};
      else if(path==="/user/capacity") data={total:1000000,used:0};
      else if(path==="/user/setting/policies") data=policies;
      else if(path==="/file") data={files:[],parent:folder,props:{capability:"/////w=="},pagination:{page:0,page_size:50,total_items:0},storage_policy:policies[bound?1:0]};
      else if(path==="/file/info") data={...folder,extended_info:{storage_policy:policies[bound?1:0],entities:[],shares:[]}};
      else if(path==="/file/policy" && req.method()==="PATCH") { expect(req.postDataJSON().policy_id).toBe("policy-b"); bound=true; }
      else if(path==="/file/upload" && req.method()==="PUT") {
        const upload=req.postDataJSON();
        sessions.push(upload);
        const which=bound?"b":"a";
        data={session_id:`synthetic-${which}`,expires:Math.floor(Date.now()/1000)+600,chunk_size:5242880,upload_urls:[`http://127.0.0.1:43181/binding-storage/${which}-part`],completeURL:`http://127.0.0.1:43181/binding-storage/${which}-complete`,callback_secret:`synthetic-${which}-callback`,storage_policy:policies[bound?1:0],uri:upload.uri};
      } else if(path.startsWith("/callback/s3/")) callbacks.push(path);
      await route.fulfill({json:{code:0,data}});
    });
    const selectFile=async (name:string,expected:string)=>{
      await page.getByRole("button",{name:"New",exact:true}).click();
      await page.getByRole("menuitem",{name:"Upload files",exact:true}).click();
      const dialog=page.getByRole("dialog");
      await expect(dialog.getByText(`Current folder destination: ${expected}`,{exact:true})).toBeVisible();
      const chooser=page.waitForEvent("filechooser");
      await dialog.getByRole("button",{name:"Choose files",exact:true}).click();
      await (await chooser).setFiles({name,mimeType:"text/plain",buffer:Buffer.from(name)});
    };
    try {
      await page.goto("/home?path="+encodeURIComponent(folder.path));
      await selectFile("issued-a.txt","Bucket A");
      await expect.poll(()=>oldStarted).toBe(true);
      await page.getByRole("button",{name:"Close",exact:true}).click();
      await page.getByRole("main").getByRole("button",{name:"bound",exact:true}).click();
      await page.getByRole("menuitem",{name:"Bind storage policy",exact:true}).click();
      const bind=page.getByRole("dialog");
      await expect(bind.getByText("New uploads use this policy. Existing content keeps its current location.")).toBeVisible();
      await bind.getByRole("combobox",{name:"Storage policy"}).click();
      await page.getByRole("option",{name:"Bucket B",exact:true}).click();
      await bind.getByRole("button",{name:"Save",exact:true}).click();
      await expect.poll(()=>bound).toBe(true);
      await expect(bind).toHaveCount(0);
      await selectFile("new-b.txt","Bucket B");
      // The second uploader is queued while the issued A transfer is paused.
      expect(sessions).toHaveLength(1);
      releaseOld();
      if(resume) {
        await page.getByText("issued-a.txt",{exact:true}).first().hover();
        await expect(page.getByRole("button",{name:"Retry",exact:true})).toBeVisible({timeout:15000});
        allowOld=true;
        await page.getByRole("button",{name:"Retry",exact:true}).click();
      }
      await expect.poll(()=>callbacks.length).toBe(2);
      expect(sessions).toHaveLength(2);
      for(const upload of sessions) expect(upload).not.toHaveProperty("policy_id");
      expect(callbacks.some(path=>path.includes("synthetic-a/"))).toBe(true);
      expect(callbacks.some(path=>path.includes("synthetic-b/"))).toBe(true);
      expect(bytes["/binding-storage/a-part"]).toBe("issued-a.txt");
      expect(bytes["/binding-storage/b-part"]).toBe("new-b.txt");
    } finally { releaseOld(); }
  });
}

test("binding boundaries and rejected destination keep automatic placement",async ({page})=>{
  const user={id:"member",nickname:"Member",email:"member@example.test",created_at:"2026-01-01T00:00:00Z",language:"en-US",group:{id:"members",name:"Members",permission:"AA=="}};
  await page.addInitScript(user=>{
    localStorage.setItem("i18nextLng","en-US");
    localStorage.setItem("cloudreve_session",JSON.stringify({current:user.id,sessions:{[user.id]:{user,token:{access_token:"synthetic-access",refresh_token:"synthetic-refresh",access_expires:"2099-01-01T00:00:00Z",refresh_expires:"2099-01-01T00:00:00Z"},settings:{preferred_dark_mode:true}}},anonymousSettings:{}}));
  },user);
  const policies=[{id:"encoded-policy-a",name:"Bucket A",type:"s3",max_size:0},{id:"encoded-policy-b",name:"Bucket B",type:"s3",max_size:0}];
  const base={type:1,owned:true,capability:"/////w==",metadata:{},created_at:"2026-01-01T00:00:00Z",updated_at:"2026-01-01T00:00:00Z"};
  const rejected=[
    {...base,id:"plain-row",name:"plain.txt",type:0,path:"cloudreve://my/plain.txt",primary_entity:"entity-a"},
    {...base,id:"symbolic-row",name:"Symbolic folder",path:"cloudreve://my/shortcut",metadata:{"sys:shared_redirect":"https://share.example.test"}},
    {...base,id:"foreign-row",name:"Foreign folder",path:"cloudreve://foreign@my/folder",owned:false},
    {...base,id:"read-only-row",name:"No binding capability",path:"cloudreve://my/read-only",capability:Buffer.from([255,255,223,255]).toString("base64")},
  ];
  const valid={...base,id:"valid-row",name:"Owned folder",path:"cloudreve://my/owned"};
  let patch:any;
  let upload:any;
  await page.route("**/boundary-storage/**",route=>route.fulfill({status:200,headers:{ETag:'"synthetic-etag"'},contentType:"application/xml",body:'<CompleteMultipartUploadResult><ETag>"synthetic-etag"</ETag></CompleteMultipartUploadResult>'}));
  await page.route("**/api/v4/**",async route=>{
    const req=route.request();
    const path=new URL(req.url()).pathname.replace("/api/v4","");
    let data:any={};
    if(path.startsWith("/site/config/")) data={title:"Bind boundaries",default_theme:"#3f51b5",themes:"#3f51b5",icons:"[]",viewers:"{}",user};
    else if(path==="/user/capacity") data={total:1000000,used:0};
    else if(path==="/user/setting/policies") data=policies;
    else if(path==="/file") {
      const trash=new URL(req.url()).searchParams.get("uri")?.includes("trash");
      data={files:trash?[{...base,id:"trash-row",name:"Trash folder"}]:[...rejected,valid],parent:{...base,id:"root",name:"Root",path:trash?"cloudreve://trash":"cloudreve://my/"},props:{capability:"/////w=="},pagination:{page:0,page_size:50,total_items:trash?1:5},storage_policy:policies[0]};
    }
    else if(path==="/file/policy" && req.method()==="PATCH") {
      patch=req.postDataJSON();
      await route.fulfill({json:{code:40007,msg:"Storage destination revoked"}});
      return;
    } else if(path==="/file/upload" && req.method()==="PUT") {
      upload=req.postDataJSON();
      data={session_id:"synthetic-a",expires:Math.floor(Date.now()/1000)+600,chunk_size:5242880,upload_urls:["http://127.0.0.1:43181/boundary-storage/part"],completeURL:"http://127.0.0.1:43181/boundary-storage/complete",callback_secret:"synthetic-callback",storage_policy:policies[0],uri:upload.uri};
    }
    await route.fulfill({json:{code:0,data}});
  });
  await page.goto("/home");
  await page.getByRole("main").getByRole("button",{name:"My Files",exact:true}).click();
  await expect(page.getByRole("menuitem",{name:"Bind storage policy",exact:true})).toHaveCount(0);
  for(const target of rejected) {
    await page.getByText(target.name,{exact:true}).first().click({button:"right"});
    await expect(page.getByRole("menuitem",{name:"Bind storage policy",exact:true})).toHaveCount(0);
    await page.keyboard.press("Escape");
  }
  await page.goto("/home?path="+encodeURIComponent("cloudreve://trash"));
  await page.getByText("Trash folder",{exact:true}).first().click({button:"right"});
  await expect(page.getByRole("menuitem",{name:"Bind storage policy",exact:true})).toHaveCount(0);
  await page.keyboard.press("Escape");
  expect(patch).toBeUndefined();
  await page.goto("/home");
  await page.getByText("Owned folder",{exact:true}).first().click({button:"right"});
  await page.getByRole("menuitem",{name:"Bind storage policy",exact:true}).click();
  const bind=page.getByRole("dialog");
  await bind.getByRole("combobox",{name:"Storage policy"}).click();
  await page.getByRole("option",{name:"Bucket B",exact:true}).click();
  await bind.getByRole("button",{name:"Save",exact:true}).click();
  await expect(page.getByText("Current group have no permission to perform such action.",{exact:true})).toBeVisible();
  await expect(bind.getByRole("combobox",{name:"Storage policy"})).toHaveText("Bucket B");
  await expect(bind.getByRole("button",{name:"Save",exact:true})).toBeEnabled();
  expect(patch.policy_id).toBe("encoded-policy-b");
  expect(new URL(patch.uri).username).toBe("member");
  await bind.getByRole("button",{name:"Cancel",exact:true}).click();
  await page.getByRole("button",{name:"New",exact:true}).click();
  await page.getByRole("menuitem",{name:"Upload files",exact:true}).click();
  const dialog=page.getByRole("dialog");
  await expect(dialog.getByText("Current folder destination: Bucket A",{exact:true})).toBeVisible();
  const chooser=page.waitForEvent("filechooser");
  await dialog.getByRole("button",{name:"Choose files",exact:true}).click();
  await (await chooser).setFiles({name:"after-rejected-bind.txt",mimeType:"text/plain",buffer:Buffer.from("old placement survives rejection")});
  await expect.poll(()=>upload?.uri).toContain("after-rejected-bind.txt");
  expect(upload).not.toHaveProperty("policy_id");
});

test("community migration submits official contract and follows accepted task",async ({page})=>{
  const user={id:"member",nickname:"Member",email:"member@example.test",created_at:"2026-01-01T00:00:00Z",language:"en-US",group:{id:"members",name:"Members",permission:Buffer.from([0,4]).toString("base64")}};
  await page.addInitScript(user=>{
    localStorage.setItem("i18nextLng","en-US");
    localStorage.setItem("cloudreve_session",JSON.stringify({current:user.id,sessions:{[user.id]:{user,token:{access_token:"synthetic-access",refresh_token:"synthetic-refresh",access_expires:"2099-01-01T00:00:00Z",refresh_expires:"2099-01-01T00:00:00Z"},settings:{preferred_dark_mode:true}}},anonymousSettings:{}}));
  },user);
  const policy={id:"encoded-policy-a",name:"Bucket A",type:"s3",max_size:0};
  const file={id:"file-a",type:0,name:"relocate.txt",path:"cloudreve://my/relocate.txt",owned:true,capability:"/////w==",metadata:{},size:12,primary_entity:"entity-a",created_at:"2026-01-01T00:00:00Z",updated_at:"2026-01-01T00:00:00Z"};
  const requests:any[]=[];
  let accepted:any;
  await page.route("**/api/v4/**",async route=>{
    const req=route.request();
    const path=new URL(req.url()).pathname.replace("/api/v4","");
    let data:any={};
    if(path.startsWith("/site/config/")) data={title:"Migration",default_theme:"#3f51b5",themes:"#3f51b5",icons:"[]",viewers:"{}",user};
    else if(path==="/user/capacity") data={total:1000000,used:12};
    else if(path==="/user/setting/policies") data=[policy];
    else if(path==="/file") data={files:[file],parent:{id:"root",type:1,name:"Root",path:"cloudreve://my/",owned:true,capability:"/////w==",metadata:{}},props:{capability:"/////w=="},pagination:{page:0,page_size:50,total_items:1},storage_policy:policy};
    else if(path==="/workflow/reloacte" && req.method()==="POST") {
      requests.push(req.postDataJSON());
      if(requests.length===1) { await route.fulfill({json:{code:50001,msg:"Migration destination unavailable"}}); return; }
      accepted={id:"encoded-task",type:"relocate",status:"queued",created_at:"2026-01-01T00:00:00Z",updated_at:"2026-01-01T00:00:00Z",summary:{phase:"planning",props:{src_multiple:requests[1].src,dst_policy_id:policy.id,dst_policy_name:policy.name}}};
      data=accepted;
    } else if(path==="/workflow") data={tasks:accepted?[{...accepted,status:"completed",summary:{...accepted.summary,phase:"completed"}}]:[],pagination:{page:0,page_size:25,total_items:accepted?1:0}};
    await route.fulfill({json:{code:0,data}});
  });
  await page.goto("/home");
  await page.getByText("relocate.txt",{exact:true}).first().click({button:"right"});
  await page.getByRole("menuitem",{name:"Relocate storage policy",exact:true}).click();
  const dialog=page.getByRole("dialog");
  await expect(dialog.getByText("Move existing content to another storage policy. Future upload preferences remain unchanged.")).toBeVisible();
  const create=dialog.getByRole("button",{name:"Create migration task",exact:true});
  await expect(create).toBeDisabled();
  expect(requests).toHaveLength(0);
  await dialog.getByRole("combobox",{name:"Storage policy"}).click();
  await page.getByRole("option",{name:"Bucket A",exact:true}).click();
  await create.click();
  await expect(page.getByText("Migration destination unavailable",{exact:false})).toBeVisible();
  await expect(dialog.getByRole("combobox",{name:"Storage policy"})).toHaveText("Bucket A");
  await expect(create).toBeEnabled();
  expect(accepted).toBeUndefined();
  await create.click();
  await expect(page.getByText("Migration task accepted. Follow its progress in Background Tasks.",{exact:true})).toBeVisible();
  expect(requests).toHaveLength(2);
  expect(requests[1].dst_policy_id).toBe("encoded-policy-a");
  expect(requests[1].src).toHaveLength(1);
  const source=new URL(requests[1].src[0]);
  expect(source.username).toBe("member");
  expect(source.pathname).toBe("/relocate.txt");
  await page.getByRole("button",{name:"View",exact:true}).last().click();
  await expect(page).toHaveURL(/\/tasks/);
  await expect(page.getByText("Bucket A",{exact:false}).first()).toBeVisible();
  await expect(page.getByText("relocate.txt",{exact:true}).first()).toBeVisible();
  await expect(page.getByRole("button",{name:"Retry",exact:true})).toHaveCount(0);
  await expect(page.getByRole("button",{name:"Cancel",exact:true})).toHaveCount(0);
});

test("migration permission refresh hides stale actions without changing upload grants",async ({page})=>{
  const user={id:"member",nickname:"Member",email:"member@example.test",created_at:"2026-01-01T00:00:00Z",language:"en-US",group:{id:"members",name:"Members",permission:Buffer.from([0,4]).toString("base64")}};
  await page.addInitScript(user=>{
    localStorage.setItem("i18nextLng","en-US");
    localStorage.setItem("cloudreve_session",JSON.stringify({current:user.id,sessions:{[user.id]:{user,token:{access_token:"synthetic-access",refresh_token:"synthetic-refresh",access_expires:"2099-01-01T00:00:00Z",refresh_expires:"2099-01-01T00:00:00Z"},settings:{preferred_dark_mode:true}}},anonymousSettings:{}}));
  },user);
  const policies=[{id:"encoded-policy-a",name:"Bucket A",type:"s3",max_size:0},{id:"encoded-policy-b",name:"Bucket B",type:"s3",max_size:0}];
  const file={id:"file-a",type:0,name:"permissions.txt",path:"cloudreve://my/permissions.txt",owned:true,metadata:{},size:12,primary_entity:"entity-a",created_at:"2026-01-01T00:00:00Z",updated_at:"2026-01-01T00:00:00Z"};
  let permitted=true;
  let lists=0;
  let attempts=0;
  let accepted=0;
  await page.route("**/api/v4/**",async route=>{
    const req=route.request();
    const path=new URL(req.url()).pathname.replace("/api/v4","");
    let data:any={};
    if(path.startsWith("/site/config/")) data={title:"Permissions",default_theme:"#3f51b5",themes:"#3f51b5",icons:"[]",viewers:"{}",user:{...user,group:{...user.group,permission:permitted?user.group.permission:"AA=="}}};
    else if(path==="/user/capacity") data={total:1000000,used:12};
    else if(path==="/user/setting/policies") data=policies;
    else if(path==="/file") {
      lists++;
      data={files:[{...file,capability:permitted?"/////w==":Buffer.from([255,255,191,255]).toString("base64")}],parent:{id:"root",type:1,name:"Root",path:"cloudreve://my/",owned:true,capability:"/////w==",metadata:{}},props:{capability:"/////w=="},pagination:{page:0,page_size:50,total_items:1},storage_policy:policies[0]};
    } else if(path==="/workflow/reloacte" && req.method()==="POST") {
      attempts++;
      if(!permitted) { await route.fulfill({json:{code:40007,msg:"Storage migration is disabled for this group"}}); return; }
      accepted++;
      data={id:"encoded-task",type:"relocate",status:"queued",created_at:"2026-01-01T00:00:00Z",updated_at:"2026-01-01T00:00:00Z"};
    }
    await route.fulfill({json:{code:0,data}});
  });
  await page.goto("/home");
  await page.getByText("permissions.txt",{exact:true}).first().click({button:"right"});
  await page.getByRole("menuitem",{name:"Relocate storage policy",exact:true}).click();
  let dialog=page.getByRole("dialog");
  await dialog.getByRole("combobox",{name:"Storage policy"}).click();
  await page.getByRole("option",{name:"Bucket B",exact:true}).click();
  const before=lists;
  permitted=false;
  await dialog.getByRole("button",{name:"Create migration task",exact:true}).click();
  await expect(page.getByText("Current group have no permission to perform such action.",{exact:true})).toBeVisible();
  await expect.poll(()=>lists).toBeGreaterThan(before);
  expect(accepted).toBe(0);
  expect(attempts).toBe(1);
  await expect(dialog.getByRole("button",{name:"Create migration task",exact:true})).toBeDisabled();
  await dialog.getByRole("button",{name:"Cancel",exact:true}).click();
  await page.getByText("permissions.txt",{exact:true}).first().click({button:"right"});
  await expect(page.getByRole("menuitem",{name:"Relocate storage policy",exact:true})).toHaveCount(0);
  await page.keyboard.press("Escape");
  await page.getByRole("button",{name:"New",exact:true}).click();
  await page.getByRole("menuitem",{name:"Upload files",exact:true}).click();
  dialog=page.getByRole("dialog");
  await dialog.getByRole("combobox",{name:"Storage policy"}).click();
  await expect(page.getByRole("option",{name:"Bucket B",exact:true})).toBeVisible();
  await page.keyboard.press("Escape");
  await dialog.getByRole("button",{name:"Cancel",exact:true}).click();
  permitted=true;
  const reload=page.waitForResponse(response=>new URL(response.url()).pathname==="/api/v4/file");
  const refresh=page.getByRole("button",{name:"Refresh",exact:true});
  await refresh.click();
  await reload;
  await expect(refresh.locator("svg")).toHaveCSS("animation-name","none");
  await page.getByText("permissions.txt",{exact:true}).first().click({button:"right"});
  await page.getByRole("menuitem",{name:"Relocate storage policy",exact:true}).click();
  dialog=page.getByRole("dialog");
  await dialog.getByRole("combobox",{name:"Storage policy"}).click();
  await page.getByRole("option",{name:"Bucket B",exact:true}).click();
  await dialog.getByRole("button",{name:"Create migration task",exact:true}).click();
  await expect.poll(()=>accepted).toBe(1);
});

for(const blocked of ["eligible","foreign","symbolic","trash","no_capability","missing_capability"]) {
  test(`mixed migration selection checks every source (${blocked})`,async ({page})=>{
    const user={id:"member",nickname:"Member",email:"member@example.test",created_at:"2026-01-01T00:00:00Z",language:"en-US",group:{id:"members",name:"Members",permission:Buffer.from([0,4]).toString("base64")}};
    await page.addInitScript(user=>{
      localStorage.setItem("i18nextLng","en-US");
      localStorage.setItem("cloudreve_session",JSON.stringify({current:user.id,sessions:{[user.id]:{user,token:{access_token:"synthetic-access",refresh_token:"synthetic-refresh",access_expires:"2099-01-01T00:00:00Z",refresh_expires:"2099-01-01T00:00:00Z"},settings:{preferred_dark_mode:true}}},anonymousSettings:{}}));
    },user);
    const policy={id:"encoded-policy-b",name:"Bucket B",type:"s3",max_size:0};
    const common={owned:true,capability:"/////w==",metadata:{},created_at:"2026-01-01T00:00:00Z",updated_at:"2026-01-01T00:00:00Z"};
    const file={...common,id:"source-file",type:0,name:"picked.txt",path:"cloudreve://my/picked.txt",size:12,primary_entity:"entity-a"};
    const folder:any={...common,id:"source-folder",type:1,name:"picked-folder",path:"cloudreve://my/picked-folder"};
    if(blocked==="foreign") folder.owned=false;
    if(blocked==="symbolic") folder.metadata={"sys:shared_redirect":"https://share.example.test"};
    if(blocked==="trash") { folder.path="cloudreve://trash/picked-folder";folder.metadata={"sys:restore_uri":"cloudreve://my/picked-folder"}; }
    if(blocked==="no_capability") folder.capability=Buffer.from([255,255,191,255]).toString("base64");
    if(blocked==="missing_capability") delete folder.capability;
    let migration:any;
    await page.route("**/api/v4/**",async route=>{
      const req=route.request();
      const path=new URL(req.url()).pathname.replace("/api/v4","");
      let data:any={};
      if(path.startsWith("/site/config/")) data={title:"Mixed selection",default_theme:"#3f51b5",themes:"#3f51b5",icons:"[]",viewers:"{}",user};
      else if(path==="/user/capacity") data={total:1000000,used:12};
      else if(path==="/user/setting/policies") data=[policy];
      else if(path==="/file") data={files:[file,folder],parent:{...common,id:"root",type:1,name:"Root",path:"cloudreve://my/"},props:{capability:"/////w=="},pagination:{page:0,page_size:50,total_items:2},storage_policy:policy};
      else if(path==="/workflow/reloacte" && req.method()==="POST") { migration=req.postDataJSON();data={id:"encoded-task",type:"relocate",status:"queued",created_at:"2026-01-01T00:00:00Z",updated_at:"2026-01-01T00:00:00Z"}; }
      await route.fulfill({json:{code:0,data}});
    });
    await page.goto("/home");
    await page.getByRole("main").getByText("picked.txt",{exact:true}).click();
    await page.getByRole("main").getByText("picked-folder",{exact:true}).click({modifiers:["Control"]});
    await page.getByRole("main").getByText("picked.txt",{exact:true}).click({button:"right"});
    const entry=page.getByRole("menuitem",{name:"Relocate storage policy",exact:true});
    if(blocked!=="eligible") { await expect(entry).toHaveCount(0);expect(migration).toBeUndefined();return; }
    await entry.click();
    const dialog=page.getByRole("dialog");
    await dialog.getByRole("combobox",{name:"Storage policy"}).click();
    await page.getByRole("option",{name:"Bucket B",exact:true}).click();
    await dialog.getByRole("button",{name:"Create migration task",exact:true}).click();
    await expect.poll(()=>migration?.src?.length).toBe(2);
    expect(migration.dst_policy_id).toBe("encoded-policy-b");
    expect(migration.src.map((src:string)=>new URL(src).pathname).sort()).toEqual(["/picked-folder","/picked.txt"]);
    for(const src of migration.src) expect(new URL(src).username).toBe("member");
  });
}

for(const available of [true,false]) {
  test(`fresh tasks page resolves public migration destination (${available?"available":"unavailable"})`,async ({page})=>{
    const user={id:"member",nickname:"Member",email:"member@example.test",created_at:"2026-01-01T00:00:00Z",language:"en-US",group:{id:"members",name:"Members",permission:"AA=="}};
    await page.addInitScript(user=>{
      localStorage.setItem("i18nextLng","en-US");
      localStorage.setItem("cloudreve_session",JSON.stringify({current:user.id,sessions:{[user.id]:{user,token:{access_token:"synthetic-member-access",refresh_token:"synthetic-refresh",access_expires:"2099-01-01T00:00:00Z",refresh_expires:"2099-01-01T00:00:00Z"},settings:{preferred_dark_mode:true}}},anonymousSettings:{}}));
    },user);
    let descriptions=0;
    await page.route("**/api/v4/**",async route=>{
      const req=route.request();
      const path=new URL(req.url()).pathname.replace("/api/v4","");
      expect(path.startsWith("/admin/")).toBe(false);
      let data:any={};
      if(path.startsWith("/site/config/")) data={title:"Fresh tasks",default_theme:"#3f51b5",themes:"#3f51b5",icons:"[]",viewers:"{}",user};
      else if(path==="/user/capacity") data={total:1000000,used:12};
      else if(path==="/user/setting/policies") {
        expect(req.headers().authorization).toBe("Bearer synthetic-member-access");
        descriptions++;
        data=[{id:"encoded-policy-a",name:"Current default A",type:"s3",max_size:0},...(available?[{id:"encoded-policy-b",name:"Current bucket B",type:"s3",max_size:0}]:[])];
      } else if(path==="/workflow") data={tasks:[{id:"encoded-task",type:"relocate",status:"completed",created_at:"2026-01-01T00:00:00Z",updated_at:"2026-01-01T00:00:00Z",summary:{phase:"completed",props:{src_multiple:["cloudreve://member@my/historical.txt"],dst_policy_id:"encoded-policy-b",dst_policy_name:"Old stored bucket name"}}}],pagination:{page:0,page_size:25,total_items:1}};
      await route.fulfill({json:{code:0,data}});
    });
    await page.goto("/tasks");
    await expect.poll(()=>descriptions).toBeGreaterThan(0);
    await expect(page.getByText("historical.txt",{exact:true}).first()).toBeVisible();
    await expect(page.getByText(available?"Current bucket B":"Policy outside current choices (encoded-policy-b)",{exact:false}).first()).toBeVisible();
    await expect(page.getByText("Current default A",{exact:false})).toHaveCount(0);
    await expect(page.getByText("Old stored bucket name",{exact:false})).toHaveCount(0);
  });
}
