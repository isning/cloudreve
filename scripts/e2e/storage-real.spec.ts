import {test,expect,Page} from "@playwright/test";
import fs from "node:fs";

// Public native HTTP through the owned fixture proxy, with real S3 assertions
// in the Go caller. This suite never fulfills or replays business responses.
const path=process.env.CLOUDREVE_STORAGE_BROWSER_CONFIG;
if(!path) throw new Error("Native storage browser fixture config is required");
const config=JSON.parse(fs.readFileSync(path,"utf8"));

async function login(page:Page,email:string,password:string){
 await page.goto("/session");
 await page.locator('input[name="email"]').fill(email);
 await page.getByRole("button",{name:"Next",exact:true}).click();
 await expect(page.locator('input[name="password"]')).toBeVisible({timeout:10_000});
 await page.locator('input[name="password"]').fill(password);
 await page.getByRole("button",{name:"Sign in",exact:true}).click();
 await expect(page.getByRole("button",{name:"New",exact:true})).toBeVisible();
}
async function signout(page:Page){
 await page.getByRole("button").filter({has:page.locator(".MuiAvatar-root")}).first().click();
 await page.getByText("Sign out",{exact:true}).click();
 await expect(page.locator('input[name="email"]')).toBeVisible();
}
async function upload(page:Page,name:string,content:string){
 await page.getByRole("button",{name:"New",exact:true}).click();
 await page.getByRole("menuitem",{name:"Upload files",exact:true}).click();
 const dialog=page.getByRole("dialog");
 await expect(dialog.getByRole("combobox",{name:"Storage policy"})).toContainText("Automatic");
 const chooser=page.waitForEvent("filechooser");
 await dialog.getByRole("button",{name:"Choose files",exact:true}).click();
 await (await chooser).setFiles({name,mimeType:"text/plain",buffer:Buffer.from(content)});
 await expect(page.getByRole("button",{name:`${name} Uploaded`,exact:true}).first()).toBeVisible({timeout:30_000});
 await page.getByRole("button",{name:"Close",exact:true}).click();
 await expect(page.getByRole("main").getByText(name,{exact:true})).toBeVisible({timeout:30_000});
}

test("native browser configures two policies, migrates to B and preserves bound A",async({page})=>{
 page.on("pageerror",error=>console.error("Native UI error:",error.message));
 let before:any;
 page.on("response",async r=>{
  if(new URL(r.url()).pathname!=="/api/v4/file")return;
  try {const row=(await r.json()).data.files.find((f:any)=>f.name==="browser.txt");if(row&&!before)before=row;}catch{/* A closed navigation can abandon its response. */}
 });
 await page.addInitScript(()=>localStorage.setItem("i18nextLng","en-US"));
 await login(page,config.admin_email,config.admin_password);
 await page.goto(`/admin/group/${config.group_id}`);
 const choices=page.getByRole("combobox",{name:"Available storage policies"});
 await expect(choices).toBeVisible();
 await choices.click();
 await page.getByRole("option",{name:new RegExp(config.policies[1].name)}).click();
 await page.keyboard.press("Escape");
 const saved=page.waitForResponse(response=>new URL(response.url()).pathname===`/api/v4/admin/group/${config.group_id}` && response.request().method()==="PUT");
 await page.getByRole("button",{name:/save/i,exact:true}).click();
 expect((await (await saved).json()).code).toBe(0);
 await page.reload();
 await expect(choices).toContainText(config.policies[0].name);
 await expect(choices).toContainText(config.policies[1].name);
 await page.goto("/home");
 await signout(page);
 await login(page,config.member_email,config.member_password);
 await page.getByRole("main").getByText("browser-bound",{exact:true}).dblclick();
 await expect(page).toHaveURL(/browser-bound/);
 await page.getByRole("main").getByRole("button",{name:"browser-bound",exact:true}).first().click();
 await page.getByRole("menuitem",{name:"Bind storage policy",exact:true}).click();
 const binding=page.getByRole("dialog");
 await binding.getByRole("combobox",{name:"Storage policy"}).click();
 await page.getByRole("option",{name:config.policies[0].name,exact:true}).click();
 await binding.getByRole("button",{name:"Save",exact:true}).click();
 await expect(binding).not.toBeVisible();
 await upload(page,"browser.txt","real browser and real S3 migration");
 await expect.poll(()=>before?.id).toBeTruthy();
 fs.writeFileSync(config.result_path,JSON.stringify(before),{mode:0o600});
 await page.getByRole("main").getByText("browser.txt",{exact:true}).click({button:"right"});
 await page.getByRole("menuitem",{name:"Relocate storage policy",exact:true}).click();
 const migration=page.getByRole("dialog");
 await migration.getByRole("combobox",{name:"Storage policy"}).click();
 await page.getByRole("option",{name:config.policies[1].name,exact:true}).click();
 await migration.getByRole("button",{name:"Create migration task",exact:true}).click();
 await page.getByRole("alert").getByRole("button",{name:"View",exact:true}).click();
 await expect(page).toHaveURL(/\/tasks/);
 await page.locator(".MuiAccordionSummary-root").filter({hasText:"browser.txt"}).click({position:{x:8,y:8}});
 await expect(page.getByText("Finished",{exact:true}).first()).toBeVisible({timeout:180_000});
 await expect(page.getByRole("button",{name:"Retry",exact:true})).toHaveCount(0);
 await expect(page.getByRole("button",{name:"Cancel",exact:true})).toHaveCount(0);
 await page.goto("/home");
 await page.getByRole("main").getByText("browser-bound",{exact:true}).dblclick();
 await expect(page).toHaveURL(/browser-bound/);
 await upload(page,"future.txt","future uploads still use the bound source");
});

test("native browser mixed overlapping tree migrates versions and permanent link",async({page})=>{
 await page.addInitScript(()=>localStorage.setItem("i18nextLng","en-US"));
 await login(page,config.member_email,config.member_password);
 const selected: any[]=[];
 page.on("response",async response=>{
  if(new URL(response.url()).pathname==="/api/v4/workflow/reloacte" && response.request().method()==="POST") selected.push(response.request().postDataJSON());
 });
 await page.getByRole("main").getByText("tree",{exact:true}).click({modifiers:["Control"]});
 await page.getByRole("main").getByText("inside.txt",{exact:true}).click({modifiers:["Control"]});
 await expect(page.getByRole("button",{name:"2 selected",exact:true})).toBeVisible();
 await page.getByRole("main").getByText("inside.txt",{exact:true}).click({button:"right"});
 await page.getByRole("menuitem",{name:"Relocate storage policy",exact:true}).click();
 const dialog=page.getByRole("dialog");
 
 await dialog.getByRole("combobox",{name:"Storage policy"}).click();
 await page.getByRole("option",{name:config.policies[1].name,exact:true}).click();
 await dialog.getByRole("button",{name:"Create migration task",exact:true}).click();
 await page.getByRole("alert").getByRole("button",{name:"View",exact:true}).click();
 await expect(page).toHaveURL(/\/tasks/);
 await page.locator(".MuiAccordionSummary-root").first().click({position:{x:8,y:8}});
 await expect(page.getByText("Finished",{exact:true}).first()).toBeVisible({timeout:180_000});
 await expect(page.getByText(config.policies[1].name,{exact:false}).first()).toBeVisible();
 await expect(page.getByText("Completed entities: 3 / 3",{exact:true})).toBeVisible();
 await expect(page.getByRole("button",{name:"Retry",exact:true})).toHaveCount(0);
 await expect(page.getByRole("button",{name:"Cancel",exact:true})).toHaveCount(0);
 expect(selected).toHaveLength(1);expect(selected[0].src).toHaveLength(2);
 await page.goto("/home");
 await page.getByRole("main").getByText("tree",{exact:true}).dblclick();await expect(page).toHaveURL(/tree/);
 await page.getByRole("main").getByText("inside.txt",{exact:true}).click({button:"right"});
 await page.getByRole("menuitem",{name:"More actions",exact:true}).hover();
 await page.getByRole("menuitem",{name:"Manage versions",exact:true}).click();
 const versions=page.getByRole("dialog");
 await expect(versions.getByRole("cell",{name:config.policies[1].name,exact:true})).toHaveCount(2);
 for(const row of [1,2]) {
  await versions.getByRole("row").nth(row).getByRole("button").first().click();
  const downloaded=page.waitForEvent("download");
  await page.getByRole("menuitem",{name:"Download",exact:true}).click();
  const download=await downloaded;expect(await download.failure()).toBeNull();
 }
 await page.keyboard.press("Escape");
 const response=await page.request.get(config.permanent_link);
 expect(response.ok()).toBe(true);expect(await response.text()).toBe("inside current version");
});
