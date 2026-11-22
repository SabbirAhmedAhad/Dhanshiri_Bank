const { JSDOM } = require("jsdom"); const fs = require("fs"); const { webcrypto } = require("crypto");
const sleep = (ms = 60) => new Promise((r) => setTimeout(r, ms));
const log = [];
let w; function fakeFetch(url, opts = {}) {
  const j = (o, ok = true) => Promise.resolve({ ok, json: async () => o });
  if (url.endsWith("/api/me")) return j({ csrf: "t", user: w.__user || null });
  if (url.endsWith("/api/register")) return j({ ok: true });
  if (url.endsWith("/api/login")) return j({ otp: true, phone: "•••••••001" });
  if (url.endsWith("/api/login/otp")) { w.__user = { name: "Rahim Uddin", role: "customer", username: "rahim" }; return j({ user: w.__user, csrf: "t2" }); }
  if (url.endsWith("/api/logout")) { w.__user = null; return j({ ok: true }); }
  if (url.endsWith("/api/accounts")) return j({ accounts: [{ no: "0101-000123", balance: 1500000 }] });
  if (url.includes("/api/accounts/") && !url.includes("link")) return j({ no: "0101-000123", balance: 1500000, txns: [] });
  return j({ error: "not mocked: " + url }, false);
}
const dom = new JSDOM('<!doctype html><html><body><div id="root"></div></body></html>', { url: "https://ibank.dhanshiri.test:8443/", pretendToBeVisual: true, runScripts: "outside-only" });
w = dom.window;
w.fetch = fakeFetch; w.scrollTo = () => {}; w.matchMedia = () => ({ matches: false, addListener() {}, removeListener() {} });
Object.defineProperty(w, "crypto", { value: webcrypto, configurable: true });
w.eval(fs.readFileSync("bundle.js", "utf8"));
const btn = (t) => [...w.document.querySelectorAll("button, a")].find((b) => b.textContent.trim() === t);
const has = (t) => w.document.body.textContent.includes(t);
const click = async (t) => { const b = btn(t); if (!b) throw new Error("no button: " + t); b.click(); await sleep(); };
const setVal = (label, v) => {
  const lab = [...w.document.querySelectorAll("label")].find((l) => l.textContent.startsWith(label));
  const el = lab && lab.querySelector("input, select"); if (!el) throw new Error("no field: " + label);
  Object.getOwnPropertyDescriptor(w.HTMLInputElement.prototype, "value").set.call(el, v);
  el.dispatchEvent(new w.Event("input", { bubbles: true }));
};
const check = (name, ok) => { log.push((ok ? "PASS " : "FAIL ") + name); };
(async () => {
  await sleep(200);
  check("landing has Log in in top bar", !!btn("Log in") && has("Your money,"));
  await click("Log in");
  check("Log in opens login page", has("Welcome back"));
  await click("← Back to home");
  check("login page -> back to landing", has("Your money,"));
  await click("Open account");
  check("Open account opens create page", has("Create your account"));
  await click("← Back to home");
  check("create page -> back to landing", has("Your money,"));
  await click("Open account");
  setVal("Full name", "Test Person"); setVal("Username", "test_person"); setVal("Password", "Test@12345"); setVal("Mobile number", "01800000009");
  await click("Create account");
  check("account created screen", has("Account created"));
  await click("Log in");
  check("after create: Log in opens login form (not account-created)", has("Welcome back") && !has("Account created"));
  await click("Create an account");
  check("login -> create account link", has("Create your account"));
  await click("I already have an account");
  check("create -> already have account -> login", has("Welcome back"));
  setVal("Username", "rahim"); setVal("Password", "Rahim@123");
  await click("Send me a code");
  check("login asks for OTP", has("Enter your code"));
  const code = w.document.querySelector("input[inputmode=numeric]");
  Object.getOwnPropertyDescriptor(w.HTMLInputElement.prototype, "value").set.call(code, "123456"); code.dispatchEvent(new w.Event("input", { bubbles: true }));
  await click("Confirm and log in");
  check("OTP -> dashboard", has("Good day, Rahim"));
  await click("← Landing page");
  check("dashboard -> landing page", has("Your money,"));
  check("logged-in landing shows Dashboard, not Log in", !!btn("Dashboard") && !btn("Log in"));
  await click("Dashboard");
  check("top bar Dashboard returns to dashboard", has("Good day, Rahim"));
  await click("Log out");
  check("logout -> landing", has("Your money,"));
  console.log(log.join("\n"));
  process.exit(0);
})().catch((e) => { console.log(log.join("\n")); console.log("ERROR: " + e.message); process.exit(1); });
