import { useEffect, useState } from "react";
import QRCode from "qrcode";

let CSRF = "";
async function api(path, o = {}) {
  const r = await fetch("/api" + path, {
    method: o.method || (o.body ? "POST" : "GET"), credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-CSRF": CSRF },
    body: o.body ? JSON.stringify(o.body) : undefined,
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || "Request failed");
  return d;
}
const vcode = location.pathname.startsWith("/verify/") ? decodeURIComponent(location.pathname.slice(8)) : null;
const money = (p) => (p / 100).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const newRef = () => (crypto.randomUUID ? crypto.randomUUID() : Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, "0")).join(""));

/* A real QR code (same kind as the one printed on every statement), pointing at a sample verification link. */
function SampleQr() {
  const [src, setSrc] = useState("");
  useEffect(() => {
    QRCode.toDataURL(location.origin + "/verify/SAMPLE-0000", { margin: 1, width: 140, color: { dark: "#0c1a14", light: "#eef1f5" } })
      .then(setSrc).catch(() => setSrc(""));
  }, []);
  return src ? <img className="qr" src={src} alt="Sample verification QR code" /> : <span className="qr" aria-hidden="true" />;
}

/* 3D tilt: the element follows the pointer in perspective. Pure CSS variables, no libraries. */
function Tilt({ children, className = "", strength = 7, as: Tag = "div", ...rest }) {
  const move = (e) => {
    const r = e.currentTarget.getBoundingClientRect();
    const x = (e.clientX - r.left) / r.width - 0.5, y = (e.clientY - r.top) / r.height - 0.5;
    e.currentTarget.style.setProperty("--rx", (-y * strength).toFixed(2) + "deg");
    e.currentTarget.style.setProperty("--ry", (x * strength).toFixed(2) + "deg");
  };
  const leave = (e) => { e.currentTarget.style.setProperty("--rx", "0deg"); e.currentTarget.style.setProperty("--ry", "0deg"); };
  return <Tag className={"tilt " + className} onMouseMove={move} onMouseLeave={leave} {...rest}>{children}</Tag>;
}

export default function App() {
  const [user, setUser] = useState(undefined), [view, setView] = useState(vcode ? "verify" : "home"), [down, setDown] = useState(false);
  useEffect(() => {
    api("/me").then((d) => { CSRF = d.csrf; setUser(d.user); if (d.user && !vcode) setView("reports"); }).catch(() => setDown(true));
  }, []);
  if (down) return <main className="page"><p className="err">The service is not reachable. Check that the server is running, then reload.</p></main>;
  if (user === undefined) return null;
  const go = (v) => { setView(v); window.scrollTo(0, 0); };
  const logout = async () => { await api("/logout", { method: "POST" }); CSRF = (await api("/me")).csrf; setUser(null); go("home"); };
  const authed = (d) => { CSRF = d.csrf; setUser(d.user); go("reports"); };
  const onAuth = view === "login" || view === "register";
  return (<div className="app">
    <header className="topbar">
      <button className="brand" onClick={() => go("home")}><span className="mark">D</span>Dhanshiri<b>Bank</b></button>
      <nav>
        <button className="ghost" onClick={() => go("home")}>Home</button>
        <button className="ghost" onClick={() => go("verify")}>Verify a statement</button>
        {user ? (<>
          <button className="ghost" onClick={() => go("reports")}>Dashboard</button>
          <span className="who">{user.name}</span>
          <button className="ghost" onClick={logout}>Log out</button></>) : (<>
          <button className="ghost" onClick={() => go("login")}>Log in</button>
          <button className="cta" onClick={() => go("register")}>Open account</button></>)}
      </nav>
    </header>
    {view === "home" && <Landing go={go} user={user} />}
    {onAuth && <Login key={view} mode={view === "login" ? "login" : "register"} go={go} onAuth={authed} />}
    {view === "verify" && <main className="page center"><Verify first={vcode} /></main>}
    {user && view === "reports" && <Workspace user={user} go={go} logout={logout} />}
    <footer className="foot">
      <div className="foot-grid">
        <div><div className="foot-brand">Dhanshiri Bank Ltd</div><p>Motijheel, Dhaka. Demonstration site.</p></div>
        <div><h4>Services</h4><p>Accounts</p><p>Transfers</p><p>Signed statements</p></div>
        <div><h4>Security</h4><p>Two-officer approval</p><p>Branch certificates</p><p>Verifiable PDFs</p></div>
      </div>
      <div className="foot-note">All data in this site is synthetic. The address and the names are fictional.</div>
    </footer>
  </div>);
}

function Landing({ go, user }) {
  const services = [
    ["01", "Accounts", "Open a checking account. New customers start with BDT 10,000.", "register", "Open an account"],
    ["02", "Transfers", "Send money to any Dhanshiri account. Your balance updates at once.", "login", "Log in to transfer"],
    ["03", "Signed statements", "Each PDF carries a digital signature. Anyone can check it with its code.", "verify", "Check a statement"],
    ["04", "Branch security", "Branch computers use their own certificate. Two officers approve sensitive changes.", "login", "Staff log in"],
  ];
  const steps = [
    ["Open an account", "Register with your mobile number. National ID is optional and stored encrypted."],
    ["Log in with a one-time code", "Your password alone is never enough. A code goes to your phone each time."],
    ["Move your money", "Send transfers to any Dhanshiri account and see the balance update straight away."],
    ["Download a signed statement", "The download link works for two minutes, then it expires."],
    ["Anyone can check it", "Scan the code on the statement. If one number was changed, the check fails."],
  ];
  return (<>
    <section className="hero">
      <div className="hero-glow" aria-hidden="true" />
      <div className="hero-inner">
        <div className="hero-copy reveal">
          <span className="kicker">Dhanshiri Bank</span>
          <h1>Your money,<br /><span className="grad">proven.</span></h1>
          <p className="lede">Open an account in minutes. Every statement we issue can be checked by anyone with one scan.</p>
          <div className="hero-actions">
            <button className="cta big" onClick={() => go(user ? "reports" : "register")}>{user ? "Go to dashboard" : "Open an account"}</button>
            <button className="ghost big" onClick={() => go("verify")}>Verify a statement</button>
          </div>
          <dl className="stats">
            <div><dt>Statement check</dt><dd>1 scan</dd></div>
            <div><dt>Approval for sensitive changes</dt><dd>2 officers</dd></div>
            <div><dt>Opening balance</dt><dd>BDT 10,000</dd></div>
          </dl>
        </div>
        <div className="hero-visual reveal">
          <Tilt className="scene" strength={10}>
            <div className="card3d">
              <div className="card3d-top"><b>Dhanshiri Bank Ltd</b><span className="tag">Signed · Genuine</span></div>
              <p className="card3d-title">Account statement (sample)</p>
              <dl><dt>Account</dt><dd>•••• 4567</dd><dt>Issued</dt><dd>2026-11-22 10:30 UTC</dd></dl>
              <div className="card3d-foot"><SampleQr /><span>Sample only. Scan the code on a real statement to check it. This sample code is not a real statement.</span></div>
            </div>
          </Tilt>
          <div className="orb o1" /><div className="orb o2" />
        </div>
      </div>
    </section>

    <section className="section" id="services">
      <div className="section-head"><span className="kicker">Services</span><h2>Banking that you can check</h2></div>
      <div className="cards">{services.map(([n, t, d, v, btn]) => (
        <div key={n} className="service">
          <span className="service-n">{n}</span><h3>{t}</h3><p>{d}</p>
          <button className="link" onClick={() => go(v)}>{btn} <span aria-hidden="true">→</span></button>
        </div>))}</div>
    </section>

    <section className="section alt" id="how">
      <div className="section-head"><span className="kicker">How it works</span><h2>Five steps from account to proof</h2></div>
      <ol className="timeline">{steps.map(([t, d], i) => (<li key={t} className="reveal-item" style={{ animationDelay: `${i * 90}ms` }}>
        <span className="dot">{i + 1}</span><div><h3>{t}</h3><p>{d}</p></div></li>))}</ol>
    </section>

    <section className="section" id="security">
      <div className="security">
        <div><span className="kicker">Security</span><h2>Your trust is our first priority</h2></div>
        <div className="security-list">
          <p>Every page is served over TLS when the site runs in secure mode.</p>
          <p>Branch computers prove who they are with their own certificate before they send anything.</p>
          <p>Five wrong passwords lock sign-in for that user from that address for five minutes.</p>
          <p>Staff cannot revoke a certificate or reset a password alone. A second officer must approve, and every step is logged.</p>
        </div>
      </div>
    </section>

    <section className="section cta-band">
      <h2>Ready to bank online?</h2>
      <button className="cta big" onClick={() => go("register")}>Open an account</button>
    </section>
  </>);
}

function Login({ mode, go, onAuth }) {
  const reg = mode === "register";
  const [err, setErr] = useState(""), [otp, setOtp] = useState(null), [done, setDone] = useState(false), [busy, setBusy] = useState(false);
  const [f, setF] = useState({ name: "", username: "", password: "", phone: "", nid: "" }), [code, setCode] = useState("");
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value });
  const submit = async () => {
    setErr(""); setBusy(true);
    try {
      if (reg) { await api("/register", { body: f }); setDone(true); }
      else { const d = await api("/login", { body: f }); setOtp(d.phone); }
    } catch (e) { setErr(e.message); } finally { setBusy(false); }
  };
  const verify = async () => { setErr(""); try { onAuth(await api("/login/otp", { body: { code } })); } catch (e) { setErr(e.message); } };
  let card;
  if (done) card = (<><h2>Account created</h2><p className="muted">You can log in now.</p><button className="cta big" onClick={() => go("login")}>Log in</button><button className="link" onClick={() => go("home")}>← Back to home</button></>);
  else if (otp) card = (<><h2>Enter your code</h2>
    <p className="muted">We sent a 6-digit code to {otp}. It expires in 5 minutes.</p>
    <label className="field">Code<input value={code} inputMode="numeric" maxLength={6} autoFocus onChange={(e) => setCode(e.target.value)} onKeyDown={(e) => e.key === "Enter" && verify()} /></label>
    {err && <p className="err">{err}</p>}
    <button className="cta big" onClick={verify}>Confirm and log in</button></>);
  else card = (<><h2>{reg ? "Create your account" : "Welcome back"}</h2>
    <p className="muted">{reg ? "A few details to get you started." : "Sign in to continue to your account."}</p>
    {reg && <label className="field">Full name<input value={f.name} onChange={set("name")} /></label>}
    <label className="field">Username<input value={f.username} onChange={set("username")} autoFocus /></label>
    <label className="field">Password{reg && " (8 or more characters)"}<input type="password" value={f.password} onChange={set("password")} onKeyDown={(e) => !reg && e.key === "Enter" && submit()} /></label>
    {reg && <>
      <label className="field">Mobile number<input value={f.phone} inputMode="numeric" placeholder="01XXXXXXXXX" onChange={set("phone")} /></label>
      <label className="field">National ID (optional)<input value={f.nid} inputMode="numeric" onChange={set("nid")} /></label></>}
    {err && <p className="err">{err}</p>}
    <button className="cta big" onClick={submit} disabled={busy}>{busy ? "Please wait…" : reg ? "Create account" : "Send me a code"}</button>
    <button className="link" onClick={() => go(reg ? "login" : "register")}>{reg ? "I already have an account" : "Create an account"}</button>
    <button className="link" onClick={() => go("home")}>← Back to home</button></>);
  return (<main className="auth">
    <section className="auth-promo">
      <div className="promo-shape" aria-hidden="true" />
      <span className="kicker">Secure digital banking</span>
      <h1>Banking that<br /><span className="grad">moves with you.</span></h1>
      <p>Simple everyday banking, protected by strong identity checks and digitally signed statements.</p>
      <ul className="promo-points"><li>Two-factor sign-in</li><li>Instant transfers</li><li>Verifiable statements</li></ul>
    </section>
    <section className="auth-card-wrap"><div className="auth-card">{card}</div>
      <p className="auth-note">Your information is protected with secure session controls.</p>
    </section>
  </main>);
}

function Workspace({ user, go, logout }) {
  const admin = user.role === "admin", officer = user.role === "officer";
  const [active, setActive] = useState("dashboard");
  const jump = (id, key) => { setActive(key); document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" }); };
  const links = officer ? [["dashboard", "Overview", "branch-panel"]]
    : admin ? [["dashboard", "Overview", "admin-top"], ["requests", "Approvals", "requests-panel"], ["certs", "Certificates", "certs-panel"], ["db", "Database", "db-panel"], ["security", "Security checks", "security-panel"]]
    : [["dashboard", "Overview", "dashboard-top"], ["accounts", "Accounts", "accounts-panel"], ["transfer", "Fund transfer", "transfer-panel"], ["statements", "Statements", "statements-panel"]];
  return (<div className="shell">
    <aside className="side">
      <button className="brand" onClick={() => go("reports")}><span className="mark">D</span>Dhanshiri<b>Bank</b></button>
      <div className="profile"><div className="avatar">{(user.name || "U").slice(0, 1).toUpperCase()}</div>
        <div><b>{user.name}</b><small>{admin ? "Administrator" : officer ? "Branch officer" : "Customer"}</small></div></div>
      <nav className="side-nav">{links.map(([k, label, id]) => (
        <button key={k} className={"side-link" + (active === k ? " on" : "")} onClick={() => jump(id, k)}>{label}</button>))}</nav>
      <button className="side-link" onClick={() => go("home")}>← Landing page</button>
      <button className="side-link out" onClick={logout}>Log out</button>
    </aside>
    <main className="content">
      <div id={admin ? "admin-top" : officer ? "branch-top" : "dashboard-top"} className="top reveal">
        <div><span className="kicker">Secure portal</span><h1>Good day, {(user.name || "").split(" ")[0] || "there"}</h1><p className="muted">Here is your overview.</p></div>
        <span className="pill-ok"><i /> Secure session</span>
      </div>
      {admin ? <Admin /> : officer ? <Branches /> : <Customer user={user} />}
    </main>
  </div>);
}

function Customer({ user }) {
  const [a, setA] = useState([]), [open, setOpen] = useState(null), [t, setT] = useState([]), [err, setErr] = useState(""), [msg, setMsg] = useState("");
  const [f, setF] = useState({ from: "", to: "", amount: "", note: "" }), [ref, setRef] = useState(newRef);
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value });
  const load = () => api("/accounts").then((d) => { setA(d.accounts); setF((s) => ({ ...s, from: s.from || d.accounts[0]?.no || "" })); });
  useEffect(() => { load().catch((e) => setErr(e.message)); }, []);
  const run = async (fn) => { setErr(""); setMsg(""); try { await fn(); } catch (e) { setErr(e.message); } };
  const show = (no) => run(async () => { setOpen(no); setT((await api("/accounts/" + no)).txns); });
  const download = async (no) => {
    const { url } = await api(`/accounts/${no}/link`);
    const r = await fetch(url, { credentials: "same-origin" });
    if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(d.error || "Could not download the statement. Try again."); }
    const a = document.createElement("a"), href = URL.createObjectURL(await r.blob());
    a.href = href; a.download = `statement-${no}.pdf`; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(href), 1000); setMsg("Statement downloaded.");
  };
  const send = () => run(async () => {
    await api("/transfer", { body: { ...f, ref } }); setMsg("Transfer sent."); setRef(newRef());
    setF({ ...f, to: "", amount: "", note: "" }); await load(); if (open) await show(open);
  });
  const total = a.reduce((s, x) => s + x.balance, 0);
  return (<>
    <section className="kpis">
      <Tilt className="kpi" strength={5}><span>Total balance</span><b>BDT {money(total)}</b></Tilt>
      <Tilt className="kpi" strength={5}><span>Accounts</span><b>{a.length}</b></Tilt>
      <Tilt className="kpi" strength={5}><span>Security</span><b className="ok">Protected</b></Tilt>
    </section>

    <section className="panel" id="accounts-panel">
      <div className="panel-head"><h2>Accounts</h2>
        <button className="cta" onClick={() => run(async () => { await api("/accounts/open", { method: "POST", body: {} }); await load(); })}>+ Open account</button></div>
      {user.nid && <p className="muted">National ID on file: {user.nid}</p>}
      <div className="acct-grid">{a.map((x) => (<div key={x.no} className="acct">
        <span className="muted">Checking ···{x.no.slice(-4)}</span>
        <b className="bal">BDT {money(x.balance)}</b>
        <span className="muted small">{x.no}</span>
        <div className="acts"><button className="ghost" onClick={() => show(x.no)}>Transactions</button>
          <button className="ghost" onClick={() => run(() => download(x.no))}>Signed statement</button></div>
      </div>))}</div>
      {err && <p className="err">{err}</p>}{msg && <p className="good">{msg}</p>}
    </section>

    <section className="panel" id="transfer-panel">
      <div className="panel-head"><h2>Fund transfer</h2><span className="tag-soft">Protected transaction</span></div>
      <div className="form-grid">
        <label className="field">From<select value={f.from} onChange={set("from")}>{a.map((x) => <option key={x.no} value={x.no}>···{x.no.slice(-4)} (BDT {money(x.balance)})</option>)}</select></label>
        <label className="field">To account number<input value={f.to} onChange={set("to")} placeholder="0204-000456" /></label>
        <label className="field">Amount (BDT)<input type="number" min="0.01" step="0.01" value={f.amount} onChange={set("amount")} /></label>
        <label className="field">Note<input maxLength={60} value={f.note} onChange={set("note")} /></label>
      </div>
      <button className="cta big" onClick={send}>Continue transfer</button>
    </section>

    <section className="panel" id="statements-panel">
      <div className="panel-head"><h2>{open ? "Transactions ···" + open.slice(-4) : "Transactions"}</h2></div>
      {!open && <p className="muted">Press “Transactions” on an account to see its history.</p>}
      {open && <div className="scroll"><table><thead><tr><th>Date (UTC)</th><th>Description</th><th className="num">Amount</th><th className="num">Balance</th></tr></thead>
        <tbody>{t.map((x, i) => <tr key={i}><td>{x.at}</td><td>{x.descr}</td><td className={"num " + (x.amount > 0 ? "good" : "")}>{money(x.amount)}</td><td className="num">{money(x.after)}</td></tr>)}</tbody></table></div>}
    </section>
  </>);
}

function Branches() {
  const [u, setU] = useState([]), [err, setErr] = useState("");
  useEffect(() => { api("/uploads").then((d) => setU(d.uploads)).catch((e) => setErr(e.message)); }, []);
  return (<section className="panel" id="branch-panel">
    <div className="panel-head"><h2>Branch network activity</h2></div>
    {err && <p className="err">Could not load uploads: {err}</p>}
    {!err && u.length === 0 && <p className="muted">No branch uploads yet.</p>}
    {u.length > 0 && <div className="scroll"><table><thead><tr><th>Received (UTC)</th><th>Branch certificate</th><th>File</th><th>State</th></tr></thead>
      <tbody>{u.map((x, i) => <tr key={i}><td>{x.at}</td><td>{x.branch}</td><td>{x.name}</td><td>{x.done ? "Complete" : "Waiting to resume"}</td></tr>)}</tbody></table></div>}
  </section>);
}

function Verify({ first }) {
  const [code, setCode] = useState(first || ""), [res, setRes] = useState(null), [err, setErr] = useState("");
  const check = async (c = code) => { setRes(null); setErr(""); try { setRes(await api("/verify/" + encodeURIComponent(c.trim()))); } catch (e) { setErr(e.message); } };
  useEffect(() => { if (first) check(first); }, []);
  return (<div className="verify-card">
    <span className="kicker">Document authenticity</span>
    <h2>Verify a statement</h2>
    <p className="muted">Enter the statement code printed on the PDF, or scan the code on the page.</p>
    <label className="field">Statement code<input value={code} onChange={(e) => setCode(e.target.value)} onKeyDown={(e) => e.key === "Enter" && check()} /></label>
    <button className="cta big" onClick={() => check()}>Check statement</button>
    {err && <p className="err">{err}</p>}
    {res && <p className={res.genuine ? "good" : "err"}>{res.genuine
      ? `Genuine. Statement for account ending ${res.last4}, issued ${res.at} UTC.`
      : "This statement’s signing certificate has been revoked. Do not rely on it."}</p>}
  </div>);
}

function Admin() {
  const [d, setD] = useState({ requests: [], audit: [], me: "" }), [f, setF] = useState({ action: "revoke_cert", target: "" });
  const [msg, setMsg] = useState(""), [err, setErr] = useState(""), [secret, setSecret] = useState("");
  const load = () => api("/admin/requests").then(setD).catch((e) => setErr(e.message));
  useEffect(() => { load(); }, []);
  const act = async (p, body) => {
    setErr(""); setMsg("");
    try { const r = await api(p, { method: "POST", body: body || {} });
      if (r.message) { if (r.message.startsWith("Temporary password")) setSecret(r.message); else setMsg(r.message); }
      load();
    } catch (e) { setErr(e.message); }
  };
  const name = { revoke_cert: "Revoke certificate", reset_password: "Reset password" };
  return (<>
    <section className="panel" id="requests-panel">
      <div className="panel-head"><h2>Approvals</h2><span className="tag-soft">One officer asks, another approves</span></div>
      <div className="form-grid">
        <label className="field">Change<select value={f.action} onChange={(e) => setF({ ...f, action: e.target.value })}>
          <option value="revoke_cert">Revoke a certificate</option><option value="reset_password">Reset a user’s password</option></select></label>
        <label className="field">{f.action === "revoke_cert" ? "Certificate name (e.g. client-branch-rangpur)" : "Username"}
          <input value={f.target} onChange={(e) => setF({ ...f, target: e.target.value })} /></label>
      </div>
      <button className="cta big" onClick={() => act("/admin/requests", f)}>Ask for approval</button>
      {err && <p className="err">{err}</p>}{msg && <p className="good">{msg}</p>}
      {secret && <div className="secret" role="alert"><p><b>{secret}</b></p><p className="muted">Write this down now and hand it over in person. It will not be shown again.</p>
        <button className="ghost" onClick={() => setSecret("")}>I have written it down</button></div>}
      <div className="scroll"><table><thead><tr><th>Change</th><th>Target</th><th>Asked by</th><th>Status</th><th></th></tr></thead>
        <tbody>{d.requests.map((x) => (<tr key={x.id}>
          <td>{name[x.action]}</td><td>{x.target}</td><td>{x.req_by}</td>
          <td>{x.status === "pending" ? "Waiting" : x.status === "approved" ? "Approved by " + x.approver : "Rejected by " + x.approver}</td>
          <td>{x.status === "pending" && (x.req_by === d.me ? <span className="muted">Another officer must decide</span> : <>
            <button className="cta" onClick={() => act(`/admin/requests/${x.id}/approve`)}>Approve</button>{" "}
            <button className="ghost" onClick={() => act(`/admin/requests/${x.id}/reject`)}>Reject</button></>)}</td>
        </tr>))}</tbody></table></div>
    </section>
    <CertWatch />
    <DbView />
    <WebSecurityChecks />
    <section className="panel"><div className="panel-head"><h2>Activity log</h2></div>
      <div className="scroll"><table><tbody>{d.audit.map((x, i) => <tr key={i}><td>{x.at}</td><td>{x.usr}</td><td>{x.event}</td></tr>)}</tbody></table></div></section>
  </>);
}

function CertWatch() {
  const [d, setD] = useState({ certs: [], refused: [] }), [err, setErr] = useState("");
  useEffect(() => { api("/admin/certs").then(setD).catch((e) => setErr(e.message)); }, []);
  const soon = d.certs.filter((c) => c.warn && !c.revoked && c.days >= 0);
  return (<section className="panel" id="certs-panel">
    <div className="panel-head"><h2>Certificates</h2></div>
    {err && <p className="err">Could not load certificates: {err}</p>}
    {soon.length > 0 && <p className="err">Renew soon: {soon.map((c) => `${c.name} (${c.days} days)`).join(", ")}</p>}
    <div className="scroll"><table><thead><tr><th>Name</th><th>Days left</th><th>State</th></tr></thead>
      <tbody>{d.certs.map((c) => <tr key={c.name}><td>{c.name}</td><td>{c.days}</td>
        <td>{c.revoked ? "Revoked" : c.days < 0 ? "Expired" : c.warn ? "Renew soon" : "Valid"}</td></tr>)}</tbody></table></div>
    <h3>Refused uploads</h3>
    {d.refused.length === 0 ? <p className="muted">None.</p> : <div className="scroll"><table><tbody>
      {d.refused.map((x, i) => <tr key={i}><td>{x.at}</td><td>{x.who}</td><td>{x.reason}</td></tr>)}</tbody></table></div>}
  </section>);
}

function DbView() {
  const [d, setD] = useState(null), [err, setErr] = useState(""), [open, setOpen] = useState(false);
  const load = () => api("/admin/db").then(setD).catch((e) => setErr(e.message));
  return (<section className="panel" id="db-panel">
    <div className="panel-head"><h2>Database (read-only)</h2></div>
    <p className="muted">Password hashes, National ID numbers and encrypted files are never shown. Latest 50 rows per table. Money is in paisa (divide by 100 for BDT).</p>
    {!open ? <button className="cta" onClick={() => { setOpen(true); load(); }}>Show database</button>
      : <button className="ghost" onClick={() => setOpen(false)}>Hide database</button>}
    {err && <p className="err">{err}</p>}
    {open && d && d.tables.map((t) => (<div key={t.table}>
      <h3>{t.table} <span className="muted">({t.count} rows)</span></h3>
      {t.rows.length === 0 ? <p className="muted">No rows.</p> : <div className="scroll"><table>
        <thead><tr>{t.columns.map((c) => <th key={c}>{c}</th>)}</tr></thead>
        <tbody>{t.rows.map((r, i) => <tr key={i}>{t.columns.map((c) => <td key={c}>{r[c] === null ? "" : String(r[c])}</td>)}</tr>)}</tbody>
      </table></div>}
    </div>))}
  </section>);
}

const SECURITY_CHECKS = [
  ["SQL injection", "Login and account lookups use parameterized queries. Injection strings do not sign in and do not expose other data.", "test_web_sqli"],
  ["Stored and reflected XSS", "Notes and verification codes come back as JSON data and are shown as text. The page sends a Content-Security-Policy.", "test_web_stored_xss, test_web_reflected_xss"],
  ["CSRF", "Every state-changing request needs the session’s X-CSRF token.", "test_web_csrf"],
  ["IDOR (account isolation)", "A customer cannot see another customer’s account.", "test_web_idor"],
  ["Brute-force protection", "Five wrong passwords lock sign-in for that user from that address for five minutes.", "test_web_login_rate_limit"],
  ["Session and cookie security", "The session cookie is HttpOnly and SameSite=Lax, and Secure in HTTPS mode.", "test_web_session_cookie"],
  ["Malicious file upload", "File names are checked, only PDF, JPEG and PNG are accepted, and the content must match its type. No antivirus scan yet.", "test_web_upload"],
  ["Security headers", "nosniff, frame denial, no-referrer and a Content-Security-Policy. HSTS in HTTPS mode.", "test_web_security_headers, test_web_https"],
  ["Unauthorized transaction", "A transfer from an account you do not own is refused and changes no balance.", "test_web_unauthorized"],
  ["Duplicate transaction", "Each transfer carries a reference. A repeat is refused with HTTP 409 and applied only once.", "test_web_duplicate"],
];

function WebSecurityChecks() {
  return (<section className="panel" id="security-panel">
    <div className="panel-head"><h2>Web application security checks</h2></div>
    <p className="muted">Each control is covered by an automated test in the lab suite. This shows the controls work in this demo; it is not an external penetration test.</p>
    <div className="check-grid">{SECURITY_CHECKS.map(([name, detail, tests]) => (<Tilt key={name} className="check" strength={5}>
      <span className="pill">Tested</span><h3>{name}</h3><p>{detail}</p><code>{tests}</code>
    </Tilt>))}</div>
  </section>);
}
