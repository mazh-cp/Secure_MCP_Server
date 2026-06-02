from __future__ import annotations

# Check Point-branded, single-file admin console. Served by admin/server.py.
# Brand system: Brand Berry #ee0c5d (dominant accent), Gravitas Grey #41273c,
# Clay #f2f2f2; Arial; no rounded corners; no shadows. Logo SVG (white-text
# variant, with the dot) is embedded inline. Functional status colors
# (ok/warn/danger) are kept to small badges, under the 5% accent budget.
# This is a served, interactive app, so minimal inline JS is used (no external
# resources) — consistent with the single-file architecture.

_LOGO_WHITE = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 205 44" height="22" '
    'role="img" aria-label="Check Point">'
    '<path fill="#fff" d="M46.7,29.9h0c0-4.3,3.2-7.8,7.7-7.8s4.4.9,5.8,2.3l-2.1,2.4c-1.1-1-2.3-1.7-3.8-1.7-2.5,0-4.3,2.1-4.3,4.6h0c0,2.6,1.7,4.7,4.3,4.7s2.7-.7,3.9-1.7l2.1,2.1c-1.5,1.6-3.2,2.7-6,2.7-4.3,0-7.5-3.4-7.5-7.7Z"/>'
    '<path fill="#fff" d="M62.9,22.4h3.2v5.9h6v-5.9h3.2v14.9h-3.2v-6h-6v6h-3.2v-14.9Z"/>'
    '<path fill="#fff" d="M79.2,22.4h11.1v2.9h-7.9v3h6.9v2.9h-6.9v3.1h8v2.9h-11.2v-14.9Z"/>'
    '<path fill="#fff" d="M92.7,29.9h0c0-4.3,3.2-7.8,7.7-7.8s4.4.9,5.8,2.3l-2.1,2.4c-1.1-1-2.3-1.7-3.8-1.7-2.5,0-4.3,2.1-4.3,4.6h0c0,2.6,1.7,4.7,4.3,4.7s2.7-.7,3.9-1.7l2.1,2.1c-1.5,1.6-3.2,2.7-6,2.7-4.3,0-7.5-3.4-7.5-7.7Z"/>'
    '<path fill="#fff" d="M108.8,22.4h3.2v6.5l6-6.5h3.9l-6,6.3,6.3,8.6h-3.9l-4.6-6.4-1.7,1.8v4.6h-3.2v-14.9h0Z"/>'
    '<path fill="#fff" d="M130.8,22.4h6c3.5,0,5.6,2.1,5.6,5.2h0c0,3.5-2.6,5.3-6,5.3h-2.5v4.5h-3.2v-14.9h0ZM136.6,29.9c1.6,0,2.6-1,2.6-2.3h0c0-1.5-1-2.3-2.6-2.3h-2.5v4.6h2.6,0Z"/>'
    '<path fill="#fff" d="M144.5,29.9h0c0-4.3,3.3-7.8,7.8-7.8s7.8,3.4,7.8,7.7h0c0,4.3-3.3,7.8-7.8,7.8s-7.8-3.4-7.8-7.7ZM156.8,29.9h0c0-2.6-1.8-4.7-4.5-4.7s-4.4,2.1-4.4,4.6h0c0,2.6,1.8,4.7,4.5,4.7s4.4-2.1,4.4-4.6Z"/>'
    '<path fill="#fff" d="M163.3,22.4h3.2v14.9h-3.2v-14.9Z"/>'
    '<path fill="#fff" d="M170.6,22.4h3l6.9,9.2v-9.2h3.2v14.9h-2.8l-7.1-9.5v9.5h-3.2v-14.9Z"/>'
    '<path fill="#fff" d="M191,25.4h-4.5v-3h12.2v3h-4.5v11.9h-3.2v-11.9h0Z"/>'
    '<path fill="#fff" d="M201.8,24.4h-.4v-1.7h-.6v-.3h1.6v.3h-.6v1.7h0Z"/>'
    '<path fill="#fff" d="M204,23.9h0l-.6-1v1.5h-.4v-2.1h.4l.6,1,.6-1h.4v2.1h-.3v-1.5l-.6,1h0Z"/>'
    '<path fill="#fff" d="M44.2,11.2c-2.3,2.9-6.5,3.4-9.4,1-2.9-2.3-3.3-6.6-1-9.5,2.3-2.9,6.5-3.4,9.4-1,2.9,2.3,3.3,6.6,1,9.5Z"/>'
    '<path fill="#ee0c5d" d="M35.2,21.7c-1.8.9-4.1.8-6-.2l-5.2,7.1c.7.8,1,1.7,1.1,2.7,0,.9-.2,1.8-.7,2.6-1.3,2.1-4,2.7-6.1,1.3-.2-.1-.4-.3-.6-.5,0,0-.1-.1-.2-.2-.1-.1-.2-.3-.3-.4,0,0,0-.1-.1-.2-.1-.2-.2-.4-.3-.6,0,0,0-.1,0-.2,0-.2-.1-.3-.2-.5,0,0,0-.1,0-.2,0-.2,0-.4-.1-.7v-.2c0-.2,0-.4,0-.6h0c0-.4,0-.6.1-.8,0,0,0-.1,0-.2,0-.2.2-.5.3-.7l-4.2-3.2-1.3,1.8-4.8-3.7,3.6-4.9,4.8,3.7-1.3,1.8,4.3,3.3c1.3-1.1,3.2-1.4,4.8-.5l5.2-7c-2.1-2.1-2.6-5.4-1.1-8.1.3-.5.7-1,1.1-1.4-2.8-2-6.3-3.1-10-3.1C8,7.8,0,15.9,0,25.9c0,10,7.9,18.1,17.8,18.1,9.8,0,17.8-8,17.9-18,0-1.5-.2-2.9-.5-4.2Z"/>'
    "</svg>"
)

_CSS = """
*{margin:0;padding:0;box-sizing:border-box;border-radius:0}
body{font-family:Arial,Helvetica,sans-serif;background:#f2f2f2;color:#231f20;line-height:1.45}
header{background:#41273c;border-bottom:3px solid #ee0c5d;padding:14px 28px;display:flex;align-items:center;gap:16px}
header .brand{display:flex;align-items:center;gap:14px}
header .sep{width:1px;height:26px;background:#6b5560}
header h1{color:#fff;font-size:15px;font-weight:bold;letter-spacing:.3px}
header h1 span{color:#ee0c5d}
header .who{margin-left:auto;color:#cfc6cc;font-size:12px}
header .who button{margin-left:12px;background:none;border:1px solid #6b5560;color:#fff;padding:5px 10px;font-size:11px;cursor:pointer}
nav{background:#fff;border-bottom:1px solid #d9d5d8;padding:0 28px;display:flex;gap:4px}
nav button{background:none;border:0;border-bottom:3px solid transparent;padding:12px 16px;font-size:13px;font-weight:bold;color:#6b5560;cursor:pointer}
nav button.active{color:#ee0c5d;border-bottom-color:#ee0c5d}
main{padding:24px 28px;max-width:1180px}
.tab{display:none}.tab.active{display:block}
h2{font-size:16px;margin-bottom:14px;color:#41273c}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:22px}
.card{background:#fff;border:1px solid #d9d5d8;padding:16px}
.card .k{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#6b5560}
.card .v{font-size:26px;font-weight:bold;margin-top:6px;color:#41273c}
.badge{display:inline-block;padding:2px 9px;font-size:11px;font-weight:bold;color:#fff}
.b-ok{background:#1f9d57}.b-warn{background:#fcb117;color:#41273c}.b-danger{background:#ff3312}
.b-info{background:#741984}.b-berry{background:#ee0c5d}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #d9d5d8;font-size:13px}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid #eee}
th{background:#41273c;color:#fff;font-size:11px;text-transform:uppercase;letter-spacing:.4px}
tr:last-child td{border-bottom:0}
.chip{display:inline-block;background:#f2f2f2;border:1px solid #d9d5d8;padding:1px 7px;font-size:11px;margin:1px}
.panel{background:#fff;border:1px solid #d9d5d8;padding:18px;margin-bottom:22px}
.panel h3{font-size:13px;color:#41273c;margin-bottom:12px;text-transform:uppercase;letter-spacing:.4px}
label.f{display:block;font-size:12px;font-weight:bold;color:#41273c;margin:10px 0 4px}
input[type=text],input[type=number],input[type=password],select{font-family:inherit;font-size:13px;padding:8px;border:1px solid #d9d5d8;width:100%;max-width:360px;background:#fff}
.scopes{display:flex;flex-wrap:wrap;gap:10px;margin-top:6px}
.scopes label{font-size:12px;font-weight:normal;display:flex;align-items:center;gap:5px}
.btn{background:#e40c5b;color:#fff;border:0;padding:9px 18px;font-size:13px;font-weight:bold;cursor:pointer;margin-top:14px}
.btn:hover{background:#b70d4e}
.btn.sec{background:#fff;color:#41273c;border:1px solid #d9d5d8}
.btn.sm{padding:4px 10px;font-size:11px;margin:0}
.btn.danger{background:#ff3312}
.tip{border-left:4px solid #d9d5d8;background:#fff;border:1px solid #d9d5d8;padding:12px 14px;margin-bottom:10px}
.tip.critical{border-left-color:#ff3312}.tip.warning{border-left-color:#fcb117}
.tip.info{border-left-color:#741984}.tip.ok{border-left-color:#1f9d57}
.tip .t{font-weight:bold;font-size:13px;color:#41273c}
.tip .d{font-size:12px;color:#5a4350;margin-top:3px}
.note{font-size:12px;color:#6b5560;margin-top:8px;font-style:normal}
.overlay{position:fixed;inset:0;background:#41273c;display:flex;align-items:center;justify-content:center;z-index:1000}
.login{background:#fff;border-top:4px solid #ee0c5d;padding:30px;width:340px}
.login h2{margin-bottom:6px}.login p{font-size:12px;color:#6b5560;margin-bottom:14px}
.err{color:#ff3312;font-size:12px;margin-top:10px;min-height:16px}
.hidden{display:none}
"""

_JS = """
let SESSION=sessionStorage.getItem('smcp_session')||'';
let RESTART_UNITS=[];
const $=s=>document.querySelector(s);
const esc=s=>String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const SCOPES=['threat_emulation','file_sandboxing','ai_guard','threat_intel','url_category','anti_phishing'];

async function api(method,path,body){
  const h={'Content-Type':'application/json'};
  if(SESSION) h['Authorization']='Bearer '+SESSION;
  const r=await fetch(path,{method,headers:h,body:body?JSON.stringify(body):undefined});
  if(r.status===401){showLogin();throw new Error('unauthorized');}
  const t=await r.text();
  let d={};try{d=t?JSON.parse(t):{};}catch(e){}
  if(!r.ok) throw new Error(d.error||('HTTP '+r.status));
  return d;
}
function showLogin(){$('#overlay').classList.remove('hidden');}
function hideLogin(){$('#overlay').classList.add('hidden');}

async function login(){
  const tok=$('#token').value;$('#loginErr').textContent='';
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:tok})});
    const d=await r.json();
    if(!r.ok){$('#loginErr').textContent=d.error||'Login failed';return;}
    SESSION=d.session;sessionStorage.setItem('smcp_session',SESSION);
    $('#token').value='';hideLogin();loadAll();
  }catch(e){$('#loginErr').textContent='Login failed';}
}
function logout(){SESSION='';sessionStorage.removeItem('smcp_session');showLogin();}

function tab(name,btn){
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('nav button').forEach(b=>b.classList.remove('active'));
  $('#tab-'+name).classList.add('active');btn.classList.add('active');
}

function badgeBool(ok,okText,badText){return ok?`<span class="badge b-ok">${okText}</span>`:`<span class="badge b-danger">${badText}</span>`;}

async function loadAll(){
  try{
    const o=await api('GET','/api/overview');
    renderOverview(o);renderIdentities(o.identities);renderConfig(o.op_config);
    renderAudit(o.audit);renderHealth(o.health);renderRestart(o.restart);
    const pol=await api('GET','/api/policies');renderPolicies(pol.policies);
  }catch(e){/* 401 already handled */}
}

function renderOverview(o){
  const a=o.audit;
  const v=a.exists?badgeBool(a.verified,'VERIFIED','TAMPERED'):'<span class="badge b-info">EMPTY</span>';
  $('#ov-cards').innerHTML=`
    <div class="card"><div class="k">Audit Chain</div><div class="v">${v}</div></div>
    <div class="card"><div class="k">Audit Events</div><div class="v">${a.total}</div></div>
    <div class="card"><div class="k">Errors / Denials</div><div class="v">${a.by_result.error||0}</div></div>
    <div class="card"><div class="k">DLP Findings</div><div class="v">${a.dlp_findings}</div></div>
    <div class="card"><div class="k">Identities</div><div class="v">${o.identities.length}</div></div>`;
  $('#ov-guidance').innerHTML=o.guidance.map(t=>`<div class="tip ${t.level}"><div class="t">${esc(t.title)}</div><div class="d">${esc(t.detail)}</div></div>`).join('');
}

function renderIdentities(list){
  $('#id-rows').innerHTML=list.map(i=>`<tr>
    <td>${esc(i.caller_id)||'<em>?</em>'}</td>
    <td>${i.allowed_tools.map(s=>`<span class="chip">${esc(s)}</span>`).join('')}</td>
    <td>${badgeBool(i.valid,'VALID','INVALID')}</td>
    <td><button class="btn sm danger" onclick="delIdentity('${esc(i.caller_id)}')">Delete</button></td></tr>`).join('')
    ||'<tr><td colspan="4">No identities configured.</td></tr>';
  $('#id-scopes').innerHTML=SCOPES.map(s=>`<label><input type="checkbox" value="${s}"> ${s}</label>`).join('');
}
async function saveIdentity(){
  const cid=$('#id-caller').value.trim();
  const scopes=[...document.querySelectorAll('#id-scopes input:checked')].map(c=>c.value);
  $('#id-err').textContent='';
  try{await api('PUT','/api/identities',{caller_id:cid,allowed_tools:scopes});$('#id-caller').value='';
    $('#id-ok').textContent='Saved. Restart the affected instance on the Instances tab to apply.';loadAll();}
  catch(e){$('#id-err').textContent=e.message;}
}
async function delIdentity(cid){
  if(!confirm('Delete identity '+cid+'? Applies on next MCP server start.'))return;
  try{await api('DELETE','/api/identities/'+encodeURIComponent(cid));loadAll();}catch(e){alert(e.message);}
}

function renderConfig(c){
  $('#cfg-dlp').value=c.dlp_mode;$('#cfg-quota').value=c.daily_quota;$('#cfg-rate').value=c.rate_limit_per_minute;
}
async function saveConfig(){
  $('#cfg-err').textContent='';$('#cfg-ok').textContent='';
  try{
    await api('PUT','/api/config',{dlp_mode:$('#cfg-dlp').value,daily_quota:parseInt($('#cfg-quota').value,10),rate_limit_per_minute:parseInt($('#cfg-rate').value,10)});
    $('#cfg-ok').textContent='Saved. Applies on next (re)start — use the Instances tab to restart affected instances.';
  }catch(e){$('#cfg-err').textContent=e.message;}
}
async function saveConfigAndRestart(){
  if(!confirm('Save configuration and restart ALL managed instances?\\nIn-flight tool calls will drop.'))return;
  $('#cfg-err').textContent='';$('#cfg-ok').textContent='';
  try{
    await api('PUT','/api/config',{dlp_mode:$('#cfg-dlp').value,daily_quota:parseInt($('#cfg-quota').value,10),rate_limit_per_minute:parseInt($('#cfg-rate').value,10)});
    const r=await api('POST','/api/restart-all');
    if(!r.enabled){$('#cfg-ok').textContent='Saved. In-console restart not configured — restart instances from the host.';}
    else{const ok=r.results.filter(x=>x.ok).length;$('#cfg-ok').textContent=`Saved and restarted ${ok}/${r.results.length} instance(s).`;}
    setTimeout(loadAll,400);
  }catch(e){$('#cfg-err').textContent=e.message;}
}

function renderAudit(a){
  $('#au-cards').innerHTML=`
    <div class="card"><div class="k">Chain</div><div class="v">${a.exists?badgeBool(a.verified,'OK','BROKEN'):'<span class="badge b-info">EMPTY</span>'}</div></div>
    <div class="card"><div class="k">Total</div><div class="v">${a.total}</div></div>
    <div class="card"><div class="k">OK</div><div class="v">${a.by_result.ok||0}</div></div>
    <div class="card"><div class="k">Error</div><div class="v">${a.by_result.error||0}</div></div>`;
  $('#au-rows').innerHTML=(a.recent||[]).map(e=>{
    const r=e.result==='ok'?'<span class="badge b-ok">ok</span>':'<span class="badge b-danger">error</span>';
    const det=e.result==='error'?esc((e.details||{}).error_type||''):'';
    return `<tr><td>${esc(e.seq)}</td><td>${esc(e.caller_id)}</td><td>${esc(e.tool)}</td><td>${esc(e.action)}</td><td>${r} ${det}</td></tr>`;
  }).join('')||'<tr><td colspan="5">No audit entries.</td></tr>';
}

function renderHealth(h){
  $('#hl-cards').innerHTML=h.map(u=>{
    const b=u.reachable?`<span class="badge b-ok">REACHABLE</span>`:`<span class="badge b-danger">DOWN</span>`;
    const x=u.reachable?('HTTP '+u.status):esc(u.error||'');
    return `<div class="card"><div class="k">${esc(u.name)}</div><div class="v" style="font-size:16px">${b}</div><div class="note">${esc(u.url)}<br>${x}</div></div>`;
  }).join('');
}

function renderRestart(r){
  const el=$('#rs-body');RESTART_UNITS=[];
  if(!r||!r.enabled){
    el.innerHTML=`<div class="tip info"><div class="t">In-console restart not configured</div><div class="d">Set <strong>SECURE_MCP_MANAGED_UNITS</strong> (an allowlist of systemd units) and grant the console narrow restart permission to enable restarts here. Otherwise restart from the host: <code>systemctl restart secure-mcp@&lt;instance&gt;</code>.</div></div>`;
    return;
  }
  RESTART_UNITS=r.units.map(u=>u.unit);
  const rows=r.units.map(u=>{
    const st=u.active_state;const cls=st==='active'?'b-ok':(st==='failed'?'b-danger':'b-warn');
    return `<tr><td>${esc(u.unit)}</td><td><span class="badge ${cls}">${esc(st)}</span> ${esc(u.sub_state)}</td>
      <td><button class="btn sm" onclick="doRestart('${esc(u.unit)}')">Restart</button></td></tr>`;
  }).join('');
  el.innerHTML=`<table><thead><tr><th>Unit</th><th>State</th><th></th></tr></thead><tbody>${rows}</tbody></table>
    <button class="btn sec" onclick="doRestartAll()">Restart All Affected</button>
    <div class="note" id="rs-msg"></div>`;
}
async function doRestart(unit){
  if(!confirm('Restart '+unit+'?\\nIn-flight tool calls on that instance will drop.'))return;
  try{const d=await api('POST','/api/restart',{unit});
    $('#rs-msg').textContent=d.ok?('Restarted '+unit):('Restart failed: '+(d.message||('rc '+d.returncode)));
    setTimeout(loadAll,400);
  }catch(e){$('#rs-msg').textContent=e.message;}
}
async function doRestartAll(){
  if(!confirm('Restart ALL managed instances?\\nIn-flight tool calls will drop.'))return;
  for(const u of RESTART_UNITS){try{await api('POST','/api/restart',{unit:u});}catch(e){}}
  setTimeout(loadAll,400);
}

const POL_BOOLS=['ProtectionEnabled','UrlFilteringEnabled','BlockMaliciousUrls','BlockPhishingUrls','BlockSuspiciousUrls','AllowUserBypass'];
function renderPolicies(list){
  if($('#pol-bools').children.length===0){
    $('#pol-bools').innerHTML=POL_BOOLS.map(k=>`<label><input type="checkbox" id="pb-${k}"> ${k}</label>`).join('');
  }
  $('#pol-rows').innerHTML=(list||[]).map(p=>{
    const keys=Object.keys(p.settings||{}).map(k=>`<span class="chip">${esc(k)}</span>`).join('');
    return `<tr><td>${esc(p.group)}</td><td>${esc(p.version)}</td><td>${keys}</td>
      <td><button class="btn sm sec" onclick='editPolicy(${JSON.stringify(p).replace(/'/g,"&#39;")})'>Edit</button></td></tr>`;
  }).join('')||'<tr><td colspan="4">No group policies authored.</td></tr>';
}
function editPolicy(p){
  $('#pol-group').value=p.group||'';
  const s=p.settings||{};
  POL_BOOLS.forEach(k=>{const el=$('#pb-'+k);if(el)el.checked=!!s[k];});
  $('#pol-allow').value=(s.UrlAllowlist||[]).join('\\n');
  $('#pol-block').value=(s.UrlBlocklist||[]).join('\\n');
  tab('policy',document.querySelector('nav button:last-child'));
}
async function savePolicy(){
  $('#pol-err').textContent='';$('#pol-ok').textContent='';
  const group=$('#pol-group').value.trim();
  const settings={};
  POL_BOOLS.forEach(k=>{settings[k]=!!($('#pb-'+k)&&$('#pb-'+k).checked);});
  const allow=$('#pol-allow').value.split('\\n').map(s=>s.trim()).filter(Boolean);
  const block=$('#pol-block').value.split('\\n').map(s=>s.trim()).filter(Boolean);
  if(allow.length) settings.UrlAllowlist=allow;
  if(block.length) settings.UrlBlocklist=block;
  try{
    const d=await api('PUT','/api/policies',{group,settings});
    $('#pol-ok').textContent=`Saved policy v${d.version} for ${group}. Devices apply on next poll.`;
    loadAll();
  }catch(e){$('#pol-err').textContent=e.message;}
}

window.addEventListener('DOMContentLoaded',()=>{
  if(SESSION) loadAll(); else showLogin();
});
"""


def render_console_html() -> str:
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>secure-mcp Management Console</title>
<style>{_CSS}</style></head>
<body>
<header>
  <div class="brand">{_LOGO_WHITE}<div class="sep"></div><h1>secure-mcp <span>·</span> Management Console</h1></div>
  <div class="who">Check Point Security Broker<button onclick="logout()">Sign out</button></div>
</header>
<nav>
  <button class="active" onclick="tab('overview',this)">Overview</button>
  <button onclick="tab('identities',this)">Identities &amp; Scopes</button>
  <button onclick="tab('config',this)">Configuration</button>
  <button onclick="tab('audit',this)">Audit Trail</button>
  <button onclick="tab('health',this)">Upstream Health</button>
  <button onclick="tab('instances',this)">Instances</button>
  <button onclick="tab('policy',this)">Browser Policy</button>
</nav>
<main>
  <section id="tab-overview" class="tab active">
    <h2>Operational Overview</h2>
    <div class="cards" id="ov-cards"></div>
    <h2>Guidance</h2>
    <div id="ov-guidance"></div>
  </section>

  <section id="tab-identities" class="tab">
    <h2>Identities &amp; Scopes</h2>
    <table><thead><tr><th>Caller ID</th><th>Allowed Scopes</th><th>Status</th><th></th></tr></thead>
    <tbody id="id-rows"></tbody></table>
    <div class="panel" style="margin-top:22px"><h3>Create / Update Identity</h3>
      <label class="f">Caller ID</label>
      <input type="text" id="id-caller" placeholder="e.g. soc-analyst-desktop">
      <label class="f">Allowed Scopes</label>
      <div class="scopes" id="id-scopes"></div>
      <button class="btn" onclick="saveIdentity()">Save Identity</button>
      <div class="err" id="id-err"></div>
      <div class="note" id="id-ok"></div>
      <div class="note">Writes an identity file the MCP server consumes on its next start. Apply least privilege.</div>
    </div>
  </section>

  <section id="tab-config" class="tab">
    <h2>Operational Configuration</h2>
    <div class="panel"><h3>Guard Settings</h3>
      <label class="f">DLP Mode</label>
      <select id="cfg-dlp"><option value="block">block</option><option value="redact">redact</option><option value="flag">flag</option></select>
      <label class="f">Daily Quota (0 = unlimited)</label>
      <input type="number" id="cfg-quota" min="0">
      <label class="f">Rate Limit (calls / minute / scope)</label>
      <input type="number" id="cfg-rate" min="1">
      <button class="btn" onclick="saveConfig()">Save Configuration</button>
      <button class="btn sec" onclick="saveConfigAndRestart()">Save &amp; Restart Affected</button>
      <div class="err" id="cfg-err"></div>
      <div class="note" id="cfg-ok"></div>
      <div class="note">Persisted to the operational config file. <strong>Applies on the next MCP server (re)start</strong> — secret keys are never managed here.</div>
    </div>
  </section>

  <section id="tab-audit" class="tab">
    <h2>Audit Trail</h2>
    <div class="cards" id="au-cards"></div>
    <table><thead><tr><th>Seq</th><th>Caller</th><th>Tool</th><th>Action</th><th>Result</th></tr></thead>
    <tbody id="au-rows"></tbody></table>
    <div class="note">Tool-call audit log (read-only). Verified against the HMAC-chained record; secret-shaped fields are redacted at write time.</div>
  </section>

  <section id="tab-health" class="tab">
    <h2>Upstream Health</h2>
    <div class="cards" id="hl-cards"></div>
    <div class="note">Live reachability probe from the console host (TLS verified, no credentials sent). Any HTTP response means reachable.</div>
  </section>

  <section id="tab-instances" class="tab">
    <h2>Managed Instances</h2>
    <div class="panel"><h3>Restart Affected Instances</h3>
      <div id="rs-body"></div>
    </div>
    <div class="note">Config and identity changes apply when the MCP server (re)starts. Restart targets an operator-defined allowlist of systemd units; a restart drops that instance's in-flight tool calls and reconnecting clients re-launch it. Every restart is audited.</div>
  </section>

  <section id="tab-policy" class="tab">
    <h2>Browser Policy (per group)</h2>
    <table><thead><tr><th>Group</th><th>Version</th><th>Settings</th><th></th></tr></thead>
    <tbody id="pol-rows"></tbody></table>
    <div class="panel" style="margin-top:22px"><h3>Author / Update Group Policy</h3>
      <label class="f">Group</label>
      <input type="text" id="pol-group" placeholder="e.g. sales">
      <label class="f">Toggles</label>
      <div class="scopes" id="pol-bools"></div>
      <label class="f">URL Allowlist (one host per line)</label>
      <textarea id="pol-allow" rows="3" style="width:100%;max-width:360px;font-family:inherit;font-size:13px;padding:8px;border:1px solid #d9d5d8"></textarea>
      <label class="f">URL Blocklist (one host per line)</label>
      <textarea id="pol-block" rows="3" style="width:100%;max-width:360px;font-family:inherit;font-size:13px;padding:8px;border:1px solid #d9d5d8"></textarea>
      <button class="btn" onclick="savePolicy()">Save Policy</button>
      <div class="err" id="pol-err"></div>
      <div class="note" id="pol-ok"></div>
      <div class="note">Served to devices as an Ed25519-signed envelope by the edge PDP. Devices apply it on their next poll — no MCP server restart needed.</div>
    </div>
  </section>
</main>

<div id="overlay" class="overlay hidden">
  <div class="login">
    <h2>Sign In</h2>
    <p>Enter the admin token to manage this secure-mcp deployment.</p>
    <label class="f">Admin Token</label>
    <input type="password" id="token" onkeydown="if(event.key==='Enter')login()" autocomplete="off">
    <button class="btn" style="width:100%" onclick="login()">Sign In</button>
    <div class="err" id="loginErr"></div>
  </div>
</div>
<script>{_JS}</script>
</body></html>"""
