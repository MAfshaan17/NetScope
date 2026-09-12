const state={alerts:[],packets:[],flows:[],protocols:{},history:[],lastPacketTotal:0,paused:false};
const $=id=>document.getElementById(id);
const esc=v=>String(v??"—").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const sev=s=>String(s||"LOW").toLowerCase();
const bytes=n=>{n=Number(n)||0;return n<1024?`${n} B`:n<1048576?`${(n/1024).toFixed(1)} KB`:`${(n/1048576).toFixed(1)} MB`};
async function api(path){const r=await fetch(path,{cache:"no-store"});if(!r.ok)throw Error(`HTTP ${r.status}`);return r.json()}

function renderProtocols(){
  const entries=Object.entries(state.protocols).sort((a,b)=>b[1]-a[1]); const total=entries.reduce((a,[,n])=>a+n,0)||1;
  $("protocols").innerHTML=entries.length?entries.slice(0,7).map(([p,n])=>{let pct=Math.round(n/total*100);return `<div class="proto"><b>${esc(p)}</b><div class="bar"><i style="width:${pct}%"></i></div><span>${pct}%</span></div>`}).join(""):`<div class="empty">No protocol telemetry yet.</div>`;
}
function alertRows(items){
  return items.map(a=>`<div class="alert-row"><span class="sev ${sev(a.severity)}">${esc(a.severity||"LOW")}</span><div><div class="alert-name">${esc(a.alert_type||"Security Event")}</div><div class="alert-sub">${esc(a.rule_id||"—")} · confidence ${esc(a.confidence??"—")}%</div></div><span class="ip">${esc(a.source_ip)} → ${esc(a.destination_ip)}</span><span class="time">${esc(a.timestamp||"")}</span></div>`).join("");
}
function renderAlerts(){
  const high=state.alerts.filter(a=>["HIGH","CRITICAL"].includes(String(a.severity).toUpperCase())).length;
  const rules=new Set(state.alerts.map(a=>a.rule_id).filter(Boolean)).size;
  $("sideAlerts").textContent=state.alerts.length;$("incidentPill").textContent=`${state.alerts.length} EVENTS`;
  $("intelEvents").textContent=state.alerts.length;$("intelHigh").textContent=high;$("intelRules").textContent=rules;
  $("alertsList").innerHTML=state.alerts.length?alertRows(state.alerts.slice(-8).reverse()):`<div class="empty">No security alerts detected.</div>`;
  $("incidentList").innerHTML=state.alerts.length?state.alerts.slice().reverse().map(a=>`<div class="incident"><span class="sev ${sev(a.severity)}">${esc(a.severity||"LOW")}</span><div><h3>${esc(a.alert_type||"Security Event")}</h3><p>${esc(a.source_ip)} → ${esc(a.destination_ip)} · ${esc(a.rule_id||"—")} · confidence ${esc(a.confidence??"—")}%</p></div><span class="time">${esc(a.timestamp||"")}</span></div>`).join(""):`<div class="empty">No active incidents.</div>`;
  $("timelineList").innerHTML=state.alerts.length?state.alerts.slice().reverse().map(a=>`<div class="event"><b>${esc(a.alert_type||"Security Event")}</b><p>${esc(a.source_ip)} → ${esc(a.destination_ip)} · ${esc(a.rule_id||"—")}</p><time>${esc(a.timestamp||"Unknown time")}</time></div>`).join(""):`<div class="empty">Timeline is empty.</div>`;
}
function renderTables(filter=""){
  const q=filter.toLowerCase();
  const packets=state.packets.filter(p=>JSON.stringify(p).toLowerCase().includes(q)).slice(-40).reverse();
  $("packetMeta").textContent=`${state.packets.length} packets`;
  $("packetTable").innerHTML=packets.length?packets.map(p=>`<tr><td>${esc(p.direction)}</td><td>${esc(p.source_ip)}:${esc(p.source_port)}</td><td>${esc(p.destination_ip)}:${esc(p.destination_port)}</td><td>${esc(p.protocol)}</td><td>${esc(p.service)}</td><td>${esc(p.packet_size)} B</td></tr>`).join(""):`<tr><td colspan="6" class="empty">No packets match the search.</td></tr>`;
  $("flowMeta").textContent=`${state.flows.length} flows`;
  $("flowTable").innerHTML=state.flows.slice().reverse().map(f=>{const s=Array.isArray(f.source)?`${f.source[0]}:${f.source[1]}`:f.source;const d=Array.isArray(f.destination)?`${f.destination[0]}:${f.destination[1]}`:f.destination;return `<tr><td>${esc(s)}</td><td>${esc(d)}</td><td>${esc(f.protocol)}</td><td>${esc(f.packets)}</td><td>${esc(bytes(f.bytes))}</td></tr>`}).join("")||`<tr><td colspan="5" class="empty">No network flows detected.</td></tr>`;
}
function chart(){
  const c=$("traffic"),r=c.getBoundingClientRect(),d=devicePixelRatio||1,w=r.width,h=r.height;c.width=Math.max(300,w*d);c.height=Math.max(160,h*d);const x=c.getContext("2d");x.scale(d,d);x.clearRect(0,0,w,h);
  x.strokeStyle="#182738";x.lineWidth=1;for(let i=1;i<5;i++){x.beginPath();x.moveTo(0,i*h/5);x.lineTo(w,i*h/5);x.stroke()}
  const v=state.history.length?state.history:[0],m=Math.max(5,...v);x.beginPath();v.forEach((n,i)=>{const px=i*(w/Math.max(1,v.length-1)),py=h-12-(n/m)*(h-25);i?x.lineTo(px,py):x.moveTo(px,py)});x.strokeStyle="#4cddb0";x.lineWidth=2;x.stroke();
}
async function load(){
  if(state.paused)return;
  try{
    const [st,al,fl,pk]=await Promise.all([api("/stats"),api("/alerts"),api("/flows"),api("/packets")]);
    state.alerts=Array.isArray(al)?al:[];state.flows=Array.isArray(fl)?fl:[];state.packets=Array.isArray(pk)?pk:[];
    const total=Number(st.packets)||state.packets.length, delta=Math.max(0,total-state.lastPacketTotal);state.lastPacketTotal=total;
    state.history.push(delta);if(state.history.length>24)state.history.shift();
    $("packets").textContent=total.toLocaleString();$("flows").textContent=(Number(st.flows)||state.flows.length).toLocaleString();$("alerts").textContent=(Number(st.alerts)||state.alerts.length).toLocaleString();$("rate").textContent=delta.toLocaleString();$("peakRate").textContent=`Peak ${Math.max(...state.history,0)} packets`;
    state.protocols={};state.packets.forEach(p=>{let k=String(p.protocol||"OTHER").toUpperCase();state.protocols[k]=(state.protocols[k]||0)+1});
    renderProtocols();renderAlerts();renderTables($("packetSearch")?.value||"");chart();
    $("error").classList.add("hidden");
  }catch(e){$("error").textContent=`Backend connection unavailable: ${e.message}. Start the NetScope API to restore live telemetry.`;$("error").classList.remove("hidden")}
}
function go(page){document.querySelectorAll(".page").forEach(x=>x.classList.toggle("active",x.id===page));document.querySelectorAll(".nav").forEach(x=>x.classList.toggle("active",x.dataset.page===page));const t={overview:"Network Overview",packets:"Live Packets",flows:"Network Flows",incidents:"Incident Queue",threats:"Threat Intelligence",timeline:"Attack Timeline",about:"About NetScope"};$("pageTitle").textContent=t[page]||t.overview;history.replaceState(null,"","#"+page)}
document.querySelectorAll(".nav").forEach(a=>a.onclick=e=>{e.preventDefault();go(a.dataset.page)});
document.querySelectorAll("[data-go]").forEach(b=>b.onclick=()=>go(b.dataset.go));
$("refreshBtn").onclick=load;$("pauseBtn").onclick=()=>{state.paused=!state.paused;$("pauseBtn").textContent=state.paused?"▶":"Ⅱ";$("pollState").textContent=state.paused?"PAUSED":"LIVE"};
$("packetSearch").addEventListener("input",e=>renderTables(e.target.value));window.addEventListener("resize",chart);
go(location.hash.slice(1)&&document.getElementById(location.hash.slice(1))?location.hash.slice(1):"overview");load();setInterval(load,5000);
