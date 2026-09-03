(() => {
  const root = document.querySelector("[data-performance-root]"); if (!root) return;
  const state = {data: null, timer: null};
  const $ = s => root.parentElement.querySelector(s) || document.querySelector(s);
  const text = (node, value) => { node.textContent = value == null ? "-" : value; };
  const ms = value => value == null ? "-" : `${Number(value).toFixed(2)} ms`;
  const classify = value => Number(value) > 1000 ? "very slow" : Number(value) > 500 ? "slow" : Number(value) >= 300 ? "noticeable" : "normal";
  function render(data) {
    state.data = data; const summary = document.querySelector("[data-performance-summary]"); summary.replaceChildren();
    const cards = [["Average request",ms(data.summary.average_request_duration_ms)],["p95 request",ms(data.summary.p95_request_duration_ms)],["Slowest request",ms(data.summary.slowest_request_duration_ms)],["Average SQL",ms(data.summary.average_sql_duration_ms)],["Highest SQL query count",data.summary.highest_sql_query_count],["Average external",ms(data.summary.average_external_duration_ms)],["Retained requests",data.state.sample_count]];
    cards.forEach(([label,value]) => { const card=document.createElement("div"); card.className="card"; const span=document.createElement("span"); span.textContent=label; const strong=document.createElement("strong"); strong.textContent=value == null ? "-" : value; card.append(span,strong); summary.append(card); });
    text(document.querySelector("[data-performance-status]"), data.state.enabled ? "Enabled" : "Disabled");
    const route=(document.querySelector("[data-performance-route]")?.value || "").toLowerCase(); const status=document.querySelector("[data-performance-status-filter]")?.value; const slow=document.querySelector("[data-performance-slow]")?.checked;
    const rows=document.querySelector("[data-performance-rows]"); rows.replaceChildren();
    data.samples.filter(s=>(!route || s.path.toLowerCase().includes(route)) && (!status || String(s.status_code)===status) && (!slow || Number(s.total_duration_ms)>=300)).forEach(s=>{ const tr=document.createElement("tr"); const values=[new Date(s.timestamp).toLocaleTimeString(),s.method,s.path,s.status_code,ms(s.total_duration_ms),s.database_query_count,ms(s.database_duration_ms),ms(s.template_duration_ms),s.external_call_count,ms(s.external_duration_ms),s.process_rss_bytes == null ? "-" : `${(s.process_rss_bytes/1048576).toFixed(1)} MB`]; values.forEach((v,i)=>{const td=document.createElement("td"); td.textContent=v; if(i===4){td.dataset.speed=classify(s.total_duration_ms); td.setAttribute("aria-label",`${v}, ${classify(s.total_duration_ms)}`);} tr.append(td);}); rows.append(tr);});
    if(!rows.children.length){const tr=document.createElement("tr"),td=document.createElement("td"); td.colSpan=11; td.className="muted"; td.textContent=data.state.sample_count ? "No samples match the selected filters." : "No samples retained."; tr.append(td); rows.append(tr);}
  }
  async function refresh(){ try { const response=await fetch("/api/system/about/performance",{headers:{Accept:"application/json"},cache:"no-store"}); if(!response.ok) return; render(await response.json()); } catch (_) {} }
  function schedule(){ if(state.timer) clearInterval(state.timer); state.timer=document.querySelector("[data-performance-live]")?.checked ? setInterval(refresh,3000) : null; }
  ["[data-performance-route]","[data-performance-status-filter]","[data-performance-slow]"].forEach(s=>document.querySelector(s)?.addEventListener("input",()=>state.data&&render(state.data)));
  document.querySelector("[data-performance-live]")?.addEventListener("change",schedule); document.addEventListener("visibilitychange",()=>{if(document.hidden){if(state.timer)clearInterval(state.timer);state.timer=null;} else schedule();}); refresh();
})();
