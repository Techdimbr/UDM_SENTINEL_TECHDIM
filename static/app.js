/* Painel UniFi de Segurança - frontend (vanilla JS) */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const view = $('#view');
const state = { view: 'overview', cache: {}, charts: [] };

const TITLES = {
  overview: 'Visão geral', threats: 'Ameaças detectadas (IDS/IPS)', audit: 'Auditoria e configuração guiada de segurança',
  firewall: 'Firewall, zonas e políticas', networks: 'Redes e WiFi', clients: 'Clientes conectados', devices: 'Dispositivos UniFi',
  traffic: 'Navegação: aplicações, categorias e destinos acessados', validation: 'Validação autorizada do IDS/IPS e do firewall',
  logs: 'Logs de eventos e alarmes', vpn: 'VPN, WAN e DNS', continuity: 'Continuidade: DNS do Active Directory e failover de WAN',
  explorer: 'Explorador da API', settings: 'Configurações',
};

// ------------------------------------------------------------------ utils
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmtBytes = b => { if (b == null) return '-'; const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0; b = Number(b); while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; } return b.toFixed(i ? 1 : 0) + ' ' + u[i]; };
const fmtBps = b => b == null ? '-' : fmtBytes(b).replace(/B$/, 'bps').replace('KB', 'Kb').replace('MB', 'Mb').replace('GB', 'Gb');
const fmtDate = t => { if (!t) return '-'; const d = new Date(typeof t === 'number' && t < 1e12 ? t * 1000 : t); return isNaN(d) ? String(t) : d.toLocaleString('pt-BR'); };
const fmtUptime = s => { if (s == null) return '-'; s = Number(s); const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60); return (d ? d + 'd ' : '') + h + 'h ' + m + 'm'; };
const tag = (t, cls) => `<span class="tag ${cls || t}">${esc(t)}</span>`;
const RISK_LABEL = { critico: 'Crítico', alto: 'Alto', medio: 'Médio', baixo: 'Baixo', info: 'Info', ok: 'OK' };

function showAlert(msg, cls = '') { const a = $('#alert'); a.className = 'alert ' + cls; a.textContent = msg; }
function hideAlert() { $('#alert').classList.add('hidden'); }
function openModal(title, html) { $('#modalTitle').textContent = title; $('#modalBody').innerHTML = html; $('#modal').classList.remove('hidden'); }
function closeModal() { $('#modal').classList.add('hidden'); }
$('#modal').addEventListener('click', e => { if (e.target.id === 'modal') closeModal(); });

async function api(path, opts = {}) {
  const r = await fetch(path, { headers: { 'Content-Type': 'application/json' }, ...opts, body: opts.body ? JSON.stringify(opts.body) : undefined });
  let data = null; try { data = await r.json(); } catch { }
  if (!r.ok) {
    const msg = (data && (data.detail || data.message)) || r.statusText;
    const err = new Error(typeof msg === 'string' ? msg : JSON.stringify(msg)); err.status = r.status; err.data = data; throw err;
  }
  return data;
}
async function load(key, path, force = false) {
  if (!force && state.cache[key]) return state.cache[key];
  const d = await api(path); state.cache[key] = d; return d;
}
function destroyCharts() { state.charts.forEach(c => c.destroy()); state.charts = []; }
function chart(ctx, cfg) { if (!window.Chart) return; const c = new Chart(ctx, cfg); state.charts.push(c); return c; }
const chartDefaults = { plugins: { legend: { labels: { color: '#8b98a9' } } }, scales: { x: { ticks: { color: '#8b98a9' }, grid: { color: '#273241' } }, y: { ticks: { color: '#8b98a9' }, grid: { color: '#273241' } } } };
const PALETTE = ['#3b82f6', '#ef4444', '#f59e0b', '#22c55e', '#a855f7', '#38bdf8', '#f472b6', '#84cc16', '#fb923c', '#94a3b8'];

// -------------------------------------------------------------- navigation
$('#nav').addEventListener('click', e => { const a = e.target.closest('a'); if (a) go(a.dataset.view); });
$('#refreshBtn').addEventListener('click', () => render(true));
function go(v) { state.view = v; $$('#nav a').forEach(a => a.classList.toggle('active', a.dataset.view === v)); $('#viewTitle').textContent = TITLES[v]; location.hash = v; render(); }

async function render(force = false) {
  hideAlert(); destroyCharts();
  view.innerHTML = '<div class="spinner">Carregando…</div>';
  try {
    await VIEWS[state.view](force);
  } catch (e) {
    if (e.status === 428) { view.innerHTML = ''; showAlert('Painel ainda não configurado. Informe o endereço do UDM Pro (ou ID do console) e a chave API.', 'info'); if (state.view !== 'settings') return go('settings'); return VIEWS.settings(); }
    view.innerHTML = '';
    showAlert('Erro: ' + e.message + (e.data && e.data.unifi ? '\n' + JSON.stringify(e.data.unifi).slice(0, 600) : ''));
  }
}

async function checkConn() {
  try {
    const c = await api('/api/config/test', { method: 'POST' });
    $('#conn').classList.add('ok'); $('#connText').textContent = `Conectado · Network ${c.applicationVersion}`;
    $('#siteBadge').textContent = `Site: ${c.site.name}` + (c.classicApi ? '' : ' · API clássica indisponível');
    state.conn = c;
  } catch (e) { $('#conn').classList.remove('ok'); $('#connText').textContent = e.status === 428 ? 'Não configurado' : 'Falha: ' + e.message.slice(0, 60); state.conn = null; }
}

// ----------------------------------------------------------------- views
const VIEWS = {};

VIEWS.overview = async (force) => {
  const o = await load('overview', '/api/overview', force);
  const devs = o.devices || [], clients = o.clients || [], nets = o.networks || [], wifi = o.wifi || [];
  const online = devs.filter(d => d.state === 'ONLINE').length;
  const gw = devs.find(d => (d.features || []).includes('gateway'));
  const gwStats = gw && o.deviceStats[gw.id];
  const thr = o.threats;
  const health = o.health || [];
  const errs = Object.entries(o.errors || {});
  view.innerHTML = `
  ${errs.length ? `<div class="alert info">Alguns dados não puderam ser carregados: ${errs.map(([k, v]) => `<b>${k}</b>: ${esc(v)}`).join(' · ')}</div>` : ''}
  ${!o.classicApi ? `<div class="alert info">A API clássica (eventos, alarmes, IPS) não respondeu com esta chave/conexão. Ameaças e logs exigem conexão <b>local</b> ao UDM Pro com chave API do console. Os dados da Integration API continuam disponíveis.</div>` : ''}
  <div class="grid g6">
    <div class="card"><h3>Dispositivos UniFi</h3><div class="kpi">${online}/${devs.length}<small>online</small></div></div>
    <div class="card"><h3>Clientes</h3><div class="kpi">${clients.length}<small>${clients.filter(c => c.type === 'WIRELESS').length} WiFi · ${clients.filter(c => c.type === 'WIRED').length} cabo · ${clients.filter(c => c.type === 'VPN' || c.type === 'TELEPORT').length} VPN</small></div></div>
    <div class="card"><h3>Redes / WiFi</h3><div class="kpi">${nets.length}<small>${wifi.length} SSIDs</small></div></div>
    <div class="card"><h3>Ameaças (7d)</h3><div class="kpi">${thr ? thr.total : '-'}<small>${thr ? thr.blocked + ' bloqueadas · ' + thr.detectedOnly + ' só detectadas' : 'indisponível'}</small></div></div>
    <div class="card"><h3>Políticas de firewall</h3><div class="kpi">${(o.policies || []).length}<small>${(o.zones || []).length} zonas</small></div></div>
    <div class="card"><h3>Gateway</h3><div class="kpi">${gwStats ? Math.round(gwStats.cpuUtilizationPct ?? 0) + '%' : '-'}<small>CPU · RAM ${gwStats ? Math.round(gwStats.memoryUtilizationPct ?? 0) + '%' : '-'} · up ${gwStats ? fmtUptime(gwStats.uptimeSec) : '-'}</small></div></div>
  </div>
  <div class="grid g3 mt">
    <div class="card"><h3>Saúde dos subsistemas</h3>${health.length ? health.map(h => `<div style="display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid var(--border)"><span>${esc(SUBSYS[h.subsystem] || h.subsystem)}</span>${tag(h.status === 'ok' ? 'ok' : h.status, h.status === 'ok' ? 'ok' : 'alto')}</div>`).join('') : '<div class="muted">Sem dados (API clássica).</div>'}
      ${o.sysinfo ? `<div class="small muted mt">UniFi Network ${esc(o.sysinfo.version)} · ${esc(o.sysinfo.hostname || '')} · ${esc(o.sysinfo.ubnt_device_type || '')}</div>` : ''}</div>
    <div class="card"><h3>Ameaças por tipo (7 dias)</h3><div class="canvas-wrap"><canvas id="chThreatTypes"></canvas></div></div>
    <div class="card"><h3>Ameaças por risco</h3><div class="canvas-wrap"><canvas id="chThreatRisk"></canvas></div></div>
  </div>
  <div class="grid g2 mt">
    <div class="card"><h3>Alarmes ativos</h3>${(o.alarms || []).length ? `<div class="tbl" style="max-height:300px"><table>${o.alarms.slice(0, 15).map(a => `<tr><td class="small muted">${fmtDate(a.time)}</td><td>${tag(a.kind)} ${esc(a.title)}<div class="small muted">${esc(a.message || '')}</div></td></tr>`).join('')}</table></div>` : '<div class="muted">Nenhum alarme ativo.</div>'}</div>
    <div class="card"><h3>Dispositivos internos com ameaças</h3>${thr && thr.internalDevices.length ? `<table>${thr.internalDevices.map(d => `<tr><td>${esc(d.name || 'desconhecido')}<div class="small mono muted">${d.ip}</div></td><td>${tag(RISK_LABEL[d.maxRisk], d.maxRisk)}</td><td>${d.count} eventos</td></tr>`).join('')}</table>` : '<div class="muted">Nenhum dispositivo interno envolvido em ameaças.</div>'}</div>
  </div>
  <div class="card mt"><h3>Dispositivos UniFi</h3><table><tr><th>Nome</th><th>Modelo</th><th>IP</th><th>Estado</th><th>Firmware</th><th>CPU</th><th>RAM</th><th>Uptime</th><th>Uplink</th></tr>
    ${devs.map(d => { const s = o.deviceStats[d.id] || {}; return `<tr><td><a onclick="showDevice('${d.id}')">${esc(d.name)}</a><div class="small muted">${(d.features || []).join(', ')}</div></td><td>${esc(d.model)}</td><td class="mono">${esc(d.ipAddress)}</td><td>${tag(d.state)}</td><td>${esc(d.firmwareVersion || '')} ${d.firmwareUpdatable ? tag('atualização', 'medio') : ''}</td><td>${s.cpuUtilizationPct != null ? Math.round(s.cpuUtilizationPct) + '%' : '-'}</td><td>${s.memoryUtilizationPct != null ? Math.round(s.memoryUtilizationPct) + '%' : '-'}</td><td>${fmtUptime(s.uptimeSec)}</td><td class="small">${s.uplink ? '↓' + fmtBps(s.uplink.rxRateBps) + ' ↑' + fmtBps(s.uplink.txRateBps) : '-'}</td></tr>`; }).join('')}</table></div>`;
  if (thr) {
    chart($('#chThreatTypes'), { type: 'bar', data: { labels: thr.byType.map(t => t.title), datasets: [{ label: 'eventos', data: thr.byType.map(t => t.count), backgroundColor: PALETTE }] }, options: { ...chartDefaults, indexAxis: 'y', maintainAspectRatio: false, plugins: { legend: { display: false } } } });
    chart($('#chThreatRisk'), { type: 'doughnut', data: { labels: ['Crítico', 'Alto', 'Médio', 'Baixo'], datasets: [{ data: [thr.byRisk.critico, thr.byRisk.alto, thr.byRisk.medio, thr.byRisk.baixo], backgroundColor: ['#a855f7', '#ef4444', '#f59e0b', '#38bdf8'] }] }, options: { maintainAspectRatio: false, plugins: { legend: { position: 'right', labels: { color: '#8b98a9' } } } } });
  }
};
const SUBSYS = { wan: 'Internet (WAN)', lan: 'Rede local (LAN)', wlan: 'WiFi', www: 'Conectividade web', vpn: 'VPN' };

// ---------------------------------------------------------------- threats
VIEWS.threats = async (force) => {
  const days = state.threatDays || 7;
  const t = await load('threats' + days, `/api/threats?days=${days}&limit=1000`, force);
  const s = t.summary;
  state.threatFilter = state.threatFilter || 'all';
  const filtered = ev => state.threatFilter === 'all' || ev.risk === state.threatFilter || (state.threatFilter === 'saida' && ev.direction === 'saida') || (state.threatFilter === 'nao-bloq' && !ev.blocked);
  view.innerHTML = `
  <div class="help">O UDM Pro usa o motor <b>Suricata</b> com regras <b>Emerging Threats</b>. Cada evento abaixo foi interpretado automaticamente: o que é, de onde veio, se foi bloqueado e o que fazer. Clique em um evento para a explicação completa.</div>
  <div class="toolbar mt">
    <label style="margin:0">Período</label><select id="thrDays">${[1, 3, 7, 14, 30].map(d => `<option value="${d}" ${d === days ? 'selected' : ''}>${d} dia(s)</option>`).join('')}</select>
    <div class="chips" id="thrChips">${[['all', 'Todos'], ['critico', 'Crítico'], ['alto', 'Alto'], ['medio', 'Médio'], ['baixo', 'Baixo'], ['saida', 'Originados de dentro'], ['nao-bloq', 'Não bloqueados']].map(([k, l]) => `<span class="chip ${state.threatFilter === k ? 'active' : ''}" data-f="${k}">${l}</span>`).join('')}</div>
    <input id="thrSearch" placeholder="Buscar assinatura, IP…" style="margin-left:auto;width:240px">
  </div>
  <div class="grid g4">
    <div class="card"><h3>Total</h3><div class="kpi">${s.total}</div></div>
    <div class="card"><h3>Bloqueadas</h3><div class="kpi" style="color:var(--ok)">${s.blocked}</div></div>
    <div class="card"><h3>Só detectadas</h3><div class="kpi" style="color:var(--warn)">${s.detectedOnly}</div></div>
    <div class="card"><h3>Críticas / Altas</h3><div class="kpi" style="color:var(--bad)">${s.byRisk.critico + s.byRisk.alto}</div></div>
  </div>
  <div class="grid g3 mt">
    <div class="card"><h3>Principais origens externas</h3>${s.topSources.length ? `<table>${s.topSources.map(x => `<tr><td class="mono">${x.ip}</td><td>${x.count}</td></tr>`).join('')}</table>` : '<div class="muted">-</div>'}</div>
    <div class="card"><h3>Países de origem</h3><div class="canvas-wrap"><canvas id="chCountry"></canvas></div></div>
    <div class="card"><h3>Dispositivos internos envolvidos</h3>${s.internalDevices.length ? `<table>${s.internalDevices.map(d => `<tr><td>${esc(d.name || '?')}<div class="mono small muted">${d.ip}</div></td><td>${tag(RISK_LABEL[d.maxRisk], d.maxRisk)}</td><td>${d.count}</td></tr>`).join('')}</table>` : '<div class="muted">Nenhum</div>'}</div>
  </div>
  <div class="mt" id="thrList"></div>`;
  const list = $('#thrList');
  const draw = () => {
    const q = ($('#thrSearch').value || '').toLowerCase();
    const evs = t.events.filter(filtered).filter(e => !q || JSON.stringify([e.signature, e.src.ip, e.dst.ip, e.title]).toLowerCase().includes(q));
    list.innerHTML = evs.length ? evs.slice(0, 400).map((e, i) => `
      <div class="threat ${e.risk}" onclick="showThreat(${t.events.indexOf(e)})">
        <div class="t"><span class="sig">${tag(RISK_LABEL[e.risk], e.risk)} ${esc(e.title)} ${e.blocked ? tag('bloqueado', 'ok') : tag('não bloqueado', 'alto')}</span><span class="small muted">${fmtDate(e.time)}</span></div>
        <div class="small mono muted mt" style="margin-top:4px">${esc(e.signature)}</div>
        <div class="small muted">${e.src.internal ? '🏠' : '🌐'} ${e.src.ip}${e.src.port ? ':' + e.src.port : ''} ${e.src.country ? '(' + esc(e.src.country) + ')' : ''} → ${e.dst.internal ? '🏠' : '🌐'} ${e.dst.ip}${e.dst.port ? ':' + e.dst.port : ''} · ${esc(e.proto || '')} ${e.internalDevice && e.internalDevice.name ? '· dispositivo: <b>' + esc(e.internalDevice.name) + '</b>' : ''}</div>
      </div>`).join('') + (evs.length > 400 ? `<div class="muted small">Mostrando 400 de ${evs.length}.</div>` : '') : '<div class="card muted">Nenhum evento no filtro.</div>';
  };
  draw();
  state.threatEvents = t.events;
  $('#thrSearch').addEventListener('input', draw);
  $('#thrChips').addEventListener('click', e => { const c = e.target.closest('.chip'); if (!c) return; state.threatFilter = c.dataset.f; $$('#thrChips .chip').forEach(x => x.classList.toggle('active', x === c)); draw(); });
  $('#thrDays').addEventListener('change', e => { state.threatDays = Number(e.target.value); render(); });
  if (s.topCountries.length) chart($('#chCountry'), { type: 'bar', data: { labels: s.topCountries.map(c => c.country), datasets: [{ label: 'eventos', data: s.topCountries.map(c => c.count), backgroundColor: '#3b82f6' }] }, options: { ...chartDefaults, maintainAspectRatio: false, plugins: { legend: { display: false } } } });
};

window.showThreat = i => {
  const e = state.threatEvents[i];
  openModal(e.title, `
    <div class="chips" style="margin-bottom:10px">${tag('Risco ' + RISK_LABEL[e.risk], e.risk)} ${tag('Severidade Suricata: ' + e.severityLabel, 'info')} ${e.blocked ? tag('Bloqueado pelo IPS', 'ok') : tag('Apenas detectado', 'alto')} ${tag(e.direction === 'saida' ? 'Saída (interno → internet)' : e.direction === 'entrada' ? 'Entrada (internet → interno)' : e.direction, 'info')}</div>
    <p><b>Resumo:</b> ${esc(e.summary)}</p>
    <div class="kv">
      <b>Assinatura</b><span class="mono">${esc(e.signature)} ${e.signatureId ? '(SID ' + e.signatureId + ')' : ''}</span>
      <b>Categoria</b><span>${esc(e.category || '-')} ${e.categoryUnifi ? '· UniFi: ' + esc(e.categoryUnifi) : ''}</span>
      <b>Quando</b><span>${fmtDate(e.time)}</span>
      <b>Origem</b><span class="mono">${e.src.ip}${e.src.port ? ':' + e.src.port : ''} ${e.src.country ? '(' + esc(e.src.country) + ')' : ''} ${e.src.internal ? '— rede interna' : '— internet'}</span>
      <b>Destino</b><span class="mono">${e.dst.ip}${e.dst.port ? ':' + e.dst.port : ''} ${e.dst.country ? '(' + esc(e.dst.country) + ')' : ''} ${e.dst.internal ? '— rede interna' : '— internet'}</span>
      <b>Protocolo</b><span>${esc(e.proto || '-')} ${e.appProto ? '/ ' + esc(e.appProto) : ''}</span>
      ${e.internalDevice ? `<b>Dispositivo interno</b><span>${esc(e.internalDevice.name || 'desconhecido')} · ${e.internalDevice.ip} ${e.internalDevice.mac ? '· ' + e.internalDevice.mac : ''}</span>` : ''}
      ${e.cve ? `<b>CVE</b><span><a href="${e.cveUrl}" target="_blank">${e.cve}</a></span>` : ''}
    </div>
    ${e.stage ? `<div class="kv"><b>Etapa do ataque</b><span>${esc(e.stage)}</span>${e.etGroup ? `<b>Grupo de regras</b><span class="mono">${esc(e.etGroup)}</span>` : ''}</div>` : ''}
    ${e.etGroupInfo ? `<p class="small muted">${esc(e.etGroupInfo)}</p>` : ''}
    <h4>O que é</h4><p>${esc(e.what)}</p>
    ${e.how ? `<h4>Como funciona</h4><p>${esc(e.how)}</p>` : ''}
    <h4>O que isso significa para você</h4><p>${esc(e.means)}</p>
    ${e.canCause ? `<h4>O que pode causar</h4><p>${esc(e.canCause)}</p>` : ''}
    ${e.urgency ? `<div class="help" style="margin:10px 0"><b>Urgência:</b> ${esc(e.urgency)}</div>` : ''}
    ${e.falsePositive ? `<div class="small muted"><b>Sobre falso positivo:</b> ${esc(e.falsePositive)}</div>` : ''}
    ${(e.mitre || []).length ? `<h4>MITRE ATT&CK</h4><table>${e.mitre.map(m => `<tr><td class="mono"><a href="https://attack.mitre.org/techniques/${esc(m.id).replace('.', '/')}/" target="_blank">${esc(m.id)}</a></td><td>${esc(m.name)}</td><td class="small muted">${esc(m.tactic)}</td></tr>`).join('')}</table>` : ''}
    <h4>O que fazer</h4><ol class="steps">${e.steps.map(s => `<li>${esc(s)}</li>`).join('')}</ol>
    ${e.sidUrl ? `<p class="small"><a href="${esc(e.sidUrl)}" target="_blank">Pesquisar esta assinatura (SID) na web →</a></p>` : ''}
    ${e.internalDevice && e.internalDevice.mac ? `<button class="btn danger" onclick="blockClient('${e.internalDevice.mac}', '${esc(e.internalDevice.name || e.internalDevice.ip)}')">Bloquear este dispositivo da rede</button>` : ''}
    <details class="mt"><summary class="muted small">Evento bruto (JSON)</summary><pre>${esc(JSON.stringify(e.raw, null, 2))}</pre></details>`);
};

window.blockClient = async (mac, name, unblock = false) => {
  if (!confirm(`${unblock ? 'Desbloquear' : 'Bloquear'} "${name}" (${mac})?`)) return;
  try { const r = await api('/api/clients/block', { method: 'POST', body: { mac, unblock } }); showAlert(r.message, 'ok'); closeModal(); delete state.cache.clients; }
  catch (e) { showAlert('Falha: ' + e.message); }
};

// ------------------------------------------------------------------ audit
VIEWS.audit = async (force) => {
  const a = await load('audit', '/api/audit', force);
  const areas = [...new Set(a.findings.map(f => f.area))];
  state.auditArea = state.auditArea || 'all';
  const color = a.score >= 75 ? 'var(--ok)' : a.score >= 50 ? 'var(--warn)' : 'var(--bad)';
  view.innerHTML = `
  <div class="grid g3">
    <div class="card score"><div class="ring" style="border-color:${color}">${a.grade}</div><div><div class="kpi">${a.score}/100<small>pontuação de segurança</small></div><div class="small muted mt">${a.counts.critico} críticos · ${a.counts.alto} altos · ${a.counts.medio} médios · ${a.counts.baixo} baixos</div></div></div>
    <div class="card" style="grid-column:span 2"><h3>Como funciona</h3><p class="small">O painel leu a configuração do seu UDM Pro (IPS, WiFi, redes, firewall, VPN, gateway, eventos) e comparou com boas práticas. Cada item explica <b>o que foi encontrado</b>, <b>por que importa</b>, <b>como corrigir manualmente</b> no app UniFi e, quando possível, oferece um botão <b>Aplicar</b> que faz a mudança pela API (sempre com confirmação).</p>
    ${!a.classicApi ? '<p class="small" style="color:var(--warn)">API clássica indisponível: verificações de IPS, UPnP e eventos administrativos foram puladas.</p>' : ''}
    ${a.errors.length ? `<details><summary class="small muted">${a.errors.length} aviso(s) de coleta</summary><pre>${esc(a.errors.join('\n'))}</pre></details>` : ''}</div>
  </div>
  <div class="toolbar mt"><div class="chips" id="audChips"><span class="chip ${state.auditArea === 'all' ? 'active' : ''}" data-a="all">Todas as áreas</span>${areas.map(x => `<span class="chip ${state.auditArea === x ? 'active' : ''}" data-a="${x}">${esc(x)}</span>`).join('')}</div>
  <label style="margin:0 0 0 auto"><input type="checkbox" id="audHideOk" ${state.auditHideOk ? 'checked' : ''}> ocultar OK/info</label></div>
  <div id="audList"></div>`;
  const draw = () => {
    const hide = $('#audHideOk').checked; state.auditHideOk = hide;
    const fs = a.findings.filter(f => (state.auditArea === 'all' || f.area === state.auditArea) && !(hide && (f.severity === 'ok' || f.severity === 'info')));
    $('#audList').innerHTML = fs.map((f, i) => `
      <details class="finding" ${['critico', 'alto'].includes(f.severity) ? 'open' : ''}>
        <summary>${tag(RISK_LABEL[f.severity], f.severity)} <b>${esc(f.title)}</b> <span class="muted small" style="margin-left:auto">${esc(f.area)}</span></summary>
        <div class="body">
          <div><b>Encontrado:</b> ${esc(f.detail)}</div>
          ${f.why ? `<div><b>Por que importa:</b> ${esc(f.why)}</div>` : ''}
          ${f.manual.length ? `<div><b>Como corrigir no UniFi:</b><ol>${f.manual.map(m => `<li>${esc(m)}</li>`).join('')}</ol></div>` : ''}
          ${f.fix ? `<div><button class="btn primary sm" onclick="applyFix(${a.findings.indexOf(f)})">Aplicar: ${esc(f.fix.label)}</button> <span class="small muted">via API, com confirmação</span></div>` : ''}
        </div>
      </details>`).join('') || '<div class="card muted">Nada a mostrar.</div>';
  };
  state.auditFindings = a.findings;
  draw();
  $('#audChips').addEventListener('click', e => { const c = e.target.closest('.chip'); if (!c) return; state.auditArea = c.dataset.a; $$('#audChips .chip').forEach(x => x.classList.toggle('active', x === c)); draw(); });
  $('#audHideOk').addEventListener('change', draw);
};

window.applyFix = async i => {
  const f = state.auditFindings[i];
  if (!confirm(`Aplicar "${f.fix.label}"?\n\n${f.title}\n\nA alteração será feita imediatamente no seu UDM Pro.`)) return;
  try { const r = await api('/api/audit/apply', { method: 'POST', body: f.fix }); showAlert('✔ ' + r.message, 'ok'); delete state.cache.audit; delete state.cache.overview; setTimeout(() => render(true), 800); }
  catch (e) { showAlert('Falha ao aplicar: ' + e.message + (e.data && e.data.unifi ? '\n' + JSON.stringify(e.data.unifi).slice(0, 800) : '')); }
};

// --------------------------------------------------------------- firewall
VIEWS.firewall = async (force) => {
  const fw = await load('firewall', '/api/firewall', force);
  const nets = await load('networks', '/api/networks', force);
  const zn = Object.fromEntries(fw.zones.map(z => [z.id, z.name]));
  const nn = Object.fromEntries(nets.map(n => [n.id, n.name]));
  const describeFilter = tf => { if (!tf) return 'qualquer'; if (tf.type === 'NETWORK') return 'redes: ' + (tf.networkFilter.matchOpposite ? 'exceto ' : '') + tf.networkFilter.networkIds.map(id => nn[id] || id.slice(0, 8)).join(', ') + (tf.portFilter ? ' portas ' + descPorts(tf.portFilter) : ''); if (tf.type === 'PORT') return 'portas ' + descPorts(tf.portFilter); if (tf.type === 'IP_ADDRESS') return 'IPs ' + JSON.stringify(tf.ipAddressFilter || tf).slice(0, 60); if (tf.type === 'REGION') return 'regiões ' + (tf.regionFilter?.countryCodes || []).join(','); if (tf.type === 'DOMAIN') return 'domínios ' + (tf.domainFilter?.domains || []).join(','); if (tf.type === 'APPLICATION' || tf.type === 'APPLICATION_CATEGORY') return 'aplicações (DPI)'; return tf.type; };
  const descPorts = pf => pf ? (pf.matchOpposite ? 'exceto ' : '') + (pf.items || []).map(p => p.type === 'PORT_NUMBER_RANGE' ? p.start + '-' + p.stop : p.value).join(',') : '';
  const descProto = sc => { if (!sc || !sc.protocolFilter) return (sc && sc.ipVersion) || 'todos'; const pf = sc.protocolFilter; return (pf.type === 'PRESET' ? pf.preset.name : pf.type === 'NAMED_PROTOCOL' ? pf.protocol.name : 'proto ' + pf.protocolNumber) + ' (' + sc.ipVersion + ')'; };
  const userPols = fw.policies.filter(p => p.metadata?.origin === 'USER_DEFINED');
  const sysPols = fw.policies.filter(p => p.metadata?.origin !== 'USER_DEFINED');
  const polRow = p => `<tr><td>${p.index ?? ''}</td><td><b>${esc(p.name)}</b><div class="small muted">${esc(p.description || '')}</div></td><td>${tag(p.action.type, p.action.type === 'ALLOW' ? 'ok' : 'alto')}</td><td>${esc(zn[p.source.zoneId] || '?')}<div class="small muted">${esc(describeFilter(p.source.trafficFilter))}</div></td><td>${esc(zn[p.destination.zoneId] || '?')}<div class="small muted">${esc(describeFilter(p.destination.trafficFilter))}</div></td><td class="small">${esc(descProto(p.ipProtocolScope))}${p.connectionStateFilter ? '<br>' + p.connectionStateFilter.join(',') : ''}</td><td>${p.enabled ? tag('ativa', 'ok') : tag('inativa', 'info')} ${p.loggingEnabled ? tag('log', 'info') : ''}</td><td>${p.metadata?.origin === 'USER_DEFINED' ? `<button class="btn sm" onclick="togglePolicy('${p.id}',${!p.enabled})">${p.enabled ? 'Desativar' : 'Ativar'}</button> ${!p.loggingEnabled ? `<button class="btn sm" onclick="policyLog('${p.id}')">Log</button>` : ''} <button class="btn sm danger" onclick="delPolicy('${p.id}','${esc(p.name)}')">Excluir</button>` : ''}</td></tr>`;
  view.innerHTML = `
  <div class="help"><b>Zone-Based Firewall:</b> cada rede pertence a uma <b>zona</b> (Internal, External, Guest, VPN, Hotspot, DMZ ou personalizadas). Políticas definem o que pode passar de uma zona para outra. Ordem importa: a primeira regra que casar decide.</div>
  <div class="grid g2 mt">
    <div class="card"><h3>Zonas (${fw.zones.length})</h3><table><tr><th>Zona</th><th>Origem</th><th>Redes</th></tr>${fw.zones.map(z => `<tr><td><b>${esc(z.name)}</b></td><td class="small muted">${esc(z.metadata?.origin || '')}</td><td class="small">${z.networkIds.map(id => esc(nn[id] || id.slice(0, 8))).join(', ') || '<span class="muted">nenhuma</span>'}</td></tr>`).join('')}</table></div>
    <div class="card"><h3>Assistente: criar política de bloqueio</h3>
      <p class="small muted">Exemplos: bloquear <b>IoT → Internal</b> (câmeras/TVs não acessam seus PCs), <b>Guest → Internal</b>, ou bloquear portas administrativas (22, 3389, 445) vindas de qualquer zona.</p>
      <div class="form-row">
        <div class="field"><label>Nome</label><input id="wzName" value="Bloquear IoT para rede interna"></div>
        <div class="field"><label>Ação</label><select id="wzAction"><option value="BLOCK">BLOCK (descartar silenciosamente)</option><option value="REJECT">REJECT (recusar com resposta)</option><option value="ALLOW">ALLOW (permitir)</option></select></div>
        <div class="field"><label>Zona de origem</label><select id="wzSrc">${fw.zones.map(z => `<option value="${z.id}">${esc(z.name)}</option>`).join('')}</select></div>
        <div class="field"><label>Zona de destino</label><select id="wzDst">${fw.zones.map(z => `<option value="${z.id}" ${z.name === 'Internal' ? 'selected' : ''}>${esc(z.name)}</option>`).join('')}</select></div>
        <div class="field"><label>Redes de origem (opcional, Ctrl para várias)</label><select id="wzSrcNets" multiple size="4">${nets.map(n => `<option value="${n.id}">${esc(n.name)} (VLAN ${n.vlanId})</option>`).join('')}</select></div>
        <div class="field"><label>Redes de destino (opcional)</label><select id="wzDstNets" multiple size="4">${nets.map(n => `<option value="${n.id}">${esc(n.name)} (VLAN ${n.vlanId})</option>`).join('')}</select></div>
        <div class="field"><label>Portas de destino (opcional, ex.: 22,3389,445 ou 8000-8100; ignorado se redes de destino selecionadas)</label><input id="wzPorts" placeholder="22,3389,445"></div>
        <div class="field"><label>Protocolo</label><select id="wzProto"><option value="">Todos</option><option value="TCP_UDP">TCP+UDP</option><option value="TCP">TCP</option><option value="UDP">UDP</option><option value="ICMP">ICMP</option></select></div>
        <div class="field"><label>Estado da conexão</label><select id="wzState"><option value="">Todos</option><option value="NEW">Somente NEW (não quebra respostas de conexões iniciadas do outro lado)</option></select></div>
        <div class="field"><label>Log</label><select id="wzLog"><option value="1">Ativado (recomendado)</option><option value="0">Desativado</option></select></div>
      </div>
      <button class="btn" onclick="wizardPreview()">Pré-visualizar JSON</button> <button class="btn primary" onclick="wizardCreate()">Criar política</button>
      <pre id="wzPreview" class="hidden mt"></pre>
    </div>
  </div>
  <div class="card mt"><h3>Políticas personalizadas (${userPols.length})</h3><div class="tbl"><table><tr><th>#</th><th>Nome</th><th>Ação</th><th>Origem</th><th>Destino</th><th>Protocolo</th><th>Estado</th><th></th></tr>${userPols.map(polRow).join('') || '<tr><td colspan="8" class="muted">Nenhuma política personalizada. Use o assistente acima.</td></tr>'}</table></div></div>
  <div class="card mt"><h3>Políticas do sistema / predefinidas (${sysPols.length})</h3><div class="tbl" style="max-height:400px"><table><tr><th>#</th><th>Nome</th><th>Ação</th><th>Origem</th><th>Destino</th><th>Protocolo</th><th>Estado</th><th></th></tr>${sysPols.map(polRow).join('')}</table></div></div>
  ${fw.aclRules.length ? `<div class="card mt"><h3>Regras ACL de switch (${fw.aclRules.length})</h3><pre>${esc(JSON.stringify(fw.aclRules, null, 1)).slice(0, 5000)}</pre></div>` : ''}
  ${fw.trafficMatchingLists.length ? `<div class="card mt"><h3>Listas de correspondência de tráfego (${fw.trafficMatchingLists.length})</h3><table>${fw.trafficMatchingLists.map(t => `<tr><td>${esc(t.name)}</td><td class="small muted">${esc(t.type || '')}</td><td class="small mono">${esc(JSON.stringify(t.items || t.entries || '').slice(0, 120))}</td></tr>`).join('')}</table></div>` : ''}`;
};
function wizardBody() {
  const sel = id => $$(`#${id} option:checked`).map(o => o.value);
  const ports = $('#wzPorts').value.split(',').map(s => s.trim()).filter(Boolean);
  return { name: $('#wzName').value, actionType: $('#wzAction').value, sourceZoneId: $('#wzSrc').value, destinationZoneId: $('#wzDst').value, sourceNetworkIds: sel('wzSrcNets'), destinationNetworkIds: sel('wzDstNets'), destinationPorts: ports, protocol: $('#wzProto').value || null, connectionStates: $('#wzState').value ? [$('#wzState').value] : null, loggingEnabled: $('#wzLog').value === '1', enabled: true };
}
window.wizardPreview = async () => { try { const r = await api('/api/firewall/policies', { method: 'POST', body: { ...wizardBody(), preview: true } }); const p = $('#wzPreview'); p.classList.remove('hidden'); p.textContent = JSON.stringify(r.preview, null, 2); } catch (e) { showAlert(e.message); } };
window.wizardCreate = async () => { const b = wizardBody(); if (!confirm(`Criar política "${b.name}"?`)) return; try { const r = await api('/api/firewall/policies', { method: 'POST', body: b }); showAlert('✔ ' + r.message, 'ok'); delete state.cache.firewall; render(true); } catch (e) { showAlert('Falha: ' + e.message + (e.data?.unifi ? '\n' + JSON.stringify(e.data.unifi).slice(0, 800) : '')); } };
window.togglePolicy = async (id, en) => { try { await api(`/api/firewall/policies/${id}/enabled`, { method: 'POST', body: { enabled: en } }); delete state.cache.firewall; render(true); } catch (e) { showAlert(e.message); } };
window.policyLog = async id => { try { await api(`/api/firewall/policies/${id}/logging`, { method: 'POST', body: { enabled: true } }); delete state.cache.firewall; render(true); } catch (e) { showAlert(e.message); } };
window.delPolicy = async (id, name) => { if (!confirm(`Excluir a política "${name}"?`)) return; try { await api(`/api/firewall/policies/${id}`, { method: 'DELETE' }); delete state.cache.firewall; render(true); } catch (e) { showAlert(e.message); } };

// --------------------------------------------------------------- networks
VIEWS.networks = async (force) => {
  const [nets, wifi, zonesData] = await Promise.all([load('networks', '/api/networks', force), load('wifi', '/api/wifi', force), load('firewall', '/api/firewall', force)]);
  const zn = Object.fromEntries(zonesData.zones.map(z => [z.id, z.name]));
  const nn = Object.fromEntries(nets.map(n => [n.id, n.name]));
  const SEC = { OPEN: ['Aberta (sem senha)', 'critico'], WPA2_PERSONAL: ['WPA2 Personal', 'baixo'], WPA2_WPA3_PERSONAL: ['WPA2/WPA3 Personal', 'ok'], WPA3_PERSONAL: ['WPA3 Personal', 'ok'], WPA2_ENTERPRISE: ['WPA2 Enterprise', 'ok'], WPA2_WPA3_ENTERPRISE: ['WPA2/WPA3 Enterprise', 'ok'], WPA3_ENTERPRISE: ['WPA3 Enterprise', 'ok'] };
  view.innerHTML = `
  <div class="card"><h3>Redes / VLANs (${nets.length})</h3><div class="tbl"><table><tr><th>Nome</th><th>VLAN</th><th>Tipo</th><th>Sub-rede</th><th>DHCP</th><th>Zona</th><th>Isolada</th><th>Internet</th><th>mDNS</th><th>DHCP Guard</th><th>IPv6</th><th></th></tr>
    ${nets.map(n => { const v4 = n.ipv4Configuration || {}; const dhcp = v4.dhcpConfiguration; return `<tr><td><b>${esc(n.name)}</b> ${n.default ? tag('padrão', 'info') : ''} ${!n.enabled ? tag('desativada', 'info') : ''}</td><td>${n.vlanId}</td><td class="small">${esc(n.management)}</td><td class="mono small">${v4.hostIpAddress ? v4.hostIpAddress + '/' + v4.prefixLength : '-'}</td><td class="small">${dhcp ? (dhcp.mode || 'server') + (dhcp.range ? ' ' + dhcp.range.start + '–' + dhcp.range.stop : '') : '-'}</td><td>${esc(zn[n.zoneId] || '-')}</td><td>${n.isolationEnabled ? tag('sim', 'ok') : tag('não', 'info')}</td><td>${n.internetAccessEnabled === false ? tag('bloqueada', 'alto') : tag('sim', 'ok')}</td><td>${n.mdnsForwardingEnabled ? 'sim' : 'não'}</td><td>${n.dhcpGuarding ? tag('ativo', 'ok') : tag('off', 'info')}</td><td>${n.ipv6Configuration ? 'sim' : 'não'}</td><td><button class="btn sm" onclick="showJson('Rede: ${esc(n.name)}', ${esc(JSON.stringify(JSON.stringify(n)))})">JSON</button></td></tr>`; }).join('')}</table></div></div>
  <div class="card mt"><h3>Redes WiFi / SSIDs (${wifi.length})</h3><div class="tbl"><table><tr><th>SSID</th><th>Segurança</th><th>Rede</th><th>Bandas</th><th>Tipo</th><th>Isolamento de clientes</th><th>PMF</th><th>Oculta</th><th>Senha</th><th>Filtro MAC</th><th></th></tr>
    ${wifi.map(w => { const sc = w.securityConfiguration || {}; const s = SEC[sc.type] || [sc.type, 'info']; const netRef = w.network || {}; return `<tr><td><b>${esc(w.name)}</b> ${!w.enabled ? tag('desativada', 'info') : ''}</td><td>${tag(s[0], s[1])}</td><td class="small">${netRef.type === 'SPECIFIC' ? esc(nn[netRef.networkId] || netRef.networkId) : 'nativa do AP'}</td><td class="small">${(w.broadcastingFrequencies || w.broadcastingFrequenciesGHz || []).join(' / ')} GHz</td><td class="small">${esc(w.type || '')}</td><td>${w.clientIsolationEnabled ? tag('ativo', 'ok') : tag('off', 'info')}</td><td class="small">${sc.pmfMode || 'off'}</td><td class="small">${w.hideName ? 'sim' : 'não'}</td><td class="small">${sc.passphraseLength ? sc.passphraseLength + ' chars' + (sc.passphraseLength < 12 ? ' ' + tag('curta', 'alto') : '') : '-'}</td><td class="small">${w.clientFilteringPolicy ? esc(w.clientFilteringPolicy.type || 'sim') : 'não'}</td><td><button class="btn sm" onclick="showJson('WiFi: ${esc(w.name)}', ${esc(JSON.stringify(JSON.stringify(w)))})">JSON</button></td></tr>`; }).join('')}</table></div></div>
  <div class="help mt"><b>Boas práticas:</b> IoT/câmeras/TVs em VLAN própria com isolamento; convidados com isolamento de clientes; WPA2/WPA3 com senha ≥ 16 caracteres; PMF opcional; DHCP Guarding com o IP do gateway como servidor confiável.</div>`;
};
window.showJson = (title, json) => openModal(title, `<pre>${esc(JSON.stringify(JSON.parse(json), null, 2))}</pre>`);

// ---------------------------------------------------------------- clients
VIEWS.clients = async (force) => {
  const cl = await load('clients', '/api/clients', force);
  const devs = await load('devices', '/api/devices', force);
  const dn = Object.fromEntries(devs.map(d => [d.id, d.name]));
  view.innerHTML = `<div class="toolbar"><input id="clSearch" placeholder="Buscar nome, IP, MAC, fabricante…" style="width:300px"><select id="clType"><option value="">Todos os tipos</option><option>WIRELESS</option><option>WIRED</option><option>VPN</option><option>TELEPORT</option></select><span class="muted small">${cl.length} clientes</span></div><div class="card"><div class="tbl" id="clTbl"></div></div>`;
  const draw = () => {
    const q = $('#clSearch').value.toLowerCase(), t = $('#clType').value;
    const rows = cl.filter(c => (!t || c.type === t) && (!q || JSON.stringify(c).toLowerCase().includes(q)));
    $('#clTbl').innerHTML = `<table><tr><th>Nome</th><th>Tipo</th><th>IP</th><th>MAC</th><th>Fabricante / SO</th><th>Conexão</th><th>Sinal</th><th>Tráfego ↓/↑</th><th>Acesso</th><th>Desde</th><th></th></tr>
      ${rows.map(c => { const x = c.extra || {}; return `<tr><td><b>${esc(c.name || x.hostname || '(sem nome)')}</b>${x.hostname && x.hostname !== c.name ? `<div class="small muted">${esc(x.hostname)}</div>` : ''}</td><td>${tag(c.type, 'info')}</td><td class="mono">${esc(c.ipAddress || '-')}</td><td class="mono small">${esc(c.macAddress || '-')}</td><td class="small">${esc(x.oui || '-')}${x.os ? '<br>' + esc(x.os) : ''}</td><td class="small">${x.essid ? esc(x.essid) + ' · ' + (x.channel ? 'ch ' + x.channel : '') + ' ' + esc(x.radioProto || '') : (x.switchPort ? 'porta ' + x.switchPort : '')}<br><span class="muted">${esc(dn[c.uplinkDeviceId] || '')} ${x.network ? '· ' + esc(x.network) : ''}</span></td><td class="small">${x.signal != null ? x.signal + ' dBm' : (x.rssi != null ? x.rssi : '-')}</td><td class="small">${x.rxBytes != null ? fmtBytes(x.rxBytes) + ' / ' + fmtBytes(x.txBytes) : '-'}</td><td>${c.access?.type === 'GUEST' ? tag('convidado', 'medio') : tag(c.access?.type || '-', 'info')} ${x.blocked ? tag('bloqueado', 'alto') : ''}</td><td class="small muted">${fmtDate(c.connectedAt)}</td><td>${c.macAddress ? `<button class="btn sm ${x.blocked ? '' : 'danger'}" onclick="blockClient('${c.macAddress}','${esc(c.name)}',${!!x.blocked})">${x.blocked ? 'Desbloquear' : 'Bloquear'}</button>` : ''} <button class="btn sm" onclick="showJson('Cliente', ${esc(JSON.stringify(JSON.stringify(c)))})">JSON</button></td></tr>`; }).join('')}</table>`;
  };
  draw(); $('#clSearch').addEventListener('input', draw); $('#clType').addEventListener('change', draw);
};

// ---------------------------------------------------------------- devices
VIEWS.devices = async (force) => {
  const devs = await load('devicesStats', '/api/devices?stats=true', force);
  const pend = await load('pending', '/api/pending-devices', force);
  view.innerHTML = `<div class="grid g3">${devs.map(d => { const s = d.stats || {}; return `<div class="card"><div style="display:flex;justify-content:space-between"><b>${esc(d.name)}</b>${tag(d.state)}</div><div class="small muted">${esc(d.model)} · ${(d.features || []).join(', ')} · ${esc(d.ipAddress)} · ${esc(d.macAddress)}</div>
    <div class="small mt">Firmware ${esc(d.firmwareVersion || '-')} ${d.firmwareUpdatable ? tag('atualização disponível', 'medio') : tag('atualizado', 'ok')}</div>
    <div class="mt small">CPU ${Math.round(s.cpuUtilizationPct ?? 0)}%<div class="bar"><i style="width:${Math.min(100, s.cpuUtilizationPct ?? 0)}%"></i></div></div>
    <div class="mt small">RAM ${Math.round(s.memoryUtilizationPct ?? 0)}%<div class="bar"><i style="width:${Math.min(100, s.memoryUtilizationPct ?? 0)}%"></i></div></div>
    <div class="small muted mt">Uptime ${fmtUptime(s.uptimeSec)} · load ${s.loadAverage1Min ?? '-'} / ${s.loadAverage5Min ?? '-'} / ${s.loadAverage15Min ?? '-'} · último contato ${fmtDate(s.lastHeartbeatAt)}</div>
    ${s.uplink ? `<div class="small muted">Uplink ↓${fmtBps(s.uplink.rxRateBps)} ↑${fmtBps(s.uplink.txRateBps)}</div>` : ''}
    <div class="mt"><button class="btn sm" onclick="showDevice('${d.id}')">Detalhes</button> <button class="btn sm danger" onclick="restartDevice('${d.id}','${esc(d.name)}')">Reiniciar</button></div></div>`; }).join('')}</div>
  <div class="card mt"><h3>Aguardando adoção (${pend.length})</h3>${pend.length ? `<table>${pend.map(p => `<tr><td>${esc(p.model)}</td><td class="mono">${esc(p.macAddress)}</td><td class="mono">${esc(p.ipAddress || '')}</td><td>${esc(p.name || '')}</td></tr>`).join('')}</table>` : '<div class="muted">Nenhum.</div>'}</div>`;
};
window.showDevice = async id => {
  try {
    const d = await api(`/api/devices/${id}`);
    const ports = (d.interfaces?.ports || []);
    const radios = (d.interfaces?.radios || []);
    const st = (d.stats?.interfaces) || {};
    const pst = Object.fromEntries((st.ports || []).map(p => [p.portIdx, p]));
    openModal(`${d.name} (${d.model})`, `
      <div class="kv"><b>IP / MAC</b><span class="mono">${d.ipAddress} · ${d.macAddress}</span><b>Estado</b><span>${tag(d.state)}</span><b>Firmware</b><span>${d.firmwareVersion} ${d.firmwareUpdatable ? tag('atualização', 'medio') : ''}</span><b>Adotado em</b><span>${fmtDate(d.adoptedAt)}</span><b>Provisionado</b><span>${fmtDate(d.provisionedAt)}</span><b>Uplink</b><span>${d.uplink ? esc(JSON.stringify(d.uplink)) : '-'}</span></div>
      ${ports.length ? `<h4>Portas (${ports.length})</h4><div class="tbl" style="max-height:300px"><table><tr><th>#</th><th>Conector</th><th>Estado</th><th>Velocidade</th><th>PoE</th><th>Tráfego ↓/↑</th></tr>${ports.map(p => { const s = pst[p.idx] || {}; return `<tr><td>${p.idx}</td><td>${p.connector}</td><td>${tag(p.state, p.state === 'UP' ? 'ok' : 'info')}</td><td>${p.speedMbps ? p.speedMbps + ' Mbps' : '-'} / máx ${p.maxSpeedMbps}</td><td class="small">${p.poe ? (p.poe.enabled ? p.poe.standard + ' ' + p.poe.state : 'off') : '-'}</td><td class="small">${s.rxRateBps != null ? fmtBps(s.rxRateBps) + ' / ' + fmtBps(s.txRateBps) : '-'}</td></tr>`; }).join('')}</table></div>` : ''}
      ${radios.length ? `<h4>Rádios</h4><table><tr><th>Banda</th><th>Canal</th><th>Largura</th><th>Padrão</th><th>Clientes</th><th>Utilização</th></tr>${radios.map(r => { const s = (st.radios || []).find(x => x.frequencyGHz === r.frequencyGHz) || {}; return `<tr><td>${r.frequencyGHz} GHz</td><td>${r.channel ?? '-'}</td><td>${r.channelWidthMHz ?? '-'} MHz</td><td>${r.wlanStandard || ''}</td><td>${s.connectedClients ?? '-'}</td><td>${s.utilizationPct != null ? s.utilizationPct + '%' : '-'}</td></tr>`; }).join('')}</table>` : ''}
      <details class="mt"><summary class="muted small">JSON completo</summary><pre>${esc(JSON.stringify(d, null, 2))}</pre></details>`);
  } catch (e) { showAlert(e.message); }
};
window.restartDevice = async (id, name) => { if (!confirm(`Reiniciar "${name}"?`)) return; try { await api(`/api/devices/${id}/restart`, { method: 'POST' }); showAlert('Reinicialização solicitada.', 'ok'); } catch (e) { showAlert(e.message); } };

// ------------------------------------------------------------------- logs
VIEWS.logs = async (force) => {
  const hours = state.logHours || 72;
  const [evs, alarms] = await Promise.all([load('events' + hours, `/api/events?hours=${hours}&limit=1000`, force), load('alarms', '/api/alarms', force)]);
  state.logKind = state.logKind || 'all';
  view.innerHTML = `
  <div class="toolbar"><label style="margin:0">Período</label><select id="logHours">${[6, 24, 72, 168, 720].map(h => `<option value="${h}" ${h === hours ? 'selected' : ''}>${h < 24 ? h + 'h' : (h / 24) + ' dias'}</option>`).join('')}</select>
    <div class="chips" id="logChips">${[['all', 'Todos'], ['seguranca', 'Segurança'], ['alerta', 'Alertas'], ['info', 'Informativos']].map(([k, l]) => `<span class="chip ${state.logKind === k ? 'active' : ''}" data-k="${k}">${l}</span>`).join('')}</div>
    <input id="logSearch" placeholder="Buscar…" style="margin-left:auto;width:240px"></div>
  <div class="grid g2">
    <div class="card"><h3>Alarmes (${alarms.length})</h3><div class="tbl" style="max-height:340px"><table>${alarms.map(a => `<tr><td class="small muted" style="white-space:nowrap">${fmtDate(a.time)}</td><td>${tag(a.kind)} <b>${esc(a.title)}</b> ${a.archived ? tag('arquivado', 'info') : ''}<div class="small muted">${esc(a.message || '')}</div>${a.hint ? `<div class="small" style="color:var(--info)">💡 ${esc(a.hint)}</div>` : ''}</td></tr>`).join('') || '<tr><td class="muted">Nenhum alarme.</td></tr>'}</table></div></div>
    <div class="card"><h3>Eventos por tipo</h3><div class="canvas-wrap"><canvas id="chEv"></canvas></div></div>
  </div>
  <div class="card mt"><h3>Eventos (<span id="evCount"></span>)</h3><div class="tbl" id="evTbl"></div></div>`;
  const draw = () => {
    const q = $('#logSearch').value.toLowerCase();
    const rows = evs.filter(e => (state.logKind === 'all' || e.kind === state.logKind) && (!q || JSON.stringify(e).toLowerCase().includes(q)));
    $('#evCount').textContent = rows.length;
    $('#evTbl').innerHTML = `<table><tr><th>Quando</th><th>Tipo</th><th>Evento</th><th>Detalhes</th><th>Usuário/Cliente</th><th>Dispositivo</th></tr>${rows.slice(0, 600).map(e => `<tr><td class="small muted" style="white-space:nowrap">${fmtDate(e.time)}</td><td>${tag(e.kind)}</td><td><b>${esc(e.title)}</b><div class="small mono muted">${esc(e.key)}</div></td><td class="small">${esc(e.message || '')}${e.ssid ? ' · SSID ' + esc(e.ssid) : ''}${e.ip ? ' · ' + esc(e.ip) : ''}</td><td class="small">${esc(e.user || e.admin || '')}</td><td class="small">${esc(e.device || '')}</td></tr>`).join('')}</table>`;
  };
  draw(); $('#logSearch').addEventListener('input', draw);
  $('#logChips').addEventListener('click', e => { const c = e.target.closest('.chip'); if (!c) return; state.logKind = c.dataset.k; $$('#logChips .chip').forEach(x => x.classList.toggle('active', x === c)); draw(); });
  $('#logHours').addEventListener('change', e => { state.logHours = Number(e.target.value); render(); });
  const counts = {}; evs.forEach(e => counts[e.title] = (counts[e.title] || 0) + 1);
  const top = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10);
  chart($('#chEv'), { type: 'bar', data: { labels: top.map(t => t[0]), datasets: [{ label: 'eventos', data: top.map(t => t[1]), backgroundColor: PALETTE }] }, options: { ...chartDefaults, indexAxis: 'y', maintainAspectRatio: false, plugins: { legend: { display: false } } } });
};

// -------------------------------------------------------------------- vpn
VIEWS.vpn = async (force) => {
  const [vpn, wans, dns] = await Promise.all([load('vpn', '/api/vpn', force), load('wans', '/api/wans', force), load('dns', '/api/dns', force).catch(() => [])]);
  let sec = null; try { sec = await load('secset', '/api/security-settings', force); } catch { }
  const VPNRISK = { PPTP: 'critico', L2TP: 'medio', OPENVPN: 'ok', WIREGUARD: 'ok', UID: 'ok' };
  view.innerHTML = `
  <div class="grid g2">
    <div class="card"><h3>Servidores VPN (${vpn.servers.length})</h3><table><tr><th>Nome</th><th>Tipo</th><th>Estado</th><th>Avaliação</th></tr>${vpn.servers.map(v => `<tr><td>${esc(v.name)}</td><td>${esc(v.type)}</td><td>${v.enabled ? tag('ativo', 'ok') : tag('inativo', 'info')}</td><td>${tag({ critico: 'inseguro (PPTP)', medio: 'aceitável', ok: 'seguro' }[VPNRISK[v.type] || 'ok'], VPNRISK[v.type] || 'ok')}</td></tr>`).join('') || '<tr><td class="muted">Nenhum servidor VPN.</td></tr>'}</table>
      ${vpn.tunnels.length ? `<h3 class="mt">Túneis site-a-site (${vpn.tunnels.length})</h3><table>${vpn.tunnels.map(t => `<tr><td>${esc(t.name)}</td><td>${esc(t.type)}</td><td>${t.enabled ? tag('ativo', 'ok') : tag('inativo', 'info')}</td></tr>`).join('')}</table>` : ''}</div>
    <div class="card"><h3>Interfaces WAN (${wans.length})</h3><table>${wans.map(w => `<tr><td><b>${esc(w.name)}</b></td><td class="small mono muted">${esc(JSON.stringify(Object.fromEntries(Object.entries(w).filter(([k]) => !['id', 'name'].includes(k))))).slice(0, 200)}</td></tr>`).join('') || '<tr><td class="muted">-</td></tr>'}</table></div>
  </div>
  <div class="card mt"><h3>Políticas DNS / registros (${dns.length})</h3>${dns.length ? `<table><tr><th>Tipo</th><th>Domínio</th><th>Valor</th><th>Ativo</th></tr>${dns.map(d => `<tr><td>${esc(d.type)}</td><td class="mono">${esc(d.domain || d.name || '')}</td><td class="mono small">${esc(d.ipAddress || d.value || d.target || '')}</td><td>${d.enabled ? tag('sim', 'ok') : tag('não', 'info')}</td></tr>`).join('')}</table>` : '<div class="muted">Nenhuma política DNS personalizada.</div>'}</div>
  ${sec ? `<div class="card mt"><h3>Configurações de segurança do gateway (API clássica)</h3><div class="grid g3">
    <div><b>IDS/IPS</b><div class="kv mt"><b>Modo</b><span>${esc(sec.ips?.ips_mode || '-')}</span><b>Categorias</b><span>${(sec.ips?.enabled_categories || []).length}</span><b>Ad block</b><span>${sec.ips?.ad_blocking_enabled ? 'sim' : 'não'}</span><b>Restringe TOR</b><span>${sec.ips?.restrict_tor ? 'sim' : 'não'}</span><b>Restringe torrent</b><span>${sec.ips?.restrict_torrents ? 'sim' : 'não'}</span><b>Honeypot</b><span>${sec.ips?.honeypot_enabled ? 'sim' : 'não'}</span></div></div>
    <div><b>Gateway</b><div class="kv mt"><b>UPnP</b><span>${sec.usg?.upnp_enabled ? tag('ATIVO', 'alto') : tag('off', 'ok')}</span><b>GeoIP</b><span>${sec.usg?.geo_ip_filtering_enabled ? 'ativo (' + esc(sec.usg?.geo_ip_filtering_block || '') + ')' : 'off'}</span><b>Log WAN</b><span>${sec.usg?.firewall_wan_default_log ? 'sim' : 'não'}</span><b>Log LAN</b><span>${sec.usg?.firewall_lan_default_log ? 'sim' : 'não'}</span><b>mDNS</b><span>${sec.usg?.mdns_enabled ? 'sim' : 'não'}</span><b>DPI</b><span>${sec.dpi?.enabled ? 'sim' : 'não'}</span></div></div>
    <div><b>Gestão</b><div class="kv mt"><b>SSH</b><span>${sec.mgmt?.x_ssh_enabled ? tag('ativo', 'baixo') : 'off'}</span><b>Auto-update</b><span>${sec.mgmt?.auto_upgrade ? 'sim' : 'não'}</span><b>LED</b><span>${sec.mgmt?.led_enabled ? 'on' : 'off'}</span></div></div>
  </div><details class="mt"><summary class="small muted">JSON completo</summary><pre>${esc(JSON.stringify(sec, null, 2))}</pre></details></div>` : ''}`;
};

// --------------------------------------------------- navegação e tráfego
VIEWS.traffic = async (force) => {
  const days = state.destDays || 7;
  const [t, d, s] = await Promise.all([
    load('traffic', '/api/traffic?top=25', force),
    load('dest' + days, `/api/destinations?days=${days}`, force),
    load('sessions', '/api/sessions?hours=24', force).catch(() => ({ available: false })),
  ]);
  const RISKC = { critico: 'critico', alto: 'alto', medio: 'medio', baixo: 'baixo' };
  view.innerHTML = `
  <div class="help">O UniFi <b>não guarda histórico de URLs visitadas</b> — isso não existe na API e nenhum painel consegue extrair.
  O que existe é a classificação por <b>DPI</b> (qual aplicação/categoria consumiu banda) e os <b>destinos concretos</b> que
  apareceram em eventos do IPS. É o mais próximo de "sites acessados" que o equipamento realmente entrega.</div>

  ${!t.available ? `<div class="alert info mt">${esc(t.reason)}</div>` :
    !t.dpiEnabled ? `<div class="alert info mt">${esc(t.hint || 'Sem dados de DPI.')}</div>` : `
  <div class="grid g2 mt">
    <div class="card"><h3>Aplicações mais acessadas</h3>
      <table><tr><th>Aplicação</th><th>Categoria</th><th>Total</th><th>↓ / ↑</th><th>Clientes</th></tr>
      ${t.byApp.map(a => `<tr><td><b>${esc(a.app)}</b></td><td class="small muted">${esc(a.category)}</td>
        <td>${fmtBytes(a.totalBytes)}</td><td class="small muted">${fmtBytes(a.rxBytes)} / ${fmtBytes(a.txBytes)}</td>
        <td class="small">${a.clients ?? '-'}</td></tr>`).join('')}</table></div>
    <div class="card"><h3>Categorias</h3><div class="canvas-wrap"><canvas id="chCat"></canvas></div>
      <table class="mt">${t.byCategory.map(c => `<tr><td>${esc(c.category)}</td><td>${fmtBytes(c.totalBytes)}</td></tr>`).join('')}</table></div>
  </div>
  <div class="card mt"><h3>Por dispositivo</h3><div class="tbl"><table><tr><th>Dispositivo</th><th>MAC</th><th>Total</th><th>Principais aplicações</th></tr>
    ${t.byClient.map(c => `<tr><td><b>${esc(c.name)}</b></td><td class="mono small muted">${esc(c.mac)}</td><td>${fmtBytes(c.totalBytes)}</td>
      <td class="small">${c.topApps.map(a => `${esc(a.app)} <span class="muted">(${fmtBytes(a.totalBytes)})</span>`).join(' · ')}</td></tr>`).join('')}</table></div></div>`}

  <div class="card mt"><h3>Destinos externos vistos pelo IPS</h3>
    <div class="toolbar"><label style="margin:0">Período</label><select id="destDays">${[1, 3, 7, 14, 30].map(x => `<option value="${x}" ${x === days ? 'selected' : ''}>${x} dia(s)</option>`).join('')}</select>
      <span class="small muted">${d.available ? d.total + ' destinos distintos' : ''}</span></div>
    ${d.available ? `<div class="tbl"><table><tr><th>IP</th><th>País</th><th>Risco</th><th>Eventos</th><th>Bloqueados</th><th>Tipos</th></tr>
      ${d.destinations.map(x => `<tr><td class="mono">${esc(x.ip)}</td><td class="small">${esc(x.country || '-')}</td>
        <td>${tag(RISK_LABEL[x.maxRisk], RISKC[x.maxRisk])}</td><td>${x.count}</td><td class="small">${x.blocked}</td>
        <td class="small muted">${x.types.map(esc).join(', ')}</td></tr>`).join('')}</table></div>`
      : `<div class="alert info">${esc(d.reason)}</div>`}</div>

  <div class="card mt"><h3>Sessões de clientes (24h)</h3>
    ${s.available ? `<div class="tbl" style="max-height:360px"><table><tr><th>Dispositivo</th><th>IP</th><th>Início</th><th>Duração</th><th>↓ / ↑</th><th>Rede</th></tr>
      ${s.sessions.map(x => `<tr><td><b>${esc(x.name)}</b><div class="mono small muted">${esc(x.mac || '')}</div></td><td class="mono small">${esc(x.ip || '-')}</td>
        <td class="small muted">${fmtDate(x.start)}</td><td class="small">${fmtUptime(x.durationSec)}</td>
        <td class="small">${fmtBytes(x.rxBytes)} / ${fmtBytes(x.txBytes)}</td><td class="small muted">${esc(x.network || '-')}</td></tr>`).join('')}</table></div>`
      : `<div class="alert info">${esc(s.reason || 'Indisponível.')}</div>`}</div>`;

  $('#destDays').addEventListener('change', e => { state.destDays = Number(e.target.value); render(); });
  if (t.available && t.byCategory && t.byCategory.length)
    chart($('#chCat'), { type: 'doughnut', data: { labels: t.byCategory.map(c => c.category), datasets: [{ data: t.byCategory.map(c => c.totalBytes), backgroundColor: PALETTE }] }, options: { maintainAspectRatio: false, plugins: { legend: { position: 'right', labels: { color: '#8b98a9' } } } } });
};

// ------------------------------------------------------ validação IDS/IPS
VIEWS.validation = async (force) => {
  const v = await load('valTests', '/api/validation/tests', force);
  state.valTests = v.tests;
  view.innerHTML = `
  <div class="help"><b>Para que serve:</b> um IPS mal configurado é visualmente idêntico a um IPS funcionando — a diferença só
  aparece durante um incidente real. Estes testes geram tráfego que <b>casa com assinaturas conhecidas do Suricata</b>, sem
  nenhum payload capaz de causar dano, e depois releem os eventos do IPS para provar se ele detectou.</div>

  <div class="alert mt"><b>Uso autorizado apenas.</b> Execute somente contra equipamento seu ou com autorização escrita do dono.
  A varredura é restrita por código a IPs privados que pertençam às redes deste site — alvos públicos são recusados.</div>

  <div class="card mt"><h3>Testes disponíveis</h3>
    ${v.tests.map(t => `<details class="finding"><summary><input type="checkbox" class="valChk" value="${esc(t.id)}" ${t.optIn ? '' : 'checked'} onclick="event.stopPropagation()">
      <b>${esc(t.name)}</b> ${t.optIn ? tag('opcional', 'info') : ''} <span class="muted small" style="margin-left:auto">${esc(t.category)}</span></summary>
      <div class="body">
        <div><b>O que envia:</b> ${esc(t.sends)}</div>
        <div><b>Por que valida algo:</b> ${esc(t.why)}</div>
        <div><b>Assinatura esperada:</b> <span class="mono small">${esc(t.expects)}</span></div>
        <div><b>Risco do teste:</b> ${esc(t.harm)}</div>
      </div></details>`).join('')}
    <div class="form-row mt">
      <div class="field"><label>Alvo da varredura (deve estar na sua rede)</label>
        <input id="valTarget" value="${esc((v.targets.gateways || [])[0] || '')}" placeholder="192.168.1.1">
        <div class="small muted">Aceitos: ${(v.targets.gateways || []).map(esc).join(', ') || 'nenhum detectado'}${(v.targets.subnets || []).length ? ' · sub-redes ' + v.targets.subnets.map(esc).join(', ') : ''}</div></div>
    </div>
    <label class="mt" style="display:block"><input type="checkbox" id="valAuth"> <b>Confirmo que este equipamento é meu ou tenho autorização escrita do proprietário para testá-lo.</b></label>
    <button class="btn primary mt" onclick="valRun()">Executar validação</button>
    <button class="btn mt" id="valCorr" onclick="valCorrelate()" disabled>Verificar detecções</button>
  </div>
  <div id="valOut" class="mt"></div>`;
};

window.valRun = async () => {
  const tests = $$('.valChk:checked').map(c => c.value);
  if (!tests.length) return showAlert('Selecione ao menos um teste.');
  if (!$('#valAuth').checked) return showAlert('Marque a confirmação de autorização antes de executar.');
  const out = $('#valOut'); out.innerHTML = '<div class="spinner">Executando testes…</div>';
  try {
    const r = await api('/api/validation/run', { method: 'POST', body: { authorized: true, tests, target: $('#valTarget').value.trim() } });
    state.valRun = { startedAt: r.startedAt, tests };
    $('#valCorr').disabled = false;
    out.innerHTML = `<div class="card"><h3>Tráfego gerado</h3>
      <table><tr><th>Teste</th><th>Resultado</th></tr>
      ${r.results.map(x => { const e = x.executed; return `<tr><td><b>${esc(x.name)}</b><div class="small muted">${esc(x.expects)}</div></td>
        <td class="small">${e.reached === false ? `<span style="color:var(--warn)">não alcançou: ${esc(e.error || '')}</span>`
          : e.open !== undefined ? `alvo ${esc(e.target)} · <b>${e.open.length}</b> porta(s) abertas: <span class="mono">${e.open.join(', ') || '—'}</span><div class="muted">fechadas ${e.closed.length} · filtradas ${e.filtered.length} · varridas ${e.scanned.length}</div>`
          : e.resolved ? `resolveu para <span class="mono">${e.resolved.map(esc).join(', ')}</span>`
          : `HTTP ${e.status} · ${e.bytes} bytes`}</td></tr>`; }).join('')}</table>
      <div class="small muted mt">${esc(r.note)}</div></div>`;
  } catch (e) { out.innerHTML = `<div class="alert">${esc(e.message)}</div>`; }
};

window.valCorrelate = async () => {
  if (!state.valRun) return;
  const out = $('#valOut');
  out.insertAdjacentHTML('beforeend', '<div class="spinner" id="valWait">Lendo eventos do IPS…</div>');
  try {
    const r = await api('/api/validation/correlate', { method: 'POST', body: state.valRun });
    $('#valWait')?.remove();
    if (!r.available) { out.insertAdjacentHTML('beforeend', `<div class="alert info">${esc(r.reason)}</div>`); return; }
    const ok = r.detected === r.total;
    out.insertAdjacentHTML('beforeend', `<div class="card mt"><h3>Veredito do IPS</h3>
      <div class="alert ${ok ? 'ok' : ''}">${esc(r.verdict)}</div>
      <div class="grid g3 mt">
        <div class="card"><h3>Detectados</h3><div class="kpi" style="color:var(--ok)">${r.detected}/${r.total}</div></div>
        <div class="card"><h3>Bloqueados</h3><div class="kpi">${r.blockedCount}</div><small class="muted">detectar sem bloquear = modo Notificar</small></div>
        <div class="card"><h3>Eventos na janela</h3><div class="kpi">${r.eventsInWindow}</div></div>
      </div>
      <table class="mt"><tr><th>Teste</th><th>Detectou?</th><th>Assinatura casada</th></tr>
      ${Object.entries(r.byTest).map(([k, t]) => `<tr><td><b>${esc(t.name)}</b><div class="small muted">esperado: ${esc(t.expects)}</div></td>
        <td>${t.detected ? tag('sim', 'ok') : tag('não', 'alto')}</td>
        <td class="small mono">${t.hits.map(h => esc(h.signature) + (h.blocked ? ' ' : ' (só detectado)')).join('<br>') || '—'}</td></tr>`).join('')}</table></div>`);
  } catch (e) { $('#valWait')?.remove(); out.insertAdjacentHTML('beforeend', `<div class="alert">${esc(e.message)}</div>`); }
};

// ----------------------------------------------------------- continuidade
VIEWS.continuity = async (force) => {
  const adParam = state.adServers ? `?adServers=${encodeURIComponent(state.adServers)}` : '';
  const [dns, wan] = await Promise.all([
    api('/api/continuity/dns-ad' + adParam),
    api('/api/continuity/wan'),
  ]);
  state.contDns = dns; state.contWan = wan;
  const d = dns.detection, m = wan.monitor, v = wan.vpn;
  const confRow = c => `<tr><td><b>${esc(c.name)}</b><div class="small muted">VLAN ${c.vlanId}</div></td>
    <td class="mono small">${c.adDnsServers.map(esc).join('<br>')}</td>
    <td class="mono small muted">${esc(c.gatewayIp || '-')}</td>
    <td>${tag(String(c.contentFilteringValue), 'alto')}<div class="small muted">${esc(c.contentFilteringField || '')}</div></td></tr>`;

  view.innerHTML = `
  <div class="help">Duas falhas operacionais que o app do UniFi não mostra e que só aparecem quando algo já quebrou:
  o <b>content filtering sequestrando o DNS do Active Directory</b> e a <b>VPN presa na WAN antiga depois do failover</b>.</div>

  <div class="card mt"><h3>1 · DNS do Active Directory vs. content filtering</h3>
    <p class="small">Quando o content filtering é ativado numa rede, o gateway passa a redirecionar a porta 53 para o resolvedor
    do filtro ainda em <b>PREROUTING</b> — antes da etapa de filtragem. Por isso <b>nenhuma regra de firewall "permitir" desfaz o
    sequestro</b>: a consulta nunca chega ao controlador de domínio, e os registros SRV do AD (<span class="mono">_ldap._tcp</span>,
    <span class="mono">_kerberos._tcp</span>) não existem no resolvedor público. Resultado: logon, ingresso no domínio e replicação falham.</p>
    <div class="toolbar">
      <div class="field" style="flex:1;margin:0"><label>Controladores de domínio (opcional — separados por vírgula; vazio = detectar sozinho)</label>
        <input id="adSrv" value="${esc(state.adServers || '')}" placeholder="192.168.10.10, 192.168.10.11"></div>
      <button class="btn" onclick="contDetect()">Detectar</button>
    </div>
    <div class="grid g2 mt">
      <div><b>${d.conflicts.length ? '⚠ VLANs com DNS sequestrado' : '✔ Nenhuma VLAN com DNS sequestrado'}</b>
        ${d.conflicts.length ? `<table class="mt"><tr><th>Rede</th><th>DNS do AD</th><th>Gateway</th><th>Filtro</th></tr>${d.conflicts.map(confRow).join('')}</table>
        <div class="small" style="color:var(--bad);margin-top:8px">${esc(d.conflicts[0].impact)}</div>` :
        `<div class="muted small mt">${d.networksChecked} rede(s) verificadas. Nenhuma aponta para um DNS interno que esteja sendo filtrado.</div>`}</div>
      <div><b>Redes com DNS interno já saudável</b>
        ${d.healthy.length ? `<table class="mt">${d.healthy.map(h => `<tr><td>${esc(h.name)}</td><td class="mono small">${h.adDnsServers.map(esc).join(', ')}</td><td>${tag('sem filtro', 'ok')}</td></tr>`).join('')}</table>`
        : '<div class="muted small mt">Nenhuma.</div>'}</div>
    </div>
    ${dns.steps.length ? `<h4 class="mt">Plano de correção (${dns.steps.length} passos, nesta ordem)</h4>
      <ol class="steps">${dns.steps.map((s, i) => `<li style="margin-bottom:8px">
        ${s.decisive ? tag('decisivo', 'ok') : tag('reforço', 'info')} <b>${esc(s.title)}</b>
        <div class="small muted">${esc(s.why)}</div>
        <div class="small mono muted">${esc(s.api)}</div>
        <button class="btn sm mt" onclick="contStep(${i})">Aplicar só este passo</button></li>`).join('')}</ol>
      <button class="btn primary" onclick="contApplyAll()">Aplicar plano completo</button>
      <span class="small muted">cada alteração é feita via API, com confirmação</span>`
    : `<div class="alert ok mt">Nada a corrigir: o DNS do Active Directory não está sendo interceptado.</div>`}
    <div id="contDnsOut" class="mt"></div>
  </div>

  <div class="card mt"><h3>2 · Failover de WAN e religamento da VPN</h3>
    <p class="small">O servidor VPN amarra a escuta a uma WAN. Quando a secundária assume, o endpoint continua apontando para a
    WAN antiga e os clientes não reconectam. A Integration API expõe <span class="mono">/wans</span> e <span class="mono">/vpn/servers</span>
    <b>somente para leitura</b> — a detecção usa ela, e a reescrita do vínculo só é possível pela API clássica
    (<span class="mono">/rest/networkconf</span>). Por isso a reconciliação começa sempre em <b>simulação</b>.</p>
    <div class="grid g2 mt">
      <div><b>Interfaces WAN</b><table class="mt"><tr><th>WAN</th><th>Estado</th><th>IP</th><th>Prioridade</th></tr>
        ${wan.snapshot.wans.map(w => `<tr><td><b>${esc(w.name)}</b> ${w.id === wan.snapshot.activeWanId ? tag('ATIVA', 'ok') : ''}</td>
          <td>${esc(String(w.state ?? '-'))}</td><td class="mono small">${esc(w.ipAddress || '-')}</td><td class="small">${esc(String(w.priority ?? '-'))}</td></tr>`).join('')}</table></div>
      <div><b>Vínculo dos servidores VPN</b>
        ${v.changes.length ? `<div class="alert mt">${v.changes.length} servidor(es) fora de sincronia com a WAN ativa (${esc(v.activeWanName || '?')}).</div>
          <table>${v.changes.map(ch => `<tr><td><b>${esc(ch.name)}</b><div class="small muted">${esc(ch.type || '')}</div></td>
            <td class="small">escuta em <span class="mono">${esc(String(ch.from))}</span> → deveria ser <span class="mono">${esc(String(ch.toName || ch.to))}</span></td>
            <td>${ch.writable ? tag('gravável', 'ok') : tag('só leitura', 'alto')}</td></tr>`).join('')}</table>`
          : `<div class="alert ok mt">Todos os servidores VPN apontam para a WAN ativa (${esc(v.activeWanName || '?')}).</div>`}
        ${v.note ? `<div class="small" style="color:var(--warn)">${esc(v.note)}</div>` : ''}</div>
    </div>
    <div class="toolbar mt">
      <label style="margin:0">Simular queda para</label>
      <select id="simWan">${wan.snapshot.wans.filter(w => w.id !== wan.snapshot.activeWanId).map(w => `<option value="${esc(w.id)}">${esc(w.name)}</option>`).join('') || '<option value="">(sem WAN alternativa)</option>'}</select>
      <button class="btn" onclick="contSimulate()">Simular failover (só leitura)</button>
      <button class="btn" onclick="contReconcile(true)">Reconciliar em simulação</button>
      <button class="btn primary" onclick="contReconcile(false)">Aplicar reconciliação</button>
    </div>
    <div id="contWanOut" class="mt"></div>

    <h4 class="mt">Monitor automático</h4>
    <p class="small muted">Vigia a WAN ativa em segundo plano — o failover não espera alguém estar olhando o painel.</p>
    <div class="toolbar">
      <div class="field" style="margin:0"><label>Intervalo (s)</label><input id="monInt" type="number" min="5" value="${m.intervalSec}" style="width:90px"></div>
      <label style="margin:0"><input type="checkbox" id="monAuto" ${m.autoReconcile ? 'checked' : ''}> reconciliar sozinho ao detectar troca</label>
      <label style="margin:0"><input type="checkbox" id="monDry" ${m.dryRun ? 'checked' : ''}> manter em simulação (não grava)</label>
      ${m.enabled ? `<button class="btn danger" onclick="contMonitor(false)">Parar monitor</button>` : `<button class="btn primary" onclick="contMonitor(true)">Iniciar monitor</button>`}
      <button class="btn" onclick="contPoll()">Verificar agora</button>
      <span class="small">${m.enabled ? tag('ligado', 'ok') : tag('desligado', 'info')} ${m.error ? tag('erro', 'alto') : ''}</span>
    </div>
    ${m.error ? `<div class="alert">Monitor: ${esc(m.error)}</div>` : ''}
    <div class="mt"><b>Transições detectadas (${m.history.length})</b>
      ${m.history.length ? `<table class="mt"><tr><th>Quando</th><th>De</th><th>Para</th><th>Ação</th></tr>
        ${m.history.map(h => `<tr><td class="small muted">${fmtDate(h.at)}</td><td>${esc(String(h.from))}<div class="small mono muted">${esc(h.fromIp || '')}</div></td>
        <td>${esc(String(h.to))}<div class="small mono muted">${esc(h.toIp || '')}</div></td>
        <td class="small">${h.reconcile ? (h.reconcile.error ? '⚠ ' + esc(h.reconcile.error) : (h.reconcile.dryRun ? 'simulado: ' : 'aplicado: ') + h.reconcile.changes + ' mudança(s)') : '—'}</td></tr>`).join('')}</table>`
        : '<div class="muted small">Nenhuma troca de WAN registrada desde que o monitor começou.</div>'}</div>
  </div>`;
};

window.contDetect = () => { state.adServers = $('#adSrv').value.trim(); render(true); };

window.contStep = async i => {
  const s = state.contDns.steps[i];
  if (!confirm(`Aplicar este passo?\n\n${s.title}\n\n${s.api}`)) return;
  const out = $('#contDnsOut'); out.innerHTML = '<span class="muted">Aplicando…</span>';
  try { const r = await api('/api/continuity/dns-ad/step', { method: 'POST', body: { action: s.action, params: s.params } });
    out.innerHTML = `<div class="alert ok">✔ ${esc(r.message || 'Passo aplicado.')}</div>`; setTimeout(() => render(true), 900); }
  catch (e) { out.innerHTML = `<div class="alert">Falha: ${esc(e.message)}</div>`; }
};

window.contApplyAll = async () => {
  const n = state.contDns.steps.length;
  if (!confirm(`Aplicar os ${n} passos no seu UDM Pro agora?\n\nO passo decisivo desativa o content filtering nas VLANs com DNS de Active Directory.`)) return;
  const out = $('#contDnsOut'); out.innerHTML = '<span class="muted">Aplicando plano…</span>';
  try {
    const r = await api('/api/continuity/dns-ad/apply', { method: 'POST', body: { adServers: (state.adServers || '').split(',').map(s => s.trim()).filter(Boolean) } });
    out.innerHTML = `<div class="alert ${r.resolved ? 'ok' : ''}">${esc(r.message)}</div>
      <table class="mt">${r.applied.map(a => `<tr><td>${a.ok ? '✔' : '✕'}</td><td>${esc(a.step)}</td><td class="small muted">${esc(a.message || '')}</td></tr>`).join('')}</table>`;
    setTimeout(() => render(true), 1500);
  } catch (e) { out.innerHTML = `<div class="alert">Falha: ${esc(e.message)}</div>`; }
};

window.contSimulate = async () => {
  const out = $('#contWanOut'); out.innerHTML = '<span class="muted">Simulando…</span>';
  try {
    const r = await api(`/api/continuity/wan/simulate?targetWanId=${encodeURIComponent($('#simWan').value)}`);
    if (!r.possible) { out.innerHTML = `<div class="alert info">${esc(r.reason)}</div>`; return; }
    out.innerHTML = `<div class="alert ${r.wouldSelfHeal ? 'ok' : 'info'}">${esc(r.summary)}</div>
      ${r.impacted.length ? `<table>${r.impacted.map(i => `<tr><td><b>${esc(i.name)}</b></td><td class="small">${esc(i.effect)}</td><td>${i.writable ? tag('corrigível via API', 'ok') : tag('exige ajuste manual', 'alto')}</td></tr>`).join('')}</table>` : ''}
      <div class="small muted mt">Simulação somente leitura — nada foi alterado no equipamento.</div>`;
  } catch (e) { out.innerHTML = `<div class="alert">Falha: ${esc(e.message)}</div>`; }
};

window.contReconcile = async (dry) => {
  if (!dry && !confirm('Reescrever o vínculo de WAN dos servidores VPN agora?\n\nIsto grava na configuração do UDM Pro pela API clássica.')) return;
  const out = $('#contWanOut'); out.innerHTML = '<span class="muted">Calculando…</span>';
  try {
    const r = await api('/api/continuity/vpn/reconcile', { method: 'POST', body: { dryRun: dry } });
    out.innerHTML = `<div class="alert ${r.inSync ? 'ok' : 'info'}">${r.dryRun ? 'Simulação — nada foi gravado. ' : ''}${r.inSync ? 'Servidores VPN em sincronia com a WAN ativa.' : r.changes.length + ' servidor(es) fora de sincronia.'}</div>
      ${r.changes.length ? `<table>${r.changes.map(c => `<tr><td><b>${esc(c.name)}</b></td><td class="small">${esc(c.reason)}</td></tr>`).join('')}</table>` : ''}
      ${(r.applied || []).length ? `<table class="mt">${r.applied.map(a => `<tr><td>${a.ok ? '✔' : '✕'}</td><td>${esc(a.name)}</td><td class="small muted">${esc(a.message)}</td></tr>`).join('')}</table>` : ''}`;
    if (!dry) setTimeout(() => render(true), 1200);
  } catch (e) { out.innerHTML = `<div class="alert">Falha: ${esc(e.message)}</div>`; }
};

window.contMonitor = async (on) => {
  try {
    await api('/api/continuity/monitor', { method: 'POST', body: { enabled: on, intervalSec: Number($('#monInt').value) || 30, autoReconcile: $('#monAuto').checked, dryRun: $('#monDry').checked } });
    showAlert(on ? 'Monitor de failover iniciado.' : 'Monitor parado.', 'ok'); render(true);
  } catch (e) { showAlert('Falha: ' + e.message); }
};

window.contPoll = async () => {
  try { const r = await api('/api/continuity/monitor/poll', { method: 'POST' });
    showAlert(r.poll.transition ? `Troca de WAN detectada: ${r.poll.transition.from} → ${r.poll.transition.to}` : 'Nenhuma troca de WAN desde a última leitura.', r.poll.transition ? '' : 'ok');
    render(true);
  } catch (e) { showAlert('Falha: ' + e.message); }
};

// --------------------------------------------------------------- explorer
VIEWS.explorer = async () => {
  const eps = await load('endpoints', '/api/endpoints');
  const gets = eps.filter(e => e.method === 'GET');
  view.innerHTML = `
  <div class="help">Consulte qualquer endpoint <b>GET</b> da Integration API oficial (documentada em <a href="https://developer.ui.com/network/v10.4.57/gettingstarted" target="_blank">developer.ui.com</a>) ou da API clássica. <code>{siteId}</code> é substituído automaticamente.</div>
  <div class="toolbar mt"><select id="exApi"><option value="integration">Integration API (/proxy/network/integration)</option><option value="classic">API clássica (/proxy/network/api/s/&lt;site&gt;)</option></select>
    <select id="exList" style="max-width:520px"><option value="">— escolher endpoint —</option>${gets.map(e => `<option value="${e.path}">${e.tag} · ${e.path} — ${esc(e.summary)}</option>`).join('')}</select>
    <input id="exPath" placeholder="/v1/sites/{siteId}/clients  ou  /stat/health" style="flex:1"><button class="btn primary" id="exGo">Consultar</button></div>
  <div class="card"><pre id="exOut" style="max-height:65vh">Resultado aparecerá aqui.</pre></div>
  <div class="card mt"><h3>Todos os endpoints da Integration API (${eps.length})</h3><div class="tbl" style="max-height:400px"><table><tr><th>Método</th><th>Caminho</th><th>Descrição</th><th>Grupo</th></tr>${eps.map(e => `<tr><td><span class="tag ${e.method === 'GET' ? 'ok' : e.method === 'DELETE' ? 'alto' : 'medio'}">${e.method}</span></td><td class="mono small">${e.path}</td><td class="small">${esc(e.summary)}</td><td class="small muted">${esc(e.tag)}</td></tr>`).join('')}</table></div></div>`;
  $('#exList').addEventListener('change', e => { $('#exPath').value = e.target.value; $('#exApi').value = 'integration'; });
  $('#exGo').addEventListener('click', async () => { const out = $('#exOut'); out.textContent = 'Consultando…'; try { const r = await api(`/api/raw?api=${$('#exApi').value}&path=${encodeURIComponent($('#exPath').value)}`); out.textContent = JSON.stringify(r, null, 2); } catch (e) { out.textContent = 'Erro: ' + e.message + '\n' + JSON.stringify(e.data, null, 2); } });
};

// --------------------------------------------------------------- settings
VIEWS.settings = async () => {
  const c = await api('/api/config');
  view.innerHTML = `
  <div class="grid g2">
    <div class="card"><h3>Conexão com o UDM Pro</h3>
      <div class="field"><label>Modo de conexão</label><select id="cfMode"><option value="local" ${c.mode === 'local' ? 'selected' : ''}>Local — acesso direto ao IP do UDM Pro (recomendado: habilita logs e ameaças)</option><option value="cloud" ${c.mode === 'cloud' ? 'selected' : ''}>Nuvem — via api.ui.com (Site Manager Cloud Connector)</option></select></div>
      <div class="field" id="fHost"><label>Endereço do UDM Pro (IP ou hostname, ex.: 192.168.1.1)</label><input id="cfHost" value="${esc(c.host)}"></div>
      <div class="field" id="fConsole"><label>ID do console (da URL do unifi.ui.com, ex.: 74ACB9D9…:728716942)</label><input id="cfConsole" value="${esc(c.console_id)}"></div>
      <div class="field"><label>Chave API ${c.configured ? `(atual: <span class="mono">${esc(c.api_key)}</span> — deixe em branco para manter)` : ''}</label><input id="cfKey" type="password" placeholder="cole a chave API"></div>
      <div class="field"><label>Site (opcional — UUID ou nome interno; vazio = primeiro site)</label><input id="cfSite" value="${esc(c.site_id)}"></div>
      <div class="field"><label><input type="checkbox" id="cfSsl" ${c.verify_ssl ? 'checked' : ''}> Verificar certificado SSL (desmarque para o certificado autoassinado padrão do UDM)</label></div>
      <button class="btn" id="cfTest">Testar conexão</button> <button class="btn primary" id="cfSave">Salvar</button>
      <div id="cfResult" class="mt"></div>
      <p class="small muted mt">A chave é gravada apenas neste servidor em <span class="mono">${esc(c.config_path)}</span> (permissão 600) e nunca é enviada ao navegador.</p>
    </div>
    <div class="card"><h3>Como obter a chave API</h3>
      <p><b>Modo local (recomendado):</b></p><ol class="small"><li>Abra o UniFi Network no UDM Pro → <b>Settings → Control Plane → Integrations</b> (ou <b>Settings → Admins & Users → Control Plane API</b>, conforme a versão).</li><li>Clique em <b>Create API Key</b>, dê um nome e copie a chave.</li><li>Informe o IP local do UDM Pro acima. Este painel precisa estar na mesma rede (ou conectado por VPN).</li></ol>
      <p><b>Modo nuvem:</b></p><ol class="small"><li>Acesse <a href="https://unifi.ui.com" target="_blank">unifi.ui.com</a> → <b>Settings → API → Create API Key</b> (Site Manager API).</li><li>Copie o <b>ID do console</b> da URL: <span class="mono">unifi.ui.com/consoles/<b>&lt;ID&gt;</b>/…</span></li><li>Funciona de qualquer lugar, mas a API clássica (logs, IPS) pode não estar disponível pelo conector — o painel indica isso.</li></ol>
      <p class="small muted">Documentação oficial: <a href="https://developer.ui.com/network/v10.4.57/gettingstarted" target="_blank">Network API</a> · <a href="https://developer.ui.com/site-manager/v1.0.0/gettingstarted" target="_blank">Site Manager API</a></p>
      <h3 class="mt">O que o painel pode alterar</h3><ul class="small"><li>Modo/categorias do IPS, bloqueio de anúncios, TOR/torrent, UPnP (API clássica)</li><li>Isolamento de redes, DHCP Guarding, isolamento de clientes WiFi</li><li>Criar/ativar/desativar/excluir políticas de firewall, ativar log</li><li>Bloquear/desbloquear clientes, reiniciar dispositivos</li></ul><p class="small muted">Toda alteração pede confirmação. Nada é alterado automaticamente.</p>
    </div>
  </div>`;
  const syncMode = () => { const m = $('#cfMode').value; $('#fHost').classList.toggle('hidden', m !== 'local'); $('#fConsole').classList.toggle('hidden', m !== 'cloud'); };
  syncMode(); $('#cfMode').addEventListener('change', syncMode);
  const body = () => ({ mode: $('#cfMode').value, host: $('#cfHost').value, console_id: $('#cfConsole').value, api_key: $('#cfKey').value || undefined, site_id: $('#cfSite').value, verify_ssl: $('#cfSsl').checked });
  $('#cfTest').addEventListener('click', async () => { const r = $('#cfResult'); r.innerHTML = '<span class="muted">Testando…</span>'; try { const t = await api('/api/config/test', { method: 'POST', body: body() }); r.innerHTML = `<div class="alert ok">Conectado! UniFi Network ${esc(t.applicationVersion)} · site "${esc(t.site.name)}" · Integration API: ${esc(t.integrationBase)} · API clássica: ${t.classicApi ? 'disponível' : 'indisponível (logs/IPS não serão exibidos)'}</div>`; } catch (e) { r.innerHTML = `<div class="alert">Falha: ${esc(e.message)}${e.data?.unifi ? '<br><span class="small mono">' + esc(JSON.stringify(e.data.unifi)).slice(0, 400) + '</span>' : ''}</div>`; } });
  $('#cfSave').addEventListener('click', async () => { try { await api('/api/config', { method: 'POST', body: body() }); state.cache = {}; showAlert('Configuração salva.', 'ok'); await checkConn(); go('overview'); } catch (e) { showAlert(e.message); } });
};

// ------------------------------------------------------------------- boot
(async () => {
  await checkConn();
  const h = location.hash.replace('#', '');
  go(VIEWS[h] ? h : (state.conn ? 'overview' : 'settings'));
})();
