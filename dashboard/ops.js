/* DarkWatch AI - intel source configuration, ad-hoc search, onion guide,
   natural-language tasks (missions) and the DarkWatch AI chat helpers.
   Loaded after the main dashboard script; uses its helpers ($, api, post, esc …). */
"use strict";

const SRC_ICON = { hibp: '🔑', intelx: '🗄', ransomware: '☠', ahmia: '🧅', onionsearch: '🔎', hudsonrock: '🦠', leakcheck: '🔓',
  dehashed: '🗝', crtsh: '📜', urlscan: '🎣', psbdmp: '📋', leakix: '🚪', shodan: '🛰', github: '🐙' };
const CAT_LABEL = { darkweb: 'Dark web', breach: 'Breach', infostealer: 'Infostealer', leak: 'Leak', phishing: 'Phishing', exposure: 'Exposure', custom: 'Custom API' };
const ops = { sources: [], enrich: [], cat: '' };

// ------------------------------------------------------------- examples
const OPS_EXAMPLES = [
  ['Tüm kaynaklarda ara', 'acme.com ve ceo@acme.com için tüm kaynaklarda sızıntı ara'],
  ['Onion siteleri bul', 'Ahmia ve onion arama motorlarında "Acme Corp" geçen siteleri bul, izlemeye değer olanları hedef olarak öner'],
  ['Günlük izleme', 'Her gün ransomware sızıntı sitelerinde ve infostealer kayıtlarında acme.com için kontrol et'],
  ['Phishing', 'acme.com taklidi olan yeni alan adlarını (sertifika ve urlscan) kontrol et'],
  ['Crawl', 'Hedef listesini göster ve en son taranmayan hedefi tara'],
  ['English', 'Search all sources for leaked credentials of example.org and summarise what is new'],
];
function opsExamples(boxSel, inputSel) {
  const box = $(boxSel); if (!box) return;
  box.innerHTML = OPS_EXAMPLES.map(([l, t], i) => `<span class="chip" data-ex="${i}" title="${esc(t)}">${esc(l)}</span>`).join('');
  $$(boxSel + ' [data-ex]').forEach(c => c.addEventListener('click', () => { $(inputSel).value = OPS_EXAMPLES[+c.dataset.ex][1]; $(inputSel).focus(); }));
}
function opsWelcome() {
  return `<div class="empty" style="text-align:left;max-width:720px;margin:20px auto"><div class="big">Talk to DarkWatch AI</div>
    <div class="small muted" style="margin:6px 0 12px">Write what you need in plain language — DarkWatch AI searches the intel sources and onion search engines, checks what was already collected, crawls approved targets and can turn the request into a recurring monitoring mission.</div>
    <div style="display:flex;flex-direction:column;gap:6px">${OPS_EXAMPLES.map(([, t], i) => `<button class="chip-q" data-wex="${i}">${esc(t)}</button>`).join('')}</div></div>`;
}
document.addEventListener('click', e => { const b = e.target.closest('[data-wex]'); if (b) { $('#an-input').value = OPS_EXAMPLES[+b.dataset.wex][1]; $('#an-input').focus(); } });

// ------------------------------------------------------------- sources
async function loadSources() {
  const res = await api('/sources'); const s = state.status || await api('/status');
  ops.sources = res.sources; ops.enrich = res.enrichment_fields || [];
  const sel = $('#sq-src'); const cur = sel.value;
  sel.innerHTML = `<option value="">All configured sources</option><option value="ahmia,onionsearch">Onion search (Ahmia + engines)</option>` +
    res.sources.map(x => `<option value="${esc(x.name)}" ${x.enabled ? '' : 'disabled'}>${esc(x.label)}${x.enabled ? '' : ' (not configured)'}</option>`).join('');
  sel.value = cur;
  renderSourceCards();
  $('#src-feeds').innerHTML = `<div class="kv"><div>CISA KEV</div><div>Actively exploited CVEs — CVE indicators get the <span class="tag">kev-exploited</span> tag</div><div>Feodo Tracker</div><div>Botnet C2 IPs — matches get <span class="tag">feodo-c2</span></div>
    <div>Lookups</div><div>${s.enrichment.length ? s.enrichment.map(x => `<span class="tag ok">${esc(x)}</span>`).join('') : '<span class="dim">none configured — press “Configure keys” (VirusTotal, AbuseIPDB, OTX, ThreatFox, GreyNoise)</span>'}</div><div>MISP</div><div>${s.misp ? '<span class="tag ok">connected</span>' : '<span class="dim">not configured</span>'}</div></div>`;
  $('#src-history').innerHTML = res.history.length ? `<table>${res.history.map(h => `<tr><td class="small">${esc(h.source)}</td><td>${statusTag(h.status)}</td><td class="small">${h.findings} findings · ${h.alerts} alerts</td><td class="small dim">${ago(h.started)}</td></tr>${h.error ? `<tr><td colspan="4" class="small" style="color:var(--bad)">${esc(h.error.slice(0, 220))}</td></tr>` : ''}`).join('')}</table>` : '<div class="dim small">No runs yet</div>';
  if (!$('#onion-guide').dataset.done) renderOnionGuide(false);
}
function renderSourceCards() {
  const list = ops.sources.filter(x => !ops.cat || x.category === ops.cat);
  $('#src-cards').innerHTML = list.map(x => {
    const st = x.enabled ? '<span class="tag ok">enabled</span>' : `<span class="tag ${x.needs_key ? 'warn' : ''}">${x.needs_key ? 'needs API key' : 'off'}</span>`;
    const lr = x.last_run ? `Last run ${ago(x.last_run.started)} · ${esc(x.last_run.status)} · ${x.last_run.findings} findings · ${x.last_run.alerts} new alerts${x.last_run.error ? `<div style="color:var(--bad);margin-top:3px">${esc(x.last_run.error.slice(0, 300))}</div>` : ''}` : 'Never run';
    return `<div class="card src"><h3><span style="font-size:18px">${SRC_ICON[x.name] || (x.custom ? '🔌' : '•')}</span> ${esc(x.label)}<span class="right">${st}</span></h3>
      <div><span class="tag">${esc(CAT_LABEL[x.category] || x.category)}</span>${x.via_tor ? '<span class="tag acc">Tor</span>' : ''}${(x.kinds || []).map(k => `<span class="tag">${esc(k)}</span>`).join('')}</div>
      <div class="small muted">${esc(x.description)}</div>
      <div class="small dim">${lr}</div>
      <div style="display:flex;gap:6px;flex-wrap:wrap"><button class="sm ${x.enabled ? '' : 'primary'}" data-scfg="${esc(x.name)}">⚙ Configure</button><button class="sm" data-srun="${esc(x.name)}" ${x.enabled ? '' : 'disabled'}>Run now</button><button class="sm" data-stest="${esc(x.name)}" ${x.enabled ? '' : 'disabled'}>Test</button></div></div>`;
  }).join('') || empty('No sources in this category');
  $$('[data-srun]').forEach(b => b.addEventListener('click', async () => { try { await post(`/sources/${encodeURIComponent(b.dataset.srun)}/run`); toast(b.dataset.srun + ' started — results appear in Alerts', 'ok'); setTimeout(loadSources, 5000); } catch (e) { fail(e); } }));
  $$('[data-stest]').forEach(b => b.addEventListener('click', () => testSource(b.dataset.stest, b)));
  $$('[data-scfg]').forEach(b => b.addEventListener('click', () => sourceModal(ops.sources.find(x => x.name === b.dataset.scfg))));
}
async function testSource(name, btn) {
  if (btn) { btn.disabled = true; btn.textContent = 'Testing…'; }
  try { const r = await post(`/sources/${encodeURIComponent(name)}/test`);
    if (r.ok) toast(`${name}: OK ${Object.entries(r).filter(([k]) => k !== 'ok' && k !== 'sample').map(([k, v]) => `${k}=${v}`).join(' ')}`, 'ok');
    else toast(`${name}: ${r.error}`, 'err');
  } catch (e) { fail(e); } finally { if (btn) { btn.disabled = false; btn.textContent = 'Test'; } }
}
function fieldInput(f) {
  const id = 'cf-' + f.key; const v = f.value;
  if (f.secret) return `<div><label>${esc(f.label)} ${v && v.set ? `<span class="tag ok">set ${esc(v.hint)}</span>` : '<span class="tag">not set</span>'}</label><div class="toolbar" style="margin:0"><input id="${id}" type="password" autocomplete="off" class="grow" placeholder="${v && v.set ? 'leave empty to keep the saved key' : 'paste the key'}">${v && v.set ? `<button class="sm" data-clear="${esc(f.key)}">Remove</button>` : ''}</div>${f.help ? `<div class="hint">${esc(f.help)}</div>` : ''}</div>`;
  if (f.type === 'bool') return `<div><label style="display:flex;gap:8px;align-items:center"><span class="switch"><input type="checkbox" id="${id}" ${v ? 'checked' : ''}><span></span></span>${esc(f.label)}</label>${f.help ? `<div class="hint">${esc(f.help)}</div>` : ''}</div>`;
  if (f.type === 'select') return `<div><label>${esc(f.label)}</label><select id="${id}">${f.options.map(o => `<option ${o === v ? 'selected' : ''}>${esc(o)}</option>`).join('')}</select>${f.help ? `<div class="hint">${esc(f.help)}</div>` : ''}</div>`;
  if (f.type === 'text') return `<div><label>${esc(f.label)}</label><textarea id="${id}" rows="6" class="mono" style="font-size:12px">${esc(String(v || '').replace(/\\n/g, '\n'))}</textarea>${f.help ? `<div class="hint">${esc(f.help)}</div>` : ''}</div>`;
  return `<div><label>${esc(f.label)}</label><input id="${id}" ${f.type === 'int' ? 'type="number"' : ''} value="${esc(v ?? '')}">${f.help ? `<div class="hint">${esc(f.help)}</div>` : ''}</div>`;
}
function collectFields(fields) {
  const out = {};
  for (const f of fields) {
    const el = $('#cf-' + f.key); if (!el) continue;
    if (f.secret) { if (el.value.trim()) out[f.key] = el.value.trim(); if (el.dataset.clear) out[f.key] = ''; }
    else if (f.type === 'bool') out[f.key] = el.checked;
    else if (f.type === 'int') out[f.key] = +el.value;
    else out[f.key] = el.value;
  }
  return out;
}
function bindClear() { $$('[data-clear]').forEach(b => b.addEventListener('click', () => { const i = $('#cf-' + b.dataset.clear); i.value = ''; i.dataset.clear = '1'; i.placeholder = 'will be removed on save'; b.disabled = true; })); }
function sourceModal(x) {
  if (!x) return;
  if (x.custom) return customModal(x.config);
  const toggle = x.enable_key ? `<div><label style="display:flex;gap:8px;align-items:center"><span class="switch"><input type="checkbox" id="cf-enable" ${x.enabled ? 'checked' : ''}><span></span></span>Enabled</label></div>` : '';
  const torNote = x.via_tor ? `<div class="notice info" style="margin:0">Uses the Tor network. Connect Tor under <b>System</b> first.${x.name === 'ahmia' ? ' With connection “auto” Ahmia falls back to its clearnet mirror ahmia.fi when Tor is down.' : ''}</div>` : '';
  modal(`${SRC_ICON[x.name] || '⚙'} ${x.label}`, `<div class="form"><div class="small muted">${esc(x.description)}</div>${torNote}${toggle}${x.fields.map(fieldInput).join('')}
    ${x.signup ? `<div class="hint">API key / documentation: <a href="${esc(x.signup)}" target="_blank" rel="noopener noreferrer">${esc(x.signup)}</a></div>` : ''}
    <div class="hint">Queries: ${(x.kinds || []).map(esc).join(', ') || '-'} watch terms. Keys are stored only on this machine.</div></div>`,
    [['Cancel', closeModal], ['Save & test', () => saveSource(x, true)], ['Save', () => saveSource(x, false), 'primary']]);
  bindClear();
}
async function saveSource(x, test) {
  const values = collectFields(x.fields);
  if (x.enable_key) values[x.enable_key] = $('#cf-enable').checked;
  if (values.ONION_SEARCH_ENGINES !== undefined) values.ONION_SEARCH_ENGINES = values.ONION_SEARCH_ENGINES.trim().replace(/\r/g, '');
  try { await api('/sources/settings', { method: 'PUT', body: JSON.stringify({ values }) }); toast(x.label + ' saved', 'ok'); closeModal(); await loadSources(); loadStatus(true);
    if (test) testSource(x.name); } catch (e) { fail(e); }
}
$('#btn-enrich-cfg').addEventListener('click', () => {
  modal('Enrichment & general settings', `<div class="form">${ops.enrich.map(fieldInput).join('')}<div class="hint">${ops.enrich.filter(f => f.signup).map(f => `<a href="${esc(f.signup)}" target="_blank" rel="noopener noreferrer">${esc(f.label.split(' ')[0])}</a>`).join(' · ')}</div></div>`,
    [['Cancel', closeModal], ['Save', async () => { try { await api('/sources/settings', { method: 'PUT', body: JSON.stringify({ values: collectFields(ops.enrich) }) }); toast('Saved', 'ok'); closeModal(); await loadStatus(true); loadSources(); } catch (e) { fail(e); } }, 'primary']]);
  bindClear();
});
function customModal(c) {
  c = c || { method: 'GET', kinds: ['domain', 'email', 'brand'], severity: 'medium', enabled: true };
  const k = ['domain', 'email', 'brand', 'keyword', 'ip', 'crypto'];
  modal(c.name ? 'Custom API: ' + (c.label || c.name) : 'Add a custom API source', `<div class="form">
    <div class="notice info" style="margin:0">Connect any JSON API that can be searched with a term — e.g. a commercial dark-web / leak service your company already uses. <span class="mono">{term}</span> is replaced by each watch term, <span class="mono">{key}</span> by the API key.</div>
    <div class="row2"><div><label>Name (id)</label><input id="cu-name" value="${esc(c.name || '')}" ${c.name ? 'disabled' : ''} placeholder="corp-leaks"></div><div><label>Label</label><input id="cu-label" value="${esc(c.label || '')}" placeholder="Corporate leak API"></div></div>
    <div class="row2"><div style="grid-column:span 2"><label>URL</label><input id="cu-url" value="${esc(c.url || '')}" placeholder="https://api.vendor.com/v1/search?q={term}"></div></div>
    <div class="row3"><div><label>Method</label><select id="cu-method"><option ${c.method === 'GET' ? 'selected' : ''}>GET</option><option ${c.method === 'POST' ? 'selected' : ''}>POST</option></select></div><div><label>Key header</label><input id="cu-hname" value="${esc(c.header_name || '')}" placeholder="X-API-Key / Authorization"></div><div><label>Header prefix</label><input id="cu-hpre" value="${esc(c.header_prefix || '')}" placeholder="Bearer "></div></div>
    <div><label>API key ${c.api_key_set ? '<span class="tag ok">set</span>' : ''}</label><input id="cu-key" type="password" autocomplete="off" placeholder="${c.api_key_set ? 'leave empty to keep' : ''}"></div>
    <div><label>POST body (JSON, optional)</label><textarea id="cu-body" class="mono" rows="3" placeholder='{"query": "{term}", "limit": 50}'>${esc(c.body || '')}</textarea></div>
    <div class="row3"><div><label>Results path</label><input id="cu-path" value="${esc(c.results_path || '')}" placeholder="data.items"></div><div><label>Title field</label><input id="cu-title" value="${esc(c.title_field || '')}" placeholder="name"></div><div><label>URL field</label><input id="cu-urlf" value="${esc(c.url_field || '')}" placeholder="link"></div></div>
    <div class="row3"><div><label>ID field</label><input id="cu-id" value="${esc(c.id_field || '')}" placeholder="id"></div><div><label>Date field</label><input id="cu-date" value="${esc(c.date_field || '')}" placeholder="published"></div><div><label>Severity</label><select id="cu-sev">${['low', 'medium', 'high', 'critical'].map(s => `<option ${s === c.severity ? 'selected' : ''}>${s}</option>`).join('')}</select></div></div>
    <div><label>Query these watch-term kinds</label><div style="display:flex;gap:12px;flex-wrap:wrap">${k.map(x => `<label style="display:flex;gap:5px;align-items:center;margin:0"><input type="checkbox" data-ck="${x}" ${(c.kinds || []).includes(x) ? 'checked' : ''}>${x}</label>`).join('')}</div></div>
    <label style="display:flex;gap:8px;align-items:center"><span class="switch"><input type="checkbox" id="cu-en" ${c.enabled !== false ? 'checked' : ''}><span></span></span>Enabled</label></div>`,
    [...(c.name ? [['Delete', async () => { try { await del('/sources/custom/' + encodeURIComponent(c.name)); toast('Deleted', 'ok'); closeModal(); loadSources(); } catch (e) { fail(e); } }, 'danger']] : []),
     ['Cancel', closeModal], ['Save', async () => {
      const body = { name: (c.name || $('#cu-name').value).trim().toLowerCase(), label: $('#cu-label').value, url: $('#cu-url').value.trim(), method: $('#cu-method').value,
        header_name: $('#cu-hname').value.trim(), header_prefix: $('#cu-hpre').value, api_key: $('#cu-key').value, body: $('#cu-body').value.trim(),
        results_path: $('#cu-path').value.trim(), title_field: $('#cu-title').value.trim(), url_field: $('#cu-urlf').value.trim(), id_field: $('#cu-id').value.trim(),
        date_field: $('#cu-date').value.trim(), severity: $('#cu-sev').value, enabled: $('#cu-en').checked, kinds: $$('[data-ck]').filter(x => x.checked).map(x => x.dataset.ck) };
      try { const r = await post('/sources/custom', body); toast('Saved ' + r.name, 'ok'); closeModal(); await loadSources(); testSource(r.name); } catch (e) { fail(e); } }, 'primary']]);
}
$('#btn-src-custom').addEventListener('click', () => customModal(null));
chips('#src-cat', v => { ops.cat = v; renderSourceCards(); });

// ------------------------------------------------------------- ad-hoc search
function splitTerms(t) { const out = []; t.replace(/"([^"]+)"|'([^']+)'|([^,;\n]+)/g, (m, a, b, c) => { const v = (a || b || c || '').trim(); if (v) out.push(v); return m; }); return out.slice(0, 10); }
async function runSearch(terms, sources, save) {
  const box = $('#sq-out');
  if (!terms.length) { toast('Enter at least one term'); return; }
  box.innerHTML = `<div class="progress"><span></span></div><div class="small dim" style="margin-top:6px">Searching ${terms.map(esc).join(', ')} … onion searches through Tor can take a minute.</div>`;
  $('#btn-sq').disabled = true;
  try {
    const r = await post('/sources/query', { terms, sources, save });
    box.innerHTML = `<div class="small dim" style="margin-bottom:8px">Terms: ${r.terms.map(t => `<span class="tag">${esc(t.kind)}: ${esc(t.value)}</span>`).join('')}${save ? ' · stored as alerts' : ''}</div>` + r.results.map(x => `
      <details class="tcall" ${x.findings.length ? 'open' : ''}><summary><b>${esc(x.label || x.source)}</b> ${statusTag(x.status)} <span class="small dim">${x.findings.length} finding(s)</span>${x.error ? `<span class="small" style="color:${x.status === 'failed' ? 'var(--bad)' : 'var(--dim)'}">${esc(x.error.slice(0, 200))}</span>` : ''}</summary>
      <div class="tb">${x.findings.map(f => findingHtml(f)).join('') || '<div class="small dim">Nothing found.</div>'}</div></details>`).join('');
    bindTargetButtons(box);
  } catch (e) { box.innerHTML = `<div class="small" style="color:var(--bad)">${esc(e.message)}</div>`; }
  finally { $('#btn-sq').disabled = false; }
}
function findingHtml(f) {
  const results = (f.extra && f.extra.results) || [];
  const onionRows = results.length ? `<table style="margin-top:6px">${results.slice(0, 30).map(o => `<tr><td class="mono small">${esc(defang(o.onion))}</td><td class="small">${esc(o.title || '')}<div class="dim">${esc((o.snippet || '').slice(0, 160))}</div></td><td class="small dim">${esc((o.engines || []).join(', '))}</td><td><button class="sm" data-addt="${esc(o.url || ('http://' + o.onion + '/'))}" data-goal="${esc(f.term || '')}">+ Target</button></td></tr>`).join('')}</table>` : '';
  return `<div style="padding:8px 0;border-bottom:1px solid var(--line)"><div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">${sev(f.severity)}<b>${esc(f.title)}</b>${f.url ? `<span class="small dim mono">${esc(defang(f.url)).slice(0, 90)}</span>` : ''}</div>
    ${results.length ? onionRows : `<div class="small muted" style="white-space:pre-wrap;margin-top:4px">${esc((f.description || '').slice(0, 700))}</div>`}</div>`;
}
function bindTargetButtons(root) {
  $$('[data-addt]', root).forEach(b => b.addEventListener('click', async () => {
    try { await post('/tasks', { kind: 'add_target', title: 'Monitor ' + defang(b.dataset.addt).slice(0, 80), reason: 'Found by onion search', payload: { url: b.dataset.addt, mode: 'smart', goal: b.dataset.goal ? 'Find mentions of ' + b.dataset.goal : '' } });
      toast('Proposed as target — approve it in AI Tasks', 'ok'); b.disabled = true; b.textContent = 'proposed'; loadBadges(); } catch (e) { fail(e); }
  }));
}
$('#btn-sq').addEventListener('click', () => runSearch(splitTerms($('#sq-terms').value), ($('#sq-src').value || '').split(',').filter(Boolean), $('#sq-save').checked));
$('#sq-terms').addEventListener('keydown', e => { if (e.key === 'Enter') $('#btn-sq').click(); });

// ------------------------------------------------------------- onion guide
const ONION_EXAMPLE_QUERIES = [
  ['"acme.com"', 'Your domain in quotes — leak posts, combolists, forum threads'],
  ['"@acme.com" password', 'E-mail addresses of your domain together with credentials'],
  ['Acme Corp database', 'Database sale / dump announcements naming the company'],
  ['Acme ransomware', 'Leak-site posts and negotiations about the company'],
  ['acme vpn access', 'Initial-access broker offers (VPN, RDP, Citrix)'],
  ['acme combolist', 'Credential lists (often stealer logs)'],
  ['acme source code', 'Leaked repositories / internal documents'],
  ['"Acme" invoice', 'Leaked business documents'],
];
const ONION_REFERENCE = [
  ['Ahmia (search engine)', 'juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion'],
  ['Tor Project', '2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion'],
  ['DuckDuckGo', 'duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion'],
  ['BBC News', 'bbcnewsd73hkzno2ini43t4gblxvycyac5aw4gnv7t2rccijh7745uqd.onion'],
  ['ProPublica', 'p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcobkmyqsiofyeznfu5uqd.onion'],
  ['The New York Times', 'ej3kv4ebuugcmuwxctx5ic7zxh73rnxt42soi3tdneu2c2em55thufqd.onion'],
  ['Proton Mail', 'protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion'],
];
function renderOnionGuide(open) {
  const g = $('#onion-guide'); g.dataset.done = '1';
  g.innerHTML = `<details ${open ? 'open' : ''}><summary style="cursor:pointer"><b>🧅 Onion sites — how searching works, example queries and test addresses</b> <span class="small dim">· Onion siteleri: nasıl çalışır, örnek aramalar</span></summary>
    <div class="grid cols-11" style="margin-top:12px">
      <div><div class="section-t">What is an onion site?</div>
        <div class="small muted" style="line-height:1.6">Onion (hidden) services are only reachable through Tor. A v3 address has <b>56 characters</b> (a–z, 2–7) + <span class="mono">.onion</span> and a built-in checksum — DarkWatch AI verifies it, so random look-alike strings are ignored. Addresses change often and many sites are offline; search engines are the usual way to discover them.<br><br>
        <b>How DarkWatch AI searches:</b> 1) <b>Ahmia</b> (filters illegal abuse content; via Tor, ahmia.fi as fallback), 2) <b>more onion engines</b> (Torch, Haystak, Tor66, Excavator, OnionLand — enable “Onion search engines”), 3) found sites become <b>proposed targets</b> — nothing is crawled until you approve, 4) approved targets are crawled in standard / smart / agent mode and matched against your watchlist.<br><br>
        <b>Safety:</b> passive monitoring only — never log in, register, buy or contact sellers. Content that matches the safety block list is discarded unseen. Results are untrusted data.<br><br>
        <b>Türkçe özet:</b> Onion siteleri yalnızca Tor ile açılır. Önce Sistem → Tor ile bağlanın, sonra Ahmia / onion arama motorlarında marka, alan adı veya e-posta arayın. Bulunan siteler <b>önerilen hedef</b> olur; onayladığınızda taranır. Hiçbir siteye giriş yapmayın, satın almayın, iletişime geçmeyin.</div></div>
      <div><div class="section-t">Example searches (click to run on Ahmia + engines)</div>
        <table>${ONION_EXAMPLE_QUERIES.map(([q, w]) => `<tr><td><button class="chip-q mono" data-oq="${esc(q)}">${esc(q)}</button></td><td class="small dim">${esc(w)}</td></tr>`).join('')}</table>
        <div class="hint">Replace <span class="mono">acme</span> with your own brand. Quotes keep phrases together. Short or generic words return noise — prefer domains and distinctive brand names.</div>
        <div class="section-t" style="margin-top:12px">Legitimate onion sites to test the Tor connection</div>
        <table>${ONION_REFERENCE.map(([n, h]) => `<tr><td class="small">${esc(n)}</td><td class="mono small" style="word-break:break-all">${esc(h)}</td><td><button class="sm" data-ocopy="${esc(h)}">Copy</button></td></tr>`).join('')}</table>
        <div class="hint">Add one under Targets with depth 0 to check that crawling through Tor works end to end.</div></div>
    </div></details>`;
  $$('[data-oq]', g).forEach(b => b.addEventListener('click', () => { $('#sq-terms').value = b.dataset.oq; $('#sq-src').value = 'ahmia,onionsearch'; window.scrollTo({ top: 0, behavior: 'smooth' }); $('#btn-sq').click(); }));
  $$('[data-ocopy]', g).forEach(b => b.addEventListener('click', () => { try { navigator.clipboard.writeText('http://' + b.dataset.ocopy + '/'); toast('Copied', 'ok'); } catch (e) { toast('http://' + b.dataset.ocopy + '/'); } }));
}
$('#btn-src-guide').addEventListener('click', () => { renderOnionGuide(true); $('#onion-guide').scrollIntoView({ behavior: 'smooth' }); });

// ------------------------------------------------------------- tasks & missions
const EVERY_TXT = m => !m ? 'once' : m % 10080 === 0 ? `every ${m / 10080 > 1 ? m / 10080 + ' weeks' : 'week'}` : m % 1440 === 0 ? `every ${m / 1440 > 1 ? m / 1440 + ' days' : 'day'}` : m % 60 === 0 ? `every ${m / 60}h` : `every ${m} min`;
async function loadTasks() {
  const isM = state.tasks.status === 'mission';
  const res = await api(isM ? '/tasks?kind=mission' : '/tasks?status=' + encodeURIComponent(state.tasks.status)); loadBadges();
  const auto = (state.status && state.status.config.auto_approve) || [];
  $('#tk-auto').textContent = auto.length ? 'Auto-approved kinds: ' + auto.join(', ') + ' · new targets always need you' : 'Every task needs approval';
  $('#tk-list').innerHTML = res.items.length ? res.items.map(taskHtml).join('')
    : empty(isM ? 'No missions yet' : state.tasks.status === 'proposed' ? 'No proposals waiting' : 'Nothing here',
      isM ? 'Write a task above and choose a schedule — e.g. “Her gün acme.com için tüm kaynaklarda kontrol et”.' : 'Write a task above, or wait for the planner: after each crawl it suggests recrawls, new targets, watch terms and pages to review.');
  $$('[data-tapprove]').forEach(b => b.addEventListener('click', async () => { try { const r = await post(`/tasks/${b.dataset.tapprove}/approve`); toast('Task ' + r.status + (r.session_id ? ' · session #' + r.session_id : ''), 'ok'); loadTasks(); } catch (e) { fail(e); } }));
  $$('[data-treject]').forEach(b => b.addEventListener('click', async () => { try { await post(`/tasks/${b.dataset.treject}/reject`); toast('Task stopped'); loadTasks(); } catch (e) { fail(e); } }));
  $$('[data-mrun]').forEach(b => b.addEventListener('click', async () => { try { const r = await post(`/tasks/${b.dataset.mrun}/run`); toast(r.message || 'started', r.session_id ? 'ok' : 'err'); loadTasks(); } catch (e) { fail(e); } }));
  $$('[data-msess]').forEach(b => b.addEventListener('click', e => { e.preventDefault(); an.sid = +b.dataset.msess; go('analyst'); }));
}
function taskHtml(t) {
  const p = t.payload || {}; const m = t.kind === 'mission';
  const acts = t.status === 'proposed' ? `<button class="sm primary" data-tapprove="${t.id}">Approve</button><button class="sm" data-treject="${t.id}">Reject</button>`
    : m ? `<button class="sm" data-mrun="${t.id}">${t.status === 'approved' ? 'Run now' : 'Run again'}</button>${t.status === 'approved' ? `<button class="sm" data-treject="${t.id}">Stop</button>` : ''}`
    : t.status === 'approved' ? `<button class="sm" data-treject="${t.id}">Cancel</button>` : '';
  return `<div class="task"><div class="ic">${m ? '🎯' : TASK_IC[t.kind] || '•'}</div>
    <div class="body"><div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap"><b>${esc(t.title)}</b><span class="tag ${m ? 'acc' : ''}">${esc(m ? 'mission · ' + EVERY_TXT(p.interval_min) : t.kind.replace('_', ' '))}</span><span class="tag ${t.priority === 'high' ? 'bad' : ''}">${esc(t.priority)}</span><span class="tag ${t.source === 'ai' ? 'acc' : ''}">${t.source === 'ai' ? '✦ AI' : esc(t.source)}</span>${t.status !== 'proposed' ? statusTag(t.status === 'approved' && m ? 'running' : t.status) : ''}</div>
      ${t.reason && !m ? `<div class="muted small" style="margin-top:4px">${esc(t.reason)}</div>` : ''}
      <div class="small ${m ? '' : 'dim mono'}" style="margin-top:4px;word-break:break-word">${esc(m ? p.instruction : taskPayload(t))}</div>
      <div class="small dim" style="margin-top:4px">${ago(t.created_at)}${m && p.runs ? ` · ${p.runs} run(s)` : ''}${t.due_at ? ' · next ' + ago(t.due_at) : ''}${t.result ? ' · ' + esc(t.result) : ''}${p.last_session_id ? ` · <a href="#" data-msess="${p.last_session_id}">open last run →</a>` : ''}${t.run_id ? ` · from <a href="#" data-run="${t.run_id}">run #${t.run_id}</a>` : ''}</div></div>
    ${acts ? `<div class="acts">${acts}</div>` : ''}</div>`;
}
$('#btn-ms').addEventListener('click', async () => {
  const text = $('#ms-text').value.trim(); if (text.length < 5) { toast('Describe the task first'); return; }
  const every = $('#ms-every').value; $('#btn-ms').disabled = true;
  try { const r = await post('/missions', { instruction: text, every, run_now: true });
    $('#ms-text').value = ''; toast(every === 'once' ? 'Started — DarkWatch AI is working on it' : 'Mission created and first run started', 'ok');
    if (r.session_id) { an.sid = r.session_id; go('analyst'); } else loadTasks();
  } catch (e) { fail(e); } finally { $('#btn-ms').disabled = false; }
});
$('#ms-text').addEventListener('keydown', e => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) $('#btn-ms').click(); });
opsExamples('#ms-ex', '#ms-text');
