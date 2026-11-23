/* DarkWatch AI - intelligence views: organizations (tenants), threat actors,
   entity graph, evidence; alert drawer panel and overview card.
   Loaded before the main dashboard script: everything here runs lazily and
   uses the dashboard helpers (api, esc, drawer, modal, ...) at call time. */
"use strict";
(function () {
  const CLASS_LABEL = {};
  const TYPE_COLOR = { org: 'var(--accent)', asset: 'var(--low)', alert: 'var(--high)', site: '#5d6578',
    indicator: '#2fbfa8', actor: 'var(--critical)', handle: 'var(--warn)' };
  const ASSET_TYPES = [['domain', 'Domain'], ['brand', 'Brand / company'], ['employee_email', 'Employee e-mail'],
    ['email', 'E-mail (shared mailbox)'], ['executive', 'Executive name'], ['keyword', 'Keyword'], ['ip', 'IP address'],
    ['crypto', 'Crypto wallet'], ['regex', 'Regex']];
  const ui = { actors: { q: '', kind: '', offset: 0 }, ev: { offset: 0 }, graph: { center: '', depth: 2 } };

  const lvl = s => s >= 75 ? 'critical' : s >= 50 ? 'high' : s >= 25 ? 'medium' : 'low';
  const riskBadge = (score, big) => {
    const v = Math.round(score || 0), l = lvl(v);
    return `<span class="sev ${l}" title="risk ${v}/100" style="${big ? 'font-size:15px;padding:3px 10px' : ''}">${v}</span>`;
  };
  const riskBar = score => `<div class="bar" style="height:8px;margin-top:6px"><span style="width:${Math.min(100, score || 0)}%;background:var(--${lvl(score || 0)})"></span></div>`;
  const classTag = tc => tc ? `<span class="tag acc" title="${esc(CLASS_LABEL[tc] || tc)}">${esc((tc || '').replace(/_/g, ' '))}</span>` : '';
  const factorsHtml = fs => (fs || []).length ? `<div class="kv">${fs.map(f => `<div>${f.points > 0 ? '+' : ''}${f.points}</div><div>${f.alert_id ? `<a href="#" data-alert="${f.alert_id}">${esc(f.factor)}</a>` : esc(f.factor)}</div>`).join('')}</div>` : '<div class="dim small">No contributing factors.</div>';
  const short = h => h ? h.slice(0, 12) + '…' : '';

  async function download(path, filename) {
    const headers = {}; if (key) headers['X-API-Key'] = key;
    const r = await fetch(API + path, { headers });
    if (!r.ok) throw new Error('download failed: HTTP ' + r.status);
    const url = URL.createObjectURL(await r.blob());
    const a = document.createElement('a'); a.href = url; a.download = filename; document.body.appendChild(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1000);
  }

  // ---------------------------------------------------------------- overview
  async function overview() {
    const o = await api('/intel/overview');
    Object.entries(o.threat_classes || {}).forEach(([k, v]) => { CLASS_LABEL[k] = v.label; });
    const cls = Object.entries(o.open_by_class || {}).sort((a, b) => b[1] - a[1]);
    const tot = cls.reduce((a, [, v]) => a + v, 0) || 1;
    $('#ov-intel').innerHTML = `<div class="grid cols-3">
      <div class="card"><h3>Organization risk <a class="right small" data-goto="orgs">All →</a></h3>${o.top_orgs.length ? o.top_orgs.map(g =>
        `<div class="item click" data-org="${g.id}" style="padding:6px 0;cursor:pointer"><div style="display:flex;gap:8px;align-items:center">${riskBadge(g.risk_score)}<b class="trunc">${esc(g.name)}</b></div>${riskBar(g.risk_score)}</div>`).join('')
        : empty('No organizations', '<a data-goto="orgs">Add your company →</a>')}</div>
      <div class="card"><h3>Open alerts by threat class</h3>${cls.length ? cls.map(([k, v]) =>
        `<div style="display:flex;gap:8px;align-items:center;margin:6px 0"><span class="small" style="width:120px">${esc(k.replace(/_/g, ' '))}</span><div class="bar" style="flex:1"><span style="width:${100 * v / tot}%;background:var(--accent)"></span></div><span class="small dim">${v}</span></div>`).join('')
        : '<div class="dim small">No open alerts</div>'}</div>
      <div class="card"><h3>Threat actors <a class="right small" data-goto="actors">All →</a></h3>${o.top_actors.length ? o.top_actors.map(a =>
        `<div class="item" data-actor="${a.id}" style="padding:6px 0;cursor:pointer"><div style="display:flex;gap:8px;align-items:center">${riskBadge(a.risk_score)}<b class="trunc">${esc(a.name)}</b><span class="tag">${esc(a.kind.replace(/_/g, ' '))}</span></div><div class="small dim">${a.mention_count} mention(s) · ${ago(a.last_seen)}</div></div>`).join('')
        : '<div class="dim small">No actors profiled yet — they appear when forum authors or ransomware groups mention your assets.</div>'}</div></div>`;
  }

  // ---------------------------------------------------------------- organizations
  async function loadOrgs() {
    const orgs = await api('/orgs');
    const root = $('#orgs-root');
    root.innerHTML = `<div class="notice">Each organization is a <b>tenant</b>: its domains, brands, employee e-mails and executives become watch terms. Collection is shared; every tenant only sees the alerts its own assets matched, with its own risk score and an optional tenant API key.</div>
      <div class="toolbar"><span class="grow"></span><button class="primary" id="org-new">+ New organization</button></div>
      <div class="grid cols-3" id="org-cards">${orgs.length ? orgs.map(o => `<div class="card kpi click" data-org="${o.id}">
        <div style="display:flex;align-items:center;gap:10px"><div class="l" style="flex:1">${esc(o.sector || 'organization')}${o.country ? ' · ' + esc(o.country) : ''}</div>${riskBadge(o.risk_score, true)}</div>
        <div class="v" style="font-size:20px">${esc(o.name)}</div>${riskBar(o.risk_score)}
        <div class="s">${o.assets} asset(s) · ${o.open_alerts} open alert(s) · risk ${esc(o.risk_level)}</div></div>`).join('')
        : empty('No organizations yet', 'Create one and add its domains, brands and employee e-mails.')}</div>`;
    $('#org-new').addEventListener('click', orgModal);
  }

  function orgModal() {
    modal('New organization', `<div class="form">
      <div><label>Name</label><input id="o-name" placeholder="ACME Corp"></div>
      <div class="grid cols-2"><div><label>Sector</label><input id="o-sector" placeholder="finance"></div><div><label>Country</label><input id="o-country" placeholder="TR"></div></div>
      <div><label>Domains (one per line)</label><textarea id="o-domains" placeholder="acme.com"></textarea></div>
      <div><label>Brands / product names</label><textarea id="o-brands" placeholder="ACME"></textarea></div>
      <div class="hint">Employee e-mails, executives and other assets can be added after creation (bulk import supported).</div></div>`,
      [['Cancel', closeModal], ['Create', async () => {
        const lines = sel => $(sel).value.split(/[\n,;]/).map(x => x.trim()).filter(Boolean);
        const assets = [...lines('#o-domains').map(v => ({ asset_type: 'domain', value: v })), ...lines('#o-brands').map(v => ({ asset_type: 'brand', value: v }))];
        try {
          const o = await post('/orgs', { name: $('#o-name').value.trim(), sector: $('#o-sector').value.trim(), country: $('#o-country').value.trim(), assets });
          closeModal(); toast('Organization created' + (o.asset_errors.length ? ` (${o.asset_errors.length} asset(s) rejected)` : ''), o.asset_errors.length ? 'err' : 'ok');
          loadOrgs(); openOrg(o.id);
        } catch (e) { fail(e); }
      }, 'primary']]);
  }

  async function openOrg(id) {
    const [o, risk, assets, exp, alerts] = await Promise.all([api('/orgs/' + id), api(`/orgs/${id}/risk`), api(`/orgs/${id}/assets`),
      api(`/orgs/${id}/exposure`), api(`/orgs/${id}/alerts?status=open&limit=15`)]);
    let keys = [];
    try { keys = await api(`/orgs/${id}/keys`); } catch (e) { /* tenant view */ }
    const ind = i => `<div class="small mono" style="margin:3px 0"><a href="#" data-ind="${i.id}">${esc(i.value)}</a> <span class="dim">· seen ${i.seen_count}× · ${ago(i.last_seen)}</span></div>`;
    drawer(`ORGANIZATION · ${o.slug}`, o.name, `
      <div style="display:flex;gap:12px;align-items:center;margin-bottom:8px">${riskBadge(risk.score, true)}<div style="flex:1"><b>Risk ${esc(risk.level)}</b> · ${risk.open_alerts} open alert(s) · ${risk.exposed_credentials} exposed credential(s)${riskBar(risk.score)}</div></div>
      <div class="section-t">Risk factors</div>${factorsHtml(risk.factors)}
      <div class="section-t">Assets (${assets.length})</div>
      <div class="toolbar" style="margin:0 0 8px"><select id="oa-type" style="max-width:170px">${ASSET_TYPES.map(([v, l]) => `<option value="${v}">${l}</option>`).join('')}</select>
        <input id="oa-value" class="grow" placeholder="value (or paste many, one per line)"><button class="sm primary" id="oa-add">Add</button></div>
      <div class="table-wrap"><table>${assets.map(a => `<tr><td><span class="tag">${esc(a.asset_type.replace(/_/g, ' '))}</span></td><td class="mono">${esc(a.value)}</td><td>${sev(a.severity)}</td><td style="text-align:right"><button class="sm danger" data-asset-del="${a.id}">✕</button></td></tr>`).join('') || '<tr><td class="dim small">No assets yet</td></tr>'}</table></div>
      <div class="section-t">Exposure</div>
      <div class="kv"><div>Domains</div><div>${exp.domains.map(esc).join(', ') || '—'}</div>
        <div>Exposed credentials</div><div>${exp.exposed_credentials.length ? exp.exposed_credentials.slice(0, 15).map(ind).join('') : '<span class="dim small">none found</span>'}</div>
        <div>Exposed e-mails</div><div>${exp.exposed_emails.length ? exp.exposed_emails.slice(0, 15).map(ind).join('') : '<span class="dim small">none found</span>'}</div>
        <div>Ransomware listings</div><div>${exp.ransomware_listings.length ? exp.ransomware_listings.map(a => `<div class="small"><a href="#" data-alert="${a.id}">${esc(a.title)}</a></div>`).join('') : '<span class="dim small">none</span>'}</div>
        <div>Threat actors</div><div>${exp.threat_actors.length ? exp.threat_actors.map(a => `<a href="#" data-actor="${a.id}" class="tag bad">${esc(a.name)} · ${a.mentions}</a>`).join(' ') : '<span class="dim small">none</span>'}</div></div>
      <div class="section-t">Open alerts</div><div class="list">${alerts.items.length ? alerts.items.map(a => `<div class="item" data-alert="${a.id}" style="cursor:pointer">${riskBadge(a.risk_score)}<div style="min-width:0;flex:1"><div class="t trunc">${esc(a.title)}</div><div class="small dim">${classTag(a.threat_class)} ${esc(a.source)} · ${ago(a.last_seen)}</div></div></div>`).join('') : '<div class="dim small">No open alerts</div>'}</div>
      ${o.role === 'admin' ? `<div class="section-t">Tenant API keys</div>${keys.length ? keys.map(k => `<div class="small" style="display:flex;gap:8px;align-items:center;margin:4px 0"><span class="mono">${esc(k.prefix)}…</span> ${esc(k.name)} ${k.active ? '<span class="tag ok">active</span>' : '<span class="tag">revoked</span>'} <span class="dim">used ${ago(k.last_used)}</span>${k.active ? `<button class="sm danger" data-key-revoke="${k.id}">Revoke</button>` : ''}</div>`).join('') : '<div class="dim small">No keys. A tenant key only opens /api/orgs/' + id + '/…</div>'}` : ''}`,
      [['Show in graph', () => showGraph('org:' + id)], ...(o.role === 'admin' ? [['+ Tenant API key', () => newKey(id)], ['Delete organization', () => confirmModal('Delete organization', `Delete ${o.name}? Alerts and collected data are kept; only the tenant, its asset links and keys are removed.`, async () => { await del('/orgs/' + id); closeDrawer(); loadOrgs(); })]] : [])]);
    $('#oa-add').addEventListener('click', async () => {
      const v = $('#oa-value').value.trim(); if (!v) return;
      try {
        if (/[\n,;]/.test(v)) { const r = await post(`/orgs/${id}/assets/bulk`, { asset_type: $('#oa-type').value, text: v }); toast(`${r.added} added, ${r.skipped} existing, ${r.errors.length} rejected`, r.errors.length ? 'err' : 'ok'); }
        else { await post(`/orgs/${id}/assets`, { asset_type: $('#oa-type').value, value: v }); toast('Asset added', 'ok'); }
        openOrg(id);
      } catch (e) { fail(e); }
    });
    $('#oa-value').addEventListener('paste', () => setTimeout(() => { const el = $('#oa-value'); if (el.value.includes('\n')) el.value = el.value.replace(/\n/g, ', '); }, 0));
    $$('[data-asset-del]').forEach(b => b.addEventListener('click', async () => { try { await del(`/orgs/${id}/assets/${b.dataset.assetDel}`); openOrg(id); } catch (e) { fail(e); } }));
    $$('[data-key-revoke]').forEach(b => b.addEventListener('click', async () => { try { await del(`/orgs/${id}/keys/${b.dataset.keyRevoke}`); toast('Key revoked', 'ok'); openOrg(id); } catch (e) { fail(e); } }));
  }

  function newKey(id) {
    modal('New tenant API key', `<div class="form"><div><label>Name</label><input id="k-name" placeholder="customer portal"></div></div>`, [['Cancel', closeModal], ['Create', async () => {
      try {
        const k = await post(`/orgs/${id}/keys`, { name: $('#k-name').value.trim() });
        modal('Tenant API key', `<div class="notice">Copy this key now — it is stored hashed and is not shown again.</div><div class="pre mono" style="word-break:break-all">${esc(k.key)}</div><div class="hint">Send it as <span class="mono">X-API-Key</span>. It only opens <span class="mono">/api/orgs/${id}/…</span>.</div>`,
          [['Copy', () => navigator.clipboard.writeText(k.key).then(() => toast('Copied', 'ok'))], ['Done', () => { closeModal(); openOrg(id); }, 'primary']]);
      } catch (e) { fail(e); }
    }, 'primary']]);
  }

  // ---------------------------------------------------------------- threat actors
  async function loadActors() {
    const root = $('#actors-root');
    if (!$('#ac-q')) {
      root.innerHTML = `<div class="toolbar"><input id="ac-q" class="grow" placeholder="Search name or handle (Telegram, Jabber, forum nick)…">
        <select id="ac-kind" style="max-width:190px"><option value="">Any kind</option><option value="individual">Individual</option><option value="ransomware_group">Ransomware group</option><option value="group">Group</option><option value="unknown">Unknown</option></select>
        <button class="primary" id="ac-new">+ Add actor</button></div><div class="table-wrap"><table id="t-actors"></table></div><div class="pager" id="ac-pager"></div>`;
      debounce('#ac-q', () => { ui.actors.offset = 0; loadActors().catch(fail); });
      $('#ac-kind').addEventListener('change', () => { ui.actors.offset = 0; loadActors().catch(fail); });
      $('#ac-new').addEventListener('click', () => actorModal());
    }
    const p = new URLSearchParams({ limit: PAGE, offset: ui.actors.offset });
    if ($('#ac-q').value.trim()) p.set('q', $('#ac-q').value.trim());
    if ($('#ac-kind').value) p.set('kind', $('#ac-kind').value);
    const res = await api('/actors?' + p);
    const t = $('#t-actors');
    if (!res.items.length) { t.innerHTML = `<tr><td>${empty('No threat actors', 'Forum authors and ransomware groups that mention your assets are profiled automatically.')}</td></tr>`; $('#ac-pager').innerHTML = ''; return; }
    t.innerHTML = `<tr><th>Risk</th><th>Actor</th><th>Kind</th><th>Mentions</th><th>Tags</th><th>Last seen</th></tr>` + res.items.map(a =>
      `<tr class="row" data-actor="${a.id}"><td>${riskBadge(a.risk_score)}</td><td><b>${esc(a.name)}</b>${a.aliases.length ? `<div class="small dim">aka ${a.aliases.map(esc).join(', ')}</div>` : ''}</td>
       <td><span class="tag">${esc(a.kind.replace(/_/g, ' '))}</span></td><td>${a.mention_count}</td><td class="small">${(a.tags || []).slice(0, 3).map(x => `<span class="tag">${esc(x)}</span>`).join(' ')}</td><td class="small dim">${ago(a.last_seen)}</td></tr>`).join('');
    pager('#ac-pager', res.total, ui.actors, loadActors);
  }

  function actorModal(a) {
    modal(a ? 'Edit actor' : 'Add threat actor', `<div class="form">
      <div><label>Name</label><input id="ac-name" value="${esc(a ? a.name : '')}"></div>
      <div><label>Kind</label><select id="ac-k">${['individual', 'ransomware_group', 'group', 'unknown'].map(k => `<option ${a && a.kind === k ? 'selected' : ''} value="${k}">${k.replace(/_/g, ' ')}</option>`).join('')}</select></div>
      <div><label>Aliases (comma-separated)</label><input id="ac-al" value="${esc(a ? a.aliases.join(', ') : '')}"></div>
      <div><label>Description</label><textarea id="ac-desc">${esc(a ? a.description : '')}</textarea></div></div>`,
      [['Cancel', closeModal], ['Save', async () => {
        const body = { name: $('#ac-name').value.trim(), kind: $('#ac-k').value, description: $('#ac-desc').value,
          aliases: $('#ac-al').value.split(',').map(x => x.trim()).filter(Boolean) };
        try { const r = a ? await patch('/actors/' + a.id, body) : await post('/actors', body); closeModal(); toast('Saved', 'ok'); loadActors().catch(() => {}); openActor(r.id); } catch (e) { fail(e); }
      }, 'primary']]);
  }

  async function openActor(id, rebuild) {
    const a = await api(`/actors/${id}${rebuild ? '?rebuild=true' : ''}`);
    const p = a.profile || {};
    const maxW = Math.max(1, ...(p.activity || []).map(w => w.mentions));
    drawer(`THREAT ACTOR · ${a.kind.replace(/_/g, ' ').toUpperCase()}`, a.name, `
      <div style="display:flex;gap:10px;align-items:center;margin-bottom:10px">${riskBadge(a.risk_score, true)}<div>${esc(p.summary || '')}</div></div>
      ${a.aliases.length ? `<div class="small" style="margin-bottom:8px">Also known as: ${a.aliases.map(esc).join(', ')}</div>` : ''}
      ${a.description ? `<div class="pre">${esc(a.description)}</div>` : ''}
      <div class="kv"><div>First seen</div><div>${fmt(a.first_seen)}</div><div>Last seen</div><div>${fmt(a.last_seen)}</div><div>Mentions</div><div>${a.mention_count}</div>
        <div>Tags</div><div>${(a.tags || []).map(t => `<span class="tag">${esc(t)}</span>`).join(' ') || '—'}</div></div>
      <div class="section-t">Handles &amp; contacts</div>${a.handles.length ? a.handles.map(h => `<div class="small" style="margin:3px 0"><span class="tag acc">${esc(h.platform)}</span> <span class="mono">${esc(h.value)}</span> <span class="dim">· ${ago(h.last_seen)}</span></div>`).join('') : '<div class="dim small">none</div>'}
      <div class="section-t">Activity (weekly mentions)</div>${(p.activity || []).length ? `<div style="display:flex;align-items:flex-end;gap:3px;height:60px">${p.activity.map(w => `<span title="${esc(w.week)}: ${w.mentions}" style="flex:1;max-width:18px;background:var(--accent);height:${Math.max(6, 100 * w.mentions / maxW)}%;border-radius:3px 3px 0 0"></span>`).join('')}</div>` : '<div class="dim small">No recent activity</div>'}
      <div class="section-t">Venues</div>${(p.venues || []).map(v => `<div class="small mono">${esc(defang(v.host))} <span class="dim">· ${v.mentions}</span></div>`).join('') || '<div class="dim small">—</div>'}
      <div class="section-t">Targeted organizations</div>${(p.targets || []).map(t => `<span class="tag bad">${esc(t.organization)} · ${t.alerts}</span>`).join(' ') || '<div class="dim small">—</div>'}
      <div class="section-t">Linked indicators (same pages)</div>${(p.linked_indicators || []).map(i => `<div class="small mono"><a href="#" data-ind="${i.indicator_id}">${esc(i.type)}: ${esc(i.value)}</a></div>`).join('') || '<div class="dim small">—</div>'}
      <div class="section-t">Alerts</div>${(p.alerts || []).map(x => `<div class="small" style="margin:3px 0">${riskBadge(x.risk_score)} <a href="#" data-alert="${x.id}">${esc(x.title)}</a> ${classTag(x.threat_class)}</div>`).join('') || '<div class="dim small">—</div>'}
      <div class="section-t">Recent sightings</div>${a.recent.map(r => `<div class="small" style="margin:6px 0"><span class="dim">${fmt(r.ts)} · ${esc(r.source)} · ${esc(defang(r.host))}</span><div>${esc(r.context)}</div></div>`).join('') || '<div class="dim small">—</div>'}`,
      [['Rebuild profile', () => openActor(id, true)], ['Show in graph', () => showGraph('actor:' + id)], ['Edit', () => actorModal(a)],
       ['Merge another actor into this', () => mergeModal(a)],
       ['Delete', () => confirmModal('Delete actor', `Delete ${a.name} with its handles and sightings?`, async () => { await del('/actors/' + id); closeDrawer(); loadActors().catch(() => {}); })]]);
  }

  function mergeModal(a) {
    modal('Merge actors', `<div class="form"><div><label>Actor to merge into <b>${esc(a.name)}</b></label><input id="mg-q" placeholder="search name or handle"></div><div id="mg-res" class="list"></div></div>`, [['Cancel', closeModal]]);
    const search = async () => {
      const q = $('#mg-q').value.trim(); if (q.length < 2) { $('#mg-res').innerHTML = ''; return; }
      const r = await api('/actors?limit=10&q=' + encodeURIComponent(q));
      $('#mg-res').innerHTML = r.items.filter(x => x.id !== a.id).map(x => `<div class="item" data-merge="${x.id}" style="cursor:pointer"><b>${esc(x.name)}</b> <span class="small dim">${esc(x.kind)} · ${x.mention_count} mentions</span></div>`).join('') || '<div class="dim small">no match</div>';
      $$('[data-merge]').forEach(el => el.addEventListener('click', async () => { try { await post(`/actors/${a.id}/merge`, { other_id: +el.dataset.merge }); closeModal(); toast('Merged', 'ok'); openActor(a.id); loadActors().catch(() => {}); } catch (e) { fail(e); } }));
    };
    debounce('#mg-q', () => search().catch(fail));
  }

  // ---------------------------------------------------------------- entity graph
  function showGraph(center) { ui.graph.center = center; closeDrawer(); go('graph'); }

  async function loadGraph() {
    const root = $('#graph-root');
    if (!$('#gr-svg')) {
      root.innerHTML = `<div class="toolbar"><input id="gr-center" class="grow" placeholder="Centre node, e.g. org:1, actor:3, alert:12, site:abc…onion (empty = overview)">
        <select id="gr-depth" style="max-width:120px"><option value="1">depth 1</option><option value="2" selected>depth 2</option><option value="3">depth 3</option></select>
        <button class="primary" id="gr-go">Show</button><button id="gr-reset">Overview</button></div>
        <div class="legend" style="margin-bottom:8px">${Object.entries(TYPE_COLOR).map(([t, c]) => `<span><i style="background:${c}"></i>${t}</span>`).join('')}<span class="dim">· click = re-centre · double-click = details · drag = pan · wheel = zoom</span></div>
        <div class="card" style="padding:0;position:relative"><svg id="gr-svg" style="width:100%;height:68vh;display:block;cursor:grab"></svg><div id="gr-info" class="small" style="position:absolute;left:12px;bottom:10px;max-width:60%"></div></div>`;
      $('#gr-go').addEventListener('click', () => { ui.graph.center = $('#gr-center').value.trim(); loadGraph().catch(fail); });
      $('#gr-reset').addEventListener('click', () => { ui.graph.center = ''; loadGraph().catch(fail); });
      $('#gr-depth').addEventListener('change', () => loadGraph().catch(fail));
      $('#gr-center').addEventListener('keydown', e => { if (e.key === 'Enter') $('#gr-go').click(); });
    }
    $('#gr-center').value = ui.graph.center;
    const p = new URLSearchParams({ depth: $('#gr-depth').value, limit: 160 });
    if (ui.graph.center) p.set('center', ui.graph.center);
    const g = await api('/graph?' + p);
    renderGraph(g);
  }

  // Fruchterman-Reingold with cooling; positions are later fitted into the viewBox
  function layout(nodes, edges, w, h) {
    const N = nodes.length; if (!N) return;
    const idx = new Map(nodes.map((n, i) => [n.id, i]));
    nodes.forEach((n, i) => { const a = 2 * Math.PI * i / N, r = Math.min(w, h) * 0.35; n.x = w / 2 + Math.cos(a) * r; n.y = h / 2 + Math.sin(a) * r; });
    const E = edges.map(e => [idx.get(e.source), idx.get(e.target)]).filter(([a, b]) => a !== undefined && b !== undefined);
    const k = 0.55 * Math.sqrt((w * h) / N), iters = 300;
    const deg = new Array(N).fill(0); E.forEach(([i, j]) => { deg[i]++; deg[j]++; });
    const grav = deg.map(d => (d ? 0.006 : 0.04) * k);  // isolated nodes must not push the layout apart
    for (let it = 0; it < iters; it++) {
      const temp = (w / 8) * (1 - it / iters) + 1;
      const dx = new Float64Array(N), dy = new Float64Array(N);
      for (let i = 0; i < N; i++) for (let j = i + 1; j < N; j++) {
        const ex = nodes[i].x - nodes[j].x, ey = nodes[i].y - nodes[j].y, d = Math.hypot(ex, ey) || 0.01, f = k * k / d;
        dx[i] += ex / d * f; dy[i] += ey / d * f; dx[j] -= ex / d * f; dy[j] -= ey / d * f;
      }
      E.forEach(([i, j]) => {
        const ex = nodes[i].x - nodes[j].x, ey = nodes[i].y - nodes[j].y, d = Math.hypot(ex, ey) || 0.01, f = d * d / k;
        dx[i] -= ex / d * f; dy[i] -= ey / d * f; dx[j] += ex / d * f; dy[j] += ey / d * f;
      });
      for (let i = 0; i < N; i++) {
        dx[i] += (w / 2 - nodes[i].x) * grav[i] / k * 10; dy[i] += (h / 2 - nodes[i].y) * grav[i] / k * 10;
        const d = Math.hypot(dx[i], dy[i]) || 1, m = Math.min(d, temp);
        nodes[i].x += dx[i] / d * m; nodes[i].y += dy[i] / d * m;
      }
    }
  }

  function fitBox(nodes, w, h) {
    const xs = nodes.map(n => n.x), ys = nodes.map(n => n.y);
    let [x0, x1, y0, y1] = [Math.min(...xs), Math.max(...xs), Math.min(...ys), Math.max(...ys)];
    const pad = 60; x0 -= pad; y0 -= pad; x1 += pad * 2.5; y1 += pad;  // labels extend to the right
    let bw = x1 - x0, bh = y1 - y0; const ar = w / h;
    if (bw / bh > ar) { const nh = bw / ar; y0 -= (nh - bh) / 2; bh = nh; } else { const nw = bh * ar; x0 -= (nw - bw) / 2; bw = nw; }
    return [x0, y0, bw, bh];
  }

  function renderGraph(g) {
    const svg = $('#gr-svg'); const w = svg.clientWidth || 900, h = svg.clientHeight || 600;
    if (!g.nodes.length) { svg.innerHTML = ''; $('#gr-info').innerHTML = empty('Nothing to show', 'Add an organization or pick another centre node.'); return; }
    layout(g.nodes, g.edges, w, h);
    const pos = new Map(g.nodes.map(n => [n.id, n]));
    const color = n => n.type === 'alert' ? `var(--${n.severity || 'high'})` : TYPE_COLOR[n.type] || '#888';
    const radius = n => (n.id === g.center ? 13 : n.type === 'org' || n.type === 'actor' ? 10 : n.type === 'alert' ? 7 + (n.risk || 0) / 25 : 6) * Math.sqrt(z);
    let vb = fitBox(g.nodes, w, h);
    const z = Math.max(1, vb[2] / w);  // keep nodes and labels readable when the layout is larger than the view
    svg.setAttribute('viewBox', vb.join(' '));
    svg.innerHTML = `<g>${g.edges.map(e => { const a = pos.get(e.source), b = pos.get(e.target); return a && b ? `<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="#3a4258" stroke-width="${1.2 * z}"><title>${esc(e.relation)}</title></line>` : ''; }).join('')}</g>
      <g>${g.nodes.map(n => `<g class="gn" data-id="${esc(n.id)}" style="cursor:pointer"><circle cx="${n.x}" cy="${n.y}" r="${radius(n)}" fill="${color(n)}" stroke="${n.id === g.center ? '#fff' : '#0b0d12'}" stroke-width="${2 * z}"></circle>
        <text x="${n.x + radius(n) + 3}" y="${n.y + 4}" fill="#aab2c5" font-size="${12 * z}">${esc((n.label || '').slice(0, 32))}</text></g>`).join('')}</g>`;
    $('#gr-info').innerHTML = `<span class="dim">${g.nodes.length} nodes · ${g.edges.length} edges${g.truncated ? ' · truncated (raise depth carefully or pick a centre)' : ''}</span>`;
    $$('.gn', svg).forEach(el => {
      const n = pos.get(el.dataset.id);
      el.addEventListener('mouseenter', () => { $('#gr-info').innerHTML = `<b>${esc(n.type)}</b> · ${esc(n.label)}${n.risk ? ' · risk ' + Math.round(n.risk) : ''}${n.threat_class ? ' · ' + esc(n.threat_class) : ''}`; });
      el.addEventListener('click', () => { ui.graph.center = n.id; loadGraph().catch(fail); });
      el.addEventListener('dblclick', e => { e.stopPropagation(); openNode(n); });
    });
    let drag = null;
    svg.onmousedown = e => { drag = { x: e.clientX, y: e.clientY, vb: vb.slice() }; svg.style.cursor = 'grabbing'; };
    window.onmouseup = () => { drag = null; svg.style.cursor = 'grab'; };
    svg.onmousemove = e => { if (!drag) return; const sc = vb[2] / svg.clientWidth; vb = [drag.vb[0] - (e.clientX - drag.x) * sc, drag.vb[1] - (e.clientY - drag.y) * sc, vb[2], vb[3]]; svg.setAttribute('viewBox', vb.join(' ')); };
    svg.onwheel = e => { e.preventDefault(); const f = e.deltaY > 0 ? 1.12 : 0.89; const cx = vb[0] + vb[2] / 2, cy = vb[1] + vb[3] / 2; vb = [cx - vb[2] * f / 2, cy - vb[3] * f / 2, vb[2] * f, vb[3] * f]; svg.setAttribute('viewBox', vb.join(' ')); };
  }

  function openNode(n) {
    const [t, k] = [n.id.split(':')[0], n.id.slice(n.id.indexOf(':') + 1)];
    if (t === 'org') openOrg(+k).catch(fail);
    else if (t === 'actor') openActor(+k).catch(fail);
    else if (t === 'alert') openAlert(+k).catch(fail);
    else if (t === 'indicator') openInd(+k).catch(fail);
  }

  // ---------------------------------------------------------------- evidence
  async function loadEvidence() {
    const res = await api(`/evidence?limit=${PAGE}&offset=${ui.ev.offset}`);
    const root = $('#evidence-root');
    root.innerHTML = `<div class="notice">Evidence items are canonical JSON snapshots, stored compressed and addressed by <b>SHA-256</b>. Every capture, verification, export and escalation is appended to a <b>hash-chained chain of custody</b>; editing a file or a log entry breaks verification. High-severity alerts are captured automatically.</div>
      <div class="table-wrap"><table id="t-ev">${res.items.length ? `<tr><th>#</th><th>Kind</th><th>Alert</th><th>Source</th><th>SHA-256</th><th>Captured</th><th>By</th><th></th></tr>` + res.items.map(e =>
        `<tr class="row" data-ev="${e.id}"><td>${e.id}</td><td><span class="tag">${esc(e.kind.replace(/_/g, ' '))}</span></td><td>${e.alert_id ? `<a href="#" data-alert="${e.alert_id}">#${e.alert_id}</a>` : '—'}</td>
         <td class="mono small trunc" style="max-width:280px">${esc(defang(e.url))}</td><td class="mono small" title="${esc(e.sha256)}">${short(e.sha256)}</td><td class="small dim">${ago(e.captured_at)}</td><td class="small">${esc(e.captured_by)}</td><td>${e.legal_hold ? '<span class="tag warn">legal hold</span>' : ''}</td></tr>`).join('')
        : `<tr><td>${empty('No evidence yet', 'Capture it from an alert, or wait for a high-severity alert.')}</td></tr>`}</table></div><div class="pager" id="ev-pager"></div>`;
    if (res.items.length) pager('#ev-pager', res.total, ui.ev, loadEvidence);
  }

  async function openEvidence(id) {
    const e = await api('/evidence/' + id);
    drawer(`EVIDENCE #${e.id} · ${e.kind.replace(/_/g, ' ').toUpperCase()}`, e.meta.title || e.url || 'Evidence', `
      <div class="kv"><div>SHA-256</div><div class="mono" style="word-break:break-all">${esc(e.sha256)}</div><div>Size</div><div>${e.size_bytes} bytes</div>
        <div>Source</div><div class="mono" style="word-break:break-all">${esc(defang(e.url)) || '—'}</div><div>Alert</div><div>${e.alert_id ? `<a href="#" data-alert="${e.alert_id}">#${e.alert_id}</a>` : '—'}</div>
        <div>Captured</div><div>${fmt(e.captured_at)} by ${esc(e.captured_by)}</div><div>Legal hold</div><div>${e.legal_hold ? '<span class="tag warn">on</span>' : 'off'}</div>${e.note ? `<div>Note</div><div>${esc(e.note)}</div>` : ''}</div>
      <div id="ev-verify"></div>
      <div class="section-t">Chain of custody</div><div class="timeline">${e.custody.map(c => `<div style="margin:8px 0"><div class="small"><b>#${c.seq} ${esc(c.action)}</b> <span class="dim">· ${fmt(c.ts)} · ${esc(c.actor)}</span></div><div class="small">${esc(c.detail)}</div><div class="small dim mono" title="${esc(c.entry_hash)}">${short(c.entry_hash)} ← ${short(c.prev_hash) || 'genesis'}</div></div>`).join('')}</div>`,
      [['Verify integrity', async () => { try { const r = await post(`/evidence/${id}/verify`); toast(r.ok ? 'Integrity verified' : 'VERIFICATION FAILED', r.ok ? 'ok' : 'err'); await openEvidence(id); $('#ev-verify').innerHTML = `<div class="notice" style="margin-top:10px">${r.ok ? '✔ File hash and custody chain verified.' : '✖ ' + esc(r.problems.join('; '))}</div>`; } catch (er) { fail(er); } }, 'primary'],
       ['Download record', () => download(`/evidence/${id}/download`, `evidence-${id}-${e.sha256.slice(0, 12)}.json`).then(() => openEvidence(id)).catch(fail)],
       ...(e.alert_id ? [['Alert bundle (.zip)', () => download(`/alerts/${e.alert_id}/evidence/bundle`, `darkwatch-alert-${e.alert_id}-evidence.zip`).catch(fail)]] : []),
       [e.legal_hold ? 'Release legal hold' : 'Legal hold', async () => { try { await post(`/evidence/${id}/hold`, { legal_hold: !e.legal_hold }); openEvidence(id); } catch (er) { fail(er); } }]]);
  }

  // ---------------------------------------------------------------- alert drawer panel
  async function alertPanel(id, a) {
    const it = await api(`/alerts/${id}/intel`);
    const c = it.classification || {};
    const box = document.createElement('div');
    box.innerHTML = `<div class="section-t">DarkWatch intelligence</div>
      <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">${riskBadge(it.risk_score, true)} ${classTag(it.threat_class)}
        ${c.confidence ? `<span class="small dim">confidence ${Math.round(c.confidence * 100)}%</span>` : ''}${it.incident_ref ? `<span class="tag ok">IncidentForge: ${esc(it.incident_ref)}</span>` : ''}</div>
      ${c.mitre ? `<div class="small dim" style="margin-top:6px">ATT&amp;CK: ${esc(c.mitre)}</div>` : ''}
      ${(c.signals || []).length ? `<div class="small" style="margin-top:4px">Signals: ${c.signals.map(esc).join(' · ')}</div>` : ''}
      <div class="section-t">Risk factors</div>${factorsHtml(it.risk_factors)}
      <div class="kv" style="margin-top:8px"><div>Organizations</div><div>${it.organizations.map(o => `<a href="#" data-org="${o.id}" class="tag acc">${esc(o.name)}</a>`).join(' ') || '<span class="dim small">no tenant asset matched</span>'}</div>
        <div>Threat actors</div><div>${it.actors.map(x => `<a href="#" data-actor="${x.id}" class="tag bad">${esc(x.name)}</a>`).join(' ') || '<span class="dim small">none</span>'}</div>
        <div>Evidence</div><div>${it.evidence.map(e => `<a href="#" data-ev="${e.id}" class="tag">#${e.id} ${short(e.sha256)}</a>`).join(' ') || '<span class="dim small">not captured</span>'}</div></div>`;
    $('#dr-body').appendChild(box);
    const foot = $('#dr-foot');
    const btn = (label, fn) => { const b = document.createElement('button'); b.textContent = label; b.addEventListener('click', fn); foot.appendChild(b); foot.style.display = ''; };
    btn('⛨ Capture evidence', async () => { try { const e = await post(`/alerts/${id}/evidence`, { note: 'captured from dashboard' }); toast('Evidence #' + e.id + ' preserved', 'ok'); openAlert(id); } catch (e) { fail(e); } });
    if (it.evidence.length) btn('Evidence bundle', () => download(`/alerts/${id}/evidence/bundle`, `darkwatch-alert-${id}-evidence.zip`).catch(fail));
    btn('Re-score', async () => { try { const r = await post(`/alerts/${id}/rescore`); toast(`Risk ${Math.round(r.risk_score)} · ${r.threat_class}`, 'ok'); openAlert(id); } catch (e) { fail(e); } });
    if (state.status && state.status.incidentforge && !it.incident_ref)
      btn('→ IncidentForge', async () => { try { const r = await post(`/alerts/${id}/incidentforge`); toast('Incident ' + r.incident_ref + ' opened', 'ok'); openAlert(id); } catch (e) { fail(e); } });
    btn('Show in graph', () => showGraph('alert:' + id));
  }

  const riskCell = x => x.risk_score ? riskBadge(x.risk_score) + (x.threat_class && x.threat_class !== 'mention' ? `<div class="small dim">${esc(x.threat_class.replace(/_/g, ' '))}</div>` : '') : '<span class="dim small">—</span>';

  // delegated clicks for intel links anywhere in the dashboard (orgs, actors, evidence)
  document.addEventListener('click', e => {
    const o = e.target.closest('[data-org]'); if (o) { e.preventDefault(); openOrg(+o.dataset.org).catch(fail); return; }
    const a = e.target.closest('[data-actor]'); if (a) { e.preventDefault(); openActor(+a.dataset.actor).catch(fail); return; }
    const v = e.target.closest('[data-ev]'); if (v) { e.preventDefault(); openEvidence(+v.dataset.ev).catch(fail); }
    // [data-alert] links are handled by the main dashboard script
  });

  window.INTEL = {
    titles: { orgs: ['Organizations', 'Tenants, their assets, exposure and risk score'], actors: ['Threat actors', 'Forum authors, contacts and ransomware groups linked to your findings'],
      graph: ['Entity graph', 'Relationships between organizations, assets, alerts, sites, indicators and actors'], evidence: ['Evidence', 'Hashed snapshots with a verifiable chain of custody'] },
    views: { orgs: () => loadOrgs(), actors: () => loadActors(), graph: () => loadGraph(), evidence: () => loadEvidence() },
    overview, alertPanel, riskCell,
  };
})();
