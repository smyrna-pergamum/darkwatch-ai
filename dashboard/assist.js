/* DarkWatch AI - setup order, built-in Tor, built-in AI engine and the assistant.
   Loaded before the main dashboard script; uses its helpers (api, post, esc, go, toast, fail, $) at call time. */
"use strict";
(function () {
  const timers = {};
  const poll = (name, fn, ms) => { clearTimeout(timers[name]); timers[name] = setTimeout(fn, ms); };
  const pct = v => Math.round((v || 0) * 100);
  const bar = (p, color) => `<div class="bar" style="height:8px;margin:8px 0"><span style="width:${Math.max(2, Math.min(100, p))}%;background:${color || 'var(--accent)'}"></span></div>`;
  const levelTag = l => `<span class="tag ${l === 'high' ? 'bad' : l === 'medium' ? 'warn' : ''}">${esc(l)}</span>`;

  async function runAction(a) {
    if (!a) return;
    if (a.view) return go(a.view);
    if (a.call === 'tor-connect') { await post('/tor/connect', {}); toast('Connecting the built-in Tor…', 'ok'); return go('system'); }
    if (a.call === 'ai-setup') { await post('/ai/engine/setup', {}); toast('Setting up the built-in AI…', 'ok'); return go('aimodels'); }
  }
  document.addEventListener('click', e => {
    const b = e.target.closest('[data-act]'); if (!b) return;
    e.preventDefault(); runAction(JSON.parse(b.dataset.act)).catch(fail);
  });
  const actBtn = (a, primary) => a ? `<button class="sm ${primary ? 'primary' : ''}" data-act='${esc(JSON.stringify(a))}'>${esc(a.label)}</button>` : '';

  // ------------------------------------------------------------ overview: setup order + suggestions
  async function overview() {
    const [cl, sg] = await Promise.all([api('/setup/checklist'), api('/assistant/suggestions')]);
    const steps = cl.steps, required = steps.filter(s => !s.optional), left = required.filter(s => !s.done).length;
    $('#ov-setup').innerHTML = left === 0 ? '' : `<div class="card" style="margin-bottom:16px"><h3>Setup — in this order <span class="right small dim">${required.length - left}/${required.length} done</span></h3>
      <div class="setup-steps">${steps.map((s, i) => `<div class="setup-step ${s.done ? 'done' : ''} ${s.next ? 'next' : ''}">
        <div class="num">${s.done ? '✓' : i + 1}</div><div class="grow"><b>${esc(s.title)}</b>${s.optional ? ' <span class="tag">optional</span>' : ''}
        <div class="small dim">${esc(s.detail)}${s.blocked ? ' — waits for Tor' : ''}</div></div>${s.done ? '' : actBtn(s.action, s.next)}</div>`).join('')}</div>
      ${cl.deferred_crawls.length ? `<div class="hint">${cl.deferred_crawls.length} scheduled crawl(s) are waiting for Tor and start automatically once it connects.</div>` : ''}</div>`;
    renderSuggest($('#ov-assist'), sg);
  }

  function renderSuggest(el, sg) {
    if (!el) return;
    el.innerHTML = `<div class="grid cols-2"><div class="card"><h3>Suggested questions <span class="right"><button class="sm" id="btn-ai-sugg">✨ AI suggestions</button></span></h3>
      <div class="sugg">${sg.queries.map((q, i) => `<button class="chip-q ${q.ai ? 'ai' : ''}" data-q="${i}" title="${esc(q.why)}">${q.ai ? '✨ ' : q.kind === 'help' ? '❔ ' : '🔎 '}${esc(q.label)}</button>`).join('')}</div>
      <div class="hint">Click a question to ask the assistant (🔎 runs an AI analyst investigation on your data).</div></div>
      <div class="card"><h3>Recommendations</h3>${sg.recommendations.length ? `<div class="list">${sg.recommendations.map(r => `<div class="rec">${levelTag(r.level)}<span class="grow small">${esc(r.text)}</span>${actBtn(r.action)}</div>`).join('')}</div>` : '<div class="dim small">Nothing to recommend — the installation looks healthy.</div>'}</div></div>`;
    el.querySelectorAll('[data-q]').forEach(b => b.addEventListener('click', () => { const q = sg.queries[+b.dataset.q]; openPanel(); ask(q.prompt, q.kind === 'help' ? 'assistant' : 'analyst', q.label); }));
    const ab = el.querySelector('#btn-ai-sugg');
    if (ab) ab.addEventListener('click', async () => {
      ab.disabled = true; ab.textContent = 'Thinking…';
      try { const s = await api('/assistant/suggestions?ai=true'); renderSuggest(el, s); if (!s.ai_used) toast('No AI model answered — showing rule-based suggestions', 'warn'); }
      catch (e) { fail(e); ab.disabled = false; ab.textContent = '✨ AI suggestions'; }
    });
  }

  // ------------------------------------------------------------ System: built-in Tor
  async function tor() {
    const el = $('#sys-tormgr'); if (!el) return;
    const t = await api('/tor/manager');
    const busy = ['starting', 'downloading', 'connecting'].includes(t.status);
    const color = t.status === 'connected' ? 'var(--ok)' : t.status === 'failed' ? 'var(--bad)' : 'var(--accent)';
    const modes = t.bridge_modes.map(m => `<option value="${m}" ${m === t.bridge_mode ? 'selected' : ''}>${({ auto: 'auto (direct, then bridges)', direct: 'direct (no bridges)', custom: 'custom bridge lines' })[m] || m}</option>`).join('');
    el.innerHTML = `<div class="section-t">Built-in Tor</div>
      <div class="kv"><div>Status</div><div><span class="tag" style="color:${color}">${esc(t.status)}</span> ${t.transport ? `via <b>${esc(t.transport)}</b>` : ''} ${t.socks_port ? `<span class="mono small">127.0.0.1:${t.socks_port}</span>` : ''}</div>
      ${t.status === 'downloading' ? `<div>Download</div><div>${bar(pct(t.download))}</div>` : ''}
      ${busy || t.status === 'connected' ? `<div>Bootstrap</div><div>${bar(t.progress, color)}<span class="small dim">${t.progress}% ${esc(t.summary || '')}</span></div>` : ''}
      ${t.error ? `<div>Last error</div><div class="small" style="color:var(--bad)">${esc(t.error)}</div>` : ''}
      ${t.attempts.length ? `<div>Tried</div><div class="small">${t.attempts.map(a => `${a.ok ? '✓' : '✕'} ${esc(a.transport)}`).join(' · ')}</div>` : ''}
      <div>Tor binary</div><div class="small mono">${t.binary ? esc(t.binary) + (t.bundle_version ? ` (${esc(t.bundle_version)})` : '') : 'not installed — downloaded from torproject.org on Connect'}</div></div>
      <div class="toolbar" style="margin:10px 0 0;flex-wrap:wrap"><select id="tor-bridge">${modes}</select>
        <button class="sm primary" id="btn-tor-connect" ${busy ? 'disabled' : ''}>${t.status === 'connected' ? 'Connect again' : 'Connect'}</button>
        <button class="sm" id="btn-tor-reconnect">Reconnect</button>
        <button class="sm" id="btn-tor-stop" ${t.status === 'stopped' ? 'disabled' : ''}>Stop</button></div>
      <div id="tor-custom" style="display:${t.bridge_mode === 'custom' ? 'block' : 'none'};margin-top:8px"><textarea id="tor-bridges" rows="3" placeholder="obfs4 1.2.3.4:443 FINGERPRINT cert=… iat-mode=0  (one per line, from bridges.torproject.org)" style="width:100%"></textarea><div class="hint">${t.custom_bridges} custom bridge(s) saved.</div></div>
      <div class="hint">Connect starts Tor inside the app. <b>auto</b> tries a direct connection, then snowflake, obfs4 and meek bridges — use it when Tor is blocked on your network. Reconnect restarts Tor; New circuit asks for a fresh identity.</div>`;
    $('#tor-bridge').addEventListener('change', e => { $('#tor-custom').style.display = e.target.value === 'custom' ? 'block' : 'none'; });
    $('#btn-tor-connect').addEventListener('click', async () => {
      const body = { bridge_mode: $('#tor-bridge').value };
      if (body.bridge_mode === 'custom' && $('#tor-bridges').value.trim()) body.bridges = $('#tor-bridges').value;
      try { await post('/tor/connect', body); toast('Connecting…', 'ok'); tor(); } catch (e) { fail(e); }
    });
    $('#btn-tor-reconnect').addEventListener('click', async () => {
      try { const r = await post('/tor/reconnect'); toast(r.restarted ? 'Tor is reconnecting…' : (r.tor.is_tor ? 'Tor verified' : 'Tor still not verified'), r.restarted || r.tor.is_tor ? 'ok' : 'err'); tor(); if (!r.restarted) loadSystem(); } catch (e) { fail(e); }
    });
    $('#btn-tor-stop').addEventListener('click', async () => { try { await post('/tor/stop'); toast('Built-in Tor stopped', 'ok'); loadSystem(); } catch (e) { fail(e); } });
    if (busy && state.view === 'system') poll('tor', tor, 2000);
    else if (t.status === 'connected' && el.dataset.last !== 'connected' && state.view === 'system') { el.dataset.last = 'connected'; loadStatus(true).then(() => loadSystem()).catch(() => {}); }
    if (t.status !== 'connected') el.dataset.last = t.status;
  }

  // ------------------------------------------------------------ AI & Models: built-in engine
  async function engine() {
    const el = $('#ai-engine'); if (!el) return;
    const e = await api('/ai/engine');
    const running = e.status === 'running';
    const stepIdx = e.steps.indexOf(e.step);
    el.innerHTML = `<div class="card" style="margin-bottom:16px"><h3>Built-in AI engine (llama.cpp) <span class="right small dim">${e.server_running ? '<span class="tag ok">running</span>' : ''}</span></h3>
      <div class="kv"><div>Engine</div><div class="small mono">${e.engine ? esc(e.engine) : 'not installed — downloaded from the official llama.cpp releases'}</div>
      <div>Active backend</div><div>${esc(e.backend)}${e.backend === 'llamacpp' ? ' (' + esc(e.llamacpp_mode) + ')' : ''}</div>
      ${running ? `<div>Progress</div><div><div class="small">${e.steps.map((s, i) => `<span class="tag ${i < stepIdx ? 'ok' : i === stepIdx ? 'acc' : ''}">${i + 1}. ${s}</span>`).join(' ')}</div>${bar(pct(e.progress))}<span class="small dim">${esc(e.detail)}</span></div>` : ''}
      ${e.status === 'ready' ? '<div>Result</div><div><span class="tag ok">ready</span> the local model answers all AI tasks</div>' : ''}
      ${e.error ? `<div>Error</div><div class="small" style="color:var(--bad)">${esc(e.error)}</div>` : ''}</div>
      <div class="toolbar" style="margin:10px 0 0"><select id="eng-size">${Object.entries(e.catalog).map(([k, v]) => `<option value="${k}" ${k === (e.size || e.default_size) ? 'selected' : ''}>${esc(v.label)}</option>`).join('')}</select>
        <button class="primary sm" id="btn-eng-setup" ${running ? 'disabled' : ''}>${running ? 'Setting up…' : 'Set up built-in AI'}</button></div>
      <div class="hint">Downloads llama.cpp and the chosen GGUF model, switches the app to it and starts it — everything runs on this computer, nothing is sent out. ${e.auto_setup ? 'Runs automatically on first start when no local AI is found.' : ''}</div></div>`;
    $('#btn-eng-setup').addEventListener('click', async () => {
      try { await post('/ai/engine/setup', { size: $('#eng-size').value }); toast('Setting up the built-in AI…', 'ok'); engine(); } catch (er) { fail(er); }
    });
    if (running && state.view === 'aimodels') poll('engine', engine, 2000);
    else if (e.status === 'ready' && el.dataset.last === 'running') loadAIModels(true).catch(() => {});
    el.dataset.last = e.status;
  }

  // ------------------------------------------------------------ assistant panel
  const chat = { sid: null, seq: 0, kind: 'assistant', title: '' };
  function ensurePanel() {
    if ($('#as-panel')) return;
    const btn = document.createElement('button');
    btn.id = 'as-fab'; btn.title = 'Assistant — how do I…?'; btn.innerHTML = '<img src="/ui/icon.svg" alt=""><span>?</span>';
    btn.addEventListener('click', () => $('#as-panel').classList.contains('open') ? closePanel() : openPanel());
    const p = document.createElement('div');
    p.id = 'as-panel';
    p.innerHTML = `<div class="as-h"><img src="/ui/icon.svg" alt=""><div class="grow"><b>Assistant</b><div class="small dim">How to use DarkWatch AI · smart questions</div></div><button class="ghost sm" id="as-new" title="New conversation">＋</button><button class="ghost sm" id="as-close">✕</button></div>
      <div class="as-body" id="as-body"></div>
      <div class="as-sugg" id="as-sugg"></div>
      <div class="as-in"><textarea id="as-input" rows="2" placeholder="Ask anything, e.g. “Tor bağlanmıyor, ne yapmalıyım?”"></textarea><button class="primary" id="as-send">Send</button></div>`;
    document.body.append(btn, p);
    $('#as-close').addEventListener('click', closePanel);
    $('#as-new').addEventListener('click', () => { chat.sid = null; chat.seq = 0; $('#as-body').innerHTML = ''; welcome(); });
    $('#as-send').addEventListener('click', sendInput);
    $('#as-input').addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendInput(); } });
    welcome();
  }
  function openPanel() { ensurePanel(); $('#as-panel').classList.add('open'); setTimeout(() => $('#as-input').focus(), 50); }
  function closePanel() { $('#as-panel').classList.remove('open'); }
  async function welcome() {
    $('#as-body').innerHTML = `<div class="msg bot">Hi! Ask me how to use DarkWatch AI — Tor, AI models, organisations, targets, evidence — or pick a question below.</div>`;
    try {
      const sg = await api('/assistant/suggestions');
      $('#as-sugg').innerHTML = sg.queries.slice(0, 6).map((q, i) => `<button class="chip-q" data-i="${i}" title="${esc(q.why)}">${q.kind === 'help' ? '❔' : '🔎'} ${esc(q.label)}</button>`).join('');
      $$('#as-sugg [data-i]').forEach(b => b.addEventListener('click', () => { const q = sg.queries[+b.dataset.i]; ask(q.prompt, q.kind === 'help' ? 'assistant' : 'analyst', q.label); }));
    } catch (e) { $('#as-sugg').innerHTML = ''; }
  }
  function addMsg(cls, html) { const d = document.createElement('div'); d.className = 'msg ' + cls; d.innerHTML = html; $('#as-body').appendChild(d); $('#as-body').scrollTop = 1e9; return d; }
  const md = s => esc(s).replace(/\*\*(.+?)\*\*/g, '<b>$1</b>').replace(/`([^`]+)`/g, '<code>$1</code>').replace(/\n/g, '<br>');
  async function sendInput() {
    const t = $('#as-input').value.trim(); if (!t) return;
    $('#as-input').value = '';
    if (chat.sid && chat.kind === 'assistant') {
      addMsg('me', esc(t));
      try { await post(`/analyst/sessions/${chat.sid}/messages`, { text: t }); follow(); } catch (e) { addMsg('err', esc(e.message)); }
    } else ask(t, 'assistant');
  }
  async function ask(prompt, kind, label) {
    openPanel();
    addMsg('me', esc(label || prompt));
    chat.kind = kind; chat.seq = 0;
    try {
      const r = kind === 'analyst' ? await post('/analyst/sessions', { question: prompt }) : await post('/assistant/ask', { question: prompt });
      chat.sid = r.id; follow();
    } catch (e) { addMsg('err', esc(e.message)); }
  }
  async function follow() {
    if (!chat.sid) return;
    const typing = $('#as-typing') || addMsg('bot typing', '<span class="dots">thinking</span>');
    typing.id = 'as-typing';
    let s;
    try { s = await api(`/analyst/sessions/${chat.sid}?since=${chat.seq}`); } catch (e) { typing.remove(); return addMsg('err', esc(e.message)); }
    for (const ev of s.events) {
      chat.seq = Math.max(chat.seq, ev.seq);
      const p = ev.payload || {};
      if (ev.type === 'tool/call') addMsg('tool', `🔧 ${esc(p.name)}`);
      if (ev.type === 'assistant/message' && p.content && !(p.tool_calls || []).length) addMsg('bot', md(p.content));
      if (ev.type === 'report/submitted') {
        const r = p.report || {};
        addMsg('bot', `<b>${esc((r.verdict || '').replace(/_/g, ' '))}</b> · ${esc(r.severity || '')} · confidence ${Math.round((r.confidence || 0) * 100)}%<br>${md(r.summary || '')}${(r.recommended_actions || []).length ? '<br><br><b>Next steps</b><br>• ' + r.recommended_actions.map(esc).join('<br>• ') : ''}<br><a href="#analyst" class="small">Open in AI Analyst →</a>`);
      }
      if (ev.type === 'assistant/attempt' && p.error) addMsg('tool', `⚠ ${esc(p.error.message || p.error.code || 'model attempt failed')}`);
    }
    $('#as-body').appendChild(typing);
    if (['queued', 'running'].includes(s.status)) return poll('chat', follow, 1500);
    typing.remove(); $('#as-typing') && $('#as-typing').remove();
    if (s.status === 'failed') addMsg('err', esc(s.error || 'failed'));
    if (s.status === 'waiting_approval') addMsg('tool', 'The analyst proposed a change that needs your approval — see AI Analyst.');
  }

  window.ASSIST = {
    overview, tor, engine, openPanel, ask,
    after: { system: tor, aimodels: engine },
  };
  document.addEventListener('DOMContentLoaded', ensurePanel);
})();
