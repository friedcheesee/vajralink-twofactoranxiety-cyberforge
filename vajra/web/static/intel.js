/* VajraLink Intelligence UI: function-graph canvas, attack patterns, reachability SCA/SBOM,
   SAST engine attribution and DAST hand-off stats. Vanilla JS, no build step. */
(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const srcPath = () => ($('destDirInput') ? $('destDirInput').value : 'targets/VulnerableApp');
  async function getJSON(url, opts) {
    const r = await fetch(url, opts);
    if (!r.ok) throw new Error(`${r.status} ${await r.text().catch(() => '')}`.slice(0, 300));
    return r.json();
  }

  // IBM Carbon categorical data-visualisation palette
  const ENGINE_COLOR = {
    'Java AST Taint': '#6929c4',
    'Sink-Signature Scanner': '#1192e8',
    'Semgrep (synthesized Java rules)': '#005d5d',
    'Secret & Key Scanner': '#9f1853',
    'Bandit (Python)': '#b28600',
    'Sanitizer / Decoy Inspector': '#198038',
    'Vajra-Differential-Verifier': '#002d9c',
    'Vajra-Agentic-Evasion': '#8a3800',
    'Vajra-Playwright-DOM': '#ee538b',
    'Vajra-HTTP-Reflection': '#012749',
    'Vajra-Header-Auditor': '#8d8d8d',
  };
  const CARBON_CATEGORICAL = ['#6929c4', '#1192e8', '#005d5d', '#9f1853', '#fa4d56', '#570408', '#198038',
    '#002d9c', '#ee538b', '#b28600', '#009d9a', '#012749', '#8a3800', '#a56eff'];
  const colorFor = (name) => ENGINE_COLOR[name] || '#6f6f6f';
  const enginePill = (name) =>
    `<span class="eng-pill"><span class="dot" style="background:${colorFor(name)}"></span>${esc(name.replace(' (synthesized Java rules)', ' + synth rules'))}</span>`;
  window.enginePills = (list) => (list && list.length ? list.map(enginePill).join('') : '');
  window.discoveryPill = function (disc, origin) {
    let h = '';
    if (disc === 'sast-guided') h += '<span class="disc-pill disc-guided" title="SAST handed this route to DAST">SAST→DAST</span>';
    else if (disc === 'dast-independent') h += '<span class="disc-pill disc-indep" title="DAST found this on its own">DAST-only</span>';
    else if (disc === 'decoy-audit') h += '<span class="disc-pill disc-decoy" title="Route SAST declared safe, re-probed by DAST">DECOY AUDIT</span>';
    if (origin === 'simulated') h += ' <span class="disc-pill disc-sim" title="Target offline: synthesized from the route table, not a real probe">SIMULATED</span>';
    return h;
  };

  /* ------------------------------------------------------------------ generic layered canvas */
  function makeCanvas(host, opts) {
    host.innerHTML = `
      <div class="canvas-wrap" id="${host.id}-wrap">
        <div class="canvas-hud">
          <button data-z="in" title="Zoom in">＋</button><button data-z="out" title="Zoom out">－</button>
          <button data-z="fit" title="Fit to view">⤢ Fit</button>
        </div>
        <svg><defs>
          <pattern id="${host.id}-dots" width="22" height="22" patternUnits="userSpaceOnUse"><circle cx="1.5" cy="1.5" r="1.1" fill="#cbd5e1"/></pattern>
          <marker id="${host.id}-arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#94a3b8"/></marker>
        </defs>
        <rect width="100%" height="100%" fill="url(#${host.id}-dots)"/>
        <g class="viewport"></g></svg>
        <div class="canvas-legend">${opts.legend || ''}</div>
      </div>`;
    const wrap = host.querySelector('.canvas-wrap');
    const svg = wrap.querySelector('svg');
    const vp = wrap.querySelector('.viewport');
    const st = { s: 1, x: 20, y: 20 };
    const apply = () => vp.setAttribute('transform', `translate(${st.x},${st.y}) scale(${st.s})`);
    const fit = (bbox) => {
      const w = wrap.clientWidth, h = wrap.clientHeight;
      if (!bbox || !bbox.w) return;
      st.s = Math.min(1.1, Math.max(0.45, Math.min((w - 40) / bbox.w, (h - 40) / bbox.h)));
      st.x = (w - bbox.w * st.s) / 2 - bbox.x * st.s;
      st.y = 20 - bbox.y * st.s;
      apply();
    };
    let drag = null;
    wrap.addEventListener('mousedown', (e) => { if (e.target.closest('.fg-node,.canvas-hud')) return; drag = { x: e.clientX - st.x, y: e.clientY - st.y }; wrap.classList.add('dragging'); });
    window.addEventListener('mouseup', () => { drag = null; wrap.classList.remove('dragging'); });
    window.addEventListener('mousemove', (e) => { if (!drag) return; st.x = e.clientX - drag.x; st.y = e.clientY - drag.y; apply(); });
    wrap.addEventListener('wheel', (e) => {
      e.preventDefault();
      const k = e.deltaY < 0 ? 1.12 : 0.89;
      const r = wrap.getBoundingClientRect();
      const mx = e.clientX - r.left, my = e.clientY - r.top;
      st.x = mx - (mx - st.x) * k; st.y = my - (my - st.y) * k; st.s = Math.min(2.5, Math.max(0.1, st.s * k)); apply();
    }, { passive: false });
    return { wrap, svg, vp, st, apply, fit };
  }

  function aggregateEntrypoints(nodes, edges) {
    // Entrypoints of one module that call the same targets are one visual group ("N endpoints -> 1 root cause")
    const outs = {};
    edges.forEach((e) => (outs[e.src] = outs[e.src] || new Set()).add(e.dst));
    const groups = {};
    nodes.forEach((n) => {
      if (n.role !== 'entrypoint') return;
      const key = n.module + '|' + [...(outs[n.id] || [])].sort().join(',');
      (groups[key] = groups[key] || []).push(n);
    });
    const remap = {}, keep = [];
    nodes.forEach((n) => {
      if (n.role !== 'entrypoint') { keep.push(n); return; }
      const key = n.module + '|' + [...(outs[n.id] || [])].sort().join(',');
      const g = groups[key];
      if (g[0] !== n) { remap[n.id] = g[0].id; return; }
      if (g.length > 1) {
        n.label = `${g.length} endpoints`;
        n.route_count = g.reduce((a, x) => a + (x.route_count || 0), 0);
        n.routes = g.flatMap((x) => x.routes || []).slice(0, 6);
        n.grouped = g.map((x) => x.label);
      }
      keep.push(n);
    });
    const seen = new Set(), ne = [];
    edges.forEach((e) => {
      const s = remap[e.src] || e.src, d = remap[e.dst] || e.dst, k = s + '>' + d;
      if (!seen.has(k) && s !== d) { seen.add(k); ne.push({ ...e, src: s, dst: d }); }
    });
    return { nodes: keep, edges: ne };
  }

  function drawLayered(host, nodes, edges, o) {
    if (o.aggregate) { const a = aggregateEntrypoints(nodes, edges); nodes = a.nodes; edges = a.edges; }
    const cv = makeCanvas(host, o);
    const W = 232, H = 48, GX = 96, GY = 16;
    const byLayer = {};
    nodes.forEach((n) => (byLayer[n.layer] = byLayer[n.layer] || []).push(n));
    Object.keys(byLayer).forEach((l) => {
      byLayer[l].sort((a, b) => (a.module || '').localeCompare(b.module || '') || (a.label || '').localeCompare(b.label || ''));
      byLayer[l].forEach((n, i) => { n.x = 20 + l * (W + GX); n.y = 20 + i * (H + GY); });
    });
    const idx = Object.fromEntries(nodes.map((n) => [n.id, n]));
    const up = {}, down = {};
    edges.forEach((e) => { (down[e.src] = down[e.src] || []).push(e.dst); (up[e.dst] = up[e.dst] || []).push(e.src); });
    let html = '';
    edges.forEach((e, i) => {
      const a = idx[e.src], b = idx[e.dst];
      if (!a || !b) return;
      const x1 = a.x + W, y1 = a.y + H / 2, x2 = b.x, y2 = b.y + H / 2, dx = Math.max(30, (x2 - x1) / 2);
      html += `<path class="fg-edge ${e.kind || ''}" data-i="${i}" data-s="${esc(e.src)}" data-d="${esc(e.dst)}" d="M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}" marker-end="url(#${host.id}-arr)"/>`;
    });
    nodes.forEach((n) => {
      const c = o.color(n);
      html += `<g class="fg-node" data-id="${esc(n.id)}" transform="translate(${n.x},${n.y})">
        <rect class="body" width="${W}" height="${H}" rx="9" stroke="${c}"/>
        <rect width="6" height="${H}" rx="3" fill="${c}"/>
        <text class="t1" x="16" y="19">${esc(o.t1(n).slice(0, 34))}</text>
        <text class="t2" x="16" y="35">${esc(o.t2(n).slice(0, 44))}</text>
        ${o.badge ? o.badge(n, W) : ''}
      </g>`;
    });
    cv.vp.innerHTML = html;
    const bbox = nodes.length ? {
      x: 0, y: 0,
      w: Math.max(...nodes.map((n) => n.x + W)) + 30,
      h: Math.max(...nodes.map((n) => n.y + H)) + 30,
    } : null;
    cv.fit(bbox);
    cv.wrap.querySelector('.canvas-hud').addEventListener('click', (e) => {
      const z = e.target.dataset.z; if (!z) return;
      if (z === 'fit') cv.fit(bbox);
      else { const k = z === 'in' ? 1.2 : 0.83; cv.st.s = Math.min(2.5, Math.max(0.1, cv.st.s * k)); cv.apply(); }
    });
    const lineage = (id) => {
      const seen = new Set([id]);
      [up, down].forEach((adj) => { const q = [id]; while (q.length) { const c = q.pop(); (adj[c] || []).forEach((n) => { if (!seen.has(n)) { seen.add(n); q.push(n); } }); } });
      return seen;
    };
    const clear = () => {
      cv.vp.querySelectorAll('.dim,.hot,.flow,.sel').forEach((el) => el.classList.remove('dim', 'hot', 'flow', 'sel'));
    };
    cv.vp.addEventListener('click', (ev) => {
      const g = ev.target.closest('.fg-node');
      if (!g) { clear(); o.onSelect && o.onSelect(null); return; }
      const id = g.dataset.id;
      clear();
      const keep = lineage(id);
      cv.vp.querySelectorAll('.fg-node').forEach((el) => { if (!keep.has(el.dataset.id)) el.classList.add('dim'); });
      cv.vp.querySelectorAll('.fg-edge').forEach((el) => {
        if (keep.has(el.dataset.s) && keep.has(el.dataset.d)) el.classList.add('hot', 'flow'); else el.classList.add('dim');
      });
      g.classList.add('sel');
      o.onSelect && o.onSelect(idx[id]);
    });
    return cv;
  }

  /* ------------------------------------------------------------------ Function graph tab */
  const fg = { data: null, cwe: '', module: '', showAll: false, limit: 12 };
  const ROLE_COLOR = { entrypoint: '#0f62fe', 'root-sink': '#da1e28', service: '#b28600', helper: '#6f6f6f' };

  async function loadFunctionGraph() {
    const host = $('intelGraph');
    host.innerHTML = '<div style="padding:1.5rem;color:var(--text-muted)">Building inter-module function graph…</div>';
    try {
      const q = new URLSearchParams({ source_path: srcPath() });
      if (fg.cwe) q.set('cwe', fg.cwe);
      if (fg.module) q.set('module', fg.module);
      q.set('limit', fg.limit);
      fg.data = await getJSON('/api/sast/function-graph?' + q);
      renderFunctionGraph();
    } catch (e) {
      host.innerHTML = `<div class="console-line warn">Function graph error: ${esc(e.message)}</div>`;
    }
  }

  function renderFunctionGraph() {
    const d = fg.data, s = d.stats, host = $('intelGraph');
    const cwes = [...new Set((d.module_clusters || []).map((c) => c.cwe))].sort();
    host.innerHTML = `
      <div class="card-desc" style="margin-top:0.4rem">
        Every Java method is a node; edges are resolved calls (solid), <span style="color:#8e6a00">@Service / interface DI</span> (dashed) and
        <span style="color:#1f3b63">static</span> calls (dotted). A vulnerability lives in exactly <b>one root method</b>; every endpoint and importing module that
        reaches it is a <b>propagated path</b>, not a separate finding. Click any node to trace its lineage.
      </div>
      <div class="chip-row">
        <div class="stat-chip"><div class="v">${s.modules}</div><div class="l">Modules</div></div>
        <div class="stat-chip"><div class="v">${s.methods}</div><div class="l">Methods</div></div>
        <div class="stat-chip"><div class="v">${s.call_edges}</div><div class="l">Call edges</div></div>
        <div class="stat-chip warn"><div class="v">${s.di_edges}</div><div class="l">DI edges</div></div>
        <div class="stat-chip info"><div class="v">${s.entrypoints}</div><div class="l">Entrypoints</div></div>
        <div class="stat-chip bad"><div class="v">${s.root_sink_clusters}</div><div class="l">Root causes</div></div>
        <div class="stat-chip purple"><div class="v">${s.cross_module_clusters}</div><div class="l">Cross-module</div></div>
      </div>
      <div class="collapse-banner">
        <span class="big">${s.alerts_without_graph} → ${s.alerts_with_graph}</span>
        <span><b>${s.alerts_collapsed} duplicate alerts collapsed.</b> A per-endpoint tool would raise ${s.alerts_without_graph} alerts (one per endpoint reaching a flawed sink);
        the function graph groups them into ${s.alerts_with_graph} root causes, ${s.cross_module_clusters} of which live in a module that other modules import.</span>
      </div>
      <div class="intel-toolbar">
        <label style="font-size:.78rem;font-weight:600">CWE</label>
        <select id="fgCwe"><option value="">All</option>${cwes.map((c) => `<option ${c === fg.cwe ? 'selected' : ''}>${c}</option>`).join('')}</select>
        <label style="font-size:.78rem;font-weight:600">Module</label>
        <input id="fgModule" placeholder="e.g. PasswordResetService" value="${esc(fg.module)}" style="width:220px">
        <label style="font-size:.78rem;font-weight:600">Clusters</label>
        <select id="fgLimit">${[6, 12, 25, 60].map((n) => `<option ${n === fg.limit ? 'selected' : ''}>${n}</option>`).join('')}</select>
        <button class="btn btn-outline" id="fgApply" style="padding:.3rem .7rem;font-size:.75rem">Apply</button>
        <button class="btn btn-outline" id="fgReset" style="padding:.3rem .7rem;font-size:.75rem">Reset</button>
        <span class="badge badge-code">showing ${d.view.shown_clusters} of ${d.view.total_clusters} method-level clusters · ${d.view.nodes.length} nodes</span>
      </div>
      <div id="fgCanvas"></div>
      <div id="fgInspector" class="inspector">Select a node on the canvas to see its module, routes, flagged sinks, the engines that found them and how many alerts collapse into it.</div>
      <div class="section-title">Root-cause clusters <span class="badge badge-suppressed">one row = one deduplicated issue</span></div>
      <div id="fgClusters"></div>
      <div class="section-title">Module propagation <span class="badge badge-runtime">root module ← imported by</span></div>
      <div id="fgModules"></div>`;
    $('fgApply').onclick = () => { fg.cwe = $('fgCwe').value; fg.module = $('fgModule').value.trim(); fg.limit = +$('fgLimit').value; loadFunctionGraph(); };
    $('fgReset').onclick = () => { fg.cwe = ''; fg.module = ''; loadFunctionGraph(); };

    const clustersByRoot = {};
    (d.clusters || []).forEach((c) => (clustersByRoot[c.root.node_id] = clustersByRoot[c.root.node_id] || []).push(c));
    drawLayered($('fgCanvas'), d.view.nodes.map((n) => ({ ...n })), d.view.edges, {
      aggregate: true,
      legend: `<span><i style="background:#0f62fe"></i>Entrypoint (route)</span><span><i style="background:#b28600"></i>Service / bean</span>
               <span><i style="background:#6f6f6f"></i>Helper</span><span><i style="background:#da1e28"></i>Root sink method</span>
               <span style="color:#8e6a00">- - DI</span><span style="color:#0043ce">··· static</span>`,
      color: (n) => ROLE_COLOR[n.role] || '#6f6f6f',
      t1: (n) => n.label,
      t2: (n) => n.role === 'entrypoint' ? `${n.module} · ${n.route_count} route${n.route_count === 1 ? '' : 's'}${n.grouped ? ' (grouped)' : ''}`
        : n.vulns && n.vulns.length ? `${n.module} · ${[...new Set(n.vulns.map((v) => v.cwe))].join(', ')} ×${n.vulns.length}` : n.module,
      badge: (n, W) => n.is_root ? `<g transform="translate(${W - 34},-9)"><rect width="32" height="16" rx="8" fill="#da1e28"/><text x="16" y="11.5" text-anchor="middle" style="font-size:9px;font-weight:800;fill:#fff">ROOT</text></g>` : '',
      onSelect: (n) => showNodeInspector(n, clustersByRoot),
    });
    renderClusterTable();
    renderModules();
  }

  function showNodeInspector(n, clustersByRoot) {
    const box = $('fgInspector');
    if (!n) { box.textContent = 'Select a node on the canvas to see its module, routes, flagged sinks, the engines that found them and how many alerts collapse into it.'; return; }
    let h = `<h4>${esc(n.label)} <span class="badge badge-tool">${esc(n.role)}</span></h4>
      <div class="kv"><span>Module</span><span><b>${esc(n.module)}</b></span></div>
      <div class="kv"><span>Source</span><span><code>${esc(n.file)}:${n.start}-${n.end}</code></span></div>`;
    if (n.routes && n.routes.length) {
      h += `<div class="kv"><span>Routes</span><span>${n.routes.map((r) => `<span class="mini-chip">${esc(r.method)} ${esc(r.url)}${r.secure ? ' (secure)' : ''}</span>`).join('')}${n.route_count > n.routes.length ? ` +${n.route_count - n.routes.length} more` : ''}</span></div>`;
    }
    (n.vulns || []).forEach((v) => {
      h += `<div class="kv"><span>${esc(v.cwe)} · L${v.line}</span><span>${esc(v.vuln_type)} — ${window.enginePills(v.engines)}<br><code style="font-size:.72rem">${esc(v.snippet)}</code></span></div>`;
    });
    (clustersByRoot[n.id] || []).forEach((c) => {
      h += `<div class="kv"><span>Root cause ${esc(c.cwe)}</span><span><b>${c.alerts_without_graph}</b> endpoint alert(s) → <b>1</b> issue ·
        reached by ${c.entrypoints.length} entrypoint(s)${c.importing_modules.length ? ' · imported by ' + c.importing_modules.map((m) => `<span class="mini-chip imp">${esc(m)}</span>`).join('') : ' · same-module callers only'}<br>
        <span style="color:var(--text-muted);font-size:.72rem">e.g. ${esc((c.entrypoints[0] || {}).path || '')}</span></span></div>`;
    });
    box.innerHTML = h;
  }

  function renderClusterTable() {
    const rows = fg.data.module_clusters || [];
    const list = fg.showAll ? rows : rows.slice(0, 14);
    $('fgClusters').innerHTML = `
      <div class="table-scroll-container"><table><thead><tr>
        <th>CWE</th><th>Root module (flawed code)</th><th>Root methods</th><th>Endpoints reaching it</th><th>Imported / called via</th><th>Found by</th><th>Alerts</th><th></th>
      </tr></thead><tbody>${list.map((c) => `<tr>
        <td><code style="font-weight:700">${esc(c.cwe)}</code></td>
        <td><b>${esc(c.root_module)}</b><br><code style="font-size:.7rem">${esc(c.file.split('/').pop())}:${c.sink_lines.slice(0, 4).join(',')}</code></td>
        <td>${c.root_methods.length}</td>
        <td>${c.route_urls.length}<br><span style="color:var(--text-dim);font-size:.7rem">max ${c.max_hops} hops</span></td>
        <td>${c.importing_modules.length ? c.importing_modules.map((m) => `<span class="mini-chip imp">${esc(m)}</span>`).join('') : '<span style="color:var(--text-dim)">same module</span>'}</td>
        <td>${window.enginePills(c.engines)}</td>
        <td><b style="color:var(--crimson)">${c.alerts_without_graph}</b> → <b style="color:var(--emerald)">1</b></td>
        <td><button class="btn btn-outline fg-focus" style="padding:.2rem .5rem;font-size:.72rem" data-cwe="${esc(c.cwe)}" data-mod="${esc(c.root_module)}">Focus</button></td>
      </tr>`).join('')}</tbody></table></div>
      ${rows.length > 14 ? `<button class="btn btn-outline" id="fgMore" style="margin-top:.5rem;font-size:.75rem">${fg.showAll ? 'Show top 14' : `Show all ${rows.length}`}</button>` : ''}`;
    document.querySelectorAll('.fg-focus').forEach((b) => (b.onclick = () => { fg.cwe = b.dataset.cwe; fg.module = b.dataset.mod; loadFunctionGraph(); }));
    if ($('fgMore')) $('fgMore').onclick = () => { fg.showAll = !fg.showAll; renderClusterTable(); };
  }

  function renderModules() {
    const mods = (fg.data.module_graph.modules || []).filter((m) => m.own_cwes.length && m.imported_by.length);
    $('fgModules').innerHTML = mods.length ? mods.map((m) => `
      <div class="mod-card"><span class="mini-chip root">${esc(m.module)}</span> root of ${m.own_cwes.map((c) => `<code>${esc(c)}</code>`).join(', ')}
        <span class="arrow">←</span> imported by ${m.imported_by.map((x) => `<span class="mini-chip imp">${esc(x)}</span>`).join('')}
        <div style="color:var(--text-muted);font-size:.74rem;margin-top:.25rem">
          The importing module${m.imported_by.length > 1 ? 's are' : ' is'} exposed to this flaw only through the import — the issue is reported once, on <b>${esc(m.module)}</b>, not once per caller.
        </div></div>`).join('') : '<div style="color:var(--text-muted);font-size:.8rem">No cross-module propagation found.</div>';
  }

  /* ------------------------------------------------------------------ Attack patterns */
  let apFilter = 'all';
  async function loadPatterns() {
    const host = $('intelPatterns');
    host.innerHTML = '<div style="padding:1.5rem;color:var(--text-muted)">Loading attack-pattern catalog…</div>';
    try { renderPatterns(await getJSON('/api/attack-patterns')); }
    catch (e) { host.innerHTML = `<div class="console-line warn">Catalog error: ${esc(e.message)}</div>`; }
  }
  function renderPatterns(data) {
    const rows = data.patterns;
    const st = data.scan_state;
    const staticCov = rows.filter((r) => r.covered_static).length;
    const dynCov = rows.filter((r) => r.covered_dynamic).length;
    const verifiable = rows.filter((r) => r.pattern.dast_verifiable).length;
    const list = rows.filter((r) => apFilter === 'all' || (apFilter === 'dast' ? r.pattern.dast_verifiable : !r.pattern.dast_verifiable));
    $('intelPatterns').innerHTML = `
      <div class="card-desc" style="margin-top:.4rem">
        <b>What attack patterns do we cover, and how do we approach each in SAST, DAST and SCA?</b> Every pattern is a typed record
        (<code>vajra/attack_patterns/catalog.py</code>) tying CAPEC / ATT&amp;CK / CWE to the concrete Java sinks, probes and library advisories we use.
        ${st.sast ? '' : '<br><span class="cds-helper">Run SAST, DAST and correlation to overlay live coverage counts.</span>'}
      </div>
      <div class="chip-row">
        <div class="stat-chip"><div class="v">${data.total_patterns}</div><div class="l">Patterns</div></div>
        <div class="stat-chip info"><div class="v">${staticCov}/${data.total_patterns}</div><div class="l">Static coverage (this scan)</div></div>
        <div class="stat-chip purple"><div class="v">${dynCov}/${verifiable}</div><div class="l">DAST-verified / verifiable</div></div>
        <div class="stat-chip bad"><div class="v">${rows.reduce((a, r) => a + r.confirmed, 0)}</div><div class="l">Confirmed issues</div></div>
      </div>
      <div class="filter-pills" style="margin-bottom:.8rem">
        ${[['all', 'All'], ['dast', 'DAST-verifiable'], ['code', 'Code-level only (SAST)']].map(([k, l]) => `<button class="filter-pill ${apFilter === k ? 'active' : ''}" data-k="${k}">${l}</button>`).join('')}
      </div>
      <div class="ap-grid">${list.map(apCard).join('')}</div>`;
    document.querySelectorAll('#intelPatterns .filter-pill').forEach((b) => (b.onclick = () => { apFilter = b.dataset.k; renderPatterns(data); }));
  }
  function apCard(r) {
    const p = r.pattern;
    const eng = Object.entries(r.sast_engines_seen || {});
    const disc = Object.entries(r.dast_discovery || {});
    return `<div class="ap-card">
      <h4><span>${esc(p.name)}</span><span class="badge badge-${p.severity === 'CRITICAL' ? 'confirmed' : p.severity === 'HIGH' ? 'runtime' : 'code'}">${esc(p.severity)}</span></h4>
      <div class="sub">${esc(p.summary)}</div>
      <div class="ap-ids">
        <span class="badge badge-tool">${esc(p.pattern_id)}</span>
        ${p.capec.map((c) => `<span class="badge badge-quantum">${esc(c)}</span>`).join('')}
        ${p.attck.map((c) => `<span class="badge badge-agentic">ATT&amp;CK ${esc(c)}</span>`).join('')}
        <span class="badge badge-code">${esc(p.canonical_cwe)}${p.cwe_aliases.length ? ' ⟵ ' + p.cwe_aliases.map(esc).join(', ') : ''}</span>
        <span class="badge badge-tool">${esc(p.owasp)}</span>
      </div>
      ${p.capec_note ? `<div style="font-size:.7rem;color:var(--text-dim)">${esc(p.capec_note)}</div>` : ''}
      <div class="ap-metrics">
        <div><b>${r.sast_sinks}</b><small>SAST sinks</small></div>
        <div><b>${r.dast_probes}</b><small>DAST proofs</small></div>
        <div><b style="color:var(--crimson)">${r.confirmed}</b><small>Confirmed</small></div>
        <div><b>${r.sca_findings}</b><small>SCA advisories</small></div>
      </div>
      ${eng.length ? `<div style="margin:.3rem 0">${eng.map(([n, c]) => `${enginePill(n)}<small>×${c}</small>`).join(' ')}</div>` : ''}
      ${disc.length ? `<div style="margin:.3rem 0">${disc.map(([n, c]) => `${window.discoveryPill(n)}<small>×${c}</small>`).join(' ')}</div>` : ''}
      <div class="ap-sec"><div class="h">SAST — what we look for</div><ul>${p.sast_sinks.map((x) => `<li><code>${esc(x)}</code></li>`).join('')}</ul>
        <div class="h" style="margin-top:.3rem">Guards that suppress it (decoys)</div><ul>${p.sast_guards.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>
        <div style="margin-top:.2rem">Engines: ${p.sast_engines.map(enginePill).join('')}</div></div>
      <div class="ap-sec"><div class="h">DAST — how we prove it ${p.dast_verifiable ? '' : '<span class="badge badge-tool">code-level</span>'}</div>
        ${esc(p.dast_strategy)}<br><b>Proof:</b> ${esc(p.dast_proof)}</div>
      ${p.sca_links.length ? `<div class="ap-sec"><div class="h">SCA — related libraries</div>${p.sca_links.map((x) => `<span class="mini-chip">${esc(x)}</span>`).join('')}</div>` : ''}
      ${p.ai_adaptation ? `<div class="ap-sec"><div class="h">AI filter adaptation</div>${esc(p.ai_adaptation)}</div>` : ''}
      <div class="ap-sec"><div class="h">Fix</div>${esc(p.remediation)}</div>
    </div>`;
  }

  /* ------------------------------------------------------------------ SBOM / reachability */
  const sbom = { data: null, status: 'ALL', q: '', page: 25, open: new Set() };
  async function loadSbom(refresh) {
    const host = $('intelSbom');
    host.innerHTML = `<div style="padding:1.5rem;color:var(--text-muted)">${refresh ? 'Refreshing' : 'Building'} SBOM, querying OSV / EPSS / CISA KEV and tracing call paths…</div>`;
    try {
      sbom.data = await getJSON(`/api/sca/reachability?source_path=${encodeURIComponent(srcPath())}${refresh ? '&refresh=true' : ''}`);
      renderSbom();
    } catch (e) { host.innerHTML = `<div class="console-line warn">SCA error: ${esc(e.message)}</div>`; }
  }
  const STATUS_ORDER = ['Reachable', 'Unknown', 'Imported-only', 'Present-only'];

  // Bonus-requirement scorecard: maps each of the 5 "reachability-aware SCA" requirements from the problem
  // statement to the live numbers in THIS report, with a jump link to the section that proves it.
  function bonusChecklist(d) {
    const s = d.summary, ds = d.data_sources, V = d.vulnerabilities, SC = d.supply_chain;
    const viaKept = d.components.filter((c) => !c.direct && c.via).length;
    const ghsa = V.filter((v) => v.id.startsWith('GHSA-') || (v.aliases || []).some((a) => a.startsWith('GHSA-'))).length;
    const withFix = V.filter((v) => (v.fixed_versions || []).length).length;
    const withCvss = V.filter((v) => v.cvss != null).length;
    const withEpss = V.filter((v) => v.epss != null).length;
    const curated = V.filter((v) => (v.symbol_source || '').startsWith('curated')).length;
    const derived = V.filter((v) => (v.symbol_source || '').startsWith('derived')).length;
    const withPath = V.filter((v) => v.call_path).length;
    const cat = (c) => SC.filter((f) => f.category === c && f.severity !== 'INFO').length;
    const lockMissing = SC.some((f) => f.category === 'unpinned-lockfile');
    const rows = [
      ['1', 'Inventory', 'Parse lockfiles into an SBOM, keeping transitive paths', 'sbomSecAdv',
        `${s.components} components (${s.direct} direct / ${s.transitive} transitive) · ${viaKept} transitive paths kept as <code>via</code> · ` +
        `${lockMissing ? 'no lockfile in repo → resolved from build.gradle + BOM' : 'gradle.lockfile parsed'} · CycloneDX 1.5 export`],
      ['2', 'GHSA match', 'Affected versions, fixes, CVSS, EPSS and KEV', 'sbomSecAdv',
        `${V.length} advisories (${ghsa} GHSA) via OSV [${esc(ds.osv)}] · ${withFix} with fix versions · ${withCvss} CVSS · ${withEpss} EPSS [${esc(ds.epss)}] · ${s.kev_total} on CISA KEV [${esc(ds.kev)}]`],
      ['3', 'Function map', 'Vulnerable functions from OSV symbols / fix-commit diffs', 'sbomSecAdv',
        `${curated + derived}/${V.length} advisories mapped to symbols (${curated} curated from fix commits, ${derived} extracted from advisory text) · rest kept <b>Unknown</b>`],
      ['4', 'Call graph', 'Entry point → app function → library function', 'sbomSecGraph',
        `${withPath} HTTP-entrypoint call paths traced through Vajra's own AST function graph (not CodeQL/Joern) · ${s.by_status.Reachable} Reachable · ${s.kev_reachable} KEV reachable`],
      ['5', 'Supply chain', 'Malicious packages, typosquats, dependency confusion, unpinned lockfiles', 'sbomSecSupply',
        `malicious: ${cat('malicious-package')} · typosquat: ${cat('typosquat')} · dep-confusion: ${cat('dependency-confusion')} · unpinned lockfile: ${cat('unpinned-lockfile')} · floating images: ${cat('floating-tag')}`],
    ];
    const st = ['Reachable', 'Imported-only', 'Present-only', 'Unknown'].map((k) => `<span class="status-pill st-${k}">${k}: ${s.by_status[k]}</span>`).join(' ');
    return `<div class="ai-summary-card" style="margin:.6rem 0">
      <div style="font-weight:700;font-size:.9rem;margin-bottom:.4rem">Bonus feature: reachability-aware SCA — requirement checklist <span class="badge badge-suppressed">live from this scan</span></div>
      <div class="table-scroll-container"><table><thead><tr><th>#</th><th>Requirement</th><th>Evidence in this report</th><th></th></tr></thead><tbody>
      ${rows.map(([n, name, req, sec, ev]) => `<tr><td><b>${n}</b></td><td><b>✓ ${name}</b><br><span style="font-size:.7rem;color:var(--text-muted)">${req}</span></td>
        <td style="font-size:.76rem">${ev}</td><td><a href="#" onclick="document.getElementById('${sec}').scrollIntoView({behavior:'smooth'});return false;" style="font-size:.72rem">view ↓</a></td></tr>`).join('')}
      </tbody></table></div>
      <div style="margin-top:.4rem;font-size:.76rem">Statuses: ${st} <span style="color:var(--text-dim)">· Unknown is never downgraded</span></div>
    </div>`;
  }

  function renderSbom() {
    const d = sbom.data, s = d.summary, ds = d.data_sources;
    const srcb = (k, v) => `<span class="src-badge ${v === 'live' ? 'live' : ''}">${k}: ${esc(v)}</span>`;
    $('intelSbom').innerHTML = `
      <div class="card-desc" style="margin-top:.4rem">
        <b>Reachability-aware SCA:</b> a CVE only matters if the app can actually reach the vulnerable function. Each advisory is mapped to its vulnerable symbols, then traced
        <b>HTTP entrypoint → app method → library symbol</b> through the function graph. <b>Unknown is never downgraded</b>.
        Also covers the container layer (Dockerfile, docker-compose, Kubernetes) and exports CycloneDX 1.5.
      </div>
      ${bonusChecklist(d)}
      <div style="margin:.4rem 0">${srcb('OSV', ds.osv)}${srcb('EPSS', ds.epss)}${srcb('CISA KEV', ds.kev + (ds.kev_catalog_version ? ' ' + ds.kev_catalog_version : ''))}
        ${srcb('Spring Boot BOM', ds.spring_boot_bom)}${srcb('Function map', 'curated + advisory text')}
        <span class="src-badge" title="${esc(ds.container_advisories)}">container CVEs: not scanned</span></div>
      <div class="chip-row">
        <div class="stat-chip"><div class="v">${s.components}</div><div class="l">Components (${s.direct} direct / ${s.transitive} transitive)</div></div>
        <div class="stat-chip"><div class="v">${s.container_images}</div><div class="l">Container images</div></div>
        <div class="stat-chip"><div class="v">${s.vulnerabilities}</div><div class="l">Advisories matched</div></div>
        <div class="stat-chip bad"><div class="v">${s.by_status.Reachable}</div><div class="l">Reachable</div></div>
        <div class="stat-chip purple"><div class="v">${s.by_status.Unknown}</div><div class="l">Unknown (kept)</div></div>
        <div class="stat-chip warn"><div class="v">${s.by_status['Imported-only']}</div><div class="l">Imported-only</div></div>
        <div class="stat-chip"><div class="v">${s.by_status['Present-only']}</div><div class="l">Present-only</div></div>
        <div class="stat-chip good"><div class="v">${s.deprioritised_by_reachability}</div><div class="l">De-prioritised by reachability</div></div>
        <div class="stat-chip warn"><div class="v">${s.kev_total}</div><div class="l">On CISA KEV (${s.kev_reachable} reachable)</div></div>
      </div>
      <div class="intel-toolbar">
        <button class="btn btn-emerald" id="sbomRefresh" style="padding:.35rem .8rem;font-size:.75rem">Refresh advisories</button>
        <a class="btn btn-outline" href="/api/sca/cyclonedx?source_path=${encodeURIComponent(srcPath())}" download style="padding:.35rem .8rem;font-size:.75rem">CycloneDX 1.5 SBOM</a>
      </div>
      <div class="section-title" id="sbomSecGraph">Reachability call graph <span class="badge badge-code">entrypoint → app method → library symbol → library → advisory</span></div>
      <div id="sbomCanvas"></div>
      <div id="sbomInspector" class="inspector">Click a node to trace the lineage from the HTTP entrypoint to the advisory.</div>
      <div class="section-title" id="sbomSecAdv">Advisories</div>
      <div class="intel-toolbar">
        ${['ALL', ...STATUS_ORDER].map((k) => `<button class="filter-pill ${sbom.status === k ? 'active' : ''}" data-st="${k}">${k === 'ALL' ? 'All' : k} (${k === 'ALL' ? s.vulnerabilities : s.by_status[k]})</button>`).join('')}
        <input id="sbomQ" placeholder="search package / CVE" value="${esc(sbom.q)}" style="width:220px">
      </div>
      <div id="sbomVulns"></div>
      <div class="section-title">Docker / Kubernetes SBOM</div>
      <div id="sbomDocker"></div>
      <div class="section-title" id="sbomSecSupply">Supply-chain findings <span class="badge badge-runtime">${s.supply_chain_findings} actionable</span></div>
      <div id="sbomSupply"></div>`;
    $('sbomRefresh').onclick = () => loadSbom(true);
    document.querySelectorAll('#intelSbom .filter-pill').forEach((b) => (b.onclick = () => { sbom.status = b.dataset.st; sbom.page = 25; renderSbomTables(); document.querySelectorAll('#intelSbom .filter-pill').forEach((x) => x.classList.toggle('active', x === b)); }));
    $('sbomQ').oninput = (e) => { sbom.q = e.target.value; sbom.page = 25; renderSbomTables(); };
    const nodes = d.canvas.nodes.map((n) => ({ ...n, module: n.kind }));
    const SC = { Reachable: '#da1e28', Unknown: '#8a3ffc', 'Imported-only': '#b28600', 'Present-only': '#a8a8a8' };
    drawLayered($('sbomCanvas'), nodes, d.canvas.edges, {
      legend: Object.entries(SC).map(([k, c]) => `<span><i style="background:${c}"></i>${k}</span>`).join(''),
      color: (n) => SC[n.status] || '#6f6f6f',
      t1: (n) => n.label,
      t2: (n) => n.kind === 'advisory' ? `advisory · CVSS ${n.cvss ?? '?'}${n.kev ? ' · KEV' : ''} · EPSS ${n.epss ?? '–'}` : n.kind === 'entrypoint' ? (n.routes || []).slice(0, 1).join('') || 'HTTP entrypoint' : n.kind,
      onSelect: (n) => { $('sbomInspector').innerHTML = n ? `<h4>${esc(n.label)} <span class="status-pill st-${esc(n.status)}">${esc(n.status)}</span></h4><div class="kv"><span>Kind</span><span>${esc(n.kind)}</span></div>${n.routes ? `<div class="kv"><span>Routes</span><span>${n.routes.map((r) => `<span class="mini-chip">${esc(r)}</span>`).join('')}</span></div>` : ''}` : 'Click a node to trace the lineage from the HTTP entrypoint to the advisory.'; },
    });
    renderSbomTables();
  }

  function renderSbomTables() {
    const d = sbom.data;
    const q = sbom.q.toLowerCase();
    const rows = d.vulnerabilities.filter((v) => (sbom.status === 'ALL' || v.status === sbom.status) &&
      (!q || `${v.package} ${v.id} ${(v.cves || []).join(' ')} ${v.summary}`.toLowerCase().includes(q)));
    const shown = rows.slice(0, sbom.page);
    $('sbomVulns').innerHTML = `<div class="table-scroll-container"><table><thead><tr>
      <th>Reachability</th><th>Advisory</th><th>Package</th><th>CVSS</th><th>EPSS</th><th>Fix</th><th>Why</th><th>Priority</th></tr></thead><tbody>
      ${shown.map((v) => {
        const open = sbom.open.has(v.id);
        return `<tr class="adv-row" data-id="${esc(v.id)}" style="cursor:pointer">
          <td><span class="status-pill st-${esc(v.status)}">${esc(v.status)}</span></td>
          <td><code style="font-weight:700">${esc((v.cves && v.cves[0]) || v.id)}</code> ${v.kev ? '<span class="kev-badge">KEV</span>' : ''}<br><span style="font-size:.7rem;color:var(--text-dim)">${esc(v.id)}</span></td>
          <td>${esc(v.package.split(':')[1])}<br><span style="font-size:.7rem;color:var(--text-muted)">${esc(v.version || '?')} · ${v.direct ? 'direct' : 'via ' + esc((v.via || '').split(':')[1] || '')}</span></td>
          <td><span class="sev-${esc(v.severity)}">${v.cvss ?? '–'}</span></td>
          <td>${v.epss != null ? (v.epss * 100).toFixed(1) + '%' : '–'}</td>
          <td style="font-size:.74rem">${(v.fixed_versions || []).slice(0, 2).map(esc).join(', ') || '–'}</td>
          <td style="font-size:.74rem;max-width:340px">${esc(v.status_reason)}</td>
          <td><b>${v.priority_score}</b></td></tr>
          ${open ? `<tr class="adv-detail"><td colspan="8">
            <div><b>${esc(v.summary)}</b></div>
            <div class="kv" style="display:grid;grid-template-columns:140px 1fr;gap:.2rem .75rem;margin-top:.4rem">
              <span>Vulnerable symbols</span><span>${v.symbols.length ? v.symbols.map((x) => `<span class="mini-chip"><code>${esc(x)}</code></span>`).join('') + ` <small>(${esc(v.symbol_source)})</small>` : 'none known'}</span>
              ${v.symbol_note ? `<span>Note</span><span>${esc(v.symbol_note)}</span>` : ''}
              ${v.call_path ? `<span>Call path</span><span><code>${esc(v.call_path.path)}</code><br>${(v.call_path.routes || []).map((r) => `<span class="mini-chip">${esc(r)}</span>`).join('')}</span>` : ''}
              ${v.call_sites.length ? `<span>Call sites</span><span>${v.call_sites.slice(0, 4).map((c) => `<code>${esc(c.file.split('/').pop())}:${c.line}</code> ${esc(c.snippet)}`).join('<br>')}</span>` : ''}
              ${v.importing_files.length ? `<span>Imported by</span><span>${v.importing_files.slice(0, 4).map((f) => `<code>${esc(f.split('/').pop())}</code>`).join(' ')}${v.importing_files.length > 4 ? ' …' : ''}</span>` : ''}
              <span>References</span><span>${(v.references || []).map((r) => `<a href="${esc(r)}" target="_blank" rel="noopener">${esc(r.slice(0, 70))}</a>`).join('<br>')}</span>
            </div></td></tr>` : ''}`;
      }).join('')}
      </tbody></table></div>
      ${rows.length > shown.length ? `<button class="btn btn-outline" id="sbomMore" style="margin-top:.5rem;font-size:.75rem">Show ${Math.min(50, rows.length - shown.length)} more (${rows.length - shown.length} hidden)</button>` : ''}
      <div style="font-size:.72rem;color:var(--text-dim);margin-top:.3rem">${rows.length} advisories · click a row for symbols, call path and references</div>`;
    document.querySelectorAll('#sbomVulns .adv-row').forEach((tr) => (tr.onclick = () => { const id = tr.dataset.id; sbom.open.has(id) ? sbom.open.delete(id) : sbom.open.add(id); renderSbomTables(); }));
    if ($('sbomMore')) $('sbomMore').onclick = () => { sbom.page += 50; renderSbomTables(); };

    const dk = d.docker;
    const risk = (img) => { const [n, , t] = img.partition ? [img] : [img]; return ''; };
    const imgRows = [...new Map(dk.containers.map((c) => [c.image + c.source + c.role, c])).values()];
    $('sbomDocker').innerHTML = `<div class="table-scroll-container"><table><thead><tr><th>Image</th><th>Role</th><th>Source</th><th>Pinning</th></tr></thead><tbody>
      ${imgRows.map((c) => {
        const tag = c.image.includes(':') ? c.image.split(':').pop() : 'latest';
        const pin = c.image.includes('@sha256:') ? '<span class="badge badge-suppressed">digest</span>' : (tag === 'latest' ? '<span class="badge badge-confirmed">:latest floating</span>' : '<span class="badge badge-runtime">tag only</span>');
        return `<tr><td><code>${esc(c.image)}</code></td><td>${esc(c.role)}</td><td><code>${esc(c.source)}</code></td><td>${pin}</td></tr>`;
      }).join('')}</tbody></table></div>
      <div style="margin-top:.5rem;font-size:.78rem;color:var(--text-muted)">
        OS packages: ${dk.os_packages.map((p) => `<span class="mini-chip">${esc(p.name)} ${p.pinned ? '' : '(unpinned)'}</span>`).join('') || 'none'} ·
        Dockerfiles: ${dk.dockerfiles.map((f) => `<code>${esc(f.file)}</code> (${f.users.length ? 'USER ' + esc(f.users.join(',')) : 'runs as root'})`).join(', ') || 'none'} ·
        Compose services: ${dk.compose.length} · Kubernetes workloads: ${dk.k8s.length || '0 (no manifests in repo)'}</div>`;
    const sev = { HIGH: 'badge-confirmed', MEDIUM: 'badge-runtime', LOW: 'badge-code', INFO: 'badge-tool' };
    $('sbomSupply').innerHTML = `<div class="table-scroll-container"><table><thead><tr><th>Severity</th><th>Category</th><th>Finding</th><th>Evidence</th></tr></thead><tbody>
      ${d.supply_chain.map((f) => `<tr><td><span class="badge ${sev[f.severity] || 'badge-tool'}">${esc(f.severity)}</span></td><td>${esc(f.category)}</td>
        <td style="font-weight:600">${esc(f.title)}<br><span style="font-weight:400;font-size:.72rem;color:var(--text-muted)">${esc(f.detail)}</span></td>
        <td style="font-size:.7rem"><code>${esc(f.evidence.slice(0, 160))}</code></td></tr>`).join('')}</tbody></table></div>`;
  }

  /* ------------------------------------------------------------------ SAST engine attribution */
  window.renderEngineAttribution = function (rep) {
    const host = $('engineAttributionCard');
    if (!host || !rep) return;
    host.style.display = 'block';
    const engines = rep.engines.filter((e) => !e.engine.startsWith('Sanitizer'));
    const decoy = rep.engines.find((e) => e.engine.startsWith('Sanitizer'));
    const total = rep.engine_combinations.reduce((a, c) => a + c.count, 0) || 1;
    // single-engine rows keep that engine's own colour; combinations take the next unused palette colour
    const used = new Set(Object.values(ENGINE_COLOR));
    const spare = CARBON_CATEGORICAL.filter((c) => !used.has(c));
    let k = 0;
    const combos = rep.engine_combinations.map((c) => ({ ...c,
      color: !c.engines.includes(' + ') && ENGINE_COLOR[c.engines] ? ENGINE_COLOR[c.engines] : spare[k++ % spare.length] }));
    const statusTag = (st) => st === 'OK' ? '<span class="cds-tag cds-tag--green">Ran</span>'
      : st === 'NOT_APPLICABLE' ? '<span class="cds-tag cds-tag--gray">Not applicable</span>'
      : `<span class="cds-tag cds-tag--red">${esc(String(st || 'Error').toLowerCase().replace(/_/g, ' '))}</span>`;
    const kv = (k, v) => `<div class="cds-sl-row"><span>${k}</span><span class="cds-num">${v}</span></div>`;
    const tile = (e) => `
      <div class="cds-tile">
        <div class="cds-tile-head"><span class="cds-swatch" style="background:${colorFor(e.engine)}"></span>
          <span class="cds-tile-name">${esc(e.engine)}</span>${statusTag(e.status)}</div>
        <div class="cds-helper">${esc(e.kind || '')}${e.version ? ' · ' + esc(String(e.version)) : ''}${e.mode ? ' · ' + esc(e.mode) : ''}</div>
        ${e.status === 'OK' ? `
          <div class="cds-kpi"><span class="cds-kpi-num">${e.findings_after_merge}</span><span class="cds-kpi-label">sinks flagged</span></div>
          <div class="cds-sl">
            ${kv('Found only by this engine', e.unique_findings)}
            ${kv('Corroborated by another', e.corroborated_findings)}
            ${kv('Decoys identified', e.decoys_identified)}
            ${e.ground_truth_recall_pct != null ? kv('Benchmark recall, alone', e.ground_truth_recall_pct + '%') : ''}
          </div>
          ${e.java_optimizations ? `<div class="cds-helper cds-foot">${esc(e.java_optimizations)}</div>` : ''}`
        : `<div class="cds-helper" style="margin-top:.75rem">${esc(e.reason || '')}</div>`}
      </div>`;
    const conflicts = rep.merge.engine_conflicts || [];
    host.innerHTML = `
      <div class="cds-section-head">
        <div>
          <h3 class="cds-h3">Engine attribution and merge</h3>
          <p class="cds-body">Each engine runs independently. Findings on the same sink (same file and CWE, at most 3 lines apart) merge into one issue that records every engine that flagged it.</p>
        </div>
        <div class="cds-stat-strip">
          <div><span class="cds-num-lg">${rep.merge.cross_engine_merges}</span><span class="cds-kpi-label">cross-engine merges</span></div>
          <div><span class="cds-num-lg">${rep.merge.corroborated_sinks}</span><span class="cds-kpi-label">sinks found by 2+ engines</span></div>
          <div><span class="cds-num-lg">${conflicts.length}</span><span class="cds-kpi-label">disagreements</span></div>
        </div>
      </div>
      <div class="cds-tile-grid">
        ${engines.map(tile).join('')}
        ${decoy ? `<div class="cds-tile">
          <div class="cds-tile-head"><span class="cds-swatch" style="background:${colorFor(decoy.engine)}"></span>
            <span class="cds-tile-name">${esc(decoy.engine)}</span><span class="cds-tag cds-tag--green">Ran</span></div>
          <div class="cds-helper">Guard and sanitiser checks</div>
          <div class="cds-kpi"><span class="cds-kpi-num">${decoy.decoys_identified}</span><span class="cds-kpi-label">safe decoys suppressed</span></div>
          ${decoy.java_optimizations ? `<div class="cds-helper cds-foot">${esc(decoy.java_optimizations)}</div>` : ''}
        </div>` : ''}
      </div>

      <h4 class="cds-h4">Which engines found the ${total} merged active sinks</h4>
      <div class="cds-meter" role="img" aria-label="Share of sinks by engine combination">
        ${combos.map((c) => `<div style="width:${(c.count / total) * 100}%;background:${c.color}" title="${esc(c.engines)}: ${c.count}"></div>`).join('')}
      </div>
      <table class="cds-legend">
        <thead><tr><th>Engine combination</th><th class="r">Sinks</th><th class="r">Share</th></tr></thead>
        <tbody>${combos.map((c) => `<tr><td><span class="cds-swatch" style="background:${c.color}"></span>${esc(c.engines)}</td>
          <td class="r cds-num">${c.count}</td><td class="r cds-num">${((c.count / total) * 100).toFixed(1)}%</td></tr>`).join('')}</tbody>
      </table>

      ${conflicts.length ? `<div class="cds-notification cds-notification--warning">
        <div class="cds-notification-title">Engines disagreed on ${conflicts.length} sink${conflicts.length === 1 ? '' : 's'}</div>
        <ul>${conflicts.map((c) => `<li><code>${esc(c.file.split('/').pop())}:${c.line}</code> flagged by ${esc(c.flagged_by.join(', '))}; suppressed by ${esc(c.suppressed_by.join(', '))}. ${esc(c.reason || '')}</li>`).join('')}</ul>
      </div>` : ''}
      ${(rep.notes || []).length ? `<div class="cds-helper" style="margin-top:1rem">${rep.notes.map(esc).join(' ')}</div>` : ''}`;
  };

  /* ------------------------------------------------------------------ DAST hand-off stats */
  window.renderDastStats = function (st, aiPayloads, aiNote) {
    const host = $('dastStatsCard');
    if (!host || !st) return;
    host.style.display = 'block';
    const modeName = { sast_guided: 'SAST-guided only', 'sast_guided+independent': 'SAST-guided and independent', independent: 'Independent only' }[st.mode] || st.mode;
    const bd = st.findings_by_discovery || {};
    const ai = aiPayloads || [];
    const kpi = (num, label, sub) => `<div class="cds-tile cds-tile--kpi"><div class="cds-kpi-label">${label}</div>
      <div class="cds-kpi"><span class="cds-kpi-num">${num}</span>${sub ? `<span class="cds-kpi-label">${sub}</span>` : ''}</div></div>`;
    const da = st.decoy_audit || {};
    const tiles = [
      kpi(st.endpoints_probed, 'Routes probed', `of ${st.unique_routes_total} unique`),
      kpi(st.requests_sent, 'HTTP requests sent'),
      kpi(st.findings_total, 'Findings'),
      kpi(bd['sast-guided'] || 0, 'From SAST hand-off'),
      kpi(st.independent_new_findings, 'DAST-only, beyond SAST'),
      st.mode === 'sast_guided' ? kpi(`${st.endpoint_reduction_pct}%`, 'Fewer routes than a blind scan') : '',
      da.enabled ? kpi(`${da.validated_safe}/${da.routes_probed}`, 'Decoys validated safe', da.violations ? `${da.violations} violated` : '') : '',
      st.katana && st.katana.available ? kpi(st.katana.new_endpoints, 'New endpoints from crawl') : '',
    ].join('');
    const notes = [];
    if (st.independent_new_examples && st.independent_new_examples.length)
      notes.push('DAST-only examples: ' + st.independent_new_examples.slice(0, 4).map((x) => `<code>${esc(x.cwe)} ${esc((x.url || '').replace(/^https?:\/\/[^/]+/, ''))}</code>`).join(', '));
    if (st.katana) notes.push(st.katana.available ? `katana crawl (no source knowledge) found ${st.katana.new_endpoints} endpoint(s) not already in the route map.` : `katana: ${esc(st.katana.reason || 'not available')}.`);
    const aiRows = ai.map((a) => `
      <tr><td><span class="cds-tag cds-tag--gray">${esc(a.cwe)}</span></td>
        <td><code>${esc(a.route)}</code><div class="cds-helper">param <code>${esc(a.param || '')}</code></div></td>
        <td>${esc(a.technique || '')}${a.guard_basis ? `<div class="cds-helper">Guard: <code>${esc(a.guard_basis)}</code></div>` : ''}</td>
        <td><code class="cds-wrap">${esc(a.payload || '')}</code></td>
        <td><span class="cds-tag ${a.engine && a.engine.includes('live') ? 'cds-tag--green' : 'cds-tag--gray'}">${esc(a.engine || 'AI')}</span></td></tr>`).join('');
    host.innerHTML = `
      <div class="cds-section-head">
        <div>
          <h3 class="cds-h3">DAST run</h3>
          <p class="cds-body">Mode: ${esc(modeName)}. Guided routes use CWE hints from the SAST sinks each route reaches. Only classes an HTTP probe can prove are handed over; crypto, secrets and auth-logic sinks stay Code only.</p>
        </div>
        ${st.target_online ? '<span class="cds-tag cds-tag--green">Live HTTP</span>' : '<span class="cds-tag cds-tag--red">Target unreachable</span>'}
      </div>
      ${st.target_note ? `<div class="cds-notification cds-notification--info"><div class="cds-notification-title">Target address rewritten</div>${esc(st.target_note)}</div>` : ''}
      ${!st.target_online ? `<div class="cds-notification cds-notification--error"><div class="cds-notification-title">No DAST findings</div>${esc(st.offline_reason || 'The target did not respond.')}</div>` : ''}
      <div class="cds-tile-grid cds-tile-grid--kpi">${tiles}</div>
      ${notes.length ? `<div class="cds-helper" style="margin-top:.75rem">${notes.join('<br>')}</div>` : ''}
      <h4 class="cds-h4">AI filter-bypass log <span class="cds-tag cds-tag--gray" style="margin-left:.5rem">${ai.length} payload${ai.length === 1 ? '' : 's'}</span></h4>
      <p class="cds-body" style="margin-bottom:.75rem">When SAST finds a real guard on a reachable sink, its source text is sent to the AI and the returned payload is fired as an HTTP request. Unchanged guard text is served from cache.</p>
      ${ai.length ? `<table class="cds-legend cds-structured"><thead><tr><th style="width:9%">CWE</th><th style="width:22%">Route</th><th style="width:25%">Technique</th><th>Payload</th><th style="width:14%">Engine</th></tr></thead><tbody>${aiRows}</tbody></table>`
        : `<div class="cds-empty">${esc(aiNote || 'No AI-driven findings this run.')}</div>`}`;
  };

  /* ------------------------------------------------------------------ inspect modal extras */
  window.renderIssueProvenanceHtml = function (issue) {
    const vb = issue.vector_breakdown || {};
    const engines = vb.sast_engines || (issue.scanners_matched || []).filter((s) => ENGINE_COLOR[s] && !s.startsWith('Vajra-'));
    const dast = (issue.scanners_matched || []).filter((s) => s.startsWith('Vajra-'));
    const disc = vb.dast_discoveries || (vb.dast_discovery ? [vb.dast_discovery] : []);
    let h = '<div style="margin-top:.8rem;border-top:1px dashed var(--border);padding-top:.6rem;font-size:.76rem">';
    h += `<div style="font-weight:700;margin-bottom:.25rem">Provenance</div>`;
    h += `<div><b>SAST engines:</b> ${engines.length ? window.enginePills(engines) : '<span style="color:var(--text-dim)">n/a</span>'}</div>`;
    if (dast.length || disc.length) h += `<div><b>DAST:</b> ${window.enginePills(dast)} ${disc.map((d) => window.discoveryPill(d, vb.runtime_origin)).join(' ')}</div>`;
    if (vb.engine_consensus && vb.engine_consensus.bonus) h += `<div><b>Consensus bonus:</b> +${vb.engine_consensus.bonus} (${vb.engine_consensus.engines.length} engines agree)</div>`;
    if (vb.handler_hint) h += `<div><b>Handler:</b> <code>${esc(vb.handler_hint)}</code> ${vb.sast_gap ? '<span class="disc-pill disc-decoy">SAST GAP — DAST proved it, SAST did not flag this CWE</span>' : ''}</div>`;
    if (vb.decoy_violation) h += `<div style="color:var(--crimson)"><b>Decoy violated:</b> SAST suppressed this route as Variant.SECURE, but DAST exploited it — review the suppression.</div>`;
    const p = vb.propagation;
    if (p) {
      h += `<div style="margin-top:.5rem;font-weight:700">Root-sink propagation</div>
        <div>Root cause lives in <b>${esc(p.root_module)}</b> (${p.root_methods.slice(0, 3).map((m) => `<code>${esc(m)}</code>`).join(', ')}${p.root_methods.length > 3 ? ' …' : ''}).
        Reached from <b>${p.reachable_endpoints}</b> endpoint(s)${p.importing_modules.length ? ' via importing module(s) ' + p.importing_modules.map((m) => `<span class="mini-chip imp">${esc(m)}</span>`).join('') : ''}.
        <b style="color:var(--emerald)">${p.alerts_without_graph} per-endpoint alerts → 1 issue.</b></div>
        ${p.example_path ? `<div style="margin-top:.2rem"><code style="font-size:.7rem">${esc(p.example_path)}</code></div>` : ''}
        ${p.endpoint_examples && p.endpoint_examples.length ? `<div style="margin-top:.2rem">${p.endpoint_examples.map((u) => `<span class="mini-chip">${esc(u)}</span>`).join('')}</div>` : ''}`;
    }
    return h + '</div>';
  };

  /* ------------------------------------------------------------------ panel wiring */
  let intelTab = 'graph';
  window.intelSwitch = function (tab) {
    intelTab = tab;
    document.querySelectorAll('#panel5 .intel-tabbtn').forEach((b) => b.classList.toggle('active', b.dataset.tab === tab));
    ['Graph', 'Patterns', 'Sbom'].forEach((n) => $('intel' + n).classList.toggle('active', n.toLowerCase() === tab));
    window.intelLoad(false);
  };
  window.intelLoad = function (force) {
    if (intelTab === 'graph' && (force || !fg.data)) loadFunctionGraph();
    if (intelTab === 'patterns') loadPatterns();
    if (intelTab === 'sbom' && (force || !sbom.data)) loadSbom(false);
  };
  window.intelOnShow = function () { window.intelLoad(false); };
  window.intelReset = function () { fg.data = null; sbom.data = null; };
})();
