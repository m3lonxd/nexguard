// NexGuard panel — nokta bulutu telemetri arayüzü.
// Veri: /api/v1/servers, /api/v1/findings, /api/v1/actions ve WebSocket /api/v1/stream.
// Dış bağımlılık yok. Tüm hareket deterministiktir (tohumlu RNG); prefers-reduced-motion
// altında animasyon yoktur, çizim yalnızca veri/boyut değişince yapılır.
(() => {
  "use strict";

  const THRESHOLD = 5; // ajanın varsayılan SSH kaba kuvvet eşiği
  const WINDOW_MIN = 60;
  const HOURS = 24;
  const TOP_IPS = 8;
  const MAX_FINDING_ROWS = 16;
  const MAX_ACTION_ROWS = 8;
  const MOBILE_FINDING_ROWS = 7;
  const MOBILE_ACTION_ROWS = 4;
  const MAX_SERVER_ROWS = 4;

  const MONO = '"JetBrains Mono","IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace';
  const COL = { bg: "#060606", p0: "#FEFEFE", p1: "#BEBFC1", p2: "#9D9D9F", p3: "#7E7E81", p4: "#5B5B5C", p5: "#3F3F40", txt: "#E8E8E8", warn: "#E0A43A" };
  const BIN_COLORS = [COL.p5, COL.p4, COL.p3, COL.p2, COL.p1, COL.p0];

  const $ = (id) => document.getElementById(id);
  const rmQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
  const reduced = () => rmQuery.matches;

  // ---------- yardımcılar ----------
  function mulberry32(seed) {
    let a = seed >>> 0;
    return () => {
      a = (a + 0x6d2b79f5) >>> 0;
      let t = a;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  const clamp = (v, a, b) => (v < a ? a : v > b ? b : v);
  const easeIO = (t) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);
  const pad2 = (n) => String(n).padStart(2, "0");

  function fmtClock(ms) {
    const d = new Date(ms);
    return pad2(d.getHours()) + ":" + pad2(d.getMinutes()) + ":" + pad2(d.getSeconds());
  }
  function fmtDateTime(ts) {
    if (!ts) return "—";
    const d = new Date(ts);
    if (isNaN(d)) return "—";
    return pad2(d.getDate()) + "." + pad2(d.getMonth() + 1) + " " + pad2(d.getHours()) + ":" + pad2(d.getMinutes());
  }
  function fmtShortDate(ts) {
    const d = new Date(ts);
    if (isNaN(d)) return "—";
    return pad2(d.getDate()) + "." + pad2(d.getMonth() + 1) + "." + String(d.getFullYear()).slice(2);
  }
  function fmtCountdown(ms) {
    if (ms <= 0) return "00:00";
    const s = Math.floor(ms / 1000);
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    return (h ? h + ":" + pad2(m) : pad2(m)) + ":" + pad2(sec);
  }
  // Go time.Duration.String() çıktısı: "1h0m0s", "30m0s", "1.5s", "250ms"
  function parseGoDuration(str) {
    if (typeof str !== "string" || !str) return null;
    const re = /(\d+(?:\.\d+)?)(ms|h|m|s)/g;
    const unit = { h: 3600000, m: 60000, s: 1000, ms: 1 };
    let total = 0, found = false, m;
    while ((m = re.exec(str))) {
      total += parseFloat(m[1]) * unit[m[2]];
      found = true;
    }
    return found ? total : null;
  }
  function ipOf(f) {
    const ip = f && f.evidence && f.evidence.ip;
    return typeof ip === "string" ? ip : "";
  }
  function attemptsOf(f) {
    const n = Number(f && f.evidence && f.evidence.attempts);
    return Number.isFinite(n) && n > 0 ? n : 1;
  }
  function shortIP(ip, n) {
    return ip.length > n ? ip.slice(0, n - 1) + "…" : ip;
  }

  // ---------- durum ----------
  const state = {
    servers: [],
    findings: [],
    actions: [],
    lastUpdate: null,
    live: false,
  };
  let derived = null;

  function hostnameFor(id) {
    const s = state.servers.find((x) => x.id === id);
    return s ? s.hostname : id || "—";
  }

  function actionInfo(a) {
    const p = a.params || {};
    const ttlMs = parseGoDuration(p.ttl);
    const appliedMs = Date.parse(a.applied_at);
    const reverted = !!a.reverted_at || p.status === "reverted";
    let expiresAt = null;
    if (ttlMs != null && !isNaN(appliedMs)) expiresAt = appliedMs + ttlMs;
    return { p, ttlMs, appliedMs, reverted, expiresAt, ip: typeof p.ip === "string" ? p.ip : "" };
  }

  function isActiveBlock(a, now) {
    if (a.action_type !== "block_ip") return false;
    const i = actionInfo(a);
    if (i.p.status !== "applied" || i.reverted || !i.ip) return false;
    return i.expiresAt == null || i.expiresAt > now;
  }

  // Bulgulardan arazi (son 60 dk, dakikalık kovalar, IP başına) ve histogram (24 saat) verisi.
  function derive(now) {
    const byIP = new Map();
    const ghostByIP = new Map(); // önceki 60 dk penceresi (60–120 dk önce)
    const hours = new Array(HOURS).fill(0);
    const d0 = new Date(now);
    d0.setMinutes(0, 0, 0);
    const h0 = d0.getTime();
    let total = 0;

    for (const f of state.findings) {
      const t = Date.parse(f.created_at);
      if (isNaN(t)) continue;
      const att = attemptsOf(f);
      const age = Math.max(0, now - t);
      const hIdx = HOURS - 1 - (t >= h0 ? 0 : Math.ceil((h0 - t) / 3600000));
      if (hIdx >= 0 && hIdx < HOURS) hours[hIdx] += att;
      const ip = ipOf(f);
      if (ip && age > WINDOW_MIN * 60000 && age <= 2 * WINDOW_MIN * 60000) {
        let g = ghostByIP.get(ip);
        if (!g) { g = new Float32Array(WINDOW_MIN); ghostByIP.set(ip, g); }
        g[Math.min(WINDOW_MIN - 1, Math.floor((age - WINDOW_MIN * 60000) / 60000))] += att;
      }
      if (!ip || age > WINDOW_MIN * 60000) continue;
      const m = Math.min(WINDOW_MIN - 1, Math.floor(age / 60000));
      let r = byIP.get(ip);
      if (!r) {
        r = { ip, total: 0, buckets: new Float32Array(WINDOW_MIN), last: 0 };
        byIP.set(ip, r);
      }
      r.buckets[m] += att;
      r.total += att;
      r.last = Math.max(r.last, t);
      total += att;
    }

    const all = [...byIP.values()].sort((a, b) => b.total - a.total || a.ip.localeCompare(b.ip));
    const rows = all.slice(0, TOP_IPS);
    const blocked = new Set();
    for (const a of state.actions) if (isActiveBlock(a, now)) blocked.add(actionInfo(a).ip);
    rows.forEach((r, i) => {
      r.index = i;
      r.blocked = blocked.has(r.ip);
      r.ghost = ghostByIP.get(r.ip) || null;
      let pm = 0;
      for (let m = 1; m < WINDOW_MIN; m++) if (r.buckets[m] > r.buckets[pm]) pm = m;
      r.peakMin = pm;
    });

    return { rows, hidden: all.length - rows.length, total, ips: all.length, hours, h0, blockedCount: blocked.size, blocked, now };
  }

  // ---------- harf karıştırma (scramble) ----------
  const GLYPHS = "0123456789ABCDEF";
  function setText(el, text, animate) {
    if (el.textContent === text && !el._timer) return;
    if (el._timer) { clearTimeout(el._timer); el._timer = 0; }
    if (!animate || reduced() || !text) { el.textContent = text; return; }
    const n = text.length;
    const seed = n * 131 + (text.charCodeAt(0) || 0);
    let f = 0;
    const last = 10;
    const step = () => {
      let out = "";
      for (let i = 0; i < n; i++) {
        const ch = text[i];
        const resolveAt = 3 + Math.floor((i * 7) / Math.max(1, n - 1));
        if (f >= resolveAt || " .:,-/[]·—".includes(ch)) out += ch;
        else out += GLYPHS[Math.floor(mulberry32(seed + i * 7919 + f * 104729)() * 16)];
      }
      el.textContent = out;
      if (f < last && out !== text) { f++; el._timer = setTimeout(step, 34); }
      else { el.textContent = text; el._timer = 0; }
    };
    step();
  }

  // ---------- okuma sütunları ----------
  const rowMaps = { f: new Map(), a: new Map(), s: new Map() };
  const freshIDs = new Set(); // WebSocket'ten yeni gelen satırlar: scramble ile yazılır

  function mkCell(tr, cls) {
    const td = document.createElement("td");
    if (cls) td.className = cls;
    tr.appendChild(td);
    return td;
  }
  function mkSpan(parent, cls) {
    const s = document.createElement("span");
    if (cls) s.className = cls;
    parent.appendChild(s);
    return s;
  }

  // Satırı tıklanabilir yapar: fare, Enter ve boşluk tuşu detay çekmecesini açar.
  function clickable(tr, fn) {
    tr.classList.add("clickable");
    tr.tabIndex = 0;
    tr.addEventListener("click", () => fn(tr));
    tr.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fn(tr); } });
  }

  function reconcile(tbody, map, wanted, build, update) {
    const keep = new Set();
    wanted.forEach((item, i) => {
      const key = item.__key;
      keep.add(key);
      let row = map.get(key);
      const isNew = !row;
      if (isNew) { row = build(item); map.set(key, row.tr); row = row.tr; }
      update(row, item, i, isNew && freshIDs.has(key));
      if (tbody.children[i] !== row) tbody.insertBefore(row, tbody.children[i] || null);
    });
    for (const [key, tr] of map) if (!keep.has(key)) { tr.remove(); map.delete(key); }
  }

  const totals = { f: 0, a: 0 };
  const mobileMQ = window.matchMedia("(max-width: 960px)");

  // Panelin içine sığmayan satırları gizler (yarım satır kalmasın); sayaç görünen/toplam yazar.
  function fitRows() {
    const sets = [
      [".findings", "f-body", "f-count", "f", MOBILE_FINDING_ROWS],
      [".actions", "a-body", "a-count", "a", MOBILE_ACTION_ROWS],
    ];
    for (const [sel, bodyId, countId, k, mobileCap] of sets) {
      const panel = document.querySelector(sel);
      const rows = [...$(bodyId).children];
      rows.forEach((r) => { r.style.display = ""; });
      if (mobileMQ.matches) rows.forEach((r, i) => { if (i >= mobileCap) r.style.display = "none"; });
      else {
        const limit = panel.getBoundingClientRect().bottom - 12;
        rows.forEach((r) => { if (r.getBoundingClientRect().bottom > limit) r.style.display = "none"; });
      }
      const vis = rows.filter((r) => r.style.display !== "none").length;
      $(countId).textContent = vis < totals[k] ? vis + " / " + totals[k] : String(totals[k]);
    }
  }

  function renderFindings() {
    const list = [...state.findings].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
    const shown = list.slice(0, MAX_FINDING_ROWS).map((f) => Object.assign({ __key: f.id }, f));
    totals.f = list.length;
    $("f-empty").hidden = list.length > 0;
    $("f-table").hidden = list.length === 0;
    reconcile($("f-body"), rowMaps.f, shown,
      () => {
        const tr = document.createElement("tr");
        const c = {
          idx: mkCell(tr, "idx"), ip: mkCell(tr), n: mkCell(tr, "num"), u: mkCell(tr), t: mkCell(tr, "num"),
        };
        tr._c = { idx: c.idx, ip: mkSpan(c.ip), sub: mkSpan(c.ip, "sub"), n: c.n, u: c.u, t: mkSpan(c.t), sev: mkSpan(c.t, "sub") };
        tr._cells = c;
        clickable(tr, (row) => { if (row._ip) Dt.open("ip", row._ip, row); });
        return { tr };
      },
      (tr, f, i, animate) => {
        const c = tr._c;
        const ip = ipOf(f);
        const users = Array.isArray(f.evidence && f.evidence.users_tried) ? f.evidence.users_tried.join(",") : "";
        tr._ip = ip;
        tr.classList.toggle("hp", String(f.type || "").startsWith("honeypot"));
        tr.setAttribute("aria-label", (ip || f.type) + " ayrıntıları");
        setText(c.idx, pad2(i + 1), false);
        setText(c.ip, ip || f.summary || f.type || "—", animate);
        setText(c.sub, hostnameFor(f.server_id) + " · " + (f.type || "—"), animate);
        setText(c.sev, String(f.severity || "—").toUpperCase(), animate);
        const att = f.evidence && f.evidence.attempts != null ? attemptsOf(f) : null;
        setText(c.n, att == null ? "—" : att >= THRESHOLD ? "[ " + att + " ]" : String(att), animate);
        setText(c.u, users || "—", animate);
        setText(c.t, fmtClock(Date.parse(f.created_at)), animate);
        tr._cells.ip.title = f.summary || "";
        tr._cells.u.title = users;
      });
  }

  function statusOf(a) {
    const i = actionInfo(a);
    const st = i.p.status;
    if (i.reverted && st !== "revert_failed") return { label: "GERİ ALINDI", cls: "mute" };
    switch (st) {
      case "applied": return { label: "UYGULANDI", cls: "ok" };
      case "failed": return { label: "BAŞARISIZ", cls: "" };
      case "skipped": return { label: "ATLANDI", cls: "mute" };
      case "revert_failed": return { label: "GERİ ALMA HATASI", cls: "" };
      default: return { label: String(st || a.action_type || "—").toUpperCase(), cls: "mute" };
    }
  }

  function ttlText(a, now) {
    const i = actionInfo(a);
    if (i.p.status !== "applied" || i.reverted) return "—";
    if (i.expiresAt == null) return "—";
    return fmtCountdown(i.expiresAt - now);
  }

  function renderActions() {
    const list = [...state.actions].sort((a, b) => Date.parse(b.applied_at) - Date.parse(a.applied_at));
    const shown = list.slice(0, MAX_ACTION_ROWS).map((a) => Object.assign({ __key: a.id }, a));
    totals.a = list.length;
    $("a-empty").hidden = list.length > 0;
    $("a-table").hidden = list.length === 0;
    const now = Date.now();
    reconcile($("a-body"), rowMaps.a, shown,
      () => {
        const tr = document.createElement("tr");
        const rule = mkCell(tr);
        const c = { rule: mkSpan(rule), sub: mkSpan(rule, "sub"), ttl: mkCell(tr, "num"), st: mkCell(tr, "num") };
        tr._c = c;
        tr._ruleCell = rule;
        clickable(tr, (row) => { if (row._ip) Dt.open("ip", row._ip, row); });
        return { tr };
      },
      (tr, a, i, animate) => {
        const c = tr._c;
        const info = actionInfo(a);
        const p = info.p;
        const main = p.rule || a.action_type || "—";
        const bits = [];
        if (info.ip) bits.push(info.ip);
        if (p.backend) bits.push(p.backend);
        bits.push("SEVİYE " + (a.tier || "—"));
        if (a.reverted_at) bits.push("GERİ " + fmtDateTime(a.reverted_at));
        else bits.push(fmtDateTime(a.applied_at));
        if (p.reason) bits.push(String(p.reason));
        setText(c.rule, String(main), animate);
        setText(c.sub, bits.join(" · "), animate);
        tr._ruleCell.title = bits.join(" · ") + (p.rule ? "" : " · " + JSON.stringify(p));
        setText(c.ttl, ttlText(a, now), false);
        const st = statusOf(a);
        c.st.className = "num " + st.cls;
        setText(c.st, st.label, animate || (tr._st && tr._st !== st.label));
        tr._st = st.label;
        tr._action = a;
        tr._ip = info.ip;
      });
  }

  function tickTTL() {
    const now = Date.now();
    for (const tr of rowMaps.a.values()) if (tr._action) setText(tr._c.ttl, ttlText(tr._action, now), false);
  }

  function renderServers() {
    const list = [...state.servers].sort((a, b) => Date.parse(a.enrolled_at) - Date.parse(b.enrolled_at));
    const shown = list.slice(0, MAX_SERVER_ROWS).map((s) => Object.assign({ __key: s.id }, s));
    $("s-count").textContent = list.length > shown.length ? shown.length + " / " + list.length : String(list.length);
    $("s-empty").hidden = list.length > 0;
    $("s-table").hidden = list.length === 0;
    $("m-servers").textContent = String(list.length);
    $("m-agents").textContent = String(list.filter((s) => s.agent && s.agent.online).length) + " / " + list.length;
    const hpOn = list.filter((s) => s.agent && s.agent.status && s.agent.status.honeypot && s.agent.status.honeypot.enabled).length;
    $("m-hp-n").textContent = hpOn + " / " + list.length;
    $("m-hp").classList.toggle("on", hpOn > 0);
    $("m-hp").disabled = list.length === 0;
    reconcile($("s-body"), rowMaps.s, shown,
      () => {
        const tr = document.createElement("tr");
        tr._c = { h: mkCell(tr), o: mkCell(tr), e: mkCell(tr, "num") };
        clickable(tr, (row) => Dt.open("server", row._sid, row));
        return { tr };
      },
      (tr, s) => {
        tr._sid = s.id;
        tr.classList.toggle("online", !!(s.agent && s.agent.online));
        tr.setAttribute("aria-label", s.hostname + " sunucu ayrıntıları");
        setText(tr._c.h, s.hostname || "—", false);
        setText(tr._c.o, s.os || "—", false);
        setText(tr._c.e, fmtShortDate(s.enrolled_at), false);
        tr._c.h.title = s.hostname || "";
        tr._c.o.title = s.os || "";
      });
  }

  function renderMeta() {
    $("m-updated").textContent = state.lastUpdate ? fmtClock(state.lastUpdate) : "--:--:--";
    $("m-link").textContent = state.live ? "CANLI" : "YENİDEN BAĞLANIYOR";
    $("m-dot").classList.toggle("live", state.live);
  }

  function renderKpis(d) {
    $("k-total").textContent = String(d.total);
    $("k-ips").textContent = String(d.ips);
    $("k-blocked").textContent = String(d.blockedCount);
    document.querySelector(".kpi.warn").classList.toggle("zero", d.blockedCount === 0);
    $("h-total").textContent = d.hours.reduce((a, b) => a + b, 0) + " DENEME";
  }

  // Ekran okuyucu tabloları
  function renderSrTables(d) {
    const hb = $("sr-hist-body");
    hb.textContent = "";
    d.hours.forEach((v, i) => {
      const t = new Date(d.h0 - (HOURS - 1 - i) * 3600000);
      const tr = document.createElement("tr");
      [pad2(t.getHours()) + ":00", String(v)].forEach((x) => {
        const td = document.createElement("td");
        td.textContent = x;
        tr.appendChild(td);
      });
      hb.appendChild(tr);
    });
    $("hist").setAttribute("aria-label", "Son 24 saatte saatlik deneme sayıları, toplam " + d.hours.reduce((a, b) => a + b, 0) + ".");
  }

  // ---------- nokta sprite'ları ----------
  const sprites = BIN_COLORS.map((c) => {
    const s = document.createElement("canvas");
    s.width = s.height = 8;
    const g = s.getContext("2d");
    const grad = g.createRadialGradient(4, 4, 0, 4, 4, 4);
    grad.addColorStop(0, c);
    grad.addColorStop(0.65, c);
    grad.addColorStop(1, "rgba(0,0,0,0)");
    g.fillStyle = grad;
    g.fillRect(0, 0, 8, 8);
    return s;
  });

  function setupCanvas(canvas, stage) {
    const ctx = canvas.getContext("2d");
    const o = { canvas, ctx, W: 0, H: 0, dpr: 1 };
    o.resize = () => {
      const r = stage.getBoundingClientRect();
      const dpr = Math.min(2, window.devicePixelRatio || 1);
      const W = Math.max(1, Math.floor(r.width));
      const H = Math.max(1, Math.floor(r.height));
      if (W === o.W && H === o.H && dpr === o.dpr) return false;
      o.W = W; o.H = H; o.dpr = dpr;
      canvas.width = Math.floor(W * dpr);
      canvas.height = Math.floor(H * dpr);
      return true;
    };
    o.begin = () => {
      ctx.setTransform(o.dpr, 0, 0, o.dpr, 0, 0);
      ctx.globalCompositeOperation = "source-over";
      ctx.globalAlpha = 1;
      ctx.fillStyle = COL.bg;
      ctx.fillRect(0, 0, o.W, o.H);
    };
    return o;
  }

  function setFont(ctx, px, color) {
    ctx.font = px + "px " + MONO;
    ctx.fillStyle = color;
    if ("letterSpacing" in ctx) ctx.letterSpacing = "0.4px";
  }

  // ---------- SALDIRI HARİTASI ----------
  // Son 24 saatin kaynak IP'leri ülke düzeyinde konumlanır (/api/v1/geo). Konum
  // önbelleği oturum boyunca tutulur; çözülemeyen adres null olarak işaretlenir.
  const MAP_HOURS = 24;
  const geoCache = new Map();
  let geoEnabled = null;
  let geoPending = false;
  const Mp = window.NexMap.create($("map"), $("map-stage"), {
    colors: COL, mono: MONO, glCanvas: $("map-gl"),
    onChange: () => { dirty = true; },
    onPick: (ip) => { if (ip) Dt.open("ip", ip, $("map-stage")); },
  });
  // Ekran dışındaki harita çizilmez (mobilde aşağı kaydırınca). IntersectionObserver
  // arka planda açılan sekmede güncellenmeyebildiği için konum her karede ölçülür.
  function mapVisible() {
    const r = $("map-stage").getBoundingClientRect();
    return r.width > 1 && r.bottom > 0 && r.top < window.innerHeight;
  }

  function mapAttackers(now) {
    const by = new Map();
    for (const f of state.findings) {
      const ip = ipOf(f), t = Date.parse(f.created_at);
      if (!ip || isNaN(t) || now - t > MAP_HOURS * 3600000) continue;
      let r = by.get(ip);
      if (!r) { r = { ip, attempts: 0, last: 0, servers: new Set() }; by.set(ip, r); }
      r.attempts += attemptsOf(f);
      r.last = Math.max(r.last, t);
      r.servers.add(f.server_id);
    }
    return [...by.values()].sort((a, b) => b.attempts - a.attempts || a.ip.localeCompare(b.ip));
  }

  async function resolveGeo(ips) {
    const need = ips.filter((ip) => !geoCache.has(ip));
    if (!need.length || geoPending) return false;
    geoPending = true;
    try {
      for (let i = 0; i < need.length; i += 150) {
        const part = need.slice(i, i + 150);
        const q = part.map((ip) => "ip=" + encodeURIComponent(ip)).join("&");
        const res = await getJSON("/api/v1/geo?" + q);
        geoEnabled = !!res.enabled;
        for (const ip of part) geoCache.set(ip, (res.ips && res.ips[ip]) || null);
      }
      return true;
    } catch (e) {
      // ağ hatasında önbelleğe yazılmaz; bir sonraki yenilemede yeniden denenir
      return false;
    } finally {
      geoPending = false;
    }
  }

  function updateMap(now) {
    const all = mapAttackers(now);
    const blocked = derived ? derived.blocked : new Set();
    const placed = [];
    let unresolved = 0;
    for (const a of all) {
      const g = geoCache.get(a.ip);
      if (!g) { if (geoCache.has(a.ip)) unresolved++; continue; }
      placed.push({ ip: a.ip, cc: g.cc, name: g.name, lat: g.lat, lon: g.lon, attempts: a.attempts, blocked: blocked.has(a.ip) });
    }
    const targets = [];
    for (const s of state.servers) if (s.geo) targets.push({ name: s.hostname, lat: s.geo.lat, lon: s.geo.lon });
    let note = "";
    if (geoEnabled === false && all.length) note = "KONUM VERİSİ KAPALI · SUNUCUYU -geoip İLE BAŞLATIN";
    else if (unresolved) note = unresolved + " IP KONUMLANAMADI (YEREL / ÖZEL ADRES)";
    Mp.setData(placed, targets, note);
    const cc = new Map();
    for (const a of placed) cc.set(a.cc, (cc.get(a.cc) || 0) + a.attempts);
    $("map").setAttribute("aria-label", placed.length
      ? "Son 24 saatte " + placed.length + " kaynak IP, " + cc.size + " ülke. En çok: " + [...cc.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3).map((x) => x[0] + " " + x[1]).join(", ") + "."
      : "Son 24 saatte konumlanan saldırı yok.");
    renderSrMap(all);
    dirty = true;
    resolveGeo(all.map((a) => a.ip)).then((changed) => { if (changed) updateMap(Date.now()); });
  }

  function renderSrMap(all) {
    const tb = $("sr-map-body");
    tb.textContent = "";
    const blocked = derived ? derived.blocked : new Set();
    for (const a of all.slice(0, 20)) {
      const g = geoCache.get(a.ip);
      const tr = document.createElement("tr");
      [a.ip, g ? g.name : "Bilinmiyor", String(a.attempts), blocked.has(a.ip) ? "Engelli" : "Engelli değil"].forEach((t) => {
        const td = document.createElement("td");
        td.textContent = t;
        tr.appendChild(td);
      });
      tb.appendChild(tr);
    }
    if (!all.length) {
      const tr = document.createElement("tr"), td = document.createElement("td");
      td.colSpan = 4; td.textContent = "Henüz saldırı yok"; tr.appendChild(td); tb.appendChild(tr);
    }
  }

  function store(key, val) { try { localStorage.setItem(key, val); } catch { /* depolama kapalı */ } }
  function load(key) { try { return localStorage.getItem(key); } catch { return null; } }

  function setMapStyle(style, color, save) {
    Mp.setStyle(style, color);
    document.querySelectorAll("[data-style]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.style === Mp.style)));
    const cb = $("map-color");
    cb.hidden = Mp.style !== "uydu";
    cb.setAttribute("aria-pressed", String(!!color));
    if (save) { store("nexguard.stil", Mp.style); store("nexguard.renk", color ? "1" : "0"); }
    dirty = true;
  }

  function setMapMode(mode, save) {
    Mp.setMode(mode);
    document.querySelectorAll("[data-mode]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.mode === Mp.mode)));
    if (save) { try { localStorage.setItem("nexguard.harita", Mp.mode); } catch { /* depolama kapalı */ } }
    dirty = true;
  }

  // ---------- HİSTOGRAM ----------
  const Hh = setupCanvas($("hist"), $("hist-stage"));
  Hh.vals = { s: new Float32Array(HOURS), g: new Float32Array(HOURS), t0: -1e9, dur: 0, ymaxS: 5, ymaxG: 5, ymax: 5 };
  const HK = 300;
  (function buildHistPoints() {
    const rnd = mulberry32(777);
    Hh.u = new Float32Array(HOURS * HK);
    Hh.jx = new Float32Array(HOURS * HK);
    for (let i = 0; i < Hh.u.length; i++) { Hh.u[i] = rnd(); Hh.jx[i] = rnd(); }
  })();

  function niceMax(v) { return Math.max(5, Math.ceil(v / 5) * 5); }

  function startHistTween(hours, now) {
    const V = Hh.vals;
    const ymaxG = niceMax(Math.max(...hours));
    if (reduced()) {
      V.s.set(hours); V.g.set(hours); V.ymax = V.ymaxS = V.ymaxG = ymaxG; V.t0 = -1e9;
      return;
    }
    const cur = new Float32Array(HOURS);
    const p = clamp((now - V.t0) / (V.dur || 1), 0, 1);
    for (let i = 0; i < HOURS; i++) {
      const e = easeIO(clamp((p * 1.3 - i * 0.012), 0, 1));
      cur[i] = V.t0 < 0 ? V.g[i] : V.s[i] + (V.g[i] - V.s[i]) * e;
    }
    V.s = cur;
    V.ymaxS = V.ymax;
    V.g = Float32Array.from(hours);
    V.ymaxG = ymaxG;
    V.t0 = now;
    V.dur = 800;
  }

  function drawHist(now) {
    const { ctx, W, H } = Hh;
    Hh.begin();
    const V = Hh.vals;
    const p = V.t0 < 0 ? 1 : clamp((now - V.t0) / V.dur, 0, 1.3);
    const narrow = W < 520;
    const ML = narrow ? 26 : 34, MR = 6, MT = 10, MB = narrow ? 34 : 42;
    const pw = W - ML - MR, ph = H - MT - MB;
    if (V.t0 >= 0 && p >= 1.3) { V.s.set(V.g); V.ymaxS = V.ymaxG; V.t0 = -1e9; }
    const done = V.t0 < 0;
    V.ymax = done ? V.ymaxG : V.ymaxS + (V.ymaxG - V.ymaxS) * easeIO(clamp(p, 0, 1));
    const ymax = V.ymax;
    const bw = pw / HOURS;
    const baseY = MT + ph;

    // noktalı yatay kılavuzlar: her %20'de bir
    ctx.globalCompositeOperation = "lighter";
    for (let k = 0; k <= 5; k++) {
      const y = baseY - (ph * k) / 5;
      ctx.globalAlpha = k === 0 ? 0.9 : 0.55;
      for (let x = ML; x <= ML + pw; x += 5) ctx.drawImage(sprites[0], x - 0.6, y - 0.6, 1.3, 1.3);
    }
    ctx.globalAlpha = 1;

    // sütunlar: yığılmış noktalar
    for (let i = 0; i < HOURS; i++) {
      const v = done ? V.g[i] : V.s[i] + (V.g[i] - V.s[i]) * easeIO(clamp(p * 1.3 - i * 0.012, 0, 1));
      const x0 = ML + i * bw + bw * 0.14, wBar = bw * 0.72;
      // zemin okuması: her saatte birkaç sönük nokta
      for (let q = 0; q < 4; q++) {
        const jx = Hh.jx[i * HK + q];
        ctx.globalAlpha = 0.7;
        ctx.drawImage(sprites[1], x0 + jx * wBar - 0.6, baseY - 1.5 - q * 0.0, 1.3, 1.3);
      }
      ctx.globalAlpha = 1;
      if (v <= 0.001) continue;
      const cnt = Math.min(HK, Math.ceil((v / ymax) * HK));
      const hPx = (v / ymax) * ph;
      for (let q = 0; q < cnt; q++) {
        const u = Hh.u[i * HK + q];
        const jx = Hh.jx[i * HK + q];
        const y = baseY - 2 - u * hPx;
        const top = u > 0.8;
        const bin = top ? 5 : u > 0.5 ? 3 : 2;
        const s = top ? 1.7 : 1.4;
        ctx.drawImage(sprites[bin], x0 + jx * wBar - s / 2, y - s / 2, s, s);
      }
    }
    ctx.globalCompositeOperation = "source-over";

    // y etiketleri
    const fs = narrow ? 9 : 10;
    setFont(ctx, fs, COL.p3);
    ctx.textAlign = "right";
    ctx.textBaseline = "middle";
    for (let k = 0; k <= 5; k++) {
      const y = baseY - (ph * k) / 5;
      const val = (ymax * k) / 5;
      ctx.fillText(Number.isInteger(val) ? String(val) : val.toFixed(1), ML - 6, Math.round(y));
    }

    // döndürülmüş tick etiketleri
    const every = bw < 14 ? 3 : bw < 22 ? 2 : 1;
    ctx.textAlign = "right";
    ctx.textBaseline = "middle";
    for (let i = 0; i < HOURS; i++) {
      const last = i === HOURS - 1;
      if (!last && (HOURS - 1 - i) % every !== 0) continue;
      const hr = new Date((derived ? derived.h0 : Date.now()) - (HOURS - 1 - i) * 3600000).getHours();
      const cx = Math.round(ML + i * bw + bw / 2) + 0.5;
      ctx.strokeStyle = COL.p4;
      ctx.beginPath(); ctx.moveTo(cx, baseY + 4); ctx.lineTo(cx, baseY + 8); ctx.stroke();
      ctx.save();
      ctx.translate(cx + 3, baseY + 12);
      ctx.rotate(-Math.PI / 4);
      setFont(ctx, fs, last ? COL.txt : COL.p3);
      ctx.fillText(pad2(hr) + ":00", 0, 0);
      ctx.restore();
    }

    // boş durum
    if (derived && derived.hours.every((v) => v === 0)) {
      setFont(ctx, fs + 1, COL.p3);
      ctx.textAlign = "center";
      ctx.fillText("SON 24 SAATTE DENEME YOK", ML + pw / 2, MT + ph * 0.45);
    }
  }

  // ---------- bütün çizim ----------
  let dirty = true;
  let lastFrame = 0;

  let histDirty = true;

  function resizeAll() {
    const a = Mp.resize();
    const b = Hh.resize();
    if (a || b) { dirty = true; histDirty = true; }
  }

  // Harita yalnızca görünürken ve hareket varken, histogram yalnızca değişince çizilir.
  function drawAll(now, force) {
    if ((force || dirty || Mp.animating()) && mapVisible()) Mp.draw(now);
    if (Hh.W > 1 && (force || histDirty || Hh.vals.t0 >= 0)) { drawHist(now); histDirty = false; }
  }

  function loop(ts) {
    requestAnimationFrame(loop);
    if (document.hidden) return;
    if (reduced()) {
      if (!dirty && !histDirty) return;
      drawAll(ts);
      dirty = false;
      return;
    }
    if (ts - lastFrame < 33) return; // ~30 fps: sakin ve ucuz
    lastFrame = ts;
    drawAll(ts);
    dirty = false;
  }

  // ---------- veri akışı ----------
  function rebuild(opts) {
    const now = Date.now();
    derived = derive(now);
    startHistTween(derived.hours, performance.now());
    histDirty = true;
    renderKpis(derived);
    renderSrTables(derived);
    updateMap(now);
    if (opts && opts.newFinding) {
      const f = opts.newFinding;
      const ip = ipOf(f);
      if (ip) Mp.pulse(ip, performance.now());
      $("live").textContent = "Yeni bulgu: " + (ip || f.summary || f.type) + ", " + attemptsOf(f) + " deneme.";
    }
    dirty = true;
  }

  function renderLists() {
    renderFindings();
    renderActions();
    renderServers();
    renderMeta();
    fitRows();
    if (Dt) Dt.refresh();
  }

  function setError(msg) {
    const el = $("err");
    el.hidden = !msg;
    el.textContent = msg || "";
  }

  async function getJSON(url) {
    const r = await fetch(url, { headers: { Accept: "application/json" } });
    if (!r.ok) throw new Error(url + " → HTTP " + r.status);
    return r.json();
  }

  async function refresh() {
    try {
      const [servers, findings, actions] = await Promise.all([
        getJSON("/api/v1/servers"),
        getJSON("/api/v1/findings"),
        getJSON("/api/v1/actions"),
      ]);
      state.servers = servers || [];
      state.findings = findings || [];
      state.actions = actions || [];
      state.lastUpdate = Date.now();
      setError(null);
      renderLists();
      rebuild();
    } catch (e) {
      setError("Veri yüklenemedi: " + (e && e.message ? e.message : e));
    }
  }

  function upsert(list, item) {
    const i = list.findIndex((x) => x.id === item.id);
    if (i >= 0) { list[i] = item; return false; }
    list.unshift(item);
    return true;
  }

  function connectStream() {
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    let ws;
    try {
      ws = new WebSocket(proto + "//" + location.host + "/api/v1/stream");
    } catch (e) {
      state.live = false;
      renderMeta();
      setTimeout(connectStream, 2000);
      return;
    }
    let everOpen = false;
    ws.onopen = () => {
      state.live = true;
      renderMeta();
      if (everOpen) refresh(); // kopukken kaçan olayları yakala
      everOpen = true;
    };
    ws.onmessage = (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch { return; }
      if (msg.kind === "finding" && msg.finding) {
        const f = msg.finding;
        const isNew = upsert(state.findings, f);
        if (isNew) freshIDs.add(f.id);
        state.lastUpdate = Date.now();
        renderLists();
        rebuild({ newFinding: isNew ? f : null });
      } else if (msg.kind === "command" && msg.command) {
        Dt.onCommand(msg.command);
      } else if (msg.kind === "agent" && msg.server_id && msg.agent) {
        const srv = state.servers.find((x) => x.id === msg.server_id);
        if (srv) { srv.agent = msg.agent; renderServers(); updateMap(Date.now()); Dt.refresh(); }
        else refresh(); // yeni kayıt olmuş bir sunucu
      } else if (msg.kind === "action" && msg.action) {
        const a = msg.action;
        const known = state.actions.some((x) => x.id === a.id);
        if (!known) freshIDs.add(a.id);
        upsert(state.actions, a);
        state.lastUpdate = Date.now();
        renderLists();
        rebuild();
      }
      setTimeout(() => freshIDs.clear(), 600);
    };
    ws.onclose = () => {
      state.live = false;
      renderMeta();
      setTimeout(connectStream, 2000);
    };
    ws.onerror = () => { try { ws.close(); } catch { /* yok say */ } };
  }

  // ---------- dither (hareketsiz, deterministik) ----------
  function buildGrain() {
    try {
      const c = document.createElement("canvas");
      c.width = c.height = 128;
      const g = c.getContext("2d");
      const img = g.createImageData(128, 128);
      const rnd = mulberry32(31337);
      for (let i = 0; i < img.data.length; i += 4) {
        const v = rnd() < 0.5 ? 255 : 0;
        img.data[i] = img.data[i + 1] = img.data[i + 2] = v;
        img.data[i + 3] = v ? 7 : 0;
      }
      g.putImageData(img, 0, 0);
      document.documentElement.style.setProperty("--grain", "url(" + c.toDataURL() + ")");
    } catch { /* dither olmadan da çalışır */ }
  }

  // ---------- başlangıç ----------
  let Dt = null;

  function init() {
    Dt = window.NexDetail.create({
      $, state, setText, reduced, getJSON,
      fmtClock, fmtDateTime, fmtShortDate, fmtCountdown,
      ipOf, attemptsOf, actionInfo, isActiveBlock, hostnameFor,
      geo: (ip) => geoCache.get(ip) || null,
      geoKnown: (ip) => geoCache.has(ip),
      onSelect: (ip) => { Mp.select(ip, performance.now()); dirty = true; },
    });
    $("m-hp").addEventListener("click", (e) => {
      const list = [...state.servers].sort((a, b) => Date.parse(a.enrolled_at) - Date.parse(b.enrolled_at));
      if (list.length) Dt.open("server", list[0].id, e.currentTarget);
    });
    buildGrain();
    renderLists();
    resizeAll();
    derived = derive(Date.now());
    startHistTween(derived.hours, performance.now());
    renderKpis(derived);
    renderSrTables(derived);
    Mp.setReduced(reduced());
    let saved = null;
    try { saved = localStorage.getItem("nexguard.harita"); } catch { /* depolama kapalı */ }
    setMapMode(saved === "3d" ? "3d" : "2d", false);
    document.querySelectorAll("[data-mode]").forEach((b) => b.addEventListener("click", () => setMapMode(b.dataset.mode, true)));
    if (!Mp.glOK) document.querySelectorAll('[data-style="sinir"], [data-style="uydu"]').forEach((b) => { b.disabled = true; b.title = "Bu tarayıcıda WebGL2 yok"; });
    let color = load("nexguard.renk") === "1";
    setMapStyle(load("nexguard.stil") || "nokta", color, false);
    document.querySelectorAll("[data-style]").forEach((b) => b.addEventListener("click", () => setMapStyle(b.dataset.style, color, true)));
    $("map-color").addEventListener("click", () => { color = !color; setMapStyle(Mp.style, color, true); });
    document.querySelectorAll("[data-zoom]").forEach((b) => b.addEventListener("click", () => {
      const z = b.dataset.zoom;
      if (z === "reset") Mp.resetView(); else Mp.zoomBy(z === "in" ? 1.4 : 1 / 1.4);
    }));
    updateMap(Date.now());

    const ro = new ResizeObserver(resizeAll);
    ro.observe($("map-stage"));
    window.addEventListener("scroll", () => { dirty = true; }, { passive: true });
    ro.observe($("hist-stage"));
    new ResizeObserver(fitRows).observe(document.querySelector(".findings"));
    new ResizeObserver(fitRows).observe(document.querySelector(".actions"));
    window.addEventListener("resize", resizeAll);
    rmQuery.addEventListener("change", () => { Mp.setReduced(reduced()); rebuild(); dirty = true; });
    if (document.fonts && document.fonts.ready) document.fonts.ready.then(() => { dirty = true; histDirty = true; });

    requestAnimationFrame(loop);
    refresh().then(connectStream);

    // 1 sn: TTL geri sayımı; 20 sn: 60 dk penceresi kayar; 30 sn: sunucu listesi / kaçan veri
    setInterval(tickTTL, 1000);
    setInterval(() => { if (!document.hidden) { state.actions.length && renderActions(); rebuild(); } }, 20000);
    setInterval(() => { if (!document.hidden) refresh(); }, 30000);
  }

  window.__nexguard = { state, derive, rebuild, drawAll, map: Mp, geoCache, get derived() { return derived; } };
  init();
})();
