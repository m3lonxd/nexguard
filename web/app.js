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
  const MAX_FINDING_ROWS = 7;
  const MAX_ACTION_ROWS = 4;
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

  function renderFindings() {
    const list = [...state.findings].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
    const shown = list.slice(0, MAX_FINDING_ROWS).map((f) => Object.assign({ __key: f.id }, f));
    $("f-count").textContent = list.length > shown.length ? shown.length + " / " + list.length : String(list.length);
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
        return { tr };
      },
      (tr, f, i, animate) => {
        const c = tr._c;
        const ip = ipOf(f);
        const users = Array.isArray(f.evidence && f.evidence.users_tried) ? f.evidence.users_tried.join(",") : "";
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
    $("a-count").textContent = list.length > shown.length ? shown.length + " / " + list.length : String(list.length);
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
    $("m-agents").textContent = String(list.length); // her kayıtlı sunucuda bir ajan çalışır
    reconcile($("s-body"), rowMaps.s, shown,
      () => {
        const tr = document.createElement("tr");
        tr._c = { h: mkCell(tr), o: mkCell(tr), e: mkCell(tr, "num") };
        return { tr };
      },
      (tr, s) => {
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
    const tb = $("sr-terrain-body");
    tb.textContent = "";
    for (const r of d.rows) {
      const tr = document.createElement("tr");
      [r.ip, String(r.total), r.peakMin === 0 ? "şimdi" : r.peakMin + " dakika önce", r.blocked ? "Engelli" : "Engelli değil"].forEach((t) => {
        const td = document.createElement("td");
        td.textContent = t;
        tr.appendChild(td);
      });
      tb.appendChild(tr);
    }
    if (!d.rows.length) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 4;
      td.textContent = "Henüz deneme yok";
      tr.appendChild(td);
      tb.appendChild(tr);
    }
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
    $("terrain").setAttribute(
      "aria-label",
      d.total
        ? "Son 60 dakikada " + d.ips + " kaynaktan toplam " + d.total + " deneme; " + d.blockedCount + " IP engelli."
        : "Son 60 dakikada henüz deneme yok."
    );
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

  // ---------- ARAZİ ----------
  const NX = 420, NZ = 110;
  const DZ = 1.3, HH = 1.0, CAM_D = 3.2, PITCH = 0.34, YAW0 = -0.2;
  const T = setupCanvas($("terrain"), $("terrain-stage"));
  T.bloom = document.createElement("canvas");
  T.bctx = T.bloom.getContext("2d");
  T.grid = { s: new Float32Array(NX * NZ), g: new Float32Array(NX * NZ), ymaxS: 8, ymaxG: 8, ymax: 8, t0: -1e9, dur: 0 };
  T.rowE = new Float32Array(NZ).fill(1);
  T.events = [];
  T.cam = { S: 1, ox: 0, oy: 0 };
  T.rows = [];

  (function buildTerrainPoints() {
    const rnd = mulberry32(90210);
    const n = NX * NZ;
    T.n = n;
    T.px = new Float32Array(n);
    T.pz = new Float32Array(n);
    T.cell = new Uint32Array(n);
    T.iz = new Uint8Array(n);
    T.r = new Float32Array(n);
    T.rj = new Float32Array(n);
    T.ph = new Float32Array(n);
    let i = 0;
    for (let iz = 0; iz < NZ; iz++) {
      for (let ix = 0; ix < NX; ix++, i++) {
        T.px[i] = -1 + (2 * (ix + rnd())) / NX;
        T.pz[i] = (iz + rnd()) / NZ;
        T.cell[i] = iz * NX + ix;
        T.iz[i] = iz;
        T.r[i] = rnd();
        T.rj[i] = rnd();
        T.ph[i] = rnd() * 6.2832;
      }
    }
    // zemin saçılımı: arazinin altında seyrek, aşağı doğru sönen noktalar
    const nf = 5200;
    T.nf = nf;
    T.fx = new Float32Array(nf);
    T.fz = new Float32Array(nf);
    T.fy = new Float32Array(nf);
    T.fr = new Float32Array(nf);
    for (let k = 0; k < nf; k++) {
      T.fx[k] = -1.04 + rnd() * 2.08;
      T.fz[k] = rnd();
      T.fy[k] = Math.pow(rnd(), 2.2);
      T.fr[k] = rnd();
    }
    // eşik düzlemi: soluk noktalı ızgara
    const th = [];
    for (let a = 0; a <= 64; a++) for (let b = 0; b <= 10; b++) th.push(-1 + (2 * a) / 64, b / 10);
    T.th = Float32Array.from(th);
    // değer gürültüsü ızgarası (tohumlu)
    const gn = mulberry32(4242);
    T.noise = new Float32Array(64 * 64);
    for (let k = 0; k < T.noise.length; k++) T.noise[k] = gn();
  })();

  function vnoise(x, z) {
    const xi = Math.floor(x), zi = Math.floor(z);
    const fx = x - xi, fz = z - zi;
    const sx = fx * fx * (3 - 2 * fx), sz = fz * fz * (3 - 2 * fz);
    const g = (a, b) => T.noise[((b & 63) << 6) | (a & 63)];
    const a = g(xi, zi), b = g(xi + 1, zi), c = g(xi, zi + 1), d = g(xi + 1, zi + 1);
    return a + (b - a) * sx + (c - a) * sz + (a - b - c + d) * sx * sz;
  }

  const bucketX = (m) => 0.96 - (1.92 * m) / (WINDOW_MIN - 1);
  const rowZF = (r, slots) => 1 - (r + 0.5) / slots; // en yoğun IP arkada (uzakta)

  function slotsFor(d) { return Math.max(4, d.rows.length); }

  function computeTarget(d) {
    const g = new Float32Array(NX * NZ);
    const slots = slotsFor(d);
    const sx = 1.7 * (1.92 / (WINDOW_MIN - 1));
    const sz = Math.min(0.2, 0.46 / slots);
    let peak = 0;
    for (const r of d.rows) {
      const zf = rowZF(r.index, slots);
      for (let m = 0; m < WINDOW_MIN; m++) {
        const v = r.buckets[m];
        if (!v) continue;
        const x0 = bucketX(m);
        const ixa = Math.max(0, Math.floor(((x0 - 3.2 * sx + 1) / 2) * NX));
        const ixb = Math.min(NX - 1, Math.ceil(((x0 + 3.2 * sx + 1) / 2) * NX));
        const iza = Math.max(0, Math.floor((zf - 3.2 * sz) * NZ));
        const izb = Math.min(NZ - 1, Math.ceil((zf + 3.2 * sz) * NZ));
        for (let iz = iza; iz <= izb; iz++) {
          const dz = (iz + 0.5) / NZ - zf;
          const ez = Math.exp(-(dz * dz) / (2 * sz * sz));
          for (let ix = ixa; ix <= ixb; ix++) {
            const dx = -1 + (2 * (ix + 0.5)) / NX - x0;
            g[iz * NX + ix] += v * ez * Math.exp(-(dx * dx) / (2 * sx * sx));
          }
        }
      }
    }
    for (let iz = 0; iz < NZ; iz++) {
      for (let ix = 0; ix < NX; ix++) {
        const ci = iz * NX + ix;
        const x = -1 + (2 * (ix + 0.5)) / NX, z = (iz + 0.5) / NZ;
        const n1 = vnoise(x * 16 + 9, z * 7 + 3) - 0.5;
        const n2 = vnoise(x * 41 + 2, z * 17 + 8) - 0.5;
        const h = g[ci];
        g[ci] = Math.max(0, h * (1 + 0.34 * n1 + 0.16 * n2) + 0.1 * (n1 + 0.5) * (n2 + 0.5));
        if (g[ci] > peak) peak = g[ci];
      }
    }
    return { g, ymax: Math.max(8, peak * 1.2) };
  }

  function currentHeightArray() {
    const G = T.grid;
    const out = new Float32Array(NX * NZ);
    for (let iz = 0; iz < NZ; iz++) {
      const e = T.rowE[iz];
      for (let ix = 0; ix < NX; ix++) {
        const ci = iz * NX + ix;
        out[ci] = G.s[ci] + (G.g[ci] - G.s[ci]) * e;
      }
    }
    return out;
  }

  function startTween(target, now) {
    const G = T.grid;
    if (reduced()) {
      G.s.set(target.g); G.g.set(target.g);
      G.ymaxS = G.ymaxG = G.ymax = target.ymax;
      T.rowE.fill(1);
      G.t0 = -1e9;
      return;
    }
    G.s = currentHeightArray();
    G.ymaxS = G.ymax;
    G.g = target.g;
    G.ymaxG = target.ymax;
    G.t0 = now;
    G.dur = 1000;
  }

  function updateTween(now) {
    const G = T.grid;
    const p = clamp((now - G.t0) / G.dur, 0, 1.2);
    if (G.t0 < 0 || p >= 1.2) {
      if (G.t0 >= 0) { G.s.set(G.g); G.ymaxS = G.ymaxG; G.t0 = -1e9; }
      T.rowE.fill(1);
      G.ymax = G.ymaxG;
      return;
    }
    // öndeki satırlar önce, arkadakiler biraz gecikmeli: yükselme bir tarama gibi okunur
    for (let iz = 0; iz < NZ; iz++) {
      const delay = (iz / NZ) * 0.3;
      T.rowE[iz] = easeIO(clamp((p - delay) / 0.7, 0, 1));
    }
    G.ymax = G.ymaxS + (G.ymaxG - G.ymaxS) * easeIO(clamp(p, 0, 1));
  }

  function heightAt(x, zf) {
    const ix = clamp(Math.floor(((x + 1) / 2) * NX), 0, NX - 1);
    const iz = clamp(Math.floor(zf * NZ), 0, NZ - 1);
    const ci = iz * NX + ix;
    const G = T.grid;
    return G.s[ci] + (G.g[ci] - G.s[ci]) * T.rowE[iz];
  }

  const view = { cT: 1, sT: 0, cP: Math.cos(PITCH), sP: Math.sin(PITCH) };
  function setYaw(yaw) { view.cT = Math.cos(yaw); view.sT = Math.sin(yaw); }

  function fitCamera() {
    setYaw(YAW0);
    const narrow = T.W < 520;
    const L = narrow ? 96 : 112, R = narrow ? 18 : 64, Tp = 30, B = 40;
    let minx = Infinity, maxx = -Infinity, miny = Infinity, maxy = -Infinity;
    for (const X of [-1, 1]) for (const zf of [0, 1]) for (const Y of [0, HH]) {
      const Z = (zf - 0.5) * DZ;
      const x1 = X * view.cT - Z * view.sT, z1 = X * view.sT + Z * view.cT;
      const y2 = Y * view.cP + z1 * view.sP, z2 = -Y * view.sP + z1 * view.cP + CAM_D;
      const px = x1 / z2, py = -y2 / z2;
      minx = Math.min(minx, px); maxx = Math.max(maxx, px); miny = Math.min(miny, py); maxy = Math.max(maxy, py);
    }
    const aw = Math.max(50, T.W - L - R), ah = Math.max(50, T.H - Tp - B);
    const S = Math.min(aw / (maxx - minx), ah / (maxy - miny));
    T.cam = { S, ox: L + (aw - (maxx - minx) * S) / 2 - minx * S, oy: Tp + (ah - (maxy - miny) * S) / 2 - miny * S };
  }

  function project(X, Y, Z, out) {
    const x1 = X * view.cT - Z * view.sT, z1 = X * view.sT + Z * view.cT;
    const y2 = Y * view.cP + z1 * view.sP, z2 = -Y * view.sP + z1 * view.cP + CAM_D;
    const k = T.cam.S / z2;
    out.x = T.cam.ox + x1 * k;
    out.y = T.cam.oy - y2 * k;
    return out;
  }

  const P = { x: 0, y: 0 };

  function drawTerrain(now) {
    const { ctx, W, H } = T;
    T.begin();
    const drift = !reduced();
    setYaw(YAW0 + (drift ? Math.sin(now / 9000) * 0.03 : 0));
    const G = T.grid;
    updateTween(now);
    const invY = 1 / G.ymax;
    const hasData = derived && derived.rows.length > 0;
    const S = T.cam.S, ox = T.cam.ox, oy = T.cam.oy;
    const { cT, sT, cP, sP } = view;

    // bloom katmanı (yarı çözünürlük)
    const bw = Math.max(1, Math.floor(W / 2)), bh = Math.max(1, Math.floor(H / 2));
    if (T.bloom.width !== bw || T.bloom.height !== bh) { T.bloom.width = bw; T.bloom.height = bh; }
    const bctx = T.bctx;
    bctx.globalCompositeOperation = "source-over";
    bctx.clearRect(0, 0, bw, bh);
    bctx.globalCompositeOperation = "lighter";

    ctx.globalCompositeOperation = "lighter";

    // aktif tarama olayları
    const evs = T.events.filter((e) => now - e.t0 < 1500);
    T.events = evs;

    // satır taban çizgileri (soluk noktalı kılavuz)
    if (derived) {
      const slots = slotsFor(derived);
      ctx.globalAlpha = 0.5;
      for (const r of derived.rows) {
        const Z = (rowZF(r.index, slots) - 0.5) * DZ;
        for (let a = 0; a <= 70; a++) {
          const X = -1 + a / 35;
          const x1 = X * cT - Z * sT, z1 = X * sT + Z * cT;
          const y2 = z1 * sP, z2 = z1 * cP + CAM_D;
          const k = S / z2;
          ctx.drawImage(sprites[1], ox + x1 * k - 0.6, oy - y2 * k - 0.6, 1.3, 1.3);
        }
      }
      ctx.globalAlpha = 1;
    }

    // zemin saçılımı
    for (let k = 0; k < T.nf; k++) {
      const zf = T.fz[k];
      const Z = (zf - 0.5) * DZ;
      const Y = -T.fy[k] * 0.2;
      const X = T.fx[k];
      const x1 = X * cT - Z * sT, z1 = X * sT + Z * cT;
      const y2 = Y * cP + z1 * sP, z2 = -Y * sP + z1 * cP + CAM_D;
      const kk = S / z2;
      const fade = 1 - T.fy[k];
      if (T.fr[k] > 0.5 * fade + 0.05) continue;
      const bin = fade > 0.6 ? 1 : 0;
      const df = 1 - 0.5 * zf;
      ctx.globalAlpha = 0.55 * fade * df;
      ctx.drawImage(sprites[bin], ox + x1 * kk - 0.7, oy - y2 * kk - 0.7, 1.4, 1.4);
    }
    ctx.globalAlpha = 1;

    // eşik düzlemi (5 deneme): arazinin içinden geçen soluk noktalı düzlem
    {
      const Y = THRESHOLD * invY * HH;
      ctx.globalAlpha = 0.45;
      for (let k = 0; k < T.th.length; k += 2) {
        const X = T.th[k], Z = (T.th[k + 1] - 0.5) * DZ;
        const x1 = X * cT - Z * sT, z1 = X * sT + Z * cT;
        const y2 = Y * cP + z1 * sP, z2 = -Y * sP + z1 * cP + CAM_D;
        const kk = S / z2;
        ctx.drawImage(sprites[2], ox + x1 * kk - 0.65, oy - y2 * kk - 0.65, 1.3, 1.3);
      }
      ctx.globalAlpha = 1;
    }

    // ana nokta bulutu
    const t = drift ? now : 0;
    const gS = G.s, gG = G.g, rowE = T.rowE;
    for (let i = 0; i < T.n; i++) {
      const ci = T.cell[i], iz = T.iz[i];
      const e = rowE[iz];
      const h = gS[ci] + (gG[ci] - gS[ci]) * e;
      const hn = h * invY;
      const dens = 0.2 + 0.8 * Math.min(1, hn * 3);
      if (T.r[i] > dens) continue;
      const zf = T.pz[i];
      const X = T.px[i], Z = (zf - 0.5) * DZ;
      const Y = Math.min(hn, 1.05) * HH;
      let hp = h;
      if (iz > 0) { const c2 = ci - NX; hp = gS[c2] + (gG[c2] - gS[c2]) * rowE[iz - 1]; }
      const sl = (h - hp) * invY;
      const df = 1 - 0.55 * zf;
      let b = 0.12 + 0.7 * Math.pow(Math.min(1, hn * 1.5), 0.65) + clamp(sl * 26, -0.08, 0.3) + (T.rj[i] - 0.5) * 0.1;
      b *= df;
      for (let q = 0; q < evs.length; q++) {
        const ev = evs[q];
        const age = (now - ev.t0) / 1000;
        const front = age / 0.9 * 1.05 - 0.05;
        if (Math.abs(X - ev.x) < 0.13 && zf < front + 0.02) {
          const fl = Math.abs(zf - front) < 0.035 ? 0.55 : 0.28 * (1 - age / 1.5);
          if (fl > 0) b += fl;
        }
      }
      b = clamp(b, 0, 1);
      const bin = Math.min(5, (b * 6) | 0);
      let sx = X, sy = Y;
      const x1 = sx * cT - Z * sT, z1 = sx * sT + Z * cT;
      const y2 = sy * cP + z1 * sP, z2 = -sy * sP + z1 * cP + CAM_D;
      const kk = S / z2;
      let px = ox + x1 * kk, py = oy - y2 * kk;
      if (drift) { px += Math.sin(t * 0.0009 + T.ph[i]) * 0.3; py += Math.cos(t * 0.0011 + T.ph[i]) * 0.3; }
      const size = (1.2 + 1.5 * b) * (0.75 + 0.3 * df);
      ctx.drawImage(sprites[bin], px - size / 2, py - size / 2, size, size);
      if (bin >= 4) bctx.drawImage(sprites[5], px * 0.5 - size * 0.5, py * 0.5 - size * 0.5, size, size);
    }

    // bloom: yalnızca en parlak noktalar, küçük yarıçap, düşük opaklık
    ctx.globalCompositeOperation = "lighter";
    ctx.globalAlpha = 0.3;
    ctx.imageSmoothingEnabled = true;
    ctx.drawImage(T.bloom, 0, 0, bw, bh, 0, 0, W, H);
    ctx.globalAlpha = 1;
    ctx.globalCompositeOperation = "source-over";

    drawTerrainText(now, evs);
  }

  function drawTerrainText(now, evs) {
    const { ctx, W, H } = T;
    const narrow = W < 520;
    const fs = narrow ? 9.5 : 10.5;
    const d = derived;
    ctx.textBaseline = "middle";

    // zaman ekseni (ön kenar)
    setFont(ctx, fs, COL.p3);
    ctx.textAlign = "center";
    const ticks = [59, 45, 30, 15, 0];
    const zFront = -0.5 * DZ - 0.02;
    ctx.strokeStyle = COL.p4;
    ctx.lineWidth = 1;
    ticks.forEach((m) => {
      const X = bucketX(m);
      project(X, 0, -0.5 * DZ, P);
      const x = Math.round(P.x) + 0.5, y = Math.round(P.y);
      ctx.beginPath(); ctx.moveTo(x, y + 3); ctx.lineTo(x, y + 8); ctx.stroke();
      ctx.fillText(m === 0 ? "ŞİMDİ" : "-" + (m === 59 ? 60 : m) + "DK", x, y + 17);
    });
    // ön kenar hairline
    project(-1, 0, -0.5 * DZ, P);
    const fx0 = P.x, fy0 = P.y;
    project(1, 0, -0.5 * DZ, P);
    ctx.beginPath(); ctx.moveTo(Math.round(fx0), Math.round(fy0) + 0.5); ctx.lineTo(Math.round(P.x), Math.round(P.y) + 0.5);
    ctx.strokeStyle = COL.p5; ctx.stroke();

    const slots = d ? slotsFor(d) : 4;
    const G = T.grid;
    const invY = 1 / G.ymax;

    // IP etiketleri (sol)
    if (d && d.rows.length) {
      ctx.textAlign = "right";
      let lastY = -1e9;
      for (const r of [...d.rows].sort((p, q) => q.index - p.index)) {
        const Z = (rowZF(r.index, slots) - 0.5) * DZ;
        project(-1.02, 0, Z, P);
        if (Math.abs(P.y - lastY) < 11) continue;
        lastY = P.y;
        setFont(ctx, fs, r.blocked ? COL.p1 : COL.p3);
        ctx.fillText(shortIP(r.ip, narrow ? 15 : 22), Math.round(P.x) - 6, Math.round(P.y));
      }
    }

    // eşik etiketi (ön sağ köşe, düzlem seviyesinde)
    {
      const Y = THRESHOLD * invY * HH;
      project(1.0, Y, -0.5 * DZ, P);
      const x = Math.round(P.x), y = Math.round(P.y) + 0.5;
      ctx.strokeStyle = COL.p4;
      ctx.beginPath(); ctx.moveTo(x + 2, y); ctx.lineTo(x + 12, y); ctx.stroke();
      setFont(ctx, fs, COL.p3);
      ctx.textAlign = "left";
      if (!narrow) {
        ctx.fillText("EŞİK " + THRESHOLD, x + 16, y);
      } else {
        ctx.fillText(String(THRESHOLD), x + 14, y);
      }
    }

    // tepe işaretleri
    if (d) {
      for (const r of d.rows) {
        const x = bucketX(r.peakMin);
        const zf = rowZF(r.index, slots);
        const peakH = Math.max(heightAt(x, zf), r.buckets[r.peakMin] * 0.0);
        const hn = Math.min(1.05, peakH * invY);
        project(x, hn * HH, (zf - 0.5) * DZ, P);
        const px = Math.round(P.x), py = Math.round(P.y);
        const ev = evs.find((e) => e.ip === r.ip);
        if (r.blocked) {
          bracket(ctx, px, py - 6, 7, COL.warn);
          ctx.fillStyle = COL.warn;
          ctx.fillRect(px - 1, py - 7, 3, 3);
          // hairline çağrı: tepe -> raf -> etiket
          ctx.strokeStyle = COL.p3;
          ctx.beginPath();
          const left = px > W - 110;
          const dir = left ? -1 : 1;
          ctx.moveTo(px + 0.5, py - 14); ctx.lineTo(px + 0.5, py - 24); ctx.lineTo(px + 0.5 + dir * 16, py - 24);
          ctx.stroke();
          const w = narrow ? 50 : 56;
          setFont(ctx, fs, COL.warn);
          ctx.textAlign = left ? "right" : "left";
          ctx.fillText("ENGELLİ", px + dir * 21, py - 24);
          setFont(ctx, fs, COL.p3);
          ctx.fillText(String(Math.round(r.buckets[r.peakMin])), px + dir * (21 + w), py - 24);
        } else if (ev) {
          bracket(ctx, px, py - 6, 7, COL.p0);
        }
      }
    }

    // boş durum
    if (!d || !d.rows.length) {
      ctx.textAlign = "center";
      setFont(ctx, narrow ? 12 : 14, COL.txt);
      ctx.fillText("HENÜZ DENEME YOK", W / 2, H * 0.4);
      setFont(ctx, fs, COL.p3);
      ctx.fillText("SON 60 DK · EŞİK " + THRESHOLD + " DENEME · ZEMİN OKUMASI", W / 2, H * 0.4 + 22);
    }
  }

  function bracket(ctx, cx, cy, r, color) {
    const l = 4;
    ctx.strokeStyle = color;
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(cx - r + 0.5, cy - r + l + 0.5); ctx.lineTo(cx - r + 0.5, cy - r + 0.5); ctx.lineTo(cx - r + l + 0.5, cy - r + 0.5);
    ctx.moveTo(cx + r + 0.5, cy + r - l + 0.5); ctx.lineTo(cx + r + 0.5, cy + r + 0.5); ctx.lineTo(cx + r - l + 0.5, cy + r + 0.5);
    ctx.stroke();
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

  function resizeAll() {
    const a = T.resize();
    const b = Hh.resize();
    if (a) fitCamera();
    if (a || b) dirty = true;
  }

  function drawAll(now) {
    if (T.W > 1) drawTerrain(now);
    if (Hh.W > 1) drawHist(now);
  }

  function loop(ts) {
    requestAnimationFrame(loop);
    if (document.hidden) return;
    if (reduced()) {
      if (!dirty) return;
      dirty = false;
      drawAll(ts);
      return;
    }
    if (ts - lastFrame < 30) return; // ~30 fps: sakin ve ucuz
    lastFrame = ts;
    dirty = false;
    drawAll(ts);
  }

  // ---------- veri akışı ----------
  function rebuild(opts) {
    const now = Date.now();
    derived = derive(now);
    const target = computeTarget(derived);
    startTween(target, performance.now());
    startHistTween(derived.hours, performance.now());
    renderKpis(derived);
    renderSrTables(derived);
    if (opts && opts.newFinding) {
      const f = opts.newFinding;
      const ip = ipOf(f);
      const row = derived.rows.find((r) => r.ip === ip);
      if (row && !reduced()) {
        T.events.push({ ip, x: bucketX(0), t0: performance.now() });
      }
      $("live").textContent = "Yeni bulgu: " + (ip || f.summary || f.type) + ", " + attemptsOf(f) + " deneme.";
    }
    dirty = true;
  }

  function renderLists() {
    renderFindings();
    renderActions();
    renderServers();
    renderMeta();
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
  function init() {
    buildGrain();
    renderLists();
    resizeAll();
    derived = derive(Date.now());
    startTween(computeTarget(derived), performance.now());
    startHistTween(derived.hours, performance.now());
    renderKpis(derived);
    renderSrTables(derived);

    const ro = new ResizeObserver(resizeAll);
    ro.observe($("terrain-stage"));
    ro.observe($("hist-stage"));
    window.addEventListener("resize", resizeAll);
    rmQuery.addEventListener("change", () => { rebuild(); dirty = true; });
    if (document.fonts && document.fonts.ready) document.fonts.ready.then(() => { dirty = true; });

    requestAnimationFrame(loop);
    refresh().then(connectStream);

    // 1 sn: TTL geri sayımı; 20 sn: 60 dk penceresi kayar; 30 sn: sunucu listesi / kaçan veri
    setInterval(tickTTL, 1000);
    setInterval(() => { if (!document.hidden) { state.actions.length && renderActions(); rebuild(); } }, 20000);
    setInterval(() => { if (!document.hidden) refresh(); }, 30000);
  }

  window.__nexguard = { state, derive, rebuild, drawAll, get derived() { return derived; } };
  init();
})();
