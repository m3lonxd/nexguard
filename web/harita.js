/* NexGuard paneli: canlı saldırı haritası (2B düz harita ve 3B küre, Canvas2D).
   Kara noktaları dunya.js'ten (Natural Earth 1:110m) gelir. Saldırgan konumu ülke
   düzeyindedir; aynı ülkedeki IP'ler adres özetine göre birkaç derece dağıtılır.
   Statik kara katmanı 2B'de bir kez çizilir; kare başına yalnızca yaylar ve işaretler çizilir. */
(function () {
  "use strict";
  const RAD = Math.PI / 180;
  const LAT_N = 84, LAT_S = -56;
  const clamp = (v, a, b) => (v < a ? a : v > b ? b : v);

  function hash(s) { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return h >>> 0; }

  function create(canvas, stage, opt) {
    const COL = opt.colors, MONO = opt.mono;
    const ctx = canvas.getContext("2d");
    const G = window.NEXGEO || { flat: [], globe: [], flatStep: 1.5 };
    const m = {
      mode: "2d", W: 0, H: 0, dpr: 1,
      lon0: 35, pitch: 22 * RAD, // 3B görüş: başlangıçta merkez (Türkiye) önde
      attackers: [], targets: [], note: "",
      pulses: [], drag: null, lastT: 0, idleSince: 0, reduced: false,
      screen: [], selected: null, spin: null, // son karede çizilen işaretlerin ekran konumu (tıklama için)
      style: "nokta", color: false,              // taban: nokta | sinir | uydu (sinir/uydu WebGL)
      zoom3: 1, zoom2: 1, c2: { lon: 0, lat: (LAT_N + LAT_S) / 2 }, pan: null, layerDirty: true,
    };
    const ZMAX = 8;
    // WebGL taban katmanı (sınır ve uydu stilleri); yoksa yalnız nokta stili kullanılır
    const gl = opt.glCanvas && window.NexGlobe ? window.NexGlobe.create(opt.glCanvas, { onChange: () => opt.onChange() }) : null;
    const layer = document.createElement("canvas");
    const lctx = layer.getContext("2d");

    // küre noktaları: enlem sin/cos önceden
    const gn = G.globe.length / 2;
    const gLat = new Float32Array(gn), gLon = new Float32Array(gn), gCl = new Float32Array(gn), gSl = new Float32Array(gn);
    for (let i = 0; i < gn; i++) {
      gLat[i] = G.globe[2 * i] / 10 * RAD; gLon[i] = G.globe[2 * i + 1] / 10 * RAD;
      gCl[i] = Math.cos(gLat[i]); gSl[i] = Math.sin(gLat[i]);
    }

    // 2B görünüm: tam sığan ölçek x yakınlaştırma, merkez c2 (boylam, enlem)
    function baseK() {
      const pad = 10;
      return Math.min((m.W - pad * 2) / 360, (m.H - pad * 2) / (LAT_N - LAT_S));
    }
    function fit2d() {
      const k = baseK() * m.zoom2;
      return { k, ox: m.W / 2 - (m.c2.lon + 180) * k, oy: m.H / 2 - (LAT_N - m.c2.lat) * k };
    }
    function clampC2() {
      const k = baseK() * m.zoom2, hw = m.W / 2 / k, hh = m.H / 2 / k;
      m.c2.lon = hw >= 180 ? 0 : clamp(m.c2.lon, -180 + hw, 180 - hw);
      m.c2.lat = hh >= (LAT_N - LAT_S) / 2 ? (LAT_N + LAT_S) / 2 : clamp(m.c2.lat, LAT_S + hh, LAT_N - hh);
      m.layerDirty = true;
    }
    function zoomAt(f, x, y) {
      if (m.mode === "3d") { m.zoom3 = clamp(m.zoom3 * f, 1, ZMAX); opt.onChange(); return; }
      const a = fit2d();
      if (x == null) { x = m.W / 2; y = m.H / 2; }
      const lon = (x - a.ox) / a.k - 180, lat = LAT_N - (y - a.oy) / a.k;
      m.zoom2 = clamp(m.zoom2 * f, 1, ZMAX);
      const k = baseK() * m.zoom2;
      // imlecin altındaki nokta yerinde kalır
      m.c2.lon = (m.W / 2 - (x - (lon + 180) * k)) / k - 180;
      m.c2.lat = LAT_N - (m.H / 2 - (y - (LAT_N - lat) * k)) / k;
      clampC2();
      touchMode();
      opt.onChange();
    }
    // dokunmatik: 3B'de yatay sürükleme döndürür; 2B yakınken sürükleme haritayı kaydırır
    function touchMode() {
      canvas.style.touchAction = m.mode === "3d" ? "pan-y" : m.zoom2 > 1.001 ? "none" : "auto";
    }
    function resetView() {
      m.zoom2 = 1; m.zoom3 = 1; m.c2 = { lon: 0, lat: (LAT_N + LAT_S) / 2 };
      m.layerDirty = true;
      touchMode();
      opt.onChange();
    }
    function p2d(f, lat, lon) { return [f.ox + (lon + 180) * f.k, f.oy + (LAT_N - lat) * f.k]; }

    // küre KPI bloğunun altına girmesin diye biraz aşağıda ve sağda durur
    function globeR() { return Math.min(m.W * 0.46, m.H * 0.43) * m.zoom3; }
    function gcx() { return m.W * 0.54; }
    function gcy() { return m.H * 0.55; }
    // birim küre noktası -> ekran; z>0 görünür yüz
    function p3d(lat, lon, lift) {
      const cl = Math.cos(lat * RAD), x0 = cl * Math.sin((lon - m.lon0) * RAD), y0 = Math.sin(lat * RAD), z0 = cl * Math.cos((lon - m.lon0) * RAD);
      const cp = Math.cos(m.pitch), sp = Math.sin(m.pitch);
      const y = y0 * cp - z0 * sp, z = y0 * sp + z0 * cp, R = globeR() * (lift || 1);
      return [gcx() + x0 * R, gcy() - y * R, z];
    }

    function resize() {
      const r = stage.getBoundingClientRect();
      const dpr = Math.min(2, window.devicePixelRatio || 1);
      const W = Math.max(1, Math.floor(r.width)), H = Math.max(1, Math.floor(r.height));
      if (W === m.W && H === m.H && dpr === m.dpr) return false;
      m.W = W; m.H = H; m.dpr = dpr;
      canvas.width = Math.floor(W * dpr); canvas.height = Math.floor(H * dpr);
      if (gl) gl.resize(W, H, dpr);
      clampC2();
      return true;
    }

    // 2B statik katman: kara ızgarası + ince çerçeve çizgileri
    function buildLayer() {
      m.layerDirty = false;
      layer.width = canvas.width; layer.height = canvas.height;
      lctx.setTransform(m.dpr, 0, 0, m.dpr, 0, 0);
      lctx.clearRect(0, 0, m.W, m.H);
      const f = fit2d(), cell = G.flatStep * f.k, s = Math.max(1, Math.min(2.2 * Math.sqrt(m.zoom2), cell * 0.42));
      lctx.fillStyle = COL.p4;
      for (let i = 0; i < G.flat.length; i += 2) {
        const p = p2d(f, G.flat[i] / 10, G.flat[i + 1] / 10);
        lctx.globalAlpha = 0.5 + 0.25 * ((hash(String(i)) & 255) / 255);
        lctx.fillRect(p[0] - s / 2, p[1] - s / 2, s, s);
      }
      lctx.globalAlpha = 1;
      // ekvator ve 0. meridyen: noktalı kılavuz
      lctx.fillStyle = COL.p5;
      const eq = p2d(f, 0, -180)[1];
      for (let x = f.ox; x < f.ox + 360 * f.k; x += 6) lctx.fillRect(x, eq, 1, 1);
    }

    function dottedPath(pts, color, alpha, every) {
      ctx.fillStyle = color; ctx.globalAlpha = alpha;
      for (let i = 0; i < pts.length; i += every) ctx.fillRect(pts[i][0] - 0.6, pts[i][1] - 0.6, 1.2, 1.2);
    }

    // yay noktaları: 2B'de kaldırılmış ikinci derece eğri, 3B'de kaldırılmış büyük daire
    function arcPoints(a, b) {
      const n = 64, out = [];
      if (m.mode === "2d") {
        const f = fit2d(), A = p2d(f, a.lat, a.lon), B = p2d(f, b.lat, b.lon);
        const dx = B[0] - A[0], dy = B[1] - A[1], d = Math.hypot(dx, dy) || 1;
        const cx = (A[0] + B[0]) / 2 + (dy / d) * d * 0.22 * (dx > 0 ? -1 : 1), cy = (A[1] + B[1]) / 2 - Math.abs(dx / d) * d * 0.22;
        for (let i = 0; i <= n; i++) { const t = i / n, u = 1 - t; out.push([u * u * A[0] + 2 * u * t * cx + t * t * B[0], u * u * A[1] + 2 * u * t * cy + t * t * B[1], 1]); }
        return out;
      }
      const v = (p) => { const cl = Math.cos(p.lat * RAD); return [cl * Math.cos(p.lon * RAD), cl * Math.sin(p.lon * RAD), Math.sin(p.lat * RAD)]; };
      const A = v(a), B = v(b), dot = clamp(A[0] * B[0] + A[1] * B[1] + A[2] * B[2], -1, 1), om = Math.acos(dot), so = Math.sin(om) || 1;
      for (let i = 0; i <= n; i++) {
        const t = i / n, ka = Math.sin((1 - t) * om) / so, kb = Math.sin(t * om) / so;
        const x = ka * A[0] + kb * B[0], y = ka * A[1] + kb * B[1], z = ka * A[2] + kb * B[2];
        const lat = Math.asin(clamp(z, -1, 1)) / RAD, lon = Math.atan2(y, x) / RAD;
        const lift = 1 + Math.sin(Math.PI * t) * (0.06 + 0.22 * om / Math.PI);
        const p = p3d(lat, lon, lift), rr = Math.hypot(p[0] - gcx(), p[1] - gcy()) / globeR();
        out.push([p[0], p[1], p[2] > 0 || rr > 1 ? 1 : 0]);
      }
      return out;
    }

    function drawGlobe() {
      const R = globeR(), cx = gcx(), cy = gcy();
      // kenar halkası
      ctx.fillStyle = COL.p5; ctx.globalAlpha = 0.9;
      for (let a = 0; a < 360; a += 1.5) ctx.fillRect(cx + Math.cos(a * RAD) * R - 0.5, cy + Math.sin(a * RAD) * R - 0.5, 1, 1);
      const cp = Math.cos(m.pitch), sp = Math.sin(m.pitch), l0 = m.lon0 * RAD, s = Math.max(1, Math.min(1.9 * Math.sqrt(m.zoom3), R / 150));
      ctx.fillStyle = COL.p2;
      for (let i = 0; i < gn; i++) {
        const dl = gLon[i] - l0, x0 = gCl[i] * Math.sin(dl), z0 = gCl[i] * Math.cos(dl), y0 = gSl[i];
        const z = y0 * sp + z0 * cp;
        if (z <= 0.02) continue;
        const y = y0 * cp - z0 * sp;
        ctx.globalAlpha = 0.12 + 0.5 * z;
        ctx.fillRect(cx + x0 * R - s / 2, cy - y * R - s / 2, s, s);
      }
    }

    function where(p) {
      if (m.mode === "2d") { const q = p2d(fit2d(), p.lat, p.lon); return [q[0], q[1], 1]; }
      const q = p3d(p.lat, p.lon, 1); return [q[0], q[1], q[2] > 0.02 ? 1 : 0, q[2]];
    }

    function label(text, x, y, color, align) {
      ctx.globalAlpha = 1;
      ctx.font = "10px " + MONO; ctx.fillStyle = color; ctx.textAlign = align || "left"; ctx.textBaseline = "middle";
      if ("letterSpacing" in ctx) ctx.letterSpacing = "0.4px";
      if (m.style !== "nokta") {
        // görüntü tabanında okunurluk için koyu hale
        ctx.lineWidth = 3; ctx.lineJoin = "round"; ctx.strokeStyle = "rgba(6,6,6,0.85)";
        ctx.strokeText(text, Math.round(x), Math.round(y));
      }
      ctx.fillText(text, Math.round(x), Math.round(y));
    }

    function draw(now) {
      if (m.W < 2) return;
      const dt = m.lastT ? Math.min(0.1, (now - m.lastT) / 1000) : 0; m.lastT = now;
      if (m.spin) {
        // seçilen IP'ye yumuşak dönüş
        const e = Math.min(1, (now - m.spin.t0) / 900), k = e * e * (3 - 2 * e);
        m.lon0 = m.spin.from + m.spin.d * k;
        if (e >= 1) m.spin = null;
      } else if (m.mode === "3d" && !m.drag && !m.reduced && !m.selected) m.lon0 = (m.lon0 + dt * 3) % 360;
      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.globalAlpha = 1; ctx.globalCompositeOperation = "source-over";
      const useGL = gl && m.style !== "nokta";
      if (useGL) {
        // taban WebGL'de; bu katman saydam kalır, yalnızca işaretler çizilir
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        const f = fit2d();
        gl.draw({ mode: m.mode, style: m.style, color: m.color, W: m.W, H: m.H, dpr: m.dpr, cx: gcx(), cy: gcy(), R: globeR(), lon0: m.lon0, pitch: m.pitch, k: f.k, ox: f.ox, oy: f.oy });
      } else {
        ctx.fillStyle = COL.bg; ctx.fillRect(0, 0, canvas.width, canvas.height);
        if (m.mode === "2d") { if (m.layerDirty) buildLayer(); ctx.drawImage(layer, 0, 0); }
      }
      ctx.setTransform(m.dpr, 0, 0, m.dpr, 0, 0);
      if (m.mode === "3d" && !useGL) drawGlobe();

      const tgt = m.targets[0] || null;
      const maxAtt = m.attackers.reduce((a, b) => Math.max(a, b.attempts), 1);
      // yaylar (en çok deneyen 40 kaynak)
      if (tgt) {
        const top = m.attackers.slice(0, 40);
        for (let k = 0; k < top.length; k++) {
          const a = top[k], pts = arcPoints(a, tgt), vis = pts.filter((p) => p[2]);
          if (!vis.length) continue;
          const fresh = m.pulses.some((p) => p.ip === a.ip) || a.ip === m.selected;
          dottedPath(vis, fresh ? COL.warn : COL.p2, fresh ? 0.95 : 0.5, 2);
          if (!m.reduced) {
            // yol boyunca ilerleyen paket ve kısa iz
            const per = 2600 + (hash(a.ip) % 1400), t = ((now + (hash(a.ip) % per)) % per) / per, head = Math.floor(t * (pts.length - 1));
            for (let j = 0; j < 7; j++) {
              const p = pts[head - j]; if (!p || !p[2]) continue;
              ctx.globalAlpha = (fresh ? 1 : 0.8) * (1 - j / 7);
              ctx.fillStyle = fresh ? COL.warn : COL.p0;
              const s = j === 0 ? 2 : 1.3; ctx.fillRect(p[0] - s / 2, p[1] - s / 2, s, s);
            }
          }
        }
      }
      // saldırgan işaretleri
      const labelled = [];
      m.screen = [];
      for (const a of m.attackers) {
        const p = where(a); if (!p[2]) continue;
        m.screen.push({ ip: a.ip, x: p[0], y: p[1] });
        const r = 1.6 + 3.2 * Math.sqrt(a.attempts / maxAtt);
        ctx.globalAlpha = 0.95; ctx.fillStyle = a.blocked ? COL.warn : COL.p0;
        ctx.fillRect(p[0] - r / 2, p[1] - r / 2, r, r);
        ctx.globalAlpha = 0.35;
        for (let q = 0; q < 10; q++) { const ang = q / 10 * Math.PI * 2; ctx.fillRect(p[0] + Math.cos(ang) * (r + 3) - 0.5, p[1] + Math.sin(ang) * (r + 3) - 0.5, 1, 1); }
        // etiketler: en çok deneyen ilk 6 kaynak, birbirine çarpanlar atlanır
        if (labelled.length < 6 && !labelled.some((q) => Math.abs(q[1][0] - p[0]) < 46 && Math.abs(q[1][1] - p[1]) < 13)) labelled.push([a, p]);
      }
      for (const [a, p] of labelled) label(a.cc + " " + a.attempts, p[0] + 9, p[1] - 1, a.blocked ? COL.warn : COL.p1);
      // seçili kaynak: köşeli hedef çerçevesi
      const sel = m.selected && m.attackers.find((x) => x.ip === m.selected);
      if (sel) {
        const p = where(sel);
        if (p[2]) {
          const g = 9 + (m.reduced ? 0 : Math.sin(now / 260) * 1.5), L = 4;
          ctx.globalAlpha = 1; ctx.strokeStyle = COL.warn; ctx.lineWidth = 1;
          ctx.beginPath();
          for (const [sx, sy] of [[-1, -1], [1, -1], [1, 1], [-1, 1]]) {
            const cx = Math.round(p[0] + sx * g) + 0.5, cy = Math.round(p[1] + sy * g) + 0.5;
            ctx.moveTo(cx, cy - sy * L); ctx.lineTo(cx, cy); ctx.lineTo(cx - sx * L, cy);
          }
          ctx.stroke();
          label(sel.ip, p[0] + g + 6, p[1] - g, COL.warn);
        }
      }
      // yeni bulgu: genişleyen halka
      m.pulses = m.pulses.filter((u) => now - u.t0 < 6000);
      for (const u of m.pulses) {
        const a = m.attackers.find((x) => x.ip === u.ip); if (!a) continue;
        const p = where(a); if (!p[2]) continue;
        const e = ((now - u.t0) % 1500) / 1500, rr = 4 + e * 22;
        ctx.fillStyle = COL.warn; ctx.globalAlpha = (1 - e) * 0.9;
        for (let q = 0; q < 24; q++) { const ang = q / 24 * Math.PI * 2; ctx.fillRect(p[0] + Math.cos(ang) * rr - 0.6, p[1] + Math.sin(ang) * rr - 0.6, 1.2, 1.2); }
      }
      // hedef sunucular
      for (const t of m.targets) {
        const p = where(t); if (!p[2]) continue;
        ctx.globalAlpha = 1; ctx.strokeStyle = COL.p0; ctx.lineWidth = 1;
        ctx.strokeRect(Math.round(p[0]) - 3.5, Math.round(p[1]) - 3.5, 7, 7);
        ctx.fillStyle = COL.p0; ctx.fillRect(Math.round(p[0]) - 0.5, Math.round(p[1]) - 0.5, 1, 1);
        label(t.name, p[0] - 9, p[1] + 1, COL.txt, "right");
      }
      let note = m.note;
      if (m.style === "uydu" && gl && gl.satellite === "loading") note = "UYDU GÖRÜNTÜSÜ YÜKLENİYOR…";
      else if (m.style === "uydu" && gl && gl.satellite === "error") note = "UYDU GÖRÜNTÜSÜ YÜKLENEMEDİ";
      if (note) label(note, 12, m.H - 12, COL.p3);
      const z = m.mode === "3d" ? m.zoom3 : m.zoom2;
      if (z > 1.01) label(z.toFixed(1) + "×", m.W - 12, m.H - 12, COL.p3, "right");
      if (!m.attackers.length && !m.note) label("SON 24 SAATTE KONUMLANAN SALDIRI YOK", m.W / 2, m.H / 2, COL.p3, "center");
      ctx.globalAlpha = 1;
    }

    // 3B: sürükleyerek ve ok tuşlarıyla döndürme
    // tıklama (sürüklemesiz): en yakın saldırganı seçer
    let down = null;
    canvas.addEventListener("pointerdown", (e) => {
      down = { x: e.clientX, y: e.clientY };
      if (m.mode === "2d") {
        if (m.zoom2 > 1.001) { m.pan = { x: e.clientX, y: e.clientY, lon: m.c2.lon, lat: m.c2.lat }; canvas.setPointerCapture(e.pointerId); }
        return;
      }
      m.spin = null;
      m.drag = { x: e.clientX, y: e.clientY, lon0: m.lon0, pitch: m.pitch };
      canvas.setPointerCapture(e.pointerId);
    });
    canvas.addEventListener("pointerup", (e) => {
      if (!down || Math.hypot(e.clientX - down.x, e.clientY - down.y) > 4) { down = null; return; }
      down = null;
      const r = canvas.getBoundingClientRect(), x = e.clientX - r.left, y = e.clientY - r.top;
      let best = null, bd = 14;
      for (const q of m.screen) { const d = Math.hypot(q.x - x, q.y - y); if (d < bd) { bd = d; best = q.ip; } }
      if (opt.onPick) opt.onPick(best);
    });
    canvas.addEventListener("pointermove", (e) => {
      if (m.pan) {
        const k = baseK() * m.zoom2;
        m.c2.lon = m.pan.lon - (e.clientX - m.pan.x) / k;
        m.c2.lat = m.pan.lat + (e.clientY - m.pan.y) / k;
        clampC2();
        opt.onChange();
        return;
      }
      if (!m.drag) {
        if (m.screen.length) {
          const r = canvas.getBoundingClientRect(), x = e.clientX - r.left, y = e.clientY - r.top;
          const near = m.screen.some((q) => Math.hypot(q.x - x, q.y - y) < 14);
          canvas.style.cursor = near ? "pointer" : m.mode === "3d" || m.zoom2 > 1.001 ? "grab" : "default";
        }
        return;
      }
      const k = 180 / Math.max(1, globeR() * Math.PI);
      m.lon0 = m.drag.lon0 - (e.clientX - m.drag.x) * k;
      m.pitch = clamp(m.drag.pitch + (e.clientY - m.drag.y) * k * RAD, -60 * RAD, 60 * RAD);
      opt.onChange();
    });
    const end = () => { m.drag = null; m.pan = null; };
    canvas.addEventListener("pointerup", end); canvas.addEventListener("pointercancel", end);
    // tekerlek: imlecin olduğu yere yakınlaştır (sayfa kaydırması harita üstündeyken durur)
    canvas.addEventListener("wheel", (e) => {
      e.preventDefault();
      const unit = e.deltaMode === 1 ? 16 : e.deltaMode === 2 ? 400 : 1;
      const r = canvas.getBoundingClientRect();
      zoomAt(Math.exp(-e.deltaY * unit * 0.0015), e.clientX - r.left, e.clientY - r.top);
    }, { passive: false });
    canvas.addEventListener("dblclick", (e) => { e.preventDefault(); resetView(); });
    stage.addEventListener("keydown", (e) => {
      if (e.key === "+" || e.key === "=") { e.preventDefault(); zoomAt(1.25); return; }
      if (e.key === "-" || e.key === "_") { e.preventDefault(); zoomAt(0.8); return; }
      if (e.key === "0") { e.preventDefault(); resetView(); return; }
      if (m.mode !== "3d") return;
      const d = { ArrowLeft: [-10, 0], ArrowRight: [10, 0], ArrowUp: [0, -6], ArrowDown: [0, 6] }[e.key];
      if (!d) return;
      e.preventDefault(); m.lon0 += d[0]; m.pitch = clamp(m.pitch + d[1] * RAD, -60 * RAD, 60 * RAD); opt.onChange();
    });

    return {
      resize,
      draw,
      zoomBy(f) { zoomAt(f); },
      resetView,
      get zoom() { return m.mode === "3d" ? m.zoom3 : m.zoom2; },
      get glOK() { return !!gl; },
      setStyle(style, color) {
        m.style = gl && (style === "sinir" || style === "uydu") ? style : "nokta";
        m.color = !!color;
        if (m.style === "uydu") gl.loadSatellite();
        if (opt.glCanvas) opt.glCanvas.hidden = m.style === "nokta";
        m.layerDirty = true;
      },
      get style() { return m.style; },
      setMode(mode) {
        m.mode = mode === "3d" ? "3d" : "2d";
        canvas.style.cursor = m.mode === "3d" ? "grab" : "default";
        touchMode();
      },
      get mode() { return m.mode; },
      setReduced(v) { m.reduced = !!v; },
      // attackers: [{ip, cc, name, lat, lon, attempts, blocked}] deneme sayısına göre azalan
      setData(attackers, targets, note) {
        m.attackers = attackers.map((a) => {
          const h = hash(a.ip), j = a.cc ? 2.2 : 0; // aynı ülkedeki IP'leri az dağıt
          return Object.assign({}, a, { lat: clamp(a.lat + ((h & 1023) / 1023 - 0.5) * j, -80, 82), lon: a.lon + (((h >>> 10) & 1023) / 1023 - 0.5) * j * 1.4 });
        });
        m.targets = targets;
        m.note = note || "";
      },
      pulse(ip, now) { if (!m.reduced) m.pulses.push({ ip, t0: now }); },
      // seç / bırak; 3B'de küre seçilen kaynağa döner
      select(ip, now) {
        m.selected = ip || null;
        const a = ip && m.attackers.find((x) => x.ip === ip);
        if (a && m.mode === "3d") {
          let d = ((a.lon - m.lon0 + 540) % 360) - 180;
          if (m.reduced) m.lon0 = a.lon; else m.spin = { from: m.lon0, d, t0: now || performance.now() };
        }
      },
      // yeniden çizim gerekiyor mu: döner küre, hareketli paketler ya da halka
      animating() { return !!m.spin || (!m.reduced && (m.mode === "3d" || !!m.selected || (m.targets.length > 0 && m.attackers.length > 0) || m.pulses.length > 0)); },
    };
  }

  window.NexMap = { create };
})();
