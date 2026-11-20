/* NexGuard: canlı haritanın 3B küre görünümü.
   Veri harita.js'in her 5 sn'de aldığı /api/live yanıtıdır (window.NexKure.update ile gelir);
   ülke merkezleri world.json'daki eşdikdörtgen x,y'den enlem/boylama çevrilir:
   boylam = x * 0.36 - 180, enlem = 90 - y * 0.36. Taban kure.js (WebGL2), işaretler Canvas2D.
   Tüm metinler textContent/fillText ile yazılır; hiçbir değer HTML olarak yorumlanmaz. */
(function () {
  "use strict";
  var shell = document.querySelector(".map-shell");
  if (!shell) return;
  var RAD = Math.PI / 180, ZMAX = 8;
  var clamp = function (v, a, b) { return v < a ? a : v > b ? b : v; };
  var calm = window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches;
  var store = function (k, v) { try { localStorage.setItem(k, v); } catch (e) { /* depolama kapalı */ } };
  var load = function (k) { try { return localStorage.getItem(k); } catch (e) { return null; } };

  var svg = shell.querySelector("#worldmap");
  var globe = shell.querySelector(".globe");
  var glCv = globe.querySelector(".g-gl"), ov = globe.querySelector(".g-ov");
  var ctx = ov.getContext("2d");
  var styleBox = shell.querySelector(".map-style");
  var css = getComputedStyle(document.documentElement);
  var tok = function (n, d) { return (css.getPropertyValue(n) || d).trim() || d; };
  var C = {
    bg: "#1f1f1d", sea: "#1f1f1d", land: "#3a3a37", line: "#1d1d1b",
    h1: "#5c5138", h2: "#7d6a3f", h3: "#a98743", h4: "#d8a54c",
    fg: tok("--fg", "#f4f3ef"), muted: tok("--muted", "#b4b3ac"), mark: tok("--mark", "#f6b95c"),
    warn: tok("--warn", "#f0893f"), bad: tok("--bad", "#f0584f"), home: tok("--t-orange", "#e87f4d"),
    surface: tok("--surface", "#2a2a28"), lineUi: tok("--line", "#41413e"),
  };

  var m = {
    view: "2d", style: load("ng.kure.stil") === "uydu" ? "uydu" : "sinir", color: load("ng.kure.renk") === "1",
    W: 0, H: 0, dpr: 1, lon0: 30, pitch: 22 * RAD, zoom: 1,
    data: null, drag: null, spin: null, screen: [], seen: {}, born: {}, lastT: 0, raf: 0, idleUntil: 0,
  };
  var gl = null, glTried = false;

  function ll(x, y) { return { lon: x * 0.36 - 180, lat: 90 - y * 0.36 }; }
  function R() { return Math.min(m.W * 0.46, m.H * 0.44) * m.zoom; }
  function cx() { return m.W / 2; }
  function cy() { return m.H / 2; }
  function proj(lat, lon, lift) {
    var cl = Math.cos(lat * RAD), x0 = cl * Math.sin((lon - m.lon0) * RAD), y0 = Math.sin(lat * RAD), z0 = cl * Math.cos((lon - m.lon0) * RAD);
    var cp = Math.cos(m.pitch), sp = Math.sin(m.pitch), y = y0 * cp - z0 * sp, z = y0 * sp + z0 * cp, r = R() * (lift || 1);
    return [cx() + x0 * r, cy() - y * r, z];
  }

  // ülke dolgusu 2B haritadaki dört tonlu yoğunluk ölçeğiyle aynı
  function applyHeat() {
    if (!gl || !m.data) return;
    var mx = m.data.countries.reduce(function (a, c) { return Math.max(a, c.n); }, 0), heat = {};
    m.data.countries.forEach(function (c) { var r = mx ? c.n / mx : 0; heat[c.cc] = r > 0.66 ? 1 : r > 0.33 ? 0.75 : r > 0.1 ? 0.5 : 0.25; });
    gl.setHeat(heat);
  }

  function ensureGL() {
    if (glTried) return gl;
    glTried = true;
    var paths = [].map.call(svg ? svg.querySelectorAll(".land path") : [], function (p) { return { cc: p.id.replace("c-", ""), d: p.getAttribute("d") }; });
    gl = window.NexKureGL ? window.NexKureGL.create(glCv, { paths: paths, colors: C, onChange: kick }) : null;
    if (!gl) {
      var n = globe.querySelector(".g-note");
      n.textContent = "Bu tarayıcıda WebGL2 yok; 3B küre gösterilemiyor.";
      n.hidden = false;
    }
    applyHeat();
    return gl;
  }

  function resize() {
    var r = globe.getBoundingClientRect(), dpr = Math.min(2, window.devicePixelRatio || 1);
    var W = Math.max(1, Math.floor(r.width)), H = Math.max(1, Math.floor(r.height));
    if (W === m.W && H === m.H && dpr === m.dpr) return;
    m.W = W; m.H = H; m.dpr = dpr;
    ov.width = Math.floor(W * dpr); ov.height = Math.floor(H * dpr);
    if (gl) gl.resize(W, H, dpr);
    kick();
  }

  // ---------- çizim ----------
  function arcPts(a, b) {
    var v = function (p) { var cl = Math.cos(p.lat * RAD); return [cl * Math.cos(p.lon * RAD), cl * Math.sin(p.lon * RAD), Math.sin(p.lat * RAD)]; };
    var A = v(a), B = v(b), om = Math.acos(clamp(A[0] * B[0] + A[1] * B[1] + A[2] * B[2], -1, 1)), so = Math.sin(om) || 1, out = [];
    for (var i = 0; i <= 48; i++) {
      var t = i / 48, ka = Math.sin((1 - t) * om) / so, kb = Math.sin(t * om) / so;
      var x = ka * A[0] + kb * B[0], y = ka * A[1] + kb * B[1], z = ka * A[2] + kb * B[2];
      var p = proj(Math.asin(clamp(z, -1, 1)) / RAD, Math.atan2(y, x) / RAD, 1 + Math.sin(Math.PI * t) * (0.05 + 0.2 * om / Math.PI));
      var rr = Math.hypot(p[0] - cx(), p[1] - cy()) / R();
      out.push([p[0], p[1], p[2] > 0 || rr > 1]);
    }
    return out;
  }

  function stroke(pts, color, width, alpha, upto) {
    ctx.strokeStyle = color; ctx.lineWidth = width; ctx.globalAlpha = alpha; ctx.lineCap = "round";
    ctx.beginPath();
    var on = false, n = Math.max(1, Math.floor((pts.length - 1) * (upto == null ? 1 : upto)));
    for (var i = 0; i <= n; i++) {
      var p = pts[i];
      if (!p[2]) { on = false; continue; }
      if (on) ctx.lineTo(p[0], p[1]); else { ctx.moveTo(p[0], p[1]); on = true; }
    }
    ctx.stroke();
  }

  function pill(text, x, y, right) {
    ctx.font = "500 12px " + tok("--sans", "system-ui");
    var w = ctx.measureText(text).width + 18, h = 22, px = right ? x - w : x, py = y - h / 2;
    ctx.globalAlpha = 0.95;
    ctx.fillStyle = C.surface; ctx.strokeStyle = C.lineUi; ctx.lineWidth = 1;
    ctx.beginPath();
    if (ctx.roundRect) ctx.roundRect(px + 0.5, py + 0.5, w, h, 11); else ctx.rect(px + 0.5, py + 0.5, w, h);
    ctx.fill(); ctx.stroke();
    ctx.globalAlpha = 1; ctx.fillStyle = C.fg; ctx.textBaseline = "middle"; ctx.textAlign = "left";
    ctx.fillText(text, px + 9, y + 1);
    return [px, py, w, h];
  }

  function draw(now) {
    var dt = m.lastT ? Math.min(0.1, (now - m.lastT) / 1000) : 0;
    m.lastT = now;
    if (m.spin) {
      var e = Math.min(1, (now - m.spin.t0) / 900), k = e * e * (3 - 2 * e);
      m.lon0 = m.spin.from + m.spin.d * k;
      if (e >= 1) m.spin = null;
    } else if (!calm && !m.drag && now > m.idleUntil) m.lon0 = (m.lon0 + dt * 2.5) % 360;

    if (gl) gl.draw({ style: m.style, color: m.color, W: m.W, H: m.H, dpr: m.dpr, cx: cx(), cy: cy(), R: R(), lon0: m.lon0, pitch: m.pitch });
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.clearRect(0, 0, ov.width, ov.height);
    ctx.setTransform(m.dpr, 0, 0, m.dpr, 0, 0);
    var p = m.data;
    m.screen = [];
    if (!p) return;
    var level = p.level || 0;
    var home = p.home ? ll(p.home.x, p.home.y) : null;
    var list = p.countries.filter(function (c) { return c.x !== null; });

    // yaylar: en çok bağlanan 8 ülkeden sunucuya
    if (home) {
      list.filter(function (c) { return c.cc !== p.home.cc; }).slice(0, 8).forEach(function (c, i) {
        var pts = arcPts(ll(c.x, c.y), home);
        var age = calm ? 1 : clamp((now - (m.born[c.cc] || 0)) / 600, 0, 1);
        if (i === 0) stroke(pts, level >= 2 ? C.bad : C.mark, 1.8, 1, age);
        else stroke(pts, C.fg, 1, 0.5, age);
      });
    }
    // ülke noktaları
    var max = list.reduce(function (a, c) { return Math.max(a, c.n); }, 1);
    list.forEach(function (c) {
      var q = ll(c.x, c.y), s = proj(q.lat, q.lon, 1);
      if (s[2] <= 0.02) return;
      var r = 3 + Math.min(9, Math.sqrt(c.n)), anon = c.anon * 2 > c.n;
      var col = anon ? C.warn : C.fg;
      if (!calm) {
        var ph = ((now / 1800) + (c.cc.charCodeAt(0) % 7) / 7) % 1;
        ctx.globalAlpha = 0.5 * (1 - ph); ctx.strokeStyle = col; ctx.lineWidth = 1;
        ctx.beginPath(); ctx.arc(s[0], s[1], r + ph * 10, 0, Math.PI * 2); ctx.stroke();
      }
      ctx.globalAlpha = 0.5; ctx.strokeStyle = col; ctx.lineWidth = 1;
      ctx.beginPath(); ctx.arc(s[0], s[1], r, 0, Math.PI * 2); ctx.stroke();
      ctx.globalAlpha = 1; ctx.fillStyle = col; ctx.strokeStyle = C.bg;
      ctx.beginPath(); ctx.arc(s[0], s[1], Math.max(2.5, r / 2.2), 0, Math.PI * 2); ctx.fill(); ctx.stroke();
      m.screen.push({ c: c, x: s[0], y: s[1], r: r });
    });
    // sunucu
    if (home) {
      var h = proj(home.lat, home.lon, 1);
      if (h[2] > 0.02) { ctx.globalAlpha = 1; ctx.fillStyle = C.home; ctx.beginPath(); ctx.arc(h[0], h[1], 5, 0, Math.PI * 2); ctx.fill(); }
    }
    // etiketler: en çok bağlanan 5 ülke, çakışanlar atlanır
    var boxes = [], narrow = m.W < 560;
    m.screen.slice().sort(function (a, b) { return b.c.n - a.c.n; }).slice(0, narrow ? 3 : 5).forEach(function (s) {
      var name = narrow || s.c.country.length > 16 ? s.c.cc : s.c.country;
      var right = s.x > m.W * 0.6, tx = right ? s.x - s.r - 8 : s.x + s.r + 8, ty = s.y - s.r - 8;
      ctx.font = "500 12px " + tok("--sans", "system-ui");
      var w = ctx.measureText(name + " " + s.c.n).width + 18;
      var bx = right ? tx - w : tx;
      if (boxes.some(function (b) { return bx < b[0] + b[2] && bx + w > b[0] && Math.abs(ty - b[1]) < 24; })) return;
      boxes.push([bx, ty, w]);
      pill(name + " " + s.c.n, tx, ty, right);
    });
    if (m.zoom > 1.01) {
      ctx.globalAlpha = 1; ctx.fillStyle = C.muted; ctx.font = "500 12px " + tok("--sans", "system-ui");
      ctx.textAlign = "right"; ctx.textBaseline = "alphabetic";
      ctx.fillText(m.zoom.toFixed(1).replace(".", ",") + "×", m.W - 12, m.H - 12);
    }
    var note = m.style === "uydu" && gl && gl.satellite === "loading" ? "Uydu görüntüsü yükleniyor…" : m.style === "uydu" && gl && gl.satellite === "error" ? "Uydu görüntüsü yüklenemedi." : "";
    if (note) { ctx.globalAlpha = 1; ctx.fillStyle = C.muted; ctx.textAlign = "left"; ctx.fillText(note, 12, m.H - 12); }
    ctx.globalAlpha = 1;
  }

  // dönerken sürekli, durunca yalnız değişiklikte çizilir; görünmeyen sekmede durur
  function loop(ts) {
    m.raf = 0;
    if (m.view !== "3d" || document.hidden) return;
    draw(ts);
    if (!calm || m.spin || m.drag) m.raf = requestAnimationFrame(loop);
  }
  function kick() { if (m.view === "3d" && !m.raf) m.raf = requestAnimationFrame(loop); }

  // ---------- etkileşim ----------
  function zoomBy(f) { m.zoom = clamp(m.zoom * f, 1, ZMAX); m.idleUntil = performance.now() + 4000; kick(); }
  function reset() { m.zoom = 1; m.pitch = 22 * RAD; kick(); }
  var down = null;
  ov.addEventListener("pointerdown", function (e) {
    down = { x: e.clientX, y: e.clientY };
    m.spin = null;
    m.drag = { x: e.clientX, y: e.clientY, lon0: m.lon0, pitch: m.pitch };
    ov.setPointerCapture(e.pointerId);
    kick();
  });
  ov.addEventListener("pointermove", function (e) {
    if (!m.drag) {
      var r0 = ov.getBoundingClientRect(), x0 = e.clientX - r0.left, y0 = e.clientY - r0.top;
      ov.style.cursor = m.screen.some(function (s) { return Math.hypot(s.x - x0, s.y - y0) < s.r + 6; }) ? "pointer" : "grab";
      return;
    }
    var k = 180 / Math.max(1, R() * Math.PI);
    m.lon0 = m.drag.lon0 - (e.clientX - m.drag.x) * k;
    m.pitch = clamp(m.drag.pitch + (e.clientY - m.drag.y) * k * RAD, -60 * RAD, 60 * RAD);
  });
  function end(e) {
    m.drag = null;
    m.idleUntil = performance.now() + 4000;
    if (down && e && Math.hypot(e.clientX - down.x, e.clientY - down.y) <= 4) {
      var r0 = ov.getBoundingClientRect(), x0 = e.clientX - r0.left, y0 = e.clientY - r0.top, best = null, bd = 1e9;
      m.screen.forEach(function (s) { var d = Math.hypot(s.x - x0, s.y - y0); if (d < s.r + 8 && d < bd) { bd = d; best = s.c; } });
      if (best && window.NexDetay) window.NexDetay.openCountry(best.cc, ov);
    }
    down = null;
    kick();
  }
  ov.addEventListener("pointerup", end);
  ov.addEventListener("pointercancel", function () { m.drag = null; down = null; });
  ov.addEventListener("wheel", function (e) {
    e.preventDefault();
    var unit = e.deltaMode === 1 ? 16 : e.deltaMode === 2 ? 400 : 1;
    zoomBy(Math.exp(-e.deltaY * unit * 0.0015));
  }, { passive: false });
  ov.addEventListener("dblclick", function (e) { e.preventDefault(); reset(); });
  globe.addEventListener("keydown", function (e) {
    var d = { ArrowLeft: [-10, 0], ArrowRight: [10, 0], ArrowUp: [0, -6], ArrowDown: [0, 6] }[e.key];
    if (d) { e.preventDefault(); m.lon0 += d[0]; m.pitch = clamp(m.pitch + d[1] * RAD, -60 * RAD, 60 * RAD); m.idleUntil = performance.now() + 4000; kick(); return; }
    if (e.key === "+" || e.key === "=") { e.preventDefault(); zoomBy(1.25); }
    else if (e.key === "-") { e.preventDefault(); zoomBy(0.8); }
    else if (e.key === "0") { e.preventDefault(); reset(); }
  });
  globe.querySelectorAll("[data-gz]").forEach(function (b) {
    b.addEventListener("click", function () { var z = b.getAttribute("data-gz"); if (z === "reset") reset(); else zoomBy(z === "in" ? 1.4 : 1 / 1.4); });
  });

  // ---------- görünüm ve stil seçimi ----------
  function paintButtons() {
    shell.querySelectorAll("[data-mv]").forEach(function (b) { b.setAttribute("aria-pressed", String(b.getAttribute("data-mv") === m.view)); });
    shell.querySelectorAll("[data-ms]").forEach(function (b) { b.setAttribute("aria-pressed", String(b.getAttribute("data-ms") === m.style)); });
    var rb = shell.querySelector("[data-mc]");
    rb.hidden = m.style !== "uydu";
    rb.setAttribute("aria-pressed", String(m.color));
  }
  function setView(v, save) {
    m.view = v === "3d" ? "3d" : "2d";
    shell.classList.toggle("is-3d", m.view === "3d");
    globe.hidden = m.view !== "3d";
    styleBox.hidden = m.view !== "3d";
    if (svg) svg.style.display = m.view === "3d" ? "none" : "";
    if (save) store("ng.kure.gorunum", m.view);
    paintButtons();
    if (m.view === "3d") {
      ensureGL();
      if (gl && m.style === "uydu") gl.loadSatellite();
      resize();
      kick();
    }
  }
  function setStyle(s, color, save) {
    m.style = s === "uydu" ? "uydu" : "sinir";
    m.color = !!color;
    if (save) { store("ng.kure.stil", m.style); store("ng.kure.renk", m.color ? "1" : "0"); }
    if (gl && m.style === "uydu") gl.loadSatellite();
    paintButtons();
    kick();
  }
  shell.querySelectorAll("[data-mv]").forEach(function (b) { b.addEventListener("click", function () { setView(b.getAttribute("data-mv"), true); }); });
  shell.querySelectorAll("[data-ms]").forEach(function (b) { b.addEventListener("click", function () { setStyle(b.getAttribute("data-ms"), m.color, true); }); });
  shell.querySelector("[data-mc]").addEventListener("click", function () { setStyle(m.style, !m.color, true); });
  window.addEventListener("resize", function () { if (m.view === "3d") resize(); });
  document.addEventListener("visibilitychange", function () { if (!document.hidden) kick(); });

  window.NexKure = {
    update: function (p) {
      var first = !m.data;
      var now = performance.now(), seen = {};
      p.countries.forEach(function (c) { seen[c.cc] = 1; if (!m.seen[c.cc]) m.born[c.cc] = now; });
      m.seen = seen;
      m.data = p;
      if (first && p.home) m.lon0 = ll(p.home.x, p.home.y).lon;
      applyHeat();
      kick();
    },
    // seçili ülkeye dön (detay çekmecesinden)
    focus: function (cc) {
      var c = m.data && m.data.countries.filter(function (x) { return x.cc === cc && x.x !== null; })[0];
      if (!c || m.view !== "3d") return;
      var lon = ll(c.x, c.y).lon, d = ((lon - m.lon0 + 540) % 360) - 180;
      if (calm) m.lon0 = lon; else m.spin = { from: m.lon0, d: d, t0: performance.now() };
      m.idleUntil = performance.now() + 8000;
      kick();
    },
  };
  setStyle(m.style, m.color, false);
  setView(load("ng.kure.gorunum") === "3d" ? "3d" : "2d", false);
})();
