(function () {
  "use strict";
  var NS = "http://www.w3.org/2000/svg";
  var $ = function (id) { return document.getElementById(id); };
  var svg = $("worldmap"), dots = $("dots"), tip = $("map-tip"), state = $("live-state");
  if (!svg) return;
  var calm = window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches;
  var seenHits = {}, seenArcs = {}, shown = {}, timer = null, first = true;

  function svgEl(tag, attrs, parent) {
    var e = document.createElementNS(NS, tag);
    for (var k in attrs) e.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(e);
    return e;
  }
  function clear(e) { while (e.firstChild) e.removeChild(e.firstChild); }
  function td(text, cls) { var e = document.createElement("td"); e.textContent = text; if (cls) e.className = cls; return e; }
  function row(cells) { var tr = document.createElement("tr"); cells.forEach(function (c) { tr.appendChild(c); }); return tr; }
  function fmt(n) { return Math.round(n).toLocaleString("tr-TR"); }

  // Sayılar: referanstaki gibi sayarak yerine oturur
  function countTo(id, value, digits) {
    var el = $(id);
    if (!el) return;
    var format = digits ? function (v) { return v.toFixed(digits).replace(".", ","); } : fmt;
    var from = shown[id] || 0;
    shown[id] = value;
    if (calm || from === value) { el.textContent = format(value); return; }
    var dur = first ? 2400 : 700, t0 = performance.now();
    (function step(now) {
      var k = Math.min(1, (now - t0) / dur), e = 1 - Math.pow(1 - k, 4);
      el.textContent = format(from + (value - from) * e);
      if (k < 1) requestAnimationFrame(step);
    })(t0);
  }

  function drawLine(values, attack) {
    var box = $("pps-line");
    if (!box) return;
    clear(box);
    if (values.length < 2) return;
    var W = 360, H = 110, top = 12, bot = 6;
    var peak = Math.max.apply(null, values), max = Math.max(peak * 1.25, 1);
    var showThr = attack <= max * 1.6;
    if (showThr) max = Math.max(max, attack * 1.1);
    var pts = values.map(function (v, i) {
      return [(i / (values.length - 1)) * (W - 8) + 2, H - bot - (v / max) * (H - top - bot)];
    });
    var str = pts.map(function (p) { return p[0].toFixed(1) + "," + p[1].toFixed(1); }).join(" ");
    if (showThr) { var ty = H - bot - (attack / max) * (H - top - bot); svgEl("line", {"class": "thr", x1: 0, x2: W, y1: ty, y2: ty}, box); }
    svgEl("polygon", {"class": "area", points: "2," + (H - bot) + " " + str + " " + (W - 6) + "," + (H - bot)}, box);
    var ln = svgEl("polyline", {"class": "ln" + (first && !calm ? " draw" : ""), points: str, pathLength: 1}, box);
    if (!first) ln.removeAttribute("pathLength");
    var end = pts[pts.length - 1];
    svgEl("circle", {"class": "halo", cx: end[0], cy: end[1], r: 7}, box);
    svgEl("circle", {"class": "now", cx: end[0], cy: end[1], r: 3.5}, box);
  }

  function drawBars(id, values) {
    var box = $(id);
    if (!box) return;
    var max = Math.max.apply(null, values.concat([0.01]));
    while (box.children.length < values.length) box.appendChild(document.createElement("i"));
    values.forEach(function (v, i) {
      var b = box.children[i];
      b.className = v / max < 0.25 ? "dim" : "";
      b.style.transitionDelay = first ? (i * 50) + "ms" : "0ms";
      requestAnimationFrame(function () { b.style.height = Math.max(5, (v / max) * 100) + "%"; });
    });
  }

  function drawWeek(week) {
    var box = $("week");
    if (!box) return;
    var max = Math.max.apply(null, week.map(function (d) { return d.n; }).concat([1]));
    clear(box);
    week.forEach(function (d, i) {
      var w = document.createElement("div"), bar = document.createElement("i"), lab = document.createElement("span");
      if (i === week.length - 1) w.className = "today";
      lab.textContent = d.label;
      w.appendChild(bar); w.appendChild(lab); box.appendChild(w);
      var h = Math.max(12, (d.n / max) * 78);
      if (first && !calm) { bar.style.transitionDelay = (i * 70) + "ms"; requestAnimationFrame(function () { requestAnimationFrame(function () { bar.style.height = h + "%"; }); }); }
      else { bar.style.transition = "none"; bar.style.height = h + "%"; }
    });
  }

  // Kaynak ülkelerden sunucuya akan yaylar
  function drawArcs(p) {
    var layer = $("arcs");
    if (!layer) return;
    clear(layer);
    if (!p.home) return;
    var next = {};
    p.countries.filter(function (c) { return c.x !== null && c.cc !== p.home.cc; }).slice(0, 8).forEach(function (c, i) {
      var dx = p.home.x - c.x, dy = p.home.y - c.y, dist = Math.sqrt(dx * dx + dy * dy);
      var mx = (c.x + p.home.x) / 2, my = (c.y + p.home.y) / 2 - dist * 0.28;
      var d = "M" + c.x + " " + c.y + " Q" + mx + " " + my + " " + p.home.x + " " + p.home.y;
      var isNew = !seenArcs[c.cc];
      next[c.cc] = 1;
      var cls = "arc" + (i > 0 ? " minor" : "") + (isNew && !calm ? " draw" : "");
      var arc = svgEl("path", {"class": cls, d: d, pathLength: 1}, layer);
      if (isNew && !calm) arc.style.animationDelay = (0.3 + i * 0.18) + "s";
      if (i < 3 && !calm) svgEl("path", {"class": "flow", d: d, pathLength: 1}, layer);
    });
    seenArcs = next;
    var home = svgEl("g", {"class": "home", transform: "translate(" + p.home.x + " " + p.home.y + ")"}, layer);
    svgEl("circle", {"class": "halo", r: 11}, home);
    svgEl("circle", {r: 5}, home);
  }

  function drawCallouts(countries) {
    var layer = $("callouts");
    if (!layer) return;
    clear(layer);
    var width = (svg.parentNode && svg.parentNode.clientWidth) || svg.getBoundingClientRect().width;
    if (!width) return;
    var unit = 1000 / width, narrow = width < 560;
    var fs = 12 * unit, h = fs * 1.9, padX = fs * 0.75;
    var items = countries.filter(function (c) { return c.x !== null; }).slice(0, narrow ? 3 : 5).map(function (c) {
      var name = narrow || c.country.length > 16 ? c.cc : c.country;
      var flag = c.flag ? c.flag.split("/")[0] : "";
      var g = svgEl("g", {"class": "callout"}, layer);
      var line = svgEl("polyline", {}, g);
      var rect = svgEl("rect", {rx: h / 2}, g);
      var t = svgEl("text", {"font-size": fs}, g);
      t.textContent = name + " " + c.n + (flag && !narrow ? " · " + flag : "");
      return {c: c, line: line, rect: rect, t: t, w: t.getBBox().width + padX * 2, left: c.x > 640};
    });
    [true, false].forEach(function (left) {
      var floor = 14;
      items.filter(function (i) { return i.left === left; }).sort(function (a, b) { return a.c.y - b.c.y; }).forEach(function (i) {
        var y = Math.max(i.c.y - 30 * unit - h, floor);
        floor = y + h + 4 * unit;
        var x = left ? i.c.x - 34 * unit - i.w : i.c.x + 34 * unit;
        x = Math.max(2, Math.min(998 - i.w, x));
        i.rect.setAttribute("x", x); i.rect.setAttribute("y", y); i.rect.setAttribute("width", i.w); i.rect.setAttribute("height", h);
        i.t.setAttribute("x", x + padX); i.t.setAttribute("y", y + h * 0.68);
        var edge = left ? x + i.w : x, mid = y + h / 2;
        i.line.setAttribute("points", i.c.x + "," + i.c.y + " " + edge + "," + mid);
      });
    });
  }

  function showTip(c, ev) {
    if (!tip) return;
    var box = (tip.parentNode || svg).getBoundingClientRect();
    tip.textContent = c.country + ": " + c.n + " bağlantı, " + c.ips + " IP";
    tip.style.left = Math.min(ev.clientX - box.left + 12, box.width - 170) + "px";
    tip.style.top = (ev.clientY - box.top + 12) + "px";
    tip.hidden = false;
  }

  function setStateClasses(p) {
    var lvl = p.running ? "l" + p.level : "lx";
    var band = $("live-band");
    if (band) {
      band.className = "band " + lvl;
      $("band-state").textContent = p.state_label;
      $("band-facts").textContent = p.total + " bağlantı · " + p.countries.length + " ülke";
      $("band-why").textContent = p.why;
      $("live-ts").textContent = p.ts;
      $("gauge-fill").style.width = Math.min(100, p.pressure) + "%";
      $("gauge-text").textContent = p.pressure_text;
    }
    var pill = $("state-pill");
    if (pill) {
      pill.className = "state-pill " + lvl;
      pill.textContent = p.state_label;
      $("map-card").className = "map-card " + lvl;
      $("map-why").textContent = p.why + " · " + p.pressure_text;
    }
    svg.setAttribute("data-level", p.running ? p.level : 0);
  }

  function render(p) {
    setStateClasses(p);
    var vd = $("live-verdict");
    if (vd) vd.textContent = p.countries.length ? p.verdict : (p.installed ? "Şu an dışarıdan bağlı kaynak yok." : "Coğrafya veritabanı kurulu değil.");

    var max = 0, seen = {};
    p.countries.forEach(function (c) { if (c.n > max) max = c.n; });
    p.countries.forEach(function (c) {
      seen[c.cc] = true;
      var path = $("c-" + c.cc);
      if (!path) return;
      var r = max ? c.n / max : 0;
      path.setAttribute("class", "hit h" + (r > 0.66 ? 4 : r > 0.33 ? 3 : r > 0.1 ? 2 : 1));
    });
    Object.keys(seenHits).forEach(function (cc) {
      if (!seen[cc]) { var o = $("c-" + cc); if (o) o.removeAttribute("class"); }
    });
    seenHits = seen;

    clear(dots);
    p.countries.forEach(function (c) {
      if (c.x === null) return;
      var g = svgEl("g", {"class": "dot" + (c.anon * 2 > c.n ? " anon" : ""), transform: "translate(" + c.x + " " + c.y + ")"}, dots);
      var r = 3 + Math.min(9, Math.sqrt(c.n));
      svgEl("circle", {"class": "pulse", r: r}, g);
      svgEl("circle", {"class": "core", r: Math.max(2.5, r / 2.2)}, g);
      g.addEventListener("mousemove", function (ev) { showTip(c, ev); });
      g.addEventListener("mouseleave", function () { if (tip) tip.hidden = true; });
    });
    drawArcs(p);
    drawCallouts(p.countries);

    // pano
    drawLine(p.pps, p.attack_pps);
    drawBars("mbps-bars", p.mbps);
    if (p.week) drawWeek(first ? p.week : p.week);
    countTo("v-pps", p.rx_pps);
    countTo("v-mbps", p.rx_mbps, 1);
    countTo("v-mem", p.mem_pct);
    var att = $("v-attack"); if (att) att.textContent = fmt(p.attack_pps);
    var ring = $("mem-ring");
    if (ring) {
      ring.setAttribute("class", "ring" + (p.mem_pct >= 90 ? " bad" : p.mem_pct >= 80 ? " warn" : ""));
      var val = ring.querySelector(".val");
      requestAnimationFrame(function () { requestAnimationFrame(function () { val.style.strokeDashoffset = 100 - p.mem_pct; }); });
    }
    countTo("v-week", p.week ? p.week.reduce(function (a, d) { return a + d.n; }, 0) : 0);
    countTo("t-total", p.total);
    countTo("t-countries", p.countries.length);
    countTo("t-anon", p.anon_pct);
    countTo("t-pps", p.rx_pps);
    countTo("t-syn", p.syn);

    var tc = $("tb-countries");
    if (tc) {
      clear(tc);
      if (!p.countries.length) { var e = td("Bağlantı yok", "muted"); e.colSpan = 4; tc.appendChild(row([e])); }
      p.countries.slice(0, parseInt(tc.getAttribute("data-limit") || "12", 10)).forEach(function (c) {
        tc.appendChild(row([td(c.country), td(String(c.ips)), td(String(c.n)), td((c.n ? Math.round(100 * c.anon / c.n) : 0) + "%")]));
      });
    }
    var ts = $("tb-sources");
    if (ts) {
      clear(ts);
      if (!p.sources.length) { var f = td("Bağlantı yok", "muted"); f.colSpan = 4; ts.appendChild(row([f])); }
      p.sources.forEach(function (s) {
        ts.appendChild(row([td(s.ip), td(String(s.n)), td(s.country), td(s.flags.length ? s.flags.join(", ") : "-")]));
      });
    }
    first = false;
  }

  function setLive(text, cls) { if (state) { state.textContent = text; state.className = (state.classList.contains("chip") ? "chip " : "badge ") + cls; } }

  function poll() {
    fetch("/api/live", {credentials: "same-origin", cache: "no-store"})
      .then(function (r) {
        if (r.status === 401) { window.location.href = "/login"; throw new Error("oturum"); }
        if (!r.ok) throw new Error("http " + r.status);
        return r.json();
      })
      .then(function (p) { render(p); setLive("canlı", "ok"); })
      .catch(function (e) {
        if (e.message === "oturum") return;
        setLive("bağlantı hatası", "high");
        var pill = $("state-pill");
        if (pill) { pill.className = "state-pill lx"; pill.textContent = "BAĞLANTI YOK"; $("map-why").textContent = "Panele ulaşılamıyor; gösterilen veri eski olabilir."; }
        var band = $("live-band");
        if (band) { band.className = "band lx"; $("band-state").textContent = "BAĞLANTI YOK"; $("band-why").textContent = "Panele ulaşılamıyor; gösterilen veri eski olabilir."; }
      });
  }
  poll();
  timer = setInterval(poll, 5000);
  document.addEventListener("visibilitychange", function () {
    if (document.hidden) { clearInterval(timer); timer = null; }
    else if (!timer) { poll(); timer = setInterval(poll, 5000); }
  });
})();
