(function () {
  "use strict";
  var svg = document.getElementById("worldmap");
  if (!svg) return;
  var NS = "http://www.w3.org/2000/svg";
  var dots = document.getElementById("dots");
  var tip = document.getElementById("map-tip");
  var state = document.getElementById("live-state");
  var current = {};
  var timer = null;

  function el(tag, attrs, text) {
    var e = document.createElement(tag);
    if (attrs) for (var k in attrs) e.setAttribute(k, attrs[k]);
    if (text !== undefined) e.textContent = text;
    return e;
  }
  function pct(n, d) { return d ? Math.round(100 * n / d) : 0; }

  function render(p) {
    var lvl = document.getElementById("live-banner");
    if (lvl) {
      lvl.className = "panel banner l" + p.level;
      document.getElementById("live-level").textContent = "Durum: " + p.level_name.toUpperCase();
      document.getElementById("live-ts").textContent = "güncelleme " + p.ts;
    }
    var vd = document.getElementById("live-verdict");
    if (vd) vd.textContent =
      p.countries.length ? p.verdict : (p.installed ? "Şu an dışarıdan bağlı kaynak yok." : "Coğrafya veritabanı kurulu değil.");

    // ülke renkleri
    var max = 0, i;
    p.countries.forEach(function (c) { if (c.n > max) max = c.n; });
    var seen = {};
    p.countries.forEach(function (c) {
      var path = document.getElementById("c-" + c.cc);
      seen[c.cc] = true;
      if (!path) return;
      var r = max ? c.n / max : 0;
      path.setAttribute("class", "hit h" + (r > 0.66 ? 4 : r > 0.33 ? 3 : r > 0.1 ? 2 : 1));
    });
    Object.keys(current).forEach(function (cc) {
      if (!seen[cc]) { var o = document.getElementById("c-" + cc); if (o) o.removeAttribute("class"); }
    });
    current = seen;

    // noktalar (küçük ülkelerin şekli yoksa da görünsün)
    while (dots.firstChild) dots.removeChild(dots.firstChild);
    p.countries.forEach(function (c) {
      if (c.x === null || c.y === null) return;
      var g = document.createElementNS(NS, "g");
      g.setAttribute("class", "dot" + (c.anon * 2 > c.n ? " anon" : ""));
      g.setAttribute("transform", "translate(" + c.x + " " + c.y + ")");
      var r = 3 + Math.min(9, Math.sqrt(c.n));
      var pulse = document.createElementNS(NS, "circle"); pulse.setAttribute("r", r); pulse.setAttribute("class", "pulse");
      var core = document.createElementNS(NS, "circle"); core.setAttribute("r", Math.max(2.5, r / 2.2)); core.setAttribute("class", "core");
      g.appendChild(pulse); g.appendChild(core);
      g.addEventListener("mouseenter", function (ev) { showTip(c, ev); });
      g.addEventListener("mousemove", function (ev) { showTip(c, ev); });
      g.addEventListener("mouseleave", function () { tip.hidden = true; });
      dots.appendChild(g);
    });

    // tablolar
    var tc = document.getElementById("tb-countries");
    if (!tc) return;
    tc.textContent = "";
    if (!p.countries.length) tc.appendChild(rowOf([el("td", {colspan: "4", "class": "muted"}, "Bağlantı yok")]));
    p.countries.slice(0, parseInt(tc.getAttribute("data-limit") || "12", 10)).forEach(function (c) {
      tc.appendChild(rowOf([el("td", null, c.country), el("td", null, String(c.ips)), el("td", null, String(c.n)), el("td", null, pct(c.anon, c.n) + "%")]));
    });
    var ts = document.getElementById("tb-sources");
    if (ts) {
      ts.textContent = "";
      if (!p.sources.length) ts.appendChild(rowOf([el("td", {colspan: "4", "class": "muted"}, "Bağlantı yok")]));
      p.sources.forEach(function (s) {
        ts.appendChild(rowOf([el("td", null, s.ip), el("td", null, String(s.n)), el("td", null, s.country), el("td", null, s.flags.length ? s.flags.join(", ") : "-")]));
      });
    }
  }
  function rowOf(cells) { var tr = document.createElement("tr"); cells.forEach(function (c) { tr.appendChild(c); }); return tr; }

  function showTip(c, ev) {
    tip.textContent = c.country + ": " + c.n + " bağlantı, " + c.ips + " IP";
    var box = svg.getBoundingClientRect();
    tip.style.left = Math.min(ev.clientX - box.left + 12, box.width - 170) + "px";
    tip.style.top = (ev.clientY - box.top + 12) + "px";
    tip.hidden = false;
  }

  function setState(text, cls) { if (state) { state.textContent = text; state.className = "badge " + cls; } }

  function poll() {
    fetch("/api/live", {credentials: "same-origin", cache: "no-store"})
      .then(function (r) {
        if (r.status === 401) { setState("oturum bitti", "high"); window.location.href = "/login"; throw new Error("oturum"); }
        if (!r.ok) throw new Error("http " + r.status);
        return r.json();
      })
      .then(function (p) { render(p); setState("canlı", "ok"); })
      .catch(function (e) { if (e.message !== "oturum") setState("bağlantı hatası", "high"); });
  }
  poll();
  timer = setInterval(poll, 5000);
  document.addEventListener("visibilitychange", function () {
    if (document.hidden) { clearInterval(timer); timer = null; }
    else if (!timer) { poll(); timer = setInterval(poll, 5000); }
  });
})();
