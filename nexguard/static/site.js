(function () {
  "use strict";
  // Sunucudan gelen düz sayılar kısa bir sayımla belirir. Birim yazıları ve metinler dokunulmadan kalır.
  var rings = document.querySelectorAll("[data-ring]");
  requestAnimationFrame(function () { requestAnimationFrame(function () {
    rings.forEach(function (r) { r.style.strokeDashoffset = 100 - Math.min(100, parseFloat(r.getAttribute("data-ring")) || 0); });
  }); });
  if (window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  var DUR = 320;
  document.querySelectorAll(".readouts dd, .stat-value, .score span, .count").forEach(function (el) {
    var node = el.firstChild;
    if (!node || node.nodeType !== 3) return;
    var m = node.textContent.trim().match(/^(%?)(\d+(?:\.\d+)?)$/);
    if (!m) return;
    var target = parseFloat(m[2]), digits = (m[2].split(".")[1] || "").length, t0 = performance.now();
    (function step(now) {
      var k = Math.min(1, (now - t0) / DUR), e = 1 - Math.pow(1 - k, 3);
      node.textContent = m[1] + (target * e).toFixed(digits);
      if (k < 1) requestAnimationFrame(step); else node.textContent = m[1] + m[2];
    })(t0);
  });
})();
