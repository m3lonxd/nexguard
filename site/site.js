/* NexGuard tanıtım sitesi: döngü videoları.
   Veri tasarrufu / az hareket tercihinde video kaldırılır; ekran dışındaki
   video durdurulur; data-gec olan video görünür olana dek yüklenmez. */
(function () {
  "use strict";
  var videolar = Array.prototype.slice.call(document.querySelectorAll("video.dongu"));
  if (!videolar.length) return;

  var tasarruf = false;
  try { tasarruf = !!(navigator.connection && navigator.connection.saveData); } catch (e) {}
  var azHareket = !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);

  if (tasarruf || azHareket) {
    videolar.forEach(function (v) { v.removeAttribute("autoplay"); v.pause(); v.remove(); });
    return;
  }

  function oynat(v) {
    if (v.hasAttribute("data-gec")) { v.removeAttribute("data-gec"); v.preload = "auto"; v.load(); }
    var p = v.play();
    // Otomatik oynatma engellenirse alttaki görsel kalır. pause() ile kesilen
    // play() (AbortError) bir sonraki görünüşte yeniden denenir.
    if (p && p.catch) p.catch(function (h) { if (h && h.name === "NotAllowedError") v.remove(); });
  }

  if ("IntersectionObserver" in window) {
    var izle = new IntersectionObserver(function (girdiler) {
      girdiler.forEach(function (g) {
        if (g.isIntersecting) oynat(g.target); else g.target.pause();
      });
    }, { rootMargin: "200px 0px" });
    videolar.forEach(function (v) { izle.observe(v); });
  } else {
    videolar.forEach(oynat);
  }
})();
