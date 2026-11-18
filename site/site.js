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

/* Kaydırınca belirme (yalnızca opaklık) ve kod bloklarını kopyalama. */
(function () {
  "use strict";
  var bloklar = Array.prototype.slice.call(document.querySelectorAll("[data-goster]"));
  var azHareket = !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);
  function goster(el) { el.classList.add("gor"); }
  if (azHareket || !("IntersectionObserver" in window)) {
    bloklar.forEach(goster);
  } else {
    var g = new IntersectionObserver(function (girdiler) {
      girdiler.forEach(function (e) {
        if (e.isIntersecting) { goster(e.target); g.unobserve(e.target); }
      });
    }, { rootMargin: "0px 0px -8% 0px" });
    bloklar.forEach(function (el) { g.observe(el); });
  }

  function kopyala(metin) {
    if (navigator.clipboard && navigator.clipboard.writeText) return navigator.clipboard.writeText(metin);
    return new Promise(function (coz, red) {
      var t = document.createElement("textarea");
      t.value = metin; t.setAttribute("readonly", ""); t.style.position = "fixed"; t.style.opacity = "0";
      document.body.appendChild(t); t.select();
      try { document.execCommand("copy") ? coz() : red(); } catch (e) { red(e); } finally { t.remove(); }
    });
  }
  Array.prototype.forEach.call(document.querySelectorAll("[data-kopya]"), function (b) {
    b.addEventListener("click", function () {
      var kod = b.closest("figure").querySelector("code");
      var ilk = b.textContent;
      kopyala(kod.textContent).then(
        function () { b.textContent = "Kopyalandı"; },
        function () { b.textContent = "Kopyalanamadı"; }
      ).then(function () { setTimeout(function () { b.textContent = ilk; }, 1600); });
    });
  });
})();
