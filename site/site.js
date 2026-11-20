/* NexGuard: kaydırma → sahne ilerlemesi, adım blokları, meta okuması, kopyalama.
   WebGL2 yoksa ya da ekran <900px ise sahne hiç başlatılmaz; sayfa statik görsellerle okunur kalır. */
(function () {
  "use strict";
  var kok = document.documentElement;
  var yol = document.getElementById("nasil"), kap = document.getElementById("kapanis");
  var bloklar = Array.prototype.slice.call(document.querySelectorAll("[data-blok]"));
  var metaSol = document.querySelector("[data-meta]"), metaAdim = document.querySelector("[data-adim]");
  var geniş = window.matchMedia("(min-width: 900px)");
  var azHareket = !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);
  var tuval = document.getElementById("tuval"), sahneVar = false, basladi = false, bekliyor = false;
  var adimMeta = ["SUNUCU → YEREL PANEL", "KAYNAK · /proc/net/tcp · journalctl", "ÖLÇÜM · 5 SN", "YANIT · NFT TABLE INET NEXGUARD", "PANEL · 127.0.0.1:8787"];
  var sonAdim = -1;

  function sm(a, b, x) { var t = Math.max(0, Math.min(1, (x - a) / (b - a))); return t * t * (3 - 2 * t); }
  function adimOf(g) { return g < 0.075 ? 0 : g < 0.26 ? 1 : g < 0.5 ? 2 : g < 0.72 ? 3 : 4; }
  var KARE = [0.0, 0.17, 0.47, 0.70, 0.98]; // reduced-motion: her adım için tek kare

  function scramble(el, metin) {
    if (!el) return;
    if (azHareket) { el.textContent = metin; return; }
    var kare = 0, G = "0123456789ABCDEF", n = metin.length;
    (function adim() {
      var s = "", i;
      for (i = 0; i < n; i++) s += (metin[i] === " " || i < kare - 5) ? metin[i] : G[Math.floor(Math.abs(Math.sin((i + 1) * 12.9898 + kare * 78.233) * 43758.5453) % 1 * 16)];
      el.textContent = s;
      if (++kare < n + 6) setTimeout(adim, 28);
    })();
  }

  function guncelle() {
    bekliyor = false;
    if (!sahneVar) return;
    var vh = window.innerHeight, r = yol.getBoundingClientRect();
    var g = Math.max(0, Math.min(1, -r.top / Math.max(1, r.height - vh)));
    var a = adimOf(g);
    if (azHareket) g = KARE[a];
    var kr = kap.getBoundingClientRect();
    var c = sm(0.1, 0.85, Math.max(0, Math.min(1, 1 - kr.top / vh)));
    var dimT = Math.max(0, Math.min(1, (vh - r.bottom) / (vh * 0.5)));
    var dim = 1 - 0.62 * dimT;
    window.NexScene.set(g, c, dim, azHareket);
    if (a !== sonAdim) {
      sonAdim = a;
      bloklar.forEach(function (b) { b.classList.toggle("on", +b.getAttribute("data-blok") === a); });
      if (metaSol) scramble(metaSol, adimMeta[a]);
      if (metaAdim) metaAdim.textContent = (a < 10 ? "0" : "") + a + "/04";
    }
  }
  function iste() { if (!bekliyor) { bekliyor = true; requestAnimationFrame(guncelle); } }

  function ac() {
    if (!geniş.matches) return;
    if (!basladi) {
      basladi = true;
      var ok = false;
      try {
        ok = window.NexScene && window.NexScene.init(tuval, {
          hud: document.getElementById("hud-sahne"), azHareket: azHareket, tux: "media/tux.png",
          hazir: function () { iste(); },
          kayip: function () { kapat(true); }
        });
      } catch (e) { ok = false; }
      if (!ok) return;
    } else { window.NexScene.surdur(); }
    sahneVar = true; kok.classList.add("sahne-acik");
    if (window.NexScene.yenidenBoyutla) window.NexScene.yenidenBoyutla();
    iste();
  }
  function kapat(kalici) {
    sahneVar = false; kok.classList.remove("sahne-acik");
    if (window.NexScene) window.NexScene.duraklat();
    if (kalici) geniş = { matches: false, addEventListener: function () {} }; // bağlam kaybında yeniden deneme
    bloklar.forEach(function (b) { b.classList.remove("on"); });
  }
  function degisti() { if (geniş.matches) ac(); else kapat(false); }

  if (geniş.addEventListener) geniş.addEventListener("change", degisti); else geniş.addListener(degisti);
  window.addEventListener("scroll", iste, { passive: true });
  window.addEventListener("resize", iste);
  ac();

  /* Kopyala */
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
      var kod = b.closest("figure").querySelector("code"), ilk = b.textContent;
      kopyala(kod.textContent).then(
        function () { b.textContent = "KOPYALANDI"; },
        function () { b.textContent = "KOPYALANAMADI"; }
      ).then(function () { setTimeout(function () { b.textContent = ilk; }, 1600); });
    });
  });
})();
