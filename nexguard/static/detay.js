/* NexGuard: IP detay çekmecesi.
   [data-ip] taşıyan her öğeye (tablolardaki IP'ler) ve 3B küredeki ülkelere tıklanınca sağdan açılır.
   Veri /api/ip'den gelir ve tamamen yereldir. İşlemler (engelle, kaldır, izin listesi) iki adımlı
   onay ister: ilk tıklama sorar, ikincisi uygular. Saldırgan kontrolündeki her metin (kullanıcı adı,
   parola, komut, ilk baytlar) yalnızca textContent ile yazılır. */
(function () {
  "use strict";
  var root = document.getElementById("drawer");
  if (!root) return;
  var body = document.getElementById("dr-body"), title = document.getElementById("dr-title"),
    sub = document.getElementById("dr-sub"), chips = document.getElementById("dr-chips"), kind = document.getElementById("dr-kind");
  var calm = window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches;
  var opener = null, current = null, seq = 0;

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = String(text);
    return e;
  }
  function section(label, i) {
    var s = el("section", "dr-sec");
    s.style.setProperty("--i", String(i));
    s.appendChild(el("h3", "", label));
    body.appendChild(s);
    return s;
  }
  function stats(parent, pairs) {
    var g = el("div", "dr-stats");
    pairs.forEach(function (p) {
      var d = el("div", "dr-stat" + (p[2] ? " " + p[2] : ""));
      d.appendChild(el("span", "", p[0]));
      d.appendChild(el("b", "", p[1]));
      g.appendChild(d);
    });
    parent.appendChild(g);
  }
  function chip(text, cls) { chips.appendChild(el("span", "dr-chip " + (cls || ""), text)); }
  function csrf() { var i = document.querySelector('input[name="csrf"]'); return i ? i.value : ""; }
  function fmtUntil(ts) { var d = new Date(ts * 1000); return ("0" + d.getHours()).slice(-2) + ":" + ("0" + d.getMinutes()).slice(-2); }

  // ---------- işlemler (iki adımlı onay) ----------
  function action(parent, label, ask, run, opts) {
    var b = el("button", "dr-btn" + (opts && opts.cls ? " " + opts.cls : ""), label);
    b.type = "button";
    if (opts && opts.disabled) { b.disabled = true; if (opts.why) b.title = opts.why; }
    var armed = 0;
    b.addEventListener("click", function () {
      if (!armed) {
        armed = setTimeout(function () { armed = 0; b.textContent = label; b.classList.remove("armed"); }, 4000);
        b.textContent = ask; b.classList.add("armed");
        return;
      }
      clearTimeout(armed); armed = 0;
      b.classList.remove("armed");
      run(b);
    });
    parent.appendChild(b);
    return b;
  }
  function post(path, fields, btn) {
    var out = body.querySelector(".dr-msg");
    btn.disabled = true;
    var f = new URLSearchParams(fields);
    f.set("csrf", csrf());
    return fetch(path, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: f.toString() })
      .then(function (r) { return r.json().catch(function () { return { ok: false, message: "Yanıt okunamadı (HTTP " + r.status + ")." }; }); })
      .then(function (j) { return j; }, function () { return { ok: false, message: "Panele ulaşılamadı." }; })
      .then(function (j) {
        var ip = current && current.type === "ip" ? current.key : null;
        if (ip) return load(ip, false).then(function () { flash(j); });
        flash(j);
      });
  }
  function flash(j) {
    var out = body.querySelector(".dr-msg");
    if (!out) return;
    out.textContent = j.message || (j.ok ? "Tamam." : "İşlem başarısız.");
    out.className = "dr-msg " + (j.ok ? "ok" : "bad");
    out.hidden = false;
  }

  // ---------- IP görünümü ----------
  function renderIP(d, animate) {
    kind.textContent = "Kaynak IP";
    title.textContent = d.ip;
    var g = d.geo;
    sub.textContent = g.installed ? [g.country || "Bilinmiyor", g.asn ? "AS" + g.asn : "", g.org].filter(Boolean).join(" · ")
      : "Coğrafya veritabanı kurulu değil";
    chips.textContent = "";
    if (d.block) chip("Engelli · " + fmtUntil(d.block.until) + "'e dek", "bad");
    if (d.allowed) chip("İzin listesinde", "ok");
    (g.flags || []).forEach(function (f) { chip(f, "warn"); });
    if (d.live) chip("Şu an bağlı", "info");

    body.textContent = "";
    var s0 = section("Özet", 0);
    stats(s0, [
      ["Şu an bağlantı", String(d.live)],
      ["SSH denemesi · 7 gün", d.ssh ? String(d.ssh.n) : "0"],
      ["Tuzak oturumu", String(d.trap.length)],
      ["TCP tuzağı", String(d.tcp_trap.reduce(function (a, h) { return a + h.n; }, 0))],
    ]);
    if (d.flood.length) {
      var fl = el("ul", "dr-list");
      d.flood.forEach(function (f) { fl.appendChild(el("li", "", f.proto.toUpperCase() + " seli · " + Math.round(f.pps) + " paket/sn · " + f.mbps.toFixed(2) + " Mbit/sn" + (f.spoof ? " · " + f.spoof : ""))); });
      s0.appendChild(fl);
    }

    var s1 = section("Müdahale", 1);
    var row = el("div", "dr-actions");
    var noBlock = !d.blockable ? (d.allowed ? "İzin listesindeki adres engellenmez." : "Bu adres engellenemez.") : "";
    action(row, "1 saat engelle", "Onayla: 1 saat", function (b) { post("/api/ip/block", { ip: d.ip, minutes: "60" }, b); }, { cls: "primary", disabled: !!noBlock, why: noBlock });
    action(row, "24 saat engelle", "Onayla: 24 saat", function (b) { post("/api/ip/block", { ip: d.ip, minutes: "1440" }, b); }, { disabled: !!noBlock, why: noBlock });
    if (d.block) action(row, "Engeli kaldır", "Onayla: kaldır", function (b) { post("/api/ip/unblock", { ip: d.ip }, b); });
    if (d.allowed) action(row, "İzin listesinden çıkar", "Onayla: çıkar", function (b) { post("/api/ip/disallow", { ip: d.ip }, b); });
    else action(row, "İzin listesine al", "Onayla: hiç engelleme", function (b) { post("/api/ip/allow", { ip: d.ip }, b); });
    s1.appendChild(row);
    var msg = el("p", "dr-msg"); msg.hidden = true; s1.appendChild(msg);
    if (!d.helper) s1.appendChild(el("p", "dr-note", "Engel yardımcısı bu makinede kurulu değil: engel listesine yazılır ama güvenlik duvarına uygulanmaz (deploy/kur.sh)."));
    var full = el("a", "dr-link", "Tam araştırma: ağ sahibi, ters DNS, kötüye kullanım bildirimi →");
    full.href = "/kaynak?ip=" + encodeURIComponent(d.ip);
    s1.appendChild(full);

    var i = 2;
    if (d.ssh && d.ssh.users.length) {
      var s2 = section("Gerçek SSH'a denenen kullanıcılar", i++);
      var tags = el("div", "dr-tags");
      d.ssh.users.forEach(function (u) { tags.appendChild(el("code", "", (u.user || "(boş)") + (u.n > 1 ? " ×" + u.n : ""))); });
      s2.appendChild(tags);
      s2.appendChild(el("p", "dr-note", "Son deneme: " + d.ssh.last));
    }
    if (d.trap.length) {
      var s3 = section("SSH tuzağı oturumları", i++);
      d.trap.forEach(function (t) {
        var a = el("article", "dr-trap");
        a.appendChild(el("p", "dr-meta", t.ts + (t.client ? " · " + t.client : "")));
        if (t.user) {
          var c = el("p", "");
          c.appendChild(document.createTextNode("giriş: "));
          c.appendChild(el("code", "", t.user));
          c.appendChild(document.createTextNode(" / "));
          c.appendChild(el("code", "", t.password || "(boş)"));
          a.appendChild(c);
        }
        if (t.commands.length) a.appendChild(el("pre", "", t.commands.map(function (x) { return "$ " + x; }).join("\n")));
        s3.appendChild(a);
      });
    }
    if (d.tcp_trap.length) {
      var s4 = section("TCP tuzağı dokunuşları", i++);
      var tl = el("ul", "dr-list");
      d.tcp_trap.forEach(function (h) {
        var li = el("li", "");
        li.appendChild(el("span", "dr-meta", h.when + " · port " + h.port + (h.n > 1 ? " · ×" + h.n : "")));
        li.appendChild(el("code", "dr-clip", h.payload || "(boş)"));
        tl.appendChild(li);
      });
      s4.appendChild(tl);
    }
    if (d.events.length) {
      var s5 = section("Panel olayları", i++);
      var el5 = el("ul", "dr-list");
      d.events.forEach(function (e) { var li = el("li", "lv-" + e.level); li.appendChild(el("span", "dr-meta", e.ts + " · " + e.module)); li.appendChild(el("span", "", e.message)); el5.appendChild(li); });
      s5.appendChild(el5);
    }
    if (window.NexKure && g.cc) window.NexKure.focus(g.cc);
  }

  // ---------- ülke görünümü (3B küreden) ----------
  function renderCountry(cc) {
    var p = window.NexLive, c = p && p.countries.filter(function (x) { return x.cc === cc; })[0];
    kind.textContent = "Ülke";
    title.textContent = c ? c.country : cc;
    sub.textContent = c ? c.n + " bağlantı · " + c.ips + " IP" : "Bu ülkeden şu an bağlantı yok.";
    chips.textContent = "";
    if (c && c.anon * 2 > c.n) chip("Çoğu aracı ağdan", "warn");
    body.textContent = "";
    var s = section("Bu ülkeden en çok bağlananlar", 0);
    var list = (p ? p.sources : []).filter(function (x) { return x.cc === cc; });
    if (!list.length) { s.appendChild(el("p", "dr-note", "En çok bağlanan ilk 10 kaynak arasında bu ülkeden IP yok.")); return; }
    var ul = el("ul", "dr-list");
    list.forEach(function (x) {
      var li = el("li", "");
      var b = el("button", "ip-link", x.ip); b.type = "button"; b.setAttribute("data-ip", x.ip);
      li.appendChild(b);
      li.appendChild(el("span", "dr-meta", x.n + " bağlantı" + (x.org ? " · " + x.org : "") + (x.flags.length ? " · " + x.flags.join(", ") : "")));
      ul.appendChild(li);
    });
    s.appendChild(ul);
    if (window.NexKure) window.NexKure.focus(cc);
  }

  // ---------- çekmece ----------
  function show(from) {
    if (from && !root.contains(from)) opener = from;
    root.hidden = false;
    root.classList.remove("in");
    void root.offsetWidth;
    root.classList.toggle("anim", !calm);
    root.classList.add("in");
    document.body.classList.add("drawer-open");
    document.getElementById("dr-close").focus({ preventScroll: true });
  }
  function load(ip, animate) {
    var my = ++seq;
    if (animate) { body.textContent = ""; body.appendChild(el("p", "dr-note", "Yükleniyor…")); }
    return fetch("/api/ip?ip=" + encodeURIComponent(ip), { credentials: "same-origin", cache: "no-store" })
      .then(function (r) {
        if (r.status === 401) { window.location.href = "/login"; throw new Error("oturum"); }
        return r.json().then(function (j) { if (!r.ok) throw new Error(j.error || ("HTTP " + r.status)); return j; });
      })
      .then(function (d) { if (my === seq && current && current.key === ip) renderIP(d, animate); })
      .catch(function (e) {
        if (my !== seq || e.message === "oturum") return;
        kind.textContent = "Kaynak IP"; title.textContent = ip; sub.textContent = ""; chips.textContent = "";
        body.textContent = "";
        body.appendChild(el("p", "dr-msg bad", e.message || "Ayrıntı alınamadı."));
      });
  }
  function openIP(ip, from) {
    current = { type: "ip", key: ip };
    kind.textContent = "Kaynak IP"; title.textContent = ip; sub.textContent = ""; chips.textContent = "";
    show(from);
    load(ip, true);
  }
  function openCountry(cc, from) {
    current = { type: "cc", key: cc };
    show(from);
    renderCountry(cc);
  }
  function close() {
    if (!current) return;
    current = null; seq++;
    root.classList.remove("in");
    root.hidden = true;
    document.body.classList.remove("drawer-open");
    if (opener && document.contains(opener)) opener.focus({ preventScroll: true });
    opener = null;
  }

  document.getElementById("dr-close").addEventListener("click", close);
  document.addEventListener("keydown", function (e) { if (e.key === "Escape" && current) { e.preventDefault(); close(); } });
  document.addEventListener("click", function (e) {
    var t = e.target.closest && e.target.closest("[data-ip]");
    if (t) { e.preventDefault(); openIP(t.getAttribute("data-ip"), t); }
  });

  window.NexDetay = { openIP: openIP, openCountry: openCountry, close: close };
})();
