/* NexGuard paneli: detay çekmecesi (kaynak IP ve sunucu) ve panelden ajana komutlar.
   Saldırganın gönderdiği her değer (kullanıcı adı, şifre, istemci sürümü, payload)
   yalnızca textContent ile yazılır; HTML olarak hiçbir zaman yorumlanmaz. */
(function () {
  "use strict";
  const HOURS = 24;

  function create(ctx) {
    const { $, state } = ctx;
    const root = $("drawer"), body = $("d-body"), kind = $("d-kind"), title = $("d-title"), sub = $("d-sub"), chips = $("d-chips");
    let view = null;          // { type: "ip"|"server", key }
    let opener = null;        // çekmece kapanınca odak geri döner
    const cmdLog = new Map(); // komut id -> son durum (WebSocket ile güncellenir)
    const serverCmds = new Map(); // sunucu id -> son komutlar (GET ile yüklenir)
    const drafts = new Map();     // sunucu id -> kaydedilmemiş honeypot formu
    let deferred = false;         // kullanıcı yazarken gelen yenileme, odak çıkınca yapılır

    // ---------- küçük DOM yardımcıları ----------
    function el(tag, cls, text) {
      const e = document.createElement(tag);
      if (cls) e.className = cls;
      if (text != null) e.textContent = String(text);
      return e;
    }
    function section(label, i) {
      const s = el("section", "d-sec");
      s.style.setProperty("--i", String(i));
      s.appendChild(el("h3", "label", label));
      body.appendChild(s);
      return s;
    }
    function kv(parent, pairs) {
      const g = el("dl", "d-kv");
      for (const [k, v, cls] of pairs) {
        g.appendChild(el("dt", "label dim", k));
        g.appendChild(el("dd", cls || "", v));
      }
      parent.appendChild(g);
      return g;
    }
    function chip(text, cls) { chips.appendChild(el("span", "d-chip " + (cls || ""), text)); }
    function button(parent, text, onClick, opts) {
      const b = el("button", "d-btn" + (opts && opts.warn ? " warn" : ""), text);
      b.type = "button";
      if (opts && opts.disabled) b.disabled = true;
      if (opts && opts.title) { b.title = opts.title; b.setAttribute("aria-label", text + " · " + opts.title); }
      b.addEventListener("click", onClick);
      parent.appendChild(b);
      return b;
    }
    function empty(parent, text) { parent.appendChild(el("p", "d-empty", text)); }

    // ---------- veri yardımcıları ----------
    const t24 = () => Date.now() - HOURS * 3600000;
    function findingsFor(ip) {
      return state.findings.filter((f) => ctx.ipOf(f) === ip).sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
    }
    function actionsFor(ip) {
      return state.actions.filter((a) => ctx.actionInfo(a).ip === ip).sort((a, b) => Date.parse(b.applied_at) - Date.parse(a.applied_at));
    }
    function serverById(id) { return state.servers.find((s) => s.id === id) || null; }
    function agentOf(s) { return (s && s.agent) || { online: false }; }
    function allowedOn(s, ip) { const st = agentOf(s).status; return !!(st && st.allow && st.allow.includes(ip)); }
    function blockedOn(s, ip) {
      const st = agentOf(s).status;
      if (st && st.blocked && st.blocked.includes(ip)) return true;
      const now = Date.now();
      return state.actions.some((a) => ctx.isActiveBlock(a, now) && ctx.actionInfo(a).ip === ip &&
        state.findings.some((f) => f.id === a.finding_id && f.server_id === s.id));
    }

    // ---------- komutlar ----------
    // Ajan çok hızlı yanıt verince sonuç, POST yanıtından ya da "oluşturuldu"
    // yayınından önce gelebilir; durum yalnızca ileri gider.
    const RANK = { pending: 0, sent: 1, done: 2, failed: 2 };
    function remember(map, c) {
      const old = map.get(c.id);
      if (!old || (RANK[c.status] || 0) >= (RANK[old.status] || 0)) map.set(c.id, c);
    }
    async function send(serverId, type, params) {
      const r = await fetch("/api/v1/servers/" + encodeURIComponent(serverId) + "/commands", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ type, params }),
      });
      if (!r.ok) throw new Error((await r.text()).trim() || "HTTP " + r.status);
      const c = await r.json();
      remember(cmdLog, c);
      return c;
    }
    const CMD_LABEL = { block_ip: "ENGELLE", unblock_ip: "ENGELİ KALDIR", allow_ip: "İZİN LİSTESİNE AL", disallow_ip: "İZİNDEN ÇIKAR", honeypot: "HONEYPOT" };
    const ST_LABEL = { pending: "KUYRUKTA", sent: "GÖNDERİLDİ", done: "UYGULANDI", failed: "HATA" };
    function cmdLine(parent, c) {
      const row = el("li", "d-cmd " + c.status);
      const s = serverById(c.server_id);
      row.appendChild(el("span", "", (s ? s.hostname : c.server_id) + " · " + (CMD_LABEL[c.type] || c.type) + (c.params && c.params.ip ? " " + c.params.ip : "")));
      const st = el("span", "st", ST_LABEL[c.status] || c.status.toUpperCase());
      row.appendChild(st);
      if (c.error) row.appendChild(el("span", "sub", c.error));
      else if (c.status === "pending") row.appendChild(el("span", "sub", "ajan bağlanınca uygulanacak"));
      parent.appendChild(row);
    }
    async function run(btn, targets, type, params, out) {
      if (!targets.length) return;
      btn.disabled = true;
      const errs = [];
      for (const s of targets) {
        try { await send(s.id, type, params); } catch (e) { errs.push(s.hostname + ": " + e.message); }
      }
      btn.disabled = false;
      render(false);
      if (errs.length) {
        // yeniden çizimden sonra hata yeni bölüme yazılır
        const p = body.querySelector(".d-err");
        if (p) { p.textContent = errs.join(" · "); p.hidden = false; }
      }
    }

    // ---------- IP görünümü ----------
    function renderIP(ip, animate) {
      const fs = findingsFor(ip), as = actionsFor(ip);
      const g = ctx.geo(ip);
      kind.textContent = "KAYNAK IP";
      ctx.setText(title, ip, animate);
      sub.textContent = g ? g.name + " · " + g.cc : ctx.geoKnown(ip) ? "Konum yok (yerel / özel adres)" : "Konum aranıyor…";
      const hit = [...new Set(fs.map((f) => f.server_id))].map(serverById).filter(Boolean);
      const targets = hit.length ? hit : state.servers.slice();
      const blocked = targets.some((s) => blockedOn(s, ip));
      const allowed = targets.length > 0 && targets.every((s) => allowedOn(s, ip));
      chips.textContent = "";
      if (blocked) chip("ENGELLİ", "warn");
      if (allowed) chip("İZİN LİSTESİNDE", "ok");
      if (fs.some((f) => String(f.type).startsWith("honeypot"))) chip("HONEYPOT", "warn");

      // özet
      const recent = fs.filter((f) => Date.parse(f.created_at) >= t24());
      const total = recent.reduce((n, f) => n + ctx.attemptsOf(f), 0);
      const s0 = section("ÖZET / SON 24 SAAT", 0);
      kv(s0, [
        ["DENEME", String(total)],
        ["BULGU", String(fs.length)],
        ["İLK GÖRÜLME", fs.length ? ctx.fmtDateTime(fs[fs.length - 1].created_at) : "—"],
        ["SON GÖRÜLME", fs.length ? ctx.fmtDateTime(fs[0].created_at) : "—"],
        ["SUNUCULAR", hit.map((s) => s.hostname).join(", ") || "—"],
      ]);
      // saatlik iz
      const hours = new Array(HOURS).fill(0);
      const h0 = new Date(); h0.setMinutes(0, 0, 0);
      for (const f of recent) {
        const t = Date.parse(f.created_at), i = HOURS - 1 - (t >= h0.getTime() ? 0 : Math.ceil((h0.getTime() - t) / 3600000));
        if (i >= 0 && i < HOURS) hours[i] += ctx.attemptsOf(f);
      }
      const spark = el("div", "d-spark");
      spark.setAttribute("role", "img");
      spark.setAttribute("aria-label", "Saatlik deneme: " + hours.join(", "));
      const mx = Math.max(1, ...hours);
      hours.forEach((v, i) => {
        const col = el("span", "col" + (i === HOURS - 1 ? " now" : ""));
        col.style.setProperty("--h", String(v / mx));
        col.style.setProperty("--d", String(i));
        col.title = v + " deneme";
        spark.appendChild(col);
      });
      s0.appendChild(spark);

      // komutlar
      const s1 = section("MÜDAHALE", 1);
      const row = el("div", "d-actions");
      const err = el("p", "d-err"); err.hidden = true;
      const none = !targets.length;
      const local = /^(127\.|0\.0\.0\.0$|169\.254\.|::1$|fe80:)/i.test(ip);
      const tip = none ? "Kayıtlı sunucu yok" : "Hedef: " + targets.map((s) => s.hostname).join(", ");
      const btip = local ? "Yerel adres engellenmez" : tip;
      button(row, "ENGELLE 1 SA", (e) => run(e.currentTarget, targets, "block_ip", { ip, ttl: "1h" }, err), { warn: true, disabled: none || allowed || local, title: btip });
      button(row, "ENGELLE 24 SA", (e) => run(e.currentTarget, targets, "block_ip", { ip, ttl: "24h" }, err), { warn: true, disabled: none || allowed || local, title: btip });
      button(row, "ENGELİ KALDIR", (e) => run(e.currentTarget, targets, "unblock_ip", { ip }, err), { disabled: none || !blocked, title: tip });
      if (allowed) button(row, "İZİNDEN ÇIKAR", (e) => run(e.currentTarget, targets, "disallow_ip", { ip }, err), { disabled: none, title: tip });
      else button(row, "İZİN LİSTESİNE AL", (e) => run(e.currentTarget, targets, "allow_ip", { ip }, err), { disabled: none, title: tip + " · izinli IP hiç engellenmez" });
      s1.appendChild(row);
      s1.appendChild(err);
      const mine = [...cmdLog.values()].filter((c) => c.params && c.params.ip === ip).sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at)).slice(0, 6);
      if (mine.length) { const ul = el("ul", "d-cmds"); mine.forEach((c) => cmdLine(ul, c)); s1.appendChild(ul); }

      // denenen kimlikler
      const users = new Map(), creds = [];
      let client = "", payload = "";
      for (const f of fs) {
        const ev = f.evidence || {};
        if (Array.isArray(ev.users_tried)) for (const u of ev.users_tried) users.set(String(u), (users.get(String(u)) || 0) + 1);
        if (Array.isArray(ev.credentials)) for (const c of ev.credentials) if (creds.length < 30) creds.push(c);
        if (!client && ev.client) client = String(ev.client);
        if (!payload && ev.payload) payload = String(ev.payload);
      }
      const s2 = section("DENENEN KULLANICILAR", 2);
      if (users.size) {
        const wrap = el("div", "d-tags");
        [...users.entries()].sort((a, b) => b[1] - a[1]).slice(0, 24).forEach(([u, n]) => wrap.appendChild(el("span", "d-tag", n > 1 ? u + " ×" + n : u)));
        s2.appendChild(wrap);
      } else empty(s2, "Kullanıcı adı kaydı yok.");
      if (creds.length || client || payload) {
        const s3 = section("HONEYPOT KAYDI", 3);
        if (client || payload) kv(s3, [["İSTEMCİ", client || "—"], ["İLK BAYTLAR", payload || "—", "mono-break"]]);
        if (creds.length) {
          const tb = el("table", "readout d-table");
          const head = el("tr"); ["KULLANICI", "ŞİFRE / ANAHTAR", "YÖNTEM"].forEach((h) => head.appendChild(el("th", "label dim", h)));
          tb.appendChild(el("thead")).appendChild(head);
          const tbody = el("tbody");
          for (const c of creds) {
            const tr = el("tr");
            tr.appendChild(el("td", "", c.user || "—"));
            tr.appendChild(el("td", "mono-break", c.password || "—"));
            tr.appendChild(el("td", "dim", c.method || "—"));
            tbody.appendChild(tr);
          }
          tb.appendChild(tbody);
          s3.appendChild(tb);
        }
      }

      // olay geçmişi
      const s4 = section("OLAY GEÇMİŞİ", 4);
      const items = [
        ...fs.map((f) => ({ t: Date.parse(f.created_at), k: String(f.type || "bulgu").toUpperCase(), s: f.summary || "", srv: f.server_id })),
        ...as.map((a) => {
          const i = ctx.actionInfo(a);
          return { t: Date.parse(a.reverted_at || a.applied_at), k: (a.reverted_at ? "GERİ ALINDI" : String(a.action_type).toUpperCase()) + " · " + String(i.p.status || "").toUpperCase(), s: i.p.reason || (i.p.backend ? i.p.backend + (i.p.ttl ? " · " + i.p.ttl : "") : ""), warn: i.p.status === "applied" && !a.reverted_at };
        }),
      ].sort((a, b) => b.t - a.t).slice(0, 14);
      if (items.length) {
        const ol = el("ol", "d-time");
        for (const it of items) {
          const li = el("li", it.warn ? "warn" : "");
          li.appendChild(el("span", "t", ctx.fmtDateTime(it.t)));
          li.appendChild(el("span", "k", it.k));
          if (it.s) li.appendChild(el("span", "s", it.s));
          ol.appendChild(li);
        }
        s4.appendChild(ol);
      } else empty(s4, "Kayıt yok.");
    }

    // ---------- sunucu görünümü ----------
    function parsePorts(v) {
      const out = [];
      for (const part of String(v).split(/[\s,]+/)) {
        if (!part) continue;
        const n = Number(part);
        if (!Number.isInteger(n) || n < 1 || n > 65535) throw new Error("Geçersiz port: " + part);
        if (!out.includes(n)) out.push(n);
      }
      return out;
    }

    function renderServer(id, animate) {
      const s = serverById(id);
      kind.textContent = "SUNUCU";
      if (!s) { title.textContent = id; sub.textContent = "Sunucu bulunamadı"; chips.textContent = ""; return; }
      const ag = agentOf(s), st = ag.status || null, hp = st && st.honeypot;
      ctx.setText(title, s.hostname, animate);
      sub.textContent = [s.ip || "adres yok", s.os, s.geo ? s.geo.name : null].filter(Boolean).join(" · ");
      chips.textContent = "";
      chip(ag.online ? "AJAN ÇEVRİMİÇİ" : "AJAN ÇEVRİMDIŞI", ag.online ? "ok" : "");
      if (hp && hp.enabled) chip("HONEYPOT AÇIK", "warn");

      const fs = state.findings.filter((f) => f.server_id === id);
      const s0 = section("ÖZET", 0);
      kv(s0, [
        ["KAYIT", ctx.fmtDateTime(s.enrolled_at)],
        ["SON TEMAS", ag.last_seen ? ctx.fmtDateTime(ag.last_seen) : "—"],
        ["AJAN SÜRÜMÜ", (st && st.version) || "—"],
        ["BULGU / 24 SA", String(fs.filter((f) => Date.parse(f.created_at) >= t24()).length)],
        ["ETKİN ENGEL", st ? String(st.blocked.length) : "—"],
        ["HONEYPOT DOKUNUŞU", hp ? String(hp.hits) : "—"],
      ]);

      // honeypot formu
      const s1 = section("HONEYPOT", 1);
      const form = el("form", "d-form");
      form.noValidate = true;
      const on = el("button", "d-toggle");
      on.type = "button";
      const dr = drafts.get(id);
      let enabled = dr ? dr.enabled : !!(hp && hp.enabled);
      const paint = () => { on.setAttribute("aria-pressed", String(enabled)); on.textContent = enabled ? "AÇIK" : "KAPALI"; };
      paint();
      const save = () => drafts.set(id, { enabled, ssh: sshIn.value, tcp: tcpIn.value, ab: ab.checked });
      on.addEventListener("click", () => { enabled = !enabled; paint(); save(); });
      const f1 = el("label", "d-field"); f1.appendChild(el("span", "label dim", "DURUM")); f1.appendChild(on);
      const sshIn = el("input"); sshIn.type = "number"; sshIn.min = "1"; sshIn.max = "65535"; sshIn.inputMode = "numeric";
      sshIn.value = hp && hp.ssh_port ? String(hp.ssh_port) : "2222";
      const f2 = el("label", "d-field"); f2.appendChild(el("span", "label dim", "SAHTE SSH PORTU")); f2.appendChild(sshIn);
      const tcpIn = el("input"); tcpIn.type = "text"; tcpIn.spellcheck = false;
      tcpIn.value = hp && hp.tcp_ports && hp.tcp_ports.length ? hp.tcp_ports.join(", ") : "23, 3389, 5900";
      const f3 = el("label", "d-field wide"); f3.appendChild(el("span", "label dim", "TCP TUZAK PORTLARI")); f3.appendChild(tcpIn);
      // hiç yapılandırılmamış honeypot'ta otomatik engel varsayılan olarak açık
      const configured = !!(hp && (hp.enabled || hp.ssh_port || (hp.tcp_ports && hp.tcp_ports.length)));
      const ab = el("input"); ab.type = "checkbox"; ab.checked = configured ? !!hp.auto_block : true;
      if (dr) { sshIn.value = dr.ssh; tcpIn.value = dr.tcp; ab.checked = dr.ab; }
      [sshIn, tcpIn, ab].forEach((x) => x.addEventListener("input", save));
      const f4 = el("label", "d-check"); f4.appendChild(ab); f4.appendChild(el("span", "", "Dokunan IP'yi otomatik engelle"));
      [f1, f2, f3, f4].forEach((x) => form.appendChild(x));
      const ferr = el("p", "d-err"); ferr.hidden = true;
      const submit = el("button", "d-btn warn", "UYGULA"); submit.type = "submit";
      if (!ag.online) submit.title = "Ajan çevrimdışı: komut kuyruğa alınır";
      form.appendChild(submit);
      form.addEventListener("submit", (e) => {
        e.preventDefault();
        ferr.hidden = true;
        let ports, sshPort = 0;
        try {
          ports = parsePorts(tcpIn.value);
          if (sshIn.value.trim()) {
            sshPort = Number(sshIn.value);
            if (!Number.isInteger(sshPort) || sshPort < 1 || sshPort > 65535) throw new Error("Geçersiz SSH portu");
          }
        } catch (x) { ferr.textContent = x.message; ferr.hidden = false; return; }
        drafts.delete(id);
        run(submit, [s], "honeypot", { enabled, ssh_port: sshPort || null, tcp_ports: ports.filter((p) => p !== sshPort), auto_block: ab.checked }, ferr);
      });
      s1.appendChild(form);
      s1.appendChild(ferr);
      if (hp) {
        const errs = hp.errors ? Object.values(hp.errors) : [];
        kv(s1, [["DİNLENEN", hp.listening.length ? hp.listening.join(", ") : "—"], ...errs.map((e) => ["HATA", e, "warn"])]);
      }
      s1.appendChild(el("p", "d-note", "Tuzak portlarına dışarıdan ulaşılması için sunucunun güvenlik duvarında (UFW) bu portlar açılmalı. 1024 altı portlar ajan servisinde CAP_NET_BIND_SERVICE ister. Gerçek SSH portunu (22) tuzak olarak seçmeyin."));

      // engelli ve izinli IP'ler
      const s2 = section("ETKİN ENGELLER", 2);
      listIPs(s2, st ? st.blocked : [], "KALDIR", (ip, b) => run(b, [s], "unblock_ip", { ip }, ferr2(s2)), st ? "Etkin engel yok." : "Ajan durumu henüz gelmedi.");
      const s3 = section("İZİN LİSTESİ", 3);
      listIPs(s3, st ? st.allow : [], "ÇIKAR", (ip, b) => run(b, [s], "disallow_ip", { ip }, ferr2(s3)), st ? "İzin listesi boş." : "Ajan durumu henüz gelmedi.");

      // komut geçmişi
      const s4 = section("KOMUT GEÇMİŞİ", 4);
      const list = mergedCmds(id);
      if (list.length) { const ul = el("ul", "d-cmds"); list.slice(0, 12).forEach((c) => cmdLine(ul, c)); s4.appendChild(ul); }
      else empty(s4, "Henüz komut yok.");
      if (!serverCmds.has(id)) loadCmds(id);

      // son bulgular
      const s5 = section("SON BULGULAR", 5);
      const recent = [...fs].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at)).slice(0, 8);
      if (recent.length) {
        const ul = el("ul", "d-links");
        for (const f of recent) {
          const ip = ctx.ipOf(f);
          const li = el("li");
          const b = el("button", "d-link");
          b.type = "button";
          b.appendChild(el("span", "", ip || f.type));
          b.appendChild(el("span", "sub", ctx.fmtDateTime(f.created_at) + " · " + f.type + " · " + ctx.attemptsOf(f)));
          if (ip) b.addEventListener("click", () => open("ip", ip, b));
          else b.disabled = true;
          li.appendChild(b);
          ul.appendChild(li);
        }
        s5.appendChild(ul);
      } else empty(s5, "Bulgu yok.");
    }
    function ferr2(sec) {
      let p = sec.querySelector(".d-err");
      if (!p) { p = el("p", "d-err"); p.hidden = true; sec.appendChild(p); }
      return p;
    }
    function listIPs(parent, ips, label, onClick, emptyText) {
      if (!ips || !ips.length) { empty(parent, emptyText); return; }
      const ul = el("ul", "d-iplist");
      for (const ip of ips) {
        const li = el("li");
        const a = el("button", "d-link", ip); a.type = "button";
        a.addEventListener("click", () => open("ip", ip, a));
        li.appendChild(a);
        button(li, label, (e) => onClick(ip, e.currentTarget));
        ul.appendChild(li);
      }
      parent.appendChild(ul);
    }
    function mergedCmds(id) {
      const m = new Map();
      for (const c of serverCmds.get(id) || []) m.set(c.id, c);
      for (const c of cmdLog.values()) if (c.server_id === id) remember(m, c);
      return [...m.values()].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
    }
    async function loadCmds(id) {
      serverCmds.set(id, []);
      try {
        const list = await ctx.getJSON("/api/v1/servers/" + encodeURIComponent(id) + "/commands");
        serverCmds.set(id, list || []);
        if (view && view.type === "server" && view.key === id) render(false);
      } catch (e) {
        serverCmds.delete(id); // bir sonraki açılışta yeniden denenir
      }
    }

    // ---------- çekmece ----------
    function render(animate) {
      if (!view) return;
      const scroll = body.scrollTop;
      body.textContent = "";
      root.classList.toggle("anim", !!animate && !ctx.reduced());
      if (view.type === "ip") renderIP(view.key, animate);
      else renderServer(view.key, animate);
      if (!animate) body.scrollTop = scroll;
    }

    function open(type, key, from) {
      if (!key) return;
      const same = view && view.type === type && view.key === key;
      view = { type, key };
      if (from && !root.contains(from)) opener = from;
      root.hidden = false;
      document.body.classList.add("drawer-open");
      // yeniden tetiklenen animasyon için sınıfı kaldır-ekle
      root.classList.remove("in");
      void root.offsetWidth;
      root.classList.add("in");
      render(!same);
      ctx.onSelect(type === "ip" ? key : null);
      if (!same) body.scrollTop = 0;
      $("d-close").focus({ preventScroll: true });
    }

    function close() {
      if (!view) return;
      view = null;
      root.classList.remove("in");
      root.hidden = true;
      document.body.classList.remove("drawer-open");
      ctx.onSelect(null);
      if (opener && document.contains(opener)) opener.focus({ preventScroll: true });
      opener = null;
    }

    const typing = () => { const a = document.activeElement; return !!a && root.contains(a) && (a.tagName === "INPUT" || a.tagName === "TEXTAREA"); };
    function refresh() {
      if (!view) return;
      if (typing()) { deferred = true; return; }
      render(false);
    }
    root.addEventListener("focusout", () => setTimeout(() => { if (deferred && !typing()) { deferred = false; render(false); } }, 0));

    $("d-close").addEventListener("click", close);
    document.addEventListener("keydown", (e) => { if (e.key === "Escape" && view) { e.preventDefault(); close(); } });

    return {
      open,
      close,
      get view() { return view; },
      refresh,
      onCommand(c) {
        remember(cmdLog, c);
        const list = serverCmds.get(c.server_id);
        if (list) {
          const i = list.findIndex((x) => x.id === c.id);
          if (i < 0) list.unshift(c);
          else if ((RANK[c.status] || 0) >= (RANK[list[i].status] || 0)) list[i] = c;
        }
        refresh();
      },
    };
  }

  window.NexDetail = { create };
})();
