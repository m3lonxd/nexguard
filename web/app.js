function dashboard() {
  return {
    servers: [],
    findings: [],
    actions: [],
    error: null,

    async init() {
      await this.refresh();
      this.connectStream();
    },

    async refresh() {
      try {
        const [servers, findings, actions] = await Promise.all([
          fetch("/api/v1/servers").then((r) => r.json()),
          fetch("/api/v1/findings").then((r) => r.json()),
          fetch("/api/v1/actions").then((r) => r.json()),
        ]);
        this.servers = servers || [];
        this.findings = findings || [];
        this.actions = actions || [];
        this.error = null;
      } catch (e) {
        this.error = "Veri yüklenemedi: " + e;
      }
    },

    connectStream() {
      const proto = location.protocol === "https:" ? "wss:" : "ws:";
      const ws = new WebSocket(proto + "//" + location.host + "/api/v1/stream");
      ws.onmessage = (ev) => {
        let msg;
        try {
          msg = JSON.parse(ev.data);
        } catch {
          return;
        }
        if (msg.kind === "finding" && msg.finding) {
          this.findings.unshift(msg.finding);
        } else if (msg.kind === "action" && msg.action) {
          this.actions = this.actions.filter((a) => a.id !== msg.action.id);
          this.actions.unshift(msg.action);
        }
      };
      ws.onclose = () => setTimeout(() => this.connectStream(), 2000);
    },

    hostnameFor(serverId) {
      const s = this.servers.find((s) => s.id === serverId);
      return s ? s.hostname : serverId;
    },

    fmtTime(ts) {
      if (!ts) return "—";
      return new Date(ts).toLocaleString("tr-TR");
    },
  };
}
