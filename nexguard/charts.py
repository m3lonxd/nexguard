"""Sunucu tarafında üretilen SVG grafikler (JS gerektirmez, CSP ile uyumlu; renkler CSS sınıflarından gelir)."""
from markupsafe import Markup, escape


def _nice_max(v: float) -> float:
    if v <= 0:
        return 1.0
    mag = 10 ** (len(str(int(v))) - 1) if v >= 1 else 1
    for m in (1, 2, 2.5, 5, 10):
        if v <= m * mag:
            return float(m * mag)
    return float(10 * mag)


def _fmt(v: float) -> str:
    if v >= 1_000_000:
        return f"{v / 1_000_000:.1f}M".replace(".0M", "M")
    if v >= 1000:
        return f"{v / 1000:.1f}k".replace(".0k", "k")
    return f"{v:.0f}" if v >= 10 or v == int(v) else f"{v:.1f}"


def line_chart(values: list[float], *, unit: str = "", warn: float | None = None, attack: float | None = None,
               step_seconds: int = 5, w: int = 640, h: int = 170, cls: str = "c1",
               spark: bool = False) -> Markup:
    """Eksenli çizgi grafik; eşikler yatay kesik çizgi olarak gösterilir.

    spark=True eksen etiketlerini kaldırır (özet kartlarındaki küçük grafikler için).
    """
    if len(values) < 2:
        return Markup('<div class="chart-empty">Veri toplanıyor...</div>')
    left, right, top, bottom = (2, 2, 3, 3) if spark else (44, 12, 10, 24)
    pw, ph = w - left - right, h - top - bottom
    peak = max(values)
    ceiling = peak
    for t in (warn, attack):
        if t is not None and t <= peak * 3:
            ceiling = max(ceiling, t * 1.05)
    ymax = _nice_max(ceiling * 1.1)

    def px(i: int) -> float:
        return left + pw * i / (len(values) - 1)

    def py(v: float) -> float:
        return top + ph - ph * min(v, ymax) / ymax

    parts = [f'<svg viewBox="0 0 {w} {h}" class="chart{" spark" if spark else ""}" role="img" aria-label="Grafik">']
    if not spark:
        for i in range(5):
            v = ymax * i / 4
            y = py(v)
            parts.append(f'<line class="grid" x1="{left}" x2="{w - right}" y1="{y:.1f}" y2="{y:.1f}"/>')
            parts.append(f'<text class="ax" x="{left - 6}" y="{y + 4:.1f}" text-anchor="end">{_fmt(v)}</text>')
        total_s = step_seconds * (len(values) - 1)
        for frac, label in ((0, f"-{total_s // 60 or 1} dk" if total_s >= 60 else f"-{total_s} sn"), (1, "şimdi")):
            x = left + pw * frac
            parts.append(f'<text class="ax" x="{x:.1f}" y="{h - 6}" text-anchor="{"start" if frac == 0 else "end"}">{label}</text>')
    for t, name in ((warn, "uyarı"), (attack, "saldırı")):
        if t is not None and t <= ymax:
            y = py(t)
            parts.append(f'<line class="thr {name}" x1="{left}" x2="{w - right}" y1="{y:.1f}" y2="{y:.1f}"/>')
            if not spark:
                parts.append(f'<text class="thr-t {name}" x="{w - right - 2}" y="{y - 3:.1f}" '
                             f'text-anchor="end">{name} eşiği</text>')
    pts = " ".join(f"{px(i):.1f},{py(v):.1f}" for i, v in enumerate(values))
    area = f"{left},{top + ph} {pts} {px(len(values) - 1):.1f},{top + ph}"
    parts.append(f'<polygon class="area {cls}" points="{area}"/><polyline class="ln {cls}" points="{pts}"/>')
    if not spark:
        parts.append(f'<circle class="dot {cls}" cx="{px(len(values) - 1):.1f}" cy="{py(values[-1]):.1f}" r="3.5"/>')
        parts.append(f'<text class="cur {cls}" x="{left + 4}" y="{top + 12}">{_fmt(values[-1])} {escape(unit)}</text>')
    parts.append("</svg>")
    return Markup("".join(parts))


def donut(percent: float, *, center: str, sub: str = "", state: str = "ok", size: int = 132) -> Markup:
    """Halka gösterge. state: ok | warn | bad | idle."""
    r, c = 52, 2 * 3.14159265 * 52
    p = max(0.0, min(100.0, percent))
    return Markup(
        f'<svg viewBox="0 0 132 132" width="{size}" height="{size}" class="donut {state}" role="img" aria-label="{escape(center)}">'
        f'<circle class="trk" cx="66" cy="66" r="{r}"/>'
        f'<circle class="val" cx="66" cy="66" r="{r}" stroke-dasharray="{c * p / 100:.1f} {c:.1f}" transform="rotate(-90 66 66)"/>'
        f'<text x="66" y="{70 if sub else 76}" text-anchor="middle" class="dc">{escape(center)}</text>'
        + (f'<text x="66" y="90" text-anchor="middle" class="ds">{escape(sub)}</text>' if sub else "") + "</svg>")


def bars(items: list[tuple[str, float, str]], *, w: int = 560, row: int = 30) -> Markup:
    """Yatay çubuk grafik. items: (etiket, değer, sınıf). Değer metni çubuğun sağında."""
    if not items:
        return Markup("")
    mx = max(v for _, v, _ in items) or 1
    label_w, val_w = 150, 56
    bw = w - label_w - val_w
    out = [f'<svg viewBox="0 0 {w} {row * len(items)}" class="bars" role="img" aria-label="Çubuk grafik">']
    for i, (label, v, cls) in enumerate(items):
        y = i * row
        width = max(3.0, bw * v / mx)
        out.append(f'<text class="bl" x="0" y="{y + 19}">{escape(label)}</text>'
                   f'<rect class="bk" x="{label_w}" y="{y + 6}" width="{bw}" height="14" rx="7"/>'
                   f'<rect class="bf {escape(cls)}" x="{label_w}" y="{y + 6}" width="{width:.1f}" height="14" rx="7"/>'
                   f'<text class="bv" x="{w}" y="{y + 19}" text-anchor="end">{_fmt(v)}</text>')
    out.append("</svg>")
    return Markup("".join(out))
