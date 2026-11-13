"""Shared SVG + CSS @keyframes primitives for animated ByteByteGo-style diagrams."""

import html
import unicodedata

SHARED_SYMBOLS = """
<defs>
  <marker id="bb-ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="9" markerHeight="9" markerUnits="userSpaceOnUse" orient="auto-start-reverse">
    <path d="M1 1L9.5 5L1 9Z" fill="#111111" stroke="#111111" stroke-linejoin="round"/>
  </marker>
  <marker id="bb-ah-red" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="9" markerHeight="9" markerUnits="userSpaceOnUse" orient="auto-start-reverse">
    <path d="M1 1L9.5 5L1 9Z" fill="#e11d48" stroke="#e11d48" stroke-linejoin="round"/>
  </marker>
  <marker id="bb-ah-green" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="9" markerHeight="9" markerUnits="userSpaceOnUse" orient="auto-start-reverse">
    <path d="M1 1L9.5 5L1 9Z" fill="#16a34a" stroke="#16a34a" stroke-linejoin="round"/>
  </marker>
  <marker id="bb-ah-blue" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="9" markerHeight="9" markerUnits="userSpaceOnUse" orient="auto-start-reverse">
    <path d="M1 1L9.5 5L1 9Z" fill="#2563eb" stroke="#2563eb" stroke-linejoin="round"/>
  </marker>
  <marker id="bb-ah-amber" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="9" markerHeight="9" markerUnits="userSpaceOnUse" orient="auto-start-reverse">
    <path d="M1 1L9.5 5L1 9Z" fill="#d97706" stroke="#d97706" stroke-linejoin="round"/>
  </marker>
  <filter id="bb-shadow" x="-8%" y="-8%" width="118%" height="126%">
    <feDropShadow dx="0" dy="2" stdDeviation="2.2" flood-color="#0f172a" flood-opacity="0.14"/>
  </filter>
  <symbol id="bb-packet" preserveAspectRatio="none" viewBox="0 0 44 28">
    <g stroke="#111111" stroke-width="2" stroke-linejoin="round" stroke-linecap="round">
      <rect x="1" y="1" width="42" height="26" rx="7" style="fill:var(--pk,#7de3b4)" vector-effect="non-scaling-stroke"/>
      <path d="M7 6.5H18" fill="none" stroke="#ffffff" stroke-width="2.2" opacity=".7" vector-effect="non-scaling-stroke"/>
    </g>
  </symbol>
  <symbol id="bb-nic" viewBox="0 0 64 64">
    <g stroke="#111111" stroke-width="2.2" stroke-linejoin="round" stroke-linecap="round">
      <rect x="8" y="14" width="48" height="32" rx="5" fill="#7de3b4"/>
      <rect x="16" y="21" width="20" height="16" rx="2" fill="#1e293b"/>
      <circle cx="46" cy="24" r="3" fill="#ffe27a"/>
      <circle cx="46" cy="34" r="3" fill="#ff9f43"/>
      <path d="M14 46V53H22V46M26 46V53H34V46M38 46V53H46V46" fill="#ffd66b"/>
    </g>
  </symbol>
  <symbol id="bb-shield" viewBox="0 0 64 64">
    <g stroke="#111111" stroke-width="2.2" stroke-linejoin="round" stroke-linecap="round">
      <path d="M32 6L52 14V30C52 44 42 54 32 58C22 54 12 44 12 30V14Z" fill="#ffe4e6"/>
      <path d="M32 13L45 18.5V30C45 39.5 38.5 47 32 50.5C25.5 47 19 39.5 19 30V18.5Z" fill="#fb7185"/>
      <path d="M25 31L30 36L40 25" fill="none" stroke="#ffffff" stroke-width="3.5"/>
    </g>
  </symbol>
  <symbol id="bb-cpu" viewBox="0 0 64 64">
    <g stroke="#111111" stroke-width="2.2" stroke-linejoin="round" stroke-linecap="round">
      <rect x="16" y="16" width="32" height="32" rx="6" fill="#93c5fd"/>
      <rect x="23" y="23" width="18" height="18" rx="3" fill="#ffffff"/>
      <path d="M24 8V16M32 8V16M40 8V16M24 48V56M32 48V56M40 48V56M8 24H16M8 32H16M8 40H16M48 24H56M48 32H56M48 40H56"/>
    </g>
  </symbol>
  <symbol id="bb-map" viewBox="0 0 64 64">
    <g stroke="#111111" stroke-width="2.2" stroke-linejoin="round" stroke-linecap="round">
      <ellipse cx="32" cy="15" rx="20" ry="7" fill="#fde68a"/>
      <path d="M12 15V47C12 51 21 54 32 54C43 54 52 51 52 47V15" fill="#fef3c7"/>
      <path d="M12 26C12 30 21 33 32 33C43 33 52 30 52 26M12 37C12 41 21 44 32 44C43 44 52 41 52 37" fill="none"/>
      <ellipse cx="32" cy="15" rx="20" ry="7" fill="#fbbf24"/>
    </g>
  </symbol>
  <symbol id="bb-server" viewBox="0 0 64 64">
    <g stroke="#111111" stroke-width="2" stroke-linejoin="round" stroke-linecap="round">
      <rect x="8" y="6" width="48" height="15" rx="3.5" fill="#cbd5e1"/>
      <path d="M14 10V17M20 10V17M26 10V17" stroke="#f97316" stroke-width="2.6"/>
      <circle cx="47" cy="13.5" r="2.5" fill="#4ade80" stroke-width="1.5"/>
      <rect x="8" y="24" width="48" height="15" rx="3.5" fill="#cbd5e1"/>
      <path d="M14 28V35M20 28V35M26 28V35" stroke="#f97316" stroke-width="2.6"/>
      <circle cx="47" cy="31.5" r="2.5" fill="#4ade80" stroke-width="1.5"/>
      <rect x="8" y="42" width="48" height="15" rx="3.5" fill="#cbd5e1"/>
      <path d="M14 46V53M20 46V53M26 46V53" stroke="#f97316" stroke-width="2.6"/>
      <circle cx="47" cy="49.5" r="2.5" fill="#ffffff" stroke-width="1.5"/>
    </g>
  </symbol>
  <symbol id="bb-app" viewBox="0 0 64 64">
    <g stroke="#111111" stroke-width="2.2" stroke-linejoin="round" stroke-linecap="round">
      <rect x="6" y="10" width="52" height="44" rx="6" fill="#ffffff"/>
      <path d="M6 16Q6 10 12 10H52Q58 10 58 16V23H6Z" fill="#3b82f6"/>
      <circle cx="13" cy="16.5" r="2" fill="#ffffff" stroke-width="1.4"/>
      <circle cx="20" cy="16.5" r="2" fill="#ffffff" stroke-width="1.4"/>
      <circle cx="27" cy="16.5" r="2" fill="#ffffff" stroke-width="1.4"/>
      <path d="M16 33L24 39L16 45M28 45H42" fill="none" stroke="#1e293b" stroke-width="2.8"/>
    </g>
  </symbol>
  <symbol id="bb-doc" viewBox="0 0 64 64">
    <g stroke="#111111" stroke-width="2.2" stroke-linejoin="round" stroke-linecap="round">
      <path d="M14 6H38L50 18V58H14Z" fill="#ffffff"/>
      <path d="M38 6V18H50" fill="#cbd5e1"/>
      <path d="M21 28H43M21 36H43M21 44H35" fill="none" stroke="#3b82f6" stroke-width="2.5"/>
    </g>
  </symbol>
  <symbol id="bb-ring" viewBox="0 0 64 64">
    <g stroke="#111111" stroke-width="2.2" stroke-linejoin="round" stroke-linecap="round">
      <circle cx="32" cy="32" r="24" fill="#fde68a"/>
      <circle cx="32" cy="32" r="11" fill="#ffffff"/>
      <path d="M32 8V21M32 43V56M8 32H21M43 32H56M15 15L24 24M40 40L49 49M49 15L40 24M24 40L15 49" stroke="#d97706" stroke-width="2"/>
    </g>
  </symbol>
  <symbol id="bb-disk" viewBox="0 0 64 64">
    <g stroke="#111111" stroke-width="2.2" stroke-linejoin="round" stroke-linecap="round">
      <rect x="10" y="10" width="44" height="44" rx="7" fill="#cbd5e1"/>
      <circle cx="32" cy="29" r="13" fill="#ffffff"/>
      <circle cx="32" cy="29" r="4.5" fill="#475569"/>
      <path d="M20 47H44" stroke="#1e293b" stroke-width="3"/>
      <circle cx="17" cy="47" r="2" fill="#22c55e"/>
    </g>
  </symbol>
</defs>
"""

BASE_CSS = (
    "text{font-family:'Noto Sans','Noto Sans Thai','DejaVu Sans',sans-serif}"
    ".ant{fill:none;stroke:#111111;stroke-width:2.2;stroke-dasharray:8 6;animation:bb-ants .7s linear infinite}"
    ".ant-red{fill:none;stroke:#e11d48;stroke-width:2.4;stroke-dasharray:8 6;animation:bb-ants .65s linear infinite}"
    ".ant-green{fill:none;stroke:#16a34a;stroke-width:2.4;stroke-dasharray:8 6;animation:bb-ants .65s linear infinite}"
    ".ant-blue{fill:none;stroke:#2563eb;stroke-width:2.4;stroke-dasharray:8 6;animation:bb-ants .65s linear infinite}"
    ".ant-amber{fill:none;stroke:#d97706;stroke-width:2.2;stroke-dasharray:7 5;animation:bb-ants .75s linear infinite}"
    ".card{filter:url(#bb-shadow)}"
    "@keyframes bb-ants{to{stroke-dashoffset:-14}}"
    "@media (prefers-reduced-motion: reduce){*{animation:none!important}}"
)

ROW_COLORS = ["#d6eefb", "#fde5dc", "#d8f3e3", "#e7dff8", "#faefd3", "#dbeafe"]


def esc(s: str) -> str:
    return html.escape(s, quote=True)


def advance_units(text: str) -> float:
    """Count spacing characters (ignore Thai combining vowels/tone marks)."""
    total = 0.0
    for ch in text:
        if unicodedata.combining(ch):
            continue
        if ord(ch) == 0x0E31 or 0x0E34 <= ord(ch) <= 0x0E3A or 0x0E47 <= ord(ch) <= 0x0E4E:
            continue
        total += 0.9 if ord(ch) > 127 else 1.0
    return max(1.0, total)


def badge_x_width(text: str, font_size: int = 23) -> int:
    return max(96, int(advance_units(text) * (font_size * 0.57)) + 44)


def make_header(tag_left: str, tag_right: str, subtitle: str,
                c_left: str = "#6a3cc8", c_right: str = "#ff8a1f") -> str:
    w1 = badge_x_width(tag_left, 23)
    w2 = badge_x_width(tag_right, 22)
    x2 = 44 + w1 + 12
    assert x2 + w2 <= 936, f"header too wide ({x2 + w2} > 936) for {tag_left} + {tag_right}"
    return (
        '<rect x="24" y="22" width="8" height="52" rx="4" fill="#2ee6a6" stroke="#111111" stroke-width="2"/>'
        f'<rect x="44" y="22" width="{w1}" height="46" rx="9" fill="{c_left}" stroke="#111111" stroke-width="2"/>'
        f'<text x="{44 + w1 / 2:.1f}" y="52" font-size="22" font-weight="700" fill="#ffffff" text-anchor="middle">{esc(tag_left)}</text>'
        f'<rect x="{x2}" y="22" width="{w2}" height="46" rx="9" fill="{c_right}" stroke="#111111" stroke-width="2"/>'
        f'<text x="{x2 + w2 / 2:.1f}" y="52" font-size="21" font-weight="700" fill="#111111" text-anchor="middle">{esc(tag_right)}</text>'
        f'<text x="44" y="95" font-size="15.5" font-weight="600" fill="#1e293b" text-anchor="start">{esc(subtitle)}</text>'
    )


def make_stage(y: int, h: int, title: str, header_bg: str = "#6a3cc8", body_bg: str = "#dff3f8") -> str:
    return (
        f'<clipPath id="clip-stage-{y}"><rect x="24" y="{y}" width="912" height="{h}" rx="16"/></clipPath>'
        f'<g clip-path="url(#clip-stage-{y})">'
        f'<rect x="24" y="{y}" width="912" height="44" fill="{header_bg}"/>'
        f'<rect x="24" y="{y + 44}" width="912" height="{h - 44}" fill="{body_bg}"/>'
        f'</g>'
        f'<path d="M24 {y + 44}H936" stroke="#111111" stroke-width="2"/>'
        f'<rect x="24" y="{y}" width="912" height="{h}" rx="16" fill="none" stroke="#111111" stroke-width="2"/>'
        f'<text x="480" y="{y + 28}" font-size="16" font-weight="700" fill="#ffffff" text-anchor="middle">{esc(title)}</text>'
    )


def kf_highlight(cls: str, dur: float, t0: float, t1: float) -> str:
    p0 = max(0.0, (t0 - 0.15) / dur * 100.0)
    p0_in = (t0 + 0.15) / dur * 100.0
    p1_out = max(p0_in + 0.2, (t1 - 0.15) / dur * 100.0)
    p1 = min(100.0, (t1 + 0.15) / dur * 100.0)
    return (
        f"@keyframes {cls}{{0%{{opacity:0}}{p0:.2f}%{{opacity:0}}{p0_in:.2f}%{{opacity:1}}"
        f"{p1_out:.2f}%{{opacity:1}}{p1:.2f}%{{opacity:0}}100%{{opacity:0}}}}"
        f".{cls}{{opacity:0;animation:{cls} {dur:.1f}s linear infinite}}"
    )


def kf_pop(cls: str, dur: float, t0: float, t1: float) -> str:
    p0 = max(0.0, t0 / dur * 100.0)
    p0_in = min(99.0, (t0 + 0.22) / dur * 100.0)
    p1_out = max(p0_in + 0.1, (t1 - 0.20) / dur * 100.0)
    p1 = min(100.0, t1 / dur * 100.0)
    return (
        f"@keyframes {cls}{{0%{{opacity:0}}{p0:.2f}%{{opacity:0}}{p0_in:.2f}%{{opacity:1}}"
        f"{p1_out:.2f}%{{opacity:1}}{p1:.2f}%{{opacity:0}}100%{{opacity:0}}}}"
        f".{cls}{{opacity:0;animation:{cls} {dur:.1f}s linear infinite}}"
    )


def kf_move(cls: str, dur: float, t0: float, t1: float,
            pts: list[tuple[float, float]]) -> str:
    assert len(pts) >= 2
    p0 = t0 / dur * 100.0
    p_end = t1 / dur * 100.0
    span = p_end - p0
    x0, y0 = pts[0]
    frames = [
        f"0%{{opacity:0;transform:translate({x0:.1f}px,{y0:.1f}px)}}",
        f"{p0:.2f}%{{opacity:0;transform:translate({x0:.1f}px,{y0:.1f}px)}}",
    ]
    for idx, (x, y) in enumerate(pts):
        frac = 0.08 + 0.84 * (idx / (len(pts) - 1))
        p = p0 + span * frac
        frames.append(f"{p:.2f}%{{opacity:1;transform:translate({x:.1f}px,{y:.1f}px)}}")
    frames.append(f"{p_end:.2f}%{{opacity:0;transform:translate({pts[-1][0]:.1f}px,{pts[-1][1]:.1f}px)}}")
    frames.append(f"100%{{opacity:0;transform:translate({x0:.1f}px,{y0:.1f}px)}}")
    return (
        f"@keyframes {cls}{{{''.join(frames)}}}"
        f".{cls}{{opacity:0;transform:translate({x0:.1f}px,{y0:.1f}px);animation:{cls} {dur:.1f}s linear infinite}}"
    )


def pkt_chip(cls: str, label: str, fill: str, width: int = 0, height: int = 28) -> str:
    auto_w = max(84, int(advance_units(label) * 8.0) + 28)
    w = max(width, auto_w) if width else auto_w
    return (
        f'<g class="{cls}">'
        f'<use href="#bb-packet" x="{-w / 2:.1f}" y="{-height / 2:.1f}" width="{w}" height="{height}" style="--pk:{fill}"/>'
        f'<text x="0" y="5" text-anchor="middle" font-size="12.5" font-weight="700" fill="#111111">{esc(label)}</text>'
        f'</g>'
    )


def pop_pill(cls: str, cx: float, cy: float, text: str,
             fill: str = "#22c55e", text_fill: str = "#ffffff") -> str:
    w = max(124, int(advance_units(text) * 8.0) + 30)
    return (
        f'<g class="{cls}">'
        f'<rect x="{cx - w / 2:.1f}" y="{cy - 12:.1f}" width="{w}" height="24" rx="12" fill="{fill}" stroke="#111111" stroke-width="1.8"/>'
        f'<text x="{cx:.1f}" y="{cy + 4.5:.1f}" font-size="12" font-weight="700" fill="{text_fill}" text-anchor="middle">{esc(text)}</text>'
        f'</g>'
    )


def make_step_table(y: int, steps: list[tuple[str, str, float, float]], dur: float,
                    split_x: int = 264, header_bg: str = "#6a3cc8") -> tuple[str, str, int]:
    row_h = 44
    head_h = 44
    n = len(steps)
    total_h = head_h + n * row_h

    clips = [f'<rect x="24" y="{y}" width="912" height="{head_h}" fill="{header_bg}"/>']
    lines = []
    for i in range(n):
        ry = y + head_h + i * row_h
        col = ROW_COLORS[i % len(ROW_COLORS)]
        clips.append(f'<rect x="24" y="{ry}" width="912" height="{row_h}" fill="{col}"/>')
        lines.append(f'<path d="M24 {ry}H936" stroke="#111111" stroke-width="2"/>')

    out = [
        f'<clipPath id="clip-tbl-{y}"><rect x="24" y="{y}" width="912" height="{total_h}" rx="16"/></clipPath>',
        f'<g clip-path="url(#clip-tbl-{y})">{"".join(clips)}</g>',
        "".join(lines),
        f'<path d="M{split_x} {y}V{y + total_h}" stroke="#111111" stroke-width="2"/>',
        f'<rect x="24" y="{y}" width="912" height="{total_h}" rx="16" fill="none" stroke="#111111" stroke-width="2"/>',
        f'<text x="{(24 + split_x) / 2:.1f}" y="{y + 28}" font-size="16" font-weight="700" fill="#ffffff" text-anchor="middle">ขั้นตอน</text>',
        f'<text x="{(split_x + 936) / 2:.1f}" y="{y + 28}" font-size="16" font-weight="700" fill="#ffffff" text-anchor="middle">เกิดอะไรขึ้น</text>',
    ]

    css = []
    for i, (short_title, desc, t0, t1) in enumerate(steps):
        ry = y + head_h + i * row_h
        cy = ry + row_h / 2
        cls = f"hi{i}"
        css.append(kf_highlight(cls, dur, t0, t1))
        out.append(
            f'<rect class="{cls}" x="27" y="{ry + 3}" width="906" height="{row_h - 6}" rx="9" '
            f'fill="#ffe27a" stroke="#111111" stroke-width="2" style="opacity:0"/>'
        )
        out.append(
            f'<circle cx="48" cy="{cy:.1f}" r="12" fill="#ffffff" stroke="#111111" stroke-width="2"/>'
            f'<text x="48" y="{cy + 5:.1f}" font-size="13.5" font-weight="700" fill="#111111" text-anchor="middle">{i + 1}</text>'
            f'<text x="68" y="{cy + 5:.1f}" font-size="14" font-weight="700" fill="#111111" text-anchor="start">{esc(short_title)}</text>'
            f'<text x="{split_x + 14}" y="{cy + 5:.1f}" font-size="13.5" font-weight="400" fill="#111111" text-anchor="start">{esc(desc)}</text>'
        )

    return "".join(out), "".join(css), total_h


def node_card(x: int, y: int, w: int, h: int, title: str, sub: str = "",
              fill: str = "#ffffff", icon: str = "", badge: str = "", badge_fill: str = "#e2e8f0") -> str:
    """Draw a card with clean non-overlapping spacing for icon, title, subtitle, and pill badge."""
    parts = [
        f'<rect class="card" x="{x}" y="{y}" width="{w}" height="{h}" rx="14" fill="{fill}" stroke="#111111" stroke-width="2"/>'
    ]
    cx = x + w / 2
    if icon and badge:
        icon_size = 40 if h < 140 else 44
        parts.append(f'<use href="#{icon}" x="{cx - icon_size / 2:.1f}" y="{y + 10}" width="{icon_size}" height="{icon_size}"/>')
        ty = y + 10 + icon_size + 18
        sy = ty + 19
        by = y + h - 28
        assert sy + 6 < by, f"Card '{title}' height {h} too small for icon+sub+badge"
    elif icon and not badge:
        icon_size = 44 if h >= 120 else 38
        parts.append(f'<use href="#{icon}" x="{cx - icon_size / 2:.1f}" y="{y + 14}" width="{icon_size}" height="{icon_size}"/>')
        ty = y + 14 + icon_size + 22
        sy = ty + 20
        by = 0
    elif not icon and badge:
        ty = y + (26 if h <= 96 else 30)
        sy = ty + 20
        by = y + h - 27
        assert sy + 5 < by, f"Card '{title}' height {h} too small for sub+badge"
    else:
        ty = y + (h / 2 - 4 if sub else h / 2 + 5)
        sy = ty + 21
        by = 0

    parts.append(f'<text x="{cx:.1f}" y="{ty:.1f}" font-size="14.5" font-weight="700" fill="#111111" text-anchor="middle">{esc(title)}</text>')
    if sub:
        parts.append(f'<text x="{cx:.1f}" y="{sy:.1f}" font-size="12.5" font-weight="500" fill="#475569" text-anchor="middle">{esc(sub)}</text>')
    if badge:
        bw = min(w - 14, max(84, int(advance_units(badge) * 7.6) + 22))
        bx = cx - bw / 2
        parts.append(f'<rect x="{bx:.1f}" y="{by}" width="{bw}" height="21" rx="10.5" fill="{badge_fill}" stroke="#111111" stroke-width="1.5"/>')
        parts.append(f'<text x="{cx:.1f}" y="{by + 15:.1f}" font-size="11.5" font-weight="700" fill="#111111" text-anchor="middle">{esc(badge)}</text>')
    return "".join(parts)
