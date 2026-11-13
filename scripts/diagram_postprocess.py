#!/usr/bin/env python3
"""Turn a raw mermaid-cli SVG into the course's ByteByteGo-style SVG.

What it adds on top of the Mermaid output:
  * rounded corners on node boxes (rx=10) and subgraph cards (rx=16)
  * a soft drop shadow under every node
  * a white rounded "card" background so the image reads well on
    GitHub's light and dark themes
  * the fonts, embedded as WOFF subsets, so Thai text looks the same on
    every viewer and keeps the widths Mermaid measured at render time

Font subsetting uses HarfBuzz (libharfbuzz-subset.so.0) through ctypes, so
no Python packages are needed. On Ubuntu it comes with libharfbuzz-subset0.

Usage: diagram_postprocess.py RAW.svg OUT.svg FONT_DIR
"""

import base64
import ctypes
import ctypes.util
import html
import re
import struct
import sys
import zlib
from pathlib import Path

# (CSS family, weight, file) in fallback order; must match the order of
# themeVariables.fontFamily in docs/diagrams/mermaid-config.json.
FONTS = [
    ("Noto Sans", 400, "NotoSans-Regular.ttf"),
    ("Noto Sans", 700, "NotoSans-Bold.ttf"),
    ("Noto Sans Thai", 400, "NotoSansThai-Regular.ttf"),
    ("Noto Sans Thai", 700, "NotoSansThai-Bold.ttf"),
    ("DejaVu Sans", 400, "DejaVuSans.ttf"),
    ("DejaVu Sans", 700, "DejaVuSans-Bold.ttf"),
]

SHADOW_DEFS = (
    '<defs><filter id="bbg-shadow" x="-10%" y="-10%" width="120%" height="140%">'
    '<feDropShadow dx="0" dy="2" stdDeviation="2.2" flood-color="#0f172a" flood-opacity="0.16"/>'
    "</filter></defs>"
)

EXTRA_CSS = (
    ".node rect, .node polygon, .node circle, .node ellipse, .node path"
    "{filter:url(#bbg-shadow);}"
    ".cluster-label .nodeLabel, .cluster-label span, .cluster-label p"
    "{color:#ffffff !important;fill:#ffffff !important;}"
)


# --------------------------------------------------------------------------
# HarfBuzz subsetting through ctypes
# --------------------------------------------------------------------------
class HarfBuzz:
    def __init__(self):
        hb = ctypes.CDLL(ctypes.util.find_library("harfbuzz") or "libharfbuzz.so.0")
        sub = ctypes.CDLL(ctypes.util.find_library("harfbuzz-subset") or "libharfbuzz-subset.so.0")
        P = ctypes.c_void_p
        hb.hb_blob_create_from_file.restype = P
        hb.hb_blob_create_from_file.argtypes = [ctypes.c_char_p]
        hb.hb_face_create.restype = P
        hb.hb_face_create.argtypes = [P, ctypes.c_uint]
        hb.hb_face_reference_blob.restype = P
        hb.hb_face_reference_blob.argtypes = [P]
        hb.hb_blob_get_data.restype = ctypes.POINTER(ctypes.c_char)
        hb.hb_blob_get_data.argtypes = [P, ctypes.POINTER(ctypes.c_uint)]
        hb.hb_set_create.restype = P
        hb.hb_set_add.argtypes = [P, ctypes.c_uint32]
        hb.hb_set_has.restype = ctypes.c_int
        hb.hb_set_has.argtypes = [P, ctypes.c_uint32]
        hb.hb_face_collect_unicodes.argtypes = [P, P]
        for f in ("hb_blob_destroy", "hb_face_destroy", "hb_set_destroy"):
            getattr(hb, f).argtypes = [P]
        sub.hb_subset_input_create_or_fail.restype = P
        sub.hb_subset_input_unicode_set.restype = P
        sub.hb_subset_input_unicode_set.argtypes = [P]
        sub.hb_subset_input_set_flags.argtypes = [P, ctypes.c_uint]
        sub.hb_subset_or_fail.restype = P
        sub.hb_subset_or_fail.argtypes = [P, P]
        sub.hb_subset_input_destroy.argtypes = [P]
        self.hb, self.sub = hb, sub
        self.faces = {}

    def face(self, path):
        if path not in self.faces:
            blob = self.hb.hb_blob_create_from_file(str(path).encode())
            face = self.hb.hb_face_create(blob, 0)
            cmap = self.hb.hb_set_create()
            self.hb.hb_face_collect_unicodes(face, cmap)
            self.faces[path] = (face, cmap)
        return self.faces[path]

    def covers(self, path, cp):
        return bool(self.hb.hb_set_has(self.face(path)[1], cp))

    def subset(self, path, codepoints):
        face, _ = self.face(path)
        inp = self.sub.hb_subset_input_create_or_fail()
        uset = self.sub.hb_subset_input_unicode_set(inp)
        for cp in codepoints:
            self.hb.hb_set_add(uset, cp)
        self.sub.hb_subset_input_set_flags(inp, 0x1)  # HB_SUBSET_FLAGS_NO_HINTING
        out = self.sub.hb_subset_or_fail(face, inp)
        self.sub.hb_subset_input_destroy(inp)
        if not out:
            raise RuntimeError(f"hb_subset failed for {path}")
        blob = self.hb.hb_face_reference_blob(out)
        n = ctypes.c_uint()
        data = ctypes.string_at(self.hb.hb_blob_get_data(blob, ctypes.byref(n)), n.value)
        self.hb.hb_blob_destroy(blob)
        self.hb.hb_face_destroy(out)
        return data


def sfnt_to_woff(ttf: bytes) -> bytes:
    """Wrap an sfnt font in WOFF 1.0 (zlib per table, no extra deps)."""
    flavor, num = struct.unpack(">IH", ttf[:6])
    entries = []
    for i in range(num):
        tag, csum, off, length = struct.unpack(">4sIII", ttf[12 + 16 * i: 28 + 16 * i])
        entries.append((tag, csum, ttf[off:off + length]))
    entries.sort(key=lambda e: e[0])
    offset = 44 + 20 * num
    directory, payload = b"", b""
    for tag, csum, data in entries:
        comp = zlib.compress(data, 9)
        if len(comp) >= len(data):
            comp = data
        directory += struct.pack(">4sIIII", tag, offset, len(comp), len(data), csum)
        pad = (-len(comp)) % 4
        payload += comp + b"\0" * pad
        offset += len(comp) + pad
    total_sfnt = 12 + 16 * num + sum((len(d) + 3) & ~3 for _, _, d in entries)
    header = struct.pack(">4sIIHHIHHIIIII", b"wOFF", flavor, offset, num, 0,
                         total_sfnt, 1, 0, 0, 0, 0, 0, 0)
    return header + directory + payload


def visible_text(svg: str) -> str:
    text = re.sub(r"<style>.*?</style>", "", svg, flags=re.S)
    text = re.sub(r"<[^>]+>", "", text)
    return html.unescape(text)


def font_faces(svg: str, font_dir: Path) -> str:
    hb = HarfBuzz()
    chars = {ord(c) for c in visible_text(svg) if not c.isspace()} | {0x20, 0xA0}
    # HarfBuzz's Thai shaper decomposes SARA AM (U+0E33) into NIKHAHIT + SARA AA
    # by codepoint, so a subset holding only the characters seen in the text
    # makes "นำ"/"ทำ" fall back to another font. Keep the whole Thai block.
    if any(0x0E00 <= cp <= 0x0E7F for cp in chars):
        chars |= set(range(0x0E01, 0x0E5C))
    chars = sorted(chars)
    paths = {f: font_dir / f for _, _, f in FONTS}
    css = []
    for family, weight, fname in FONTS:
        # Give each codepoint to the first family (in fallback order) that has it.
        keep = []
        for cp in chars:
            owner = next((fam for fam, _, fn in FONTS if hb.covers(paths[fn], cp)), None)
            if owner == family:
                keep.append(cp)
        if not keep:
            continue
        woff = sfnt_to_woff(hb.subset(paths[fname], keep))
        b64 = base64.b64encode(woff).decode()
        css.append(
            f"@font-face{{font-family:'{family}';font-weight:{weight};font-style:normal;"
            f"src:url(data:font/woff;base64,{b64}) format('woff');}}"
        )
    return "".join(css)


LABEL_RE = re.compile(
    r'(<g [^>]*?transform="translate\()([-\d.e]+)(, ?[-\d.e]+\)"[^>]*>(?:<rect/>)?<foreignObject [^>]*?width=")([\d.]+)(")'
)


def widen_labels(svg: str) -> str:
    """Give every HTML label a little spare width, kept centred.

    Mermaid sizes each <foreignObject> to the exact text width it measured.
    Browsers drawing an SVG as an <img> may round glyph advances differently,
    which made the last character of long labels get clipped.
    """
    def grow(m):
        x, w = float(m.group(2)), float(m.group(4))
        extra = max(10.0, w * 0.06)
        return f"{m.group(1)}{x - extra / 2:.3f}{m.group(3)}{w + extra:.3f}{m.group(5)}"
    return LABEL_RE.sub(grow, svg)


# Subgraph accent colours (pill header, dashed border, tinted card), picked by
# subgraph id; ids that are not listed get the neutral slate accent.
ACCENTS = {
    "rose": ("#e11d48", "#fff7f8"),
    "blue": ("#2563eb", "#f5f9ff"),
    "green": ("#16a34a", "#f4fcf6"),
    "amber": ("#d97706", "#fffbeb"),
    "violet": ("#7c3aed", "#faf7ff"),
    "slate": ("#475569", "#f8fafc"),
}


def accent_for(cluster_id: str) -> str:
    cid = cluster_id.upper()
    if cid in ("USER", "SNIFF", "LOAD", "TOOLS", "RUN"):
        return "blue"
    if cid in ("KERNEL", "LSM", "TC", "XSK", "TRAMP", "VERIF", "SOCK", "RSHELL", "SX"):
        return "rose"
    if cid in ("TEST", "TESTRUN", "NET", "SIM", "PATH", "SAFETY"):
        return "green"
    if cid in ("MAPS", "MEM", "RB"):
        return "amber"
    if re.fullmatch(r"P\d+", cid):
        return "violet"
    return "slate"


CLUSTER_RE = re.compile(
    r'<g ([^>]*?)id="([^"]+)"([^>]*?)class="cluster[^"]*"([^>]*)>'
    r'<rect ([^>]*?)/>'
    r'<g transform="translate\(([-\d.e]+), ?([-\d.e]+)\)"([^>]*?class="cluster-label"[^>]*)>'
    r'(<foreignObject [^>]*?>)'
)


def attr(tag: str, name: str) -> float:
    return float(re.search(rf'\b{name}="([-\d.e]+)"', tag).group(1))


def style_clusters(svg: str) -> str:
    """ByteByteGo-style subgraphs: tinted dashed card + solid pill header on the top edge."""
    def card(m):
        cid, rect_attrs, lx, fo = m.group(2), m.group(5), float(m.group(6)), m.group(9)
        stroke, tint = ACCENTS[accent_for(cid)]
        ry = attr(rect_attrs, "y")
        fw, fh = attr(fo, "width"), attr(fo, "height")
        rect_attrs = re.sub(r'style="[^"]*"', "", rect_attrs)
        rect = (f'<rect {rect_attrs} style="fill:{tint} !important;stroke:{stroke} !important;'
                f'stroke-width:2px;stroke-dasharray:7 5;"/>')
        ph = fh + 10
        pill = (f'<rect class="bbg-pill" x="{lx - 14:.2f}" y="{ry - ph / 2:.2f}" width="{fw + 28:.2f}" '
                f'height="{ph:.2f}" rx="{ph / 2:.2f}" ry="{ph / 2:.2f}" filter="url(#bbg-shadow)" '
                f'style="fill:{stroke} !important;stroke:none !important;stroke-dasharray:none !important;"/>')
        label = f'<g transform="translate({lx}, {ry - fh / 2:.2f})"{m.group(8)}>{fo}'
        return f'<g {m.group(1)}id="{cid}"{m.group(3)}class="cluster"{m.group(4)}>{rect}{pill}{label}'
    return CLUSTER_RE.sub(card, svg)


def process(svg: str, font_dir: Path) -> str:
    # Rounded corners: plain node boxes (no rx yet, or block-beta's rx="0") and subgraph cards.
    svg = re.sub(r'<rect ([^>]*?)\s?r[xy]="0" r[xy]="0"([^>]*class="basic label-container"[^>]*)/>',
                 r'<rect \1\2/>', svg)
    svg = re.sub(r'<rect (?![^>]*\brx=)([^>]*class="basic label-container"[^>]*)/>',
                 r'<rect rx="10" ry="10" \1/>', svg)
    svg = re.sub(r'(<g [^>]*class="cluster[^"]*"[^>]*><rect )', r'\1rx="16" ry="16" ', svg)

    # Other diagram types: sequence actors/notes, packet fields, block-beta boxes.
    for cls, r in (("actor", 10), ("note", 8), ("labelBox", 6), ("packetBlock", 4)):
        svg = re.sub(rf'<rect (?![^>]*\brx=)([^>]*class="[^"]*\b{cls}\b[^"]*"[^>]*)/>',
                     rf'<rect rx="{r}" ry="{r}" \1/>', svg)

    # Pad the viewBox and draw a white card behind everything.
    pad = 16
    m = re.search(r'viewBox="([-\d.]+) ([-\d.]+) ([\d.]+) ([\d.]+)"', svg)
    x, y, w, h = (float(v) for v in m.groups())
    x, y, w, h = x - pad, y - pad, w + 2 * pad, h + 2 * pad
    svg = svg.replace(m.group(0), f'viewBox="{x:.2f} {y:.2f} {w:.2f} {h:.2f}"', 1)
    card = (f'<rect x="{x + 2:.1f}" y="{y + 2:.1f}" width="{w - 4:.1f}" height="{h - 4:.1f}" '
            f'rx="18" ry="18" fill="#ffffff" stroke="#e2e8f0" stroke-width="2"/>')

    svg = widen_labels(svg)
    svg = style_clusters(svg)
    faces = font_faces(svg, font_dir)

    # Root <svg> tag: fixed pixel size (GitHub still shrinks wide images to
    # the column width), transparent background so the card's corners show.
    m = re.match(r"<svg[^>]*>", svg)
    tag = m.group(0)
    tag = re.sub(r'\s(width|height)="[^"]*"', "", tag)
    tag = re.sub(r'\sstyle="[^"]*"', "", tag)
    tag = tag[:-1] + f' width="{w:.0f}" height="{h:.0f}" style="background-color: transparent;">'
    # Card first, so it sits under every diagram type (sequence diagrams draw
    # their actors before Mermaid's <style>).
    head = f"<style>{EXTRA_CSS}{faces}</style>{SHADOW_DEFS}{card}"
    svg = tag + head + svg[m.end():]
    return svg


def main():
    raw, out, font_dir = sys.argv[1], sys.argv[2], Path(sys.argv[3])
    svg = Path(raw).read_text(encoding="utf-8")
    Path(out).write_text(process(svg, font_dir), encoding="utf-8")


if __name__ == "__main__":
    main()
