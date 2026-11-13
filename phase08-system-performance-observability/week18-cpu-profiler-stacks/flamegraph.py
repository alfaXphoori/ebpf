#!/usr/bin/env python3
"""
Week 18: Minimal Flame Graph renderer (folded stacks -> SVG)

Reads the folded format written by `cpu-profiler -folded FILE`
(one line per unique stack: "frame1;frame2;...;leaf COUNT") and draws a
static SVG flame graph: root at the bottom, width = share of samples.
Frames ending in "_[k]" are kernel frames and get a separate color.

Standard library only, so it runs anywhere Python 3 does. For an interactive
graph (zoom/search) use Brendan Gregg's flamegraph.pl or speedscope.app.

Usage:
    python3 flamegraph.py out.txt --title "busy on-CPU" > cpu.svg
"""

import argparse
import hashlib
import sys
from html import escape

FRAME_H = 16       # height of one stack level (px)
PAD_TOP = 34       # room for title + subtitle
PAD_SIDE = 10
MIN_WIDTH_PX = 0.3 # default: skip frames narrower than this (unreadable anyway)
FONT = 'font-family="Verdana, sans-serif"'


class Node:
    __slots__ = ("name", "count", "children")

    def __init__(self, name):
        self.name = name
        self.count = 0
        self.children = {}


def parse_folded(lines):
    """Build a prefix tree; each node's count = samples whose stack passes through it."""
    root = Node("all")
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        stack, _, count = line.rpartition(" ")
        try:
            n = int(count)
        except ValueError:
            continue  # malformed line
        root.count += n
        node = root
        for frame in stack.split(";"):
            child = node.children.get(frame)
            if child is None:
                child = node.children[frame] = Node(frame)
            child.count += n
            node = child
    return root


def depth_of(node):
    return 1 + max((depth_of(c) for c in node.children.values()), default=0)


def color(name):
    """Stable color per frame name: kernel = orange/red, user = yellow/amber."""
    h = int(hashlib.md5(name.encode()).hexdigest()[:4], 16) / 0xFFFF
    if name.endswith("_[k]"):
        return f"rgb({int(205 + 50 * h)},{int(90 + 60 * h)},40)"
    return f"rgb({int(225 + 30 * h)},{int(170 + 60 * h)},{int(40 + 30 * h)})"


def render(root, width, title, min_width=MIN_WIDTH_PX):
    levels = depth_of(root)
    height = PAD_TOP + levels * FRAME_H + 24
    scale = (width - 2 * PAD_SIDE) / root.count if root.count else 0
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">',
        f'<rect width="100%" height="100%" fill="#f8f8f8"/>',
        f'<text x="{width / 2}" y="18" text-anchor="middle" font-size="15" {FONT}>{escape(title)}</text>',
        f'<text x="{width / 2}" y="30" text-anchor="middle" font-size="10" fill="#555" {FONT}>'
        f'{root.count} samples · width = share of on-CPU samples · '
        f'orange = kernel frame (_[k]) · yellow = user frame</text>',
    ]

    def draw(node, x, level):
        w = node.count * scale
        if w < min_width:
            return
        y = height - 24 - (level + 1) * FRAME_H
        pct = 100.0 * node.count / root.count
        label = escape(node.name)
        out.append(
            f'<g><title>{label} ({node.count} samples, {pct:.2f}%)</title>'
            f'<rect x="{x:.2f}" y="{y}" width="{w:.2f}" height="{FRAME_H - 1}" '
            f'fill="{"#ccc" if level == 0 else color(node.name)}" rx="2"/>'
        )
        max_chars = int((w - 6) / 6.5)  # ~6.5px per char at 11px
        if max_chars >= 3:
            text = node.name if len(node.name) <= max_chars else node.name[: max_chars - 2] + ".."
            out.append(
                f'<text x="{x + 3:.2f}" y="{y + FRAME_H - 4}" font-size="11" {FONT}>{escape(text)}</text>'
            )
        out.append("</g>")
        # Children sorted by name (flamegraph.pl convention: x order is alphabetical, not time)
        cx = x
        for child in sorted(node.children.values(), key=lambda c: c.name):
            draw(child, cx, level + 1)
            cx += child.count * scale

    draw(root, PAD_SIDE, 0)
    out.append("</svg>")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="Render folded stacks as a static SVG flame graph")
    ap.add_argument("folded", nargs="?", default="-", help="folded stacks file (default: stdin)")
    ap.add_argument("--title", default="Flame Graph", help="title shown at the top")
    ap.add_argument("--width", type=int, default=1200, help="SVG width in px")
    ap.add_argument("--min-width", type=float, default=MIN_WIDTH_PX,
                    help="omit frames narrower than this many px (smaller file)")
    args = ap.parse_args()

    src = sys.stdin if args.folded == "-" else open(args.folded, encoding="utf-8", errors="replace")
    with src:
        root = parse_folded(src)
    if root.count == 0:
        sys.exit("no samples in input")
    sys.stdout.write(render(root, args.width, args.title, args.min_width))


if __name__ == "__main__":
    main()
