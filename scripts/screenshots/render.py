#!/usr/bin/env python3
"""Render real terminal transcripts (.ansi) into PNG terminal screenshots.

Input : scripts/screenshots/raw/<weekNN>-<name>.ansi (+ .title) written by lib.sh
Output: <lab dir>/screenshots/<weekNN>-<name>.png

The transcript text is never edited, only laid out: ANSI SGR colors are turned
into HTML spans and a headless Chromium (the minlag/mermaid-cli docker image the
diagrams already use) takes the screenshot.

Usage:
    scripts/screenshots/render.py               # render every transcript
    scripts/screenshots/render.py week07 week08 # only these weeks
"""

import glob
import html
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RAW = os.path.join(ROOT, "scripts", "screenshots", "raw")
IMAGE = "minlag/mermaid-cli:11.4.2"
MAX_LINES = 80          # safety net; lab scripts should trim long output first
MAX_COLS = 140

PALETTE = [  # One Dark-ish, readable on #1e1e2e
    "#45475a", "#f38ba8", "#a6e3a1", "#f9e2af", "#89b4fa", "#f5c2e7", "#94e2d5", "#bac2de",
    "#585b70", "#f38ba8", "#a6e3a1", "#f9e2af", "#89b4fa", "#f5c2e7", "#94e2d5", "#a6adc8",
]

SGR_RE = re.compile(r"\x1b\[([0-9;]*)m")
OTHER_ESC = re.compile(r"\x1b(\[[0-9;?]*[A-Za-ln-z]|\][^\x07\x1b]*(\x07|\x1b\\)|[()][A-Z0-9]|[=>])")


def xterm256(n):
    if n < 16:
        return PALETTE[n]
    if n < 232:
        n -= 16
        lv = [0, 95, 135, 175, 215, 255]
        return "#%02x%02x%02x" % (lv[n // 36], lv[(n // 6) % 6], lv[n % 6])
    g = 8 + (n - 232) * 10
    return "#%02x%02x%02x" % (g, g, g)


class State:
    def __init__(self):
        self.reset()

    def reset(self):
        self.fg = self.bg = None
        self.bold = self.dim = self.italic = self.under = False

    def apply(self, params):
        codes = [int(c) if c else 0 for c in params.split(";")] if params else [0]
        i = 0
        while i < len(codes):
            c = codes[i]
            if c == 0:
                self.reset()
            elif c == 1:
                self.bold = True
            elif c == 2:
                self.dim = True
            elif c == 3:
                self.italic = True
            elif c == 4:
                self.under = True
            elif c == 22:
                self.bold = self.dim = False
            elif c == 23:
                self.italic = False
            elif c == 24:
                self.under = False
            elif 30 <= c <= 37:
                self.fg = PALETTE[c - 30]
            elif 90 <= c <= 97:
                self.fg = PALETTE[c - 90 + 8]
            elif c == 39:
                self.fg = None
            elif 40 <= c <= 47:
                self.bg = PALETTE[c - 40]
            elif 100 <= c <= 107:
                self.bg = PALETTE[c - 100 + 8]
            elif c == 49:
                self.bg = None
            elif c in (38, 48) and i + 1 < len(codes):
                if codes[i + 1] == 5 and i + 2 < len(codes):
                    col = xterm256(codes[i + 2]); i += 2
                elif codes[i + 1] == 2 and i + 4 < len(codes):
                    col = "#%02x%02x%02x" % tuple(codes[i + 2:i + 5]); i += 4
                else:
                    col = None
                if c == 38:
                    self.fg = col
                else:
                    self.bg = col
            i += 1

    def style(self):
        s = []
        if self.fg:
            s.append("color:" + self.fg)
        if self.bg:
            s.append("background:" + self.bg)
        if self.bold:
            s.append("font-weight:700")
        if self.dim:
            s.append("opacity:.6")
        if self.italic:
            s.append("font-style:italic")
        if self.under:
            s.append("text-decoration:underline")
        return ";".join(s)


def clean(text):
    text = text.replace("\r\n", "\n")
    # carriage-return overwrites: keep what is left after the last \r on a line
    lines = []
    for line in text.split("\n"):
        if "\r" in line:
            line = line.rstrip("\r").split("\r")[-1]
        while "\x08" in line:
            line = re.sub(r".?\x08", "", line, count=1)
        lines.append(line)
    text = "\n".join(lines)
    text = OTHER_ESC.sub("", text)
    # pty artifact: `script` echoes a NUL as a literal "^@" when stdin hits EOF
    text = text.replace("^@", "")
    text = re.sub(r"[\x00-\x08\x0b-\x1a\x1c-\x1f\x7f]", "", text)
    return text.rstrip("\n")


def trim(lines):
    if len(lines) <= MAX_LINES:
        return lines
    head, tail = lines[:MAX_LINES - 25], lines[-20:]
    gap = len(lines) - len(head) - len(tail)
    return head + ["\x1b[2m... (ตัด %d บรรทัดเพื่อความกระชับ) ...\x1b[0m" % gap] + tail


def visible_len(line):
    return len(SGR_RE.sub("", line))


def wrap(line):
    """Hard-wrap very long lines while keeping SGR codes intact."""
    if visible_len(line) <= MAX_COLS:
        return [line]
    out, cur, n = [], "", 0
    for tok in re.split(r"(\x1b\[[0-9;]*m)", line):
        if tok.startswith("\x1b["):
            cur += tok
            continue
        for ch in tok:
            if n == MAX_COLS:
                out.append(cur); cur, n = "", 0
            cur += ch; n += 1
    out.append(cur)
    return out


def to_html(text):
    st = State()
    lines = []
    for raw in text.split("\n"):
        lines.extend(wrap(raw))
    lines = trim(lines)
    body = []
    for line in lines:
        # state carries across lines like a real terminal
        parts, pos, buf = [], 0, []
        for m in SGR_RE.finditer(line):
            seg = line[pos:m.start()]
            if seg:
                buf.append((st.style(), seg))
            st.apply(m.group(1))
            pos = m.end()
        if line[pos:]:
            buf.append((st.style(), line[pos:]))
        for sty, seg in buf:
            e = html.escape(seg)
            parts.append('<span style="%s">%s</span>' % (sty, e) if sty else e)
        body.append("".join(parts))
    return "\n".join(body)


PAGE = """<!doctype html><html><head><meta charset="utf-8"><style>
@font-face{font-family:TMono;src:url('file:///fonts/DejaVuSansMono.ttf')}
@font-face{font-family:TMono;font-weight:700;src:url('file:///fonts/DejaVuSansMono-Bold.ttf')}
@font-face{font-family:TThai;src:url('file:///fonts/NotoSansThai-Regular.ttf')}
@font-face{font-family:TThai;font-weight:700;src:url('file:///fonts/NotoSansThai-Bold.ttf')}
@font-face{font-family:TUI;src:url('file:///fonts/NotoSans-Regular.ttf')}
html,body{margin:0;background:transparent}
#win{display:inline-block;margin:24px;border-radius:10px;overflow:hidden;
 background:#1e1e2e;border:1px solid #11111b;min-width:720px}
#bar{height:34px;background:#313244;display:flex;align-items:center;padding:0 14px;position:relative}
.d{width:12px;height:12px;border-radius:50%%;margin-right:8px}
#t{position:absolute;left:0;right:0;text-align:center;color:#cdd6f4;font:600 13px TUI,TThai,sans-serif;pointer-events:none}
pre{margin:0;padding:14px 18px 16px;color:#cdd6f4;font:13.5px/1.45 TMono,TThai,monospace;white-space:pre}
</style></head><body><div id="win"><div id="bar"><span class="d" style="background:#f38ba8"></span>
<span class="d" style="background:#f9e2af"></span><span class="d" style="background:#a6e3a1"></span>
<div id="t">%(title)s</div></div><pre>%(body)s</pre></div></body></html>"""

SHOOT_JS = r"""
const puppeteer = require('/home/mermaidcli/node_modules/puppeteer');
const fs = require('fs');
(async () => {
  const browser = await puppeteer.launch({executablePath: '/usr/bin/chromium-browser',
    args: ['--no-sandbox', '--allow-file-access-from-files']});
  const page = await browser.newPage();
  await page.setViewport({width: 1600, height: 1000, deviceScaleFactor: 1.5});
  for (const f of fs.readdirSync('/work').filter(f => f.endsWith('.html')).sort()) {
    await page.goto('file:///work/' + f, {waitUntil: 'load'});
    await page.evaluate(() => document.fonts.ready);
    const el = await page.$('#win');
    const box = await el.boundingBox();
    await page.screenshot({path: '/work/' + f.replace(/\.html$/, '.png'), omitBackground: true,
      clip: {x: box.x, y: box.y, width: box.width, height: box.height}});
  }
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
"""

FONTS = {
    "DejaVuSansMono.ttf": "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "DejaVuSansMono-Bold.ttf": "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
    "NotoSansThai-Regular.ttf": "/usr/share/fonts/truetype/noto/NotoSansThai-Regular.ttf",
    "NotoSansThai-Bold.ttf": "/usr/share/fonts/truetype/noto/NotoSansThai-Bold.ttf",
    "NotoSans-Regular.ttf": "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
}


def shrink(src, dest):
    """Quantize to a 256-color palette: terminal text has few colors, so this
    cuts the PNG to roughly a third without visible loss."""
    try:
        from PIL import Image
    except ImportError:
        shutil.move(src, dest)
        return
    img = Image.open(src).convert("RGBA")
    img.quantize(colors=256, method=Image.Quantize.FASTOCTREE).save(dest, optimize=True)
    os.remove(src)


def lab_dir_for(week):
    hits = glob.glob(os.path.join(ROOT, "phase*", week + "-*"))
    if len(hits) != 1:
        sys.exit("cannot find lab dir for " + week)
    return hits[0]


def main():
    weeks = set(sys.argv[1:])
    files = sorted(glob.glob(os.path.join(RAW, "week*.ansi")))
    if weeks:
        files = [f for f in files if os.path.basename(f).split("-")[0] in weeks]
    if not files:
        sys.exit("no transcripts found in " + RAW)
    work = tempfile.mkdtemp(prefix="shots-")
    fonts = os.path.join(work, "fonts")
    os.makedirs(fonts)
    for name, src in FONTS.items():
        shutil.copy(src, os.path.join(fonts, name))
    for f in files:
        name = os.path.basename(f)[:-5]
        with open(f, encoding="utf-8", errors="replace") as fh:
            body = to_html(clean(fh.read()))
        tpath = f[:-5] + ".title"
        title = open(tpath, encoding="utf-8").read().strip() if os.path.exists(tpath) else name
        with open(os.path.join(work, name + ".html"), "w", encoding="utf-8") as out:
            out.write(PAGE % {"title": html.escape(title), "body": body})
    with open(os.path.join(work, "shoot.js"), "w") as fh:
        fh.write(SHOOT_JS)
    os.chmod(work, 0o777)
    subprocess.run(["docker", "run", "--rm", "-u", "%d:%d" % (os.getuid(), os.getgid()),
                    "-v", work + ":/work", "-v", fonts + ":/fonts:ro",
                    "--entrypoint", "node", IMAGE, "/work/shoot.js"], check=True)
    for f in files:
        name = os.path.basename(f)[:-5]
        dest_dir = os.path.join(lab_dir_for(name.split("-")[0]), "screenshots")
        os.makedirs(dest_dir, exist_ok=True)
        dest = os.path.join(dest_dir, name + ".png")
        shrink(os.path.join(work, name + ".png"), dest)
        print("  %-60s %5d KB" % (os.path.relpath(dest, ROOT), os.path.getsize(dest) // 1024))
    shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
