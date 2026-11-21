#!/usr/bin/env python3
"""Insert/refresh the screenshot gallery in each lab README.

The block lives between <!-- screenshots:begin --> and <!-- screenshots:end -->
right after the "## 4." heading (and its Environment quote, if any). Captions
come from raw/<name>.title written by lib.sh.

Usage: scripts/screenshots/embed.py [week07 ...]
"""

import glob
import os
import platform
import re
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RAW = os.path.join(ROOT, "scripts", "screenshots", "raw")
BEGIN, END = "<!-- screenshots:begin -->", "<!-- screenshots:end -->"


def block(lab, week):
    pngs = sorted(glob.glob(os.path.join(lab, "screenshots", week + "-*.png")))
    if not pngs:
        return None
    day = time.strftime("%Y-%m-%d", time.localtime(max(os.path.getmtime(p) for p in pngs)))
    out = [BEGIN, "", "### 📸 ภาพหน้าจอจากการรันจริง (Real Terminal Screenshots)", "",
           "> รันจริงบน `Linux %s` (Ubuntu 26.04) เมื่อ %s ด้วยสคริปต์ "
           "[`scripts/screenshots/%s.sh`](../../scripts/screenshots/%s.sh) "
           "ทุกบรรทัดในภาพมาจากคำสั่งจริง (render เป็นภาพด้วย `scripts/screenshots/render.py`) "
           "ค่าอย่าง PID, เวลา, latency จึงอาจต่างจากข้อความในหัวข้อย่อยด้านล่างเล็กน้อย"
           % (platform.release(), day, week, week), ""]
    note = os.path.join(ROOT, "scripts", "screenshots", week + ".note")
    if os.path.exists(note):  # optional per-week caveat, e.g. a busy-machine benchmark
        out += ["> " + open(note, encoding="utf-8").read().strip(), ""]
    for i, p in enumerate(pngs, 1):
        name = os.path.basename(p)[:-4]
        tfile = os.path.join(RAW, name + ".title")
        title = open(tfile, encoding="utf-8").read().strip() if os.path.exists(tfile) else name
        out += ["![%s](screenshots/%s.png)" % (title.replace("]", ""), name), "",
                "*ภาพที่ %d: %s*" % (i, title), ""]
    out.append(END)
    return "\n".join(out)


def main():
    weeks = sys.argv[1:] or sorted({os.path.basename(p).split("-")[0]
                                    for p in glob.glob(os.path.join(ROOT, "phase*", "week*"))})
    for week in weeks:
        labs = glob.glob(os.path.join(ROOT, "phase*", week + "-*"))
        if len(labs) != 1:
            continue
        lab = labs[0]
        b = block(lab, week)
        if not b:
            continue
        readme = os.path.join(lab, "README.md")
        text = open(readme, encoding="utf-8").read()
        if BEGIN in text:
            text = re.sub(re.escape(BEGIN) + ".*?" + re.escape(END), lambda _: b, text, flags=re.S)
        else:
            m = re.search(r"^## 4\..*\n", text, flags=re.M)
            if not m:
                print("!! no '## 4.' heading in", readme)
                continue
            pos = m.end()
            env = re.match(r"(\s*\n)*(>.*\n)+", text[pos:])  # keep Environment quote first
            if env:
                pos += env.end()
            text = text[:pos] + "\n" + b + "\n\n" + text[pos:].lstrip("\n")
        open(readme, "w", encoding="utf-8").write(text)
        print("embedded", week, "->", os.path.relpath(readme, ROOT))


if __name__ == "__main__":
    main()
