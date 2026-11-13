#!/usr/bin/env python3
"""Verify documentation links, diagram parity (.mmd <-> .svg), and script permissions."""

import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def check_markdown_links():
    errors = []
    md_files = sorted(glob.glob(os.path.join(ROOT, "**", "*.md"), recursive=True))
    md_files = [m for m in md_files if "/vendor/" not in m and "/.git/" not in m]

    for md in md_files:
        base = os.path.dirname(md)
        rel_md = os.path.relpath(md, ROOT)
        with open(md, encoding="utf-8") as f:
            text = f.read()
        # Strip fenced code blocks so example snippets aren't treated as links
        text_nocode = re.sub(r"```.*?```", "", text, flags=re.S)
        for m in re.finditer(r"!?\[[^\]]*\]\(([^)]+)\)", text_nocode):
            target = m.group(1).strip()
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            path_part = target.split("#", 1)[0]
            if not path_part:
                continue
            resolved = os.path.normpath(os.path.join(base, path_part))
            if not os.path.exists(resolved):
                errors.append(f"broken link in {rel_md}: {target}")
    return md_files, errors


def check_diagrams(md_files):
    errors = []
    src_dir = os.path.join(ROOT, "docs", "diagrams", "src")
    svg_dir = os.path.join(ROOT, "docs", "diagrams")

    mmds = {os.path.splitext(os.path.basename(p))[0] for p in glob.glob(os.path.join(src_dir, "*.mmd"))}
    svgs = {os.path.splitext(os.path.basename(p))[0] for p in glob.glob(os.path.join(svg_dir, "*.svg"))}

    missing_svg = sorted(mmds - svgs)
    missing_mmd = sorted(svgs - mmds)
    if missing_svg:
        errors.append(f"diagrams missing rendered SVG: {missing_svg}")
    if missing_mmd:
        errors.append(f"SVGs missing source .mmd: {missing_mmd}")

    all_md_text = "\n".join(open(m, encoding="utf-8").read() for m in md_files)
    unreferenced = [s for s in sorted(svgs) if f"{s}.svg" not in all_md_text]
    if unreferenced:
        errors.append(f"unreferenced SVGs in docs/diagrams/: {unreferenced}")
    return len(svgs), errors


def check_script_permissions():
    errors = []
    scripts = sorted(
        glob.glob(os.path.join(ROOT, "**", "*.sh"), recursive=True)
        + glob.glob(os.path.join(ROOT, "**", "*.py"), recursive=True)
    )
    for path in scripts:
        if "/vendor/" in path or "/.git/" in path:
            continue
        with open(path, encoding="utf-8") as f:
            first_line = f.readline()
        if first_line.startswith("#!") and not os.access(path, os.X_OK):
            errors.append(f"script has shebang but lacks +x permission: {os.path.relpath(path, ROOT)}")
    return errors


def main():
    md_files, link_errors = check_markdown_links()
    svg_count, diag_errors = check_diagrams(md_files)
    perm_errors = check_script_permissions()

    errors = link_errors + diag_errors + perm_errors
    if errors:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        return 1

    print(f"docs-check OK: {len(md_files)} markdown files, {svg_count} diagrams, 0 broken links")
    return 0


if __name__ == "__main__":
    sys.exit(main())
