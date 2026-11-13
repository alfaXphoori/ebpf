#!/usr/bin/env bash
# ==============================================================================
# Render docs/diagrams/src/*.mmd into ByteByteGo-style SVGs in docs/diagrams/
# and render animated SVGs managed by scripts/render_animated_diagrams.py.
#
#   scripts/render_diagrams.sh               # render every diagram
#   scripts/render_diagrams.sh week08-overview content-tree-phase04
#                                            # render only these (names without .mmd)
#
# Needs (for Mermaid diagrams): docker, the minlag/mermaid-cli image below,
# python3, libharfbuzz-subset0, fonts-noto-core and fonts-dejavu-core.
# (Animated SVGs only need python3, libharfbuzz-subset0 and the fonts.)
# ==============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIAG="$ROOT/docs/diagrams"
SRC="$DIAG/src"
IMAGE="${MMDC_IMAGE:-minlag/mermaid-cli:11.4.2}"

mapfile -t anim_all < <(python3 "$ROOT/scripts/render_animated_diagrams.py" --list)
is_anim() {
    local x="$1" a
    for a in "${anim_all[@]}"; do
        [ "$a" = "$x" ] && return 0
    done
    return 1
}

if [ $# -gt 0 ]; then
    req=("$@")
else
    req=()
    for f in "$SRC"/*.mmd; do req+=("$(basename "$f" .mmd)"); done
fi

mmd_names=()
anim_names=()
for n in "${req[@]}"; do
    if is_anim "$n"; then
        anim_names+=("$n")
    else
        [ -f "$SRC/$n.mmd" ] || { echo "no such diagram: $SRC/$n.mmd"; exit 1; }
        mmd_names+=("$n")
    fi
done

if [ ${#mmd_names[@]} -gt 0 ]; then
    WORK="$(mktemp -d)"
    trap 'rm -rf "$WORK"' EXIT
    mkdir -p "$WORK/fonts" "$WORK/out"
    chmod 777 "$WORK/out"

    # The same font files are used to measure text inside the container and
    # to build the subsets embedded in each SVG, so the widths always match.
    for f in /usr/share/fonts/truetype/noto/NotoSans-Regular.ttf \
             /usr/share/fonts/truetype/noto/NotoSans-Bold.ttf \
             /usr/share/fonts/truetype/noto/NotoSansThai-Regular.ttf \
             /usr/share/fonts/truetype/noto/NotoSansThai-Bold.ttf \
             /usr/share/fonts/truetype/dejavu/DejaVuSans.ttf \
             /usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf; do
        [ -f "$f" ] || { echo "missing font: $f (apt install fonts-noto-core fonts-dejavu-core)"; exit 1; }
        cp "$f" "$WORK/fonts/"
    done

    for n in "${mmd_names[@]}"; do
        cp "$SRC/$n.mmd" "$WORK/out/"
    done
    cp "$DIAG/mermaid-config.json" "$WORK/out/config.json"

    # One container run for all diagrams (Chromium start-up dominates the time).
    docker run --rm -u "$(id -u):$(id -g)" \
        -v "$WORK/out:/data" -v "$WORK/fonts:/usr/share/fonts/bbg:ro" \
        --entrypoint sh "$IMAGE" -c '
            set -e
            for f in /data/*.mmd; do
                /home/mermaidcli/node_modules/.bin/mmdc -q -p /puppeteer-config.json \
                    -c /data/config.json -b white -i "$f" -o "${f%.mmd}.raw.svg"
            done'

    for n in "${mmd_names[@]}"; do
        python3 "$ROOT/scripts/diagram_postprocess.py" "$WORK/out/$n.raw.svg" "$DIAG/$n.svg" "$WORK/fonts"
        printf '  %-32s %6s KB\n' "$n.svg" "$(( $(stat -c %s "$DIAG/$n.svg") / 1024 ))"
    done
fi

if [ ${#anim_names[@]} -gt 0 ]; then
    python3 "$ROOT/scripts/render_animated_diagrams.py" "${anim_names[@]}"
fi
