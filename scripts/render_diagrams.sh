#!/usr/bin/env bash
# ==============================================================================
# Render docs/diagrams/src/*.mmd into ByteByteGo-style SVGs in docs/diagrams/
#
#   scripts/render_diagrams.sh               # render every diagram
#   scripts/render_diagrams.sh week08-overview content-tree-phase04
#                                            # render only these (names without .mmd)
#
# Needs: docker, the minlag/mermaid-cli image below, python3,
#        libharfbuzz-subset0 (font subsetting), fonts-noto-core and fonts-dejavu-core.
# ==============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIAG="$ROOT/docs/diagrams"
SRC="$DIAG/src"
IMAGE="${MMDC_IMAGE:-minlag/mermaid-cli:11.4.2}"

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

if [ $# -gt 0 ]; then
    names=("$@")
else
    names=()
    for f in "$SRC"/*.mmd; do names+=("$(basename "$f" .mmd)"); done
fi

for n in "${names[@]}"; do
    [ -f "$SRC/$n.mmd" ] || { echo "no such diagram: $SRC/$n.mmd"; exit 1; }
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

for n in "${names[@]}"; do
    python3 "$ROOT/scripts/diagram_postprocess.py" "$WORK/out/$n.raw.svg" "$DIAG/$n.svg" "$WORK/fonts"
    printf '  %-32s %6s KB\n' "$n.svg" "$(( $(stat -c %s "$DIAG/$n.svg") / 1024 ))"
done
