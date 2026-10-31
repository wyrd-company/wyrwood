#!/usr/bin/env bash
# ---
# relationships:
#   demonstrates: overview
# ---
#
# Records docs/user/assets/demo.gif and the web interface screenshots from a
# fresh demo site: the web interface half with agent-browser, then the
# command-line half with VHS. Requires agent-browser, vhs, ffmpeg, and
# gifsicle as well as what docs/demo/stack.sh requires.
set -euo pipefail

repository=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
root=${WYRWOOD_DEMO_ROOT:-/tmp/wyrwood-demo}
demo=$repository/docs/demo

case "${1:-}" in
""|--screenshots) ;;
*) echo "usage: $0 [--screenshots]" >&2; exit 2 ;;
esac

cd "$repository"
"$demo/stack.sh" down
trap '"$demo/stack.sh" down' EXIT
"$demo/stack.sh" up
if [ "${1:-}" = --screenshots ]; then
	export WYRWOOD_DEMO_SCREENSHOTS_ONLY=1
fi
"$demo/web.sh"
python3 "$demo/check.py" --record
if [ "${1:-}" = --screenshots ]; then
	exit 0
fi
vhs "$demo/cli.tape"

# One 960-pixel-wide clip at 10 frames per second, the web interface first.
ffmpeg -y -v error -i "$root/web.mp4" -i "$root/cli.mp4" -filter_complex \
	"[0:v]fps=10,scale=960:-2:flags=lanczos,setsar=1[web];[1:v]fps=10,scale=960:-2:flags=lanczos,setsar=1[cli];[web][cli]concat=n=2:v=1:a=0,split[a][b];[a]palettegen=stats_mode=diff[palette];[b][palette]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle" \
	"$root/demo.gif"
gifsicle -O3 --lossy=40 "$root/demo.gif" -o "$repository/docs/user/assets/demo.gif"
