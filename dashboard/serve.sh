#!/usr/bin/env bash
# Serve the live dashboard. Open http://localhost:<port>/ while a run is going.
set -euo pipefail
cd "$(dirname "$0")"
PORT="${1:-8800}"
echo "dashboard: http://localhost:$PORT/"
exec python3 -m http.server "$PORT"
