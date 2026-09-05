#!/bin/bash
# One-command Garmin sync: pull latest data, commit, and push to GitHub.
#
# Usage:
#   ./sync.sh            # pull last 7 days and push
#   ./sync.sh 14         # pull last 14 days and push
#   ./sync.sh --no-push  # pull and commit locally, skip the push

set -euo pipefail
cd "$(dirname "$0")"

# launchd runs this with a minimal PATH — make sure common tool locations are covered.
export PATH="/usr/local/bin:/opt/homebrew/bin:/opt/anaconda3/bin:$PATH"

echo "=== sync.sh run: $(date '+%Y-%m-%d %H:%M:%S') ==="

DAYS=7
PUSH=1
for arg in "$@"; do
  case "$arg" in
    --no-push) PUSH=0 ;;
    *) DAYS="$arg" ;;
  esac
done

# Find a python3 that actually has garminconnect installed — plain `python3`
# on this machine doesn't always resolve to the right environment.
PYTHON=python3
if ! "$PYTHON" -c "import garminconnect" >/dev/null 2>&1; then
  for candidate in /opt/anaconda3/bin/python3 /opt/homebrew/bin/python3 /usr/local/bin/python3; do
    if [ -x "$candidate" ] && "$candidate" -c "import garminconnect" >/dev/null 2>&1; then
      PYTHON="$candidate"
      break
    fi
  done
fi
if ! "$PYTHON" -c "import garminconnect" >/dev/null 2>&1; then
  echo "No Python environment with garminconnect found. Run: pip install garminconnect garth" >&2
  exit 1
fi

"$PYTHON" sync_garmin.py --days "$DAYS"

git add garmin.json garmin_activities.json garmin/
if git diff --cached --quiet; then
  echo "No new data — nothing to commit."
  exit 0
fi

git commit -m "sync latest garmin data" --quiet
echo "Committed: $(git log -1 --format=%H)"

if [ "$PUSH" -eq 1 ]; then
  git push
  echo "Pushed to GitHub."
else
  echo "Skipped push (--no-push)."
fi
