#!/usr/bin/env bash
#==============================================================================
# tools/gen-manifest.sh
#
# Regenerates the EDGEBOX_FILES array in bootstrap.sh with current SHA256
# hashes of all artifacts. Run this before every release.
#
# Usage (from repo root):
#   bash tools/gen-manifest.sh
#
# The script:
#   1. Computes SHA256 of all files in ENV/install.sh, ENV/lib/*.sh
#      (and future files as they're added)
#   2. Writes the manifest block back into ENV/bootstrap.sh between the
#      markers BEGIN-MANIFEST and END-MANIFEST
#==============================================================================

set -euo pipefail

# Run from repo root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$REPO_ROOT"

ENV_DIR="ENV"
BOOTSTRAP="${ENV_DIR}/bootstrap.sh"

if [[ ! -f "$BOOTSTRAP" ]]; then
    echo "ERROR: ${BOOTSTRAP} not found. Run from the repo root." >&2
    exit 1
fi

# List of files to include in manifest.
# Format: "remote_path|local_path"
FILES=(
    "install.sh|install.sh"
    "lib/common.sh|lib/common.sh"
    "lib/alert.sh|lib/alert.sh"
    "lib/subscription.sh|lib/subscription.sh"
    "scripts/edgeboxctl|scripts/edgeboxctl"
    "scripts/dashboard-backend.sh|scripts/dashboard-backend.sh"
    "scripts/protocol-health-monitor.sh|scripts/protocol-health-monitor.sh"
    "scripts/edgebox-traffic-randomize.sh|scripts/edgebox-traffic-randomize.sh"
    "scripts/edgebox-ipq.sh|scripts/edgebox-ipq.sh"
    "scripts/traffic-alert.sh|scripts/traffic-alert.sh"
    "scripts/traffic-collector.sh|scripts/traffic-collector.sh"
    "scripts/apply-firewall.sh|scripts/apply-firewall.sh"
    "scripts/system-stats.sh|scripts/system-stats.sh"
    "scripts/edgebox-init.sh|scripts/edgebox-init.sh"
)

echo "Computing SHA256 hashes..."
declare -a ENTRIES=()
for entry in "${FILES[@]}"; do
    IFS='|' read -r remote local <<<"$entry"
    local_file="${ENV_DIR}/${local}"
    if [[ ! -f "$local_file" ]]; then
        echo "  SKIP $remote (not present)"
        continue
    fi
    sha=$(sha256sum "$local_file" | awk '{print $1}')
    echo "  ${sha}  ${remote}"
    ENTRIES+=("    \"${remote}|${local}|${sha}\"")
done

# Build new manifest block
MANIFEST_LINES=$(printf '%s\n' "${ENTRIES[@]}")

# Replace EDGEBOX_FILES=(...) in bootstrap.sh
python3 << PYEOF
import re

with open("${BOOTSTRAP}") as f:
    content = f.read()

new_block = """EDGEBOX_FILES=(
${MANIFEST_LINES}
)"""

pattern = re.compile(r'EDGEBOX_FILES=\(.*?\n\)', re.DOTALL)
m = pattern.search(content)
if not m:
    print("ERROR: EDGEBOX_FILES=(...) block not found in bootstrap.sh", flush=True)
    raise SystemExit(1)

content = content[:m.start()] + new_block + content[m.end():]
with open("${BOOTSTRAP}", "w") as f:
    f.write(content)

print("Manifest updated in ${BOOTSTRAP}")
PYEOF

echo ""
echo "Done. Review the changes:"
echo "  git diff ${BOOTSTRAP}"
