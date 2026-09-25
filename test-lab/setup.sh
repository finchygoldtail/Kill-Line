#!/usr/bin/env bash
# Prepare and start the Kill Line test lab.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# A synthetic corpus for the enumeration demo (harmless text files).
mkdir -p "$HERE/workspace/corpus" "$HERE/workspace/output"
for i in $(seq 1 300); do echo "synthetic document $i" > "$HERE/workspace/corpus/doc-$i.txt"; done
chmod 0644 "$HERE/fake-secrets/api-key.txt"
docker compose -f "$HERE/docker-compose.yml" up -d --build
docker compose -f "$HERE/docker-compose.yml" ps
