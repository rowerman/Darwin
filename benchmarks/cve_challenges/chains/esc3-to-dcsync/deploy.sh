#!/bin/bash
set -euo pipefail
echo "[Chain 5] AD CS ESC3 to DCSync — 3 steps, AD CS"
echo ""
echo "  Requires GOAD with AD CS role installed."
echo ""
echo "  Step 1: Certipy find vulnerable templates → request cert with SAN → PKINIT → Domain Admin → flag{chain5-step1-esc3}"
echo "  Step 2: impacket-secretsdump → DCSync → flag{chain5-step2-dcsync-final}"
echo ""
echo "[Chain 5] Ready."
