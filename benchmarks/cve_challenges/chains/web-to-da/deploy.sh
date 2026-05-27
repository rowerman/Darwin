#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
echo "[Chain 1] Web to Domain Admin — 6 steps, 3 domains"

# Step 1: WordPress (Docker)
echo "=== Step 1: Deploy WEB-03 WordPress ==="
WEB03_DIR="$ROOT/docker/web/wordpress-simple-file-list"
CVE_FLAG="flag{chain1-step1-wp}" docker compose -f "$WEB03_DIR/docker-compose.yml" up -d --build 2>&1 | tail -2
echo "  [+] WordPress at http://localhost:8080"
echo "  [+] Flag: flag{chain1-step1-wp}"

# Step 2: Linux PrivEsc (Vagrant)
echo "=== Step 2: Deploy LNX-01 nftables Kernel Exploit ==="
if [ -f "$ROOT/docker/linux/nftables-cve-2024-1086/qemu.sh" ]; then
  echo "  [+] QEMU: cd $ROOT/docker/linux/nftables-cve-2024-1086 && bash qemu.sh &"
elif command -v vagrant &>/dev/null; then
  (cd "$ROOT/docker/linux/nftables-cve-2024-1086" && vagrant up) &
  echo "  [+] Vagrant VM starting (192.168.57.101)"
else
  echo "  [!] No VM runtime — use QEMU or Vagrant"
fi

# Step 3-5: AD Scenarios (Docker Samba AD DC)
echo "=== Steps 3-5: AD nodes (Kerberoasting → PTH → DCSync) ==="
AD_COMPOSE="$ROOT/ad/docker-compose.yml"
if ! docker ps --format '{{.Names}}' | grep -q ad-dc01; then
  echo "  [*] Starting Samba AD DC..."
  docker compose -f "$AD_COMPOSE" up -d --build 2>&1 | tail -2
  echo "  [*] Waiting for AD provisioning..."
  sleep 15
fi
echo "  [+] AD DC at 192.168.100.10 (north.sevenkingdoms.local)"
echo "  [+] Attack path:"
echo "     Step 3: impacket-GetUserSPNs north.sevenkingdoms.local/lowpriv:Password123! -dc-ip 192.168.100.10"
echo "     Step 4: Pass-the-Hash → lateral movement"
echo "     Step 5: impacket-secretsdump → DCSync"

echo ""
echo "[Chain 1] Ready. Attack starts from WEB-03 (port 8080)."
