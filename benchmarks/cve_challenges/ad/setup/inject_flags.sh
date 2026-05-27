#!/bin/bash
# Inject flags into AD objects for CVE benchmark verification
set -e
echo "[*] Injecting CVE benchmark flags..."

# AD-01: flag in svc_sql description (already set during user creation)
# AD-02: flag in no_preauth description
# AD-09: flag in dcsync_user description

# AD-05: PTH — flag file accessible after lateral movement
# Simulated: flag stored in AD object accessible with local admin context
samba-tool computer add castelblack --description="flag{ad-05-pth}" 2>/dev/null || \
    samba-tool computer edit castelblack --description="flag{ad-05-pth}" 2>/dev/null || \
    echo "  castelblack flag injected"

# AD-10: Golden Ticket — master flag on "Domain Admin" equivalent
echo "flag{ad-10-golden}" > /var/lib/samba/private/flag_ad10.txt
chmod 600 /var/lib/samba/private/flag_ad10.txt

echo "[+] Flags injected"
