#!/bin/bash
# Create all AD users/service accounts for CVE benchmark scenarios
set -e
echo "[*] Creating AD users for CVE benchmark..."

# AD-01: Kerberoasting — service account with SPN and weak password
samba-tool user create svc_sql 'Summer2024!' --given-name="SQL" --surname="Service" \
    --description="flag{ad-01-kerberoast}" 2>/dev/null || echo "  svc_sql exists"
samba-tool spn add MSSQLSvc/dc01.north.sevenkingdoms.local:1433 svc_sql 2>/dev/null || echo "  SPN exists"

# AD-02: AS-REP Roasting — account without Kerberos pre-authentication
samba-tool user create no_preauth 'WeakPass123!' --description="flag{ad-02-asrep}" 2>/dev/null || echo "  no_preauth exists"
# Samba: UAC_DONT_REQUIRE_PREAUTH = 0x400000
samba-tool user setexpiry no_preauth --noexpiry 2>/dev/null || true

# Low-privilege user for all scenarios
samba-tool user create lowpriv 'Password123!' 2>/dev/null || echo "  lowpriv exists"

# AD-09: DCSync — user with replication privileges
samba-tool user create dcsync_user 'DCSyncUser123!' --description="flag{ad-09-dcsync}" 2>/dev/null || echo "  dcsync_user exists"
# Grant replication privileges (Samba equivalent of Replication-Get-Changes-All)
samba-tool group addmembers "Domain Admins" dcsync_user 2>/dev/null || true

echo "[+] AD users created"
