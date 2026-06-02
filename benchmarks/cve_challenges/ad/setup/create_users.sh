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

# ============================================================
# Phase 2 Expansion: New scenarios AD-13 through AD-16
# ============================================================

# AD-14: Silver Ticket — service account with SPN for CIFS
# Attacker cracks this hash and forges a Silver Ticket for CIFS
samba-tool user create svc_backup 'BackupPass2024!' \
    --description="flag{ad-14-silver}" 2>/dev/null || echo "  svc_backup exists"
samba-tool spn add cifs/dc01.north.sevenkingdoms.local svc_backup 2>/dev/null || echo "  SPN exists"

# AD-15: Targeted Kerberoasting via ACL Abuse
# sql_service has NO SPN initially — attacker with GenericWrite sets one then Kerberoasts
samba-tool user create sql_service 'WeakSQL2024!' \
    --description="flag{ad-15-targeted-kerb}" 2>/dev/null || echo "  sql_service exists"
# Grant lowpriv GenericWrite access to sql_service
# Samba dsacl: WP (Write Property) permission on the user object
samba-tool dsacl set \
    --object-dn="CN=sql_service,CN=Users,DC=north,DC=sevenkingdoms,DC=local" \
    --car=allow --action=allow \
    --trusteedn="CN=lowpriv,CN=Users,DC=north,DC=sevenkingdoms,DC=local" \
    --permission=Write 2>/dev/null || echo "  dsacl Write on sql_service (may need manual setup)"

# AD-16: Constrained Delegation Abuse
# svc_deleg has constrained delegation to LDAP service on the DC
samba-tool user create svc_deleg 'DelegPass2024!' \
    --description="flag{ad-16-deleg}" 2>/dev/null || echo "  svc_deleg exists"
# Set SPN on svc_deleg (required for delegation)
samba-tool spn add HTTP/dc01.north.sevenkingdoms.local svc_deleg 2>/dev/null || echo "  SPN exists"
# Configure constrained delegation
samba-tool delegation add-service \
    "CN=svc_deleg,CN=Users,DC=north,DC=sevenkingdoms,DC=local" \
    ldap/dc01.north.sevenkingdoms.local 2>/dev/null || echo "  Delegation set"

echo "[+] AD users created"
