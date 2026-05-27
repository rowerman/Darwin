#!/bin/bash
# Wrapper for nowsci/samba-domain entrypoint — injects CVE benchmark users after AD provisioning
set -e

# Run the original Samba DC entrypoint in background
/sbin/my_init &
PID=$!

# Wait for Samba AD to be provisioned
echo "[CVE-Benchmark] Waiting for Samba AD DC provisioning..."
for i in $(seq 1 60); do
    if samba-tool domain level show >/dev/null 2>&1; then
        echo "[CVE-Benchmark] AD domain ready"
        break
    fi
    sleep 5
done

# Inject CVE benchmark users and flags
if [ -f /setup/create_users.sh ]; then
    echo "[CVE-Benchmark] Creating AD users for scenarios..."
    bash /setup/create_users.sh
fi
if [ -f /setup/inject_flags.sh ]; then
    echo "[CVE-Benchmark] Injecting flags..."
    bash /setup/inject_flags.sh
fi

wait $PID
