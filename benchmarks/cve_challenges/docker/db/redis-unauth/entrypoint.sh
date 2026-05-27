#!/bin/bash
# Set flag from CVE_FLAG env var (defaults to static value if not set)
echo "${CVE_FLAG:-flag{db-05-default}}" > /flag.txt
chmod 644 /flag.txt
exec "$@"
