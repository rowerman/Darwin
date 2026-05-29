#!/bin/bash
set -euo pipefail
kind delete cluster --name cve-k8s-12-hostpath
rm -rf /home/kianabin/cve-flags/k8s-12
