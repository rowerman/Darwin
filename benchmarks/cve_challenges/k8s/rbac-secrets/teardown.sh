#!/bin/bash
set -euo pipefail
kind delete cluster --name cve-k8s-06-rbac 2>&1
