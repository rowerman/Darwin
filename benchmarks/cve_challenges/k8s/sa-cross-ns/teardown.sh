#!/bin/bash
set -euo pipefail
kind delete cluster --name cve-k8s-13-sa-cross
