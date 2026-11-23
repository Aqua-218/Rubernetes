#!/usr/bin/env bash
set -euo pipefail

kubectl create namespace "$K6_NAMESPACE" --dry-run=client -o json | kubectl apply -f -
kubectl -n "$K6_NAMESPACE" apply -f - <<YAML
apiVersion: v1
kind: ConfigMap
metadata:
  name: k6-prometheus
data:
  prometheus.yml: |
    global:
      scrape_interval: 5s
    scrape_configs:
      - job_name: prometheus
        static_configs:
          - targets: [localhost:9090]
            labels:
              namespace: "$K6_NAMESPACE"
              pod: k6-prometheus
---
apiVersion: v1
kind: Pod
metadata:
  name: k6-prometheus
  labels:
    app: k6-prometheus
spec:
  containers:
    - name: prometheus
      image: quay.io/prometheus/prometheus:v3.14.0@sha256:5ce7540c3c00ef4ab0c9d2c995c6a5b9c421f44b4a115d97a2c7af3b1c21cbb0
      args: [--config.file=/etc/k6-prometheus/prometheus.yml, --storage.tsdb.path=/tmp/prometheus]
      ports:
        - containerPort: 9090
      readinessProbe:
        httpGet:
          path: /-/ready
          port: 9090
      volumeMounts:
        - name: config
          mountPath: /etc/k6-prometheus
          readOnly: true
  volumes:
    - name: config
      configMap:
        name: k6-prometheus
---
apiVersion: v1
kind: Service
metadata:
  name: k6-prometheus
spec:
  selector:
    app: k6-prometheus
  ports:
    - port: 9090
      targetPort: 9090
YAML
kubectl -n "$K6_NAMESPACE" wait pod/k6-prometheus --for=condition=Ready --timeout=3m
