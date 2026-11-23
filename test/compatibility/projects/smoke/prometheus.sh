#!/usr/bin/env bash
set -euo pipefail

path="/api/v1/namespaces/${K6_NAMESPACE:?}/services/http:prometheus-server:80/proxy/api/v1/query"
for ((attempt = 0; attempt < 30; attempt++)); do
  if self=$(kubectl get --raw "$path?query=up%7Bjob%3D%22prometheus%22%7D") &&
     ruby -rjson -e '
       response = JSON.parse(STDIN.read)
       samples = Array(response.dig("data", "result"))
       self_scraped = samples.any? do |sample|
         sample.dig("metric", "job") == "prometheus" && sample.dig("value", 1) == "1"
       end
       abort unless response["status"] == "success" && self_scraped
     ' <<< "$self" &&
     exporter=$(kubectl get --raw "$path?query=count%28node_uname_info%29") &&
     ruby -rjson -e '
       response = JSON.parse(STDIN.read)
       samples = Array(response.dig("data", "result"))
       abort unless response["status"] == "success" && samples.any? { |sample| sample.dig("value", 1).to_f.positive? }
     ' <<< "$exporter"; then
    exit 0
  fi
  ruby -e 'sleep 5'
done
echo "Prometheus did not ingest both self-scrape and node-exporter samples" >&2
exit 1
