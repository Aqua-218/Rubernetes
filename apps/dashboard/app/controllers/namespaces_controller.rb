# frozen_string_literal: true

class NamespacesController < ApplicationController
  def index
    @namespaces = Array(client.get("namespaces")["items"]).sort_by { |n| n.dig("metadata", "name") }
    pods = Array(client.get("pods", namespace: :all)["items"])
    @pod_counts = pods.group_by { |p| p.dig("metadata", "namespace") }.transform_values(&:length)
  end

  def show
    @namespace = client.get("namespaces", params[:id])
    ns = params[:id]
    @counts = {}
    {"pods" => ["pods", "v1"], "deployments" => ["deployments", "apps/v1"], "statefulsets" => ["statefulsets", "apps/v1"],
     "daemonsets" => ["daemonsets", "apps/v1"], "jobs" => ["jobs", "batch/v1"], "services" => ["services", "v1"],
     "ingresses" => ["ingresses", "networking.k8s.io/v1"], "configmaps" => ["configmaps", "v1"], "secrets" => ["secrets", "v1"],
     "persistentvolumeclaims" => ["persistentvolumeclaims", "v1"]}.each do |key, (resource, version)|
      @counts[key] = Array(client.get(resource, namespace: ns, api_version: version)["items"]).length
    rescue StandardError
      @counts[key] = "?"
    end
    @quotas = Array(client.get("resourcequotas", namespace: ns)["items"]) rescue []
    @events = Array(client.get("events", namespace: ns)["items"]).sort_by { |e| e["lastTimestamp"] || "" }.reverse.first(20)
  end
end
