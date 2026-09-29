# frozen_string_literal: true

class OverviewController < ApplicationController
  def index
    return unless api_available?

    @nodes = list("nodes")
    @namespaces = list("namespaces")
    @pods = list("pods")
    @deployments = list("deployments", api_version: "apps/v1")
    @statefulsets = list("statefulsets", api_version: "apps/v1")
    @daemonsets = list("daemonsets", api_version: "apps/v1")
    @services = list("services")
    @pvcs = list("persistentvolumeclaims")
    @events = list("events").select { |e| e["type"] == "Warning" }
                            .sort_by { |e| e["lastTimestamp"] || e.dig("metadata", "creationTimestamp") || "" }.reverse.first(15)
    @pod_phases = @pods.group_by { |p| p.dig("status", "phase") }.transform_values(&:length)
    @unhealthy_pods = @pods.reject { |p| healthy_pod?(p) }
    @targets = runtime.scraper.statuses.values
    @alerts = runtime.rules.alerts
  end

  private

  def list(resource, api_version: "v1")
    Array(client.get(resource, api_version: api_version)["items"])
  rescue StandardError => e
    @warnings = (@warnings || []) << "#{resource}: #{e.message}"
    []
  end

  def healthy_pod?(pod)
    phase = pod.dig("status", "phase")
    return true if phase == "Succeeded"
    return false unless phase == "Running"

    Array(pod.dig("status", "containerStatuses")).all? { |c| c["ready"] }
  end
end
