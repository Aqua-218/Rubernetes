# frozen_string_literal: true

module ApplicationHelper
  def pod_status(pod)
    status = pod["status"] || {}
    return "Terminating" if pod.dig("metadata", "deletionTimestamp")

    statuses = Array(status["initContainerStatuses"]) + Array(status["containerStatuses"])
    waiting = statuses.find { |c| c.dig("state", "waiting", "reason") }
    return waiting.dig("state", "waiting", "reason") if waiting

    terminated = Array(status["containerStatuses"]).find do |c|
      c.dig("state", "terminated", "reason") && c.dig("state", "terminated", "reason") != "Completed"
    end
    return terminated.dig("state", "terminated", "reason") if terminated && status["phase"] != "Succeeded"

    inits = Array(status["initContainerStatuses"])
    unfinished = inits.count { |c| !c.dig("state", "terminated") }
    return "Init:#{inits.length - unfinished}/#{inits.length}" if unfinished.positive?

    status["phase"].to_s
  end

  def pod_ready(pod)
    statuses = Array(pod.dig("status", "containerStatuses"))
    "#{statuses.count { |c| c["ready"] }}/#{Array(pod.dig("spec", "containers")).length}"
  end

  def pod_restarts(pod)
    Array(pod.dig("status", "containerStatuses")).sum { |c| c["restartCount"].to_i }
  end

  def badge(text, tone = nil)
    tone ||= case text.to_s
             when "Running", "Ready", "Active", "Bound", "up", "firing", "True", "Succeeded", "ok", "Complete" then "ok"
             when "Pending", "pending", "ContainerCreating", "PodInitializing", "Terminating", "Init:0/1" then "warn"
             when "", "unknown", "inactive" then "muted"
             else text.to_s.start_with?("Init:") ? "warn" : "bad"
             end
    tone = "bad" if text.to_s == "firing"
    content_tag(:span, text, class: "badge badge-#{tone}")
  end

  def human_bytes(value)
    return "" if value.nil?

    units = %w[B KiB MiB GiB TiB]
    v = value.to_f
    unit = units.first
    units.each do |u|
      unit = u
      break if v < 1024

      v /= 1024
    end
    v >= 100 ? "#{v.round} #{unit}" : "#{v.round(1)} #{unit}"
  end

  def human_cores(value)
    return "" if value.nil?

    value < 1 ? "#{(value * 1000).round}m" : value.round(2).to_s
  end

  def human_number(value)
    return "" if value.nil?
    return value.to_s if value.is_a?(String)
    return "NaN" if value.respond_to?(:nan?) && value.nan?

    value == value.to_i ? value.to_i.to_s : value.round(3).to_s
  end

  def format_labels(labels)
    (labels || {}).map { |k, v| "#{k}=#{v}" }.join(", ")
  end

  def time_ago(timestamp)
    timestamp.blank? ? "" : age(timestamp)
  end

  def nav_link(name, path, active: nil)
    is_active = active.nil? ? request.path == path || (path != "/" && request.path.start_with?(path)) : active
    link_to name, path, class: ("active" if is_active)
  end

  def resource_index_path(kind, namespace = nil)
    namespace ? "/namespaces/#{namespace}/#{kind}" : "/#{kind}"
  end

  def resource_show_path(kind, name, namespace = nil)
    namespace ? "/namespaces/#{namespace}/#{kind}/#{name}" : "/#{kind}/#{name}"
  end
end
