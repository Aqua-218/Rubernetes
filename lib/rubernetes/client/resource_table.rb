# frozen_string_literal: true

require "time"

module Rubernetes
  module Client
    # The columns `kubectl get` prints for a list, for `-o table` and `-o wide`.
    # Pods get kubectl's NAME READY STATUS RESTARTS AGE (and IP NODE when
    # wide); every other kind gets NAME and AGE.
    class ResourceTable
      def initialize(wide: false, now: Time.now.utc)
        @wide = wide
        @now = now
      end

      def render(value)
        resources = items(value)
        return "No resources found." if resources.empty?

        kinds = resources.map { |resource| resource["kind"] }.uniq
        header, row = case kinds
                      when ["Pod"] then [pod_header, method(:pod_row)]
                      when ["Node"] then [@wide ? NODE_WIDE : NODE, method(:node_row)]
                      else [%w[NAME AGE], method(:generic_row)]
                      end
        rows = resources.map { |resource| row.call(resource) }
        rows = rows.map { |row| row.first(header.length) }
        widths = header.each_index.map { |index| ([header] + rows).map { |row| row[index].to_s.length }.max }
        ([header] + rows).map { |row| row.each_with_index.map { |cell, index| cell.to_s.ljust(widths[index]) }.join("   ").rstrip }.join("\n")
      end

      private

      def items(value)
        list = value.is_a?(Hash) && value["items"].is_a?(Array) ? value["items"] : Array(value.is_a?(Hash) ? [value] : value)
        list.select { |resource| resource.is_a?(Hash) }.map do |resource|
          resource["kind"] ? resource : resource.merge("kind" => list_kind(value))
        end
      end

      def list_kind(value)
        value.is_a?(Hash) ? value["kind"].to_s.delete_suffix("List") : ""
      end

      NODE = %w[NAME STATUS ROLES AGE VERSION].freeze
      NODE_WIDE = %w[NAME STATUS ROLES AGE VERSION INTERNAL-IP OS-IMAGE KERNEL-VERSION].freeze

      def node_row(node)
        conditions = Array(node.dig("status", "conditions"))
        ready = conditions.find { |condition| condition["type"] == "Ready" }
        status = ready && ready["status"] == "True" ? "Ready" : "NotReady"
        status += ",SchedulingDisabled" if node.dig("spec", "unschedulable")
        roles = (node.dig("metadata", "labels") || {}).keys.filter_map { |key| key.delete_prefix("node-role.kubernetes.io/") if key.start_with?("node-role.kubernetes.io/") }
        info = node.dig("status", "nodeInfo") || {}
        address = Array(node.dig("status", "addresses")).find { |entry| entry["type"] == "InternalIP" }
        [node.dig("metadata", "name"), status, roles.empty? ? "<none>" : roles.sort.join(","), age(node), info["kubeletVersion"],
         address ? address["address"] : "<none>", info["osImage"], info["kernelVersion"]]
      end

      def pod_header = @wide ? %w[NAME READY STATUS RESTARTS AGE IP NODE] : %w[NAME READY STATUS RESTARTS AGE]

      def generic_row(resource) = [resource.dig("metadata", "name"), age(resource)]

      def pod_row(pod)
        spec = pod["spec"] || {}
        status = pod["status"] || {}
        statuses = Array(status["containerStatuses"])
        total = Array(spec["containers"]).length
        ready = statuses.count { |entry| entry["ready"] }
        restarts = statuses.sum { |entry| entry["restartCount"].to_i }
        [pod.dig("metadata", "name"), "#{ready}/#{total}", pod_status(pod), restarts.to_s, age(pod),
         status["podIP"] || "<none>", spec["nodeName"] || "<none>"]
      end

      # kubectl's printPod, in the order it decides: a reason on the Pod, an
      # unfinished init container, a waiting or terminated container, a Pod
      # being deleted.
      def pod_status(pod)
        status = pod["status"] || {}
        reason = status["reason"] || status["phase"] || "Unknown"
        init_total = Array(pod.dig("spec", "initContainers")).length
        initializing = false
        Array(status["initContainerStatuses"]).each_with_index do |entry, index|
          state = entry["state"] || {}
          next if state.dig("terminated", "exitCode").to_i.zero? && state["terminated"]

          initializing = true
          reason = if state["terminated"]
                     "Init:#{state.dig("terminated", "reason") || "ExitCode:#{state.dig("terminated", "exitCode")}"}"
                   elsif state.dig("waiting", "reason") && state.dig("waiting", "reason") != "PodInitializing"
                     "Init:#{state.dig("waiting", "reason")}"
                   else
                     "Init:#{index}/#{init_total}"
                   end
          break
        end
        unless initializing
          running = false
          Array(status["containerStatuses"]).reverse_each do |entry|
            state = entry["state"] || {}
            if state.dig("waiting", "reason")
              reason = state.dig("waiting", "reason")
            elsif state["terminated"]
              reason = state.dig("terminated", "reason") || "ExitCode:#{state.dig("terminated", "exitCode")}"
            elsif state["running"] && entry["ready"]
              running = true
            end
          end
          reason = "Running" if reason == "Completed" && running
        end
        pod.dig("metadata", "deletionTimestamp") ? "Terminating" : reason
      end

      def age(resource)
        created = resource.dig("metadata", "creationTimestamp")
        return "<unknown>" unless created

        seconds = (@now - Time.iso8601(created.to_s)).to_i
        return "#{[seconds, 0].max}s" if seconds < 120
        return "#{seconds / 60}m" if seconds < 3_600 * 3
        return "#{seconds / 3_600}h" if seconds < 86_400 * 2

        "#{seconds / 86_400}d"
      rescue ArgumentError
        "<unknown>"
      end
    end
  end
end
