# frozen_string_literal: true

require_relative "target"
require_relative "targets"

module Prom
  # A built-in kube-state-metrics: turns the cluster's API objects into the
  # series a Kubernetes Prometheus setup expects (the same names and labels
  # as kubernetes/kube-state-metrics for the covered families), served as an
  # internal scrape target so rules and dashboards can use
  # kube_pod_status_phase, kube_deployment_status_replicas_available and
  # friends without another component.
  class KubeState
    def initialize(client:)
      @client = client
    end

    # The exposition text of the current cluster state.
    def render
      out = +""
      nodes(out)
      namespaces(out)
      pods(out)
      deployments(out)
      statefulsets(out)
      daemonsets(out)
      jobs(out)
      services(out)
      persistent_volume_claims(out)
      out
    end

    # A Prom::Target that scrapes this renderer in-process.
    def target
      Target.new(job: "kube-state", instance: "dashboard", labels: {}, url: "internal://kube-state",
                 fetch: -> { [200, render] })
    end

    private

    def list(resource, api_version: "v1")
      Array(@client.get(resource, api_version: api_version)["items"])
    rescue StandardError
      []
    end

    def esc(value)
      value.to_s.gsub("\\", "\\\\\\\\").gsub('"', '\\"').gsub("\n", "\\n")
    end

    def sample(out, name, labels, value)
      body = labels.map { |k, v| "#{k}=\"#{esc(v)}\"" }.join(",")
      out << "#{name}{#{body}} #{value}\n"
    end

    def header(out, name, type, help)
      out << "# HELP #{name} #{help}\n# TYPE #{name} #{type}\n"
    end

    def quantity(text)
      return nil if text.nil?

      value = text.to_s
      match = /\A([+-]?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)(m|k|Ki|M|Mi|G|Gi|T|Ti|P|Pi|E|Ei)?\z/.match(value)
      return nil unless match

      number = Float(match[1])
      case match[2]
      when "m" then number / 1000
      when "k" then number * 1e3
      when "M" then number * 1e6
      when "G" then number * 1e9
      when "T" then number * 1e12
      when "P" then number * 1e15
      when "E" then number * 1e18
      when "Ki" then number * 1024
      when "Mi" then number * 1024**2
      when "Gi" then number * 1024**3
      when "Ti" then number * 1024**4
      when "Pi" then number * 1024**5
      when "Ei" then number * 1024**6
      else number
      end
    end

    def epoch(text)
      Time.iso8601(text.to_s).to_i
    rescue ArgumentError
      nil
    end

    def nodes(out)
      items = list("nodes")
      header(out, "kube_node_info", "gauge", "Information about a cluster node.")
      header(out, "kube_node_status_condition", "gauge", "The condition of a cluster node.")
      header(out, "kube_node_status_capacity", "gauge", "The capacity for different resources of a node.")
      header(out, "kube_node_status_allocatable", "gauge", "The allocatable for different resources of a node that are available for scheduling.")
      header(out, "kube_node_spec_unschedulable", "gauge", "Whether a node can schedule new pods.")
      header(out, "kube_node_created", "gauge", "Unix creation timestamp")
      items.each do |node|
        name = node.dig("metadata", "name")
        info = node.dig("status", "nodeInfo") || {}
        sample(out, "kube_node_info", {"node" => name, "kernel_version" => info["kernelVersion"], "os_image" => info["osImage"],
                                       "container_runtime_version" => info["containerRuntimeVersion"], "kubelet_version" => info["kubeletVersion"],
                                       "internal_ip" => Array(node.dig("status", "addresses")).find { |a| a["type"] == "InternalIP" }&.dig("address")}, 1)
        Array(node.dig("status", "conditions")).each do |condition|
          %w[true false unknown].each do |status|
            sample(out, "kube_node_status_condition", {"node" => name, "condition" => condition["type"], "status" => status},
                   condition["status"].to_s.downcase == status ? 1 : 0)
          end
        end
        %w[capacity allocatable].each do |kind|
          (node.dig("status", kind) || {}).each do |resource, raw|
            value = quantity(raw)
            next if value.nil?

            unit = case resource
                   when "cpu" then "core"
                   when "memory", "ephemeral-storage" then "byte"
                   else "integer"
                   end
            sample(out, "kube_node_status_#{kind}", {"node" => name, "resource" => resource.tr("-", "_"), "unit" => unit}, value)
          end
        end
        sample(out, "kube_node_spec_unschedulable", {"node" => name}, node.dig("spec", "unschedulable") ? 1 : 0)
        created = epoch(node.dig("metadata", "creationTimestamp"))
        sample(out, "kube_node_created", {"node" => name}, created) if created
      end
    end

    def namespaces(out)
      header(out, "kube_namespace_status_phase", "gauge", "kubernetes namespace status phase.")
      list("namespaces").each do |ns|
        name = ns.dig("metadata", "name")
        phase = ns.dig("status", "phase")
        %w[Active Terminating].each { |p| sample(out, "kube_namespace_status_phase", {"namespace" => name, "phase" => p}, phase == p ? 1 : 0) }
      end
    end

    def pods(out)
      items = list("pods")
      header(out, "kube_pod_info", "gauge", "Information about pod.")
      header(out, "kube_pod_status_phase", "gauge", "The pods current phase.")
      header(out, "kube_pod_status_ready", "gauge", "Describes whether the pod is ready to serve requests.")
      header(out, "kube_pod_container_status_restarts_total", "counter", "The number of container restarts per container.")
      header(out, "kube_pod_container_status_ready", "gauge", "Describes whether the containers readiness check succeeded.")
      header(out, "kube_pod_container_status_running", "gauge", "Describes whether the container is currently in running state.")
      header(out, "kube_pod_container_status_waiting_reason", "gauge", "Describes the reason the container is currently in waiting state.")
      header(out, "kube_pod_container_status_terminated_reason", "gauge", "Describes the reason the container is currently in terminated state.")
      header(out, "kube_pod_container_resource_requests", "gauge", "The number of requested request resource by a container.")
      header(out, "kube_pod_container_resource_limits", "gauge", "The number of requested limit resource by a container.")
      header(out, "kube_pod_start_time", "gauge", "Start time in unix timestamp for a pod.")
      header(out, "kube_pod_owner", "gauge", "Information about the Pod's owner.")
      items.each do |pod|
        meta = pod["metadata"] || {}
        namespace = meta["namespace"]
        name = meta["name"]
        status = pod["status"] || {}
        base = {"namespace" => namespace, "pod" => name, "uid" => meta["uid"]}
        sample(out, "kube_pod_info", base.merge("node" => pod.dig("spec", "nodeName"), "host_ip" => status["hostIP"], "pod_ip" => status["podIP"],
                                                "created_by_kind" => Array(meta["ownerReferences"]).first&.dig("kind"),
                                                "created_by_name" => Array(meta["ownerReferences"]).first&.dig("name"),
                                                "priority_class" => pod.dig("spec", "priorityClassName")), 1)
        Array(meta["ownerReferences"]).each do |owner|
          sample(out, "kube_pod_owner", base.merge("owner_kind" => owner["kind"], "owner_name" => owner["name"],
                                                   "owner_is_controller" => owner["controller"] ? "true" : "false"), 1)
        end
        %w[Pending Running Succeeded Failed Unknown].each do |phase|
          sample(out, "kube_pod_status_phase", base.merge("phase" => phase), status["phase"] == phase ? 1 : 0)
        end
        ready = Array(status["conditions"]).find { |c| c["type"] == "Ready" }
        %w[true false unknown].each do |value|
          sample(out, "kube_pod_status_ready", base.merge("condition" => value), ready && ready["status"].to_s.downcase == value ? 1 : 0)
        end
        start = epoch(status["startTime"])
        sample(out, "kube_pod_start_time", base, start) if start
        containers = Array(status["containerStatuses"]) + Array(status["initContainerStatuses"])
        containers.each do |cs|
          labels = base.merge("container" => cs["name"])
          sample(out, "kube_pod_container_status_restarts_total", labels, cs["restartCount"].to_i)
          sample(out, "kube_pod_container_status_ready", labels, cs["ready"] ? 1 : 0)
          sample(out, "kube_pod_container_status_running", labels, cs.dig("state", "running") ? 1 : 0)
          waiting = cs.dig("state", "waiting", "reason")
          sample(out, "kube_pod_container_status_waiting_reason", labels.merge("reason" => waiting), 1) if waiting
          terminated = cs.dig("state", "terminated", "reason")
          sample(out, "kube_pod_container_status_terminated_reason", labels.merge("reason" => terminated), 1) if terminated
        end
        (Array(pod.dig("spec", "containers")) + Array(pod.dig("spec", "initContainers"))).each do |container|
          %w[requests limits].each do |kind|
            (container.dig("resources", kind) || {}).each do |resource, raw|
              value = quantity(raw)
              next if value.nil?

              unit = resource == "cpu" ? "core" : (resource.include?("memory") || resource.include?("storage") ? "byte" : "integer")
              sample(out, "kube_pod_container_resource_#{kind}", base.merge("container" => container["name"], "node" => pod.dig("spec", "nodeName"),
                                                                            "resource" => resource.tr("-", "_"), "unit" => unit), value)
            end
          end
        end
      end
    end

    def workload(out, kind, items, prefix)
      header(out, "#{prefix}_spec_replicas", "gauge", "Number of desired pods for a #{kind}.")
      header(out, "#{prefix}_status_replicas", "gauge", "The number of replicas per #{kind}.")
      header(out, "#{prefix}_status_replicas_available", "gauge", "The number of available replicas per #{kind}.")
      header(out, "#{prefix}_status_replicas_ready", "gauge", "The number of ready replicas per #{kind}.")
      header(out, "#{prefix}_status_replicas_updated", "gauge", "The number of updated replicas per #{kind}.")
      header(out, "#{prefix}_metadata_generation", "gauge", "Sequence number representing a specific generation of the desired state.")
      header(out, "#{prefix}_status_observed_generation", "gauge", "The generation observed by the #{kind} controller.")
      items.each do |item|
        labels = {"namespace" => item.dig("metadata", "namespace"), kind.downcase => item.dig("metadata", "name")}
        status = item["status"] || {}
        sample(out, "#{prefix}_spec_replicas", labels, item.dig("spec", "replicas").to_i)
        sample(out, "#{prefix}_status_replicas", labels, status["replicas"].to_i)
        sample(out, "#{prefix}_status_replicas_available", labels, status["availableReplicas"].to_i)
        sample(out, "#{prefix}_status_replicas_ready", labels, status["readyReplicas"].to_i)
        sample(out, "#{prefix}_status_replicas_updated", labels, status["updatedReplicas"].to_i)
        sample(out, "#{prefix}_metadata_generation", labels, item.dig("metadata", "generation").to_i)
        sample(out, "#{prefix}_status_observed_generation", labels, status["observedGeneration"].to_i)
      end
    end

    def deployments(out)
      items = list("deployments", api_version: "apps/v1")
      workload(out, "Deployment", items, "kube_deployment")
      header(out, "kube_deployment_status_condition", "gauge", "The current status conditions of a deployment.")
      items.each do |item|
        labels = {"namespace" => item.dig("metadata", "namespace"), "deployment" => item.dig("metadata", "name")}
        Array(item.dig("status", "conditions")).each do |condition|
          %w[true false unknown].each do |value|
            sample(out, "kube_deployment_status_condition", labels.merge("condition" => condition["type"], "status" => value),
                   condition["status"].to_s.downcase == value ? 1 : 0)
          end
        end
      end
    end

    def statefulsets(out)
      workload(out, "StatefulSet", list("statefulsets", api_version: "apps/v1"), "kube_statefulset")
    end

    def daemonsets(out)
      items = list("daemonsets", api_version: "apps/v1")
      %w[desired_number_scheduled current_number_scheduled number_ready number_available number_misscheduled updated_number_scheduled].each do |field|
        header(out, "kube_daemonset_status_#{field}", "gauge", "DaemonSet status #{field.tr("_", " ")}.")
      end
      items.each do |item|
        labels = {"namespace" => item.dig("metadata", "namespace"), "daemonset" => item.dig("metadata", "name")}
        status = item["status"] || {}
        {"desired_number_scheduled" => "desiredNumberScheduled", "current_number_scheduled" => "currentNumberScheduled",
         "number_ready" => "numberReady", "number_available" => "numberAvailable", "number_misscheduled" => "numberMisscheduled",
         "updated_number_scheduled" => "updatedNumberScheduled"}.each do |metric, key|
          sample(out, "kube_daemonset_status_#{metric}", labels, status[key].to_i)
        end
      end
    end

    def jobs(out)
      items = list("jobs", api_version: "batch/v1")
      header(out, "kube_job_status_succeeded", "gauge", "The number of pods which reached Phase Succeeded.")
      header(out, "kube_job_status_failed", "gauge", "The number of pods which reached Phase Failed.")
      header(out, "kube_job_status_active", "gauge", "The number of actively running pods.")
      header(out, "kube_job_complete", "gauge", "The job has completed its execution.")
      header(out, "kube_job_failed", "gauge", "The job has failed its execution.")
      items.each do |item|
        labels = {"namespace" => item.dig("metadata", "namespace"), "job_name" => item.dig("metadata", "name")}
        status = item["status"] || {}
        sample(out, "kube_job_status_succeeded", labels, status["succeeded"].to_i)
        sample(out, "kube_job_status_failed", labels, status["failed"].to_i)
        sample(out, "kube_job_status_active", labels, status["active"].to_i)
        conditions = Array(status["conditions"])
        %w[Complete Failed].each do |type|
          condition = conditions.find { |c| c["type"] == type }
          next unless condition

          %w[true false unknown].each do |value|
            sample(out, "kube_job_#{type.downcase}", labels.merge("condition" => value), condition["status"].to_s.downcase == value ? 1 : 0)
          end
        end
      end
    end

    def services(out)
      header(out, "kube_service_info", "gauge", "Information about service.")
      list("services").each do |item|
        sample(out, "kube_service_info", {"namespace" => item.dig("metadata", "namespace"), "service" => item.dig("metadata", "name"),
                                          "cluster_ip" => item.dig("spec", "clusterIP"), "type" => item.dig("spec", "type")}, 1)
      end
    end

    def persistent_volume_claims(out)
      header(out, "kube_persistentvolumeclaim_status_phase", "gauge", "The phase the persistent volume claim is currently in.")
      header(out, "kube_persistentvolumeclaim_resource_requests_storage_bytes", "gauge", "The capacity of storage requested by the persistent volume claim.")
      list("persistentvolumeclaims").each do |item|
        labels = {"namespace" => item.dig("metadata", "namespace"), "persistentvolumeclaim" => item.dig("metadata", "name")}
        phase = item.dig("status", "phase")
        %w[Lost Bound Pending].each { |p| sample(out, "kube_persistentvolumeclaim_status_phase", labels.merge("phase" => p), phase == p ? 1 : 0) }
        storage = quantity(item.dig("spec", "resources", "requests", "storage"))
        sample(out, "kube_persistentvolumeclaim_resource_requests_storage_bytes", labels, storage) if storage
      end
    end
  end
end
