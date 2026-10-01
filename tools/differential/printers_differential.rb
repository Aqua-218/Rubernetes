#!/usr/bin/env ruby
# frozen_string_literal: true

# Server-side table printing (lib/rubernetes/api/table_printer.rb) against
# upstream's convertors: random objects of every printed kind, the default
# convertor, CRD additionalPrinterColumns over random JSONPath, and
# APIService go to test/conformance/kubernetes/printers_oracle and to the
# port, and the tables must match cell for cell.
#
#   ruby tools/differential/printers_differential.rb [--seed N] [--cases N]

require "json"
require "optparse"
require_relative "printers_oracle"
require_relative "../../lib/rubernetes/api/table_printer"

module PrintersDifferential
  TP = Rubernetes::API::TablePrinter

  class Generator
    def initialize(random)
      @r = random
    end

    def pick(*values) = values.flatten.sample(random: @r)
    def chance(probability) = @r.rand < probability
    def int(range) = @r.rand(range)
    def maybe(probability = 0.5) = chance(probability) ? yield : nil

    def name = "#{pick(%w[a web db cache api x])}-#{int(0..999)}"

    def time
      "@T#{pick(-3, -30, -119, -125, -600, -601, -3599, -7200, -10_800, -30_000, -86_400, -200_000, -700_000,
                -40_000_000, -100_000_000, -300_000_000, 1, 3) * (chance(0.2) ? int(1..3) : 1)}"
    end

    def micro = "@M#{pick(-5, -130, -4000, -90_000)}"
    def quantity = pick(%w[1 0 100m 1Gi 512Mi 2 1500m 10G 1k 250M 3Ti 0.5])

    def labels(max = 3)
      Array.new(int(0..max)) { ["#{pick(%w[app tier k8s.io/name role x-y])}#{int(0..3)}", pick(%w[web db a b v1 2])] }.to_h
    end

    def selector
      return nil if chance(0.1)

      result = {}
      result["matchLabels"] = labels(2) if chance(0.8)
      if chance(0.4)
        result["matchExpressions"] = Array.new(int(1..2)) do
          operator = pick(%w[In NotIn Exists DoesNotExist])
          expression = {"key" => pick(%w[app tier zone app0]), "operator" => operator}
          expression["values"] = Array.new(int(1..3)) { pick(%w[b a c web]) }.uniq if %w[In NotIn].include?(operator)
          expression
        end
      end
      result
    end

    def metadata(namespaced: true, deleting: false)
      meta = {"name" => name, "creationTimestamp" => chance(0.97) ? time : nil, "resourceVersion" => int(1..9999).to_s}.compact
      meta["namespace"] = "ns" if namespaced
      meta["labels"] = labels if chance(0.4)
      meta["deletionTimestamp"] = time if deleting || chance(0.1)
      meta
    end

    def containers(count = int(0..3))
      Array.new(count) { |index| {"name" => "c#{index}", "image" => pick(%w[nginx busybox:1.36 registry.k8s.io/pause:3.10])} }
    end

    def template(extra = {})
      {"metadata" => {"labels" => labels(2)}, "spec" => {"containers" => containers(int(1..3))}.merge(extra)}
    end

    def condition(type, statuses = %w[True False Unknown])
      {"type" => type, "status" => pick(statuses), "reason" => pick("", "R", "Scheduled", "SchedulingGated"),
       "message" => pick("", "m")}.reject { |_, value| value == "" }
    end

    def container_state
      case int(0..3)
      when 0 then {"running" => {"startedAt" => time}}
      when 1 then {"waiting" => {"reason" => pick("", "CrashLoopBackOff", "PodInitializing", "ContainerCreating")}.reject do |_, v|
        v == ""
      end}
      when 2
        {"terminated" => {"exitCode" => pick(0, 0, 1, 137), "signal" => pick(0, 0, 9), "reason" => pick("", "Completed", "Error", "OOMKilled"),
                          "finishedAt" => time}.reject { |_, v| v == "" }}
      else {}
      end
    end

    def container_status(name)
      status = {"name" => name, "ready" => chance(0.5), "restartCount" => pick(0, 0, 1, 5), "image" => "i", "imageID" => "",
                "state" => container_state}
      status["lastState"] = {"terminated" => {"exitCode" => 1, "finishedAt" => time}} if chance(0.4)
      status["started"] = chance(0.5) if chance(0.7)
      status
    end

    def pod
      init = Array.new(int(0..2)) do |index|
        container = {"name" => "i#{index}", "image" => "busybox"}
        container["restartPolicy"] = "Always" if chance(0.4)
        container
      end
      main = containers(int(1..3))
      phase = pick(%w[Pending Running Succeeded Failed Unknown])
      status = {"phase" => phase}
      status["reason"] = pick("Evicted", "NodeLost", "OutOfcpu") if chance(0.15)
      status["conditions"] = Array.new(int(0..3)) { condition(pick(%w[Ready Initialized PodScheduled ContainersReady gate-a])) }
      status["initContainerStatuses"] = init.map { |container| container_status(container["name"]) } if chance(0.7)
      status["containerStatuses"] = main.map { |container| container_status(container["name"]) } if chance(0.8)
      if chance(0.6)
        status["podIP"] = "10.0.0.#{int(1..250)}"
        status["podIPs"] = [{"ip" => status["podIP"]}]
      end
      status["nominatedNodeName"] = "n2" if chance(0.1)
      spec = {"containers" => main}
      spec["initContainers"] = init unless init.empty?
      spec["nodeName"] = "node-#{int(1..3)}" if chance(0.6)
      spec["readinessGates"] = Array.new(int(1..2)) { {"conditionType" => pick(%w[gate-a gate-b])} } if chance(0.2)
      {"apiVersion" => "v1", "kind" => "Pod", "metadata" => metadata, "spec" => spec, "status" => status}
    end

    def service
      type = pick(%w[ClusterIP NodePort LoadBalancer ExternalName])
      spec = {"type" => type, "ports" => Array.new(int(0..3)) do |index|
        {"name" => "p#{index}", "port" => pick(80, 443, 8080), "protocol" => pick(%w[TCP UDP])}
      end}
      spec["ports"].each { |port| port["nodePort"] = int(30_000..32_000) } if %w[NodePort LoadBalancer].include?(type)
      spec.delete("ports") if spec["ports"].empty?
      if type == "ExternalName"
        spec["externalName"] = "example.com"
      else
        spec["clusterIP"] = chance(0.1) ? "None" : "10.96.0.#{int(1..200)}"
        spec["clusterIPs"] = [spec["clusterIP"]]
      end
      spec["externalIPs"] = Array.new(int(1..2)) { "1.2.3.#{int(1..9)}" } if chance(0.3)
      spec["selector"] = labels(2) if chance(0.7)
      status = {}
      if type == "LoadBalancer" && chance(0.7)
        status["loadBalancer"] = {"ingress" => Array.new(int(0..3)) do
          chance(0.5) ? {"ip" => "34.1.#{int(1..9)}.#{int(1..9)}"} : {"hostname" => "lb-#{int(1..99)}.very-long-hostname.example.com"}
        end}
      end
      {"apiVersion" => "v1", "kind" => "Service", "metadata" => metadata, "spec" => spec, "status" => status}
    end

    def node
      conditions = Array.new(int(0..3)) { condition(pick(%w[Ready MemoryPressure DiskPressure])) }
      labels = {}
      labels["node-role.kubernetes.io/#{pick("control-plane", "worker", "")}"] = "" if chance(0.6)
      labels["kubernetes.io/role"] = pick("master", "") if chance(0.3)
      labels["kubernetes.io/hostname"] = "n"
      info = {"kubeletVersion" => pick("v1.36.2", ""), "osImage" => pick("Ubuntu", ""), "kernelVersion" => pick("6.8.0", ""),
              "containerRuntimeVersion" => pick("rubernetes://1", ""), "architecture" => pick("amd64", ""),
              "machineID" => "", "systemUUID" => "", "bootID" => "", "kubeProxyVersion" => "", "operatingSystem" => "linux"}
      addresses = Array.new(int(0..3)) { {"type" => pick(%w[InternalIP ExternalIP Hostname]), "address" => "10.1.0.#{int(1..9)}"} }
      {"apiVersion" => "v1", "kind" => "Node", "metadata" => metadata(namespaced: false).merge("labels" => labels),
       "spec" => {"unschedulable" => chance(0.2)}, "status" => {"conditions" => conditions, "nodeInfo" => info, "addresses" => addresses}}
    end

    def event
      base = {"apiVersion" => "v1", "kind" => "Event", "metadata" => metadata,
              "involvedObject" => {"kind" => pick("Pod", "Node", ""), "name" => pick("p", ""), "fieldPath" => pick("", "spec.containers{c}")},
              "reason" => pick("Started", "BackOff"), "message" => pick(" pulled image \n", "x"), "type" => pick("Normal", "Warning"),
              "source" => {"component" => pick("", "kubelet"), "host" => pick("", "node-1")}, "count" => pick(0, 1, 7),
              "reportingComponent" => pick("", "rc"), "reportingInstance" => pick("", "ri")}
      base["firstTimestamp"] = time if chance(0.7)
      base["lastTimestamp"] = time if chance(0.6)
      base["eventTime"] = micro if chance(0.4)
      base["series"] = {"count" => int(1..9), "lastObservedTime" => micro} if chance(0.2)
      base
    end

    def job_status
      status = {"succeeded" => int(0..3)}
      status["startTime"] = time if chance(0.7)
      status["completionTime"] = time if chance(0.3)
      status["conditions"] = Array.new(int(0..2)) { condition(pick(%w[Complete Failed Suspended FailureTarget SuccessCriteriaMet])) }
      status
    end

    def hpa_v2
      metrics = Array.new(int(0..4)) do
        case pick(%w[Resource Pods Object External ContainerResource Bogus])
        when "Resource"
          target = if chance(0.5)
                     {"type" => "Utilization",
                      "averageUtilization" => pick(50, 80)}
                   else
                     {"type" => "AverageValue", "averageValue" => quantity}
                   end
          {"type" => "Resource", "resource" => {"name" => pick("cpu", "memory"), "target" => target}}
        when "ContainerResource"
          target = if chance(0.5)
                     {"type" => "Utilization",
                      "averageUtilization" => 60}
                   else
                     {"type" => "AverageValue", "averageValue" => quantity}
                   end
          {"type" => "ContainerResource", "containerResource" => {"name" => "cpu", "container" => "c", "target" => target}}
        when "Pods"
          {"type" => "Pods", "pods" => {"metric" => {"name" => "qps"}, "target" => {"type" => "AverageValue", "averageValue" => quantity}}}
        when "Object"
          target = chance(0.5) ? {"type" => "Value", "value" => quantity} : {"type" => "AverageValue", "averageValue" => quantity}
          {"type" => "Object",
           "object" => {"metric" => {"name" => "rps"}, "describedObject" => {"kind" => "Service", "name" => "s"}, "target" => target}}
        when "External"
          target = chance(0.5) ? {"type" => "Value", "value" => quantity} : {"type" => "AverageValue", "averageValue" => quantity}
          {"type" => "External", "external" => {"metric" => {"name" => "queue"}, "target" => target}}
        else
          {"type" => "Bogus"}
        end
      end
      current = metrics.map do |metric|
        next nil if chance(0.3)

        case metric["type"]
        when "Resource" then {"type" => "Resource",
                              "resource" => {"name" => metric.dig("resource", "name"),
                                             "current" => {"averageValue" => quantity,
                                                           "averageUtilization" => chance(0.6) ? 42 : nil}.compact}}
        when "ContainerResource" then {"type" => "ContainerResource",
                                       "containerResource" => {"name" => "cpu", "container" => "c",
                                                               "current" => {"averageValue" => quantity}}}
        when "Pods" then {"type" => "Pods", "pods" => {"metric" => {"name" => "qps"}, "current" => {"averageValue" => quantity}}}
        when "Object" then {"type" => "Object",
                            "object" => {"metric" => {"name" => "rps"}, "describedObject" => {"kind" => "Service", "name" => "s"},
                                         "current" => {"value" => quantity, "averageValue" => chance(0.5) ? quantity : nil}.compact}}
        when "External" then {"type" => "External",
                              "external" => {"metric" => {"name" => "queue"},
                                             "current" => {"value" => quantity, "averageValue" => chance(0.5) ? quantity : nil}.compact}}
        end
      end
      current = current.take_while { |entry| !entry.nil? }
      spec = {"scaleTargetRef" => {"kind" => "Deployment", "name" => "d", "apiVersion" => "apps/v1"}, "maxReplicas" => int(1..10),
              "metrics" => metrics}
      spec["minReplicas"] = int(1..3) if chance(0.8)
      {"apiVersion" => "autoscaling/v2", "kind" => "HorizontalPodAutoscaler", "metadata" => metadata,
       "spec" => spec, "status" => {"currentReplicas" => int(0..5), "desiredReplicas" => 1, "currentMetrics" => current}}
    end

    def hpa_v1
      spec = {"scaleTargetRef" => {"kind" => "Deployment", "name" => "d"}, "maxReplicas" => int(1..10)}
      spec["minReplicas"] = int(1..3) if chance(0.7)
      spec["targetCPUUtilizationPercentage"] = pick(50, 80) if chance(0.6)
      meta = metadata
      if chance(0.4)
        meta["annotations"] = {"autoscaling.alpha.kubernetes.io/metrics" =>
          JSON.generate([{"type" => "Pods", "pods" => {"metricName" => "qps", "targetAverageValue" => quantity}},
                         {"type" => "External", "external" => {"metricName" => "q", "targetAverageValue" => quantity}}].first(int(1..2)))}
      end
      status = {"currentReplicas" => int(0..3), "desiredReplicas" => 1}
      status["currentCPUUtilizationPercentage"] = 33 if chance(0.5)
      {"apiVersion" => "autoscaling/v1", "kind" => "HorizontalPodAutoscaler", "metadata" => meta, "spec" => spec, "status" => status}
    end

    def workload(kind)
      spec = {"replicas" => int(0..5), "selector" => selector || {}, "template" => template}
      status = {"replicas" => int(0..5), "readyReplicas" => int(0..5), "updatedReplicas" => int(0..5), "availableReplicas" => int(0..5)}
      api = kind == "ReplicationController" ? "v1" : "apps/v1"
      if kind == "ReplicationController"
        spec["selector"] = labels(2)
        spec.delete("template") if chance(0.2)
      end
      {"apiVersion" => api, "kind" => kind, "metadata" => metadata, "spec" => spec, "status" => status}
    end

    def object_for(kind)
      meta = metadata
      cluster = metadata(namespaced: false)
      case kind
      when "Pod" then pod
      when "PodTemplate" then {"apiVersion" => "v1", "kind" => kind, "metadata" => meta, "template" => template}
      when "PodDisruptionBudget"
        spec = {}
        spec["minAvailable"] = pick(1, "50%") if chance(0.6)
        spec["maxUnavailable"] = pick(2, "10%") if chance(0.4)
        {"apiVersion" => "policy/v1", "kind" => kind, "metadata" => meta, "spec" => spec,
         "status" => {"disruptionsAllowed" => int(0..3), "currentHealthy" => 0, "desiredHealthy" => 0, "expectedPods" => 0}}
      when "ReplicationController", "ReplicaSet", "Deployment" then workload(kind)
      when "StatefulSet" then workload(kind).tap { |object| object["spec"]["serviceName"] = "s" }
      when "DaemonSet"
        {"apiVersion" => "apps/v1", "kind" => kind, "metadata" => meta,
         "spec" => {"selector" => selector || {}, "template" => template(chance(0.5) ? {"nodeSelector" => labels(2)} : {})},
         "status" => %w[desiredNumberScheduled currentNumberScheduled numberReady updatedNumberScheduled numberAvailable numberMisscheduled].to_h do |key|
           [key, int(0..4)]
         end}
      when "Job"
        spec = {"template" => template, "selector" => selector}.compact
        spec["completions"] = int(1..5) if chance(0.5)
        spec["parallelism"] = int(0..4) if chance(0.6)
        {"apiVersion" => "batch/v1", "kind" => kind, "metadata" => meta, "spec" => spec, "status" => job_status}
      when "CronJob"
        spec = {"schedule" => "*/5 * * * *", "jobTemplate" => {"spec" => {"template" => template, "selector" => selector}.compact}}
        spec["timeZone"] = "Etc/UTC" if chance(0.3)
        spec["suspend"] = chance(0.5)
        status = {}
        status["lastScheduleTime"] = time if chance(0.5)
        status["active"] = [{"kind" => "Job", "name" => "j"}] * int(0..2)
        {"apiVersion" => "batch/v1", "kind" => kind, "metadata" => meta, "spec" => spec, "status" => status}
      when "Service" then service
      when "Ingress"
        spec = {"rules" => Array.new(int(0..5)) { chance(0.8) ? {"host" => "h#{int(1..9)}.example.com"} : {} }}
        spec["ingressClassName"] = "nginx" if chance(0.5)
        spec["tls"] = [{"hosts" => ["a"]}] if chance(0.4)
        {"apiVersion" => "networking.k8s.io/v1", "kind" => kind, "metadata" => meta, "spec" => spec,
         "status" => {"loadBalancer" => {"ingress" => Array.new(int(0..3)) do
           chance(0.6) ? {"ip" => "34.1.1.#{int(1..9)}"} : {"hostname" => "lb#{int(1..9)}.a-rather-long-name.example"}
         end}}}
      when "IngressClass"
        cluster["annotations"] = {"ingressclass.kubernetes.io/is-default-class" => pick("true", "false")} if chance(0.5)
        spec = {"controller" => "example.com/ingress"}
        spec["parameters"] = {"kind" => "Params", "name" => "p", "apiGroup" => chance(0.5) ? "example.com" : nil}.compact if chance(0.6)
        {"apiVersion" => "networking.k8s.io/v1", "kind" => kind, "metadata" => cluster, "spec" => spec}
      when "Endpoints"
        subsets = Array.new(int(0..3)) do
          subset = {"addresses" => Array.new(int(0..4)) { {"ip" => chance(0.8) ? "10.2.0.#{int(1..9)}" : "fd00::#{int(1..9)}"} }}
          if chance(0.8)
            subset["ports"] = Array.new(int(0..2)) do |index|
              {"name" => "p#{index}", "port" => pick(80, 443), "protocol" => "TCP"}
            end
          end
          subset
        end
        {"apiVersion" => "v1", "kind" => kind, "metadata" => meta, "subsets" => subsets}
      when "Node" then node
      when "Event" then event
      when "Namespace" then {"apiVersion" => "v1", "kind" => kind, "metadata" => cluster,
                             "status" => {"phase" => pick("Active", "Terminating")}}
      when "Secret"
        {"apiVersion" => "v1", "kind" => kind, "metadata" => meta, "type" => pick("Opaque", "kubernetes.io/tls"),
         "data" => Array.new(int(0..3)) { |index| ["k#{index}", "dg=="] }.to_h}
      when "ServiceAccount" then {"apiVersion" => "v1", "kind" => kind, "metadata" => meta}
      when "PersistentVolume"
        cluster["annotations"] = {"volume.beta.kubernetes.io/storage-class" => "beta"} if chance(0.2)
        spec = {"capacity" => chance(0.9) ? {"storage" => quantity} : {}, "accessModes" => Array.new(int(0..3)) do
          pick(%w[ReadWriteOnce ReadOnlyMany ReadWriteMany ReadWriteOncePod])
        end,
                "persistentVolumeReclaimPolicy" => pick("Retain", "Delete"), "hostPath" => {"path" => "/tmp/x"}}
        spec["claimRef"] = {"namespace" => "ns", "name" => "c"} if chance(0.5)
        spec["storageClassName"] = "standard" if chance(0.6)
        spec["volumeAttributesClassName"] = "vac" if chance(0.2)
        spec["volumeMode"] = pick("Filesystem", "Block")
        {"apiVersion" => "v1", "kind" => kind, "metadata" => cluster, "spec" => spec,
         "status" => {"phase" => pick("Available", "Bound", "Released"), "reason" => pick("", "Failed")}.reject { |_, v| v == "" }}
      when "PersistentVolumeClaim"
        meta["annotations"] = {"volume.beta.kubernetes.io/storage-class" => "beta"} if chance(0.2)
        spec = {"accessModes" => ["ReadWriteOnce"], "resources" => {"requests" => {"storage" => quantity}}}
        spec["volumeName"] = "pv-1" if chance(0.6)
        spec["storageClassName"] = pick("standard", "") if chance(0.6)
        spec["volumeAttributesClassName"] = "vac" if chance(0.2)
        spec["volumeMode"] = "Filesystem" if chance(0.8)
        status = {"phase" => pick("Pending", "Bound")}
        status["accessModes"] = Array.new(int(0..2)) { pick(%w[ReadWriteOnce ReadWriteMany]) } if chance(0.7)
        status["capacity"] = {"storage" => quantity} if chance(0.7)
        {"apiVersion" => "v1", "kind" => kind, "metadata" => meta, "spec" => spec, "status" => status}
      when "ComponentStatus"
        {"apiVersion" => "v1", "kind" => kind, "metadata" => cluster,
         "conditions" => Array.new(int(0..2)) do
           {"type" => pick("Healthy", "Other"), "status" => pick("True", "False"), "message" => pick("ok", ""), "error" => pick("", "boom")}
         end}
      when "HorizontalPodAutoscaler" then chance(0.7) ? hpa_v2 : hpa_v1
      when "ConfigMap"
        {"apiVersion" => "v1", "kind" => kind, "metadata" => meta, "data" => labels(3),
         "binaryData" => chance(0.3) ? {"b" => "AA=="} : nil}.compact
      when "NetworkPolicy"
        {"apiVersion" => "networking.k8s.io/v1", "kind" => kind, "metadata" => meta, "spec" => {"podSelector" => selector || {}}}
      when "RoleBinding", "ClusterRoleBinding"
        subjects = Array.new(int(0..4)) do
          subject_kind = pick(%w[User Group ServiceAccount])
          subject = {"kind" => subject_kind, "name" => name}
          subject["namespace"] = "ns" if subject_kind == "ServiceAccount"
          subject["apiGroup"] = "rbac.authorization.k8s.io" unless subject_kind == "ServiceAccount"
          subject
        end
        {"apiVersion" => "rbac.authorization.k8s.io/v1", "kind" => kind, "metadata" => kind == "RoleBinding" ? meta : cluster,
         "roleRef" => {"apiGroup" => "rbac.authorization.k8s.io", "kind" => pick("Role", "ClusterRole"), "name" => "r"}, "subjects" => subjects}
      when "CertificateSigningRequest"
        spec = {"request" => "", "signerName" => "kubernetes.io/kube-apiserver-client", "username" => pick("alice", "")}
        spec["expirationSeconds"] = pick(600, 3600, 86_400 * 3) if chance(0.5)
        status = {"conditions" => Array.new(int(0..2)) { {"type" => pick(%w[Approved Denied Failed]), "status" => "True"} }}
        status["certificate"] = "Y2VydA==" if chance(0.3)
        {"apiVersion" => "certificates.k8s.io/v1", "kind" => kind, "metadata" => cluster, "spec" => spec, "status" => status}
      when "Lease"
        spec = {}
        spec["holderIdentity"] = "h" if chance(0.6)
        {"apiVersion" => "coordination.k8s.io/v1", "kind" => kind, "metadata" => meta, "spec" => spec}
      when "StorageClass"
        if chance(0.5)
          cluster["annotations"] =
            {pick("storageclass.kubernetes.io/is-default-class",
                  "storageclass.beta.kubernetes.io/is-default-class") => pick("true", "false")}
        end
        object = {"apiVersion" => "storage.k8s.io/v1", "kind" => kind, "metadata" => cluster, "provisioner" => "example.com/p"}
        object["reclaimPolicy"] = pick("Retain", "Delete") if chance(0.5)
        object["volumeBindingMode"] = pick("WaitForFirstConsumer", "Immediate") if chance(0.5)
        object["allowVolumeExpansion"] = chance(0.5) if chance(0.5)
        object
      when "VolumeAttributesClass" then {"apiVersion" => "storage.k8s.io/v1", "kind" => kind, "metadata" => cluster, "driverName" => "d",
                                         "parameters" => {"a" => "b"}}
      when "ControllerRevision"
        if chance(0.7)
          meta["ownerReferences"] =
            [{"apiVersion" => pick("apps/v1", "v1", "example.com/v2"), "kind" => pick("StatefulSet", "DaemonSet"), "name" => "o", "uid" => "u",
              "controller" => chance(0.7)}]
        end
        {"apiVersion" => "apps/v1", "kind" => kind, "metadata" => meta, "revision" => int(1..9)}
      when "ResourceQuota"
        names = %w[pods requests.cpu limits.memory limits.cpu services requests.storage].sample(int(0..4), random: @r)
        {"apiVersion" => "v1", "kind" => kind, "metadata" => meta, "spec" => {"hard" => names.to_h { |key| [key, quantity] }},
         "status" => {"hard" => names.to_h { |key| [key, quantity] }, "used" => names.select do
           chance(0.7)
         end.to_h { |key| [key, quantity] }}}
      when "PriorityClass"
        object = {"apiVersion" => "scheduling.k8s.io/v1", "kind" => kind, "metadata" => cluster, "value" => int(-10..1_000_000),
                  "globalDefault" => chance(0.3)}
        object["preemptionPolicy"] = pick("Never", "PreemptLowerPriority") if chance(0.5)
        object
      when "RuntimeClass" then {"apiVersion" => "node.k8s.io/v1", "kind" => kind, "metadata" => cluster, "handler" => "runc"}
      when "VolumeAttachment"
        spec = {"attacher" => "csi.example.com", "nodeName" => "n1", "source" => chance(0.8) ? {"persistentVolumeName" => "pv"} : {}}
        {"apiVersion" => "storage.k8s.io/v1", "kind" => kind, "metadata" => cluster, "spec" => spec,
         "status" => {"attached" => chance(0.5)}}
      when "EndpointSlice"
        ports = Array.new(int(0..5)) do
          if chance(0.3)
            {"name" => "http"}
          else
            (chance(0.2) ? {} : {"port" => pick(80, 443), "name" => "p", "protocol" => "TCP"})
          end
        end
        endpoints = Array.new(int(0..3)) { {"addresses" => Array.new(int(1..3)) { "10.3.0.#{int(1..9)}" }} }
        {"apiVersion" => "discovery.k8s.io/v1", "kind" => kind, "metadata" => meta, "addressType" => pick("IPv4", "IPv6"),
         "ports" => ports, "endpoints" => endpoints}
      when "CSINode"
        {"apiVersion" => "storage.k8s.io/v1", "kind" => kind, "metadata" => cluster, "spec" => {"drivers" => Array.new(int(0..2)) do |index|
          {"name" => "d#{index}", "nodeID" => "n"}
        end}}
      when "CSIDriver"
        spec = {}
        spec["attachRequired"] = chance(0.5) if chance(0.6)
        spec["podInfoOnMount"] = chance(0.5) if chance(0.6)
        spec["storageCapacity"] = chance(0.5) if chance(0.6)
        spec["requiresRepublish"] = chance(0.5) if chance(0.6)
        spec["tokenRequests"] = Array.new(int(0..2)) { {"audience" => pick("a", "b")} } if chance(0.5)
        spec["volumeLifecycleModes"] = Array.new(int(0..2)) { pick("Persistent", "Ephemeral") } if chance(0.6)
        {"apiVersion" => "storage.k8s.io/v1", "kind" => kind, "metadata" => cluster, "spec" => spec}
      when "MutatingWebhookConfiguration", "ValidatingWebhookConfiguration"
        webhooks = Array.new(int(0..3)) { |index| {"name" => "w#{index}.example.com", "clientConfig" => {"url" => "https://x"}, "sideEffects" => "None", "admissionReviewVersions" => ["v1"]} }
        {"apiVersion" => "admissionregistration.k8s.io/v1", "kind" => kind, "metadata" => cluster, "webhooks" => webhooks}
      when "ValidatingAdmissionPolicy", "MutatingAdmissionPolicy"
        field_name = kind.start_with?("Validating") ? "validations" : "mutations"
        entries = Array.new(int(0..3)) do
          if field_name == "validations"
            {"expression" => "true"}
          else
            {"patchType" => "ApplyConfiguration",
             "applyConfiguration" => {"expression" => "Object{}"}}
          end
        end
        spec = {field_name => entries}
        spec["paramKind"] = {"apiVersion" => "v1", "kind" => "ConfigMap"} if chance(0.5)
        {"apiVersion" => "admissionregistration.k8s.io/v1", "kind" => kind, "metadata" => cluster, "spec" => spec}
      when "ValidatingAdmissionPolicyBinding", "MutatingAdmissionPolicyBinding"
        spec = {"policyName" => "p"}
        if chance(0.7)
          ref = {}
          ref["name"] = "n" if chance(0.5)
          ref["namespace"] = "ns" if chance(0.5)
          ref["selector"] = selector || {} if !ref["name"] && chance(0.7)
          spec["paramRef"] = ref
        end
        {"apiVersion" => "admissionregistration.k8s.io/v1", "kind" => kind, "metadata" => cluster, "spec" => spec}
      when "FlowSchema"
        spec = {"priorityLevelConfiguration" => {"name" => "pl"}, "matchingPrecedence" => int(1..9999)}
        spec["distinguisherMethod"] = {"type" => pick("ByUser", "ByNamespace")} if chance(0.5)
        {"apiVersion" => "flowcontrol.apiserver.k8s.io/v1", "kind" => kind, "metadata" => cluster, "spec" => spec,
         "status" => {"conditions" => Array.new(int(0..1)) { {"type" => "Dangling", "status" => pick("True", "False")} }}}
      when "PriorityLevelConfiguration"
        spec = if chance(0.3)
                 {"type" => "Exempt", "exempt" => {}}
               else
                 limit = if chance(0.5)
                           {"type" => "Queue",
                            "queuing" => {"queues" => int(1..64), "handSize" => int(1..8),
                                          "queueLengthLimit" => int(1..50)}}
                         else
                           {"type" => "Reject"}
                         end
                 {"type" => "Limited", "limited" => {"nominalConcurrencyShares" => int(0..100), "limitResponse" => limit}}
               end
        {"apiVersion" => "flowcontrol.apiserver.k8s.io/v1", "kind" => kind, "metadata" => cluster, "spec" => spec}
      when "Scale"
        {"apiVersion" => "autoscaling/v1", "kind" => kind, "metadata" => meta, "spec" => {"replicas" => int(0..5)},
         "status" => {"replicas" => int(0..5), "selector" => "a=b"}}
      when "DeviceClass", "ResourceClaimTemplate"
        spec = kind == "DeviceClass" ? {} : {"spec" => {"devices" => {}}}
        {"apiVersion" => "resource.k8s.io/v1", "kind" => kind, "metadata" => kind == "DeviceClass" ? cluster : meta, "spec" => spec}
      when "ResourceClaim"
        status = {}
        if chance(0.6)
          status["allocation"] = {"devices" => {"results" => []}}
          status["reservedFor"] = [{"resource" => "pods", "name" => "p", "uid" => "u"}] if chance(0.5)
        end
        {"apiVersion" => "resource.k8s.io/v1", "kind" => kind, "metadata" => meta, "spec" => {"devices" => {}}, "status" => status}
      when "ResourceSlice"
        spec = {"driver" => "gpu.example.com", "pool" => {"name" => "pool-#{int(1..3)}", "generation" => 1, "resourceSliceCount" => 1}}
        chance(0.6) ? spec["nodeName"] = "n1" : spec["allNodes"] = true
        {"apiVersion" => "resource.k8s.io/v1", "kind" => kind, "metadata" => cluster, "spec" => spec}
      when "ClusterTrustBundle"
        {"apiVersion" => "certificates.k8s.io/v1beta1", "kind" => kind, "metadata" => cluster,
         "spec" => {"signerName" => pick("", "example.com/signer"), "trustBundle" => "x"}}
      when "PodCertificateRequest"
        spec = {"signerName" => "example.com/s", "podName" => "p", "podUID" => "u", "serviceAccountName" => "sa", "serviceAccountUID" => "u2",
                "nodeName" => "n1", "nodeUID" => "u3", "pkixPublicKey" => "", "proofOfPossession" => ""}
        spec["unverifiedUserAnnotations"] = labels(2) if chance(0.5)
        {"apiVersion" => "certificates.k8s.io/v1beta1", "kind" => kind, "metadata" => meta, "spec" => spec,
         "status" => {"conditions" => Array.new(int(0..2)) do
           {"type" => pick(%w[Issued Denied Failed Other]), "status" => "True", "reason" => "R", "message" => "m", "lastTransitionTime" => time}
         end}}
      when "LeaseCandidate"
        {"apiVersion" => "coordination.k8s.io/v1beta1", "kind" => kind, "metadata" => meta,
         "spec" => {"leaseName" => "l", "binaryVersion" => "1.36.2", "emulationVersion" => pick("", "1.35"), "strategy" => "OldestEmulationVersion"}}
      when "StorageVersion"
        status = {"storageVersions" => Array.new(int(0..5)) do |index|
          {"apiServerID" => "s#{index}", "encodingVersion" => "v1", "decodableVersions" => ["v1"]}
        end}
        status["commonEncodingVersion"] = "v1" if chance(0.5)
        {"apiVersion" => "internal.apiserver.k8s.io/v1alpha1", "kind" => kind, "metadata" => cluster, "spec" => {}, "status" => status}
      when "ResourcePoolStatusRequest"
        object = {"apiVersion" => "resource.k8s.io/v1alpha3", "kind" => kind, "metadata" => cluster,
                  "spec" => {"driver" => "gpu.example.com"}}
        if chance(0.8)
          pools = Array.new(int(0..3)) do
            pool = {"driver" => "gpu.example.com", "poolName" => "p", "generation" => 1}
            %w[totalDevices availableDevices allocatedDevices unavailableDevices].each { |key| pool[key] = int(0..8) if chance(0.8) }
            pool["validationError"] = "bad" if chance(0.2)
            pool
          end
          status = {"pools" => pools, "conditions" => Array.new(int(0..2)) do
            {"type" => pick("Complete", "Failed"), "status" => pick("True", "False"), "reason" => "R", "message" => "", "lastTransitionTime" => time}
          end}
          status["poolCount"] = int(0..5) if chance(0.7)
          object["status"] = status
        end
        object
      when "DeviceTaintRule"
        taint = {"key" => "example.com/t", "value" => pick("", "v"), "effect" => pick("NoSchedule", "NoExecute")}
        taint["timeAdded"] = time if chance(0.6)
        {"apiVersion" => "resource.k8s.io/v1alpha3", "kind" => kind, "metadata" => cluster,
         "spec" => {"deviceSelector" => {"driver" => "d"}, "taint" => taint}}
      when "ServiceCIDR"
        {"apiVersion" => "networking.k8s.io/v1", "kind" => kind, "metadata" => cluster,
         "spec" => {"cidrs" => ["10.96.0.0/16", "fd00::/108"].first(int(1..2))}}
      when "IPAddress"
        spec = {}
        if chance(0.8)
          spec["parentRef"] = {"group" => pick("", "example.com"), "resource" => "services", "namespace" => pick("", "ns"), "name" => "svc"}.reject do |_, v|
            v == "" && chance(0.5)
          end
        end
        {"apiVersion" => "networking.k8s.io/v1", "kind" => kind, "metadata" => cluster, "spec" => spec}
      when "StorageVersionMigration"
        {"apiVersion" => "storagemigration.k8s.io/v1beta1", "kind" => kind, "metadata" => cluster,
         "spec" => {"resource" => {"group" => pick("", "apps"), "resource" => "deployments"}},
         "status" => {"conditions" => Array.new(int(0..3)) do
           {"type" => pick(%w[Running Failed Succeeded Other]), "status" => pick("True", "False"), "reason" => "R", "message" => "",
            "lastTransitionTime" => time}
         end}}
      when "Workload"
        {"apiVersion" => "scheduling.k8s.io/v1alpha2", "kind" => kind, "metadata" => meta,
         "spec" => {"podGroupTemplates" => [{"name" => "g", "schedulingPolicy" => {"basic" => {}}}]}}
      when "PodGroup"
        spec = {"schedulingPolicy" => chance(0.5) ? {"gang" => {"minCount" => 2}} : {"basic" => {}}}
        spec["podGroupTemplateRef"] = {"workload" => {"workloadName" => "w", "podGroupTemplateName" => "g"}} if chance(0.6)
        conditions = Array.new(int(0..2)) do
          {"type" => pick("PodGroupScheduled", "DisruptionTarget"), "status" => pick("True", "False"), "reason" => pick("Preempted", "R"),
           "message" => "", "lastTransitionTime" => time}
        end
        {"apiVersion" => "scheduling.k8s.io/v1alpha2", "kind" => kind, "metadata" => meta, "spec" => spec,
         "status" => {"conditions" => conditions}}
      when "Status"
        {"apiVersion" => "v1", "kind" => "Status", "metadata" => {}, "status" => "Failure", "reason" => "NotFound", "message" => "gone"}
      else
        raise "no generator for #{kind}"
      end
    end
  end

  PRINTER_KINDS = %w[Pod PodTemplate PodDisruptionBudget ReplicationController ReplicaSet DaemonSet Job CronJob Service Ingress
                     IngressClass StatefulSet Endpoints Node Event Namespace Secret ServiceAccount PersistentVolume PersistentVolumeClaim
                     ComponentStatus Deployment HorizontalPodAutoscaler ConfigMap NetworkPolicy RoleBinding ClusterRoleBinding
                     CertificateSigningRequest Lease StorageClass VolumeAttributesClass ControllerRevision ResourceQuota PriorityClass
                     RuntimeClass VolumeAttachment EndpointSlice CSINode CSIDriver MutatingWebhookConfiguration ValidatingWebhookConfiguration
                     ValidatingAdmissionPolicy ValidatingAdmissionPolicyBinding MutatingAdmissionPolicy MutatingAdmissionPolicyBinding
                     FlowSchema PriorityLevelConfiguration Scale DeviceClass ResourceClaim ResourceClaimTemplate ResourceSlice
                     ClusterTrustBundle PodCertificateRequest LeaseCandidate StorageVersion ResourcePoolStatusRequest DeviceTaintRule
                     ServiceCIDR IPAddress StorageVersionMigration Workload PodGroup].freeze

  CRD_PATHS = %w[.spec.replicas .spec.name .status.phase .metadata.creationTimestamp .spec.items[0].name .spec.items[*].name
                 .spec.items[-1] .spec.items[1:3] .spec.map.a .spec .spec.items .spec.flag .spec.ratio .spec.missing .status.when
                 .spec.items[?(@.name=="x")].value .spec.items[?(@.value>2)].name .spec.items[?(@.name)].name ..x
                 .spec.nested.list[0].x .spec.items[5] .spec['name'] .spec.nothing[0] .spec.items[0:0] .spec.big .spec.tiny
                 .spec.html .spec.nullish].freeze

  module_function

  def cases(random, count)
    generator = Generator.new(random)
    result = []
    count.times do |index|
      roll = random.rand
      if roll < 0.72
        kind = PRINTER_KINDS.sample(random: random)
        object = generator.object_for(kind)
        if random.rand < 0.2 && kind != "Scale"
          items = Array.new(random.rand(0..4)) do
            generator.object_for(kind).tap do |item|
              item.delete("apiVersion") && item.delete("kind")
            end
          end
          object = {"apiVersion" => object["apiVersion"], "kind" => "#{kind}List",
                    "metadata" => {"resourceVersion" => "77", "continue" => random.rand < 0.3 ? "tok" : nil}.compact, "items" => items}
        end
        result << {"name" => "printer/#{index}/#{kind}", "convertor" => "printer", "noHeaders" => random.rand < 0.1, "object" => object}
      elsif roll < 0.8
        kind = %w[Role ClusterRole LimitRange CSIStorageCapacity].sample(random: random)
        object = {"apiVersion" => "v1", "kind" => kind, "metadata" => generator.metadata}
        if random.rand < 0.3
          object = {"apiVersion" => "v1", "kind" => "#{kind}List", "metadata" => {"resourceVersion" => "5"},
                    "items" => [object, {"metadata" => generator.metadata}]}
        end
        result << {"name" => "default/#{index}/#{kind}", "convertor" => "default", "noHeaders" => random.rand < 0.1, "object" => object}
      elsif roll < 0.95
        columns = Array.new(random.rand(0..4)) do |column|
          entry = {"name" => "C#{column}", "type" => %w[string integer number boolean date string].sample(random: random),
                   "jsonPath" => CRD_PATHS.sample(random: random)}
          entry["priority"] = random.rand(0..1) if random.rand < 0.3
          entry["format"] = "int32" if random.rand < 0.1
          entry["description"] = "d" if random.rand < 0.3
          entry
        end
        spec = {"replicas" => [3, 3.5, nil].sample(random: random), "name" => "x", "flag" => [true, false].sample(random: random),
                "ratio" => [0.25, 1e21, 1_234_567.0].sample(random: random), "map" => {"a" => 1},
                "items" => Array.new(random.rand(0..3)) { |item| {"name" => %w[x y z][item], "value" => item + random.rand(0..2)} },
                "nested" => {"list" => [{"x" => "y"}]}, "big" => 12_345_678_901, "tiny" => 1.5e-7, "html" => "<a&b>", "nullish" => nil}
        object = {"apiVersion" => "example.com/v1", "kind" => "Widget",
                  "metadata" => generator.metadata, "spec" => spec,
                  "status" => {"phase" => "Ready", "when" => [generator.time, "not-a-time", ""].sample(random: random)}}
        if random.rand < 0.3
          object = {"apiVersion" => "example.com/v1", "kind" => "WidgetList", "metadata" => {"resourceVersion" => "9"},
                    "items" => [object, object.merge("metadata" => generator.metadata)]}
        end
        result << {"name" => "crd/#{index}", "convertor" => "crd", "noHeaders" => random.rand < 0.1, "columns" => columns,
                   "object" => object}
      else
        spec = {"group" => "metrics.k8s.io", "version" => "v1beta1", "groupPriorityMinimum" => 100, "versionPriority" => 100}
        spec["service"] = {"namespace" => "kube-system", "name" => "metrics-server"} if random.rand < 0.6
        conditions = if random.rand < 0.7
                       [{"type" => "Available", "status" => %w[True False Unknown].sample(random: random),
                         "reason" => ["", "FailedDiscoveryCheck"].sample(random: random), "lastTransitionTime" => generator.time}.reject do |_, v|
                         v == ""
                       end]
                     else
                       []
                     end
        object = {"apiVersion" => "apiregistration.k8s.io/v1", "kind" => "APIService", "metadata" => generator.metadata(namespaced: false),
                  "spec" => spec, "status" => {"conditions" => conditions}}
        result << {"name" => "apiservice/#{index}", "convertor" => "apiservice", "noHeaders" => random.rand < 0.1, "object" => object}
      end
    end
    result
  end

  def port_table(test_case, oracle)
    served = oracle.fetch("served")
    now = Rational(oracle.fetch("now"), 1_000_000_000)
    convertor = case test_case["convertor"]
                when "printer" then :printer
                when "default" then :default
                when "apiservice" then :apiservice
                else [:crd, test_case["columns"]]
                end
    TP.table_for(served, include_object: "None", now: Time.at(now).utc, no_headers: test_case["noHeaders"], convertor: convertor)
  rescue TP::PrintError => error
    {"error" => error.message}
  end

  def normalize(table)
    return table if table.key?("error") || table.key?("decodeError") || table.key?("newError")

    {"columnDefinitions" => table["columnDefinitions"],
     "rows" => Array(table["rows"]).map { |row| {"cells" => row["cells"], "conditions" => row["conditions"]}.compact },
     "metadata" => (table["metadata"] || {}).reject { |_, value| value.nil? || value == "" }}
  end

  def run(seed:, count:)
    random = Random.new(seed)
    test_cases = cases(random, count)
    oracle = PrintersOracle.run("cases" => test_cases)
    mismatches = []
    decode_errors = 0
    test_cases.zip(oracle).each do |test_case, expected|
      if expected.key?("decodeError")
        decode_errors += 1
        mismatches << [test_case["name"], expected["decodeError"], nil] if decode_errors <= 3
        next
      end
      want = normalize(expected)
      got = normalize(port_table(test_case, expected))
      next if want == got

      mismatches << [test_case["name"], want, got]
    end
    [test_cases.length, mismatches, decode_errors]
  end
end

if $PROGRAM_NAME == __FILE__
  seed = Random.new_seed % 1_000_000
  count = 400
  OptionParser.new do |parser|
    parser.on("--seed N", Integer) { |value| seed = value }
    parser.on("--cases N", Integer) { |value| count = value }
  end.parse!
  total, mismatches, decode_errors = PrintersDifferential.run(seed: seed, count: count)
  puts "seed=#{seed} cases=#{total} mismatches=#{mismatches.length} decode_errors=#{decode_errors}"
  mismatches.first(8).each do |name, want, got|
    puts "--- #{name}"
    if want.is_a?(Hash) && got.is_a?(Hash) && want["columnDefinitions"] == got["columnDefinitions"] && want["rows"].is_a?(Array) && got["rows"].is_a?(Array)
      want["rows"].zip(got["rows"]).each_with_index do |(expected, actual), index|
        next if expected == actual

        puts "row #{index} oracle: #{JSON.generate(expected)[0, 900]}"
        puts "row #{index} port:   #{JSON.generate(actual)[0, 900]}"
      end
      puts "rows oracle=#{want["rows"].length} port=#{got["rows"].length}" if want["rows"].length != got["rows"].length
      puts "metadata oracle=#{want["metadata"]} port=#{got["metadata"]}" if want["metadata"] != got["metadata"]
    else
      puts "oracle: #{JSON.generate(want)[0, 1500]}"
      puts "port:   #{JSON.generate(got)[0, 1500]}"
    end
  end
  exit(mismatches.empty? ? 0 : 1)
end
