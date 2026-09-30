# frozen_string_literal: true

module Dashboard
  # What the cluster browser knows how to list: API group/version, whether
  # the kind is namespaced, and the table columns (name -> lambda over the
  # object).  Anything not here is still reachable as YAML.
  module ResourceCatalog
    Entry = Struct.new(:kind, :resource, :api_version, :columns, :scalable, keyword_init: true)

    AGE = ->(o) { o.dig("metadata", "creationTimestamp") }

    def self.ready_count(object, ready_key, total_key)
      status = object["status"] || {}
      "#{status[ready_key].to_i}/#{status[total_key] || object.dig("spec", "replicas") || 0}"
    end

    NAMESPACED = {
      deployments: Entry.new(kind: "Deployment", resource: "deployments", api_version: "apps/v1", scalable: true, columns: {
                               "Ready" => ->(o) { ready_count(o, "readyReplicas", "replicas") },
                               "Up-to-date" => ->(o) { o.dig("status", "updatedReplicas").to_i },
                               "Available" => ->(o) { o.dig("status", "availableReplicas").to_i },
                               "Images" => lambda { |o|
                                 Array(o.dig("spec", "template", "spec", "containers")).map do |c|
                                   c["image"]
                                 end.join(", ")
                               },
                               "Age" => AGE
                             }),
      statefulsets: Entry.new(kind: "StatefulSet", resource: "statefulsets", api_version: "apps/v1", scalable: true, columns: {
                                "Ready" => ->(o) { ready_count(o, "readyReplicas", "replicas") },
                                "Images" => lambda { |o|
                                  Array(o.dig("spec", "template", "spec", "containers")).map do |c|
                                    c["image"]
                                  end.join(", ")
                                },
                                "Age" => AGE
                              }),
      daemonsets: Entry.new(kind: "DaemonSet", resource: "daemonsets", api_version: "apps/v1", scalable: false, columns: {
                              "Desired" => ->(o) { o.dig("status", "desiredNumberScheduled").to_i },
                              "Ready" => ->(o) { o.dig("status", "numberReady").to_i },
                              "Available" => ->(o) { o.dig("status", "numberAvailable").to_i },
                              "Age" => AGE
                            }),
      replicasets: Entry.new(kind: "ReplicaSet", resource: "replicasets", api_version: "apps/v1", scalable: true, columns: {
                               "Desired" => ->(o) { o.dig("spec", "replicas").to_i },
                               "Current" => ->(o) { o.dig("status", "replicas").to_i },
                               "Ready" => ->(o) { o.dig("status", "readyReplicas").to_i },
                               "Age" => AGE
                             }),
      jobs: Entry.new(kind: "Job", resource: "jobs", api_version: "batch/v1", scalable: false, columns: {
                        "Completions" => ->(o) { "#{o.dig("status", "succeeded").to_i}/#{o.dig("spec", "completions") || 1}" },
                        "Active" => ->(o) { o.dig("status", "active").to_i },
                        "Failed" => ->(o) { o.dig("status", "failed").to_i },
                        "Age" => AGE
                      }),
      cronjobs: Entry.new(kind: "CronJob", resource: "cronjobs", api_version: "batch/v1", scalable: false, columns: {
                            "Schedule" => ->(o) { o.dig("spec", "schedule") },
                            "Suspend" => ->(o) { o.dig("spec", "suspend") ? "true" : "false" },
                            "Last schedule" => ->(o) { o.dig("status", "lastScheduleTime") },
                            "Age" => AGE
                          }),
      services: Entry.new(kind: "Service", resource: "services", api_version: "v1", scalable: false, columns: {
                            "Type" => ->(o) { o.dig("spec", "type") },
                            "Cluster IP" => ->(o) { o.dig("spec", "clusterIP") },
                            "Ports" => lambda { |o|
                              Array(o.dig("spec", "ports")).map do |p|
                                "#{p["port"]}#{":#{p["nodePort"]}" if p["nodePort"]}/#{p["protocol"]}"
                              end.join(", ")
                            },
                            "Age" => AGE
                          }),
      ingresses: Entry.new(kind: "Ingress", resource: "ingresses", api_version: "networking.k8s.io/v1", scalable: false, columns: {
                             "Class" => ->(o) { o.dig("spec", "ingressClassName") },
                             "Hosts" => ->(o) { Array(o.dig("spec", "rules")).map { |r| r["host"] }.compact.join(", ") },
                             "Address" => lambda { |o|
                               Array(o.dig("status", "loadBalancer", "ingress")).map do |i|
                                 i["ip"] || i["hostname"]
                               end.join(", ")
                             },
                             "Age" => AGE
                           }),
      endpointslices: Entry.new(kind: "EndpointSlice", resource: "endpointslices", api_version: "discovery.k8s.io/v1", scalable: false, columns: {
                                  "Service" => ->(o) { o.dig("metadata", "labels", "kubernetes.io/service-name") },
                                  "Endpoints" => ->(o) { Array(o["endpoints"]).flat_map { |e| Array(e["addresses"]) }.join(", ") },
                                  "Age" => AGE
                                }),
      configmaps: Entry.new(kind: "ConfigMap", resource: "configmaps", api_version: "v1", scalable: false, columns: {
                              "Data" => ->(o) { (o["data"] || {}).length },
                              "Age" => AGE
                            }),
      secrets: Entry.new(kind: "Secret", resource: "secrets", api_version: "v1", scalable: false, columns: {
                           "Type" => ->(o) { o["type"] },
                           "Data" => ->(o) { (o["data"] || {}).length },
                           "Age" => AGE
                         }),
      persistentvolumeclaims: Entry.new(kind: "PersistentVolumeClaim", resource: "persistentvolumeclaims", api_version: "v1", scalable: false, columns: {
                                          "Status" => ->(o) { o.dig("status", "phase") },
                                          "Volume" => ->(o) { o.dig("spec", "volumeName") },
                                          "Capacity" => ->(o) { o.dig("status", "capacity", "storage") },
                                          "Storage class" => ->(o) { o.dig("spec", "storageClassName") },
                                          "Age" => AGE
                                        }),
      serviceaccounts: Entry.new(kind: "ServiceAccount", resource: "serviceaccounts", api_version: "v1", scalable: false,
                                 columns: {"Age" => AGE}),
      horizontalpodautoscalers: Entry.new(kind: "HorizontalPodAutoscaler", resource: "horizontalpodautoscalers", api_version: "autoscaling/v2",
                                          scalable: false, columns: {
                                            "Reference" => lambda { |o|
                                              "#{o.dig("spec", "scaleTargetRef", "kind")}/#{o.dig("spec", "scaleTargetRef", "name")}"
                                            },
                                            "Min" => ->(o) { o.dig("spec", "minReplicas") },
                                            "Max" => ->(o) { o.dig("spec", "maxReplicas") },
                                            "Replicas" => ->(o) { o.dig("status", "currentReplicas") },
                                            "Age" => AGE
                                          })
    }.freeze

    CLUSTER = {
      nodes: Entry.new(kind: "Node", resource: "nodes", api_version: "v1", scalable: false, columns: {}),
      namespaces: Entry.new(kind: "Namespace", resource: "namespaces", api_version: "v1", scalable: false, columns: {}),
      persistentvolumes: Entry.new(kind: "PersistentVolume", resource: "persistentvolumes", api_version: "v1", scalable: false, columns: {
                                     "Capacity" => ->(o) { o.dig("spec", "capacity", "storage") },
                                     "Access modes" => ->(o) { Array(o.dig("spec", "accessModes")).join(",") },
                                     "Reclaim" => ->(o) { o.dig("spec", "persistentVolumeReclaimPolicy") },
                                     "Status" => ->(o) { o.dig("status", "phase") },
                                     "Claim" => lambda { |o|
                                       c = o.dig("spec", "claimRef")
                                       c ? "#{c["namespace"]}/#{c["name"]}" : ""
                                     },
                                     "Storage class" => ->(o) { o.dig("spec", "storageClassName") },
                                     "Age" => AGE
                                   }),
      storageclasses: Entry.new(kind: "StorageClass", resource: "storageclasses", api_version: "storage.k8s.io/v1", scalable: false, columns: {
                                  "Provisioner" => ->(o) { o["provisioner"] },
                                  "Reclaim" => ->(o) { o["reclaimPolicy"] },
                                  "Binding" => ->(o) { o["volumeBindingMode"] },
                                  "Default" => lambda { |o|
                                    o.dig("metadata", "annotations", "storageclass.kubernetes.io/is-default-class") == "true" ? "yes" : ""
                                  },
                                  "Age" => AGE
                                }),
      ingressclasses: Entry.new(kind: "IngressClass", resource: "ingressclasses", api_version: "networking.k8s.io/v1", scalable: false, columns: {
                                  "Controller" => ->(o) { o.dig("spec", "controller") }, "Age" => AGE
                                }),
      customresourcedefinitions: Entry.new(kind: "CustomResourceDefinition", resource: "customresourcedefinitions",
                                           api_version: "apiextensions.k8s.io/v1", scalable: false, columns: {
                                             "Group" => ->(o) { o.dig("spec", "group") },
                                             "Scope" => ->(o) { o.dig("spec", "scope") },
                                             "Versions" => ->(o) { Array(o.dig("spec", "versions")).map { |v| v["name"] }.join(",") },
                                             "Age" => AGE
                                           }),
      clusterroles: Entry.new(kind: "ClusterRole", resource: "clusterroles", api_version: "rbac.authorization.k8s.io/v1", scalable: false,
                              columns: {"Age" => AGE}),
      priorityclasses: Entry.new(kind: "PriorityClass", resource: "priorityclasses", api_version: "scheduling.k8s.io/v1", scalable: false, columns: {
                                   "Value" => ->(o) { o["value"] }, "Global default" => lambda { |o|
                                                                      o["globalDefault"] ? "true" : "false"
                                                                    }, "Age" => AGE
                                 })
    }.freeze

    def self.find(kind)
      NAMESPACED[kind.to_sym] || CLUSTER[kind.to_sym]
    end
  end
end
