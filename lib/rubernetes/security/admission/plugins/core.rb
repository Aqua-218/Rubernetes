# frozen_string_literal: true

require "time"

require_relative "../framework"
require_relative "../registry"
require_relative "../../../node_declared_features"

module Rubernetes
  module Security
    module Admission
      # Built-in admission plugins (plugin/pkg/admission/*, k8s.io/apiserver/pkg/admission/plugin/*).
      # Each class mirrors the upstream plugin's decision; the ordering and
      # the default-on set come from the corpus through Registry.
      module Plugins
        module Helpers
          def metadata(object) = object.is_a?(Hash) ? (object["metadata"] || {}) : {}
          def spec(object) = object.is_a?(Hash) ? (object["spec"] || {}) : {}

          def pod_containers(pod)
            Array(spec(pod)["containers"]) + Array(spec(pod)["initContainers"]) + Array(spec(pod)["ephemeralContainers"])
          end

          def reject!(message, code: 403, reason: "Forbidden", details: nil)
            raise Rejected.new(message, code: code, reason: reason, details: details, plugin: name)
          end

          def invalid!(kind, name, causes)
            details = {"kind" => kind, "name" => name, "causes" => causes}
            raise Rejected.new("#{kind} #{name.inspect} is invalid: #{causes.map do |cause|
              "#{cause["field"]}: #{cause["message"]}"
            end.join(", ")}",
                               code: 422, reason: "Invalid", details: details, plugin: name)
          end

          # schema.GroupResource.String of the request's resource, the subject
          # admission.NewForbidden words a refusal with.
          def group_resource(attributes)
            attributes.group.to_s.empty? ? attributes.resource.to_s : "#{attributes.resource}.#{attributes.group}"
          end

          def resource?(attributes, group, resource)
            attributes.group == group && attributes.resource == resource
          end

          def quantity(value)
            Quantity.parse(value)
          end
        end

        # Minimal resource.Quantity arithmetic (canonical suffixes).
        module Quantity
          # Exact: 1e-3.to_r is not 1/1000, so "500m" parsed to a hair over
          # one half and 500m + 500m exceeded a limit of 1.  resource.Quantity
          # is decimal-exact, and a quota at exactly its limit admits.
          SUFFIXES = {"" => 1r, "n" => Rational(1, 10**9), "u" => Rational(1, 10**6), "m" => Rational(1, 1000),
                      "k" => 10r**3, "M" => 10r**6, "G" => 10r**9, "T" => 10r**12, "P" => 10r**15, "E" => 10r**18,
                      "Ki" => 1024r, "Mi" => 1024r**2, "Gi" => 1024r**3, "Ti" => 1024r**4, "Pi" => 1024r**5, "Ei" => 1024r**6}.freeze

          module_function

          def parse(value)
            return value.to_r if value.is_a?(Numeric)

            match = value.to_s.strip.match(/\A([+-]?[0-9]*\.?[0-9]+)(?:[eE]([+-]?\d+))?([a-zA-Z]*)\z/)
            raise ArgumentError, "invalid quantity #{value.inspect}" unless match

            number = match[1].to_r
            number *= 10**match[2].to_i if match[2]
            suffix = match[3]
            raise ArgumentError, "invalid quantity suffix #{suffix.inspect}" unless SUFFIXES.key?(suffix)

            number * SUFFIXES.fetch(suffix)
          end

          def format(rational)
            return rational.to_i.to_s if rational == rational.to_i

            "#{(rational * 1000).to_i}m"
          end
        end

        class AlwaysAdmit < Plugin
          include Helpers

          def validate(_attributes) = nil
        end
        Registry.register("AlwaysAdmit") { |context, config| AlwaysAdmit.new("AlwaysAdmit", context: context, config: config) }

        class AlwaysDeny < Plugin
          include Helpers

          def validate(_attributes) = reject!("admission plugin AlwaysDeny rejects every request")
        end
        Registry.register("AlwaysDeny") { |context, config| AlwaysDeny.new("AlwaysDeny", context: context, config: config) }

        # NamespaceLifecycle: reject creates in a terminating or missing
        # namespace, protect the immortal namespaces from deletion.
        class NamespaceLifecycle < Plugin
          include Helpers

          IMMORTAL = %w[default kube-system kube-public].freeze

          def validate(attributes)
            if resource?(attributes, "", "namespaces") && attributes.operation == "DELETE" && IMMORTAL.include?(attributes.name)
              reject!("this namespace may not be deleted")
            end
            return if attributes.namespace.empty? || attributes.operation == "DELETE"
            return if resource?(attributes, "", "namespaces")

            namespace = @context.namespace(attributes.namespace)
            if namespace.nil?
              return if attributes.operation == "UPDATE"

              reject!("namespace #{attributes.namespace.inspect} not found", code: 404, reason: "NotFound")
            end
            return unless namespace.dig("status", "phase") == "Terminating" && attributes.operation == "CREATE"

            reject!("unable to create new content in namespace #{attributes.namespace} because it is being terminated",
                    details: {"causes" => [{"reason" => "NamespaceTerminating",
                                            "message" => "namespace #{attributes.namespace} is being terminated"}]})
          end
        end
        Registry.register("NamespaceLifecycle") do |context, config|
          NamespaceLifecycle.new("NamespaceLifecycle", context: context, config: config)
        end

        class NamespaceExists < Plugin
          include Helpers

          def validate(attributes)
            return if attributes.namespace.empty? || resource?(attributes, "", "namespaces")

            return unless @context.namespace(attributes.namespace).nil?

            reject!("namespace #{attributes.namespace.inspect} does not exist", code: 404,
                                                                                reason: "NotFound")
          end
        end
        Registry.register("NamespaceExists") { |context, config| NamespaceExists.new("NamespaceExists", context: context, config: config) }

        class NamespaceAutoProvision < Plugin
          include Helpers

          def admit(attributes)
            return if attributes.namespace.empty? || resource?(attributes, "", "namespaces") || attributes.operation == "DELETE"
            return if @context.namespace(attributes.namespace)

            @context.create_namespace(attributes.namespace) if @context.respond_to?(:create_namespace)
          end
        end
        Registry.register("NamespaceAutoProvision") do |context, config|
          NamespaceAutoProvision.new("NamespaceAutoProvision", context: context, config: config)
        end

        # LimitPodHardAntiAffinityTopology: forbid hard pod anti-affinity with a
        # topology key other than kubernetes.io/hostname.
        class LimitPodHardAntiAffinityTopology < Plugin
          include Helpers

          def validate(attributes)
            return unless resource?(attributes, "", "pods") && attributes.object

            terms = Array(spec(attributes.object).dig("affinity", "podAntiAffinity", "requiredDuringSchedulingIgnoredDuringExecution"))
            terms.each do |term|
              next if term["topologyKey"] == "kubernetes.io/hostname"

              invalid!("Pod", attributes.name,
                       [{"reason" => "FieldValueForbidden", "field" => "spec.affinity.podAntiAffinity.requiredDuringSchedulingIgnoredDuringExecution",
                         "message" => "Forbidden: pod anti-affinity topology key must be kubernetes.io/hostname"}])
            end
          end
        end
        Registry.register("LimitPodHardAntiAffinityTopology") do |context, config|
          LimitPodHardAntiAffinityTopology.new("LimitPodHardAntiAffinityTopology", context: context, config: config)
        end

        # LimitRanger: apply LimitRange defaults and enforce min/max/ratio.
        class LimitRanger < Plugin
          include Helpers

          LIMIT_RANGER_ANNOTATION = "kubernetes.io/limit-ranger"

          # MutateLimit -> mergePodResourceRequirements, once per LimitRange:
          # the range's Container defaults (defaultContainerResourceRequirements,
          # a later item winning) fill each regular and init container's
          # missing limits, then its missing requests, and the Pod records what
          # was set in the kubernetes.io/limit-ranger annotation.  v1
          # SetDefaults_Pod has already run, so a limit the container set is
          # its request; a defaulted limit never becomes the request.
          def admit(attributes)
            return unless resource?(attributes, "", "pods") && attributes.object && attributes.operation == "CREATE"

            ranges = limit_ranges(attributes.namespace)
            return if ranges.empty?

            pod = attributes.object
            %w[containers initContainers].each do |field|
              Array(spec(pod)[field]).each do |container|
                next unless container.is_a?(Hash)

                resources = (container["resources"] ||= {})
                (resources["limits"] || {}).each { |resource, value| (resources["requests"] ||= {})[resource] ||= value }
              end
            end
            ranges.each do |range|
              default_limits = {}
              default_requests = {}
              Array(range.dig("spec", "limits")).each do |item|
                next unless item["type"] == "Container"

                default_requests.merge!(item["defaultRequest"] || {})
                default_limits.merge!(item["default"] || {})
              end
              annotations = []
              {"containers" => "container", "initContainers" => "init container"}.each do |field, label|
                Array(spec(pod)[field]).each do |container|
                  next unless container.is_a?(Hash)

                  resources = (container["resources"] ||= {})
                  limits = (resources["limits"] ||= {})
                  requests = (resources["requests"] ||= {})
                  set_limits = default_limits.keys.reject { |name| limits.key?(name) }.each { |name| limits[name] = default_limits[name] }
                  set_requests = default_requests.keys.reject do |name|
                    requests.key?(name)
                  end.each { |name| requests[name] = default_requests[name] }
                  annotations << "#{set_requests.sort.join(", ")} request for #{label} #{container["name"]}" unless set_requests.empty?
                  annotations << "#{set_limits.sort.join(", ")} limit for #{label} #{container["name"]}" unless set_limits.empty?
                end
              end
              next if annotations.empty?

              metadata = (pod["metadata"] ||= {})
              (metadata["annotations"] ||= {})[LIMIT_RANGER_ANNOTATION] = "LimitRanger plugin set: #{annotations.join("; ")}"
            end
          end

          def validate(attributes)
            return unless attributes.object && %w[CREATE UPDATE].include?(attributes.operation)

            ranges = limit_ranges(attributes.namespace)
            return if ranges.empty?

            ranges.each do |range|
              Array(range.dig("spec", "limits")).each do |item|
                case item["type"]
                when "Container"
                  if resource?(attributes, "", "pods")
                    pod_containers(attributes.object).each do |container|
                      check_limits(attributes, item, container["resources"] || {}, "container #{container["name"]}")
                    end
                  end
                when "Pod"
                  check_limits(attributes, item, pod_totals(attributes.object), "pod") if resource?(attributes, "", "pods")
                when "PersistentVolumeClaim"
                  if resource?(
                    attributes, "", "persistentvolumeclaims"
                  )
                    check_limits(attributes, item, {"requests" => spec(attributes.object).dig("resources", "requests") || {}},
                                 "persistentvolumeclaim")
                  end
                end
              end
            end
          end

          private

          def limit_ranges(namespace)
            return [] if namespace.empty?

            @context.list("limitranges", namespace)
          end

          # limitranger podRequests / podLimits: containers add up, each init
          # container runs next to the sidecars before it, the Pod needs the
          # larger; pod-level cpu/memory (PodLevelResources) override the
          # aggregate.  No overhead.  Sidecars and pod-level resources were
          # ignored, so a Pod LimitRange judged only the regular containers.
          POD_LEVEL_LIMIT_RANGE_RESOURCES = %w[cpu memory].freeze

          def pod_totals(pod)
            helpers = Rubernetes::ResourceHelpers
            requests = helpers.aggregate_container_requests(pod)
            limits = helpers.aggregate_container_limits(pod)
            pod_resources = helpers.pod_resources(pod)
            if pod_resources
              helpers.resource_list(pod_resources["requests"]).each do |name, value|
                requests[name] = value if POD_LEVEL_LIMIT_RANGE_RESOURCES.include?(name)
              end
              helpers.resource_list(pod_resources["limits"]).each do |name, value|
                limits[name] = value if POD_LEVEL_LIMIT_RANGE_RESOURCES.include?(name)
              end
            end
            {"requests" => requests.transform_values(&:to_s), "limits" => limits.transform_values(&:to_s)}
          end

          # minConstraint/maxConstraint, plugin/pkg/admission/limitranger/admission.go.
          # A MISSING value is itself a violation -- "No request is specified" /
          # "No limit is specified" -- and max is compared against the request
          # as well as the limit.  Skipping the check when the value was absent
          # let a Pod asking for 600Gi through a max of 500Mi, because it
          # specified no limit at all.
          def check_limits(attributes, item, resources, _label)
            (item["min"] || {}).each do |resource, minimum|
              request = resources.dig("requests", resource)
              limit = resources.dig("limits", resource)
              if request.nil?
                reject!("minimum #{resource} usage per #{item["type"]} is #{minimum}.  No request is specified")
                next
              end
              reject!("minimum #{resource} usage per #{item["type"]} is #{minimum}, but request is #{request}") if quantity(request) < quantity(minimum)
              if !limit.nil? && quantity(limit) < quantity(minimum)
                reject!("minimum #{resource} usage per #{item["type"]} is #{minimum}, but limit is #{limit}")
              end
            end
            (item["max"] || {}).each do |resource, maximum|
              limit = resources.dig("limits", resource)
              request = resources.dig("requests", resource)
              if limit.nil?
                reject!("maximum #{resource} usage per #{item["type"]} is #{maximum}.  No limit is specified")
                next
              end
              reject!("maximum #{resource} usage per #{item["type"]} is #{maximum}, but limit is #{limit}") if quantity(limit) > quantity(maximum)
              if !request.nil? && quantity(request) > quantity(maximum)
                reject!("maximum #{resource} usage per #{item["type"]} is #{maximum}, but request is #{request}")
              end
            end
            (item["maxLimitRequestRatio"] || {}).each do |resource, ratio|
              request = resources.dig("requests", resource)
              limit = resources.dig("limits", resource)
              next if request.nil? || limit.nil? || quantity(request).zero?

              if quantity(limit) / quantity(request) > quantity(ratio)
                reject!("#{resource} max limit to request ratio per #{item["type"]} is #{ratio}, but provided ratio is #{(quantity(limit) / quantity(request)).to_f}")
              end
            end
            attributes
          end
        end
        Registry.register("LimitRanger") { |context, config| LimitRanger.new("LimitRanger", context: context, config: config) }

        # ServiceAccount: default serviceAccountName, verify the account
        # exists, mount the projected token volume, and forbid pods from
        # referencing secrets of other service accounts.
        class ServiceAccount < Plugin
          include Helpers

          DEFAULT_NAME = "default"
          TOKEN_VOLUME_PREFIX = "kube-api-access-"
          MOUNT_PATH = "/var/run/secrets/kubernetes.io/serviceaccount"

          def admit(attributes)
            return unless resource?(attributes, "", "pods") && attributes.object && attributes.operation == "CREATE"

            pod = attributes.object
            # A mirror Pod is a static Pod's API object: no service account
            # is set, and the validation rules for mirrors apply.
            return mirror_pod_errors(pod, attributes.name) if mirror_pod?(pod)

            pod_spec = pod["spec"] ||= {}
            pod_spec["serviceAccountName"] = DEFAULT_NAME if pod_spec["serviceAccountName"].to_s.empty?
            account = @context.get("serviceaccounts", attributes.namespace, pod_spec["serviceAccountName"])
            if account.nil?
              unless pod_spec["serviceAccountName"] == DEFAULT_NAME && @config["allow_missing_default"] == true
                return reject!("pods #{attributes.name.inspect} is forbidden: error looking up service account #{attributes.namespace}/#{pod_spec["serviceAccountName"]}: serviceaccount #{pod_spec["serviceAccountName"].inspect} not found")
              end

              return
            end
            automount = if pod_spec.key?("automountServiceAccountToken")
                          pod_spec["automountServiceAccountToken"]
                        else
                          account.fetch(
                            "automountServiceAccountToken", true
                          )
                        end
            return if automount == false
            return if Array(pod_spec["volumes"]).any? { |volume| volume["name"].to_s.start_with?(TOKEN_VOLUME_PREFIX) }

            volume_name = "#{TOKEN_VOLUME_PREFIX}#{random_suffix}"
            (pod_spec["volumes"] ||= []) << {
              "name" => volume_name,
              "projected" => {"defaultMode" => 420, "sources" => [
                {"serviceAccountToken" => {"expirationSeconds" => 3607, "path" => "token"}},
                {"configMap" => {"name" => "kube-root-ca.crt", "items" => [{"key" => "ca.crt", "path" => "ca.crt"}]}},
                {"downwardAPI" => {"items" => [{"path" => "namespace",
                                                "fieldRef" => {"apiVersion" => "v1", "fieldPath" => "metadata.namespace"}}]}}
              ]}
            }
            (Array(pod_spec["containers"]) + Array(pod_spec["initContainers"])).each do |container|
              mounts = container["volumeMounts"] ||= []
              next if mounts.any? { |mount| mount["mountPath"] == MOUNT_PATH }

              mounts << {"name" => volume_name, "readOnly" => true, "mountPath" => MOUNT_PATH}
            end
          end

          MIRROR_ANNOTATION = "kubernetes.io/config.mirror"

          def mirror_pod?(pod) = (pod.dig("metadata", "annotations") || {}).key?(MIRROR_ANNOTATION)

          # serviceaccount admission Validate for a mirror Pod.
          def mirror_pod_errors(pod, name)
            forbidden = "pods #{name.to_s.inspect} is forbidden: "
            pod_spec = pod["spec"] || {}
            reject!("#{forbidden}a mirror pod may not reference service accounts") unless pod_spec["serviceAccountName"].to_s.empty?
            containers = Array(pod_spec["containers"]) + Array(pod_spec["initContainers"]) + Array(pod_spec["ephemeralContainers"])
            volumes = Array(pod_spec["volumes"])
            secrets = !Array(pod_spec["imagePullSecrets"]).empty? ||
                      containers.any? do |container|
                        Array(container["envFrom"]).any? { |source| source.key?("secretRef") } ||
                          Array(container["env"]).any? { |variable| (variable["valueFrom"] || {}).key?("secretKeyRef") }
                      end ||
                      volumes.any? do |volume|
                        volume.key?("secret") || volume.dig("azureFile", "secretName") ||
                          Array(volume.dig("projected", "sources")).any? { |source| source.key?("secret") } ||
                          %w[cephfs cinder flexVolume iscsi rbd scaleIO storageos csi].any? do |kind|
                            volume.dig(kind, "secretRef") || volume.dig(kind, "nodePublishSecretRef")
                          end
                      end
            reject!("#{forbidden}a mirror pod may not reference secrets") if secrets
            if volumes.any? { |volume| Array(volume.dig("projected", "sources")).any? { |source| source.key?("serviceAccountToken") } }
              reject!("#{forbidden}a mirror pod may not use ServiceAccountToken volume projections")
            end
            nil
          end

          def validate(attributes)
            return unless resource?(attributes, "", "pods") && attributes.object && attributes.operation == "CREATE"

            pod = attributes.object
            return mirror_pod_errors(pod, attributes.name) if mirror_pod?(pod)

            account = @context.get("serviceaccounts", attributes.namespace, spec(pod)["serviceAccountName"].to_s)
            return if account.nil?

            allowed = Array(account["secrets"]).map { |reference| reference["name"] }
            Array(spec(pod)["volumes"]).each do |volume|
              secret = volume.dig("secret", "secretName")
              next if secret.nil? || !secret.start_with?("#{spec(pod)["serviceAccountName"]}-token-")
              next if allowed.include?(secret)

              reject!("pods #{attributes.name.inspect} is forbidden: volume with secret.secretName=#{secret.inspect} is not allowed because service account #{spec(pod)["serviceAccountName"]} does not reference that secret")
            end
          end

          private

          def random_suffix
            @context.respond_to?(:random_suffix) ? @context.random_suffix : SecureRandom.alphanumeric(5).downcase
          end
        end
        Registry.register("ServiceAccount") { |context, config| ServiceAccount.new("ServiceAccount", context: context, config: config) }

        # TaintNodesByCondition: new nodes start NotReady/unschedulable-tainted.
        class TaintNodesByCondition < Plugin
          include Helpers

          NOT_READY = {"key" => "node.kubernetes.io/not-ready", "effect" => "NoSchedule"}.freeze

          def admit(attributes)
            return unless resource?(attributes, "", "nodes") && attributes.object && attributes.operation == "CREATE"

            taints = attributes.object["spec"] ||= {}
            taints["taints"] ||= []
            taints["taints"] << NOT_READY.dup unless taints["taints"].any? { |taint| taint["key"] == NOT_READY["key"] }
          end
        end
        Registry.register("TaintNodesByCondition") do |context, config|
          TaintNodesByCondition.new("TaintNodesByCondition", context: context, config: config)
        end

        class AlwaysPullImages < Plugin
          include Helpers

          def admit(attributes)
            return unless resource?(attributes, "", "pods") && attributes.object && %w[CREATE UPDATE].include?(attributes.operation)

            pod_containers(attributes.object).each { |container| container["imagePullPolicy"] = "Always" }
          end

          def validate(attributes)
            return unless resource?(attributes, "", "pods") && attributes.object && %w[CREATE UPDATE].include?(attributes.operation)

            pod_containers(attributes.object).each do |container|
              unless container["imagePullPolicy"] == "Always"
                reject!("Spec.Containers[#{container["name"]}].ImagePullPolicy: Forbidden: this image pull policy is not allowed, forced to Always")
              end
            end
          end
        end
        Registry.register("AlwaysPullImages") do |context, config|
          AlwaysPullImages.new("AlwaysPullImages", context: context, config: config)
        end

        # ImagePolicyWebhook: consult an external image review backend.
        class ImagePolicyWebhook < Plugin
          include Helpers

          def validate(attributes)
            return unless resource?(attributes, "", "pods") && attributes.object && %w[CREATE UPDATE].include?(attributes.operation)

            transport = @config["transport"]
            reject!("ImagePolicyWebhook is enabled without a backend") if transport.nil? && @config["default_allow"] != true
            return if transport.nil?

            review = {"apiVersion" => "imagepolicy.k8s.io/v1alpha1", "kind" => "ImageReview",
                      "spec" => {"containers" => pod_containers(attributes.object).map { |container| {"image" => container["image"]} },
                                 "annotations" => metadata(attributes.object).fetch("annotations", {}).select do |key, _|
                                   key.start_with?("*.image-policy.k8s.io/")
                                 end,
                                 "namespace" => attributes.namespace}}
            code, body = transport.call(JSON.generate(review))
            allowed = code.to_i.between?(200, 299) && (body.is_a?(String) ? JSON.parse(body) : body).dig("status", "allowed") == true
            reject!("pod is not allowed by the image policy webhook") unless allowed || (!code.to_i.between?(200,
                                                                                                             299) && @config["default_allow"] == true)
          rescue JSON::ParserError
            reject!("image policy webhook returned an invalid response") unless @config["default_allow"] == true
          end
        end
        Registry.register("ImagePolicyWebhook") do |context, config|
          ImagePolicyWebhook.new("ImagePolicyWebhook", context: context, config: config)
        end

        # PodNodeSelector: namespace annotation scheduler.alpha.kubernetes.io/node-selector.
        class PodNodeSelector < Plugin
          include Helpers

          ANNOTATION = "scheduler.alpha.kubernetes.io/node-selector"

          def admit(attributes)
            return unless resource?(attributes, "", "pods") && attributes.object && attributes.operation == "CREATE"

            selector = namespace_selector(attributes.namespace)
            return if selector.empty?

            pod_spec = attributes.object["spec"] ||= {}
            pod_spec["nodeSelector"] = (pod_spec["nodeSelector"] || {}).merge(selector) { |_key, pod_value, _ns_value| pod_value }
          end

          def validate(attributes)
            return unless resource?(attributes, "", "pods") && attributes.object && attributes.operation == "CREATE"

            selector = namespace_selector(attributes.namespace)
            pod_selector = spec(attributes.object)["nodeSelector"] || {}
            selector.each do |key, value|
              reject!("pod node label selector conflicts with its namespace node label selector") if pod_selector.key?(key) && pod_selector[key] != value
            end
          end

          private

          def namespace_selector(namespace)
            value = @context.namespace(namespace)&.dig("metadata", "annotations", ANNOTATION)
            value = @config["cluster_default_node_selector"] if value.nil?
            return {} if value.to_s.empty?

            value.split(",").map { |pair| pair.split("=", 2) }.to_h { |key, val| [key.strip, val.to_s.strip] }
          end
        end
        Registry.register("PodNodeSelector") { |context, config| PodNodeSelector.new("PodNodeSelector", context: context, config: config) }

        # Priority: resolve priorityClassName into priority / preemptionPolicy.
        class Priority < Plugin
          include Helpers

          SYSTEM_CLASSES = {"system-cluster-critical" => 2_000_000_000, "system-node-critical" => 2_000_001_000}.freeze

          def admit(attributes)
            return unless resource?(attributes, "", "pods") && attributes.object && attributes.operation == "CREATE"

            pod_spec = attributes.object["spec"] ||= {}
            class_name = pod_spec["priorityClassName"].to_s
            if class_name.empty?
              default = @context.list("priorityclasses", nil, group: "scheduling.k8s.io").find { |klass| klass["globalDefault"] == true }
              if default
                pod_spec["priorityClassName"] = default.dig("metadata", "name")
                pod_spec["priority"] = default["value"]
                pod_spec["preemptionPolicy"] = default["preemptionPolicy"] || "PreemptLowerPriority"
              else
                pod_spec["priority"] = 0
                pod_spec["preemptionPolicy"] ||= "PreemptLowerPriority"
              end
              return
            end
            # Upstream's Priority plugin resolves the two system classes for any
            # namespace (the kube-system-only rule left in 1.17); local-path's
            # helper Pods use system-node-critical in local-path-storage.
            if SYSTEM_CLASSES.key?(class_name)
              pod_spec["priority"] = SYSTEM_CLASSES[class_name]
              pod_spec["preemptionPolicy"] ||= "PreemptLowerPriority"
              return
            end
            klass = @context.get("priorityclasses", nil, class_name, group: "scheduling.k8s.io")
            reject!("no PriorityClass with name #{class_name} was found") if klass.nil?
            pod_spec["priority"] = klass["value"]
            pod_spec["preemptionPolicy"] = klass["preemptionPolicy"] || "PreemptLowerPriority"
          end

          def validate(attributes)
            return unless resource?(attributes, "scheduling.k8s.io",
                                    "priorityclasses") && attributes.object && %w[CREATE UPDATE].include?(attributes.operation)

            value = attributes.object["value"].to_i
            return unless value >= 1_000_000_000 && !attributes.name.start_with?("system-")

            reject!("PriorityClass value must be lower than 1000000000 (system reserved)")
          end
        end
        Registry.register("Priority") { |context, config| Priority.new("Priority", context: context, config: config) }

        class DefaultTolerationSeconds < Plugin
          include Helpers

          DEFAULT_SECONDS = 300
          KEYS = %w[node.kubernetes.io/not-ready node.kubernetes.io/unreachable].freeze

          def admit(attributes)
            return unless resource?(attributes, "", "pods") && attributes.object && %w[CREATE UPDATE].include?(attributes.operation)

            pod_spec = attributes.object["spec"] ||= {}
            tolerations = pod_spec["tolerations"] ||= []
            KEYS.each do |key|
              next if tolerations.any? { |toleration| toleration["key"] == key && toleration["effect"] == "NoExecute" }

              tolerations << {"key" => key, "operator" => "Exists", "effect" => "NoExecute",
                              "tolerationSeconds" => @config.fetch("default_seconds", DEFAULT_SECONDS)}
            end
          end
        end
        Registry.register("DefaultTolerationSeconds") do |context, config|
          DefaultTolerationSeconds.new("DefaultTolerationSeconds", context: context, config: config)
        end

        # PodTolerationRestriction: namespace default/whitelist tolerations.
        class PodTolerationRestriction < Plugin
          include Helpers

          DEFAULT_ANNOTATION = "scheduler.alpha.kubernetes.io/defaultTolerations"
          WHITELIST_ANNOTATION = "scheduler.alpha.kubernetes.io/tolerationsWhitelist"

          def admit(attributes)
            return unless resource?(attributes, "", "pods") && attributes.object && attributes.operation == "CREATE"

            defaults = annotation(attributes.namespace, DEFAULT_ANNOTATION) || @config["default_tolerations"] || []
            pod_spec = attributes.object["spec"] ||= {}
            pod_spec["tolerations"] = (pod_spec["tolerations"] || []) + defaults.reject do |toleration|
              Array(pod_spec["tolerations"]).include?(toleration)
            end
          end

          def validate(attributes)
            return unless resource?(attributes, "", "pods") && attributes.object && attributes.operation == "CREATE"

            whitelist = annotation(attributes.namespace, WHITELIST_ANNOTATION) || @config["whitelist"]
            return if whitelist.nil?

            Array(spec(attributes.object)["tolerations"]).each do |toleration|
              next if whitelist.any? { |allowed| allowed.all? { |key, value| toleration[key] == value } }

              reject!("pod tolerations (possibly merged with namespace default tolerations) conflict with its namespace whitelist")
            end
          end

          private

          def annotation(namespace, key)
            value = @context.namespace(namespace)&.dig("metadata", "annotations", key)
            value.nil? ? nil : JSON.parse(value)
          rescue JSON::ParserError
            reject!("namespace #{namespace} annotation #{key} is not valid JSON")
          end
        end
        Registry.register("PodTolerationRestriction") do |context, config|
          PodTolerationRestriction.new("PodTolerationRestriction", context: context, config: config)
        end

        # EventRateLimit: token buckets per server/namespace/user/source+object.
        class EventRateLimit < Plugin
          include Helpers

          def initialize(name, context:, config:)
            super
            @buckets = Hash.new { |hash, key| hash[key] = {tokens: nil, at: nil} }
            @mutex = Mutex.new
          end

          def validate(attributes)
            return unless resource?(attributes, "", "events") && %w[CREATE UPDATE].include?(attributes.operation)

            limits = Array(@config["limits"])
            return if limits.empty?

            now = @context.clock.call.to_f
            limits.each do |limit|
              key = case limit["type"]
                    when "Server" then "server"
                    when "Namespace" then "namespace/#{attributes.namespace}"
                    when "User" then "user/#{attributes.user.name}"
                    when "SourceAndObject" then "source/#{attributes.object&.dig("source")}/#{attributes.object&.dig("involvedObject")}"
                    end
              qps = limit.fetch("qps", 50).to_f
              burst = limit.fetch("burst", 100).to_f
              @mutex.synchronize do
                bucket = @buckets[[limit["type"], key]]
                bucket[:tokens] = burst if bucket[:tokens].nil?
                bucket[:tokens] = [burst, bucket[:tokens] + ((now - (bucket[:at] || now)) * qps)].min
                bucket[:at] = now
                reject!("limit reached on type #{limit["type"]}", code: 429, reason: "TooManyRequests") if bucket[:tokens] < 1
                bucket[:tokens] -= 1
              end
            end
          end
        end
        Registry.register("EventRateLimit") { |context, config| EventRateLimit.new("EventRateLimit", context: context, config: config) }

        class ExtendedResourceToleration < Plugin
          include Helpers

          def admit(attributes)
            return unless resource?(attributes, "", "pods") && attributes.object && attributes.operation == "CREATE"

            extended = pod_containers(attributes.object).flat_map do |container|
              (container.dig("resources", "requests") || {}).keys + (container.dig("resources", "limits") || {}).keys
            end
              .uniq.select do |resource|
              resource.include?("/") && !resource.start_with?(
                "kubernetes.io/", "requests."
              )
            end
            return if extended.empty?

            pod_spec = attributes.object["spec"] ||= {}
            tolerations = pod_spec["tolerations"] ||= []
            extended.each do |resource|
              next if tolerations.any? { |toleration| toleration["key"] == resource }

              tolerations << {"key" => resource, "operator" => "Exists", "effect" => "NoSchedule"}
            end
          end
        end
        Registry.register("ExtendedResourceToleration") do |context, config|
          ExtendedResourceToleration.new("ExtendedResourceToleration", context: context, config: config)
        end

        class DefaultStorageClass < Plugin
          include Helpers

          def admit(attributes)
            return unless resource?(attributes, "", "persistentvolumeclaims") && attributes.object && attributes.operation == "CREATE"

            claim_spec = attributes.object["spec"] ||= {}
            return if claim_spec.key?("storageClassName") || !claim_spec["volumeName"].to_s.empty?

            defaults = @context.list("storageclasses", nil, group: "storage.k8s.io").select do |klass|
              klass.dig("metadata", "annotations", "storageclass.kubernetes.io/is-default-class") == "true"
            end
            return if defaults.empty?

            chosen = defaults.max_by { |klass| [klass.dig("metadata", "creationTimestamp").to_s, klass.dig("metadata", "name").to_s] }
            claim_spec["storageClassName"] = chosen.dig("metadata", "name")
          end
        end
        Registry.register("DefaultStorageClass") do |context, config|
          DefaultStorageClass.new("DefaultStorageClass", context: context, config: config)
        end

        class StorageObjectInUseProtection < Plugin
          include Helpers

          PVC_FINALIZER = "kubernetes.io/pvc-protection"
          PV_FINALIZER = "kubernetes.io/pv-protection"

          def admit(attributes)
            return unless attributes.object && attributes.operation == "CREATE"

            finalizer = if resource?(attributes, "", "persistentvolumeclaims") then PVC_FINALIZER
                        elsif resource?(attributes, "", "persistentvolumes") then PV_FINALIZER
                        end
            return if finalizer.nil?

            metadata = attributes.object["metadata"] ||= {}
            metadata["finalizers"] = (metadata["finalizers"] || []) | [finalizer]
          end
        end
        Registry.register("StorageObjectInUseProtection") do |context, config|
          StorageObjectInUseProtection.new("StorageObjectInUseProtection", context: context, config: config)
        end

        class PodGroupProtection < Plugin
          include Helpers

          FINALIZER = "scheduling.k8s.io/podgroup-protection"

          def admit(attributes)
            return unless resource?(attributes, "scheduling.k8s.io", "podgroups") && attributes.object && attributes.operation == "CREATE"

            metadata = attributes.object["metadata"] ||= {}
            metadata["finalizers"] = (metadata["finalizers"] || []) | [FINALIZER]
          end
        end
        Registry.register("PodGroupProtection") do |context, config|
          PodGroupProtection.new("PodGroupProtection", context: context, config: config)
        end

        # OwnerReferencesPermissionEnforcement: changing ownerReferences with
        # blockOwnerDeletion requires update on the owner's finalizers.
        class OwnerReferencesPermissionEnforcement < Plugin
          include Helpers

          def validate(attributes)
            return unless attributes.object && %w[CREATE UPDATE].include?(attributes.operation)

            new_refs = Array(metadata(attributes.object)["ownerReferences"])
            old_refs = Array(metadata(attributes.old_object)["ownerReferences"])
            blocking = new_refs.select { |ref| ref["blockOwnerDeletion"] == true } - old_refs.select do |ref|
              ref["blockOwnerDeletion"] == true
            end
            return if blocking.empty?

            authorizer = @context.respond_to?(:authorizer) ? @context.authorizer : nil
            return if authorizer.nil?

            blocking.each do |ref|
              api_version = ref["apiVersion"].to_s
              group = api_version.include?("/") ? api_version.split("/").first : ""
              resource = if @context.respond_to?(:resource_for_kind)
                           @context.resource_for_kind(group,
                                                      ref["kind"])
                         else
                           ref["kind"].to_s.downcase + "s"
                         end
              check = Authorization::Attributes.new(user: attributes.user, verb: "update", api_group: group, resource: resource, subresource: "finalizers",
                                                    namespace: attributes.namespace, name: ref["name"], resource_request: true)
              decision = authorizer.authorize(check)
              unless decision.allowed?
                reject!("cannot set blockOwnerDeletion if an ownerReference refers to a resource you can't set finalizers on: #{ref["kind"]} #{ref["name"]}")
              end
            end
          end
        end
        Registry.register("OwnerReferencesPermissionEnforcement") do |context, config|
          OwnerReferencesPermissionEnforcement.new("OwnerReferencesPermissionEnforcement", context: context, config: config)
        end

        class PersistentVolumeClaimResize < Plugin
          include Helpers

          def validate(attributes)
            return unless resource?(attributes, "",
                                    "persistentvolumeclaims") && attributes.object && attributes.old_object && attributes.operation == "UPDATE"

            new_size = spec(attributes.object).dig("resources", "requests", "storage")
            old_size = spec(attributes.old_object).dig("resources", "requests", "storage")
            return if new_size.nil? || old_size.nil? || quantity(new_size) <= quantity(old_size)

            reject!("only bound persistent volume claims can be expanded") unless attributes.old_object.dig("status", "phase") == "Bound"
            class_name = spec(attributes.old_object)["storageClassName"].to_s
            klass = class_name.empty? ? nil : @context.get("storageclasses", nil, class_name, group: "storage.k8s.io")
            return if klass && klass["allowVolumeExpansion"] == true

            reject!("persistentvolumeclaims #{attributes.name.inspect} is forbidden: only dynamically provisioned pvc can be resized and the storageclass that provisions the pvc must support resize")
          end
        end
        Registry.register("PersistentVolumeClaimResize") do |context, config|
          PersistentVolumeClaimResize.new("PersistentVolumeClaimResize", context: context, config: config)
        end

        # RuntimeClass: apply overhead and scheduling constraints from the RuntimeClass.
        class RuntimeClass < Plugin
          include Helpers

          def admit(attributes)
            return unless resource?(attributes, "", "pods") && attributes.object && attributes.operation == "CREATE"

            pod_spec = attributes.object["spec"] ||= {}
            name = pod_spec["runtimeClassName"].to_s
            return if name.empty?

            runtime_class = @context.get("runtimeclasses", nil, name, group: "node.k8s.io")
            if runtime_class.nil?
              reject!("pods #{attributes.name.inspect} is forbidden: pod rejected: RuntimeClass #{name.inspect} not found",
                      code: 403)
            end
            overhead = runtime_class.dig("overhead", "podFixed")
            if overhead
              reject!("pod rejected: Pod's Overhead doesn't match RuntimeClass's defined Overhead") if pod_spec["overhead"] && pod_spec["overhead"] != overhead
              pod_spec["overhead"] = overhead
            end
            scheduling = runtime_class["scheduling"] || {}
            (scheduling["nodeSelector"] || {}).each do |key, value|
              existing = pod_spec.dig("nodeSelector", key)
              reject!("pod rejected: conflict: runtime class node selector #{key}=#{value} conflicts with pod node selector") if existing && existing != value
              (pod_spec["nodeSelector"] ||= {})[key] = value
            end
            Array(scheduling["tolerations"]).each do |toleration|
              pod_spec["tolerations"] = (pod_spec["tolerations"] || []) | [toleration]
            end
          end

          def validate(attributes)
            return unless resource?(attributes, "", "pods") && attributes.object && attributes.operation == "CREATE"

            name = spec(attributes.object)["runtimeClassName"].to_s
            return if name.empty?

            runtime_class = @context.get("runtimeclasses", nil, name, group: "node.k8s.io")
            return unless runtime_class.nil?

            reject!("pods #{attributes.name.inspect} is forbidden: pod rejected: RuntimeClass #{name.inspect} not found")
          end
        end
        Registry.register("RuntimeClass") { |context, config| RuntimeClass.new("RuntimeClass", context: context, config: config) }

        class DefaultIngressClass < Plugin
          include Helpers

          def admit(attributes)
            return unless resource?(attributes, "networking.k8s.io", "ingresses") && attributes.object && attributes.operation == "CREATE"

            ingress_spec = attributes.object["spec"] ||= {}
            return if ingress_spec.key?("ingressClassName") || metadata(attributes.object).dig("annotations", "kubernetes.io/ingress.class")

            defaults = @context.list("ingressclasses", nil, group: "networking.k8s.io").select do |klass|
              klass.dig("metadata", "annotations", "ingressclass.kubernetes.io/is-default-class") == "true"
            end
            return if defaults.empty?

            chosen = defaults.max_by { |klass| [klass.dig("metadata", "creationTimestamp").to_s, klass.dig("metadata", "name").to_s] }
            ingress_spec["ingressClassName"] = chosen.dig("metadata", "name")
          end
        end
        Registry.register("DefaultIngressClass") do |context, config|
          DefaultIngressClass.new("DefaultIngressClass", context: context, config: config)
        end

        class DenyServiceExternalIPs < Plugin
          include Helpers

          def validate(attributes)
            return unless resource?(attributes, "", "services") && attributes.object && %w[CREATE UPDATE].include?(attributes.operation)

            new_ips = Array(spec(attributes.object)["externalIPs"])
            old_ips = Array(spec(attributes.old_object)["externalIPs"])
            return if (new_ips - old_ips).empty?

            invalid!("Service", attributes.name,
                     [{"reason" => "FieldValueForbidden", "field" => "spec.externalIPs", "message" => "Forbidden: externalIPs have been disabled"}])
          end
        end
        Registry.register("DenyServiceExternalIPs") do |context, config|
          DenyServiceExternalIPs.new("DenyServiceExternalIPs", context: context, config: config)
        end

        # PodTopologyLabels (PodTopologyLabelsAdmission, Beta, on): the Node's
        # zone and region labels are copied, overwriting, onto a Binding (the
        # binding subresource then copies them onto the Pod) or onto a Pod
        # created with spec.nodeName.
        class PodTopologyLabels < Plugin
          include Helpers

          LABELS = %w[topology.kubernetes.io/zone topology.kubernetes.io/region].freeze

          def admit(attributes)
            return unless resource?(attributes, "", "pods") && attributes.object && attributes.operation == "CREATE"

            node_name = case attributes.subresource.to_s
                        when "binding"
                          return unless attributes.object.dig("target", "kind") == "Node"

                          attributes.object.dig("target", "name")
                        when ""
                          attributes.object.dig("spec", "nodeName")
                        end
            return if node_name.to_s.empty?

            node = @context.get("nodes", nil, node_name)
            return if node.nil?

            copied = LABELS.filter_map { |label| [label, node.dig("metadata", "labels", label)] if node.dig("metadata", "labels", label) }
            return if copied.empty?

            labels = (attributes.object["metadata"] ||= {})["labels"] ||= {}
            copied.each { |label, value| labels[label] = value }
          end
        end
        Registry.register("PodTopologyLabels") do |context, config|
          PodTopologyLabels.new("PodTopologyLabels", context: context, config: config)
        end

        class PodGroupWorkloadExists < Plugin
          include Helpers

          def validate(attributes)
            return unless resource?(attributes, "scheduling.k8s.io", "podgroups") && attributes.object && attributes.operation == "CREATE"

            workload = attributes.object.dig("spec", "workloadRef", "name") || attributes.object.dig("spec", "workload")
            return if workload.nil?

            reject!("PodGroup #{attributes.name.inspect} refers to a Workload that does not exist") if @context.get("workloads",
                                                                                                                    attributes.namespace, workload, group: "scheduling.k8s.io", version: "v1alpha2").nil?
          end
        end
        Registry.register("PodGroupWorkloadExists") do |context, config|
          PodGroupWorkloadExists.new("PodGroupWorkloadExists", context: context, config: config)
        end

        # plugin/pkg/admission/nodedeclaredfeatures: an update of a bound Pod
        # (main resource or pods/resize) that needs a node-declared feature --
        # a pod-level or non-sidecar init container resize -- is refused when
        # the Pod's Node does not declare it.  The previous version of this
        # plugin checked a "spec.requiredNodeFeatures" field that does not
        # exist in the Pod API, at binding time, so it never refused anything.
        class NodeDeclaredFeatureValidator < Plugin
          include Helpers

          # The feature registry and the component version it is matched
          # against; replaced only by tests (upstream injects both the same way).
          attr_writer :framework, :version

          def validate(attributes)
            return unless @context.feature_enabled?(NodeDeclaredFeatures::GATE)
            return unless attributes.operation == "UPDATE" && resource?(attributes, "", "pods")
            return unless [nil, "", "resize"].include?(attributes.subresource)

            pod = attributes.object
            old_pod = attributes.old_object
            return unless pod.is_a?(Hash) && old_pod.is_a?(Hash)

            node_name = spec(pod)["nodeName"].to_s
            return if node_name.empty?
            # Upstream skips when metadata.generation did not move; the pod
            # strategy bumps it exactly when the spec changes, and this API
            # server assigns the new generation after validating admission.
            return if spec(old_pod) == spec(pod)

            framework = @framework || NodeDeclaredFeatures::DEFAULT_FRAMEWORK
            required = framework.infer_for_pod_update(old_pod, pod, @version || NodeDeclaredFeatures::KUBERNETES_VERSION)
            return if required.empty?

            name = attributes.name || metadata(pod)["name"]
            node = @context.get("nodes", nil, node_name)
            reject!("pods #{name.to_s.inspect} is forbidden: node #{node_name.inspect} not found") if node.nil?

            result = framework.match_node(required, node)
            return if result.match?

            reject!("pods #{name.to_s.inspect} is forbidden: pod update requires features #{result.unsatisfied_requirements.join(", ")} " \
                    "which are not available on node #{node_name.inspect}")
          end
        end
        Registry.register("NodeDeclaredFeatureValidator") do |context, config|
          NodeDeclaredFeatureValidator.new("NodeDeclaredFeatureValidator", context: context, config: config)
        end

        class JobValidation < Plugin
          include Helpers

          def validate(attributes)
            return unless resource?(attributes, "batch", "jobs") && attributes.object && attributes.operation == "CREATE"
            return unless @context.feature_enabled?("WorkloadWithJob")

            workload = spec(attributes.object).dig("workloadRef", "name")
            return if workload.nil?

            reject!("Job #{attributes.name.inspect} refers to a Workload that does not exist") if @context.get("workloads",
                                                                                                               attributes.namespace, workload, group: "scheduling.k8s.io", version: "v1alpha2").nil?
          end
        end
        Registry.register("JobValidation") { |context, config| JobValidation.new("JobValidation", context: context, config: config) }

        # plugin/pkg/admission/podresize: a resize of a bound Pod (pods/resize,
        # generation moved) is refused on a non-linux Node and when the Pod's
        # new requests exceed the Node's allocatable.  Which fields a resize
        # may change is ValidatePodResize's business (schema validation).
        class PodResizeValidator < Plugin
          include Helpers

          def validate(attributes)
            return unless @context.feature_enabled?("InPlacePodVerticalScaling")
            return unless attributes.operation == "UPDATE" && resource?(attributes, "", "pods") && attributes.subresource.to_s == "resize"

            pod = attributes.object
            old_pod = attributes.old_object
            return unless pod.is_a?(Hash) && old_pod.is_a?(Hash)

            node_name = spec(pod)["nodeName"].to_s
            return if node_name.empty?
            # Generation only moves with the spec; this server assigns it
            # after validating admission, so compare the specs instead.
            return if spec(pod) == spec(old_pod)

            name = attributes.name.to_s
            node = @context.get("nodes", nil, node_name)
            reject!("pods #{name.inspect} is forbidden: node #{node_name.inspect} not found") if node.nil?

            os = node.dig("metadata", "labels", "kubernetes.io/os")
            if !os.nil? && os != "linux"
              reject!("pods #{name.inspect} is forbidden: pod resize is only supported on linux nodes, node #{node_name.inspect} is #{os.inspect}",
                      details: {"causes" => [{"reason" => "UnsupportedPlatform"}]})
            end
            allocatable = Rubernetes::ResourceHelpers.resource_list(node.dig("status", "allocatable"))
            requests = Rubernetes::ResourceHelpers.pod_requests(pod)
            zero = Rubernetes::Schema::Quantity.parse("0")
            messages = []
            cpu = requests["cpu"] || zero
            cpu_allocatable = allocatable["cpu"] || zero
            memory = requests["memory"] || zero
            memory_allocatable = allocatable["memory"] || zero
            messages << "cpu, requested: #{cpu.milli_value}, allocatable: #{cpu_allocatable.milli_value}" if cpu.value > cpu_allocatable.value
            messages << "memory, requested: #{memory.value.ceil}, allocatable: #{memory_allocatable.value.ceil}" if memory.value > memory_allocatable.value
            return if messages.empty?

            reject!("pods #{name.inspect} is forbidden: node didn't have enough allocatable resources: #{messages.join("; ")}",
                    details: {"causes" => [{"reason" => "NodeCapacity"}]})
          end
        end
        Registry.register("PodResizeValidator") do |context, config|
          PodResizeValidator.new("PodResizeValidator", context: context, config: config)
        end
      end
    end
  end
end
