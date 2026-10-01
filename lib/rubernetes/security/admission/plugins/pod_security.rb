# frozen_string_literal: true

require_relative "core"
require_relative "../../pod_security"

module Rubernetes
  module Security
    module Admission
      module Plugins
        # PodSecurity admission (k8s.io/pod-security-admission admission.go and
        # plugin/pkg/admission/security/podsecurity, v1.36.2): the Pod Security
        # Standards a namespace's pod-security.kubernetes.io labels select,
        # enforced on Pods, audited and warned on Pods and the pod templates of
        # workload resources, and checked against existing Pods when a
        # namespace's enforce level tightens.  Configuration is the
        # PodSecurityConfiguration: defaults and exemptions (usernames,
        # namespaces, runtimeClasses).
        class PodSecurity < Plugin
          include Helpers

          PS = Security::PodSecurity

          POD_SPEC_RESOURCES = {
            ["", "pods"] => [], ["", "replicationcontrollers"] => %w[spec template], ["", "podtemplates"] => %w[template],
            %w[apps replicasets] => %w[spec template], %w[apps deployments] => %w[spec template],
            %w[apps statefulsets] => %w[spec template], %w[apps daemonsets] => %w[spec template],
            %w[batch jobs] => %w[spec template], %w[batch cronjobs] => %w[spec jobTemplate spec template]
          }.freeze
          IGNORED_POD_SUBRESOURCES = %w[exec attach binding eviction log portforward proxy status].freeze
          NAMESPACE_MAX_PODS_TO_CHECK = 3000

          def initialize(name, context: nil, config: {})
            super
            defaults = @config["defaults"] || {}
            level_version = lambda do |mode|
              level, = PS.parse_level(defaults.fetch(mode, "privileged").to_s)
              version, = PS.parse_version(defaults.fetch("#{mode}-version", "latest").to_s)
              PS::LevelVersion.new(level, version)
            end
            @default_policy = PS::Policy.new(level_version.call("enforce"), level_version.call("audit"), level_version.call("warn"))
            exemptions = @config["exemptions"] || {}
            @exempt_usernames = Array(exemptions["usernames"]).map(&:to_s)
            @exempt_namespaces = Array(exemptions["namespaces"]).map(&:to_s)
            @exempt_runtime_classes = Array(exemptions["runtimeClasses"]).map(&:to_s)
            @evaluator = PS::Evaluator.new
          end

          def handles?(attributes)
            %w[CREATE UPDATE].include?(attributes.operation) &&
              (resource?(attributes, "", "namespaces") || POD_SPEC_RESOURCES.key?([attributes.group, attributes.resource]))
          end

          def validate(attributes)
            return unless handles?(attributes)

            response = if resource?(attributes, "", "namespaces")
                         validate_namespace(attributes)
                       elsif resource?(attributes, "", "pods")
                         validate_pod(attributes)
                       else
                         validate_pod_controller(attributes)
                       end
            finish(attributes, response)
          end

          private

          Response = Struct.new(:allowed, :warnings, :annotations, :error)

          def allowed(annotations = {}) = Response.new(true, [], annotations, nil)

          def finish(attributes, response)
            response.warnings.each { |warning| attributes.warn(warning) }
            response.annotations.each { |key, value| attributes.annotate("#{PS::LABEL_PREFIX}#{key}", value) }
            raise response.error if response.error
          end

          # ---- namespaces ---------------------------------------------------

          def validate_namespace(attributes)
            return allowed unless attributes.subresource.empty?

            namespace = attributes.object
            return error_response(bad_request("failed to decode namespace")) unless namespace.is_a?(Hash)

            name = metadata(namespace)["name"].to_s
            new_policy, new_errors = PS.policy_to_evaluate(metadata(namespace)["labels"], @default_policy)
            case attributes.operation
            when "CREATE"
              return invalid_response(name, new_errors) if new_errors.any?

              exempt_namespace_warning_response(name, new_policy, metadata(namespace)["labels"]) || allowed
            else
              old = attributes.old_object
              return error_response(bad_request("failed to decode  old namespace")) unless old.is_a?(Hash)

              old_policy, old_errors = PS.policy_to_evaluate(metadata(old)["labels"], @default_policy)
              return invalid_response(name, new_errors) if new_errors.any? && (old_errors.empty? || new_errors != old_errors)
              return allowed if new_policy.enforce == old_policy.enforce
              return allowed if new_policy.enforce.level == "privileged"
              if new_policy.enforce.version == old_policy.enforce.version &&
                 PS.compare_levels(new_policy.enforce.level, old_policy.enforce.level) < 1
                return allowed
              end
              return exempt_namespace_warning_response(name, new_policy, metadata(namespace)["labels"]) || allowed if exempt_namespace?(name)

              Response.new(true, evaluate_pods_in_namespace(name, new_policy.enforce), {}, nil)
            end
          end

          def exempt_namespace_warning_response(name, policy, labels)
            return nil unless exempt_namespace?(name)
            return nil if policy.fully_privileged? || policy.equivalent?(@default_policy)

            labels = {} unless labels.is_a?(Hash)
            parts = []
            {"enforce" => policy.enforce, "audit" => policy.audit, "warn" => policy.warn}.each do |mode, level_version|
              next if level_version.level == "privileged"
              next unless labels.key?("#{PS::LABEL_PREFIX}#{mode}") || labels.key?("#{PS::LABEL_PREFIX}#{mode}-version")

              parts << "#{mode}=#{level_version}"
            end
            Response.new(true, ["namespace #{name.inspect} is exempt from Pod Security, and the policy (#{parts.join(", ")}) will be ignored"],
                         {}, nil)
          end

          # EvaluatePodsInNamespace: the new enforce level against the Pods
          # already there (one per controller first), as warnings.
          def evaluate_pods_in_namespace(namespace, enforce)
            pods = begin
              @context.list("pods", namespace)
            rescue StandardError
              return ["failed to list pods while checking new PodSecurity enforce level"]
            end
            prioritized = prioritize(pods)
            total = prioritized.length
            prioritized = prioritized.first(NAMESPACE_MAX_PODS_TO_CHECK)
            counts = {}
            order = []
            prioritized.each do |pod|
              result = PS.aggregate(@evaluator.evaluate(enforce, metadata(pod), spec(pod)))
              next if result.allowed

              warning = result.forbidden_reason
              name = metadata(pod)["name"].to_s
              entry = counts[warning]
              if entry.nil?
                counts[warning] = entry = {name: name, count: 0}
                order << warning
              elsif name < entry[:name]
                entry[:name] = name
              end
              entry[:count] += 1
            end
            warnings = []
            if prioritized.length < total
              warnings << "new PodSecurity enforce level only checked against the first #{prioritized.length} of #{total} existing pods"
            end
            warnings << "existing pods in namespace #{namespace.inspect} violate the new PodSecurity enforce level #{enforce.to_s.inspect}" if order.any?
            decorated = order.map do |warning|
              entry = counts[warning]
              case entry[:count]
              when 1 then "#{entry[:name]}: #{warning}"
              when 2 then "#{entry[:name]} (and 1 other pod): #{warning}"
              else "#{entry[:name]} (and #{entry[:count] - 1} other pods): #{warning}"
              end
            end
            warnings + decorated.sort
          end

          def prioritize(pods)
            evaluated = {}
            first = []
            duplicates = []
            Array(pods).each do |pod|
              next unless pod.is_a?(Hash)
              next if exempt_runtime_class?(spec(pod)["runtimeClassName"])

              owner = Array(metadata(pod)["ownerReferences"]).find { |reference| reference["controller"] == true }
              if owner.nil?
                first << pod
              elsif evaluated[owner["uid"]]
                duplicates << pod
              else
                first << pod
                evaluated[owner["uid"]] = true
              end
            end
            first + duplicates
          end

          # ---- pods ---------------------------------------------------------

          def validate_pod(attributes)
            return allowed if IGNORED_POD_SUBRESOURCES.include?(attributes.subresource)

            if exempt_namespace?(attributes.namespace)
              record_exemption(attributes)
              return allowed(PS::EXEMPTION_REASON_ANNOTATION => "namespace")
            end
            if exempt_user?(user_name(attributes))
              record_exemption(attributes)
              return allowed(PS::EXEMPTION_REASON_ANNOTATION => "user")
            end
            namespace = @context.namespace(attributes.namespace)
            if namespace.nil?
              record_error(true, attributes)
              return error_response(Rejected.new("Internal error occurred: failed to lookup namespace #{attributes.namespace.inspect}",
                                                 code: 500, reason: "InternalError"))
            end
            policy, errors = PS.policy_to_evaluate(metadata(namespace)["labels"], @default_policy)
            if errors.empty? && policy.fully_privileged?
              record_evaluation("allow", policy.enforce, "enforce", attributes)
              return allowed(PS::ENFORCED_POLICY_ANNOTATION => PS::LevelVersion.new("privileged", PS::Version.latest).to_s)
            end
            pod = attributes.object
            unless pod.is_a?(Hash)
              record_error(true, attributes)
              return error_response(bad_request("failed to decode pod"))
            end
            if attributes.operation == "UPDATE"
              old = attributes.old_object
              unless old.is_a?(Hash)
                record_error(true, attributes)
                return error_response(bad_request("failed to decode old pod"))
              end
              return allowed unless significant_pod_update?(pod, old)
            end
            evaluate_pod(policy, errors, metadata(pod), spec(pod), attributes, enforce: true)
          end

          # isSignificantPodUpdate: only an image change (or a container added
          # or removed) is evaluated again.
          def significant_pod_update?(pod, old)
            new_spec = spec(pod)
            old_spec = spec(old)
            %w[containers initContainers].each do |list|
              current = Array(new_spec[list])
              previous = Array(old_spec[list])
              return true if current.length != previous.length
              return true if current.each_index.any? { |index| current[index]["image"] != previous[index]["image"] }
            end
            Array(new_spec["ephemeralContainers"]).any? do |container|
              previous = Array(old_spec["ephemeralContainers"]).find { |candidate| candidate["name"] == container["name"] }
              previous.nil? || previous["image"] != container["image"]
            end
          end

          def validate_pod_controller(attributes)
            return allowed unless attributes.subresource.empty?

            if exempt_namespace?(attributes.namespace)
              record_exemption(attributes)
              return allowed(PS::EXEMPTION_REASON_ANNOTATION => "namespace")
            end
            if exempt_user?(user_name(attributes))
              record_exemption(attributes)
              return allowed(PS::EXEMPTION_REASON_ANNOTATION => "user")
            end
            namespace = @context.namespace(attributes.namespace)
            if namespace.nil?
              record_error(true, attributes)
              return allowed("error" => "failed to lookup namespace #{attributes.namespace.inspect}: namespaces #{attributes.namespace.inspect} not found")
            end
            policy, errors = PS.policy_to_evaluate(metadata(namespace)["labels"], @default_policy)
            return allowed if errors.empty? && policy.warn.level == "privileged" && policy.audit.level == "privileged"

            object = attributes.object
            unless object.is_a?(Hash)
              record_error(true, attributes)
              return allowed("error" => "failed to decode object")
            end
            path = POD_SPEC_RESOURCES.fetch([attributes.group, attributes.resource])
            template = object.dig(*path)
            return allowed unless template.is_a?(Hash)

            evaluate_pod(policy, errors, metadata(template), spec(template), attributes, enforce: false)
          end

          # EvaluatePod: enforce (Pods only), then audit and warn, reusing
          # the result of an identical level and version.
          def evaluate_pod(policy, policy_errors, pod_metadata, pod_spec, attributes, enforce:)
            if exempt_runtime_class?(pod_spec["runtimeClassName"])
              record_exemption(attributes)
              return allowed(PS::EXEMPTION_REASON_ANNOTATION => "runtimeClass")
            end
            annotations = {}
            if policy_errors.any?
              annotations["error"] = "Failed to parse policy: #{aggregate_error(policy_errors)}"
              record_error(false, attributes)
            end
            cached = {}
            response = Response.new(true, [], annotations, nil)
            if enforce
              annotations[PS::ENFORCED_POLICY_ANNOTATION] = policy.enforce.to_s
              result = PS.aggregate(@evaluator.evaluate(policy.enforce, pod_metadata, pod_spec))
              if result.allowed
                record_evaluation("allow", policy.enforce, "enforce", attributes)
              else
                response.allowed = false
                response.error = Rejected.new("#{group_resource(attributes)} #{attributes.name.inspect} is forbidden: violates PodSecurity " \
                                              "#{policy.enforce.to_s.inspect}: #{result.forbidden_detail}",
                                              code: 403, reason: "Forbidden",
                                              details: {"name" => attributes.name, "kind" => attributes.resource}, plugin: name)
                record_evaluation("deny", policy.enforce, "enforce", attributes)
              end
              cached[key(policy.enforce)] = result
            end
            audit = cached[key(policy.audit)] ||= PS.aggregate(@evaluator.evaluate(policy.audit, pod_metadata, pod_spec))
            unless audit.allowed
              annotations[PS::AUDIT_VIOLATIONS_ANNOTATION] =
                "would violate PodSecurity #{policy.audit.to_s.inspect}: #{audit.forbidden_detail}"
              record_evaluation("deny", policy.audit, "audit", attributes)
            end
            if response.allowed
              warn = cached[key(policy.warn)] || PS.aggregate(@evaluator.evaluate(policy.warn, pod_metadata, pod_spec))
              unless warn.allowed
                response.warnings << "would violate PodSecurity #{policy.warn.to_s.inspect}: #{warn.forbidden_detail}"
                record_evaluation("deny", policy.warn, "warn", attributes)
              end
            end
            response
          end

          def key(level_version) = [level_version.level, level_version.version]

          def aggregate_error(errors)
            rendered = errors.map { |error| "#{error["field"]}: Invalid value: #{error["value"].inspect}: #{error["message"]}" }
            rendered.length == 1 ? rendered.first : "[#{rendered.join(", ")}]"
          end

          def invalid_response(name, errors)
            causes = errors.map do |error|
              {"reason" => "FieldValueInvalid", "field" => error["field"],
               "message" => "Invalid value: #{error["value"].inspect}: #{error["message"]}"}
            end
            summary = causes.map { |cause| "#{cause["field"]}: #{cause["message"]}" }
            message = "Namespace #{name.inspect} is invalid: #{summary.length == 1 ? summary.first : "[#{summary.join(", ")}]"}"
            Response.new(false, [], {}, Rejected.new(message, code: 422, reason: "Invalid",
                                                              details: {"name" => name, "kind" => "Namespace", "causes" => causes},
                                                              plugin: self.name))
          end

          def bad_request(message) = Rejected.new(message, code: 400, reason: "BadRequest", plugin: name)

          def error_response(error) = Response.new(false, [], {"error" => error.message}, error)

          def user_name(attributes)
            user = attributes.user
            user.respond_to?(:name) ? user.name.to_s : ""
          end

          def exempt_namespace?(namespace) = !namespace.to_s.empty? && @exempt_namespaces.include?(namespace.to_s)
          def exempt_user?(user) = !user.to_s.empty? && @exempt_usernames.include?(user.to_s)
          def exempt_runtime_class?(runtime_class) = !runtime_class.to_s.empty? && @exempt_runtime_classes.include?(runtime_class.to_s)

          # ---- metrics (pod-security-admission metrics.go) --------------------

          def operation_label(attributes) = attributes.operation.downcase

          def resource_label(attributes)
            return "pod" if resource?(attributes, "", "pods")
            return "namespace" if resource?(attributes, "", "namespaces")

            "controller"
          end

          def record_evaluation(decision, level_version, mode, attributes)
            return unless @metrics

            version = if level_version.version.latest? || level_version.level == "privileged"
                        "latest"
                      elsif !PS::API_VERSION.older?(level_version.version)
                        level_version.version.to_s
                      else
                        "future"
                      end
            @metrics.increment("pod_security_evaluations_total",
                               {"decision" => decision, "policy_level" => level_version.level, "policy_version" => version, "mode" => mode,
                                "request_operation" => operation_label(attributes), "resource" => resource_label(attributes),
                                "subresource" => attributes.subresource})
          rescue StandardError
            nil
          end

          def record_exemption(attributes)
            @metrics&.increment("pod_security_exemptions_total",
                                {"request_operation" => operation_label(attributes), "resource" => resource_label(attributes),
                                 "subresource" => attributes.subresource})
          end

          def record_error(fatal, attributes)
            @metrics&.increment("pod_security_errors_total",
                                {"fatal" => fatal.to_s, "request_operation" => operation_label(attributes), "resource" => resource_label(attributes),
                                 "subresource" => attributes.subresource})
          end
        end
        Registry.register("PodSecurity") { |context, config| PodSecurity.new("PodSecurity", context: context, config: config) }
      end
    end
  end
end
