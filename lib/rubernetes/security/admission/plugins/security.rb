# frozen_string_literal: true

require "json"
require "openssl"

require_relative "../../../claim_quota_usage"
require_relative "core"
require_relative "../../../pod_quota_usage"
require_relative "../../../pod_api_references"

module Rubernetes
  module Security
    module Admission
      module Plugins
        # NodeRestriction (plugin/pkg/admission/noderestriction, v1.36.2): what
        # a kubelet (system:node:<name>) may write once the node authorizer let
        # the request through -- its own mirror Pods and the status of Pods
        # bound to it, evictions of those Pods, its own Node (no taints,
        # ownerReferences, configSource or reserved labels), the resize status
        # of claims, tokens bound to its Pods, its own Lease, CSINode and
        # ResourceSlices, its PodCertificateRequests and its own CSRs.
        class NodeRestriction < Plugin
          include Helpers

          MIRROR_ANNOTATION = "kubernetes.io/config.mirror"
          NODE_RESTRICTION_NAMESPACE = "node-restriction.kubernetes.io"
          # k8s.io/kubelet/pkg/apis kubeletLabels / kubeletLabelNamespaces.
          KUBELET_LABELS = %w[kubernetes.io/hostname topology.kubernetes.io/zone topology.kubernetes.io/region
                              failure-domain.beta.kubernetes.io/zone failure-domain.beta.kubernetes.io/region
                              beta.kubernetes.io/instance-type node.kubernetes.io/instance-type kubernetes.io/os
                              kubernetes.io/arch beta.kubernetes.io/os beta.kubernetes.io/arch].freeze
          KUBELET_LABEL_NAMESPACES = %w[kubelet.kubernetes.io node.kubernetes.io].freeze
          KUBELET_SIGNERS = %w[kubernetes.io/kubelet-serving kubernetes.io/kube-apiserver-client-kubelet].freeze
          # Fields a node may change in a claim's status (with
          # RecoverVolumeExpansionFailure, GA).
          PVC_STATUS_FIELDS = %w[capacity conditions allocatedResourceStatuses allocatedResources].freeze

          def validate(attributes)
            user = attributes.user
            return unless user.node?

            node_name = user.node_name.to_s
            reject!("could not determine node from user #{user.name.inspect}") if node_name.empty?

            case [attributes.group, attributes.resource]
            when ["", "pods"]
              case attributes.subresource
              when "" then admit_pod(attributes, node_name)
              when "status" then admit_pod_status(attributes, node_name)
              when "eviction" then admit_pod_eviction(attributes, node_name)
              else reject!("unexpected pod subresource #{attributes.subresource.inspect}, only 'status' and 'eviction' are allowed")
              end
            when ["", "nodes"] then admit_node(attributes, node_name)
            when ["", "persistentvolumeclaims"]
              reject!("may only update PVC status") unless attributes.subresource == "status"

              admit_pvc_status(attributes, node_name)
            when ["", "serviceaccounts"] then admit_service_account(attributes, node_name)
            when ["certificates.k8s.io", "podcertificaterequests"] then admit_pod_certificate_request(attributes, node_name)
            when ["coordination.k8s.io", "leases"] then admit_lease(attributes, node_name)
            when ["storage.k8s.io", "csinodes"] then admit_csi_node(attributes, node_name)
            when ["resource.k8s.io", "resourceslices"] then admit_resource_slice(attributes, node_name)
            when ["certificates.k8s.io", "certificatesigningrequests"] then admit_csr(attributes, node_name)
            end
          end

          private

          def admit_pod(attributes, node_name)
            case attributes.operation
            when "CREATE" then validate_mirror_pod(attributes.object, node_name)
            when "DELETE"
              pod = existing_pod(attributes.namespace, attributes.name)
              reject!("node #{node_name.inspect} can only delete pods with spec.nodeName set to itself") unless spec(pod)["nodeName"] == node_name
            else
              reject!("unexpected operation #{attributes.operation.inspect}, node #{node_name.inspect} can only create and delete mirror pods")
            end
          end

          # noderestriction admitPodCreate: a node creates only its own mirror
          # Pods, owned by its Node as controller, referencing no API object.
          def validate_mirror_pod(pod, node_name)
            node = node_name.inspect
            unless (metadata(pod)["annotations"] || {}).key?(MIRROR_ANNOTATION)
              reject!("pod does not have \"#{MIRROR_ANNOTATION}\" annotation, node #{node} can only create mirror pods")
            end
            reject!("node #{node} can only create pods with spec.nodeName set to itself") unless spec(pod)["nodeName"] == node_name
            owners = Array(metadata(pod)["ownerReferences"])
            reject!("node #{node} can only create pods with a single owner reference set to itself") if owners.length > 1
            reject!("node #{node} can only create pods with an owner reference set to itself") if owners.empty?
            owner = owners.first
            unless owner["apiVersion"] == "v1" && owner["kind"] == "Node" && owner["name"] == node_name
              reject!("node #{node} can only create pods with an owner reference set to itself")
            end
            reject!("node #{node} can only create pods with a controller owner reference set to itself") unless owner["controller"] == true
            reject!("node #{node} must not set blockOwnerDeletion on an owner reference") if owner["blockOwnerDeletion"] == true
            registered = @context.get("nodes", nil, node_name)
            reject!("nodes #{node} not found", code: 404, reason: "NotFound") if registered.nil?
            actual = registered.dig("metadata", "uid").to_s
            reject!("node #{node_name} UID mismatch: expected #{actual} got #{owner["uid"]}") unless owner["uid"].to_s == actual
            resource = PodAPIReferences.find(pod)
            reject!("node #{node} can not create pods that reference #{resource}") if resource
          end

          def admit_pod_status(attributes, node_name)
            reject!("unexpected operation #{attributes.operation.inspect}") unless attributes.operation == "UPDATE"

            old = attributes.old_object
            reject!("node #{node_name.inspect} can only update pod status for pods with spec.nodeName set to itself") unless spec(old)["nodeName"] == node_name
            pod = attributes.object
            unless (metadata(old)["labels"] || {}) == (metadata(pod)["labels"] || {})
              reject!("node #{node_name.inspect} cannot update labels through pod status")
            end
            reject!("node #{node_name.inspect} cannot update resource claim statues") unless resource_claim_statuses(old) == resource_claim_statuses(pod)
            return if (old || {}).dig("status", "extendedResourceClaimStatus") == (pod || {}).dig("status", "extendedResourceClaimStatus")

            reject!("node #{node_name.inspect} cannot update extended resource claim status")
          end

          def resource_claim_statuses(pod)
            Array((pod || {}).dig("status", "resourceClaimStatuses")).map { |status| [status["name"], status["resourceClaimName"]] }
          end

          def admit_pod_eviction(attributes, node_name)
            reject!("unexpected operation #{attributes.operation}") unless attributes.operation == "CREATE"

            pod_name = attributes.name.to_s
            pod_name = metadata(attributes.object)["name"].to_s if pod_name.empty?
            reject!("could not determine pod from request data") if pod_name.empty?
            pod = existing_pod(attributes.namespace, pod_name)
            reject!("node #{node_name} can only evict pods with spec.nodeName set to itself") unless spec(pod)["nodeName"] == node_name
          end

          def existing_pod(namespace, name)
            pod = @context.get("pods", namespace, name)
            reject!("pods #{name.to_s.inspect} not found", code: 404, reason: "NotFound") if pod.nil?

            pod
          end

          # admitPVCStatus: only the resize status may change.
          def admit_pvc_status(attributes, node_name)
            reject!("unexpected operation #{attributes.operation.inspect}") unless attributes.operation == "UPDATE"

            old = comparable_claim(attributes.old_object)
            updated = comparable_claim(attributes.object)
            return if old == updated

            reject!("node #{node_name.inspect} is not allowed to update fields other than status.quantity and status.conditions")
          end

          def comparable_claim(claim)
            copy = JSON.parse(JSON.generate(claim || {}))
            (copy["metadata"] ||= {}).delete("resourceVersion")
            copy["metadata"].delete("managedFields")
            PVC_STATUS_FIELDS.each { |field| (copy["status"] ||= {}).delete(field) }
            copy
          end

          def admit_node(attributes, node_name)
            requested = attributes.name.to_s
            requested = metadata(attributes.object)["name"].to_s if requested.empty? && attributes.operation == "CREATE"
            reject!("node #{node_name.inspect} is not allowed to modify node #{requested.inspect}") unless requested == node_name

            case attributes.operation
            when "CREATE"
              object = attributes.object || {}
              reject!("node #{node_name.inspect} is not allowed to create pods with a non-nil configSource") unless spec(object)["configSource"].nil?
              bad = forbidden_labels(modified_labels(metadata(object)["labels"] || {}, {}))
              reject!("node #{node_name.inspect} is not allowed to set the following labels: #{bad.join(", ")}") unless bad.empty?
            when "UPDATE"
              object = attributes.object || {}
              old = attributes.old_object || {}
              if !spec(object)["configSource"].nil? && spec(object)["configSource"] != spec(old)["configSource"]
                reject!("node #{node_name.inspect} is not allowed to update configSource to a new non-nil configSource")
              end
              reject!("node #{node_name.inspect} is not allowed to modify taints") unless Array(spec(object)["taints"]) == Array(spec(old)["taints"])
              unless Array(metadata(object)["ownerReferences"]) == Array(metadata(old)["ownerReferences"])
                reject!("node #{node_name.inspect} is not allowed to modify ownerReferences")
              end
              bad = forbidden_labels(modified_labels(metadata(object)["labels"] || {}, metadata(old)["labels"] || {}))
              reject!("is not allowed to modify labels: #{bad.join(", ")}") unless bad.empty?
            end
          end

          def modified_labels(left, right)
            (left.keys | right.keys).select { |key| !left.key?(key) || !right.key?(key) || left[key] != right[key] }.sort
          end

          def label_namespace(key)
            parts = key.to_s.split("/", 2)
            parts.length == 2 ? parts.first : ""
          end

          def kubernetes_label?(key)
            namespace = label_namespace(key)
            %w[kubernetes.io k8s.io].any? { |domain| namespace == domain || namespace.end_with?(".#{domain}") }
          end

          def kubelet_label?(key)
            return true if KUBELET_LABELS.include?(key)

            namespace = label_namespace(key)
            KUBELET_LABEL_NAMESPACES.any? { |allowed| namespace == allowed || namespace.end_with?(".#{allowed}") }
          end

          # getForbiddenLabels.
          def forbidden_labels(keys)
            keys.select do |key|
              namespace = label_namespace(key)
              restricted = namespace == NODE_RESTRICTION_NAMESPACE || namespace.end_with?(".#{NODE_RESTRICTION_NAMESPACE}")
              restricted || (kubernetes_label?(key) && !kubelet_label?(key))
            end.sort
          end

          def admit_service_account(attributes, node_name)
            return unless attributes.operation == "CREATE" && attributes.subresource == "token"

            ref = spec(attributes.object)["boundObjectRef"]
            unless ref.is_a?(Hash) && ref["apiVersion"] == "v1" && ref["kind"] == "Pod" && !ref["name"].to_s.empty?
              reject!("node requested token not bound to a pod")
            end
            reject!("node requested token with a pod binding without a uid") if ref["uid"].to_s.empty?
            pod = existing_pod(attributes.namespace, ref["name"])
            unless ref["uid"].to_s == metadata(pod)["uid"].to_s
              reject!("the UID in the bound object reference (#{ref["uid"]}) does not match the UID in record. The object might have been deleted and then " \
                      "recreated")
            end
            reject!("node requested token bound to a pod scheduled on a different node") unless spec(pod)["nodeName"] == node_name
            return if @context.feature_gates.fetch("ServiceAccountNodeAudienceRestriction", true) == false

            validate_token_audience(attributes, pod)
          end

          # validateNodeServiceAccountAudience (ServiceAccountNodeAudienceRestriction,
          # Beta on): a node may only ask for an audience its Pod uses -- a
          # projected serviceAccountToken volume, or a CSI driver (inline, or
          # behind a PVC's PV) whose CSIDriver requests tokens for it -- unless
          # it is authorized for request-serviceaccounts-token-audience.
          def validate_token_audience(attributes, pod)
            audiences = Array(attributes.object&.dig("spec", "audiences"))
            reject!("node may only request 0 or 1 audiences") if audiences.length > 1
            audience = audiences.first.to_s
            return if pod_references_audience?(pod, audience)

            if @context.authorizer
              check = Authorization::Attributes.new(user: attributes.user, verb: "request-serviceaccounts-token-audience",
                                                    namespace: attributes.namespace, api_group: "", api_version: "v1",
                                                    resource: audience, name: attributes.name, resource_request: true)
              decision = @context.authorizer.authorize(check)
              return if decision.respond_to?(:allowed?) && decision.allowed?
            end
            reject!("audience #{audience.inspect} not found in pod spec volume, #{attributes.user.name} is not authorized to request tokens for this audience")
          end

          def pod_references_audience?(pod, audience)
            Array(pod.dig("spec", "volumes")).any? do |volume|
              next true if Array(volume.dig("projected", "sources")).any? do |source|
                token = source["serviceAccountToken"]
                token.is_a?(Hash) && token["audience"].to_s == audience
              end

              driver = if volume.dig("ephemeral", "volumeClaimTemplate")
                         driver_for_claim(pod.dig("metadata", "namespace"), "#{pod.dig("metadata", "name")}-#{volume["name"]}")
                       elsif (claim = volume.dig("persistentVolumeClaim", "claimName"))
                         driver_for_claim(pod.dig("metadata", "namespace"), claim)
                       else
                         volume.dig("csi", "driver")
                       end
              next false if driver.to_s.empty?

              csi_driver = @context.get("csidrivers", nil, driver, group: "storage.k8s.io", version: "v1")
              Array(csi_driver&.dig("spec", "tokenRequests")).any? { |request| request["audience"].to_s == audience }
            end
          rescue StandardError
            false
          end

          def driver_for_claim(namespace, name)
            claim = @context.get("persistentvolumeclaims", namespace, name)
            volume_name = claim&.dig("spec", "volumeName")
            return nil if volume_name.to_s.empty?

            @context.get("persistentvolumes", nil, volume_name)&.dig("spec", "csi", "driver")
          end

          # admitPodCertificateRequest: a node asks only for its own running,
          # non-mirror Pods, naming their current node, Pod and service
          # account UIDs.  UID mismatches may be informer lag, so they are not
          # Forbidden.
          def admit_pod_certificate_request(attributes, node_name)
            reject!("PodCertificateRequest feature gate is disabled") if @context.feature_gates.fetch("PodCertificateRequest",
                                                                                                      false) == false
            reject!("unexpected operation #{attributes.operation}") unless attributes.operation == "CREATE"
            reject!("unexpected subresource #{attributes.subresource}") unless attributes.subresource.to_s.empty?

            request = spec(attributes.object)
            namespace = attributes.namespace
            pod_name = request["podName"].to_s
            unless request["nodeName"].to_s == node_name
              reject!("PodCertificateRequest.Spec.NodeName=#{request["nodeName"].to_s.inspect}, which is not the requesting node #{node_name.inspect}")
            end
            node = @context.get("nodes", nil, node_name)
            if node.nil?
              reject!("while retrieving node #{node_name.inspect} named in the PodCertificateRequest: nodes #{node_name.inspect} not found",
                      code: 404, reason: "NotFound")
            end
            unless metadata(node)["uid"].to_s == request["nodeUID"].to_s
              reject!("PodCertificateRequest for pod \"#{namespace}/#{pod_name}\" names node UID #{request["nodeUID"].to_s.inspect}, inconsistent with the " \
                      "running node " \
                      "(#{metadata(node)["uid"].to_s.inspect})",
                      code: 500, reason: "InternalError")
            end
            pod = @context.get("pods", namespace, pod_name)
            if pod.nil?
              reject!("while retrieving pod \"#{namespace}/#{pod_name}\" named in the PodCertificateRequest: pods #{pod_name.inspect} not found",
                      code: 404, reason: "NotFound")
            end
            unless request["podUID"].to_s == metadata(pod)["uid"].to_s
              reject!("PodCertificateRequest for pod \"#{namespace}/#{pod_name}\" contains pod UID (#{request["podUID"].to_s.inspect}) which differs from " \
                      "running pod " \
                      "#{metadata(pod)["uid"].to_s.inspect}",
                      code: 500, reason: "InternalError")
            end
            unless spec(pod)["nodeName"].to_s == node_name
              reject!("pod \"#{namespace}/#{pod_name}\" is not running on node #{node_name.inspect} named in the PodCertificateRequest")
            end
            reject!("pod \"#{namespace}/#{pod_name}\" is a mirror pod") if (metadata(pod)["annotations"] || {}).key?(MIRROR_ANNOTATION)
            unless request["serviceAccountName"].to_s == spec(pod)["serviceAccountName"].to_s
              reject!("PodCertificateRequest for pod \"#{namespace}/#{pod_name}\" contains serviceAccountName (#{request["serviceAccountName"].to_s.inspect}) that differs from running pod (#{spec(pod)["serviceAccountName"].to_s.inspect})")
            end
            account = @context.get("serviceaccounts", namespace, request["serviceAccountName"].to_s)
            if account.nil?
              reject!("while retrieving service account \"#{namespace}/#{request["serviceAccountName"]}\" named in the PodCertificateRequest: not found",
                      code: 500, reason: "InternalError")
            end
            return if metadata(account)["uid"].to_s == request["serviceAccountUID"].to_s

            reject!("PodCertificateRequest for pod \"#{namespace}/#{pod_name}\" names service account UID #{request["serviceAccountUID"].to_s.inspect}, which differs from the running service account (#{metadata(account)["uid"].to_s.inspect})",
                    code: 500, reason: "InternalError")
          end

          def admit_lease(attributes, node_name)
            reject!("can only access leases in the \"kube-node-lease\" system namespace") unless attributes.namespace == "kube-node-lease"

            name = attributes.operation == "CREATE" ? metadata(attributes.object)["name"].to_s : attributes.name.to_s
            reject!("can only access node lease with the same name as the requesting node") unless name == node_name
          end

          def admit_csi_node(attributes, node_name)
            name = attributes.operation == "CREATE" ? metadata(attributes.object)["name"].to_s : attributes.name.to_s
            reject!("can only access CSINode with the same name as the requesting node") unless name == node_name
          end

          def admit_resource_slice(attributes, node_name)
            case attributes.operation
            when "CREATE"
              unless spec(attributes.object)["nodeName"].to_s == node_name
                reject!("can only create ResourceSlice with the same NodeName as the requesting node")
              end
            when "DELETE"
              unless spec(attributes.old_object)["nodeName"].to_s == node_name
                reject!("can only delete ResourceSlice with the same NodeName as the requesting node")
              end
            end
          end

          # admitCSR: a kubelet CSR's subject must be the node itself.
          def admit_csr(attributes, node_name)
            return unless attributes.operation == "CREATE"

            request = spec(attributes.object)
            return unless KUBELET_SIGNERS.include?(request["signerName"].to_s)

            common_name = begin
              pem = request["request"].to_s
              pem = pem.unpack1("m") unless pem.include?("-----BEGIN")
              csr = OpenSSL::X509::Request.new(pem)
              csr.subject.to_a.find { |entry| entry[0] == "CN" }&.fetch(1, nil)
            rescue StandardError => error
              reject!("unable to parse csr: #{error.message}")
            end
            reject!("can only create a node CSR with CN=system:node:#{node_name}") unless common_name == "system:node:#{node_name}"
          end
        end
        Registry.register("NodeRestriction") { |context, config| NodeRestriction.new("NodeRestriction", context: context, config: config) }

        module CertificateHelpers
          SIGNERS = %w[kubernetes.io/kube-apiserver-client kubernetes.io/kube-apiserver-client-kubelet kubernetes.io/kubelet-serving
                       kubernetes.io/legacy-unknown].freeze

          def signer_resource(signer)
            if SIGNERS.include?(signer) || signer.start_with?("kubernetes.io/")
              [signer.split("/").first, signer.split("/").last, "signers"]
            else
              domain, name = signer.split("/", 2)
              [domain, name, "signers"]
            end
          end

          # SubjectAccessReview-style check against the configured authorizer:
          # verb on certificates.k8s.io signers with the signer name, falling
          # back to the domain wildcard "<domain>/*".
          def signer_permitted?(attributes, verb, signer)
            authorizer = @context.respond_to?(:authorizer) ? @context.authorizer : nil
            return true if authorizer.nil?

            domain, = signer.split("/", 2)
            [signer, "#{domain}/*"].any? do |resource_name|
              check = Authorization::Attributes.new(user: attributes.user, verb: verb, api_group: "certificates.k8s.io", resource: "signers",
                                                    name: resource_name, resource_request: true)
              authorizer.authorize(check).allowed?
            end
          end
        end

        class CertificateApproval < Plugin
          include Helpers
          include CertificateHelpers

          def validate(attributes)
            return unless resource?(attributes, "certificates.k8s.io",
                                    "certificatesigningrequests") && attributes.subresource == "approval" && attributes.operation == "UPDATE"

            old_conditions = Array(attributes.old_object&.dig("status", "conditions")).map { |condition| condition["type"] }
            new_conditions = Array(attributes.object&.dig("status", "conditions")).map { |condition| condition["type"] }
            return if (new_conditions - old_conditions).empty?

            signer = spec(attributes.object)["signerName"].to_s
            reject!("user not permitted to approve requests with signerName #{signer.inspect}") unless signer_permitted?(attributes,
                                                                                                                         "approve", signer)
          end
        end
        Registry.register("CertificateApproval") do |context, config|
          CertificateApproval.new("CertificateApproval", context: context, config: config)
        end

        class CertificateSigning < Plugin
          include Helpers
          include CertificateHelpers

          def validate(attributes)
            return unless resource?(attributes, "certificates.k8s.io",
                                    "certificatesigningrequests") && attributes.subresource == "status" && attributes.operation == "UPDATE"

            old_certificate = attributes.old_object&.dig("status", "certificate").to_s
            new_certificate = attributes.object&.dig("status", "certificate").to_s
            return if new_certificate.empty? || new_certificate == old_certificate

            signer = spec(attributes.object)["signerName"].to_s
            reject!("user not permitted to sign requests with signerName #{signer.inspect}") unless signer_permitted?(attributes, "sign",
                                                                                                                      signer)
          end
        end
        Registry.register("CertificateSigning") do |context, config|
          CertificateSigning.new("CertificateSigning", context: context, config: config)
        end

        class ClusterTrustBundleAttest < Plugin
          include Helpers
          include CertificateHelpers

          def validate(attributes)
            return unless attributes.group == "certificates.k8s.io" && attributes.resource == "clustertrustbundles" && %w[CREATE
                                                                                                                          UPDATE].include?(attributes.operation)

            signer = spec(attributes.object)["signerName"].to_s
            return if signer.empty?

            reject!("user not permitted to attest for signerName #{signer.inspect}") unless signer_permitted?(attributes, "attest", signer)
          end
        end
        Registry.register("ClusterTrustBundleAttest") do |context, config|
          ClusterTrustBundleAttest.new("ClusterTrustBundleAttest", context: context, config: config)
        end

        # CertificateSubjectRestriction: kube-apiserver-client CSRs may not
        # request system:masters.
        class CertificateSubjectRestriction < Plugin
          include Helpers

          def validate(attributes)
            return unless resource?(attributes, "certificates.k8s.io", "certificatesigningrequests") && attributes.operation == "CREATE"
            return unless spec(attributes.object)["signerName"] == "kubernetes.io/kube-apiserver-client"

            request = spec(attributes.object)["request"].to_s
            return if request.empty?

            csr = OpenSSL::X509::Request.new(request.unpack1("m0"))
            organizations = csr.subject.to_a.select { |entry| entry[0] == "O" }.map { |entry| entry[1] }
            reject!("use of kubernetes.io/kube-apiserver-client signer with system:masters group is not allowed") if organizations.include?("system:masters")
          rescue OpenSSL::X509::RequestError, ArgumentError
            reject!("certificate request is not a valid PEM/DER CSR", code: 400, reason: "BadRequest")
          end
        end
        Registry.register("CertificateSubjectRestriction") do |context, config|
          CertificateSubjectRestriction.new("CertificateSubjectRestriction", context: context, config: config)
        end

        # ResourceQuota: enforce namespace quotas on object counts and
        # compute resources.  Usage is computed from live objects so the
        # plugin never trusts a stale status; the quota status is refreshed
        # through the context after admission.
        class ResourceQuota < Plugin
          include Helpers

          COUNTED = {
            "pods" => ["", "pods"], "services" => ["", "services"], "replicationcontrollers" => ["", "replicationcontrollers"],
            "resourcequotas" => ["", "resourcequotas"], "secrets" => ["", "secrets"], "configmaps" => ["", "configmaps"],
            "persistentvolumeclaims" => ["", "persistentvolumeclaims"], "services.nodeports" => ["", "services"], "services.loadbalancers" => ["", "services"]
          }.freeze
          POD_RESOURCES = {"cpu" => "cpu", "memory" => "memory", "ephemeral-storage" => "ephemeral-storage",
                           "requests.cpu" => "cpu", "requests.memory" => "memory", "requests.ephemeral-storage" => "ephemeral-storage",
                           "limits.cpu" => "cpu", "limits.memory" => "memory", "limits.ephemeral-storage" => "ephemeral-storage"}.freeze

          def validate(attributes)
            return unless %w[CREATE UPDATE].include?(attributes.operation) && attributes.object && !attributes.namespace.empty?
            return unless attributes.subresource.empty?

            delta = usage_delta(attributes)
            return if delta.empty?

            MAX_CHARGE_ATTEMPTS.times do
              quotas = begin
                if @context.respond_to?(:list!)
                  @context.list!("resourcequotas",
                                 attributes.namespace)
                else
                  @context.list("resourcequotas", attributes.namespace)
                end
              rescue StandardError => error
                # plugin/pkg/admission/resourcequota: an error reading the
                # quotas fails the request; it never admits by default.
                reject!("the resource quotas of namespace #{attributes.namespace} could not be read: #{error.class}: #{error.message}",
                        code: 503, reason: "ServiceUnavailable")
              end
              trace_quota(attributes, delta, quotas, "listed")
              return if quotas.empty?

              charges = begin
                quotas.filter_map { |quota| charge_for(quota, attributes, delta) }
              rescue Rejected => rejected
                trace_quota(attributes, delta, quotas, "rejected: #{rejected.message}")
                raise
              end
              committed = charges.empty? || commit_charges(charges, attributes.namespace)
              trace_quota(attributes, delta, quotas, committed ? "committed #{charges.map(&:last).inspect[0, 300]}" : "conflict")
              return if committed
            end
            reject!("the resource quota could not be updated: too many concurrent writers", code: 409, reason: "Conflict")
          end

          # RUBERNETES_TRACE_QUOTA=1 prints every quota decision this plugin
          # makes to stderr: what it listed, the delta it charged, the outcome.
          TRACE_QUOTA = ENV["RUBERNETES_TRACE_QUOTA"].to_s == "1"

          def trace_quota(attributes, delta, quotas, outcome)
            return unless TRACE_QUOTA

            line = {"timestamp" => Time.now.utc.iso8601(6), "level" => "info", "event" => "quota.trace",
                    "namespace" => attributes.namespace, "resource" => attributes.resource,
                    "name" => attributes.object&.dig("metadata", "name") || attributes.object&.dig("metadata", "generateName"),
                    "delta" => delta.transform_values { |value| Quantity.format(value) },
                    "quotas" => quotas.map do |quota|
                      {"name" => quota.dig("metadata", "name"), "rv" => quota.dig("metadata", "resourceVersion"), "used" => quota.dig("status", "used")}
                    end,
                    "outcome" => outcome}
            $stderr.write(JSON.generate(line) << "\n")
          rescue StandardError
            nil
          end

          # plugin/pkg/admission/resourcequota/controller.go: an admitted
          # request is CHARGED -- its usage is written into the quota's
          # status.used before the object is stored -- so the next request
          # sees it.  Checking against status.used alone let a request pass
          # on a total the quota controller had not recomputed yet: a
          # LoadBalancer created 150 ms after a NodePort Service was admitted
          # over a one-node-port quota.
          MAX_CHARGE_ATTEMPTS = 5

          # resourcequota/controller.go checkRequest for one matching quota:
          # the quota's status.hard is what is enforced (spec.hard reaches it
          # through the quota controller), a quota whose usage is not known
          # yet refuses the request, a Pod quota'd on cpu/memory must request
          # them per container unless it sets pod-level resources, and every
          # exceeded resource is named in one message.
          def charge_for(quota, attributes, delta)
            return nil unless scope_matches?(quota, attributes)

            name = quota.dig("metadata", "name")
            hard = quota.dig("status", "hard") || {}
            return nil if hard.empty?

            used = quota.dig("status", "used") || {}
            if resource?(attributes, "", "pods")
              missing = Rubernetes::PodQuotaUsage.missing_container_constraints(attributes.object, hard.keys)
              unless missing.empty?
                detail = missing.keys.sort.map { |resource| "#{resource} for: #{missing[resource].uniq.sort.join(",")}" }.join("; ")
                reject!("#{group_resource(attributes)} #{attributes.name.to_s.inspect} is forbidden: failed quota: #{name}: must specify #{detail}")
              end
            end
            unknown = hard.keys.select { |resource| delta.key?(resource) && !used.key?(resource) }
            unless unknown.empty?
              reject!("#{group_resource(attributes)} #{attributes.name.to_s.inspect} is forbidden: status unknown for quota: #{name}, resources: #{unknown.sort.join(",")}")
            end
            requested = hard.keys.each_with_object({}) do |resource, result|
              change = delta[resource]
              result[resource] = change if change && change.positive?
            end
            return nil if requested.empty?

            updated = used.dup
            exceeded = []
            requested.each do |resource, change|
              total = quantity(used.fetch(resource, "0")) + change
              exceeded << resource if total > quantity(hard[resource])
              updated[resource] = Quantity.format(total)
            end
            unless exceeded.empty?
              pretty = ->(pairs) { exceeded.sort.map { |resource| "#{resource}=#{pairs.call(resource)}" }.join(",") }
              reject!("#{group_resource(attributes)} #{attributes.name.to_s.inspect} is forbidden: exceeded quota: #{name}, " \
                      "requested: #{pretty.call(->(resource) { Quantity.format(requested[resource]) })}, " \
                      "used: #{pretty.call(->(resource) { Quantity.format(quantity(used.fetch(resource, "0"))) })}, " \
                      "limited: #{pretty.call(->(resource) { hard[resource] })}")
            end
            updated == used ? nil : [quota, updated]
          end

          # All-or-nothing only as far as the store allows: a conflict on any
          # quota restarts the whole check against fresh quotas.
          def commit_charges(charges, namespace)
            charges.each do |quota, used|
              candidate = JSON.parse(JSON.generate(quota))
              (candidate["status"] ||= {})["used"] = used
              @context.update("resourcequotas", namespace, quota.dig("metadata", "name"), candidate,
                              resource_version: quota.dig("metadata", "resourceVersion"))
            end
            true
          rescue StandardError => error
            raise unless error.class.name.to_s.end_with?("Conflict")

            false
          end

          private

          def scope_matches?(quota, attributes)
            scopes = Array(quota.dig("spec", "scopes"))
            selector = quota.dig("spec", "scopeSelector")
            return true if scopes.empty? && selector.nil?
            return false unless resource?(attributes, "", "pods")

            pod = attributes.object
            scopes.all? { |scope| scope_applies?(scope, pod) } &&
              Array(selector&.dig("matchExpressions")).all? { |expression| scope_expression_applies?(expression, pod) }
          end

          def scope_applies?(scope, pod)
            case scope
            when "Terminating" then spec(pod)["activeDeadlineSeconds"]
            when "NotTerminating" then spec(pod)["activeDeadlineSeconds"].nil?
            when "BestEffort" then best_effort?(pod)
            when "NotBestEffort" then !best_effort?(pod)
            when "PriorityClass" then !spec(pod)["priorityClassName"].to_s.empty?
            when "CrossNamespacePodAffinity" then cross_namespace_affinity?(pod)
            else true
            end
          end

          def scope_expression_applies?(expression, pod)
            case expression["scopeName"]
            when "PriorityClass"
              name = spec(pod)["priorityClassName"].to_s
              case expression["operator"]
              when "In" then Array(expression["values"]).include?(name)
              when "NotIn" then !Array(expression["values"]).include?(name)
              when "Exists" then !name.empty?
              when "DoesNotExist" then name.empty?
              else false
              end
            else scope_applies?(expression["scopeName"], pod)
            end
          end

          # qos.GetPodQOS == BestEffort (pod-level resources included).
          def best_effort?(pod)
            Rubernetes::ResourceHelpers.pod_qos(pod) == "BestEffort"
          end

          def cross_namespace_affinity?(pod)
            affinity = spec(pod)["affinity"] || {}
            %w[podAffinity podAntiAffinity].any? do |kind|
              Array(affinity.dig(kind, "requiredDuringSchedulingIgnoredDuringExecution")).any? do |term|
                term["namespaces"] || term["namespaceSelector"]
              end
            end
          end

          def usage_delta(attributes)
            delta = Hash.new(0r)
            resource = attributes.resource
            if attributes.operation == "CREATE" && !resource?(attributes, "", "pods")
              delta[resource] += 1 if COUNTED.key?(resource)
              delta["count/#{resource}"] += 1
              delta["count/#{resource}.#{attributes.group}"] += 1 unless attributes.group.empty?
            end
            if resource?(attributes, "", "pods")
              # PodUsageFunc (count/pods and pods included); an update is
              # charged SubtractWithNonNegativeResult(new, old).
              new_usage = Rubernetes::PodQuotaUsage.usage(attributes.object)
              old_usage = attributes.operation == "UPDATE" && attributes.old_object ? Rubernetes::PodQuotaUsage.usage(attributes.old_object) : {}
              new_usage.each do |key, value|
                change = value - old_usage.fetch(key, 0r)
                delta[key] += change if change.positive?
              end
            elsif resource?(attributes, "", "persistentvolumeclaims") && attributes.operation == "CREATE"
              storage = spec(attributes.object).dig("resources", "requests", "storage")
              delta["requests.storage"] += quantity(storage) if storage
              class_name = spec(attributes.object)["storageClassName"]
              delta["#{class_name}.storageclass.storage.k8s.io/requests.storage"] += quantity(storage) if storage && class_name
              delta["#{class_name}.storageclass.storage.k8s.io/persistentvolumeclaims"] += 1 if class_name
            elsif resource?(attributes, "resource.k8s.io", "resourceclaims") && attributes.operation == "CREATE"
              # The object count is charged above; the devices per class here.
              Rubernetes::ClaimQuotaUsage.usage(attributes.object).each do |name, count|
                delta[name] += count unless name == Rubernetes::ClaimQuotaUsage::COUNT
              end
            elsif resource?(attributes, "", "services") && attributes.operation == "CREATE"
              # quota/v1/evaluator/core/services.go charges node ports by the
              # number of SERVICE PORTS, not by the ports that already carry an
              # allocated nodePort: "node port quota charging is based on
              # service ports".  A client never sets nodePort -- the API server
              # allocates it -- so counting allocated ones charged every new
              # Service zero and the quota could never be exceeded.
              delta["services.nodeports"] += service_node_ports(spec(attributes.object))
              delta["services.loadbalancers"] += 1 if spec(attributes.object)["type"] == "LoadBalancer"
            end
            delta
          end

          # A LoadBalancer allocates a node port per service port unless it was
          # asked not to (allocateLoadBalancerNodePorts), which is why the
          # conformance quota spec expects a LoadBalancer to be refused once a
          # NodePort Service has used the allowance up.
          def service_node_ports(service_spec)
            ports = Array(service_spec["ports"]).length
            case service_spec["type"].to_s
            when "NodePort" then ports
            when "LoadBalancer" then service_spec["allocateLoadBalancerNodePorts"] == false ? 0 : ports
            else 0
            end
          end
        end
        Registry.register("ResourceQuota") { |context, config| ResourceQuota.new("ResourceQuota", context: context, config: config) }
      end
    end
  end
end
